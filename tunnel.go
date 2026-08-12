/*
 * tunnel.go — the core of the tool: one complete DH P2P session, from
 * handshake through concurrent serving, plus the retry machinery.
 *
 * Handshake phases (see handshake()):
 *   1. p2psrv discovery  — find the camera's P2P server and probe it;
 *   2. relay session     — ask the cloud for a relay agent, open a PTCP
 *                          session on mainRemote and exchange the 0x17
 *                          sign token (the session credential);
 *   3. channel request   — /device/<sn>/p2p-channel with our Identify,
 *                          random AID and local address (AES-encrypted
 *                          for type 1 devices);
 *   4. NAT punch         — inverted-STUN against the camera using its
 *                          LocalAddr + PubAddr; if it never answers we
 *                          fall back to the already-established relay
 *                          session as the data socket;
 *   5. PTCP auth         — on the direct socket: 0x03 sync, 0x19 sign
 *                          handoff, 0x1B finish.
 *
 * Serving model: one reader goroutine per UDP socket (the only owner
 * of that socket and its PTCP counters), one heartbeat goroutine, and
 * one goroutine per accepted TCP connection that does a background
 * bind then streams data over its realm. A single failure degrades
 * gracefully: a bad bind kills only that connection, a dead channel
 * fails the tunnel and runWithRetries restarts it.
 */

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	BIND_TIMEOUT      = 10 * time.Second
	HEARTBEAT_TIMEOUT = 10 * time.Second
	RETRY_ATTEMPTS    = 3
	RETRY_DELAY       = 2 * time.Second
	CSEQ_BASE         = 100
	CSEQ_STEP         = 1000
)

// errDeviceNotFound — the cloud answered 404 for /device/<sn>/p2p-channel:
// the serial does not exist or the device is powered off. Retrying is
// pointless, so this short-circuits the retry machinery entirely.
var errDeviceNotFound = errors.New("device response: code=404 Not Found")

// notFoundPrinted — the "{SN} isn't exist or turned off." notice is emitted
// exactly once per run, no matter how many tunnels hit the 404.
var notFoundPrinted sync.Once

func deviceNotFound(serial string) {
	notFoundPrinted.Do(func() {
		fmt.Printf("%s isn't exist or turned off.\n", serial)
	})
}

func isNotFound(reason string) bool {
	return reason == errDeviceNotFound.Error()
}

// ptcpHeartbeat — client-initiated PTCP heartbeat (0x13, len=0, realm=0).
// The reference implementation only acks the device's 0x13 frames; sending
// our own keeps the direct channel alive when the device goes quiet.
var ptcpHeartbeat = []byte{
	0x13, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
}

type PortSpec struct {
	Local  int
	Remote int
}

type Client struct {
	conn          net.Conn
	lastKeepalive time.Time
	cseq          int
}

type acceptConn struct {
	conn       net.Conn
	remotePort int
}

type specGroup struct {
	idxs  []int
	specs []PortSpec
}

// Tunnel — a single tunnel: full handshake + serving its own ports
// (several local listeners, binds and realms over one PTCP channel).
type Tunnel struct {
	serial, username, password, randsalt string
	dtype                                int
	debug                                bool
	logRetries                           bool

	specs   []PortSpec
	specIdx []int
	reg     *PortRegistry
	ui      *UI

	deviceRemote *UDP
	mainRemote   *UDP
	primary      *UDP // data socket: deviceRemote (direct) or mainRemote (relay)
	listeners    []net.Listener
	clients      map[uint32]*Client
	clientsMu    sync.Mutex
	acceptCh     chan acceptConn
	done         chan struct{}
	cseqCounter  int

	// concurrent serving
	readerWG  sync.WaitGroup // readers + heartbeat goroutines
	bindMu    sync.Mutex
	bindWait  map[uint32]chan struct{} // realm -> bind ack channel
	errMu     sync.Mutex
	failErr   error
}

func newTunnel(serial string, dtype int, username, password, randsalt string, debug, logRetries bool, g specGroup, reg *PortRegistry) *Tunnel {
	t := &Tunnel{
		serial:      serial,
		dtype:       dtype,
		username:    username,
		password:    password,
		randsalt:    randsalt,
		debug:       debug,
		logRetries:  logRetries,
		specs:       g.specs,
		specIdx:     g.idxs,
		reg:         reg,
		cseqCounter: CSEQ_BASE,
	}
	if reg != nil {
		t.ui = reg.ui
	}
	t.reset()
	return t
}

func (t *Tunnel) reset() {
	t.listeners = nil
	t.clients = make(map[uint32]*Client)
	t.acceptCh = make(chan acceptConn, 16)
	t.done = make(chan struct{})
	t.cseqCounter = CSEQ_BASE
	t.deviceRemote = nil
	t.mainRemote = nil
	t.primary = nil
	t.bindWait = make(map[uint32]chan struct{})
	t.failErr = nil
}

func (t *Tunnel) close() {
	select {
	case <-t.done:
	default:
		close(t.done)
	}
	for _, ln := range t.listeners {
		ln.Close()
	}
	t.clientsMu.Lock()
	for _, c := range t.clients {
		c.conn.Close()
	}
	t.clientsMu.Unlock()
	if t.deviceRemote != nil {
		t.deviceRemote.Close()
	}
	if t.mainRemote != nil {
		t.mainRemote.Close()
	}
}

func (t *Tunnel) Run() error {
	if err := t.handshake(); err != nil {
		t.close()
		return err
	}
	defer t.close()
	return t.serve()
}

// logf — single output point for tunnel noise. Only printed with --debug.
// In multi-port mode writes below the status block, otherwise to stdout.
func (t *Tunnel) logf(format string, args ...any) {
	if !t.debug {
		return
	}
	msg := fmt.Sprintf(format, args...)
	if t.ui != nil {
		t.ui.Below(msg)
	} else {
		fmt.Println(msg)
	}
}

func (t *Tunnel) markConnecting() {
	if t.reg == nil {
		return
	}
	for _, idx := range t.specIdx {
		t.reg.connecting(idx)
	}
}

// p2pChannelBody builds the /device/<sn>/p2p-channel request body for the
// given local port: our random Identify (aid), the local address the device
// should punch to (encrypted + auth block for type > 0 devices). The
// derived auth key is returned for later decrypting the device's reply.
func p2pChannelBody(lport, dtype int, username, password, randsalt string, aid []byte) (string, []byte) {
	laddr := fmt.Sprintf("127.0.0.1:%d", lport)
	ipaddr := fmt.Sprintf("<IpEncrpt>true</IpEncrpt><LocalAddr>%s</LocalAddr>", laddr)
	authStr := ""
	var key []byte
	if dtype > 0 {
		key = get_key(username, password, randsalt)
		encNonce := get_nonce()
		encLaddr := get_enc(key, encNonce, laddr)
		ipaddr = fmt.Sprintf("<IpEncrptV2>true</IpEncrptV2><LocalAddr>%s</LocalAddr>", encLaddr)
		authStr = get_auth(username, key, encNonce, laddr, randsalt)
	}

	aidHex := make([]string, 8)
	for i, b := range aid {
		aidHex[i] = fmt.Sprintf("%x", b)
	}

	body := fmt.Sprintf("<body>%s<Identify>%s</Identify>%s<version>5.0.0</version></body>",
		authStr, strings.Join(aidHex, " "), ipaddr)
	return body, key
}

func (t *Tunnel) handshake() error {
	mainRemote := NewUDP(MAIN_SERVER, MAIN_PORT, t.debug)
	mainRemote.debugLog = t.logf
	t.mainRemote = mainRemote

	mainRemote.Request("/probe/p2psrv", "", true, true)
	res, _ := mainRemote.Request(fmt.Sprintf("/online/p2psrv/%s", t.serial), "", true, true)
	if res == nil {
		return fmt.Errorf("p2psrv lookup failed")
	}
	us := res.Body["body/US"]
	if us == "" {
		return fmt.Errorf("device %s not found on p2psrv", t.serial)
	}
	p2psrv := strings.SplitN(us, ":", 2)
	p2psrvPort, _ := strconv.Atoi(p2psrv[1])

	p2psrvRemote := NewUDP(p2psrv[0], p2psrvPort, t.debug)
	p2psrvRemote.debugLog = t.logf
	p2psrvRemote.Request(fmt.Sprintf("/probe/device/%s", t.serial), "", true, true)
	p2psrvRemote.Request(fmt.Sprintf("/info/device/%s", t.serial), "", true, true)
	p2psrvRemote.Close()

	res, err := mainRemote.Request("/online/relay", "", true, true)
	if err != nil {
		return fmt.Errorf("relay lookup: %v", err)
	}
	relay := strings.SplitN(res.Body["body/Address"], ":", 2)
	relayPort, _ := strconv.Atoi(relay[1])

	deviceRemote := NewUDP(MAIN_SERVER, MAIN_PORT, t.debug)
	deviceRemote.debugLog = t.logf
	t.deviceRemote = deviceRemote

	if t.dtype > 0 && (t.username == "" || t.password == "") {
		return fmt.Errorf("username and password required for type > 0")
	}

	aid := make([]byte, 8)
	rand.Read(aid)
	body, key := p2pChannelBody(deviceRemote.lport, t.dtype, t.username, t.password, t.randsalt, aid)

	deviceRemote.Request(fmt.Sprintf("/device/%s/p2p-channel", t.serial), body, true, false)

	mainRemote.SetRemote(relay[0], relayPort)
	res, err = mainRemote.Request("/relay/agent", "", true, true)
	if err != nil {
		return fmt.Errorf("relay agent: %v", err)
	}
	token := res.Body["body/Token"]
	agent := res.Body["body/Agent"]

	agentParts := strings.SplitN(agent, ":", 2)
	agentPort, _ := strconv.Atoi(agentParts[1])

	mainRemote.SetRemote(agentParts[0], agentPort)
	mainRemote.Request(fmt.Sprintf("/relay/start/%s", token), "<body><Client>:0</Client></body>", true, true)

	res, err = deviceRemote.Read(true, 30*time.Second)
	if err == nil && res.Code < 200 {
		res, err = deviceRemote.Read(true, 30*time.Second)
	}
	if err != nil {
		return fmt.Errorf("read device response: %v", err)
	}
	if res.Code >= 400 {
		if res.Code == 404 {
			return errDeviceNotFound
		}
		if t.dtype == 0 && res.Code == 403 {
			return fmt.Errorf("device requires authentication, try --type 1 --username <user> --password <pass>")
		}
		return fmt.Errorf("device response: code=%d %s", res.Code, res.Status)
	}

	deviceLaddr := res.Body["body/LocalAddr"]
	devicePub := res.Body["body/PubAddr"]

	if t.dtype > 0 {
		nonceStr := res.Body["body/Nonce"]
		if nonceStr != "" {
			nonceVal, _ := strconv.Atoi(nonceStr)
			deviceLaddr = get_dec(key, nonceVal, deviceLaddr)
		}
	}

	devParts := strings.SplitN(devicePub, ":", 2)
	devPort, _ := strconv.Atoi(devParts[1])
	deviceRemote.SetRemote(devParts[0], devPort)

	mainRemote.SetRemote(MAIN_SERVER, MAIN_PORT)

	authStr := ""
	if t.dtype > 0 {
		nonce2 := get_nonce()
		authStr = get_auth(t.username, key, nonce2, "", t.randsalt)
	}

	mainRemote.Request(fmt.Sprintf("/device/%s/relay-channel", t.serial),
		fmt.Sprintf("<body>%s<agentAddr>%s:%d</agentAddr></body>", authStr, agentParts[0], agentPort),
		true, false)
	mainRemote.SetRemote(agentParts[0], agentPort)
	if _, err := mainRemote.Read(true, 30*time.Second); err != nil {
		return fmt.Errorf("relay-channel read: %v", err)
	}

	mainRemote.RequestPTCP([]byte{0x00, 0x03, 0x01, 0x00})
	p, err := mainRemote.ReadPTCP(30 * time.Second)
	if err != nil {
		return fmt.Errorf("ptcp sync: %v", err)
	}

	// Sign token exchange: 0x17 on the relay session yields the session
	// credential reused later for the direct PTCP handshake (0x19).
	mainRemote.RequestPTCP([]byte{
		0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	})
	p, err = mainRemote.ReadPTCP(30 * time.Second)
	if err != nil {
		return fmt.Errorf("ptcp 0x17: %v", err)
	}
	for len(p.Body) == 0 {
		p, err = mainRemote.ReadPTCP(30 * time.Second)
		if err != nil {
			return fmt.Errorf("ptcp 0x17 wait: %v", err)
		}
	}
	sign := p.Body[12:]
	mainRemote.RequestPTCP(nil)

	invAid := make([]byte, 8)
	for i, b := range aid {
		invAid[i] = ^b
	}

	cookie := make([]byte, 4)
	rand.Read(cookie)
	transID := make([]byte, 12)
	rand.Read(transID)

	eaddr := make([]byte, 6)
	binary.BigEndian.PutUint16(eaddr[0:2], uint16(devPort))
	copy(eaddr[2:], net.ParseIP(devParts[0]).To4())
	for i, b := range eaddr {
		eaddr[i] = ^b
	}

	stunInit := []byte{0xFF, 0xFE, 0xFF, 0xE7}
	stunInit = append(stunInit, cookie...)
	stunInit = append(stunInit, transID...)
	stunInit = append(stunInit, []byte{0x7F, 0xD5, 0xFF, 0xF7}...)
	stunInit = append(stunInit, invAid...)
	stunInit = append(stunInit, []byte{0xFF, 0xFB, 0xFF, 0xF7, 0xFF, 0xFE}...)
	stunInit = append(stunInit, eaddr...)

	localIPStr, localPortStr, _ := strings.Cut(deviceLaddr, ":")
	localPortVal, _ := strconv.Atoi(localPortStr)

	t.logf(":%d >>> %s:%d (LocalAddr)", deviceRemote.lport, localIPStr, localPortVal)
	t.logf(":%d >>> %s:%d (PubAddr)", deviceRemote.lport, devParts[0], devPort)

	deviceRemote.SendTo(stunInit, &net.UDPAddr{IP: net.ParseIP(localIPStr), Port: localPortVal})
	deviceRemote.Send(stunInit)

	var stunResponse []byte
	deviceRemote.SetTimeout(2 * time.Second)
	deadline := time.Now().Add(10 * time.Second)
	attempt := 0

	for time.Now().Before(deadline) {
		data, addr, err := deviceRemote.RecvFrom(4096)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				attempt++
				if attempt <= 2 {
					t.logf("Retransmit STUN init (attempt %d)", attempt)
					deviceRemote.Send(stunInit)
				}
				continue
			}
			break
		}
		magic := data[:4]
		t.logf("STUN <<< %s magic=%x len=%d", addr, magic, len(data))

		if string(magic) == "\xFE\xFE\xFF\xE7" {
			stunResponse = data
			t.logf("Got STUN response (fefeffe7)")
			break
		} else if string(magic) == "\xFF\xFE\xFF\xE7" {
			t.logf("Got device cross-STUN init (fffeffe7), responding...")
			resp := make([]byte, 0, 40)
			resp = append(resp, []byte{0xFE, 0xFE, 0xFF, 0xE7}...)
			resp = append(resp, data[4:8]...)
			resp = append(resp, data[8:20]...)
			resp = append(resp, []byte{0x7F, 0xD6, 0xFF, 0xF7}...)
			resp = append(resp, invAid...)
			resp = append(resp, []byte{0xFF, 0xFB, 0xFF, 0xF7, 0xFF, 0xFE}...)
			resp = append(resp, data[34:40]...)
			deviceRemote.SendTo(resp, addr)
			t.logf("STUN >>> %s response sent", addr)
		} else {
			t.logf("Unknown magic: %x", magic)
		}
	}

	if stunResponse == nil {
		// No STUN response — the camera did not punch a direct hole.
		// The relay PTCP session on mainRemote was already established
		// earlier in this handshake, and the camera was told the agent
		// address via /device/<sn>/relay-channel. Data flows through
		// the agent, so we simply use it as the primary data socket.
		t.logf("STUN failed — using relay agent as the data path")
		t.primary = mainRemote
		return nil
	}

	confirm := []byte{0xFE, 0xFE, 0xFF, 0xF3}
	confirm = append(confirm, cookie...)
	confirm = append(confirm, transID...)
	confirm = append(confirm, []byte{0x7F, 0xD6, 0xFF, 0xF7}...)
	confirm = append(confirm, invAid...)

	for range 5 {
		t.logf("Confirm >>>")
		deviceRemote.Send(confirm)
	}

	time.Sleep(300 * time.Millisecond)
	deviceRemote.SetTimeout(500 * time.Millisecond)
	for {
		data, addr, err := deviceRemote.RecvFrom(4096)
		if err != nil {
			break
		}
		t.logf("Drain <<< %s magic=%x len=%d", addr, data[:4], len(data))
	}
	deviceRemote.SetTimeout(0)

	if err := ptcpHandshake(deviceRemote, sign); err != nil {
		return fmt.Errorf("ptcp device handshake: %v", err)
	}
	t.logf("PTCP handshake complete (direct)")
	t.primary = deviceRemote
	return nil
}

func ptcpHandshake(u *UDP, signToken []byte) error {
	u.RequestPTCP([]byte{0x00, 0x03, 0x01, 0x00})
	p, err := u.ReadPTCP(30 * time.Second)
	if err != nil {
		return err
	}
	if string(p.Body) != "\x00\x03\x01\x00" {
		return fmt.Errorf("ptcp sync mismatch")
	}

	pkt := append([]byte{0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, signToken...)
	u.RequestPTCP(pkt)
	p, err = u.ReadPTCP(30 * time.Second)
	if err != nil {
		return err
	}
	for len(p.Body) == 0 {
		p, err = u.ReadPTCP(30 * time.Second)
		if err != nil {
			return err
		}
	}
	if p.Body[0] != 0x1A {
		return fmt.Errorf("ptcp auth mismatch: got 0x%02x", p.Body[0])
	}

	u.RequestPTCP([]byte{0x1B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	p, err = u.ReadPTCP(30 * time.Second)
	if err != nil {
		return err
	}
	if len(p.Body) != 0 {
		return fmt.Errorf("ptcp final expected empty")
	}
	return nil
}

// serve — concurrent serving. Dedicated reader goroutine per socket,
// binds handled in the background, data fanned out per realm. Nothing
// in the data path ever blocks on a bind or on a slow peer.
func (t *Tunnel) serve() error {
	type okListen struct {
		idx    int // index in PortRegistry
		port   int // actual local port after bind
		remote int // camera port
	}
	oks := []okListen{}
	for i, spec := range t.specs {
		ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", spec.Local))
		if err != nil {
			t.logf("listen :%d failed: %v", spec.Local, err)
			if t.reg != nil {
				t.reg.fail(t.specIdx[i], fmt.Sprintf("listen :%d: %v", spec.Local, err))
			}
			continue
		}
		port := spec.Local
		if port == 0 {
			if addr, ok := ln.Addr().(*net.TCPAddr); ok {
				port = addr.Port
			}
		}
		t.listeners = append(t.listeners, ln)
		oks = append(oks, okListen{idx: t.specIdx[i], port: port, remote: spec.Remote})
		go t.acceptLoop(ln, spec.Remote)
	}
	if len(t.listeners) == 0 {
		return fmt.Errorf("no listeners available for tunnel")
	}

	for _, o := range oks {
		if t.reg != nil {
			t.reg.okPort(o.idx, o.port)
		}
	}
	if t.ui == nil {
		for _, o := range oks {
			fmt.Printf("Listening on port %d, remote port %d\n", o.port, o.remote)
		}
	}

	// grace period so the first read does not count as stale
	t.primary.lastRecv = time.Now()

	t.readerWG.Add(3)
	go t.readLoop(t.deviceRemote)
	go t.readLoop(t.mainRemote)
	go t.heartbeatLoop()

	for {
		select {
		case <-t.done:
			t.readerWG.Wait()
			return t.failure()
		case ac := <-t.acceptCh:
			go t.handleBind(ac)
		}
	}
}

// readLoop owns one socket: it is the ONLY reader, so SetReadDeadline
// and the PTCP sequence counters never race across goroutines. Every
// frame is ACKed on the socket it arrived on. The primary data socket
// (direct or relay) is also the tunnel health monitor — silence for
// HEARTBEAT_TIMEOUT kills the tunnel and hands control to the retry
// machinery. The non-primary socket is read too: in direct mode this
// keeps the relay registration alive (and can even carry data if the
// camera decides to use it); in relay mode the direct socket is just
// dormant.
func (t *Tunnel) readLoop(u *UDP) {
	defer t.readerWG.Done()
	for {
		select {
		case <-t.done:
			return
		default:
		}

		p, err := u.ReadPTCP(5 * time.Second)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if u == t.primary && time.Since(u.LastRecv()) > HEARTBEAT_TIMEOUT {
					t.fail(fmt.Errorf("heartbeat timeout: no PTCP on primary socket for %v", HEARTBEAT_TIMEOUT))
					return
				}
				continue
			}
			t.fail(err)
			return
		}
		t.routePTCP(p, u)
	}
}

func (t *Tunnel) heartbeatLoop() {
	defer t.readerWG.Done()
	hb := time.NewTicker(5 * time.Second)
	defer hb.Stop()
	for {
		select {
		case <-t.done:
			return
		case <-hb.C:
			t.mainRemote.RequestPTCP([]byte{})
			t.primary.RequestPTCP(ptcpHeartbeat)

			now := time.Now()
			t.clientsMu.Lock()
			for rid, c := range t.clients {
				if now.Sub(c.lastKeepalive) > 25*time.Second {
					ka := fmt.Sprintf("OPTIONS * RTSP/1.0\r\nCSeq: %d\r\n\r\n", c.cseq)
					t.primary.RequestPTCP((&PTCPPayload{Realm: rid, Payload: []byte(ka)}).Bytes())
					c.cseq++
					c.lastKeepalive = now
				}
			}
			t.clientsMu.Unlock()
		}
	}
}

func (t *Tunnel) acceptLoop(ln net.Listener, remotePort int) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		select {
		case t.acceptCh <- acceptConn{conn: conn, remotePort: remotePort}:
		case <-t.done:
			conn.Close()
			return
		}
	}
}

// handleBind runs in its own goroutine. A bind timeout fails only that
// connection — the tunnel, other realms and other ports stay alive.
func (t *Tunnel) handleBind(ac acceptConn) {
	realmID := rand.Uint32()
	t.logf("Binding realm=%#010x port=%d", realmID, ac.remotePort)

	wait := make(chan struct{})
	t.setBindWait(realmID, wait)

	// Register the client BEFORE the bind so early camera data is
	// already routed to the accepted connection.
	t.addClient(realmID, ac.conn)

	bindPkt := make([]byte, 20)
	bindPkt[0] = 0x11
	binary.BigEndian.PutUint32(bindPkt[4:8], realmID)
	binary.BigEndian.PutUint32(bindPkt[12:16], uint32(ac.remotePort))
	bindPkt[16] = 0x7F
	bindPkt[19] = 0x01
	t.primary.RequestPTCP(bindPkt)

	select {
	case <-wait:
		t.logf("Bind OK realm=%#010x", realmID)
	case <-time.After(BIND_TIMEOUT):
		t.logf("Bind FAILED realm=%#010x port=%d", realmID, ac.remotePort)
		t.delClient(realmID)
		ac.conn.Close()
		t.takeBindWait(realmID)
	case <-t.done:
		t.takeBindWait(realmID)
		ac.conn.Close()
	}
}

func (t *Tunnel) setBindWait(realmID uint32, ch chan struct{}) {
	t.bindMu.Lock()
	t.bindWait[realmID] = ch
	t.bindMu.Unlock()
}

func (t *Tunnel) takeBindWait(realmID uint32) chan struct{} {
	t.bindMu.Lock()
	defer t.bindMu.Unlock()
	ch := t.bindWait[realmID]
	delete(t.bindWait, realmID)
	return ch
}

func (t *Tunnel) addClient(realmID uint32, conn net.Conn) {
	t.clientsMu.Lock()
	t.clients[realmID] = &Client{
		conn:          conn,
		lastKeepalive: time.Now(),
		cseq:          t.cseqCounter,
	}
	t.cseqCounter += CSEQ_STEP
	active := len(t.clients)
	t.clientsMu.Unlock()
	t.logf("Client realm=%#010x, %d active", realmID, active)
	go t.clientReader(conn, realmID)
}

func (t *Tunnel) getClient(realmID uint32) *Client {
	t.clientsMu.Lock()
	defer t.clientsMu.Unlock()
	return t.clients[realmID]
}

func (t *Tunnel) delClient(realmID uint32) {
	t.clientsMu.Lock()
	delete(t.clients, realmID)
	t.clientsMu.Unlock()
}

func (t *Tunnel) clientReader(conn net.Conn, realmID uint32) {
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			discPkt := make([]byte, 16)
			discPkt[0] = 0x12
			binary.BigEndian.PutUint32(discPkt[4:8], realmID)
			copy(discPkt[12:], "DISC")
			t.primary.RequestPTCP(discPkt)
			t.logf("Disconnected realm=%#010x", realmID)
			t.delClient(realmID)
			return
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		t.primary.RequestPTCP((&PTCPPayload{Realm: realmID, Payload: data}).Bytes())
	}
}

// routePTCP is called only from readLoop goroutines. The frame is
// ACKed on the socket that carried it, then routed: DATA to the realm's
// client, STATUS to either a pending bind or a live client, heartbeat
// just refreshes liveness (ReadPTCP already bumped lastRecv).
func (t *Tunnel) routePTCP(p *PTCP, src *UDP) {
	if len(p.Body) == 0 {
		src.RequestPTCP(nil)
		return
	}
	src.RequestPTCP(nil)

	switch p.Body[0] {
	case 0x10:
		pl, err := ParsePTCPPayload(p.Body)
		if err != nil {
			return
		}
		if c := t.getClient(pl.Realm); c != nil {
			c.conn.Write(pl.Payload)
		}
	case 0x12:
		realm := binary.BigEndian.Uint32(p.Body[4:8])
		if ch := t.takeBindWait(realm); ch != nil {
			close(ch)
			return
		}
		if c := t.getClient(realm); c != nil {
			c.conn.Close()
			t.delClient(realm)
			t.logf("DVR DISC realm=%#010x", realm)
		}
	case 0x13:
		// heartbeat from device
	default:
		t.logf("PTCP type=%#04x len=%d", p.Body[0], len(p.Body))
		if len(p.Body) >= 12 {
			tryRealm := binary.BigEndian.Uint32(p.Body[4:8])
			payload := p.Body[12:]
			if len(payload) > 0 && len(payload) <= 4096 {
				if c := t.getClient(tryRealm); c != nil {
					t.logf("Forwarding type 0x%02x as data to realm=%#010x (%d bytes)", p.Body[0], tryRealm, len(payload))
					c.conn.Write(payload)
				}
			}
		}
	}
}

func (t *Tunnel) fail(err error) {
	t.errMu.Lock()
	if t.failErr == nil {
		t.failErr = err
	}
	t.errMu.Unlock()
	select {
	case <-t.done:
	default:
		close(t.done)
	}
}

func (t *Tunnel) failure() error {
	t.errMu.Lock()
	defer t.errMu.Unlock()
	return t.failErr
}

// runWithRetries silently restarts a tunnel after it crashes. It allows
// RETRY_ATTEMPTS tries, logging "Tunnel failed, reason - ..., retrying
// N/3" in between. When exhausted, ports move to [FAIL] (or the legacy
// onExhausted callback is invoked for single-port mode). A 404 from the
// device (unknown serial / device off) is not retried: the notice is
// printed once and the tunnel is failed immediately.
func runWithRetries(t *Tunnel, onExhausted func(err error)) {
	for attempt := 1; ; attempt++ {
		err := t.Run()
		if err == nil {
			return
		}
		if errors.Is(err, errDeviceNotFound) {
			deviceNotFound(t.serial)
			if t.reg != nil {
				for _, idx := range t.specIdx {
					t.reg.fail(idx, err.Error())
				}
			}
			if onExhausted != nil {
				onExhausted(err)
			}
			return
		}
		if attempt > RETRY_ATTEMPTS {
			if t.reg != nil {
				for _, idx := range t.specIdx {
					t.reg.fail(idx, err.Error())
				}
			}
			if onExhausted != nil {
				onExhausted(err)
			}
			return
		}
		t.markConnecting()
		msg := fmt.Sprintf("Tunnel failed, reason - %v, retrying %d/%d", err, attempt, RETRY_ATTEMPTS)
		if t.ui != nil {
			t.ui.Below(msg)
		} else {
			fmt.Println(msg)
		}
		if t.logRetries {
			detail := fmt.Sprintf("[%s] tunnel retry %d/%d: %v", time.Now().Format(time.RFC3339), attempt, RETRY_ATTEMPTS, err)
			if t.ui != nil {
				t.ui.Below(detail)
			} else {
				fmt.Println(detail)
			}
		}
		time.Sleep(RETRY_DELAY)
		t.reset()
	}
}
