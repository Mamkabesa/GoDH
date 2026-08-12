/*
 * helpers.go — protocol primitives shared by the whole tool.
 *
 * Four layers are implemented here:
 *
 *  1. Credentials & crypto — get_key / get_enc / get_dec / get_auth:
 *     the DH auth chain. The password is turned into a hex MD5 key,
 *     LocalAddr is encrypted with PBKDF2-derived AES-OFB (type 1
 *     devices), and the final auth token is an HMAC-SHA256 over
 *     "<nonce><date><payload>".
 *
 *  2. PTCP framing — PTCP is Dahua's "Phony TCP": a 24-byte header
 *     carrying byte/message sequence state, followed by a body. The
 *     DATA body itself wraps a PTCPPayload (realm + stream bytes), the
 *     per-connection channel inside the PTCP session.
 *
 *  3. DH HTTP-over-UDP — requests like DHPOST /device/<sn>/p2p-channel
 *     are plain HTTP/1.1 text over a UDP socket. DHResponse +
 *     ParseDHResponse turn the reply into status + headers + an
 *     XML-flattened body map (parseXML).
 *
 *  4. UDP socket wrapper — UDP holds one socket, its local/remote
 *     addresses and the PTCP sequence state machine (sent/recv byte
 *     counters, packet ids, message ids), plus the DH HTTP request /
 *     response helpers built on top of it.
 */

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// MAIN_SERVER / MAIN_PORT — the DH cloud registrar every session
	// starts from: device discovery, p2p-channel and relay lookups.
	MAIN_SERVER = "www.easy4ipcloud.com"
	MAIN_PORT   = 8800

	// Shared client credentials baked into the DH WSSE auth. RANDSALT
	// can be overridden per-run via --randsalt (e.g. from an info blob).
	USERNAME = "cba1b29e32cb17aa46b8ff9e73c7f40b"
	USERKEY  = "996103384cdf19179e19243e959bbf8b"
	RANDSALT = ""
	IV       = "2z52*lk9o6HRyJrf"
)

var (
	cseqLock sync.Mutex
	cseq     uint32
)

/* ---------- DH auth chain ---------- */

// get_key derives the 32-hex MD5 key from username, password and salt.
func get_key(username, password, randsalt string) []byte {
	salt := randsalt
	if salt == "" {
		salt = RANDSALT
	}
	h := md5.Sum([]byte(fmt.Sprintf("%s:Login to %s:%s", username, salt, password)))
	hex := fmt.Sprintf("%X", h)
	return []byte(hex)
}

func get_nonce() int {
	n, _ := rand.Int(rand.Reader, big.NewInt(1<<31))
	return int(n.Int64())
}

func get_enc(key []byte, nonce int, data string) string {
	salt := []byte(strconv.Itoa(nonce))
	dk := pbkdf2.Key(key, salt, 20000, 32, sha256.New)

	block, _ := aes.NewCipher(dk)
	stream := cipher.NewOFB(block, []byte(IV))

	out := make([]byte, len(data))
	stream.XORKeyStream(out, []byte(data))
	return base64.StdEncoding.EncodeToString(out)
}

func get_dec(key []byte, nonce int, data string) string {
	salt := []byte(strconv.Itoa(nonce))
	dk := pbkdf2.Key(key, salt, 20000, 32, sha256.New)

	block, _ := aes.NewCipher(dk)
	stream := cipher.NewOFB(block, []byte(IV))

	raw, _ := base64.StdEncoding.DecodeString(data)
	out := make([]byte, len(raw))
	stream.XORKeyStream(out, raw)
	return string(out)
}

func get_auth(username string, key []byte, nonce int, payload, randsalt string) string {
	salt := randsalt
	if salt == "" {
		salt = RANDSALT
	}
	curdate := time.Now().Unix()

	msg := []byte(fmt.Sprintf("%d%d%s", nonce, curdate, payload))
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	auth := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	return fmt.Sprintf(
		"<CreateDate>%d</CreateDate><DevAuth>%s</DevAuth><Nonce>%d</Nonce><RandSalt>%s</RandSalt><UserName>%s</UserName>",
		curdate, auth, nonce, salt, username,
	)
}

/* ---------- PTCP framing ---------- */

// PTCPPayload is the DATA carrier inside a PTCP body: a 32-bit realm
// (the per-connection channel id) followed by the raw stream bytes.
// The high bit of the length field is the "more data" marker.
type PTCPPayload struct {
	Realm   uint32
	Payload []byte
}

func (p *PTCPPayload) Bytes() []byte {
	length := len(p.Payload) | 0x10000000
	buf := make([]byte, 12+len(p.Payload))
	binary.BigEndian.PutUint32(buf[0:4], uint32(length))
	binary.BigEndian.PutUint32(buf[4:8], p.Realm)
	binary.BigEndian.PutUint32(buf[8:12], 0)
	copy(buf[12:], p.Payload)
	return buf
}

func ParsePTCPPayload(data []byte) (*PTCPPayload, error) {
	if len(data) < 12 {
		return nil, errors.New("packet too short")
	}
	length := binary.BigEndian.Uint32(data[0:4])
	realm := binary.BigEndian.Uint32(data[4:8])
	pad := binary.BigEndian.Uint32(data[8:12])
	if pad != 0 {
		return nil, errors.New("invalid padding")
	}
	length &= 0xFFFF
	body := data[12:]
	if len(body) != int(length) {
		return nil, errors.New("invalid length")
	}
	return &PTCPPayload{Realm: realm, Payload: body}, nil
}

// PTCP is the 24-byte "Phony TCP" envelope that rides over UDP:
//   [0:4]   magic "PTCP"
//   [4:8]   Rlid — remote byte counter (how many bytes the peer sent)
//   [8:12]  Llid — local byte counter (how many bytes we sent)
//   [12:16] Pid  — packet id
//   [16:20] Lmid — local message id
//   [20:24] Rmid — remote message id
//   [24:]   Body
// Byte counters act as a UDP retransmission/ordering window; every
// received frame must be acknowledged by echoing it back (see UDP).
type PTCP struct {
	Rlid uint32
	Llid uint32
	Pid  uint32
	Lmid uint32
	Rmid uint32
	Body []byte
}

func (p *PTCP) Bytes() []byte {
	buf := make([]byte, 24+len(p.Body))
	copy(buf[0:4], []byte("PTCP"))
	binary.BigEndian.PutUint32(buf[4:8], p.Rlid)
	binary.BigEndian.PutUint32(buf[8:12], p.Llid)
	binary.BigEndian.PutUint32(buf[12:16], p.Pid)
	binary.BigEndian.PutUint32(buf[16:20], p.Lmid)
	binary.BigEndian.PutUint32(buf[20:24], p.Rmid)
	copy(buf[24:], p.Body)
	return buf
}

func ParsePTCP(data []byte) (*PTCP, error) {
	if len(data) < 24 {
		return nil, errors.New("packet too short")
	}
	if string(data[0:4]) != "PTCP" {
		return nil, errors.New("invalid magic")
	}
	return &PTCP{
		Rlid: binary.BigEndian.Uint32(data[4:8]),
		Llid: binary.BigEndian.Uint32(data[8:12]),
		Pid:  binary.BigEndian.Uint32(data[12:16]),
		Lmid: binary.BigEndian.Uint32(data[16:20]),
		Rmid: binary.BigEndian.Uint32(data[20:24]),
		Body: data[24:],
	}, nil
}

/* ---------- DH HTTP-over-UDP ---------- */

// DHResponse is a parsed reply to a DH request: HTTP status line,
// headers and the XML body flattened into "tag/path" -> text pairs.
type DHResponse struct {
	Version string
	Code    int
	Status  string
	Headers map[string]string
	Body    map[string]string
}

func ParseDHResponse(data string) *DHResponse {
	parts := strings.SplitN(data, "\r\n\r\n", 2)
	headPart := parts[0]
	bodyPart := ""
	if len(parts) > 1 {
		bodyPart = strings.TrimSpace(parts[1])
	}

	lines := strings.Split(headPart, "\r\n")
	statusParts := strings.SplitN(lines[0], " ", 3)
	code, _ := strconv.Atoi(statusParts[1])

	headers := make(map[string]string)
	for _, line := range lines[1:] {
		if hd := strings.SplitN(line, ": ", 2); len(hd) == 2 {
			headers[hd[0]] = hd[1]
		}
	}

	resp := &DHResponse{
		Version: statusParts[0],
		Code:    code,
		Status:  statusParts[2],
		Headers: headers,
	}

	if bodyPart != "" {
		resp.Body = parseXML(bodyPart)
	}

	return resp
}

/* ---------- UDP socket wrapper ---------- */

// UDP wraps one UDP socket with DH HTTP request/reply helpers and the
// PTCP sequence state. Concurrency contract: PTCP counters are guarded
// by ptcpMu; the socket itself must have a single reader goroutine
// (see Tunnel.readLoop) so SetReadDeadline never races.
type UDP struct {
	conn *net.UDPConn

	lhost string
	lport int

	rhost string
	rport int

	raddr *net.UDPAddr
	debug bool

	ptcpMu    sync.Mutex
	ptcpSent  uint32
	ptcpRecv  uint32
	ptcpCount uint32
	ptcpID    uint32
	rmid      uint32

	lastRecv time.Time
	debugLog func(format string, args ...any)
}

func NewUDP(host string, port int, debug bool) *UDP {
	conn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	local := conn.LocalAddr().(*net.UDPAddr)

	u := &UDP{
		conn:  conn,
		lhost: local.IP.String(),
		lport: local.Port,
		rhost: host,
		rport: port,
		debug: debug,
	}

	if host != "" {
		raddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", host, port))
		u.raddr = raddr
	}

	return u
}

func (u *UDP) String() string {
	return fmt.Sprintf(":%d", u.lport)
}

func (u *UDP) Close() {
	u.conn.Close()
}

func (u *UDP) SetRemote(host string, port int) {
	u.rhost = host
	u.rport = port
	u.raddr, _ = net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", host, port))
}

func (u *UDP) Send(data []byte) {
	if u.raddr != nil {
		u.conn.WriteTo(data, u.raddr)
	}
}

func (u *UDP) SendTo(data []byte, addr *net.UDPAddr) {
	u.conn.WriteTo(data, addr)
}

func (u *UDP) Recv(bufsize int, timeout time.Duration) ([]byte, error) {
	if timeout > 0 {
		u.conn.SetReadDeadline(time.Now().Add(timeout))
	} else {
		u.conn.SetReadDeadline(time.Time{})
	}

	buf := make([]byte, bufsize)
	n, _, err := u.conn.ReadFromUDP(buf)
	if err != nil {
		return nil, err
	}
	u.lastRecv = time.Now()
	return buf[:n], nil
}

func (u *UDP) RecvFrom(bufsize int) ([]byte, *net.UDPAddr, error) {
	buf := make([]byte, bufsize)
	n, addr, err := u.conn.ReadFromUDP(buf)
	if err != nil {
		return nil, nil, err
	}
	u.lastRecv = time.Now()
	return buf[:n], addr, nil
}

func (u *UDP) LastRecv() time.Time {
	return u.lastRecv
}

func (u *UDP) logf(format string, args ...any) {
	if u.debugLog != nil {
		u.debugLog(format, args...)
		return
	}
	fmt.Printf(format, args...)
	fmt.Println()
}

func (u *UDP) SetTimeout(d time.Duration) {
	if d > 0 {
		u.conn.SetReadDeadline(time.Now().Add(d))
	} else {
		u.conn.SetReadDeadline(time.Time{})
	}
}

func (u *UDP) Read(returnError bool, timeout time.Duration) (*DHResponse, error) {
	data, err := u.Recv(4096, timeout)
	if err != nil {
		return nil, err
	}

	if u.debug {
		u.logf(":%d <<< %s:%d\n%s", u.lport, u.rhost, u.rport, string(data))
	}

	res := ParseDHResponse(string(data))

	if !returnError && res.Code >= 400 {
		return nil, fmt.Errorf("error %d: %s", res.Code, res.Status)
	}

	if u.debug {
		u.logf("Parsed <<< code=%d status=%s", res.Code, res.Status)
	}

	return res, nil
}

func (u *UDP) Request(path, body string, auth, shouldRead bool) (*DHResponse, error) {
	cseqLock.Lock()
	cseq++
	myCseq := cseq
	cseqLock.Unlock()

	nonce, _ := rand.Int(rand.Reader, big.NewInt(1<<31))
	curdate := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	pwd := fmt.Sprintf("%d%sDHP2P:%s:%s", nonce, curdate, USERNAME, USERKEY)

	h := sha1.New()
	h.Write([]byte(pwd))
	digest := base64.StdEncoding.EncodeToString(h.Sum(nil))

	method := "DHGET"
	if body != "" {
		method = "DHPOST"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\nCSeq: %d\r\n", method, path, myCseq))
	if auth {
		sb.WriteString(fmt.Sprintf(
			"Authorization: WSSE profile=\"UsernameToken\"\r\nX-WSSE: UsernameToken Username=\"%s\", PasswordDigest=\"%s\", Nonce=\"%d\", Created=\"%s\"\r\n",
			USERNAME, digest, nonce, curdate,
		))
	}
	if body != "" {
		sb.WriteString(fmt.Sprintf("Content-Type: \r\nContent-Length: %d\r\n", len(body)))
	}
	sb.WriteString(fmt.Sprintf("\r\n%s", body))

	req := sb.String()

	if u.debug {
		u.logf(":%d >>> %s:%d\n%s", u.lport, u.rhost, u.rport, req)
	}

	u.Send([]byte(req))

	if shouldRead {
		return u.Read(false, 30*time.Second)
	}
	return nil, nil
}

func (u *UDP) ReadPTCP(timeout time.Duration) (*PTCP, error) {
	data, err := u.Recv(4096, timeout)
	if err != nil {
		return nil, err
	}

	ptcp, err := ParsePTCP(data)
	if err != nil {
		return nil, err
	}

	u.ptcpMu.Lock()
	if ptcp.Rlid+uint32(len(ptcp.Body)) > u.ptcpRecv {
		u.ptcpRecv = ptcp.Rlid + uint32(len(ptcp.Body))
	}
	u.rmid = ptcp.Lmid
	u.ptcpMu.Unlock()

	return ptcp, nil
}

func (u *UDP) RequestPTCP(body []byte) {
	u.ptcpMu.Lock()
	defer u.ptcpMu.Unlock()

	pid := uint32(0x0002FFFF)
	if string(body) != "\x00\x03\x01\x00" {
		pid = 0x0000FFFF - (u.ptcpCount % 0x10000)
	}

	ptcp := &PTCP{
		Rlid: u.ptcpSent,
		Llid: u.ptcpRecv,
		Pid:  pid,
		Lmid: u.ptcpID,
		Rmid: u.rmid,
		Body: body,
	}

	u.ptcpSent += uint32(len(body))
	u.ptcpID++
	if len(body) > 0 && string(body) != "\x00\x03\x01\x00" {
		u.ptcpCount++
	}

	raw := ptcp.Bytes()
	u.Send(raw)
}

func parseXML(data string) map[string]string {
	result := make(map[string]string)
	decoder := xml.NewDecoder(strings.NewReader(data))
	var stack []string

	for {
		tok, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		switch t := tok.(type) {
		case xml.StartElement:
			stack = append(stack, t.Name.Local)
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			text := strings.TrimSpace(string(t))
			if text != "" && len(stack) > 0 {
				key := strings.Join(stack, "/")
				result[key] = text
			}
		}
	}

	return result
}

func GetInvertedBytes(data []byte) []byte {
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = ^b
	}
	return out
}
