/*
 * main.go — entry point, CLI parsing and multi-port orchestration.
 *
 * The binary tunnels ports of a Dahua-style P2P camera (identified by
 * its serial number) to localhost over the DH "Dahua HTTP P2P" cloud
 * protocol. The CLI keeps Python-compatible flags and argument order
 * (the serial may be typed before any flag), so it can be dropped in
 * as a drop-in replacement for the original script.
 *
 * Three modes of operation:
 *   --decode [--decode-type dhttp|istun|ptcp] <hex> — offline dissector
 *                                          (see decode.go);
 *   single port (no --port)               — one tunnel, plain stdout;
 *   multi-port (--port ... / --threads N) — port registry + live UI,
 *                                           one tunnel per thread.
 *
 * Ports may be given as explicit local:remote pairs ("5080:80"),
 * camera-only lists ("80-85", local = ephemeral :0), or ranges. The
 * registry tracks every requested port through Connecting → OK/FAIL
 * and, on partial failure, asks the operator whether to retry the
 * failed ports or close everything.
 */

package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type PortState int

const (
	PortConnecting PortState = iota
	PortOK
	PortFAIL
)

type failEntry struct {
	idx    int
	spec   PortSpec
	reason string
}

// PortRegistry — thread-safe status book for every requested port.
//
// Tunnels report progress through okPort/fail/connecting. When the last
// Connecting port settles (pending reaches 0) a notification is pushed
// on `notify` so the orchestrator can summarise the result or prompt
// the operator about failed ports.
type PortRegistry struct {
	mu          sync.Mutex
	serial      string
	ui          *UI
	specs       []PortSpec
	states      []PortState
	reasons     []string
	actualPorts []int
	pending     int
	notify      chan struct{}
}

func newPortRegistry(serial string, specs []PortSpec, ui *UI) *PortRegistry {
	r := &PortRegistry{
		serial:      serial,
		ui:          ui,
		specs:       specs,
		states:      make([]PortState, len(specs)),
		reasons:     make([]string, len(specs)),
		actualPorts: make([]int, len(specs)),
		pending:     len(specs),
		notify:      make(chan struct{}, 1),
	}
	for i := range specs {
		r.states[i] = PortConnecting
		ui.Update(i, r.line(i, PortConnecting, ""))
	}
	return r
}

func (r *PortRegistry) line(idx int, st PortState, reason string) string {
	s := r.specs[idx]
	switch st {
	case PortOK:
		local := r.actualPorts[idx]
		if local == 0 {
			local = s.Local
		}
		return fmt.Sprintf("[OK] Obtained %s:%d -> 127.0.0.1:%d", r.serial, s.Remote, local)
	case PortFAIL:
		return fmt.Sprintf("[FAIL] Failed %s:%d | Reason: %s", r.serial, s.Remote, reason)
	default:
		return fmt.Sprintf("[..] Opening %s:%d | Connecting...", r.serial, s.Remote)
	}
}

func (r *PortRegistry) set(idx int, st PortState, reason string) {
	r.mu.Lock()
	old := r.states[idx]
	if st == PortConnecting && old != PortConnecting {
		r.pending++
	}
	if st != PortConnecting && old == PortConnecting {
		r.pending--
	}
	r.states[idx] = st
	r.reasons[idx] = reason
	line := r.line(idx, st, reason)
	pending := r.pending
	r.mu.Unlock()

	r.ui.Update(idx, line)

	if st != PortConnecting && pending == 0 {
		select {
		case r.notify <- struct{}{}:
		default:
		}
	}
}

func (r *PortRegistry) connecting(idx int) { r.set(idx, PortConnecting, "") }
func (r *PortRegistry) okPort(idx, localPort int) {
	r.mu.Lock()
	r.actualPorts[idx] = localPort
	r.mu.Unlock()
	r.set(idx, PortOK, "")
}
func (r *PortRegistry) fail(idx int, reason string) {
	r.set(idx, PortFAIL, reason)
}

func (r *PortRegistry) pendingCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.pending
}

// summary — actual local ports (after bind) + camera remote ports.
func (r *PortRegistry) summary() (remotes, locals []int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	remotes = make([]int, len(r.specs))
	locals = make([]int, len(r.specs))
	for i, s := range r.specs {
		remotes[i] = s.Remote
		locals[i] = r.actualPorts[i]
		if locals[i] == 0 {
			locals[i] = s.Local
		}
	}
	return remotes, locals
}

func (r *PortRegistry) failEntries() []failEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []failEntry
	for i := range r.specs {
		if r.states[i] == PortFAIL {
			out = append(out, failEntry{idx: i, spec: r.specs[i], reason: r.reasons[i]})
		}
	}
	return out
}

func main() {
	// Python-compatible: allow serial before flags, e.g. "dh-fwd <serial> --port ...".
	// The serial is moved to the end of os.Args so flag parsing sees only flags.
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		serial := os.Args[1]
		rest := append([]string{os.Args[0]}, os.Args[2:]...)
		rest = append(rest, serial)
		os.Args = rest
	}

	var debug, decodeMode, logRetries bool
	var dtype int
	var username, password, randsalt string
	var decodeType string
	var threads int
	var portSpec string

	flag.BoolVar(&debug, "d", false, "debug protocol output")
	flag.BoolVar(&debug, "debug", false, "debug protocol output")
	flag.IntVar(&dtype, "t", 0, "device type: 0 = no auth (default), 1 = with auth")
	flag.IntVar(&dtype, "type", 0, "device type: 0 = no auth (default), 1 = with auth")
	flag.StringVar(&username, "u", "", "username (required when --type 1)")
	flag.StringVar(&username, "username", "", "username (required when --type 1)")
	flag.StringVar(&password, "P", "", "password (required when --type 1)")
	flag.StringVar(&password, "password", "", "password (required when --type 1)")
	flag.StringVar(&randsalt, "s", "", "RandSalt from the info blob")
	flag.StringVar(&randsalt, "randsalt", "", "RandSalt from the info blob")
	flag.BoolVar(&decodeMode, "decode", false, "offline packet dissector mode")
	flag.BoolVar(&decodeMode, "D", false, "offline packet dissector mode")
	flag.StringVar(&decodeType, "decode-type", "auto", "decode type: auto, dhttp, istun, ptcp")
	flag.StringVar(&decodeType, "T", "auto", "decode type: auto, dhttp, istun, ptcp")
	flag.StringVar(&portSpec, "port", "", `port mapping "local:camera" (e.g. "5080,5081:80,81"); without ':' = camera ports only, local is random ephemeral (e.g. "80-85"); "0:81" = ephemeral local`)
	flag.StringVar(&portSpec, "p", "", `port mapping "local:camera" (e.g. "5080,5081:80,81"); without ':' = camera ports only, local is random ephemeral (e.g. "80-85"); "0:81" = ephemeral local`)
	flag.IntVar(&threads, "threads", 3, "number of parallel tunnels")
	flag.IntVar(&threads, "mt", 3, "number of parallel tunnels")
	flag.BoolVar(&logRetries, "log-retries", false, "log retry details")
	flag.BoolVar(&logRetries, "lr", false, "log retry details")
	flag.Usage = usage
	flag.Parse()

	if decodeMode {
		var input []byte
		if flag.NArg() > 0 {
			raw := strings.Join(flag.Args(), " ")
			raw = strings.NewReplacer(" ", "", "\n", "", "\t", "", "0x", "", "\\x", "").Replace(raw)
			var err error
			input, err = hex.DecodeString(raw)
			if err != nil {
				fmt.Fprintf(os.Stderr, "decode hex: %v\n", err)
				os.Exit(1)
			}
		} else {
			stat, _ := os.Stdin.Stat()
			if (stat.Mode() & os.ModeCharDevice) != 0 {
				fmt.Fprintln(os.Stderr, "usage: dh-fwd --decode [--decode-type type] <hex>")
				os.Exit(1)
			}
			buf := make([]byte, 65536)
			n, _ := os.Stdin.Read(buf)
			input = make([]byte, n)
			copy(input, buf[:n])
		}
		decodePacket(decodeType, input)
		return
	}

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}
	serial := flag.Arg(0)

	if dtype > 0 && (username == "" || password == "") {
		fmt.Fprintln(os.Stderr, "username and password required for type > 0")
		os.Exit(1)
	}

	specs, err := parsePortSpec(portSpec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "port spec: %v\n", err)
		os.Exit(1)
	}
	if threads < 1 {
		threads = 1
	}

	// Multi-port mode: several ports OR explicitly set --threads/-mt.
	// Otherwise — single-port mode without UI.
	multi := len(specs) > 1
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "threads" || f.Name == "mt" {
			multi = true
		}
	})

	if multi {
		runMulti(serial, specs, threads, dtype, username, password, randsalt, debug, logRetries)
	} else {
		runSingle(serial, specs[0], dtype, username, password, randsalt, debug, logRetries)
	}
}

// usage prints a grouped, human-readable flag reference to stderr.
func usage() {
	fmt.Fprintf(os.Stderr, `Usage: dh-fwd [options] <serial>

Tunnels ports of a Dahua P2P camera (identified by its serial number) to
localhost over the DH "Dahua HTTP P2P" cloud protocol. The serial may be
written before or after the flags.

General:
  --debug, -d             debug protocol output
  --log-retries, -lr      log retry details

Device auth:
  --type, -t <0|1>        device type: 0 = no auth (default), 1 = with auth
  --username, -u <name>   username (required when --type 1)
  --password, -P <pass>   password (required when --type 1)
  --randsalt, -s <salt>   RandSalt from the info blob

Ports:
  --port, -p <spec>       "local:camera" pairs, e.g. "5080,5081:80,81";
                          without ':' = camera ports only, local is random
                          ephemeral (e.g. "80-85"); "0:81" = ephemeral local.
                          Default: one tunnel 554:554
  --threads, -mt <n>      number of parallel tunnels (default 3)

Decode:
  --decode, -D            offline packet dissector (reads hex from argv or stdin)
  --decode-type, -T <t>   packet layer: auto, dhttp, istun, ptcp (default "auto")

Examples:
  dh-fwd 4E0743BPAGFE388 -p 5080,5081:80,81
  dh-fwd 4E0743BPAGFE388 -t 1 -u admin -P secret -p 5080:554
  dh-fwd -D -T ptcp 01000f12...
`)
}

/* ---------- Port spec parsing ---------- */

// parsePortSpec resolves the effective port list: the --port flag wins,
// otherwise one default tunnel (local 554 <-> camera 554).
func parsePortSpec(portSpec string) ([]PortSpec, error) {
	if portSpec != "" {
		locals, remotes, err := parsePortLists(portSpec)
		if err != nil {
			return nil, err
		}
		return makePortSpecs(locals, remotes)
	}
	return []PortSpec{{Local: 554, Remote: 554}}, nil
}

// parsePortLists splits a "--port" spec into local and camera (remote) lists:
//   - "l1,l2,l3:r1,r2,r3" — explicit pairs, 0 as local = ephemeral port;
//   - "8081" or "80-85" without ':' — CAMERA ports only, local is always
//     ephemeral (:0, the OS assigns a free port).
func parsePortLists(spec string) (locals, remotes []int, err error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil, fmt.Errorf("empty port spec")
	}
	parts := strings.SplitN(spec, ":", 2)
	if len(parts) == 2 {
		locals, err = parseIntList(parts[0])
		if err != nil {
			return nil, nil, fmt.Errorf("invalid local ports %q: %v", parts[0], err)
		}
		remotes, err = parseIntList(parts[1])
		if err != nil {
			return nil, nil, fmt.Errorf("invalid remote ports %q: %v", parts[1], err)
		}
		return locals, remotes, nil
	}
	remotes, err = parseIntList(spec)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid camera ports %q: %v", spec, err)
	}
	if len(remotes) == 0 {
		return nil, nil, fmt.Errorf("no ports specified")
	}
	locals = make([]int, len(remotes))
	return locals, remotes, nil
}

func parseIntList(s string) ([]int, error) {
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if loStr, hiStr, ok := strings.Cut(part, "-"); ok {
			lo, err := strconv.Atoi(strings.TrimSpace(loStr))
			if err != nil {
				return nil, err
			}
			hi, err := strconv.Atoi(strings.TrimSpace(hiStr))
			if err != nil {
				return nil, err
			}
			if lo < 1 || hi > 65535 || lo > hi {
				return nil, fmt.Errorf("invalid range %q", part)
			}
			for v := lo; v <= hi; v++ {
				out = append(out, v)
			}
			continue
		}
		v, err := strconv.Atoi(part)
		if err != nil {
			return nil, err
		}
		if v < 0 || v > 65535 {
			return nil, fmt.Errorf("port out of range: %d", v)
		}
		out = append(out, v)
	}
	return out, nil
}

func makePortSpecs(locals, remotes []int) ([]PortSpec, error) {
	if len(locals) == 0 {
		return nil, fmt.Errorf("no local ports specified")
	}
	for _, r := range remotes {
		if r == 0 {
			return nil, fmt.Errorf("remote port cannot be 0")
		}
	}
	if len(remotes) == 1 {
		r := remotes[0]
		specs := make([]PortSpec, len(locals))
		for i, l := range locals {
			specs[i] = PortSpec{Local: l, Remote: r}
		}
		return specs, nil
	}
	if len(locals) != len(remotes) {
		return nil, fmt.Errorf("port count mismatch: %d local vs %d remote", len(locals), len(remotes))
	}
	specs := make([]PortSpec, len(locals))
	for i := range locals {
		specs[i] = PortSpec{Local: locals[i], Remote: remotes[i]}
	}
	return specs, nil
}

func runSingle(serial string, spec PortSpec, dtype int, username, password, randsalt string, debug, logRetries bool) {
	g := specGroup{idxs: []int{0}, specs: []PortSpec{spec}}
	t := newTunnel(serial, dtype, username, password, randsalt, debug, logRetries, g, nil)
	runWithRetries(t, func(err error) {
		if errors.Is(err, errDeviceNotFound) {
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Tunnel failed, reason - %v, giving up after %d attempts\n", err, RETRY_ATTEMPTS)
		os.Exit(1)
	})
}

/* ---------- Tunnel orchestration ---------- */

// verifyDevice checks the serial is both registered with the cloud and
// actually reachable BEFORE any tunnel is brought up. The p2psrv online
// lookup alone passes even for powered-off devices, so the check goes one
// step further and probes the /device/<sn>/p2p-channel endpoint exactly
// like the real handshake: an offline or unknown device answers 404, which
// is caught here instead of surfacing as per-port [FAIL] spam.
func verifyDevice(serial string, dtype int, username, password, randsalt string, debug bool) bool {
	u := NewUDP(MAIN_SERVER, MAIN_PORT, debug)
	defer u.Close()
	u.Request("/probe/p2psrv", "", true, true)
	res, err := u.Request(fmt.Sprintf("/online/p2psrv/%s", serial), "", true, true)
	if err != nil {
		return false
	}
	if res == nil || res.Code >= 400 {
		return false
	}
	if res.Body["body/US"] == "" {
		return false
	}

	aid := make([]byte, 8)
	rand.Read(aid)
	body, _ := p2pChannelBody(u.lport, dtype, username, password, randsalt, aid)
	u.Request(fmt.Sprintf("/device/%s/p2p-channel", serial), body, true, false)
	res, err = u.Read(true, 30*time.Second)
	if err == nil && res.Code < 200 {
		res, err = u.Read(true, 30*time.Second)
	}
	if err != nil {
		return false
	}
	return res.Code < 400
}

func distribute(specs []PortSpec, threads int) []specGroup {
	groups := make([]specGroup, threads)
	for i, s := range specs {
		g := i % threads
		groups[g].idxs = append(groups[g].idxs, i)
		groups[g].specs = append(groups[g].specs, s)
	}
	return groups
}

// runMulti — the multi-port dashboard. Specs are round-robin distributed
// across `threads` tunnels (each tunnel opens several ports over one PTCP
// channel). It then blocks on the registry, summarising when everything
// settles and offering to retry/close on partial failure.
func runMulti(serial string, specs []PortSpec, threads int, dtype int, username, password, randsalt string, debug, logRetries bool) {
	if !verifyDevice(serial, dtype, username, password, randsalt, debug) {
		deviceNotFound(serial)
		os.Exit(1)
	}

	ui := NewUI(os.Stdout)
	ui.Start(fmt.Sprintf("Opening %d ports on %s | Threads: %d", len(specs), serial, threads), len(specs))
	reg := newPortRegistry(serial, specs, ui)

	var live sync.Map
	for _, g := range distribute(specs, threads) {
		if len(g.idxs) == 0 {
			continue
		}
		t := newTunnel(serial, dtype, username, password, randsalt, debug, logRetries, g, reg)
		for _, idx := range g.idxs {
			live.Store(idx, t)
		}
		go runWithRetries(t, nil)
	}

	summarized := false
	for {
		<-reg.notify
		if reg.pendingCount() > 0 {
			continue
		}
		fails := reg.failEntries()
		if len(fails) > 0 {
			allNotFound := true
			for _, f := range fails {
				if !isNotFound(f.reason) {
					allNotFound = false
					break
				}
			}
			if allNotFound {
				// The serial is unknown or the device is off — retrying or
				// asking the operator is pointless, close and leave.
				deviceNotFound(serial)
				live.Range(func(k, v any) bool {
					v.(*Tunnel).close()
					return true
				})
				os.Exit(1)
			}
			switch showFailPrompt(serial, fails, ui) {
			case 'c':
				live.Range(func(k, v any) bool {
					v.(*Tunnel).close()
					return true
				})
				os.Exit(0)
			case 'r':
				for _, f := range fails {
					reg.connecting(f.idx)
					g := specGroup{idxs: []int{f.idx}, specs: []PortSpec{f.spec}}
					t := newTunnel(serial, dtype, username, password, randsalt, debug, logRetries, g, reg)
					live.Store(f.idx, t)
					go runWithRetries(t, nil)
				}
				summarized = false
			}
			continue
		}
		if !summarized {
			printSummary(serial, reg, ui)
			summarized = true
		}
	}
}

func printSummary(serial string, reg *PortRegistry, ui *UI) {
	remotes, locals := reg.summary()
	ui.Below(fmt.Sprintf("Obtained %d ports on %s:%s | localhost:%s",
		len(remotes), serial, formatRange(remotes), formatList(locals)))
}

func formatRange(ports []int) string {
	p := append([]int{}, ports...)
	sort.Ints(p)
	var b strings.Builder
	for i := 0; i < len(p); {
		j := i
		for j+1 < len(p) && p[j+1] == p[j]+1 {
			j++
		}
		if j == i {
			fmt.Fprintf(&b, "%d", p[i])
		} else {
			fmt.Fprintf(&b, "%d-%d", p[i], p[j])
		}
		if j+1 < len(p) {
			b.WriteString(",")
		}
		i = j + 1
	}
	return b.String()
}

func formatList(ports []int) string {
	s := make([]string, len(ports))
	for i, p := range ports {
		s[i] = strconv.Itoa(p)
	}
	return strings.Join(s, ",")
}

func showFailPrompt(serial string, fails []failEntry, ui *UI) byte {
	sep := strings.Repeat("!", 81)
	reasons := make([]string, len(fails))
	for i, f := range fails {
		reasons[i] = fmt.Sprintf("%d: %s", f.spec.Remote, f.reason)
	}
	ui.Below(sep)
	ui.Below(fmt.Sprintf("Failed to obtain port(s) on %s. Reasons: %s", serial, strings.Join(reasons, "; ")))
	ui.Below(sep)

	reader := bufio.NewReader(os.Stdin)
	for {
		ui.Below(fmt.Sprintf("Retry failed ports or close ALL connections to %s? (r/c)", serial))
		line, err := reader.ReadString('\n')
		if err != nil {
			return 'c'
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "r":
			return 'r'
		case "c":
			return 'c'
		}
	}
}
