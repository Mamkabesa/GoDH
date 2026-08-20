# DH-FWD

Tunnels Dahua P2P camera ports (by serial number) to localhost via the DH "Dahua HTTP P2P" cloud protocol. Essentially a drop-in replacement for the original Python script — rewritten in Go, fully CLI-compatible.

Just one dependency — `golang.org/x/crypto`.

## Features

- **Single tunnel** or **multi-port mode** — forward several camera ports to different local ports at once, over parallel PTCP channels (3 by default).
- **NAT traversal** (inverted STUN), with an automatic fallback to relay if the camera doesn't respond.
- **Live device check before multi-port mode**: a dead or non-existent serial (`404`) is caught immediately, no retries wasted on it.
- **Automatic tunnel retries** (3 attempts) on channel failure, with ports marked `[FAIL]` and a retry/close prompt in multi-port mode.
- **Offline packet dissector** (`--decode`) for DH HTTP, inverted STUN, and PTCP.
- Keeps the connection alive: **PTCP heartbeat** every 5s and **RTSP keepalive** (`OPTIONS * RTSP/1.0`) for idle clients (every 25s).
- Serial number can go either before or after the flags, just like the original script.

## Build

Requires Go 1.22+ (newer versions work too).

```sh
go build -o dh-fwd .
# tests
go test ./...
# static analysis
go vet ./...
```

## Usage

```
dh-fwd [options] <serial>
```

The serial can be placed before the flags — the program moves it to the end automatically for compatibility with the original script:

```sh
./dh-fwd 4E0743BPAGFE388 -p 5080,5081:80,81
```

### Flags

| Flag | Short | Description |
|------|----------|----------|
| `--debug` | `-d` | verbose protocol debug output (requests, STUN packets, PTCP frames) |
| `--log-retries` | `-lr` | detailed retry log with timestamps |
| `--type` | `-t` | device type: `0` — no auth (default), `1` — with auth |
| `--username` | `-u` | username (for `--type 1`) |
| `--password` | `-P` | password (for `--type 1`) |
| `--randsalt` | `-s` | RandSalt from the info blob (for `--type 1`) |
| `--port` | `-p` | port list, see below |
| `--threads` | `-mt` | number of parallel tunnels (default 3) |
| `--decode` | `-D` | packet dissector mode |
| `--decode-type` | `-T` | decode layer: `auto`, `dhttp`, `istun`, `ptcp` (default `auto`) |

`--help`/`-h` prints grouped help with examples.

### Port spec (`--port`)

- `-p 5080,5081,5082:80,81,82` — explicit `local:camera` pairs, one to one;
- `-p 8080,8081,8082:80` — several local ports to one camera port;
- `-p 80-85` — camera ports only, local ports assigned randomly (ephemeral);
- `0:81` — local port `0` means "ephemeral";
- ranges also work: `-p 8080-8082:80-82`;
- without `--port` — a single `554:554` (RTSP) tunnel is opened.

Local ports listen on `0.0.0.0`; the camera's traffic is delivered to `127.0.0.1:<local>`.

### Modes

**Single** — one port, no UI, plain stdout output:
```sh
./dh-fwd 4E0743BPAGFE388 -p 5080:80
```

**Multi** — a status dashboard for the ports. Kicks in automatically with multiple ports, or when `-mt` is set explicitly:
```sh
./dh-fwd 4E0743BPAGFE388 -p 5080,5081:80,81 -mt 4
```
```
Opening 2 ports on 4E0743BPAGFE388 | Threads: 3
[..] Opening 4E0743BPAGFE388:80 | Connecting...
[OK] Obtained 4E0743BPAGFE388:80 -> 127.0.0.1:5080
[OK] Obtained 4E0743BPAGFE388:81 -> 127.0.0.1:5081
Obtained 2 ports on 4E0743BPAGFE388:80,81 | localhost:5080,5081
```

**Decode** — parses a captured packet offline:
```sh
./dh-fwd -D -T ptcp <hex>
./dh-fwd -D -T auto 0x... 0x...
echo '<hex>' | ./dh-fwd -D
```

### Error handling

- **Serial doesn't exist or the camera is off** (`404`) — no retries, just a single line:
  ```
  4E0743BPAGFE389 isn't exist or turned off.
  ```
- **Camera requires authentication** (`403`) — add `-t 1 -u <user> -P <pass>`:
  ```sh
  ./dh-fwd <sn> -t 1 -u <user> -P <pass> -p ...
  ```
- **Some ports fail to come up** — once retries are exhausted, those ports are marked `[FAIL]`, and the tool asks whether to retry (`r`) or close everything (`c`).

## How it works

DH P2P is Dahua's cloud protocol: the camera keeps a persistent UDP connection to the cloud, and the client learns how to reach it through that same cloud. GoDH walks the full path: discovery → relay session → channel registration → NAT traversal attempt → either a direct connection or relay fallback → and finally port tunneling.

### 1. Discovery

Everything starts at the registrar `www.easy4ipcloud.com:8800`:

- `DHGET /probe/p2psrv` — check that the cloud is reachable at all;
- `DHGET /online/p2psrv/<sn>` — find the P2P server the camera is attached to (the address comes back in `body/US`);
- on that server — `DHGET /probe/device/<sn>` and `DHGET /info/device/<sn>` (the info blob contains, among other things, the RandSalt used for auth via `-s`).

### 2. Relay session (always established)

Even if a direct connection ends up working, the relay session is set up first anyway — it hands out the credentials PTCP needs:

- `DHGET /online/relay` — get the relay agent's address;
- `DHPOST /relay/agent` — get a `Token` and `Agent`;
- `DHPOST /relay/start/<token>` on the agent — opens a PTCP session;
- `0x17` token exchange: the client sends `0x17`, the agent replies with a body containing the **sign token** — a kind of pass used later in the direct PTCP handshake (`0x19`).

### 3. Channel registration

`DHPOST /device/<sn>/p2p-channel` on the main server, with body:

```
<body><Identify><aid1> <aid2> ... </Identify><IpEncrpt>true</IpEncrpt>
<LocalAddr>127.0.0.1:<lport></LocalAddr><version>5.0.0</version></body>
```

- `Identify` — 8 random bytes (AID); `invAid = ^AID` is derived from it for STUN;
- for `--type 1`, `<IpEncrpt>` is replaced by `<IpEncrptV2>` with an AES-encrypted `LocalAddr` and an auth block (`get_auth`). The key is derived via `get_key`/`get_enc` (details below);
- the response contains `LocalAddr` (the camera's address inside its own NAT), `PubAddr` (public address), and for type 1, also a `Nonce` used for decryption.

At this point the camera learns the client's address and starts pushing a STUN init toward it — even if things end up falling back to relay anyway.

### 4. NAT traversal (inverted STUN)

Dahua's twist: the entire STUN packet is bit-inverted (`^b`):

- the client sends a STUN init with magic `FF FE FF E7`, a cookie, transaction ID, its own inverted address (`eaddr`), and `invAid` — to both the camera's `LocalAddr` and `PubAddr`;
- the init is retransmitted up to 2 times, with a 10-second wait window;
- if the camera sends its own cross-STUN init (`FF FE FF E7`), the client replies with `FE FE FF E7` using the same cookie/transaction ID (essentially two NAT hosts "shaking hands" through their respective providers);
- once the camera replies `FE FE FF E7`, the client sends confirmation `FE FE FF F3` (5 times), drains any leftovers, and moves on to the direct PTCP handshake.

**Fallback:** if there's no response within 10 seconds, a direct connection isn't possible. By this point the relay session is already up, the camera has received the agent's address via `DHPOST /device/<sn>/relay-channel`, and all traffic simply flows through `mainRemote` — the same cloud relay. The channel still works fine, just not directly.

### 5. PTCP authentication

PTCP ("Phony TCP") is roughly TCP over UDP:

- `00 03 01 00` — sync, expects the same in response;
- `0x19` + the sign token from step 2 — hands over the "pass", expects `0x1A`;
- `0x1B` — final handshake step, expects an empty body.

After this the channel is considered authenticated, and both sides move into data-transfer mode.

### 6. Serving: realms, bind, heartbeat

Multiple ports are multiplexed inside a single channel via **realms** — 32-bit connection IDs:

- a `realmID` is generated for each new local TCP connection; the client registers it immediately (so early data from the camera isn't lost), then sends `0x11 BIND` with the realm and the target camera port;
- the camera confirms the bind with `0x12 STATUS` (10-second timeout; a failed bind only kills that one connection, the channel stays alive);
- data is wrapped in a `PTCPPayload` (realm + bytes) and sent as `0x10 DATA`; traffic coming back from the camera is routed by realm;
- when the client disconnects, `0x12` is sent with a `DISC` tag;
- **heartbeat**: every 5 seconds — an empty frame to the relay and `0x13 HEARTBEAT` on the main socket; if the main socket goes silent for more than 10 seconds, the tunnel is considered dead (triggering retries);
- **RTSP keepalive**: idle clients (>25s) get an `OPTIONS * RTSP/1.0` — otherwise DVR cameras drop the connection on timeout.

### Auth crypto chain (type 1)

1. **`get_key`** — `MD5("<user>:Login to <salt>:<pass>")`, result in uppercase hex. Salt comes from `--randsalt` or the built-in `RANDSALT`.
2. **`get_enc`/`get_dec`** — `PBKDF2-HMAC-SHA256(key, nonce, 20000 iterations, 32 bytes)` → `AES-OFB` with IV `2z52*lk9o6HRyJrf` → base64. Used to encrypt `LocalAddr` and decrypt the camera's response.
3. **`get_auth`** — `HMAC-SHA256(key)` over `"<nonce><unix-date><payload>"` → base64, wrapped in XML (`<CreateDate><DevAuth><Nonce><RandSalt><UserName>`).

For unauthenticated requests (`--type 0`), both body and address travel in plain text.

### DH HTTP-over-UDP

All cloud requests are plain HTTP/1.1 over UDP, using `DHGET`/`DHPOST` methods:

```
DHPOST /device/4E0743BPAGFE388/p2p-channel HTTP/1.1
CSeq: 1
Authorization: WSSE profile="UsernameToken"
X-WSSE: UsernameToken Username="<user>", PasswordDigest="<sha1-base64>", Nonce="<n>", Created="<date>"

<body>...
```

The WSSE digest is `SHA1` of `<nonce><date>DHP2P:<USERNAME>:<USERKEY>`, then base64-encoded. The client credentials (USERNAME/USERKEY) are hardcoded — this is the DH cloud's shared client.

### PTCP frame header

24 bytes:

| Offset | Field | Meaning |
|----------|------|-------|
| `0:4` | magic | `PTCP` |
| `4:8` | `Rlid` | bytes sent by the peer (ack) |
| `8:12` | `Llid` | bytes sent by us |
| `12:16` | `Pid` | packet ID (decreasing counter) |
| `16:20` | `Lmid` | local message ID |
| `20:24` | `Rmid` | remote message ID |
| `24:` | body | payload |

The byte counters act as a retransmission/ordering window on top of UDP — every received frame must be acknowledged with an echo (see `UDP.RequestPTCP`). The `PTCPPayload` inside `0x10 DATA` carries the realm plus stream bytes; the high bit of the length field flags "more data follows".

## Architecture

| File | Purpose |
|------|------------|
| `main.go` | entry point: CLI, port parser, single/multi orchestration, `PortRegistry`, custom `usage()` |
| `tunnel.go` | core: full handshake (discovery → relay → channel → STUN → PTCP-auth), connection serving, retries, 404 handling |
| `helpers.go` | crypto (MD5/PBKDF2/AES-OFB/HMAC), PTCP framing, DH HTTP-over-UDP, `UDP` wrapper |
| `decode.go` | offline packet dissector (`--decode`) |
| `ui.go` | serialized line output (writer goroutine + channel) |
| `ports_test.go` | unit tests for the port parser |

### Internals

- **Concurrency contracts** (`tunnel.go`): exactly one reader goroutine per UDP socket (owns the socket and PTCP counters), one heartbeat goroutine, and one goroutine per accepted TCP connection. PTCP counters are protected by `ptcpMu`, the client registry by `clientsMu`.
- **Constants**: `BIND_TIMEOUT=10s`, `HEARTBEAT_TIMEOUT=10s`, `RETRY_ATTEMPTS=3`, `RETRY_DELAY=2s`, `CSEQ_BASE=100`, `CSEQ_STEP=1000`.
- **Retries** (`runWithRetries`): up to 3 attempts with a 2-second pause if a tunnel drops; ports go back to `Connecting` between attempts. A `404` from the device is never retried — an unknown serial or an off camera won't get better on retry.
- **`verifyDevice`** (`main.go`): before starting multi-port mode, the serial is checked using the same `p2p-channel` call as the real handshake — so a `404` doesn't turn into a mess of `[FAIL]` on every single port.
- **`PortRegistry`**: a thread-safe log of port statuses (`Connecting → OK/FAIL`); once the last pending port settles, an event is pushed to the `notify` channel — the orchestrator either summarizes the result or prompts the operator for `r`/`c`.
- **`distribute`**: ports are spread round-robin across `--threads` tunnels, with each tunnel serving several ports over one PTCP channel.

## Decode mode

`-T` picks which layer to parse; `auto` figures it out from the first 4 bytes (the magic):

- **`dhttp`** — DH HTTP-over-UDP: method, path, status, headers, and XML body in readable form. Understands both "bare" HTTP (`GET`/`POST`/`HTTP`) and the `DH`-prefixed variant.
- **`istun`** — inverted STUN: undoes the inversion and shows the message type (Binding Request/Response/Error), transaction ID, and attributes — `MAPPED-ADDRESS`, `XOR-MAPPED-ADDRESS` (with xor decoding), `USERNAME`, `REALM`, `NONCE`, `MESSAGE-INTEGRITY`, `FINGERPRINT`.
- **`ptcp`** — full PTCP frame header plus body parsing by type: `0x00 SYNC`, `0x10 DATA` (realm + payload as string or hex), `0x11 BIND`, `0x12 STATUS`, `0x13 HEARTBEAT`.

Handy for reversing and debugging: capture a packet on the wire (e.g. with `tcpdump`), feed it to `dh-fwd -D -T auto <hex>`, get a parsed breakdown.

## Acknowledgements

Built on top of:
- https://github.com/khoanguyen-3fc/dh-p2p — the base dh-p2p implementation
- https://github.com/thebadinteger/p2pwn/tree/main/core/p2p — base Go implementation of dh-p2p

Many thanks to **thebadinteger** and **khoanguyen-3fc**.

## License

GNU General Public License v3.0 (GPLv3). See the LICENSE file for details.
