<div align="center">

<h1>dh-fwd</h1>

<p>
  <a href="./README.md">English</a> | <a href="./README_ru.md">Русский</a>
</p>

</div>

A tool for creating tunnels to Dahua cameras (by serial number) and forwarding any port to localhost via the Dahua DH HTTP P2P cloud protocol. Essentially, an improved version of DH-P2P.

## Improvements 

- Supports **forwarding multiple ports at once**
- **Packet decoder** (`--decode`) — parses captured packets offline (DH HTTP, inverted STUN, PTCP).
- Sends **heartbeat**  and **RTSP keepalive** to maintain the tunnel.

## Build

Requires Go 1.22+.

```sh
git clone https://github.com/Mamkabesa/dh-fwd
cd dh-fwd
go build -o dh-fwd .

```
## Usage
```sh
dh-fwd [options] <serial>

```
Or:
```sh
./dh-fwd <serial> [options]

```
### Flags
| Flag | Short | Description |
|---|---|---|
| --debug | -d | Verbose protocol debug output (requests, STUN packets, PTCP frames) |
| --log-retries | -lr | Log retries with timestamps |
| --type | -t | Device type: 0 — no auth (default), 1 — with auth |
| --username | -u | Username (for --type 1) |
| --password | -P | Password (for --type 1) |
| --randsalt | -s | RandSalt from info blob (for --type 1) |
| --port | -p | Port mapping (see below) |
| --threads | -mt | Number of threads (default 3) |
| --decode | -D | Packet decoder mode |
| --decode-type | -T | What to decode: auto, dhttp, istun, ptcp (default auto) |
| --help | -h | Show command list |
### Port Syntax (--port)
There are two ports: **local** (the one we listen on) and **remote** (the one the camera exposes).
 * **Left side:** local port
 * **Right side:** remote port
 * If only one port is specified (e.g., -p 80), remote port 80 will be opened on **any free local port**.
**Examples:**
 * -p 5080,5081,5082:80,81,82 — explicit pairs "local:remote", one-to-one
 * -p 8080,8081,8082:80 — multiple local ports to one remote port
 * -p 80-85 — port range
 * 0:81 — local port 0 means "any free port"
 * If no port is specified, default port 554 is used.
Local ports are bound to 127.0.0.1.

**Note:** If you run the software without the -p flag or specify a listening port <1024 without running the program with sudo, you may encounter the following error:

```sh
Tunnel failed, reason - no listeners available for tunnel
```

## Modes
**Single** — forwards only 1 port:
```sh
./dh-fwd SN -p 5080:80

```
**Multi** — forwards multiple ports simultaneously. Activates automatically if multiple ports are specified, or if -mt is explicitly set:
```sh
./dh-fwd SN -p 5080,5081:80,81 -mt 4

```
```text
Opening 2 ports on SN | Threads: 3
[..] Opening SN:80 | Connecting...
[OK] Obtained SN:80 -> 127.0.0.1:5080
[OK] Obtained SN:81 -> 127.0.0.1:5081
Obtained 2 ports on SN:80,81 | localhost:5080,5081

```
**Decode** — parses a captured packet offline without connecting to the camera:
```sh
./dh-fwd -D -T ptcp <hex>
./dh-fwd -D -T auto 0x... 0x...
echo '<hex>' | ./dh-fwd -D

```
## What is Dahua P2P protocol?
This is a proprietary Dahua cloud protocol used to connect to cameras via the cloud, even if the device is behind multiple NATs. The connection sequence operates as follows: the client (SmartPSS or dh-fwd) sends a request to the main server → receives an intermediate server → creates a communication channel → attempts NAT traversal → establishes a tunnel.
> ⚠️ **IMPORTANT:** Until 2025, Dahua P2P servers established tunnels without mandatory authentication. Following reported protocol vulnerabilities, devices released after late 2024 require authentication **BEFORE** establishing a tunnel.
> 
## Decode Mode Details
The -T flag specifies which layer to decode, while auto detects it by the first 4 magic bytes:
 * **dhttp** — DH HTTP-over-UDP: method, path, status, headers, and XML body in human-readable form. Supports both standard HTTP (GET/POST/HTTP) and DH-prefixed variants.
 * **istun** — inverted STUN: reverses the inversion and displays message type (*Binding Request/Response/Error*), transaction ID, and attributes (*MAPPED-ADDRESS*, *XOR-MAPPED-ADDRESS* with XOR decoding, *USERNAME*, *REALM*, *NONCE*, *MESSAGE-INTEGRITY*, *FINGERPRINT*).
 * **ptcp** — PTCP frame header plus body parsing by type: 0x00 SYNC, 0x10 DATA (realm + payload as string or hex), 0x11 BIND, 0x12 STATUS, 0x13 HEARTBEAT.
Useful for reverse engineering and debugging: capture a packet (e.g. with tcpdump), pipe or pass it to dh-fwd -D -T auto <hex>, and receive formatted output.
## Credits
Based on:
 * khoanguyen-3fc/dh-p2p — main protocol reference
 * thebadinteger/p2pwn — additional reference
Special thanks to: **thebadinteger** and **khoanguyen-3fc**.
## ⚠️ Disclaimer
This tool was created for educational and authorized testing purposes only. Do not use it on devices you do not own or do not have explicit permission to test.
## License
GNU General Public License v3.0 (GPLv3). See LICENSE for details.
