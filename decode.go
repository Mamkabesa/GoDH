/*
 * decode.go — offline packet dissector (dh-fwd --decode).
 *
 * Takes raw hex from argv or stdin and pretty-prints a single protocol
 * layer, selected with -T:
 *
 *   dhttp — the DH HTTP-over-UDP request/response (headers + XML body);
 *   istun — Dahua's bit-inverted STUN (binding, mapped addresses...);
 *   ptcp  — the 24-byte Phony-TCP frame and its body (0x00 SYNC,
 *           0x10 DATA, 0x11 BIND, 0x12 STATUS, 0x13 HEARTBEAT).
 *
 * With no -T, autoDecode sniffs the first bytes (DH/HTTP magic, "PTCP"
 * or an 0xFF/0xFE inverted STUN) and picks the matching layer.
 */

package main

import (
	"encoding/binary"
	"fmt"
	"strings"
)

func decodePacket(decodeType string, data []byte) {
	switch decodeType {
	case "dhttp":
		decodeDHTP(data)
	case "istun":
		decodeInvertedSTUN(data)
	case "ptcp":
		decodePTCP(data)
	default:
		autoDecode(data)
	}
}

func autoDecode(data []byte) {
	if len(data) < 4 {
		fmt.Println("too short to decode")
		return
	}

	prefix := string(data[:4])
	if prefix == "DHGE" || prefix == "DHPO" || prefix == "GET " || prefix == "POST" || prefix == "HTTP" {
		decodeDHTP(data)
	} else if prefix == "PTCP" {
		decodePTCP(data)
	} else if data[0] == 0xFF || data[0] == 0xFE {
		decodeInvertedSTUN(data)
	} else {
		fmt.Printf("Unknown packet type, first 4 bytes: %x (%s)\n", data[:4], prefix)
	}
}

func decodeDHTP(data []byte) {
	fmt.Println("=== Dahua HTTP ===")
	str := string(data)
	if len(data) >= 2 && (string(data[:2]) == "DH" || string(data[:2]) == "dh") {
		str = string(data[2:])
		fmt.Println("(stripped 2-byte DH prefix)")
	}

	str = strings.ReplaceAll(str, "Content-Type: \r\n", "Content-Type: application/xml\r\n")

	parts := strings.SplitN(str, "\r\n\r\n", 2)
	headLines := strings.Split(parts[0], "\r\n")

	for _, line := range headLines {
		fmt.Printf("  %s\n", line)
	}

	if len(parts) > 1 && strings.TrimSpace(parts[1]) != "" {
		fmt.Println()
		body := strings.TrimSpace(parts[1])
		fmt.Printf("  Body (%d bytes):\n", len(body))
		prettyPrintXML(body)
	}
}

func decodeInvertedSTUN(data []byte) {
	fmt.Println("=== Inverted STUN ===")
	fmt.Printf("  Raw length: %d bytes\n", len(data))
	fmt.Printf("  First byte: 0x%02X\n", data[0])

	inv := GetInvertedBytes(data)

	fmt.Printf("  Inverted hex: %x\n", inv)

	if len(inv) >= 20 {
		msgType := uint16(inv[0])<<8 | uint16(inv[1])
		msgLen := uint16(inv[2])<<8 | uint16(inv[3])
		fmt.Printf("  STUN message type: 0x%04x\n", msgType)
		fmt.Printf("  STUN message length: %d\n", msgLen)
		fmt.Printf("  Transaction ID: %x\n", inv[8:20])

		switch msgType {
		case 0x0001:
			fmt.Println("  → Binding Request")
		case 0x0101:
			fmt.Println("  → Binding Response")
		case 0x0111:
			fmt.Println("  → Binding Error Response")
		}

		if len(inv) > 20 {
			fmt.Println("  Attributes:")
			pos := 20
			for pos+4 < len(inv) && pos < 20+int(msgLen) {
				attrType := uint16(inv[pos])<<8 | uint16(inv[pos+1])
				attrLen := uint16(inv[pos+2])<<8 | uint16(inv[pos+3])
				attrVal := inv[pos+4 : pos+4+int(attrLen)]
				fmt.Printf("    attr type=0x%04x len=%d\n", attrType, attrLen)
				printSTUNAttr(attrType, attrVal)
				pos += 4 + int(attrLen)
				if attrLen%4 != 0 {
					pos += 4 - (int(attrLen) % 4)
				}
			}
		}
	}
}

func printSTUNAttr(attrType uint16, val []byte) {
	switch attrType {
	case 0x0001:
		if len(val) >= 4 {
			family := val[0]
			port := uint16(val[2])<<8 | uint16(val[3])
			ip := ""
			if family == 0x01 && len(val) >= 8 {
				ip = fmt.Sprintf("%d.%d.%d.%d", val[4], val[5], val[6], val[7])
			} else if family == 0x02 && len(val) >= 20 {
				ip = fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
					val[4], val[5], val[6], val[7], val[8], val[9], val[10], val[11],
					val[12], val[13], val[14], val[15], val[16], val[17], val[18], val[19])
			}
			fmt.Printf("      MAPPED-ADDRESS: family=%d port=%d ip=%s\n", family, port, ip)
		}
	case 0x0020:
		if len(val) >= 4 {
			xport := (uint16(val[2])<<8 | uint16(val[3])) ^ 0x2112
			xip := fmt.Sprintf("%d.%d.%d.%d", val[4]^0x21, val[5]^0x12, val[6]^0xA4, val[7]^0x42)
			fmt.Printf("      XOR-MAPPED-ADDRESS: port=%d ip=%s\n", xport, xip)
		}
	case 0x0006:
		fmt.Printf("      USERNAME: %s\n", string(val))
	case 0x0014:
		fmt.Printf("      REALM: %s\n", string(val))
	case 0x0015:
		fmt.Printf("      NONCE: %x\n", val)
	case 0x0008:
		fmt.Printf("      MESSAGE-INTEGRITY: %x\n", val)
	case 0x8028:
		fmt.Printf("      FINGERPRINT: %x\n", val)
	default:
		fmt.Printf("      hex: %x\n", val)
	}
}

func decodePTCP(data []byte) {
	fmt.Println("=== PTCP (Phony TCP) ===")
	if len(data) < 4 {
		fmt.Println("  too short")
		return
	}

	p, err := ParsePTCP(data)
	if err != nil {
		fmt.Printf("  parse error: %v\n", err)
		return
	}

	fmt.Printf("  RLID (bytes sent):      %d (0x%08x)\n", p.Rlid, p.Rlid)
	fmt.Printf("  LLID (bytes recv):      %d (0x%08x)\n", p.Llid, p.Llid)
	fmt.Printf("  PID  (package id):      0x%08x\n", p.Pid)
	fmt.Printf("  LMID (local msg id):    %d (0x%08x)\n", p.Lmid, p.Lmid)
	fmt.Printf("  RMID (remote msg id):   %d (0x%08x)\n", p.Rmid, p.Rmid)

	if len(p.Body) == 0 {
		fmt.Println("  Body: (empty)")
		return
	}

	fmt.Printf("  Body (%d bytes):\n", len(p.Body))

	if len(p.Body) >= 4 {
		btype := p.Body[0]
		blen := uint32(p.Body[1])<<16 | uint32(p.Body[2])<<8 | uint32(p.Body[3])

		switch btype {
		case 0x00:
			fmt.Printf("    Type: SYNC (0x00)\n")
			fmt.Printf("    Length: %d\n", blen)
		case 0x10:
			fmt.Printf("    Type: DATA (0x10)\n")
			if len(p.Body) >= 12 {
				realm := binary.BigEndian.Uint32(p.Body[4:8])
				pad := binary.BigEndian.Uint32(p.Body[8:12])
				fmt.Printf("    Realm: 0x%08x\n", realm)
				fmt.Printf("    Padding: %d\n", pad)
				payload := p.Body[12:]
				fmt.Printf("    Payload (%d bytes):\n", len(payload))
				printPayload(payload)
			}
		case 0x11:
			fmt.Printf("    Type: BIND (0x11)\n")
			if len(p.Body) >= 16 {
				realm := binary.BigEndian.Uint32(p.Body[4:8])
				port := binary.BigEndian.Uint32(p.Body[12:16])
				fmt.Printf("    Realm: 0x%08x\n", realm)
				fmt.Printf("    Port: %d\n", port)
			}
		case 0x12:
			fmt.Printf("    Type: STATUS (0x12)\n")
			if len(p.Body) >= 12 {
				realm := binary.BigEndian.Uint32(p.Body[4:8])
				status := string(p.Body[12:])
				fmt.Printf("    Realm: 0x%08x\n", realm)
				fmt.Printf("    Status: %s\n", status)
			}
		case 0x13:
			fmt.Printf("    Type: HEARTBEAT (0x13)\n")
		default:
			fmt.Printf("    Type: 0x%02x (unknown)\n", btype)
			fmt.Printf("    Length: %d\n", blen)
			fmt.Printf("    Raw: %x\n", p.Body[4:])
		}
	}
}

func prettyPrintXML(xml string) {
	lines := strings.Split(xml, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			fmt.Printf("    %s\n", line)
		}
	}
}

func printPayload(data []byte) {
	if len(data) == 0 {
		return
	}

	hasPrintable := true
	for _, b := range data {
		if b < 0x20 || b > 0x7E {
			if b != 0x0A && b != 0x0D {
				hasPrintable = false
				break
			}
		}
	}

	if hasPrintable {
		fmt.Printf("    String: %s\n", string(data))
	} else if len(data) <= 64 {
		fmt.Printf("    Hex: %x\n", data)
	} else {
		fmt.Printf("    Hex (%d bytes): %x...\n", len(data), data[:64])
	}
}
