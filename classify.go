package pcap

import (
	"bytes"
	"encoding/binary"
)

// ClassifyL7 identifies a candidate protocol from the start of a TCP stream
// or UDP payload. It checks a bounded prefix and allocates no memory. A match
// identifies a parser to try. L7Unknown can also mean the prefix is incomplete
// or begins after the protocol's identifying bytes.
//
// DNS uses port 53 on TCP and ports 53, 5353, and 5355 on UDP. Kerberos uses
// port 88 and a recognized application tag. Other signatures work on any port
// of their transport.
func ClassifyL7(payload []byte, ipProto uint8, srcPort, dstPort uint16) L7Protocol {
	if len(payload) == 0 {
		return L7Unknown
	}
	switch ipProto {
	case IPProtoTCP:
		switch payload[0] {
		case 'P':
			if bytes.HasPrefix(payload, []byte(http2ClientPreface)) {
				return L7HTTP2
			}
			fallthrough
		case 'C', 'D', 'G', 'H', 'O', 'T':
			if bytes.HasPrefix(payload, []byte("HTTP/1.")) {
				return L7HTTP1
			}
			method, _, ok := bytes.Cut(payload[:min(8, len(payload))], []byte(" "))
			if ok && isStandardHTTPMethod(string(method)) {
				return L7HTTP1
			}
		case 'S':
			if bytes.HasPrefix(payload, []byte("SSH-")) {
				return L7SSH
			}
		case 0:
			if len(payload) >= 8 {
				switch {
				case bytes.HasPrefix(payload[4:], smb2Magic):
					return L7SMB2
				case bytes.HasPrefix(payload[4:], smb3TransformMagic):
					return L7SMB3Encrypted
				}
			}
		case 0x16:
			if len(payload) >= 6 && payload[1] == 3 && payload[2] <= 4 && (payload[5] == 1 || payload[5] == 2) {
				return L7TLS
			}
		case 3:
			if len(payload) >= 11 && payload[1] == 0 {
				switch payload[5] & 0xf0 {
				case x224CodeConnectionRequest, x224CodeConnectionConfirm:
					return L7RDP
				}
			}
		}
		if (srcPort == 53 || dstPort == 53) && len(payload) >= 14 && binary.BigEndian.Uint16(payload) >= 12 {
			return L7DNS
		}
	case IPProtoUDP:
		if len(payload) >= 7 && payload[0]&0xc0 == 0xc0 {
			switch binary.BigEndian.Uint32(payload[1:5]) {
			case QUICVersion1, QUICVersion2:
				return L7QUIC
			}
		}
		if (isDNSPort(srcPort) || isDNSPort(dstPort)) && len(payload) >= 12 {
			return L7DNS
		}
	default:
		return L7Unknown
	}

	if srcPort == krb5Port || dstPort == krb5Port {
		if ipProto == IPProtoTCP {
			if len(payload) < 12 {
				return L7Unknown
			}
			n := binary.BigEndian.Uint32(payload)
			if n < 8 || n > MaxKRB5PacketBytes {
				return L7Unknown
			}
			payload = payload[4:]
		}
		if len(payload) >= 8 && isKRB5ApplicationTag(payload[0]) {
			return L7KRB5
		}
	}
	return L7Unknown
}
