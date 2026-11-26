package pcap

import (
	"encoding/binary"
	"net/netip"
)

// ICMPEmbeddedPacket describes the IP packet quoted by an ICMP error.
// HasPorts reports whether the quote contains the first four bytes of a TCP
// or UDP header from an unfragmented packet or its first fragment.
type ICMPEmbeddedPacket struct {
	SrcAddr, DstAddr netip.Addr
	SrcPort, DstPort uint16
	IPVersion        uint8
	IPProtocol       uint8 // Next header at the end of the available IP header chain.
	HasPorts         bool
}

// ICMPEmbeddedPacket decodes the quoted IP header and available ports from an
// ICMPv4 type 3, 4, 11 or 12 or an ICMPv6 type 1, 2 or 3 error. Pass the
// unchanged frame bytes originally supplied to [DecodeFrame]. It returns
// false when the frame carries no supported error or the quote lacks a valid
// IP header. This observation leaves the outer frame and its flow key intact.
func (f *Frame) ICMPEmbeddedPacket(data []byte) (ICMPEmbeddedPacket, bool) {
	if f == nil || f.PayloadLength == 0 || f.PayloadOffset < 8 {
		return ICMPEmbeddedPacket{}, false
	}
	start := uint64(f.PayloadOffset)
	end := start + uint64(f.PayloadLength)
	if end > uint64(len(data)) || data[start-8] != f.ICMPType {
		return ICMPEmbeddedPacket{}, false
	}

	// RFC 4884 gives the padded quote length in 32-bit words for ICMPv4
	// and 64-bit words for ICMPv6. Some error types have no length field.
	var length uint64
	switch {
	case f.IPVersion == 4 && f.IPProtocol == IPProtoICMP:
		switch f.ICMPType {
		case 3, 11, 12:
			length = uint64(data[start-3]) * 4
		case 4:
		default:
			return ICMPEmbeddedPacket{}, false
		}
	case f.IPVersion == 6 && f.IPProtocol == IPProtoIPv6ICMP:
		switch f.ICMPType {
		case 1, 3:
			length = uint64(data[start-4]) * 8
		case 2:
		default:
			return ICMPEmbeddedPacket{}, false
		}
	default:
		return ICMPEmbeddedPacket{}, false
	}
	if length != 0 {
		end = min(end, start+length)
	}
	return decodeICMPQuote(data[start:end])
}

func decodeICMPQuote(data []byte) (ICMPEmbeddedPacket, bool) {
	if len(data) < 20 {
		return ICMPEmbeddedPacket{}, false
	}
	var packet ICMPEmbeddedPacket
	var transport []byte
	switch data[0] >> 4 {
	case 4:
		headerLen := int(data[0]&0xf) * 4
		totalLen := int(binary.BigEndian.Uint16(data[2:4]))
		if headerLen < 20 || headerLen > len(data) || totalLen < headerLen {
			return ICMPEmbeddedPacket{}, false
		}
		packet.IPVersion, packet.IPProtocol = 4, data[9]
		packet.SrcAddr = netip.AddrFrom4([4]byte(data[12:16]))
		packet.DstAddr = netip.AddrFrom4([4]byte(data[16:20]))
		if binary.BigEndian.Uint16(data[6:8])&0x1fff == 0 {
			transport = data[headerLen:min(totalLen, len(data))]
		}
	case 6:
		if len(data) < 40 {
			return ICMPEmbeddedPacket{}, false
		}
		end := min(40+int(binary.BigEndian.Uint16(data[4:6])), len(data))
		packet.IPVersion = 6
		packet.SrcAddr = netip.AddrFrom16([16]byte(data[8:24]))
		packet.DstAddr = netip.AddrFrom16([16]byte(data[24:40]))
		packet.IPProtocol, transport = icmpQuotedIPv6Transport(data[6], data[40:end])
	default:
		return ICMPEmbeddedPacket{}, false
	}
	if len(transport) >= 4 && (packet.IPProtocol == IPProtoTCP || packet.IPProtocol == IPProtoUDP) {
		packet.SrcPort = binary.BigEndian.Uint16(transport[:2])
		packet.DstPort = binary.BigEndian.Uint16(transport[2:4])
		packet.HasPorts = true
	}
	return packet, true
}

func icmpQuotedIPv6Transport(proto uint8, data []byte) (uint8, []byte) {
	for n := 0; isIPv6ExtHeader(proto); n++ {
		if n >= MaxIPv6ExtHeaders || len(data) < 8 {
			return proto, nil
		}
		size := ipv6ExtLength(proto, data[1])
		if size == 0 || size > len(data) {
			return proto, nil
		}
		if proto == IPProtoIPv6Frag && binary.BigEndian.Uint16(data[2:4])&0xfff8 != 0 {
			return data[0], nil
		}
		proto, data = data[0], data[size:]
	}
	return proto, data
}
