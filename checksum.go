package pcap

import (
	"encoding/binary"
	"math"
	"net/netip"
)

// VerifyIPv4HeaderChecksum reports whether a complete IPv4 header has a valid
// checksum. It covers the header and any options through the declared header
// length. Bytes after the header are ignored.
func VerifyIPv4HeaderChecksum(ipHdr []byte) bool {
	if len(ipHdr) < 20 || ipHdr[0]>>4 != 4 {
		return false
	}
	headerLen := int(ipHdr[0]&0x0f) * 4
	if headerLen < 20 || headerLen > len(ipHdr) || headerLen > int(binary.BigEndian.Uint16(ipHdr[2:4])) {
		return false
	}
	return foldChecksum(addChecksumWords(0, ipHdr[:headerLen])) == 0xffff
}

// VerifyTCPChecksum reports whether the supplied complete TCP segment has a
// valid checksum. Pass the IPv4 or IPv6 addresses used in the pseudo-header
// and only the TCP bytes, including options and payload, up to 65,535 bytes.
// If the checksum fails but the field is zero or holds the uncomplemented
// pseudo-header sum, likelyOffload reports a possible transmit offload.
// Both results are false for malformed headers or invalid or mismatched addresses.
func VerifyTCPChecksum(srcAddr, dstAddr netip.Addr, tcpSeg []byte) (valid bool, likelyOffload bool) {
	if len(tcpSeg) < 20 || len(tcpSeg) > math.MaxUint16 {
		return false, false
	}
	headerLen := int(tcpSeg[12]>>4) * 4
	if headerLen < 20 || headerLen > len(tcpSeg) {
		return false, false
	}
	return verifyTransportChecksum(srcAddr, dstAddr, IPProtoTCP, tcpSeg, binary.BigEndian.Uint16(tcpSeg[16:18]))
}

// VerifyUDPChecksum reports whether a complete UDP datagram has a valid
// checksum. Pass the IPv4 or IPv6 addresses used in the pseudo-header.
// Bytes beyond the UDP length are ignored. A zero checksum returns (false,
// true), which covers an omitted IPv4 UDP checksum or a possible offload.
// An invalid checksum equal to the uncomplemented pseudo-header sum also
// returns (false, true). Both results are false for invalid or mismatched
// addresses, malformed lengths, and IPv6 jumbograms.
func VerifyUDPChecksum(srcAddr, dstAddr netip.Addr, udpDgram []byte) (valid bool, likelyOffload bool) {
	if len(udpDgram) < 8 {
		return false, false
	}
	length := int(binary.BigEndian.Uint16(udpDgram[4:6]))
	if length < 8 || length > len(udpDgram) {
		return false, false
	}
	return verifyTransportChecksum(srcAddr, dstAddr, IPProtoUDP, udpDgram[:length], binary.BigEndian.Uint16(udpDgram[6:8]))
}

func verifyTransportChecksum(src, dst netip.Addr, proto uint8, data []byte, field uint16) (bool, bool) {
	sum, ok := checksumPseudoHeader(src, dst, proto, uint16(len(data)))
	if !ok {
		return false, false
	}
	if proto == IPProtoUDP && field == 0 {
		return false, true
	}
	if foldChecksum(addChecksumWords(sum, data)) == 0xffff {
		return true, false
	}
	return false, field == 0 || field == foldChecksum(sum)
}

func checksumPseudoHeader(src, dst netip.Addr, proto uint8, length uint16) (uint32, bool) {
	// For these lengths the high word of the IPv6 length is zero.
	sum := uint32(proto) + uint32(length)
	switch {
	case src.Is4() && dst.Is4():
		a, b := src.As4(), dst.As4()
		return addChecksumWords(addChecksumWords(sum, a[:]), b[:]), true
	case src.Is6() && dst.Is6():
		a, b := src.As16(), dst.As16()
		return addChecksumWords(addChecksumWords(sum, a[:]), b[:]), true
	default:
		return 0, false
	}
}

// The callers sum at most 65,535 transport bytes plus a pseudo-header.
func addChecksumWords(sum uint32, data []byte) uint32 {
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data))
		data = data[2:]
	}
	if len(data) != 0 {
		sum += uint32(data[0]) << 8
	}
	return sum
}

func foldChecksum(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(sum)
}
