package pcap

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestDecodeFrameEthernetVLANIPv4TCPWithOptions(t *testing.T) {
	// Ethernet (14) + 802.1ad QinQ (4) + 802.1Q VLAN (4) + IPv4 (20) + TCP with 4B MSS option (24) + 5B payload.
	buf := make([]byte, 14+8+20+24+5)
	binary.BigEndian.PutUint16(buf[12:14], EtherTypeQinQ)
	binary.BigEndian.PutUint16(buf[14:16], 100) // Outer VLAN 100
	binary.BigEndian.PutUint16(buf[16:18], EtherTypeVLAN)
	binary.BigEndian.PutUint16(buf[18:20], 200) // Inner VLAN 200
	binary.BigEndian.PutUint16(buf[20:22], EtherTypeIPv4)

	ip := buf[22:42]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 20+24+5)
	ip[8] = 128
	ip[9] = IPProtoTCP
	copy(ip[12:16], []byte{192, 0, 2, 1})
	copy(ip[16:20], []byte{198, 51, 100, 2})

	tcp := buf[42:66]
	binary.BigEndian.PutUint16(tcp[0:2], 49152)
	binary.BigEndian.PutUint16(tcp[2:4], 8443)
	binary.BigEndian.PutUint32(tcp[4:8], 0x11223344)
	binary.BigEndian.PutUint32(tcp[8:12], 0x55667788)
	tcp[12] = 6 << 4 // 24-byte header (4 bytes of options)
	tcp[13] = TCPFlagSYN
	binary.BigEndian.PutUint16(tcp[14:16], 64240)
	copy(tcp[20:24], []byte{2, 4, 0x05, 0xb4}) // MSS 1460
	copy(buf[66:], []byte("hello"))

	frame, err := DecodeFrame(buf, LinkTypeEthernet)
	if err != nil {
		t.Fatalf("DecodeFrame() error = %v", err)
	}
	if frame.Anomalies.Any() {
		t.Fatalf("Frame.Anomalies = %+v, want none", frame.Anomalies)
	}
	if frame.VLANCount != 2 || frame.VLANTags[0] != 100 || frame.VLANTags[1] != 200 {
		t.Fatalf("VLANs = (%d, %v), want (2, [100 200])", frame.VLANCount, frame.VLANTags)
	}
	if frame.IPVersion != 4 || frame.IPProtocol != IPProtoTCP || frame.TTL != 128 {
		t.Fatalf("IP fields = (v=%d, proto=%d, ttl=%d)", frame.IPVersion, frame.IPProtocol, frame.TTL)
	}
	if frame.SrcAddr != netip.MustParseAddr("192.0.2.1") || frame.DstAddr != netip.MustParseAddr("198.51.100.2") {
		t.Fatalf("Addrs = (%s, %s)", frame.SrcAddr, frame.DstAddr)
	}
	if frame.SrcPort != 49152 || frame.DstPort != 8443 || frame.TCPOptionsLength != 4 {
		t.Fatalf("TCP = (src=%d, dst=%d, optLen=%d)", frame.SrcPort, frame.DstPort, frame.TCPOptionsLength)
	}
	if frame.PayloadOffset != 66 || frame.PayloadLength != 5 {
		t.Fatalf("Payload span = (%d, %d), want (66, 5)", frame.PayloadOffset, frame.PayloadLength)
	}
}

func TestDecodeFrameIPv6WithHopByHopAndUDP(t *testing.T) {
	// Raw IPv6 (40) + Hop-by-Hop ext header (8) + UDP (8) + 4B payload.
	buf := make([]byte, 40+8+8+4)
	buf[0] = 0x60 // IPv6
	binary.BigEndian.PutUint16(buf[4:6], 8+8+4)
	buf[6] = IPProtoHopByHop
	buf[7] = 64
	src := netip.MustParseAddr("2001:db8::1").As16()
	dst := netip.MustParseAddr("2001:db8::2").As16()
	copy(buf[8:24], src[:])
	copy(buf[24:40], dst[:])

	// Hop-by-Hop extension header (8 bytes): nextHeader = UDP, length = 0 ((0+1)*8 = 8).
	buf[40] = IPProtoUDP
	buf[41] = 0

	// UDP header (8 bytes).
	binary.BigEndian.PutUint16(buf[48:50], 5353)
	binary.BigEndian.PutUint16(buf[50:52], 53)
	binary.BigEndian.PutUint16(buf[52:54], 12)
	copy(buf[56:], []byte("dns!"))

	frame, err := DecodeFrame(buf, LinkTypeRaw)
	if err != nil {
		t.Fatalf("DecodeFrame(IPv6) error = %v", err)
	}
	if frame.IPVersion != 6 || frame.IPProtocol != IPProtoUDP {
		t.Fatalf("IPv6 fields = (v=%d, proto=%d)", frame.IPVersion, frame.IPProtocol)
	}
	if frame.SrcPort != 5353 || frame.DstPort != 53 || frame.PayloadOffset != 56 || frame.PayloadLength != 4 {
		t.Fatalf("UDP span = (src=%d, dst=%d, off=%d, len=%d)", frame.SrcPort, frame.DstPort, frame.PayloadOffset, frame.PayloadLength)
	}
}

func TestDecodeFrameLinuxSLL2AndLoopback(t *testing.T) {
	ipv4UDP := make([]byte, 20+8)
	ipv4UDP[0] = 0x45
	binary.BigEndian.PutUint16(ipv4UDP[2:4], 28)
	ipv4UDP[8] = 64
	ipv4UDP[9] = IPProtoUDP
	copy(ipv4UDP[12:16], []byte{127, 0, 0, 1})
	copy(ipv4UDP[16:20], []byte{127, 0, 0, 1})
	binary.BigEndian.PutUint16(ipv4UDP[20:22], 1111)
	binary.BigEndian.PutUint16(ipv4UDP[22:24], 2222)

	// Linux SLL2 (20-byte header with protocol at offset 0).
	sll2 := make([]byte, 20+len(ipv4UDP))
	binary.BigEndian.PutUint16(sll2[0:2], EtherTypeIPv4)
	copy(sll2[20:], ipv4UDP)
	fSLL2, err := DecodeFrame(sll2, LinkTypeLinuxSLL2)
	if err != nil || fSLL2.SrcPort != 1111 || fSLL2.DstPort != 2222 {
		t.Fatalf("DecodeFrame(LinuxSLL2) = (%+v, %v)", fSLL2, err)
	}

	// BSD Loopback (4-byte AF_INET = 2 LE).
	loop := make([]byte, 4+len(ipv4UDP))
	binary.LittleEndian.PutUint32(loop[0:4], 2)
	copy(loop[4:], ipv4UDP)
	fLoop, err := DecodeFrame(loop, LinkTypeNull)
	if err != nil || fLoop.SrcPort != 1111 || fLoop.DstPort != 2222 {
		t.Fatalf("DecodeFrame(LinkTypeNull) = (%+v, %v)", fLoop, err)
	}
}

func TestDecodeFrameTunnelsMPLSPPPoEGREVXLANGeneve(t *testing.T) {
	// Issue #12: Verify zero-alloc tunnel peeling for MPLS, PPPoE, GRE, VXLAN, and Geneve.
	innerEth := buildEthernetIPv4TCPFrame([4]byte{10, 1, 1, 1}, [4]byte{10, 2, 2, 2}, 12345, 443, 1, 0, TCPFlagSYN, []byte("inner"))
	innerIPv4 := innerEth[14:]

	// 1. MPLS 2-label stack over IPv4: Ethernet (14) + MPLS label 1 (4, BOS=0) + MPLS label 2 (4, BOS=1) + IPv4/TCP.
	mplsFrame := make([]byte, 14+8+len(innerIPv4))
	binary.BigEndian.PutUint16(mplsFrame[12:14], EtherTypeMPLSUnicast)
	mplsFrame[14+2] = 0x00 // BOS = 0
	mplsFrame[18+2] = 0x01 // BOS = 1
	copy(mplsFrame[22:], innerIPv4)
	fMPLS, err := DecodeFrame(mplsFrame, LinkTypeEthernet)
	if err != nil || fMPLS.DstPort != 443 || fMPLS.SrcAddr != netip.MustParseAddr("10.1.1.1") {
		t.Fatalf("DecodeFrame(MPLS) = (%+v, %v)", fMPLS, err)
	}

	// 2. PPPoE Session over IPv4: Ethernet (14, 0x8864) + PPPoE (6) + PPP proto IPv4 (2, 0x0021) + IPv4/TCP.
	pppoeFrame := make([]byte, 14+8+len(innerIPv4))
	binary.BigEndian.PutUint16(pppoeFrame[12:14], EtherTypePPPoESession)
	binary.BigEndian.PutUint16(pppoeFrame[20:22], 0x0021)
	copy(pppoeFrame[22:], innerIPv4)
	fPPPoE, err := DecodeFrame(pppoeFrame, LinkTypeEthernet)
	if err != nil || fPPPoE.DstPort != 443 || fPPPoE.DstAddr != netip.MustParseAddr("10.2.2.2") {
		t.Fatalf("DecodeFrame(PPPoE) = (%+v, %v)", fPPPoE, err)
	}

	// 3. GRE over IPv4 carrying inner IPv4/TCP: Ethernet (14) + Outer IPv4 (20, proto=47) + GRE (4, proto=0x0800) + inner IPv4/TCP.
	greFrame := make([]byte, 14+20+4+len(innerIPv4))
	binary.BigEndian.PutUint16(greFrame[12:14], EtherTypeIPv4)
	greFrame[14] = 0x45
	binary.BigEndian.PutUint16(greFrame[16:18], uint16(20+4+len(innerIPv4)))
	greFrame[22] = 64
	greFrame[23] = IPProtoGRE
	copy(greFrame[26:30], []byte{172, 16, 0, 1})
	copy(greFrame[30:34], []byte{172, 16, 0, 2})
	binary.BigEndian.PutUint16(greFrame[36:38], EtherTypeIPv4)
	copy(greFrame[38:], innerIPv4)
	fGRE, err := DecodeFrame(greFrame, LinkTypeEthernet)
	if err != nil || fGRE.DstPort != 443 || fGRE.SrcAddr != netip.MustParseAddr("10.1.1.1") {
		t.Fatalf("DecodeFrame(GRE) = (%+v, %v)", fGRE, err)
	}

	// 4. VXLAN (UDP port 4789, 8-byte VXLAN header with 0x08 flag + inner Ethernet frame).
	vxlanPayload := make([]byte, 8+len(innerEth))
	vxlanPayload[0] = 0x08
	copy(vxlanPayload[8:], innerEth)
	vxlanFrame := buildEthernetIPv4UDPFrame([4]byte{172, 16, 0, 1}, [4]byte{172, 16, 0, 2}, 55555, 4789, vxlanPayload)
	fVXLAN, err := DecodeFrame(vxlanFrame, LinkTypeEthernet)
	if err != nil || fVXLAN.DstPort != 443 || fVXLAN.SrcAddr != netip.MustParseAddr("10.1.1.1") {
		t.Fatalf("DecodeFrame(VXLAN) = (%+v, %v)", fVXLAN, err)
	}

	// 5. Geneve (UDP port 6081, 8-byte Geneve header with protocol 0x6558 Transparent Ethernet Bridging + inner Ethernet frame).
	genevePayload := make([]byte, 8+len(innerEth))
	binary.BigEndian.PutUint16(genevePayload[2:4], EtherTypeTransparentBr)
	copy(genevePayload[8:], innerEth)
	geneveFrame := buildEthernetIPv4UDPFrame([4]byte{172, 16, 0, 1}, [4]byte{172, 16, 0, 2}, 55555, 6081, genevePayload)
	fGeneve, err := DecodeFrame(geneveFrame, LinkTypeEthernet)
	if err != nil || fGeneve.DstPort != 443 || fGeneve.DstAddr != netip.MustParseAddr("10.2.2.2") {
		t.Fatalf("DecodeFrame(Geneve) = (%+v, %v)", fGeneve, err)
	}
}
