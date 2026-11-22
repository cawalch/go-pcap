package pcap

import (
	"encoding/binary"
	"errors"
	"testing"
)

func TestDecodeFrameBoundsAndAnomalies(t *testing.T) {
	// 1. Unsupported link type.
	if _, err := DecodeFrame([]byte{1, 2, 3, 4}, LinkType(9999)); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("DecodeFrame(unsupported linkType) err = %v, want ErrInvalidFrame", err)
	}

	// 2. Ethernet header shorter than 14 bytes.
	if _, err := DecodeFrame(make([]byte, 13), LinkTypeEthernet); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("DecodeFrame(short Ethernet) err = %v, want ErrInvalidFrame", err)
	}

	// 3. Excessive nested VLAN tags (> MaxVLANTags).
	vlanBomb := make([]byte, 14+4*(MaxVLANTags+1)+20)
	binary.BigEndian.PutUint16(vlanBomb[12:14], EtherTypeVLAN)
	for i := range MaxVLANTags + 1 {
		off := 14 + i*4
		binary.BigEndian.PutUint16(vlanBomb[off+2:off+4], EtherTypeVLAN)
	}
	fVLAN, err := DecodeFrame(vlanBomb, LinkTypeEthernet)
	if err != nil || !fVLAN.Anomalies.VLANDepthExceeded {
		t.Fatalf("DecodeFrame(VLAN bomb) = (%+v, %v), want VLANDepthExceeded", fVLAN.Anomalies, err)
	}

	// 4. IPv4 header with invalid IHL (< 5).
	badIHL := make([]byte, 14+20)
	binary.BigEndian.PutUint16(badIHL[12:14], EtherTypeIPv4)
	badIHL[14] = 0x43 // IHL = 3 (12 bytes < 20)
	fIHL, err := DecodeFrame(badIHL, LinkTypeEthernet)
	if err != nil || !fIHL.Anomalies.InvalidIPHeaderLength {
		t.Fatalf("DecodeFrame(bad IHL) = (%+v, %v), want InvalidIPHeaderLength", fIHL.Anomalies, err)
	}

	// 5. IPv4 fragment skips L4 port decoding and sets IPFragment anomaly.
	fragFrame := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 1234, 80, 1, 1, TCPFlagSYN, []byte("frag"))
	binary.BigEndian.PutUint16(fragFrame[14+6:14+8], 0x2001) // MF=1, offset=1
	fFrag, err := DecodeFrame(fragFrame, LinkTypeEthernet)
	if err != nil || !fFrag.Anomalies.IPFragment || fFrag.SrcPort != 0 {
		t.Fatalf("DecodeFrame(IPv4 fragment) = (%+v, srcPort=%d, %v)", fFrag.Anomalies, fFrag.SrcPort, err)
	}

	// 6. TCP header with invalid DataOffset (< 5).
	badTCP := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 1234, 80, 1, 1, TCPFlagSYN, nil)
	badTCP[34+12] = 3 << 4 // DataOffset = 12 bytes < 20
	fTCP, err := DecodeFrame(badTCP, LinkTypeEthernet)
	if err != nil || !fTCP.Anomalies.InvalidTCPDataOffset {
		t.Fatalf("DecodeFrame(bad TCP DataOffset) = (%+v, %v), want InvalidTCPDataOffset", fTCP.Anomalies, err)
	}

	// 7. VXLAN carrying inner ARP must not retain outer UDP PayloadLength past frame end.
	innerARP := make([]byte, 14+28)
	binary.BigEndian.PutUint16(innerARP[12:14], EtherTypeARP)
	vxlanARP := make([]byte, 8+len(innerARP))
	vxlanARP[0] = 0x08
	copy(vxlanARP[8:], innerARP)
	vxlanARPFrame := buildEthernetIPv4UDPFrame([4]byte{172, 16, 0, 1}, [4]byte{172, 16, 0, 2}, 55555, 4789, vxlanARP)
	fVXLANARP, err := DecodeFrame(vxlanARPFrame, LinkTypeEthernet)
	if err != nil {
		t.Fatalf("DecodeFrame(VXLAN->ARP) err = %v", err)
	}
	if uint64(fVXLANARP.PayloadOffset)+uint64(fVXLANARP.PayloadLength) > uint64(len(vxlanARPFrame)) {
		t.Fatalf("VXLAN->ARP payload span (%d+%d) exceeds frame len %d", fVXLANARP.PayloadOffset, fVXLANARP.PayloadLength, len(vxlanARPFrame))
	}
	if fVXLANARP.PayloadLength != 0 {
		t.Fatalf("VXLAN->ARP PayloadLength = %d, want 0", fVXLANARP.PayloadLength)
	}

	// 8. VXLAN carrying inner IPv4 with totalLen == IHL (0 L4 bytes) must clear PayloadLength and outer ports.
	innerEmptyIP := make([]byte, 14+20)
	binary.BigEndian.PutUint16(innerEmptyIP[12:14], EtherTypeIPv4)
	innerEmptyIP[14] = 0x45
	binary.BigEndian.PutUint16(innerEmptyIP[16:18], 20)
	innerEmptyIP[23] = IPProtoICMP
	copy(innerEmptyIP[26:30], []byte{10, 1, 1, 1})
	copy(innerEmptyIP[30:34], []byte{10, 2, 2, 2})
	vxlanEmpty := make([]byte, 8+len(innerEmptyIP))
	vxlanEmpty[0] = 0x08
	copy(vxlanEmpty[8:], innerEmptyIP)
	vxlanEmptyFrame := buildEthernetIPv4UDPFrame([4]byte{172, 16, 0, 1}, [4]byte{172, 16, 0, 2}, 55555, 4789, vxlanEmpty)
	fVXLANEmpty, err := DecodeFrame(vxlanEmptyFrame, LinkTypeEthernet)
	if err != nil {
		t.Fatalf("DecodeFrame(VXLAN->empty IPv4) err = %v", err)
	}
	if uint64(fVXLANEmpty.PayloadOffset)+uint64(fVXLANEmpty.PayloadLength) > uint64(len(vxlanEmptyFrame)) {
		t.Fatalf("VXLAN->empty IPv4 payload span (%d+%d) exceeds frame len %d", fVXLANEmpty.PayloadOffset, fVXLANEmpty.PayloadLength, len(vxlanEmptyFrame))
	}
	if fVXLANEmpty.PayloadLength != 0 || fVXLANEmpty.SrcPort != 0 || fVXLANEmpty.DstPort != 0 {
		t.Fatalf("VXLAN->empty IPv4 = (len=%d, srcPort=%d, dstPort=%d), want all 0",
			fVXLANEmpty.PayloadLength, fVXLANEmpty.SrcPort, fVXLANEmpty.DstPort)
	}

	// 9. VXLAN inner frame must respect outer IP/UDP bounds and ignore trailing Ethernet padding.
	innerEth := buildEthernetIPv4TCPFrame([4]byte{10, 1, 1, 1}, [4]byte{10, 2, 2, 2}, 12345, 443, 1, 0, TCPFlagSYN, []byte("hi"))
	vxlanPad := make([]byte, 8+len(innerEth))
	vxlanPad[0] = 0x08
	copy(vxlanPad[8:], innerEth)
	vxlanPaddedFrame := append(buildEthernetIPv4UDPFrame([4]byte{172, 16, 0, 1}, [4]byte{172, 16, 0, 2}, 55555, 4789, vxlanPad), []byte("TRAILING_PAD")...)
	// Truncate inner TCP payload to test outer ipBound clamping: outer IP+UDP only covers up to innerEth.
	fVXLANPad, err := DecodeFrame(vxlanPaddedFrame, LinkTypeEthernet)
	if err != nil {
		t.Fatalf("DecodeFrame(VXLAN padded) err = %v", err)
	}
	if got := string(vxlanPaddedFrame[fVXLANPad.PayloadOffset : fVXLANPad.PayloadOffset+fVXLANPad.PayloadLength]); got != "hi" {
		t.Fatalf("VXLAN padded payload = %q, want %q", got, "hi")
	}

	// 10. Outer IPv4 fields (IPID/Frag) must not leak into inner IPv6 over Geneve.
	innerIPv6 := make([]byte, 40+8+4)
	innerIPv6[0] = 0x60
	binary.BigEndian.PutUint16(innerIPv6[4:6], 12)
	innerIPv6[6] = IPProtoICMP
	innerIPv6[7] = 64
	geneveIPv6 := make([]byte, 8+len(innerIPv6))
	binary.BigEndian.PutUint16(geneveIPv6[2:4], EtherTypeIPv6)
	copy(geneveIPv6[8:], innerIPv6)
	geneveFrame := buildEthernetIPv4UDPFrame([4]byte{172, 16, 0, 1}, [4]byte{172, 16, 0, 2}, 55555, 6081, geneveIPv6)
	binary.BigEndian.PutUint16(geneveFrame[14+4:14+6], 0x4242) // outer IPv4 IPID
	fGeneveIPv6, err := DecodeFrame(geneveFrame, LinkTypeEthernet)
	if err != nil {
		t.Fatalf("DecodeFrame(Geneve->IPv6) err = %v", err)
	}
	if fGeneveIPv6.IPVersion != 6 || fGeneveIPv6.IPID != 0 || fGeneveIPv6.SrcPort != 0 || fGeneveIPv6.DstPort != 0 {
		t.Fatalf("Geneve->IPv6 leaked outer fields: v=%d ipid=%#x srcPort=%d dstPort=%d",
			fGeneveIPv6.IPVersion, fGeneveIPv6.IPID, fGeneveIPv6.SrcPort, fGeneveIPv6.DstPort)
	}

	// 11. Linux SLL and SLL2 frames with 802.1Q VLAN tags must peel VLANs.
	vlanIPv4 := make([]byte, 4+20+8)
	binary.BigEndian.PutUint16(vlanIPv4[0:2], 42)
	binary.BigEndian.PutUint16(vlanIPv4[2:4], EtherTypeIPv4)
	vlanIPv4[4] = 0x45
	binary.BigEndian.PutUint16(vlanIPv4[6:8], 28)
	vlanIPv4[13] = IPProtoUDP
	binary.BigEndian.PutUint16(vlanIPv4[24:26], 1234)
	binary.BigEndian.PutUint16(vlanIPv4[26:28], 5678)
	binary.BigEndian.PutUint16(vlanIPv4[28:30], 8)

	sllVLAN := make([]byte, 16+len(vlanIPv4))
	binary.BigEndian.PutUint16(sllVLAN[14:16], EtherTypeVLAN)
	copy(sllVLAN[16:], vlanIPv4)
	fSLL, err := DecodeFrame(sllVLAN, LinkTypeLinuxSLL)
	if err != nil || fSLL.VLANCount != 1 || fSLL.VLANTags[0] != 42 || fSLL.SrcPort != 1234 || fSLL.DstPort != 5678 {
		t.Fatalf("DecodeFrame(SLL+VLAN) = (%+v, %v)", fSLL, err)
	}

	sll2VLAN := make([]byte, 20+len(vlanIPv4))
	binary.BigEndian.PutUint16(sll2VLAN[0:2], EtherTypeVLAN)
	copy(sll2VLAN[20:], vlanIPv4)
	fSLL2, err := DecodeFrame(sll2VLAN, LinkTypeLinuxSLL2)
	if err != nil || fSLL2.VLANCount != 1 || fSLL2.VLANTags[0] != 42 || fSLL2.SrcPort != 1234 || fSLL2.DstPort != 5678 {
		t.Fatalf("DecodeFrame(SLL2+VLAN) = (%+v, %v)", fSLL2, err)
	}
}
