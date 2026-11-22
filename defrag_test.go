package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

func buildEthernetIPv4FragmentFrame(srcIP, dstIP [4]byte, proto uint8, ipID uint16, fragOffsetBytes uint16, moreFragments bool, l4Frag []byte) []byte {
	totalLen := 20 + len(l4Frag)
	buf := make([]byte, 14+totalLen)
	binary.BigEndian.PutUint16(buf[12:14], EtherTypeIPv4)
	ip := buf[14 : 14+20]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(ip[4:6], ipID)
	fragWord := (fragOffsetBytes / 8) & 0x1fff
	if moreFragments {
		fragWord |= 0x2000
	}
	binary.BigEndian.PutUint16(ip[6:8], fragWord)
	ip[8] = 64
	ip[9] = proto
	copy(ip[12:16], srcIP[:])
	copy(ip[16:20], dstIP[:])
	copy(buf[34:], l4Frag)
	return buf
}

func TestDefragmentIPOutOfOrderAndOverlap(t *testing.T) {
	src := netip.MustParseAddr("10.0.0.1")
	dst := netip.MustParseAddr("10.0.0.2")

	// Out-of-order fragments with a conflicting overlap at offset 8..16.
	frags := []IPFragmentInput{
		{SrcAddr: src, DstAddr: dst, Protocol: IPProtoUDP, Identification: 100, FragmentOffset: 0, MoreFragments: true, Payload: []byte("0123456789ABCDEF")},
		{SrcAddr: src, DstAddr: dst, Protocol: IPProtoUDP, Identification: 100, FragmentOffset: 16, MoreFragments: false, Payload: []byte("GHIJKLMN")},
		{SrcAddr: src, DstAddr: dst, Protocol: IPProtoUDP, Identification: 100, FragmentOffset: 8, MoreFragments: true, Payload: []byte("xxxxxxxx")},
	}
	out, anomalies, err := DefragmentIP(frags)
	if err != nil {
		t.Fatalf("DefragmentIP() error = %v", err)
	}
	if string(out) != "0123456789ABCDEFGHIJKLMN" {
		t.Fatalf("DefragmentIP() = %q, want first-seen payload", out)
	}
	if !anomalies.IPFragmentOverlapConflict {
		t.Fatal("expected IPFragmentOverlapConflict = true")
	}
	if anomalies.TruncatedLayer {
		t.Fatal("expected TruncatedLayer = false")
	}

	// Exceeding MaxFragmentsPerGroup returns ErrFragmentLimit.
	tooMany := make([]IPFragmentInput, MaxFragmentsPerGroup+1)
	if _, _, err := DefragmentIP(tooMany); !errors.Is(err, ErrFragmentLimit) {
		t.Fatalf("DefragmentIP(tooMany) err = %v, want ErrFragmentLimit", err)
	}
}

func TestFragmentedUDPDNSAndQUIC(t *testing.T) {
	// 1. Fragmented DNS response over IPv4 UDP.
	dnsMsg := buildDNSQueryResponsePacket()
	udpDNS := make([]byte, 8+len(dnsMsg))
	binary.BigEndian.PutUint16(udpDNS[0:2], 53)
	binary.BigEndian.PutUint16(udpDNS[2:4], 54321)
	binary.BigEndian.PutUint16(udpDNS[4:6], uint16(len(udpDNS)))
	copy(udpDNS[8:], dnsMsg)

	// Split UDP datagram at 16-byte boundary (multiple of 8 bytes).
	dnsFrag1 := buildEthernetIPv4FragmentFrame([4]byte{8, 8, 8, 8}, [4]byte{10, 0, 0, 1}, IPProtoUDP, 0x1234, 0, true, udpDNS[:16])
	dnsFrag2 := buildEthernetIPv4FragmentFrame([4]byte{8, 8, 8, 8}, [4]byte{10, 0, 0, 1}, IPProtoUDP, 0x1234, 16, false, udpDNS[16:])

	// 2. Fragmented QUIC v1 Initial datagram over IPv4 UDP (delivered out-of-order: frag2 then frag1).
	quicCH := buildTLS13ClientHelloRecord("frag-quic.example.com", "h3")
	quicDgram := buildEncryptedQUICInitialDatagram(t, QUICVersion1, []byte{1, 2, 3, 4, 5, 6, 7, 8}, []byte{9, 10, 11, 12}, nil, 1, 0, quicCH[5:])
	udpQUIC := make([]byte, 8+len(quicDgram))
	binary.BigEndian.PutUint16(udpQUIC[0:2], 55555)
	binary.BigEndian.PutUint16(udpQUIC[2:4], 443)
	binary.BigEndian.PutUint16(udpQUIC[4:6], uint16(len(udpQUIC)))
	copy(udpQUIC[8:], quicDgram)

	quicFrag1 := buildEthernetIPv4FragmentFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 9}, IPProtoUDP, 0x5678, 0, true, udpQUIC[:32])
	quicFrag2 := buildEthernetIPv4FragmentFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 9}, IPProtoUDP, 0x5678, 32, false, udpQUIC[32:])

	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{
		dnsFrag1, dnsFrag2, quicFrag2, quicFrag1,
	})
	cap, err := New(raw)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	dnsRecs, err := cap.DNS(raw)
	if err != nil || len(dnsRecs) != 1 {
		t.Fatalf("DNS() on fragmented UDP = (%d, %v), want 1", len(dnsRecs), err)
	}
	if has, err := cap.HasDNSQuery(raw, "c2.example.com"); err != nil || !has {
		t.Fatalf("HasDNSQuery() on fragmented UDP = (%v, %v), want true", has, err)
	}

	quicRecs, err := cap.QUIC(raw)
	if err != nil || len(quicRecs) != 1 || !bytes.Equal([]byte(quicRecs[0].Handshake.ClientHello.SNI), []byte("frag-quic.example.com")) {
		t.Fatalf("QUIC() on fragmented UDP = (%+v, %v)", quicRecs, err)
	}
}
