package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
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

	// Overlap conflict after a gap must still be detected and offsets preserved.
	gapConflict := []IPFragmentInput{
		{SrcAddr: src, DstAddr: dst, Protocol: IPProtoUDP, Identification: 101, FragmentOffset: 8, MoreFragments: true, Payload: []byte("AAAAAAAA")},
		{SrcAddr: src, DstAddr: dst, Protocol: IPProtoUDP, Identification: 101, FragmentOffset: 8, MoreFragments: false, Payload: []byte("BBBBBBBB")},
	}
	outGap, anomGap, err := DefragmentIP(gapConflict)
	if err != nil {
		t.Fatalf("DefragmentIP(gapConflict) err = %v", err)
	}
	if !anomGap.TruncatedLayer || !anomGap.IPFragmentOverlapConflict {
		t.Fatalf("gapConflict anomalies = %+v, want TruncatedLayer and IPFragmentOverlapConflict", anomGap)
	}
	if len(outGap) != 16 || string(outGap[8:16]) != "AAAAAAAA" {
		t.Fatalf("gapConflict out = %q (len=%d), want 8 zero bytes + AAAAAAAA", outGap, len(outGap))
	}

	// Zero-length terminal fragment contiguous with received data should not set TruncatedLayer.
	zeroTerm := []IPFragmentInput{
		{SrcAddr: src, DstAddr: dst, Protocol: IPProtoUDP, Identification: 102, FragmentOffset: 0, MoreFragments: true, Payload: []byte("01234567")},
		{SrcAddr: src, DstAddr: dst, Protocol: IPProtoUDP, Identification: 102, FragmentOffset: 8, MoreFragments: false, Payload: nil},
	}
	outZeroTerm, anomZeroTerm, err := DefragmentIP(zeroTerm)
	if err != nil || anomZeroTerm.TruncatedLayer || string(outZeroTerm) != "01234567" {
		t.Fatalf("DefragmentIP(zeroTerm) = (%q, %+v, %v)", outZeroTerm, anomZeroTerm, err)
	}

	// Zero-length terminal fragment beyond a missing tail must set TruncatedLayer.
	gappedZeroTerm := []IPFragmentInput{
		{SrcAddr: src, DstAddr: dst, Protocol: IPProtoUDP, Identification: 102, FragmentOffset: 0, MoreFragments: true, Payload: []byte("01234567")},
		{SrcAddr: src, DstAddr: dst, Protocol: IPProtoUDP, Identification: 102, FragmentOffset: 16, MoreFragments: false, Payload: nil},
	}
	_, anomGappedZeroTerm, err := DefragmentIP(gappedZeroTerm)
	if err != nil || !anomGappedZeroTerm.TruncatedLayer {
		t.Fatalf("DefragmentIP(gappedZeroTerm) = (%+v, %v), want TruncatedLayer", anomGappedZeroTerm, err)
	}

	// Fragment extending past an earlier terminal fragment sets TruncatedLayer.
	pastTerm := []IPFragmentInput{
		{SrcAddr: src, DstAddr: dst, Protocol: IPProtoUDP, Identification: 103, FragmentOffset: 0, MoreFragments: false, Payload: []byte("01234567")},
		{SrcAddr: src, DstAddr: dst, Protocol: IPProtoUDP, Identification: 103, FragmentOffset: 8, MoreFragments: true, Payload: []byte("89ABCDEF")},
	}
	_, anomPast, err := DefragmentIP(pastTerm)
	if err != nil || !anomPast.TruncatedLayer {
		t.Fatalf("DefragmentIP(pastTerm) = (%+v, %v), want TruncatedLayer", anomPast, err)
	}

	// ipFragAccumulator must sustain turnover at MaxFragmentGroups capacity (incomplete groups)
	// and evict completed groups so reused IPIDs succeed.
	var acc ipFragAccumulator
	udp := make([]byte, 16)
	binary.BigEndian.PutUint16(udp[0:2], 53)
	binary.BigEndian.PutUint16(udp[2:4], 12345)
	binary.BigEndian.PutUint16(udp[4:6], 16)
	copy(udp[8:], []byte("12345678"))
	// Fill to capacity with incomplete groups, then churn past capacity.
	for i := range MaxFragmentGroups * 2 {
		f1 := Frame{IPVersion: 4, IPProtocol: IPProtoUDP, SrcAddr: src, DstAddr: dst, IPID: uint32(10000 + i), IPFragOffset: 0, IPMoreFragments: true, PayloadLength: 8}
		if _, _, _, ok := acc.addUDPFragment(&f1, udp[:8]); ok {
			t.Fatalf("incomplete iter %d unexpectedly completed", i)
		}
		if len(acc.groups) > MaxFragmentGroups {
			t.Fatalf("groups len = %d, exceeds MaxFragmentGroups %d", len(acc.groups), MaxFragmentGroups)
		}
	}
	// While at capacity, new complete datagrams (including reused IPIDs) must still reassemble.
	for i := range MaxFragmentGroups + 10 {
		ipID := uint32(i % 64)
		f1 := Frame{IPVersion: 4, IPProtocol: IPProtoUDP, SrcAddr: src, DstAddr: dst, IPID: ipID, IPFragOffset: 0, IPMoreFragments: true, PayloadLength: 8}
		f2 := Frame{IPVersion: 4, IPProtocol: IPProtoUDP, SrcAddr: src, DstAddr: dst, IPID: ipID, IPFragOffset: 8, IPMoreFragments: false, PayloadLength: 8}
		if _, _, _, ok := acc.addUDPFragment(&f1, udp[:8]); ok {
			t.Fatalf("iter %d: first fragment unexpectedly completed", i)
		}
		payload, sp, dp, ok := acc.addUDPFragment(&f2, udp[8:])
		if !ok || sp != 53 || dp != 12345 || string(payload) != "12345678" {
			t.Fatalf("iter %d: addUDPFragment = (%q, %d, %d, %v)", i, payload, sp, dp, ok)
		}
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

	checkReaderParity(t, raw, cap.DNS, cap.DNSFromReaderAt)
	checkReaderParity(t, raw, cap.QUIC, cap.QUICFromReaderAt)
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

func TestIPv6FragmentPolicy(t *testing.T) {
	for _, kind := range []string{"dns", "quic"} {
		var payload []byte
		src, dst := uint16(53), uint16(53000)
		if kind == "dns" {
			payload = buildDNSQueryResponsePacket()
		} else {
			var err error
			payload, err = os.ReadFile("testdata/rfc9001-client.bin")
			if err != nil {
				t.Fatal(err)
			}
			src, dst = 53000, 443
		}
		udp := make([]byte, 8+len(payload))
		binary.BigEndian.PutUint16(udp, src)
		binary.BigEndian.PutUint16(udp[2:], dst)
		binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
		copy(udp[8:], payload)
		frame := func(off uint16, more bool, data []byte) []byte {
			wire := make([]byte, 62+len(data))
			binary.BigEndian.PutUint16(wire[12:], EtherTypeIPv6)
			wire[14], wire[20], wire[21] = 0x60, IPProtoIPv6Frag, 64
			wire[37], wire[53] = 1, 2
			binary.BigEndian.PutUint16(wire[18:], uint16(8+len(data)))
			wire[54] = IPProtoUDP
			if more {
				off |= 1
			}
			binary.BigEndian.PutUint16(wire[56:], off)
			binary.BigEndian.PutUint32(wire[58:], 7)
			copy(wire[62:], data)
			return wire
		}
		tiny, err := DecodeFrame(frame(0, true, udp[:4]), LinkTypeEthernet)
		if err != nil || !tiny.Anomalies.TruncatedLayer {
			t.Fatalf("short first UDP header: %+v, %v", tiny, err)
		}
		first := frame(0, true, udp[:16])
		last := frame(16, false, udp[16:])
		atomic := frame(0, false, udp)
		for _, tc := range []struct {
			name   string
			frames [][]byte
			want   int
		}{
			{"reordered", [][]byte{last, first}, 1},
			{"identical overlap", [][]byte{first, first, last}, 0},
			{"conflicting overlap", [][]byte{first, frame(8, true, make([]byte, 8)), last}, 0},
			{"short first header", [][]byte{frame(0, true, udp[:4]), first, last}, 0},
			{"independent atomic", [][]byte{first, atomic, last}, 2},
		} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, tc.frames)
				c, err := New(raw)
				if err != nil {
					t.Fatal(err)
				}
				checkReaderParity(t, raw, c.DNS, c.DNSFromReaderAt)
				checkReaderParity(t, raw, c.QUIC, c.QUICFromReaderAt)
				var n int
				if kind == "dns" {
					r, e := c.DNS(raw)
					err = e
					n = len(r)
				} else {
					r, e := c.QUIC(raw)
					err = e
					n = len(r)
				}
				// QUIC emits one handshake per flow for the two valid datagrams.
				want := tc.want
				if kind == "quic" && want == 2 {
					want = 1
				}
				if err != nil || n != want {
					t.Fatalf("records = %d, %v; want %d", n, err, want)
				}
			})
		}
	}
}

func BenchmarkIPFragments(b *testing.B) {
	for _, tc := range []struct {
		name, addr string
		overlap    bool
	}{
		{"IPv4", "192.0.2.1", false}, {"IPv6", "2001:db8::1", false}, {"IPv6Overlap", "2001:db8::1", true},
	} {
		b.Run(tc.name, func(b *testing.B) {
			var parts [8]IPFragmentInput
			addr := netip.MustParseAddr(tc.addr)
			for i := range parts {
				parts[7-i] = IPFragmentInput{SrcAddr: addr, DstAddr: addr, Protocol: IPProtoUDP, FragmentOffset: i * 128, MoreFragments: i < 7, Payload: make([]byte, 128)}
			}
			if tc.overlap {
				parts[0].FragmentOffset -= 8
			}
			b.ReportAllocs()
			for b.Loop() {
				if _, _, err := DefragmentIP(parts[:]); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestIPv4DifferentStartFirstArrival(t *testing.T) {
	frags := []IPFragmentInput{
		{FragmentOffset: 8, Payload: []byte("first123"), MoreFragments: true},
		{FragmentOffset: 0, Payload: []byte("01234567later123"), MoreFragments: true},
		{FragmentOffset: 16, Payload: []byte("end")},
	}
	data, a, err := DefragmentIP(frags)
	if err != nil || !a.IPFragmentOverlapConflict || a.TruncatedLayer || string(data) != "01234567first123end" {
		t.Fatalf("data=%q anomalies=%+v error=%v", data, a, err)
	}
}
