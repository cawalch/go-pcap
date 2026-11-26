package pcap

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"os"
	"testing"
)

func ipipIPv4(proto uint8, payload []byte) []byte {
	ip := []byte{0x45, 0, 0, 0, 0, 1, 0, 0, 64, proto, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2}
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)+len(payload)))
	return append(ip, payload...)
}

func ipipIPv6(proto uint8, payload []byte) []byte {
	ip := make([]byte, 40, 40+len(payload))
	ip[0], ip[6], ip[7] = 0x60, proto, 64
	binary.BigEndian.PutUint16(ip[4:6], uint16(len(payload)))
	src, dst := netip.MustParseAddr("2001:db8::1").As16(), netip.MustParseAddr("2001:db8::2").As16()
	copy(ip[8:24], src[:])
	copy(ip[24:40], dst[:])
	return append(ip, payload...)
}

func TestDecodeIPIPFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/framing/ipip.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	c, packets := readWrittenPackets(t, raw)
	want := []struct {
		ipVersion uint8
		marker    LayerSpan
		srcPort   uint16
		dstPort   uint16
	}{
		{4, LayerSpan{LayerIPIP, 34, 20}, 40000, 8080},
		{6, LayerSpan{LayerIPIP, 34, 40}, 41000, 8443},
		{6, LayerSpan{LayerIPIP, 54, 40}, 41000, 8443},
	}
	if len(packets) != len(want) {
		t.Fatalf("got %d packets, want %d", len(packets), len(want))
	}
	for i, pkt := range packets {
		data, err := c.PacketPayload(raw, pkt)
		if err != nil {
			t.Fatal(err)
		}
		f, err := DecodeFrame(data, pkt.LinkType)
		expected := want[i]
		if err != nil || f.Anomalies.Any() || f.IPVersion != expected.ipVersion ||
			f.IPProtocol != IPProtoTCP || f.SrcPort != expected.srcPort || f.DstPort != expected.dstPort ||
			f.Layers[2] != expected.marker || f.Layers[4].Proto != LayerTCP {
			t.Fatalf("packet %d = %+v, %v", i, f, err)
		}
	}
	r := bytes.NewReader(raw)
	b, err := NewFromReaderAt(r, r.Size())
	if err != nil {
		t.Fatal(err)
	}
	checkReaderParity(t, raw, c.Flows, b.FlowsFromReaderAt)
}

func TestDecodeIPIPBounds(t *testing.T) {
	tcp := framingIPv4TCP(nil)[20:]
	inner := ipipIPv4(IPProtoTCP, tcp)
	tooShort := ipipIPv4(IPProtoIPv4Encap, inner)
	binary.BigEndian.PutUint16(tooShort[2:4], 36)
	wrongVersion := ipipIPv4(IPProtoIPv6, inner)
	for _, tc := range []struct {
		name         string
		wire         []byte
		wantTruncate bool
		wantInvalid  bool
	}{
		{"empty outer payload", ipipIPv4(IPProtoIPv4Encap, nil), true, false},
		{"bytes beyond outer datagram", tooShort, true, false},
		{"truncated inner IPv6", ipipIPv4(IPProtoIPv6, inner[:39]), true, false},
		{"wrong inner version", wrongVersion, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := DecodeFrame(tc.wire, LinkTypeRaw)
			if err != nil || f.Anomalies.TruncatedLayer != tc.wantTruncate ||
				f.Anomalies.InvalidIPHeaderLength != tc.wantInvalid ||
				f.IPVersion != 4 || f.SrcPort != 0 || f.LayerCount != 2 {
				t.Fatalf("frame = %+v, %v", f, err)
			}
		})
	}

	data := inner
	for range MaxFrameLayers {
		data = ipipIPv4(IPProtoIPv4Encap, data)
	}
	f, err := DecodeFrame(data, LinkTypeRaw)
	if err != nil || !f.Anomalies.TruncatedLayer || f.LayerCount != MaxFrameLayers ||
		f.IPProtocol != IPProtoIPv4Encap || f.SrcPort != 0 {
		t.Fatalf("depth-limited frame = %+v, %v", f, err)
	}
}

func TestIPIPFlowCompatibility(t *testing.T) {
	tcp := framingIPv4TCP(make([]byte, 512))[20:]
	inner4, inner6 := ipipIPv4(IPProtoTCP, tcp), ipipIPv6(IPProtoTCP, tcp)
	for _, tc := range []struct {
		name    string
		link    LinkType
		wire    []byte
		payload []byte
		proto   uint8
		src     string
		dst     string
	}{
		{"IPv4 in IPv4", LinkTypeRaw, ipipIPv4(IPProtoIPv4Encap, inner4), inner4, IPProtoIPv4Encap, "192.0.2.1", "192.0.2.2"},
		{"IPv6 in IPv4", LinkTypeRaw, ipipIPv4(IPProtoIPv6, inner6), inner6, IPProtoIPv6, "192.0.2.1", "192.0.2.2"},
		{"IPv6 in IPv6", LinkTypeRaw, ipipIPv6(IPProtoIPv6, inner6), inner6, IPProtoIPv6, "2001:db8::1", "2001:db8::2"},
		{"PKTAP IPv4 in IPv4", LinkTypeApplePktap, pktapFrame(320, 12, ipipIPv4(IPProtoIPv4Encap, inner4)), inner4, IPProtoIPv4Encap, "192.0.2.1", "192.0.2.2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := buildClassicPCAP(binary.LittleEndian, false, tc.link, MaxSnapLen, [][]byte{tc.wire})
			a, _ := readWrittenPackets(t, raw)
			r := bytes.NewReader(raw)
			b, err := NewFromReaderAt(r, r.Size())
			if err != nil {
				t.Fatal(err)
			}
			flows := checkReaderParity(t, raw, a.Flows, b.FlowsFromReaderAt)
			if len(flows) != 1 {
				t.Fatalf("flows = %+v", flows)
			}
			f := flows[0]
			if f.Protocol != tc.proto || f.SrcAddr.String() != tc.src || f.DstAddr.String() != tc.dst ||
				!f.PortsUnavailable || f.SrcPort != 0 || f.DstPort != 0 || f.CommunityID(0) != "" ||
				f.ClientBytes != uint64(len(tc.payload)) || f.Anomalies.Any() {
				t.Fatalf("outer flow key or accounting changed: %+v", f)
			}
		})
	}
}

func TestIPIPCaptureFlowIndices(t *testing.T) {
	dns := buildDNSQueryResponsePacket()
	udp := buildEthernetIPv4UDPFrame([4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}, 53, 55555, dns)[34:]
	inner := ipipIPv6(IPProtoUDP, udp)
	ext := make([]byte, 256)
	ext[0], ext[1] = IPProtoIPv6, byte(len(ext)/8-1)
	tunnel := ipipIPv6(IPProtoHopByHop, append(ext, inner...))
	second := bytes.Clone(tunnel)
	second[39] = 3 // A different enclosing destination with the same inner tuple.
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeRaw, MaxSnapLen, [][]byte{tunnel, second, inner})
	c, packets := readWrittenPackets(t, raw)
	r := bytes.NewReader(raw)
	file, err := NewFromReaderAt(r, r.Size())
	if err != nil {
		t.Fatal(err)
	}
	flows := checkReaderParity(t, raw, c.Flows, file.FlowsFromReaderAt)
	if len(flows) != 3 || flows[0].CommunityID(0) != "" || flows[1].CommunityID(0) != "" || flows[2].CommunityID(0) == "" {
		t.Fatalf("flows = %+v", flows)
	}
	records := checkReaderParity(t, raw, c.DNS, file.DNSFromReaderAt)
	if len(records) != 1 || records[0].FlowIndex != 2 || records[0].PacketIndex != 2 {
		t.Fatalf("DNS records = %+v", records)
	}
	for i, want := range [][]byte{tunnel, second} {
		payload, err := file.PacketPayloadFromReaderAt(r, packets[i])
		if err != nil {
			t.Fatal(err)
		}
		f, err := DecodeFrame(payload, packets[i].LinkType)
		if err != nil || f.IPVersion != 6 || f.IPProtocol != IPProtoUDP || f.SrcPort != 53 ||
			f.PayloadOffset <= 256 || f.PayloadLength != uint32(len(dns)) || f.Anomalies.Any() {
			t.Fatalf("ReaderAt packet %d = %+v, %v", i, f, err)
		}
		var sliceExport, readerExport bytes.Buffer
		if err := c.ExtractFlowPCAPNG(raw, &sliceExport, i); err != nil {
			t.Fatal(err)
		}
		if err := file.ExtractFlowPCAPNGFromReaderAt(r, &readerExport, i); err != nil {
			t.Fatal(err)
		}
		for _, capture := range [][]byte{sliceExport.Bytes(), readerExport.Bytes()} {
			export, exported := readWrittenPackets(t, capture)
			if len(exported) != 1 {
				t.Fatalf("flow %d exported %d packets", i, len(exported))
			}
			data, err := export.PacketPayload(capture, exported[0])
			if err != nil || !bytes.Equal(data, want) {
				t.Fatalf("flow %d selected the wrong packet (%v)", i, err)
			}
		}
	}
}

func BenchmarkDecodeFrameIPIP(b *testing.B) {
	wire := ipipIPv4(IPProtoIPv4Encap, framingIPv4TCP([]byte("payload")))
	b.ReportAllocs()
	for b.Loop() {
		if f, err := DecodeFrame(wire, LinkTypeRaw); err != nil || f.IPProtocol != IPProtoTCP {
			b.Fatal(f, err)
		}
	}
}
