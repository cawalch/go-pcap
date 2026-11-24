package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"slices"
	"testing"
)

func readFramingFixture(t testing.TB) ([]byte, *Capture, []PacketRecord) {
	t.Helper()
	raw, err := os.ReadFile("testdata/framing/wireless-ipsec.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	packets, err := c.Packets(raw)
	if err != nil {
		t.Fatal(err)
	}
	return raw, c, packets
}

func TestDecodeFrameWirelessAndIPsec(t *testing.T) {
	raw, c, packets := readFramingFixture(t)
	want := []struct {
		link   LinkType
		layers []LayerSpan
		offset uint32
		length uint32
	}{
		{LinkTypeIEEE80211, []LayerSpan{{LayerIEEE80211, 0, 24}, {LayerIPv4, 32, 20}, {LayerUDP, 52, 8}}, 60, 30},
		{LinkTypeIEEE80211, []LayerSpan{{LayerIEEE80211, 0, 36}, {LayerIPv4, 44, 20}, {LayerUDP, 64, 8}}, 72, 30},
		{LinkTypeIEEE80211RadioTap, []LayerSpan{{LayerRadiotap, 0, 25}, {LayerIEEE80211, 25, 26}, {LayerIPv4, 61, 20}, {LayerUDP, 81, 8}}, 89, 30},
		{LinkTypeIEEE80211RadioTap, []LayerSpan{{LayerRadiotap, 0, 300}, {LayerIEEE80211, 300, 24}, {LayerIPv4, 332, 20}, {LayerUDP, 352, 8}}, 360, 30},
		{LinkTypeEthernet, []LayerSpan{{LayerEthernet, 0, 14}, {LayerIPv4, 14, 20}, {LayerESP, 34, 8}}, 42, 16},
		{LinkTypeEthernet, []LayerSpan{{LayerEthernet, 0, 14}, {LayerIPv6, 14, 40}, {LayerESP, 54, 8}}, 62, 16},
		{LinkTypeEthernet, []LayerSpan{{LayerEthernet, 0, 14}, {LayerIPv4, 14, 20}, {LayerUDP, 34, 8}, {LayerIKEv2, 42, 28}}, 70, 8},
		{LinkTypeEthernet, []LayerSpan{{LayerEthernet, 0, 14}, {LayerIPv4, 14, 20}, {LayerUDP, 34, 8}, {LayerIKEv2, 46, 28}}, 74, 8},
	}
	if c.Anomalies().UnknownLinkType || len(packets) != len(want) {
		t.Fatalf("capture has %d packets, anomalies %+v", len(packets), c.Anomalies())
	}
	for i, pkt := range packets {
		data, err := c.PacketPayload(raw, pkt)
		if err != nil {
			t.Fatal(err)
		}
		f, err := DecodeFrame(data, pkt.LinkType)
		w := want[i]
		if err != nil || f.Anomalies.Any() || f.LinkType != w.link || !slices.Equal(f.LayerSlices(), w.layers) ||
			f.PayloadOffset != w.offset || f.PayloadLength != w.length {
			t.Fatalf("frame %d layers = %v; payload = %d/%d; anomalies = %+v, %v", i+1, f.LayerSlices(), f.PayloadOffset, f.PayloadLength, f.Anomalies, err)
		}
		if i == 4 || i == 5 {
			last := f.LayerSlices()[len(f.LayerSlices())-1]
			if f.IPProtocol != IPProtoESP || f.hasPorts ||
				binary.BigEndian.Uint32(data[last.Offset:]) != 0x10203040 ||
				binary.BigEndian.Uint32(data[last.Offset+4:]) != 7 {
				t.Fatalf("frame %d ESP protocol or header fields differ", i+1)
			}
		}
	}
	for _, tc := range []struct {
		proto LayerProto
		name  string
	}{{LayerIEEE80211, "ieee80211"}, {LayerRadiotap, "radiotap"}, {LayerESP, "esp"}, {LayerIKEv2, "ikev2"}} {
		if tc.proto.String() != tc.name {
			t.Errorf("layer %d string = %q, want %q", tc.proto, tc.proto.String(), tc.name)
		}
	}

	reader := bytes.NewReader(raw)
	fileCapture, err := NewFromReaderAt(reader, reader.Size())
	if err != nil || fileCapture.Anomalies().UnknownLinkType {
		t.Fatalf("ReaderAt capture: %v, %v", fileCapture, err)
	}
	checkReaderParity(t, raw, c.Flows, fileCapture.FlowsFromReaderAt)
	checkReaderParity(t, raw, c.DNS, fileCapture.DNSFromReaderAt)
	dns, err := fileCapture.DNSFromReaderAt(reader)
	if err != nil || len(dns) != 4 {
		t.Fatalf("wireless DNS = %+v, %v", dns, err)
	}
	for i, record := range dns {
		if record.PacketIndex != i || record.FlowIndex != 0 || len(record.Message.Questions) != 1 ||
			record.Message.Questions[0].Name != "wifi.example" {
			t.Errorf("wireless DNS record = %+v", record)
		}
	}
	var out bytes.Buffer
	if err := fileCapture.ExtractFlowPCAPNGFromReaderAt(reader, &out, 0); err != nil {
		t.Fatal(err)
	}
	extracted, _ := readWrittenPackets(t, out.Bytes())
	if extracted.PacketCount != 4 || len(extracted.Interfaces) != 2 {
		t.Fatalf("exported wireless flow has %d packets on %d interfaces", extracted.PacketCount, len(extracted.Interfaces))
	}
}

func TestDecodeFrameWirelessBounds(t *testing.T) {
	raw, c, packets := readFramingFixture(t)
	for _, tc := range []struct {
		name   string
		packet int
		adjust func([]byte) []byte
		err    bool
		short  bool
	}{
		{"frame-control", 0, func(p []byte) []byte { return p[:1] }, true, false},
		{"data-header", 0, func(p []byte) []byte { return p[:23] }, false, true},
		{"qos-address4-ht-control", 1, func(p []byte) []byte { return p[:35] }, false, true},
		{"protected", 0, func(p []byte) []byte { p[1] |= 0x40; return p }, false, false},
		{"more-fragments", 0, func(p []byte) []byte { p[1] |= 4; return p }, false, false},
		{"noninitial-fragment", 0, func(p []byte) []byte { p[22] |= 1; return p }, false, false},
		{"null-data", 0, func(p []byte) []byte { p[0] |= 0x40; return p }, false, false},
		{"management", 0, func(p []byte) []byte { p[0] = 0x80; return p }, false, false},
		{"a-msdu", 1, func(p []byte) []byte { p[30] |= 0x80; return p }, false, false},
		{"llc-prefix", 0, func(p []byte) []byte { return p[:31] }, false, true},
		{"llc-other-oui", 0, func(p []byte) []byte { p[27] = 1; return p }, false, false},
		{"radiotap-header", 2, func(p []byte) []byte { return p[:7] }, true, false},
		{"radiotap-version", 2, func(p []byte) []byte { p[0] = 1; return p }, true, false},
		{"radiotap-short-length", 2, func(p []byte) []byte { p[2] = 7; return p }, true, false},
		{"radiotap-long-length", 2, func(p []byte) []byte { p[2] = 255; return p }, true, false},
		{"radiotap-missing-flags", 2, func(p []byte) []byte { p[2] = 24; return p }, true, false},
		{"radiotap-missing-present-word", 2, func(p []byte) []byte { p[2] = 9; return p }, true, false},
		{"radiotap-short-80211", 2, func(p []byte) []byte { return p[:26] }, false, true},
		{"radiotap-short-padding", 2, func(p []byte) []byte { return p[:52] }, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pkt := packets[tc.packet]
			data, err := c.PacketPayload(raw, pkt)
			if err != nil {
				t.Fatal(err)
			}
			f, err := DecodeFrame(tc.adjust(bytes.Clone(data)), pkt.LinkType)
			if (tc.err && !errors.Is(err, ErrInvalidFrame)) || (!tc.err && err != nil) ||
				f.Anomalies.TruncatedLayer != tc.short || f.IPVersion != 0 {
				t.Fatalf("frame = %+v, error = %v", f, err)
			}
		})
	}
}

func TestDecodeFrameIPsecBounds(t *testing.T) {
	raw, c, packets := readFramingFixture(t)
	esp, err := c.PacketPayload(raw, packets[4])
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{34, 41} {
		f, err := DecodeFrame(esp[:n], LinkTypeEthernet)
		if err != nil || !f.Anomalies.TruncatedLayer || len(f.LayerSlices()) != 2 {
			t.Errorf("short ESP header (%d bytes) = %v, %+v, %v", n, f.LayerSlices(), f.Anomalies, err)
		}
	}

	ike, err := c.PacketPayload(raw, packets[7])
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		adjust func([]byte) []byte
	}{
		{"esp-in-udp", func(p []byte) []byte { p[42] = 0x12; return p }},
		{"missing-length", func(p []byte) []byte { return p[:71] }},
		{"short-body", func(p []byte) []byte { return p[:81] }},
		{"ikev1", func(p []byte) []byte { p[63] = 0x10; return p }},
		{"declared-shorter-than-udp", func(p []byte) []byte { p[73] = 28; return p }},
		{"declared-longer-than-udp", func(p []byte) []byte { p[73] = 37; return p }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.adjust(bytes.Clone(ike))
			f, err := DecodeFrame(p, LinkTypeEthernet)
			if err != nil || f.PayloadOffset != 42 || len(f.LayerSlices()) != 3 || f.LayerSlices()[2].Proto != LayerUDP {
				t.Fatalf("unclassified UDP payload = %+v, %v", f, err)
			}
		})
	}
}

func BenchmarkDecodeFrameWirelessAndIPsec(b *testing.B) {
	raw, c, packets := readFramingFixture(b)
	for _, tc := range []struct {
		name   string
		packet int
	}{{"80211", 1}, {"radiotap", 2}, {"esp", 4}, {"ikev2", 7}} {
		b.Run(tc.name, func(b *testing.B) {
			pkt := packets[tc.packet]
			data, err := c.PacketPayload(raw, pkt)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.SetBytes(int64(len(data)))
			for b.Loop() {
				if _, err := DecodeFrame(data, pkt.LinkType); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestLongIKEFlowBytes(t *testing.T) {
	for _, port := range []uint16{500, 4500} {
		marker := 0
		if port == 4500 {
			marker = 4
		}
		body := make([]byte, 300+marker)
		body[marker+17] = 0x20
		binary.BigEndian.PutUint32(body[marker+24:], 300)
		frame := buildEthernetIPv4UDPFrame([4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}, 50000, port, body)
		data := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{frame})
		c, err := New(data)
		if err != nil {
			t.Fatal(err)
		}
		r := &measuredReaderAt{Reader: bytes.NewReader(data)}
		flows, err := c.FlowsFromReaderAt(r)
		if r.bytesRead > 16+256 {
			t.Fatalf("read %d bytes for IKE flow headers", r.bytesRead)
		}
		checkReaderParity(t, data, c.Flows, c.FlowsFromReaderAt)
		if err != nil || len(flows) != 1 || flows[0].ClientBytes != 272 {
			t.Fatalf("port %d: flows=%+v err=%v", port, flows, err)
		}
	}
}

func TestIKEHeaderSpanningReaderAtPrefix(t *testing.T) {
	const extLen, ikeLen = 200, 4096
	const udp = 40 + extLen
	for _, port := range []uint16{500, 4500} {
		marker := 0
		if port == 4500 {
			marker = 4
		}
		frame := make([]byte, udp+8+marker+ikeLen)
		frame[0], frame[6], frame[7] = 0x60, IPProtoHopByHop, 64
		binary.BigEndian.PutUint16(frame[4:], uint16(len(frame)-40))
		frame[40], frame[41] = IPProtoUDP, extLen/8-1
		binary.BigEndian.PutUint16(frame[udp:], 50000)
		binary.BigEndian.PutUint16(frame[udp+2:], port)
		binary.BigEndian.PutUint16(frame[udp+4:], uint16(len(frame)-udp))
		ike := udp + 8 + marker
		frame[ike+17] = 0x20
		binary.BigEndian.PutUint32(frame[ike+24:], ikeLen)
		raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeRaw, 65535, [][]byte{frame})
		c, err := New(raw)
		if err != nil {
			t.Fatal(err)
		}
		r := &measuredReaderAt{Reader: bytes.NewReader(raw)}
		flows, err := c.FlowsFromReaderAt(r)
		if err != nil || len(flows) != 1 || flows[0].ClientBytes != ikeLen-28 {
			t.Fatalf("port %d: %+v, %v", port, flows, err)
		}
		if want := int64(16 + ike + 28); r.bytesRead != want {
			t.Fatalf("port %d: read %d bytes, want %d through IKE header", port, r.bytesRead, want)
		}
		checkReaderParity(t, raw, c.Flows, c.FlowsFromReaderAt)
	}
}
