package pcap

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"
)

func TestDecodePPPAndPFLOGFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/framing/ppp-pflog.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	c, packets := readWrittenPackets(t, raw)
	if c.Anomalies().UnknownLinkType || len(packets) != 3 {
		t.Fatalf("packets = %d, anomalies %+v", len(packets), c.Anomalies())
	}
	for i, pkt := range packets {
		data, err := c.PacketPayload(raw, pkt)
		if err != nil {
			t.Fatal(err)
		}
		frame, err := DecodeFrame(data, pkt.LinkType)
		if err != nil || frame.Anomalies.Any() || frame.IPProtocol != IPProtoTCP ||
			frame.SrcPort != []uint16{50000, 50001, 40000}[i] || frame.DstPort != []uint16{443, 443, 8080}[i] ||
			frame.Layers[0].Length != []uint32{4, 1, 48}[i] {
			t.Fatalf("packet %d = %+v, %v", i, frame, err)
		}
	}
	reader := bytes.NewReader(raw)
	file, err := NewFromReaderAt(reader, reader.Size())
	if err != nil || file.Anomalies().UnknownLinkType {
		t.Fatalf("ReaderAt capture: %v, %v", file, err)
	}
	checkReaderParity(t, raw, c.Flows, file.FlowsFromReaderAt)
}

func TestPPPAndPFLOGExtendedPrefixes(t *testing.T) {
	ip := buildEthernetIPv4TCPFrame([4]byte{192, 0, 2, 1}, [4]byte{198, 51, 100, 2}, 5000, 443, 10, 0, TCPFlagSYN, make([]byte, 512))[14:]
	pflog := make([]byte, 256)
	pflog[0], pflog[1] = 255, 2
	for _, tc := range []struct {
		link   LinkType
		prefix []byte
	}{
		{LinkTypePPP, []byte{0x21}},
		{LinkTypePPPHDLC, []byte{0xff, 0x03, 0x00, 0x21}},
		{LinkTypePPPPPPD, []byte{0x01, 0x03, 0x00, 0x21}},
		{LinkTypePPPWithDir, []byte{0x01, 0xff, 0x03, 0x21}},
		{LinkTypePFLOG, pflog},
	} {
		frame := append(bytes.Clone(tc.prefix), ip...)
		raw := buildClassicPCAP(binary.BigEndian, false, tc.link, MaxSnapLen, [][]byte{frame})
		c, _ := readWrittenPackets(t, raw)
		r := bytes.NewReader(raw)
		file, err := NewFromReaderAt(r, r.Size())
		if err != nil || file.Anomalies().UnknownLinkType {
			t.Fatalf("link %d: %v, %v", tc.link, file, err)
		}
		checkReaderParity(t, raw, c.Flows, file.FlowsFromReaderAt)
		flows, err := file.FlowsFromReaderAt(r)
		if err != nil || len(flows) != 1 || flows[0].DstPort != 443 {
			t.Fatalf("link %d flows = %+v, %v", tc.link, flows, err)
		}
	}
}

func TestDecodePPPAndPFLOGBounds(t *testing.T) {
	for _, tc := range []struct {
		link LinkType
		data []byte
	}{
		{LinkTypePPP, []byte{0xff, 0x03}},
		{LinkTypePPP, []byte{0x00}},
		{LinkTypePPPHDLC, []byte{0xff}},
		{LinkTypePPPPPPD, []byte{0}},
		{LinkTypePPPWithDir, []byte{0}},
		{LinkTypePFLOG, []byte{61, 2}},
	} {
		f, err := DecodeFrame(tc.data, tc.link)
		if err != nil || !f.Anomalies.TruncatedLayer || f.IPVersion != 0 {
			t.Fatalf("link %d short frame = %+v, %v", tc.link, f, err)
		}
	}
	f, err := DecodeFrame([]byte{0xc0, 0x21, 1, 2, 3}, LinkTypePPP) // LCP.
	if err != nil || f.Anomalies.Any() || f.IPVersion != 0 || f.PayloadOffset != 2 || f.PayloadLength != 3 {
		t.Fatalf("opaque LCP = %+v, %v", f, err)
	}
}

func BenchmarkDecodeFramePPPAndPFLOG(b *testing.B) {
	ip := buildEthernetIPv4TCPFrame([4]byte{192, 0, 2, 1}, [4]byte{198, 51, 100, 2}, 5000, 443, 10, 0, TCPFlagSYN, []byte("payload"))[14:]
	pflog := make([]byte, 48)
	pflog[0], pflog[1] = 45, 2
	for _, tc := range []struct {
		name string
		link LinkType
		wire []byte
	}{
		{"PPP", LinkTypePPP, append([]byte{0x21}, ip...)},
		{"PFLOG", LinkTypePFLOG, append(pflog, ip...)},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if f, err := DecodeFrame(tc.wire, tc.link); err != nil || f.IPVersion != 4 {
					b.Fatal(f, err)
				}
			}
		})
	}
}
