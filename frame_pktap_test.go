package pcap

import (
	"bytes"
	"encoding/binary"
	"os"
	"slices"
	"testing"
)

func pktapFrame(length int, dlt uint32, payload []byte) []byte {
	wire := make([]byte, length, length+len(payload))
	binary.LittleEndian.PutUint32(wire[0:4], uint32(length))
	binary.LittleEndian.PutUint32(wire[4:8], 1)
	binary.LittleEndian.PutUint32(wire[8:12], dlt)
	return append(wire, payload...)
}

func TestDecodeApplePktapFixture(t *testing.T) {
	for _, name := range []string{"darwin-pktap.pcap", "darwin-pktap.pcapng"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile("testdata/deployments/" + name)
			if err != nil {
				t.Fatal(err)
			}
			c, packets := readWrittenPackets(t, raw)
			if c.Anomalies().UnknownLinkType || len(packets) != 4 {
				t.Fatalf("packets = %d, anomalies %+v", len(packets), c.Anomalies())
			}
			r := bytes.NewReader(raw)
			file, err := NewFromReaderAt(r, r.Size())
			if err != nil || file.Anomalies().UnknownLinkType {
				t.Fatalf("ReaderAt capture: %v, %v", file, err)
			}
			checkReaderParity(t, raw, c.Flows, file.FlowsFromReaderAt)
			for _, pkt := range packets {
				data, err := c.PacketPayload(raw, pkt)
				if err != nil {
					t.Fatal(err)
				}
				frame, err := DecodeFrame(data, pkt.LinkType)
				if err != nil || frame.Anomalies.Any() || frame.SrcAddr.String() != "192.0.2.2" ||
					frame.DstAddr.String() != "198.51.100.2" || frame.IPProtocol != IPProtoUDP ||
					frame.SrcPort != 5000 || frame.DstPort != 6000 {
					t.Fatalf("frame %d = %+v, %v", pkt.Index, frame, err)
				}
				if pkt.LinkType == LinkTypeApplePktap &&
					(!slices.Equal(frame.LayerSlices(), []LayerSpan{{LayerApplePktap, 0, 156}, {LayerEthernet, 156, 14}, {LayerIPv4, 170, 20}, {LayerUDP, 190, 8}}) ||
						frame.PayloadOffset != 198 || frame.PayloadLength != 4) {
					t.Fatalf("PKTAP frame offsets = %+v", frame)
				}
			}
		})
	}
}

func TestDecodeApplePktapBounds(t *testing.T) {
	ip := buildEthernetIPv4TCPFrame([4]byte{192, 0, 2, 1}, [4]byte{198, 51, 100, 2}, 5000, 443, 10, 0, TCPFlagSYN, []byte("payload"))[14:]
	long := pktapFrame(320, 12, ip) // Native DLT_RAW.
	for _, length := range []int{1, 155, 156, 319, 320, 321} {
		frame, err := DecodeFrame(long[:length], LinkTypeApplePktap)
		if err != nil || !frame.Anomalies.TruncatedLayer || frame.IPVersion != 0 {
			t.Errorf("length %d decoded %+v, %v", length, frame, err)
		}
	}
	for _, dlt := range []uint32{149, 258, 1<<16 | 1} {
		frame, err := DecodeFrame(pktapFrame(156, dlt, ip), LinkTypeApplePktap)
		if err != nil || frame.LayerCount != 1 || frame.IPVersion != 0 {
			t.Errorf("embedded DLT %d decoded %+v, %v", dlt, frame, err)
		}
	}
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeApplePktap, MaxSnapLen, [][]byte{long})
	c, _ := readWrittenPackets(t, raw)
	reader := bytes.NewReader(raw)
	file, err := NewFromReaderAt(reader, reader.Size())
	if err != nil {
		t.Fatal(err)
	}
	checkReaderParity(t, raw, c.Flows, file.FlowsFromReaderAt)
	flows, err := file.FlowsFromReaderAt(reader)
	if err != nil || len(flows) != 1 || flows[0].DstPort != 443 {
		t.Fatalf("ReaderAt flows = %+v, %v", flows, err)
	}
}

func BenchmarkDecodeFrameApplePktap(b *testing.B) {
	payload := buildEthernetIPv4TCPFrame([4]byte{192, 0, 2, 1}, [4]byte{198, 51, 100, 2}, 5000, 443, 10, 0, TCPFlagSYN, []byte("payload"))
	wire := pktapFrame(156, 1, payload)
	b.ReportAllocs()
	for b.Loop() {
		if f, err := DecodeFrame(wire, LinkTypeApplePktap); err != nil || f.IPVersion != 4 {
			b.Fatal(f, err)
		}
	}
}
