package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"testing"
)

func TestICMPFlowErrors(t *testing.T) {
	udp := buildEthernetIPv4UDPFrame([4]byte{192, 0, 2, 10}, [4]byte{192, 0, 2, 53}, 53000, 53, []byte("query"))[14:]
	reverse := buildEthernetIPv4UDPFrame([4]byte{192, 0, 2, 53}, [4]byte{192, 0, 2, 10}, 53, 53000, []byte("reply"))[14:]
	tcp6 := ipipIPv6(IPProtoTCP, framingIPv4TCP(nil)[20:])
	unmatched := bytes.Clone(udp)
	binary.BigEndian.PutUint16(unmatched[20:22], 49000)
	unreachable := icmpErrorFrame(4, 3, udp[:28])
	unreachable[21] = 3
	fragment := bytes.Clone(unreachable)
	fragment[6] |= 0x20

	var pcapng bytes.Buffer
	writer, err := NewPCAPNGWriter(&pcapng, PCAPNGWriterOptions{LinkType: LinkTypeRaw})
	if err != nil {
		t.Fatal(err)
	}
	for i, frame := range [][]byte{
		unreachable,
		tcp6,
		icmpErrorFrame(4, 11, unmatched[:28]),
		unreachable,
		icmpErrorFrame(4, 3, reverse[:28]),
		icmpErrorFrame(4, 3, udp[:22]),
		fragment,
		udp,
		icmpErrorFrame(6, 2, tcp6[:48]),
	} {
		pkt := PacketRecord{TimestampNs: int64(100 - i), OriginalLen: uint32(len(frame))}
		if err := writer.WritePacket(pkt, frame); err != nil {
			t.Fatal(err)
		}
	}
	raw := pcapng.Bytes()
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	rows := checkReaderParity(t, raw, c.ICMPFlowErrors, c.ICMPFlowErrorsFromReaderAt)
	flows, err := c.Flows(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("groups = %+v", rows)
	}
	for i, want := range []struct {
		count, first, last           int
		version, protocol, typ, code uint8
		source, destination          uint16
	}{
		{2, 0, 3, 4, IPProtoUDP, 3, 3, 53000, 53},
		{1, 4, 4, 4, IPProtoUDP, 3, 0, 53, 53000},
		{1, 8, 8, 6, IPProtoTCP, 2, 0, 5000, 443},
	} {
		got := rows[i]
		q := got.Quote
		if got.Count != want.count || got.FirstPacketIndex != want.first || got.LastPacketIndex != want.last ||
			got.FirstTimestampNs != int64(100-want.first) || got.LastTimestampNs != int64(100-want.last) ||
			q.IPVersion != want.version || q.IPProtocol != want.protocol || !q.HasPorts ||
			q.SrcPort != want.source || q.DstPort != want.destination || got.Type != want.typ || got.Code != want.code {
			t.Fatalf("group %d = %+v", i, got)
		}
		flow := flows[got.FlowIndex]
		flowKey, _ := makeCanonicalFlowKey(flow.Protocol, flow.SrcAddr, flow.SrcPort, flow.DstAddr, flow.DstPort)
		quoteKey, _ := makeCanonicalFlowKey(q.IPProtocol, q.SrcAddr, q.SrcPort, q.DstAddr, q.DstPort)
		if flowKey != quoteKey || flow.PortsUnavailable {
			t.Fatalf("group %d wrong flow: %+v", i, flow)
		}
	}
	if rows[0].FlowIndex != rows[1].FlowIndex || rows[2].FlowIndex == rows[0].FlowIndex {
		t.Fatalf("flow identities = %d, %d, %d", rows[0].FlowIndex, rows[1].FlowIndex, rows[2].FlowIndex)
	}
}

func TestICMPFlowErrorsGroupLimit(t *testing.T) {
	quote := buildEthernetIPv4UDPFrame([4]byte{192, 0, 2, 10}, [4]byte{192, 0, 2, 53}, 53000, 53, nil)[14:42]
	frames := make([][]byte, MaxICMPFlowErrorGroups+1)
	for i := range frames {
		frame := icmpErrorFrame(4, 3, quote)
		binary.BigEndian.PutUint16(frame[48:50], uint16(i))
		frames[i] = frame
	}
	raw := buildClassicPCAP(binary.LittleEndian, true, LinkTypeRaw, 65535, frames)
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := c.ICMPFlowErrors(raw); got != nil || !errors.Is(err, ErrFlowLimit) {
		t.Fatalf("slice limit = %+v, %v", got, err)
	}
	if got, err := c.ICMPFlowErrorsFromReaderAt(bytes.NewReader(raw)); got != nil || !errors.Is(err, ErrFlowLimit) {
		t.Fatalf("ReaderAt limit = %+v, %v", got, err)
	}
}

func TestICMPFlowErrorsReaderAtPayloadReads(t *testing.T) {
	udp := buildEthernetIPv4UDPFrame([4]byte{192, 0, 2, 10}, [4]byte{192, 0, 2, 53}, 53000, 53, make([]byte, 4096))[14:]
	raw := buildClassicPCAP(binary.LittleEndian, true, LinkTypeRaw, 65535, [][]byte{udp, icmpErrorFrame(4, 3, udp[:28])})
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	reader := measuredReaderAt{Reader: bytes.NewReader(raw)}
	got, err := c.ICMPFlowErrorsFromReaderAt(&reader)
	if err != nil || len(got) != 1 || reader.bytesRead >= int64(len(udp)) {
		t.Fatalf("groups = %+v, err = %v, bytes = %d", got, err, reader.bytesRead)
	}
}

func ExampleCapture_ICMPFlowErrorsFromReaderAt() {
	// This capture contains valid quotes but no observations of those flows.
	file, err := os.Open("testdata/framing/icmp-errors.pcapng")
	if err != nil {
		panic(err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		panic(err)
	}
	capture, err := NewFromReaderAt(file, info.Size())
	if err != nil {
		panic(err)
	}
	groups, err := capture.ICMPFlowErrorsFromReaderAt(file)
	if err != nil {
		panic(err)
	}
	fmt.Println(len(groups))
	// Output:
	// 0
}

func BenchmarkICMPFlowErrors(b *testing.B) {
	udp := buildEthernetIPv4UDPFrame([4]byte{192, 0, 2, 10}, [4]byte{192, 0, 2, 53}, 53000, 53, make([]byte, 512))[14:]
	icmp := icmpErrorFrame(4, 3, udp[:28])
	frames := make([][]byte, 512)
	for i := range frames {
		if i%8 == 7 {
			frames[i] = icmp
		} else {
			frames[i] = udp
		}
	}
	raw := buildClassicPCAP(binary.LittleEndian, true, LinkTypeRaw, 65535, frames)
	c, err := New(raw)
	if err != nil {
		b.Fatal(err)
	}
	r := bytes.NewReader(raw)
	b.Run("Slice", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			rows, err := c.ICMPFlowErrors(raw)
			if err != nil || len(rows) != 1 {
				b.Fatalf("groups = %d, %v", len(rows), err)
			}
		}
	})
	b.Run("ReaderAt", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			rows, err := c.ICMPFlowErrorsFromReaderAt(r)
			if err != nil || len(rows) != 1 {
				b.Fatalf("groups = %d, %v", len(rows), err)
			}
		}
	})
}
