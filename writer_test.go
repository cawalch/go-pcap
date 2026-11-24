package pcap

import (
	"bytes"
	"errors"
	"io"
	"math"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func readWrittenPackets(t *testing.T, raw []byte) (*Capture, []PacketRecord) {
	t.Helper()
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	r := bytes.NewReader(raw)
	cr, err := NewFromReaderAt(r, r.Size())
	if err != nil || !reflect.DeepEqual(cr.Interfaces, c.Interfaces) || !reflect.DeepEqual(cr.InterfaceStats, c.InterfaceStats) {
		t.Fatalf("ReaderAt metadata mismatch: %v", err)
	}
	checkReaderParity(t, raw, c.Packets, cr.PacketsFromReaderAt)
	pkts, err := c.Packets(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, pkt := range pkts {
		got, err := cr.PacketPayloadFromReaderAt(r, pkt)
		want, e := c.PacketPayload(raw, pkt)
		if err != nil || e != nil || !bytes.Equal(got, want) {
			t.Fatalf("packet %d payload mismatch", pkt.Index)
		}
	}
	return c, pkts
}

func TestClassicWriter(t *testing.T) {
	var buf bytes.Buffer
	pw, err := NewPCAPWriter(&buf, LinkTypeRaw, 3)
	if err != nil {
		t.Fatal(err)
	}
	const last = (math.MaxUint32+1)*1_000_000_000 - 1
	for _, invalid := range []int64{-1, last + 1} {
		if !errors.Is(pw.WritePacket(invalid, nil), ErrInvalidPacket) {
			t.Fatal("accepted invalid timestamp")
		}
	}
	if err := pw.WritePacket(0, nil); err != nil {
		t.Fatal(err)
	}
	if err := pw.WritePacket(last, []byte{1, 2, 3, 4}); err != nil {
		t.Fatal(err)
	}
	c, pkts := readWrittenPackets(t, buf.Bytes())
	if !c.NanoTimestamp || c.BigEndian || c.LinkType != LinkTypeRaw || c.SnapLen != 3 || len(pkts) != 2 || pkts[0].CaptureLen != 0 || pkts[1].TimestampNs != last || pkts[1].CaptureLen != 3 || pkts[1].OriginalLen != 4 || !bytes.HasSuffix(buf.Bytes(), []byte{1, 2, 3}) {
		t.Fatal(c, pkts)
	}
	if _, err := NewPCAPWriter(nil, LinkTypeRaw, 0); !errors.Is(err, ErrInvalidHeader) {
		t.Fatal(err)
	}
	if _, err := NewPCAPWriter(io.Discard, LinkTypeRaw, MaxSnapLen+1); !errors.Is(err, ErrInvalidHeader) {
		t.Fatal(err)
	}
}

func TestClassicWriterOriginalLen(t *testing.T) {
	var buf bytes.Buffer
	pw, err := NewPCAPWriter(&buf, LinkTypeRaw, 3)
	if err != nil {
		t.Fatal(err)
	}
	start := buf.Len()
	if err := pw.WritePacketWithOriginalLen(1, []byte{1, 2, 3, 4}, 3); !errors.Is(err, ErrInvalidPacket) || buf.Len() != start {
		t.Fatalf("invalid length wrote %d bytes, err = %v", buf.Len()-start, err)
	}
	for _, payload := range [][]byte{nil, {1, 2}, {1, 2, 3, 4}} {
		if err := pw.WritePacketWithOriginalLen(123456789, payload, 1500); err != nil {
			t.Fatal(err)
		}
	}
	c, pkts := readWrittenPackets(t, buf.Bytes())
	want := [][]byte{nil, {1, 2}, {1, 2, 3}}
	if len(pkts) != len(want) {
		t.Fatalf("got %d packets", len(pkts))
	}
	for i, pkt := range pkts {
		got, err := c.PacketPayload(buf.Bytes(), pkt)
		if err != nil || !bytes.Equal(got, want[i]) || pkt.CaptureLen != uint32(len(want[i])) || pkt.OriginalLen != 1500 || pkt.TimestampNs != 123456789 {
			t.Fatalf("packet %d: %+v, payload %x, err %v", i, pkt, got, err)
		}
	}
}

func TestMultiInterfaceWriter(t *testing.T) {
	var buf bytes.Buffer
	pw, err := NewPCAPNGWriter(&buf, PCAPNGWriterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := pw.WritePacket(PacketRecord{InterfaceID: 1}, nil); !errors.Is(err, ErrInvalidPacket) {
		t.Fatal(err)
	}
	if err := pw.WriteInterfaceStats(InterfaceStatistics{InterfaceID: 1}); !errors.Is(err, ErrInvalidBlock) {
		t.Fatal(err)
	}
	start := buf.Len()
	if _, err := pw.AddInterface(PCAPNGWriterOptions{InterfaceName: strings.Repeat("a", MaxOptionStringBytes+1)}); !errors.Is(err, ErrOptionLimit) {
		t.Fatal(err)
	}
	if _, err := pw.AddInterface(PCAPNGWriterOptions{SnapLen: MaxSnapLen + 1}); !errors.Is(err, ErrInvalidHeader) || buf.Len() != start {
		t.Fatal(err)
	}
	id, err := pw.AddInterface(PCAPNGWriterOptions{LinkType: LinkTypeNull, InterfaceName: "loop", InterfaceDescription: "second", SnapLen: 96})
	if err != nil || id != 1 {
		t.Fatal(id, err)
	}
	for _, n := range []uint32{1, 0, 1} {
		if err := pw.WritePacket(PacketRecord{InterfaceID: n, TimestampNs: 123456789}, []byte{byte(n)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := pw.WriteInterfaceStats(InterfaceStatistics{InterfaceID: id, HasPacketsReceived: true, PacketsReceived: 2}); err != nil {
		t.Fatal(err)
	}
	c, pkts := readWrittenPackets(t, buf.Bytes())
	if len(c.Interfaces) != 2 || c.Interfaces[0].LinkType != LinkTypeEthernet || c.Interfaces[1].Name != "loop" || c.Interfaces[1].Description != "second" || c.Interfaces[1].SnapLen != 96 || len(c.InterfaceStats) != 1 || c.InterfaceStats[0].InterfaceID != 1 || len(pkts) != 3 {
		t.Fatal(c)
	}
	for i, n := range []uint32{1, 0, 1} {
		if pkts[i].InterfaceID != n || pkts[i].LinkType != c.Interfaces[n].LinkType || pkts[i].TimestampNs != 123456789 {
			t.Fatal(pkts[i])
		}
	}
	for i := 2; i < MaxInterfaces; i++ {
		if id, err := pw.AddInterface(PCAPNGWriterOptions{}); err != nil || id != uint32(i) {
			t.Fatal(id, err)
		}
	}
	if _, err := pw.AddInterface(PCAPNGWriterOptions{}); !errors.Is(err, ErrInterfaceLimit) {
		t.Fatal(err)
	}
}

type incompleteCaptureWrite struct {
	writes int
	failAt int
}

func (w *incompleteCaptureWrite) Write(p []byte) (int, error) {
	w.writes++
	if w.writes == w.failAt {
		return len(p) - 1, nil
	}
	return len(p), nil
}

func TestCaptureWriterPartialOutput(t *testing.T) {
	sink := &incompleteCaptureWrite{failAt: 3}
	classic, err := NewPCAPWriter(sink, LinkTypeEthernet, 0)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := classic.WritePacket(0, []byte{1, 2}); !errors.Is(err, io.ErrShortWrite) {
			t.Fatal(err)
		}
	}
	if sink.writes != 3 {
		t.Fatal(sink.writes)
	}
	sink = &incompleteCaptureWrite{failAt: 2}
	ng, err := NewPCAPNGWriter(sink, PCAPNGWriterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ng.AddInterface(PCAPNGWriterOptions{}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
	if err := ng.WritePacket(PacketRecord{}, nil); !errors.Is(err, io.ErrShortWrite) || sink.writes != 2 {
		t.Fatal(err, sink.writes)
	}
}

func TestPCAPNGWriterBoundsAndSnapLen(t *testing.T) {
	var buf bytes.Buffer
	pw, err := NewPCAPNGWriter(&buf, PCAPNGWriterOptions{LinkType: LinkTypeEthernet, SnapLen: 4})
	if err != nil {
		t.Fatal(err)
	}
	// Oversize EPB option strings must be rejected without writing corrupt TLV lengths.
	over := strings.Repeat("x", MaxOptionStringBytes+1)
	for _, pkt := range []PacketRecord{
		{ProcessName: over},
		{ProcessArgs: over},
		{ContainerID: over},
	} {
		if err := pw.WritePacket(pkt, []byte{1, 2}); !errors.Is(err, ErrOptionLimit) {
			t.Fatalf("WritePacket(oversize option) err = %v, want ErrOptionLimit", err)
		}
	}
	// Negative timestamps must be rejected on WritePacket and WriteInterfaceStats.
	if err := pw.WritePacket(PacketRecord{TimestampNs: -1}, []byte{1, 2}); !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("WritePacket(negative ts) err = %v, want ErrInvalidPacket", err)
	}
	if err := pw.WriteInterfaceStats(InterfaceStatistics{TimestampNs: -1}); !errors.Is(err, ErrInvalidBlock) {
		t.Fatalf("WriteInterfaceStats(negative ts) err = %v, want ErrInvalidBlock", err)
	}
	if err := pw.WriteInterfaceStats(InterfaceStatistics{HasStartTime: true, StartTimeNs: -1}); !errors.Is(err, ErrInvalidBlock) {
		t.Fatalf("WriteInterfaceStats(negative start) err = %v, want ErrInvalidBlock", err)
	}
	// NRB records containing only empty strings must be skipped so read-back succeeds.
	if err := pw.WriteNameResolution([]NameResolutionRecord{
		{Addr: netip.MustParseAddr("10.0.0.1"), Names: []string{""}},
		{Addr: netip.MustParseAddr("10.0.0.2"), Names: []string{"", "host.example"}},
	}); err != nil {
		t.Fatalf("WriteNameResolution() err = %v", err)
	}
	// Payloads longer than the interface SnapLen must be truncated while preserving OriginalLen.
	if err := pw.WritePacket(PacketRecord{TimestampNs: 100}, []byte{1, 2, 3, 4, 5, 6}); err != nil {
		t.Fatalf("WritePacket(over snaplen) err = %v", err)
	}
	c, pkts := readWrittenPackets(t, buf.Bytes())
	if c.Anomalies().CaptureLenExceedsSnapLen {
		t.Fatalf("unexpected CaptureLenExceedsSnapLen anomaly: %+v", c.Anomalies())
	}
	if len(pkts) != 1 || pkts[0].CaptureLen != 4 || pkts[0].OriginalLen != 6 {
		t.Fatalf("pkts = %+v, want capLen=4 origLen=6", pkts)
	}
	if len(c.NameRecords) != 1 || c.NameRecords[0].Addr != netip.MustParseAddr("10.0.0.2") || len(c.NameRecords[0].Names) != 1 || c.NameRecords[0].Names[0] != "host.example" {
		t.Fatalf("NameRecords = %+v", c.NameRecords)
	}

	// NRB record exceeding MaxOptionStringBytes must be rejected before copying into the record buffer.
	if err := pw.WriteNameResolution([]NameResolutionRecord{
		{Addr: netip.MustParseAddr("10.0.0.3"), Names: []string{strings.Repeat("a", MaxOptionStringBytes)}},
	}); !errors.Is(err, ErrOptionLimit) {
		t.Fatalf("WriteNameResolution(oversize) err = %v, want ErrOptionLimit", err)
	}

	// Explicit LinkTypeNull on interface 0 with an arbitrary interface name must round-trip as LinkTypeNull.
	var nullBuf bytes.Buffer
	nullPW, err := NewPCAPNGWriter(&nullBuf, PCAPNGWriterOptions{
		LinkType:      LinkTypeNull,
		LinkTypeSet:   true,
		InterfaceName: "loopback",
	})
	if err != nil {
		t.Fatalf("NewPCAPNGWriter(LinkTypeNull) err = %v", err)
	}
	if err := nullPW.WritePacket(PacketRecord{TimestampNs: 1}, []byte{2, 0, 0, 0}); err != nil {
		t.Fatalf("WritePacket(LinkTypeNull) err = %v", err)
	}
	nullCap, nullPkts := readWrittenPackets(t, nullBuf.Bytes())
	if len(nullCap.Interfaces) != 1 || nullCap.Interfaces[0].LinkType != LinkTypeNull || nullCap.Interfaces[0].Name != "loopback" {
		t.Fatalf("nullCap.Interfaces = %+v, want LinkTypeNull on loopback", nullCap.Interfaces)
	}
	if len(nullPkts) != 1 || nullPkts[0].LinkType != LinkTypeNull {
		t.Fatalf("nullPkts = %+v, want LinkTypeNull", nullPkts)
	}
}

func TestPCAPNGWriterProcessEvents(t *testing.T) {
	var out bytes.Buffer
	w, err := NewPCAPNGWriter(&out, PCAPNGWriterOptions{UserApplication: "go-pcap"})
	if err != nil {
		t.Fatal(err)
	}
	// The args split at a UTF-8 boundary, and all original option values fit.
	args := strings.Repeat("x", MaxOptionStringBytes-len(processCommentArgs)-1) + "世" +
		strings.Repeat("y", len(processCommentArgs)-2)
	attributed := PacketRecord{
		HasProcessID: true,
		ProcessName:  "kernel",
		HasThreadID:  true,
		HasUserID:    true,
		UserID:       math.MaxUint32,
		ProcessArgs:  args,
		ContainerID:  strings.Repeat("c", MaxOptionStringBytes),
	}
	nameOnly := PacketRecord{ProcessName: strings.Repeat("n", MaxOptionStringBytes)}
	renamed := PacketRecord{HasProcessID: true, ProcessName: "renamed"}
	want := []PacketRecord{attributed, attributed, renamed, nameOnly}
	for _, pkt := range want {
		if err := w.WritePacket(pkt, nil); err != nil {
			t.Fatal(err)
		}
	}
	raw := out.Bytes()
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Processes) != 3 || c.Processes[0].ProcessName != "kernel" || c.Processes[1].ProcessName != "renamed" ||
		c.Processes[2].ProcessID != math.MaxUint32 || c.Processes[2].ProcessName != nameOnly.ProcessName {
		t.Fatal("wrong deduplicated process entries")
	}
	packets := checkReaderParity(t, raw, c.Packets, c.PacketsFromReaderAt)
	if len(packets) != len(want) {
		t.Fatalf("packets: %d, want %d", len(packets), len(want))
	}
	for i, pkt := range packets {
		expect := want[i]
		if pkt.HasProcessID != expect.HasProcessID || pkt.ProcessID != expect.ProcessID || pkt.ProcessName != expect.ProcessName ||
			pkt.HasThreadID != expect.HasThreadID || pkt.ThreadID != expect.ThreadID ||
			pkt.HasUserID != expect.HasUserID || pkt.UserID != expect.UserID ||
			pkt.ProcessArgs != expect.ProcessArgs || pkt.ContainerID != expect.ContainerID {
			t.Errorf("packet %d attribution fields did not round trip", i)
		}
	}
}

func TestPCAPNGWriterProcessEventLimit(t *testing.T) {
	var out bytes.Buffer
	w, err := NewPCAPNGWriter(&out, PCAPNGWriterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for id := range MaxProcessEvents {
		if err := w.WritePacket(PacketRecord{ProcessID: uint32(id), HasProcessID: true}, nil); err != nil {
			t.Fatalf("entry %d: %v", id, err)
		}
	}
	before := out.Len()
	err = w.WritePacket(PacketRecord{ProcessID: math.MaxUint32, HasProcessID: true}, nil)
	if !errors.Is(err, ErrInvalidPacket) || out.Len() != before {
		t.Fatalf("reserved process ID: %v, output changed: %t", err, out.Len() != before)
	}
	err = w.WritePacket(PacketRecord{ProcessID: MaxProcessEvents, HasProcessID: true}, nil)
	if !errors.Is(err, ErrOptionLimit) || out.Len() != before {
		t.Fatalf("over limit: %v, output changed: %t", err, out.Len() != before)
	}
	if err := w.WritePacket(PacketRecord{HasProcessID: true}, nil); err != nil {
		t.Fatal(err)
	}
	c, err := New(out.Bytes())
	if err != nil || len(c.Processes) != MaxProcessEvents || c.PacketCount != MaxProcessEvents+1 {
		t.Fatalf("open capture at process limit: %v", err)
	}
}
