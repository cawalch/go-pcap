package pcap

import (
	"bytes"
	"errors"
	"io"
	"math"
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
