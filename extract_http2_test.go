package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"reflect"
	"slices"
	"testing"
)

func TestExtractHTTP2TransactionPCAPNG(t *testing.T) {
	raw, err := os.ReadFile("testdata/deployments/http2-transactions.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	c, packets := readWrittenPackets(t, raw)
	reader := bytes.NewReader(raw)
	cr, err := NewFromReaderAt(reader, reader.Size())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := c.HTTP2Transactions(raw)
	if err != nil || len(rows) != 2 {
		t.Fatalf("transactions = %+v, %v", rows, err)
	}
	target := rows[1]
	if target.ID() != (HTTP2TransactionID{6, 50, 3}) || !target.SharedPackets || !slices.Equal(target.PacketIndices, []int{6, 7, 8, 10}) {
		t.Fatalf("selected transaction = %+v", target)
	}

	var out, other bytes.Buffer
	if err := c.ExtractHTTP2TransactionPCAPNG(raw, &out, target.ID()); err != nil {
		t.Fatal(err)
	}
	if err := cr.ExtractHTTP2TransactionPCAPNGFromReaderAt(reader, &other, target.ID()); err != nil || !bytes.Equal(other.Bytes(), out.Bytes()) {
		t.Fatalf("ReaderAt parity: %v", err)
	}
	got, selected := readWrittenPackets(t, out.Bytes())
	indices := []int{0, 1, 3, 4, 5, 6, 7, 8, 10}
	if len(selected) != len(indices) || len(got.Interfaces) != 1 || len(got.Secrets) != 0 || bytes.Contains(out.Bytes(), []byte("shared headers")) || bytes.Contains(out.Bytes(), []byte("unrelated connection")) {
		t.Fatalf("export: %d packets, %d interfaces, %d secrets", len(selected), len(got.Interfaces), len(got.Secrets))
	}
	for i, at := range indices {
		want, pkt := packets[at], selected[i]
		old, err := c.PacketPayload(raw, want)
		if err != nil {
			t.Fatal(err)
		}
		data, err := got.PacketPayload(out.Bytes(), pkt)
		if err != nil {
			t.Fatal(err)
		}
		if want.InterfaceID != 1 || pkt.InterfaceID != 0 {
			t.Fatal("incorrect interface remapping")
		}
		want.Index, want.InterfaceID, want.PayloadOffset = i, 0, pkt.PayloadOffset
		if want != pkt || !bytes.Equal(old, data) {
			t.Fatalf("packet %d differs from source %d", i, at)
		}
	}
	reopened := checkReaderParity(t, out.Bytes(), got.HTTP2Transactions, got.HTTP2TransactionsFromReaderAt)
	if len(reopened) != 2 {
		t.Fatalf("reopened rows = %+v", reopened)
	}
	// Renumber just the capture ordinals. All application evidence and the
	// position within the shared HEADERS packet must survive the export.
	target.Request.PacketIndex = slices.Index(indices, target.Request.PacketIndex)
	target.Response.PacketIndex = slices.Index(indices, target.Response.PacketIndex)
	for i, at := range target.PacketIndices {
		target.PacketIndices[i] = slices.Index(indices, at)
	}
	if !reflect.DeepEqual(reopened[1], target) {
		t.Fatalf("reopened = %+v; want %+v", reopened[1], target)
	}
}

func TestExtractHTTP2TransactionPartial(t *testing.T) {
	for _, tc := range []struct {
		name   string
		modify func(*h2TestOpening)
		pair   HTTP2Pairing
		body   HTTPBodyState
		reset  bool
	}{
		{"missing response", func(*h2TestOpening) {}, HTTP2ResponseUnseen, HTTPBodyUnknown, false},
		{"gap before response", func(c *h2TestOpening) {
			c.seq[1]++
			c.frame(1, HTTP2FrameHeaders, 5, 1, []byte{0x88})
		}, HTTP2ResponseAmbiguous, HTTPBodyUnknown, false},
		{"late conflict", func(c *h2TestOpening) {
			c.frame(1, HTTP2FrameHeaders, 5, 1, []byte{0x88})
			c.seq[1] -= 10
			c.frame(1, HTTP2FrameHeaders, 5, 1, []byte{0x89})
		}, HTTP2ResponseAmbiguous, HTTPBodyUnknown, false},
		{"partial response", func(c *h2TestOpening) {
			c.frame(1, HTTP2FrameHeaders, 4, 1, []byte{0x88})
			c.frame(1, HTTP2FrameData, 0, 1, []byte("a"))
			c.seq[1]++
			c.frame(1, HTTP2FrameData, 1, 1, []byte("b"))
		}, HTTP2ResponseConfirmed, HTTPBodyPartial, false},
		{"reset", func(c *h2TestOpening) {
			c.frame(1, HTTP2FrameHeaders, 4, 1, []byte{0x88})
			c.frame(1, HTTP2FrameRSTStream, 0, 1, []byte{0, 0, 0, 8})
		}, HTTP2ResponseConfirmed, HTTPBodyPartial, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Both openings use the same endpoints and stream ID.
			prior := newH2TestOpening(500)
			prior.frame(0, HTTP2FrameHeaders, 5, 1, []byte{0x82, 0x86, 0x84})
			current := newH2TestOpening(9000)
			current.frame(0, HTTP2FrameHeaders, 5, 1, []byte{0x83, 0x86, 0x84})
			tc.modify(current)
			raw := buildClassicPCAP(binary.BigEndian, true, LinkTypeEthernet, 65535, append(prior.frames, current.frames...))
			c, _ := readWrittenPackets(t, raw)
			rows, err := c.HTTP2Transactions(raw)
			if err != nil || len(rows) != 2 {
				t.Fatalf("source rows = %+v, %v", rows, err)
			}
			want := rows[1]
			if want.Pairing != tc.pair || want.Reset != tc.reset || want.Response != nil && want.Response.BodyState != tc.body {
				t.Fatalf("source = %+v", want)
			}
			var out, other bytes.Buffer
			if err := c.ExtractHTTP2TransactionPCAPNG(raw, &out, want.ID()); err != nil {
				t.Fatal(err)
			}
			if err := c.ExtractHTTP2TransactionPCAPNGFromReaderAt(bytes.NewReader(raw), &other, want.ID()); err != nil || !bytes.Equal(out.Bytes(), other.Bytes()) {
				t.Fatalf("ReaderAt parity: %v", err)
			}
			exported, packets := readWrittenPackets(t, out.Bytes())
			if len(packets) != len(current.frames) {
				t.Fatalf("selected %d packets, want opening of %d", len(packets), len(current.frames))
			}
			for i, p := range packets {
				payload, err := exported.PacketPayload(out.Bytes(), p)
				if err != nil || !bytes.Equal(payload, current.frames[i]) {
					t.Fatalf("packet %d differs: %v", i, err)
				}
			}
			only := checkReaderParity(t, out.Bytes(), exported.HTTP2Transactions, exported.HTTP2TransactionsFromReaderAt)
			want.Request.PacketIndex -= len(prior.frames)
			if want.Response != nil {
				want.Response.PacketIndex -= len(prior.frames)
			}
			for i := range want.PacketIndices {
				want.PacketIndices[i] -= len(prior.frames)
			}
			if len(only) != 1 || !reflect.DeepEqual(only[0], want) {
				t.Fatalf("reopened = %+v, want %+v", only, want)
			}
		})
	}
}

func TestExtractHTTP2TransactionErrors(t *testing.T) {
	raw, err := os.ReadFile("testdata/deployments/http2-transactions.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	c, _ := readWrittenPackets(t, raw)
	r := &measuredReaderAt{Reader: bytes.NewReader(raw)}
	for _, id := range []HTTP2TransactionID{{-1, 0, 1}, {c.PacketCount, 0, 1}, {6, -1, 1}, {6, MaxSnapLen, 1}, {6, 0, 0}, {6, 0, 2}, {6, 0, 0x80000001}} {
		w := &incompleteCaptureWrite{}
		if err := c.ExtractHTTP2TransactionPCAPNGFromReaderAt(r, w, id); !errors.Is(err, ErrOutOfBounds) || r.calls != 0 || w.writes != 0 {
			t.Fatalf("invalid ID %+v: %v, reads=%d writes=%d", id, err, r.calls, w.writes)
		}
	}
	for _, export := range []func(io.Writer, HTTP2TransactionID) error{
		func(w io.Writer, id HTTP2TransactionID) error { return c.ExtractHTTP2TransactionPCAPNG(raw, w, id) },
		func(w io.Writer, id HTTP2TransactionID) error {
			return c.ExtractHTTP2TransactionPCAPNGFromReaderAt(r, w, id)
		},
	} {
		for _, id := range []HTTP2TransactionID{{6, 0, 3}, {6, 40, 3}, {8, 0, 3}} {
			w := &incompleteCaptureWrite{}
			if err := export(w, id); !errors.Is(err, ErrOutOfBounds) || w.writes != 0 {
				t.Fatalf("absent ID %+v: %v, %d writes", id, err, w.writes)
			}
		}
		w := &incompleteCaptureWrite{failAt: 2}
		if err := export(w, HTTP2TransactionID{6, 50, 3}); !errors.Is(err, io.ErrShortWrite) || w.writes != 2 {
			t.Fatalf("writer failure: %v, %d writes", err, w.writes)
		}
	}
}

func TestExtractHTTP2TransactionReadBudget(t *testing.T) {
	// Four large captured frames fit the copy budget by themselves. The
	// selection pass consumes part of it before the copy starts.
	o := newH2TestOpening(100)
	o.frame(0, HTTP2FrameHeaders, 5, 1, []byte{0x82, 0x86, 0x84})
	o.frame(1, HTTP2FrameHeaders, 5, 1, []byte{0x88})
	order := binary.LittleEndian
	header := buildClassicPCAP(order, true, LinkTypeEthernet, MaxSnapLen, nil)
	f := tempCaptureFile(t, header)
	offset := int64(len(header))
	for i, frame := range o.frames {
		length := len(frame)
		if i < 4 {
			length = MaxSnapLen - 256
		}
		var record [16]byte
		order.PutUint32(record[:4], uint32(i))
		order.PutUint32(record[8:12], uint32(length))
		order.PutUint32(record[12:], uint32(length))
		if _, err := f.WriteAt(record[:], offset); err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteAt(frame, offset+16); err != nil {
			t.Fatal(err)
		}
		offset += 16 + int64(length)
	}
	if err := f.Truncate(offset); err != nil {
		t.Fatal(err)
	}
	c, err := NewFromReaderAt(f, offset)
	if err != nil {
		t.Fatal(err)
	}
	r := &measuredFile{File: f}
	w := &incompleteCaptureWrite{}
	err = c.ExtractHTTP2TransactionPCAPNGFromReaderAt(r, w, HTTP2TransactionID{4, 0, 1})
	if !errors.Is(err, ErrPacketLimit) || w.writes == 0 || r.bytesRead > MaxReaderAtScanBytes || r.bytesRead < MaxReaderAtScanBytes-32<<10 {
		t.Fatalf("shared read budget: err=%v, read=%d, writes=%d", err, r.bytesRead, w.writes)
	}
}

func TestExtractHTTP2TransactionSharedTCPBudget(t *testing.T) {
	// Leave room for the request and one DATA frame, but not the empty
	// END_STREAM in the same captured packet as that DATA frame.
	client := newH2TestOpening(9000)
	client.frame(0, HTTP2FrameHeaders, 4, 1, []byte{0x83, 0x86, 0x84})
	data := buildHTTP2Frame(HTTP2FrameData, 0, 1, []byte("a"))
	client.packet(0, TCPFlagACK, append(data, buildHTTP2Frame(HTTP2FrameData, 1, 1, nil)...))
	keep := len(HTTP2ClientPreface) + 9 + 12 + len(data)
	prior := newH2TestOpening(100)
	fill := bytes.Repeat([]byte("x"), 60000)
	for n := MaxFlowStreamBytes - keep - len(HTTP2ClientPreface) - 9; n > 0; {
		size := min(n, len(fill))
		prior.packet(0, TCPFlagACK, fill[:size])
		n -= size
	}
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, append(prior.frames, client.frames...))
	c, _ := readWrittenPackets(t, raw)
	rows, err := c.HTTP2Transactions(raw)
	if err != nil || len(rows) != 1 || rows[0].Request.BodyState != HTTPBodyPartial || string(rows[0].Request.Body) != "a" || !rows[0].Request.TCPAnomalies.Truncated {
		t.Fatalf("source = %+v, %v", rows, err)
	}
	var out bytes.Buffer
	if err := c.ExtractHTTP2TransactionPCAPNG(raw, &out, rows[0].ID()); !errors.Is(err, ErrReassemblyLimit) || out.Len() != 0 {
		t.Fatalf("export = %v, wrote %d bytes", err, out.Len())
	}
	if err := c.ExtractHTTP2TransactionPCAPNGFromReaderAt(bytes.NewReader(raw), &out, rows[0].ID()); !errors.Is(err, ErrReassemblyLimit) || out.Len() != 0 {
		t.Fatalf("ReaderAt export = %v, wrote %d bytes", err, out.Len())
	}
}

func TestExtractHTTP2TransactionReorderedInterfaces(t *testing.T) {
	o := newH2TestOpening(100)
	o.frame(0, HTTP2FrameHeaders, 5, 1, []byte{0x82, 0x86, 0x84})
	o.frame(1, HTTP2FrameHeaders, 5, 1, []byte{0x88})
	// Both sides' SETTINGS arrive in capture order after the exchange that
	// needs them. A second interface carries the same tuple and sequences.
	order := []int{0, 1, 4, 5, 2, 3}
	var packets []tcpCapturePacket
	for _, i := range order {
		for iface := range 2 {
			packets = append(packets, tcpCapturePacket{uint32(iface), int64(len(packets)), o.frames[i]})
		}
	}
	raw, err := tcpInterfaceCapture(packets)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := readWrittenPackets(t, raw)
	c.SeparateTCPInterfaces = true
	want := HTTP2TransactionID{5, 0, 1}
	var out, other bytes.Buffer
	if err := c.ExtractHTTP2TransactionPCAPNG(raw, &out, want); err != nil {
		t.Fatal(err)
	}
	if err := c.ExtractHTTP2TransactionPCAPNGFromReaderAt(bytes.NewReader(raw), &other, want); err != nil || !bytes.Equal(out.Bytes(), other.Bytes()) {
		t.Fatalf("ReaderAt parity: %v", err)
	}
	got, selected := readWrittenPackets(t, out.Bytes())
	if len(got.Interfaces) != 1 || len(selected) != 6 {
		t.Fatalf("interfaces = %d, packets = %d", len(got.Interfaces), len(selected))
	}
	for i, p := range selected {
		original := packets[2*i+1]
		payload, err := got.PacketPayload(out.Bytes(), p)
		if err != nil || !bytes.Equal(payload, original.frame) || p.TimestampNs != original.ms*1_000_000 || p.InterfaceID != 0 {
			t.Fatalf("packet %d = %+v, %v", i, p, err)
		}
	}
	rows := checkReaderParity(t, out.Bytes(), got.HTTP2Transactions, got.HTTP2TransactionsFromReaderAt)
	if len(rows) != 1 || rows[0].ID() != (HTTP2TransactionID{2, 0, 1}) || rows[0].StatusCode != 200 {
		t.Fatalf("reopened = %+v", rows)
	}
}

func TestExtractHTTP2TransactionLaterFramesAtSharedCutoff(t *testing.T) {
	// The first opening consumes 60 KiB of the tuple's client-side budget.
	// Both the source and the isolated second opening remain TCP-truncated.
	// The extra frames recovered on reopen may or may not change stream 1.
	prior := newH2TestOpening(100)
	extension := buildHTTP2Frame(0xee, 0, 0, bytes.Repeat([]byte{'x'}, 60000))
	prior.packet(0, TCPFlagACK, extension)
	for _, changed := range []bool{false, true} {
		current := newH2TestOpening(10000000)
		flags := uint8(5)
		if changed {
			flags = 4
		}
		current.frame(0, HTTP2FrameHeaders, flags, 1, []byte{0x82, 0x86, 0x84})
		current.frame(1, HTTP2FrameHeaders, 5, 1, []byte{0x89})
		for range MaxFlowStreamBytes / len(extension) {
			current.packet(0, TCPFlagACK, extension)
		}
		if changed {
			current.frame(0, HTTP2FrameData, 1, 1, []byte("after source cutoff"))
		}
		current.packet(0, TCPFlagACK, extension)
		raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, slices.Concat(prior.frames, current.frames))
		c, err := New(raw)
		if err != nil {
			t.Fatal(err)
		}
		source, err := c.HTTP2Transactions(raw)
		if err != nil || len(source) != 1 || !source[0].Request.TCPAnomalies.Truncated || source[0].Request.EndStream == changed || source[0].StatusCode != 204 {
			t.Fatalf("source = %+v, %v", source, err)
		}
		var out, other bytes.Buffer
		err = c.ExtractHTTP2TransactionPCAPNG(raw, &out, source[0].ID())
		readerErr := c.ExtractHTTP2TransactionPCAPNGFromReaderAt(bytes.NewReader(raw), &other, source[0].ID())
		if changed {
			if !errors.Is(err, ErrReassemblyLimit) || !errors.Is(readerErr, ErrReassemblyLimit) || out.Len() != 0 || other.Len() != 0 {
				t.Fatalf("changed row: errors %v, %v; lengths %d, %d", err, readerErr, out.Len(), other.Len())
			}
			continue
		}
		if err != nil || readerErr != nil || !bytes.Equal(out.Bytes(), other.Bytes()) {
			t.Fatalf("reproducible row: %v, %v", err, readerErr)
		}
		sub, packets := readWrittenPackets(t, out.Bytes())
		if len(packets) != len(current.frames) {
			t.Fatalf("got %d packets, want %d", len(packets), len(current.frames))
		}
		got := checkReaderParity(t, out.Bytes(), sub.HTTP2Transactions, sub.HTTP2TransactionsFromReaderAt)
		want := source[0]
		want.Request.PacketIndex -= len(prior.frames)
		want.Response.PacketIndex -= len(prior.frames)
		for i := range want.PacketIndices {
			want.PacketIndices[i] -= len(prior.frames)
		}
		if len(got) != 1 || !reflect.DeepEqual(got[0], want) {
			t.Fatalf("reopened = %+v, want %+v", got, want)
		}
	}
}

func TestExtractHTTP2MidstreamPrefix(t *testing.T) {
	o := newH2TestOpening(100)
	for _, id := range []uint32{1, 3} {
		o.frame(0, HTTP2FrameHeaders, 5, id, []byte{0x82, 0x86, 0x84})
		o.frame(1, HTTP2FrameHeaders, 5, id, []byte{0x89})
	}
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, o.frames[2:])
	c, _ := readWrittenPackets(t, raw)
	rows, err := c.HTTP2Transactions(raw)
	if err != nil || len(rows) != 2 || !rows[0].Request.TCPAnomalies.MidstreamPickup {
		t.Fatalf("source %+v, %v", rows, err)
	}
	var out bytes.Buffer
	if err := c.ExtractHTTP2TransactionPCAPNG(raw, &out, rows[0].ID()); err != nil {
		t.Fatal(err)
	}
	sub, packets := readWrittenPackets(t, out.Bytes())
	got := checkReaderParity(t, out.Bytes(), sub.HTTP2Transactions, sub.HTTP2TransactionsFromReaderAt)
	if len(packets) != 4 || len(got) != 1 || !reflect.DeepEqual(got[0], rows[0]) {
		t.Fatalf("%d exported packets, rows %+v", len(packets), got)
	}
}

func TestExtractHTTP2TransactionCutoffBetweenPackets(t *testing.T) {
	// The server's reassembly allowance ends after the first six bytes of the
	// final HEADERS frame. Its last four bytes occupy a later, removable packet.
	prior := newH2TestOpening(100)
	fill := bytes.Repeat([]byte{'x'}, 60000)
	for n := MaxFlowStreamBytes - 9 - 15; n > 0; {
		take := min(len(fill), n)
		prior.packet(1, TCPFlagACK, fill[:take])
		n -= take
	}
	current := newH2TestOpening(9000)
	current.frame(0, HTTP2FrameHeaders, 5, 1, []byte{0x82, 0x86, 0x84})
	status := buildHTTP2Frame(HTTP2FrameHeaders, 5, 1, []byte{0x89})
	current.packet(1, TCPFlagACK, status[:6])
	current.packet(1, TCPFlagACK, status[6:])
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, slices.Concat(prior.frames, current.frames))
	c, _ := readWrittenPackets(t, raw)
	rows, err := c.HTTP2Transactions(raw)
	if err != nil || len(rows) != 1 || rows[0].Response != nil || rows[0].Pairing != HTTP2ResponseAmbiguous {
		t.Fatalf("source rows %+v, %v", rows, err)
	}
	var out, other bytes.Buffer
	want := rows[0]
	if err := c.ExtractHTTP2TransactionPCAPNG(raw, &out, want.ID()); err != nil {
		t.Fatal(err)
	}
	if err := c.ExtractHTTP2TransactionPCAPNGFromReaderAt(bytes.NewReader(raw), &other, want.ID()); err != nil || !bytes.Equal(out.Bytes(), other.Bytes()) {
		t.Fatalf("ReaderAt differs: %v", err)
	}
	sub, pkts := readWrittenPackets(t, out.Bytes())
	if len(pkts) != len(current.frames)-1 {
		t.Fatalf("exported %d packets, want %d", len(pkts), len(current.frames)-1)
	}
	for i, pkt := range pkts {
		frame, err := sub.PacketPayload(out.Bytes(), pkt)
		if err != nil || !bytes.Equal(frame, current.frames[i]) {
			t.Fatalf("packet %d differs: %v", i, err)
		}
	}
	got := checkReaderParity(t, out.Bytes(), sub.HTTP2Transactions, sub.HTTP2TransactionsFromReaderAt)
	want.Request.PacketIndex -= len(prior.frames)
	for i := range want.PacketIndices {
		want.PacketIndices[i] -= len(prior.frames)
	}
	if len(got) != 1 || !reflect.DeepEqual(got[0], want) {
		t.Fatalf("reopened = %+v, want %+v", got, want)
	}
}
