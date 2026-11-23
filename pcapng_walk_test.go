package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"reflect"
	"testing"
)

func metadataWalkFixture(t testing.TB, secretBytes int) []byte {
	t.Helper()
	var out bytes.Buffer
	w, err := NewPCAPNGWriter(&out, PCAPNGWriterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteDecryptionSecrets(SecretsTypeWireGuardKeyLog, make([]byte, secretBytes)); err != nil {
		t.Fatal(err)
	}
	names := make([]NameResolutionRecord, 256)
	for i := range names {
		names[i] = NameResolutionRecord{Addr: netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}), Names: []string{"example.test"}}
	}
	if err := w.WriteNameResolution(names); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteInterfaceStats(InterfaceStatistics{}); err != nil {
		t.Fatal(err)
	}
	frame := buildEthernetIPv4UDPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 53, 40000, buildDNSQueryResponsePacket())
	if err := w.WritePacket(PacketRecord{ProcessName: "resolver"}, frame); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestPCAPNGWalkSkipsMetadataBodies(t *testing.T) {
	raw := metadataWalkFixture(t, 4096)
	r := bytes.NewReader(raw)
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	cr, err := NewFromReaderAt(r, int64(len(raw)))
	if err != nil || !reflect.DeepEqual(c, cr) {
		t.Fatalf("open parity: %v", err)
	}
	var bodies [][2]int64
	for off := 0; off < len(raw); {
		kind := binary.LittleEndian.Uint32(raw[off:])
		end := off + int(binary.LittleEndian.Uint32(raw[off+4:]))
		switch kind {
		case BlockTypeDecryptionSecrets, BlockTypeNameResolution, BlockTypeInterfaceStats:
			bodies = append(bodies, [2]int64{int64(off + 8), int64(end - 4)})
			// Invalid secret length, NRB record length, or ISB interface ID.
			bad := bytes.Clone(raw)
			for i := off + 8; i < off+16; i++ {
				bad[i] = 0xff
			}
			_, sliceErr := New(bad)
			_, readerErr := NewFromReaderAt(bytes.NewReader(bad), int64(len(bad)))
			if sliceErr == nil || readerErr == nil {
				t.Fatalf("block %#x: open accepted invalid body: %v, %v", kind, sliceErr, readerErr)
			}
			bad = bytes.Clone(raw)
			bad[end-1] ^= 1
			_, sliceErr = c.Packets(bad)
			_, readerErr = cr.PacketsFromReaderAt(bytes.NewReader(bad))
			if !errors.Is(sliceErr, ErrInvalidBlock) || !errors.Is(readerErr, ErrInvalidBlock) {
				t.Fatalf("block %#x: trailer errors %v, %v", kind, sliceErr, readerErr)
			}
		}
		off = end
	}
	guard := readAtFunc(func(p []byte, off int64) (int, error) {
		for _, span := range bodies {
			if off < span[1] && off+int64(len(p)) > span[0] {
				t.Fatalf("packet walk read metadata body at %d", off)
			}
		}
		return r.ReadAt(p, off)
	})
	checkMetadataWalk(t, raw, guard, c.Packets, cr.PacketsFromReaderAt)
	checkMetadataWalk(t, raw, guard, c.Flows, cr.FlowsFromReaderAt)
	checkMetadataWalk(t, raw, guard, c.DNS, cr.DNSFromReaderAt)
	checkMetadataWalk(t, raw, guard, c.TLS, cr.TLSFromReaderAt)
	checkMetadataWalk(t, raw, guard, c.QUIC, cr.QUICFromReaderAt)
}

func checkMetadataWalk[T any](t *testing.T, raw []byte, r io.ReaderAt, slice func([]byte) ([]T, error), reader func(io.ReaderAt) ([]T, error)) {
	t.Helper()
	want, err := slice(raw)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reader(r)
	if err != nil || !reflect.DeepEqual(want, got) {
		t.Fatalf("scan parity: got %+v, %v; want %+v", got, err, want)
	}
}

func BenchmarkPCAPNGMetadataWalk(b *testing.B) {
	raw := metadataWalkFixture(b, 2<<20)
	c, err := New(raw)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("slice", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := c.Packets(raw); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("ReaderAt", func(b *testing.B) {
		r := &measuredReaderAt{Reader: bytes.NewReader(raw)}
		b.ReportAllocs()
		for b.Loop() {
			if _, err := c.PacketsFromReaderAt(r); err != nil {
				b.Fatal(err)
			}
		}
		b.ReportMetric(float64(r.calls)/float64(b.N), "reads/op")
		b.ReportMetric(float64(r.bytesRead)/float64(b.N), "read-B/op")
	})
	b.Run("warm-file", func(b *testing.B) {
		r := &measuredFile{File: tempCaptureFile(b, raw)}
		b.ReportAllocs()
		for b.Loop() {
			if _, err := c.PacketsFromReaderAt(r); err != nil {
				b.Fatal(err)
			}
		}
		b.ReportMetric(float64(r.calls)/float64(b.N), "reads/op")
		b.ReportMetric(float64(r.bytesRead)/float64(b.N), "read-B/op")
	})
}

// BenchmarkReaderAtMetadata covers opening a section with option padding,
// a table of address aliases, and walking a metadata-only capture.
func BenchmarkReaderAtMetadata(b *testing.B) {
	base := buildPCAPNGFixture(binary.LittleEndian, nil, nil)
	for _, workload := range []string{"section-padding", "name-records", "empty-flows"} {
		var raw bytes.Buffer
		raw.Write(base)
		var fields bytes.Buffer
		switch workload {
		case "section-padding":
			n := binary.LittleEndian.Uint32(base[4:])
			fields.Write(base[8 : n-4]) // includes the end-of-options marker
			fields.Write(make([]byte, 256<<10))
			appendPCAPNGBlock(&raw, binary.LittleEndian, BlockTypeSectionHeader, fields.Bytes())
		case "name-records":
			for range 2048 {
				appendPCAPNGOption(&fields, binary.LittleEndian, nrbRecordIPv4, []byte("\xc0\x00\x02\x01mail.example.test\x00"))
			}
			appendPCAPNGOption(&fields, binary.LittleEndian, nrbRecordEnd, nil)
			appendPCAPNGBlock(&raw, binary.LittleEndian, BlockTypeNameResolution, fields.Bytes())
		}
		b.Run(workload, func(b *testing.B) {
			c, err := New(raw.Bytes())
			if err != nil {
				b.Fatal(err)
			}
			r := &measuredReaderAt{Reader: bytes.NewReader(raw.Bytes())}
			b.ReportAllocs()
			for b.Loop() {
				if workload == "empty-flows" {
					_, err = c.FlowsFromReaderAt(r)
				} else {
					_, err = NewFromReaderAt(r, int64(raw.Len()))
				}
				if err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(r.calls)/float64(b.N), "reads/op")
			b.ReportMetric(float64(r.bytesRead)/float64(b.N), "read-B/op")
		})
	}
}

func TestPCAPNGSectionProcessReferences(t *testing.T) {
	var out bytes.Buffer
	frame := buildEthernetIPv4UDPFrame([4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}, 1200, 1201, nil)
	for i, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		out.Write(buildPCAPNGFixture(order, nil, nil))
		var pid [4]byte
		order.PutUint32(pid[:], uint32(100+i))
		appendPCAPNGBlock(&out, order, BlockTypeDarwinProcessEvent, pid[:])
		var epb bytes.Buffer
		fixed := make([]byte, 20)
		order.PutUint32(fixed[12:], uint32(len(frame)))
		order.PutUint32(fixed[16:], uint32(len(frame)))
		epb.Write(fixed)
		epb.Write(frame)
		epb.Write(make([]byte, -len(frame)&3))
		appendPCAPNGOption(&epb, order, optEPBDarwinDPEB, make([]byte, 4))
		appendPCAPNGBlock(&out, order, BlockTypeEnhancedPacket, epb.Bytes())
	}
	raw := out.Bytes()
	for pass := range 2 {
		r := bytes.NewReader(raw)
		c, err := New(raw)
		if err != nil {
			t.Fatal(err)
		}
		packets, err := c.Packets(raw)
		if err != nil || len(packets) != 2 || packets[0].ProcessID != 100 || packets[1].ProcessID != 101 {
			t.Fatalf("packets on pass %d: %+v, %v", pass, packets, err)
		}
		checkMetadataWalk(t, raw, r, c.Packets, c.PacketsFromReaderAt)
		if pass == 0 {
			var filtered bytes.Buffer
			if err := c.ExtractFlowPCAPNG(raw, &filtered, 0); err != nil {
				t.Fatal(err)
			}
			raw = filtered.Bytes()
		}
	}
}

func TestNRBRecordAndWriterLimits(t *testing.T) {
	s := scanSummary{nrbRecords: MaxNameResolutionRecords - 1}
	if err := s.addNRBRecord(100, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.addNRBRecord(nrbRecordIPv4, make([]byte, 5)); !errors.Is(err, ErrOptionLimit) {
		t.Fatalf("empty mapping after unknown record: %v", err)
	}
	w, err := NewPCAPNGWriter(io.Discard, PCAPNGWriterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	rec := NameResolutionRecord{Addr: netip.MustParseAddr("192.0.2.1")}
	for _, count := range []int{MaxNamesPerRecord, MaxNamesPerRecord + 1} {
		names := bytes.Repeat([]byte("host\x00"), count)
		rec.Names = []string{string(names)}
		var nrb, data bytes.Buffer
		data.Write(buildPCAPNGFixture(binary.BigEndian, nil, nil))
		appendPCAPNGOption(&nrb, binary.BigEndian, nrbRecordIPv4, append([]byte{192, 0, 2, 1}, names...))
		appendPCAPNGBlock(&data, binary.BigEndian, BlockTypeNameResolution, nrb.Bytes())
		_, sliceErr := New(data.Bytes())
		_, readerErr := NewFromReaderAt(bytes.NewReader(data.Bytes()), int64(data.Len()))
		for _, err := range []error{sliceErr, readerErr, w.WriteNameResolution([]NameResolutionRecord{rec})} {
			if count == MaxNamesPerRecord && err != nil || count > MaxNamesPerRecord && !errors.Is(err, ErrOptionLimit) {
				t.Fatalf("%d names: %v", count, err)
			}
		}
	}

}

func TestReaderAtEmptyCaptureAndFramePadding(t *testing.T) {
	empty := buildPCAPNGFixture(binary.LittleEndian, nil, nil)
	c, err := New(empty)
	if err != nil {
		t.Fatal(err)
	}
	r := &measuredReaderAt{Reader: bytes.NewReader(empty)}
	checkMetadataWalk(t, empty, r, c.Flows, c.FlowsFromReaderAt)
	checkMetadataWalk(t, empty, r, c.DNS, c.DNSFromReaderAt)
	checkMetadataWalk(t, empty, r, c.TLS, c.TLSFromReaderAt)
	checkMetadataWalk(t, empty, r, c.QUIC, c.QUICFromReaderAt)
	if r.calls != 0 {
		t.Fatalf("empty capture: %d reads", r.calls)
	}

	frame := buildEthernetIPv4UDPFrame([4]byte{1}, [4]byte{2}, 1001, 1002, nil)
	// An ICMP echo header followed by link-layer padding.
	frame[23] = IPProtoICMP
	frame = append(frame, make([]byte, 1024)...)
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{frame})
	c, err = New(raw)
	if err != nil {
		t.Fatal(err)
	}
	r = &measuredReaderAt{Reader: bytes.NewReader(raw)}
	checkMetadataWalk(t, raw, r, c.Flows, c.FlowsFromReaderAt)
	if r.bytesRead != pcapPacketHeaderSize+256 {
		t.Fatalf("read %d bytes for padded frame", r.bytesRead)
	}
}

func TestReaderAtLargeMetadata(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		var nrb, raw bytes.Buffer
		raw.Write(buildPCAPNGFixture(order, make([]byte, 10000), nil))
		for range 500 {
			appendPCAPNGOption(&nrb, order, nrbRecordIPv6, append(make([]byte, 16), []byte("mail.example.test\x00")...))
		}
		appendPCAPNGOption(&nrb, order, nrbRecordEnd, nil)
		appendPCAPNGOption(&nrb, order, 1, []byte("names"))
		appendPCAPNGBlock(&raw, order, BlockTypeNameResolution, nrb.Bytes())
		c, err := New(raw.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		got, err := NewFromReaderAt(bytes.NewReader(raw.Bytes()), int64(raw.Len()))
		if err != nil || len(c.NameRecords) != 500 || !reflect.DeepEqual(c, got) {
			t.Fatalf("large metadata: %d names, reader error %v", len(c.NameRecords), err)
		}
	}
}

func TestPCAPNGBlockCountBoundary(t *testing.T) {
	s := scanSummary{blocks: MaxPCAPNGBlocks - 1}
	if err := s.countBlock(); err != nil {
		t.Fatal(err)
	}
	if err := s.countBlock(); !errors.Is(err, ErrPacketLimit) {
		t.Fatalf("block limit: %v", err)
	}
}

func TestReaderAtLargeNRBWithExtensionRecords(t *testing.T) {
	// 4,096 full-sized vendor extension records, then one address mapping.
	// They fit the NRB limits even though the block exceeds MaxSnapLen.
	const count = 4096
	var data bytes.Buffer
	data.Grow(count*(MaxOptionStringBytes+4) + 1024)
	data.Write(buildPCAPNGFixture(binary.LittleEndian, nil, nil))
	start := data.Len()
	data.Write(make([]byte, 8))
	value := make([]byte, MaxOptionStringBytes)
	for range count {
		appendPCAPNGOption(&data, binary.LittleEndian, 0x8001, value)
	}
	appendPCAPNGOption(&data, binary.LittleEndian, nrbRecordIPv4, []byte{192, 0, 2, 1, 'a', 0})
	appendPCAPNGOption(&data, binary.LittleEndian, nrbRecordEnd, nil)
	length := uint32(data.Len() - start + 4)
	binary.LittleEndian.PutUint32(data.Bytes()[start:], BlockTypeNameResolution)
	binary.LittleEndian.PutUint32(data.Bytes()[start+4:], length)
	data.Write(binary.LittleEndian.AppendUint32(nil, length))
	c, err := New(data.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	got, err := NewFromReaderAt(bytes.NewReader(data.Bytes()), int64(data.Len()))
	if err != nil || len(c.NameRecords) != 1 || !reflect.DeepEqual(got, c) {
		t.Fatalf("large NRB: %v", err)
	}
}

func TestReaderAtPaddedMetadataAndOptionErrors(t *testing.T) {
	order := binary.LittleEndian
	for _, kind := range []uint32{BlockTypeSectionHeader, BlockTypeDecryptionSecrets} {
		var fixed []byte
		if kind == BlockTypeSectionHeader {
			fixed = make([]byte, 16)
			order.PutUint32(fixed, PCAPNGByteOrderMagic)
			order.PutUint16(fixed[4:], 1)
			order.PutUint64(fixed[8:], ^uint64(0))
		} else {
			fixed = make([]byte, 8)
		}
		for _, mode := range []string{"end", "oversize", "boundary"} {
			var body, data bytes.Buffer
			data.Write(buildPCAPNGFixture(order, nil, nil))
			body.Write(fixed)
			for range 3 {
				appendPCAPNGOption(&body, order, 1, make([]byte, 3072))
			}
			switch mode {
			case "end":
				appendPCAPNGOption(&body, order, 0, nil)
				body.Write(make([]byte, 64<<10))
			case "oversize":
				appendPCAPNGOption(&body, order, 1, make([]byte, MaxOptionStringBytes+1))
			case "boundary":
				body.Write([]byte{1, 0, 8, 0})
			}
			appendPCAPNGBlock(&data, order, kind, body.Bytes())
			c, a := New(data.Bytes())
			r := &measuredReaderAt{Reader: bytes.NewReader(data.Bytes())}
			got, b := NewFromReaderAt(r, int64(data.Len()))
			switch mode {
			case "end":
				if a != nil || b != nil || !reflect.DeepEqual(got, c) || r.bytesRead >= 32<<10 {
					t.Fatalf("kind %d: %v, %v, read %d", kind, a, b, r.bytesRead)
				}
			case "oversize", "boundary":
				want := ErrOptionLimit
				if mode == "boundary" {
					want = ErrInvalidBlock
				}
				if !errors.Is(a, want) || !errors.Is(b, want) {
					t.Fatalf("kind %d %s: %v, %v", kind, mode, a, b)
				}
			}
		}
	}
}
