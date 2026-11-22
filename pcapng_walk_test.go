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
