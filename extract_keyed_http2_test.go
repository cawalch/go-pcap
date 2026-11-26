package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"testing"
)

func keyedHTTP2ExportFixture(t *testing.T, truncated bool) *keyedH2Fixture {
	t.Helper()
	f := newKeyedH2(t, TLSVersion13)
	// Stream 1 installs the authority used by stream 3 in a later record.
	one := []byte{0x82, 0x87, 0x84, 0x41, 4, 't', 'e', 's', 't'}
	f.send(false, TCPFlagACK, f.record(false, buildHTTP2Frame(HTTP2FrameHeaders, 5, 1, one))) // packet 7
	two := []byte{0x82, 0x87, 4, 4, '/', 't', 'w', 'o', 0xbe}
	f.send(false, TCPFlagACK, f.record(false, buildHTTP2Frame(HTTP2FrameHeaders, 5, 3, two)))
	shared := buildHTTP2Frame(HTTP2FrameHeaders, 4, 1, []byte{0x88})
	shared = append(shared, buildHTTP2Frame(HTTP2FrameHeaders, 4, 3, []byte{0x88})...)
	f.send(true, TCPFlagACK, f.record(true, shared))
	f.send(true, TCPFlagACK, f.record(true, buildHTTP2Frame(HTTP2FrameData, 0, 3, []byte("reply"))))
	last := f.record(true, buildHTTP2Frame(HTTP2FrameData, 1, 3, nil))
	if truncated {
		f.send(true, TCPFlagACK, last[:len(last)-1])
		return f
	}
	f.send(true, TCPFlagACK, last)
	f.send(true, TCPFlagACK, f.record(true, buildHTTP2Frame(HTTP2FrameData, 1, 1, []byte("later"))))
	return f
}

func TestExtractKeyedHTTP2TransactionPCAPNG(t *testing.T) {
	for _, tc := range []struct {
		name      string
		truncated bool
		wantBody  HTTPBodyState
	}{
		{"complete", false, HTTPBodyComplete},
		{"truncated TLS record", true, HTTPBodyPartial},
	} {
		t.Run(tc.name, func(t *testing.T) {
			other := keyedHTTP2ExportFixture(t, false)
			f := keyedHTTP2ExportFixture(t, tc.truncated)
			if !tc.truncated {
				fixture, err := os.ReadFile("testdata/keyed-http2-export.pcapng")
				if err != nil || !bytes.Equal(fixture, keyedCapture(t, f.keys, f.packets)) {
					t.Fatalf("reference fixture differs: %v", err)
				}
			}
			opening := len(other.packets)
			frames := append([][]byte(nil), other.packets...)
			for _, raw := range f.packets {
				// Reuse the tuple, HTTP/2 stream IDs and keys in a new TCP opening.
				packet := bytes.Clone(raw)
				for _, offset := range []int{38, 42} {
					binary.BigEndian.PutUint32(packet[offset:], binary.BigEndian.Uint32(packet[offset:])+10_000)
				}
				frames = append(frames, packet)
			}
			raw := keyedCapture(t, f.keys, frames)
			source, original := readWrittenPackets(t, raw)
			rows := keyedH2Rows(t, raw, nil)
			if len(rows) != 4 {
				t.Fatalf("source rows: %v", rows)
			}
			want := rows[3]
			if want.ID.OpeningPacket != opening || want.ID.StreamID != 3 || want.Request.Authority != "test" ||
				!want.SharedRecords || !want.SharedPackets || want.Response == nil || want.Response.BodyState != tc.wantBody {
				t.Fatalf("source selection: %+v", want)
			}
			var out, fromReader bytes.Buffer
			if err := source.ExtractKeyedHTTP2TransactionPCAPNG(raw, nil, &out, want.ID); err != nil {
				t.Fatal(err)
			}
			r := bytes.NewReader(raw)
			reader, err := NewFromReaderAt(r, r.Size())
			if err != nil {
				t.Fatal(err)
			}
			if err := reader.ExtractKeyedHTTP2TransactionPCAPNGFromReaderAt(r, nil, &fromReader, want.ID); err != nil || !bytes.Equal(out.Bytes(), fromReader.Bytes()) {
				t.Fatalf("ReaderAt output differs: %v", err)
			}
			export, packets := readWrittenPackets(t, out.Bytes())
			const retained = 12 // Opening through stream 3 END_STREAM or the truncated record.
			if len(export.Secrets) != 0 || len(packets) != retained {
				t.Fatalf("export has %d secrets and %d packets", len(export.Secrets), len(packets))
			}
			for i := range retained {
				before, after := original[opening+i], packets[i]
				wire, err := export.PacketPayload(out.Bytes(), after)
				if err != nil || !bytes.Equal(wire, frames[opening+i]) || after.TimestampNs != before.TimestampNs ||
					after.LinkType != before.LinkType || after.CaptureLen != before.CaptureLen || after.OriginalLen != before.OriginalLen {
					t.Fatalf("export packet %d differs from source packet %d: %v", i, opening+i, err)
				}
			}
			if got := keyedH2Rows(t, out.Bytes(), nil); len(got) != 0 {
				t.Fatalf("export decrypted without keys: %v", got)
			}
			got := keyedH2Rows(t, out.Bytes(), f.keys)
			if len(got) != 2 || got[1].ID.OpeningPacket != 0 || got[1].ID.StreamID != 3 ||
				got[1].Pairing != want.Pairing || got[1].StatusCode != want.StatusCode ||
				!reflect.DeepEqual(got[1].Request, want.Request) || !reflect.DeepEqual(got[1].Response, want.Response) ||
				got[1].ServerCoverage.IncompleteTail != tc.truncated || string(got[1].Response.Body) != "reply" {
				t.Fatalf("selected exchange changed: source %+v, reopened %+v", want, got)
			}
		})
	}
}

func TestExtractKeyedHTTP2TransactionErrors(t *testing.T) {
	f := keyedHTTP2ExportFixture(t, false)
	raw := keyedCapture(t, f.keys, f.packets)
	c, _ := readWrittenPackets(t, raw)
	valid := keyedH2Rows(t, raw, nil)[1].ID
	for _, reader := range []bool{false, true} {
		export := func(w io.Writer, id KeyedHTTP2TransactionID) error {
			if reader {
				return c.ExtractKeyedHTTP2TransactionPCAPNGFromReaderAt(bytes.NewReader(raw), nil, w, id)
			}
			return c.ExtractKeyedHTTP2TransactionPCAPNG(raw, nil, w, id)
		}
		for _, stream := range []uint32{0, 2, 5, 0x80000001} {
			id := valid
			id.StreamID = stream
			var out bytes.Buffer
			if err := export(&out, id); !errors.Is(err, ErrOutOfBounds) || out.Len() != 0 {
				t.Fatalf("stream %d: output %d bytes, error %v", stream, out.Len(), err)
			}
		}
		if err := export(nil, valid); !errors.Is(err, ErrInvalidHeader) {
			t.Fatalf("nil writer: %v", err)
		}
		if err := export(&incompleteCaptureWrite{failAt: 2}, valid); !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("short writer: %v", err)
		}
	}
}

func TestExtractKeyedHTTP2TransactionReadBudget(t *testing.T) {
	f := keyedHTTP2ExportFixture(t, false)
	id := keyedH2Rows(t, keyedCapture(t, f.keys, f.packets), nil)[1].ID
	capture, reader := transactionExportBudgetCapture(t, f.packets, MaxSnapLen-128)
	w := &incompleteCaptureWrite{}
	err := capture.ExtractKeyedHTTP2TransactionPCAPNGFromReaderAt(reader, f.keys, w, id)
	if !errors.Is(err, ErrPacketLimit) || w.writes == 0 || reader.bytesRead > MaxReaderAtScanBytes || reader.bytesRead < MaxReaderAtScanBytes-32<<10 {
		t.Fatalf("shared budget: %v, reads %d, writes %d", err, reader.bytesRead, w.writes)
	}
}

func ExampleCapture_ExtractKeyedHTTP2TransactionPCAPNG() {
	raw, err := os.ReadFile("testdata/keyed-http2-export.pcapng")
	if err != nil {
		panic(err)
	}
	capture, err := New(raw)
	if err != nil {
		panic(err)
	}
	rows, err := capture.KeyedHTTP2Transactions(raw, nil)
	if err != nil {
		panic(err)
	}
	for _, row := range rows {
		if row.Request.Path == "/two" {
			var out bytes.Buffer
			if err := capture.ExtractKeyedHTTP2TransactionPCAPNG(raw, nil, &out, row.ID); err != nil {
				panic(err)
			}
			fmt.Println(row.ID.StreamID, row.Request.Path, out.Len() > 0)
		}
	}
	// Output:
	// 3 /two true
}
