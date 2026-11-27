package pcap

import (
	"bytes"
	"encoding/binary"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestHTTP1TransactionsAfterUnrelatedTCP(t *testing.T) {
	f := tempCaptureFile(t, nil)
	w, err := NewPCAPWriter(f, LinkTypeEthernet, 65535)
	if err != nil {
		t.Fatal(err)
	}
	const payloadBytes = 60 << 10
	src, dst := [4]byte{192, 0, 2, 10}, [4]byte{192, 0, 2, 20}
	noise := buildEthernetIPv4TCPFrame(src, dst, 30000, 22, 0, 0, TCPFlagACK, make([]byte, payloadBytes))
	for offset := 0; offset <= MaxReaderAtScanBytes; offset += payloadBytes {
		binary.BigEndian.PutUint32(noise[38:], uint32(offset+1)) // Ethernet and IPv4 headers, then TCP sequence.
		if err := w.WritePacket(0, noise); err != nil {
			t.Fatal(err)
		}
	}
	frames := append(txOpening(),
		txFrame(false, 101, 201, TCPFlagACK, txGET),
		txFrame(true, 201, 101+uint32(len(txGET)), TCPFlagACK, txOK),
	)
	for _, frame := range frames {
		if err := w.WritePacket(0, frame); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewFromReaderAt(f, int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := c.HTTP1Transactions(raw)
	if err != nil || len(rows) != 1 {
		t.Fatalf("slice = %d transactions, %v", len(rows), err)
	}
	row := rows[0]
	if row.Pairing != HTTP1ResponseConfirmed || row.Request.FlowIndex != 1 ||
		!slices.Equal(row.PacketIndices, []int{c.PacketCount - 2, c.PacketCount - 1}) ||
		row.Response == nil || string(row.Response.Body) != "x" {
		t.Fatalf("transaction = %+v", row)
	}

	r := &measuredFile{File: f}
	got, err := c.HTTP1TransactionsFromReaderAt(r)
	if err != nil || !reflect.DeepEqual(got, rows) || r.bytesRead > 1<<20 {
		t.Fatalf("ReaderAt = %d transactions, %v after %d bytes", len(got), err, r.bytesRead)
	}
	t.Logf("ReaderAt fetched %d bytes from a %d-byte capture", r.bytesRead, len(raw))
	var sliceExport, readerExport bytes.Buffer
	if err := c.ExtractHTTP1TransactionPCAPNG(raw, &sliceExport, row.ID()); err != nil {
		t.Fatal(err)
	}
	if err := c.ExtractHTTP1TransactionPCAPNGFromReaderAt(f, &readerExport, row.ID()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sliceExport.Bytes(), readerExport.Bytes()) {
		t.Fatal("ReaderAt export differs from slice export")
	}
	raw = readerExport.Bytes()
	reopened, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	replayed := checkReaderParity(t, raw, reopened.HTTP1Transactions, reopened.HTTP1TransactionsFromReaderAt)
	if len(replayed) != 1 || replayed[0].Pairing != HTTP1ResponseConfirmed ||
		replayed[0].Response == nil || string(replayed[0].Response.Body) != "x" {
		t.Fatalf("replayed = %+v", replayed)
	}
}

func TestHTTP1SelectiveOpenings(t *testing.T) {
	// Cross a read window so the scan needs its selective path.
	src, dst := [4]byte{192, 0, 2, 10}, [4]byte{192, 0, 2, 20}
	noise := buildEthernetIPv4TCPFrame(src, dst, 30000, 22, 1, 0, TCPFlagACK, make([]byte, 60<<10))
	noise = slices.Concat(noise[:12], []byte{0x81, 0, 0, 42}, noise[12:])
	frames := [][]byte{noise, noise}
	const first = "GET /first HTTP/1.1\r\n\r\n"
	const clipped = 300
	beforeSYN := uint32(101)
	beforeSYN -= clipped
	frames = append(frames, txOpening()...)
	frames = append(frames,
		txFrame(true, 201, 101+uint32(len(first)), TCPFlagACK, txOK),
		txFrame(false, 103, 201, TCPFlagACK, first[2:]),
		// The initial SYN clips 300 bytes. The two remaining bytes are
		// beyond the frame prefix and arrive after the rest of the request.
		txFrame(false, beforeSYN, 201, TCPFlagACK, strings.Repeat("0", clipped)+first[:2]),
		txFrame(false, 1000, 0, TCPFlagSYN, ""),
		txFrame(true, 2000, 1001, TCPFlagSYN|TCPFlagACK, ""),
		txFrame(false, 1001, 2001, TCPFlagACK, "unrelated protocol"),
	)
	// Keep both HTTP exchanges separate even though their SYNs match.
	frames = append(frames, txOpening()...)
	frames = append(frames,
		txFrame(false, 101, 201, TCPFlagACK, "GET /last HTTP/1.1\r\n\r\n"),
		txFrame(true, 201, 125, TCPFlagACK, txOK),
	)
	rows, raw, capture := txScan(t, frames)
	if len(rows) != 2 || rows[0].Request.Target != "/first" || rows[1].Request.Target != "/last" ||
		rows[0].Pairing != HTTP1ResponseConfirmed || rows[1].Pairing != HTTP1ResponseConfirmed ||
		rows[0].Request.PacketIndex != 6 || rows[0].Request.PacketPayloadOffset != clipped ||
		!slices.Equal(rows[0].PacketIndices, []int{4, 5, 6}) || !slices.Equal(rows[1].PacketIndices, []int{12, 13}) {
		t.Fatalf("transactions = %+v", rows)
	}
	view, err := capture.SelectTenant(TenantScope{})
	if err != nil {
		t.Fatal(err)
	}
	scoped := checkReaderParity(t, raw, view.HTTP1Transactions, view.HTTP1TransactionsFromReaderAt)
	for i := range rows {
		rows[i].Request.FlowIndex = 0
	}
	if !reflect.DeepEqual(scoped, rows) {
		t.Fatalf("tenant transactions = %+v, want %+v", scoped, rows)
	}
}
