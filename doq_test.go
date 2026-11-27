package pcap

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"reflect"
	"slices"
	"testing"
)

func TestDoQTransactions(t *testing.T) {
	raw, err := os.ReadFile("testdata/doq-exchanges.pcap")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := os.ReadFile("testdata/doq-exchanges.keys")
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	rows := checkReaderParity(t, raw,
		func(data []byte) ([]DoQTransaction, error) { return c.DoQTransactions(data, keys) },
		func(r io.ReaderAt) ([]DoQTransaction, error) { return c.DoQTransactionsFromReaderAt(r, keys) })
	if len(rows) != 2 {
		t.Fatalf("got %d DoQ streams", len(rows))
	}
	for i, qname := range []string{"one.example", "two.example"} {
		row := rows[i]
		wantAddress := []string{"192.0.2.10", "192.0.2.11"}[i]
		if row.StreamID != uint64(i)*4 || row.ALPNPacketIndex != 1 ||
			row.Query.State != DoQComplete || row.Reply.State != DoQComplete ||
			row.Query.DNS.Questions[0].Name != qname || row.Reply.DNS.Answers[0].Address.String() != wantAddress ||
			!slices.Equal(row.Query.PacketIndices, []int{5 + i}) || !slices.Equal(row.Reply.PacketIndices, []int{8 - i}) {
			t.Fatalf("unexpected stream %d: %+v", i, row)
		}
	}

	b := &measuredReaderAt{Reader: bytes.NewReader(raw)}
	if observed, err := c.DoQTransactionsFromReaderAt(b, keys); err != nil || !reflect.DeepEqual(observed, rows) {
		t.Fatalf("counted ReaderAt results differ: %v", err)
	}
	t.Logf("memory ReaderAt fetched %d bytes in %d calls from a %d byte input", b.bytesRead, b.calls, len(raw))
	f := &measuredFile{File: tempCaptureFile(t, raw)}
	if observed, err := c.DoQTransactionsFromReaderAt(f, keys); err != nil || !reflect.DeepEqual(observed, rows) {
		t.Fatalf("file ReaderAt results differ: %v", err)
	}
	t.Logf("file ReaderAt fetched %d bytes in %d calls", f.bytesRead, f.calls)
	if observed, err := c.DoQTransactions(raw, nil); err != nil || len(observed) != 0 {
		t.Fatalf("keyless results: %d rows, %v", len(observed), err)
	}
	h3, err := os.ReadFile("testdata/http3-framing.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	c, err = New(h3)
	if err != nil {
		t.Fatal(err)
	}
	if observed, err := c.DoQTransactions(h3, nil); err != nil || len(observed) != 0 {
		t.Fatalf("HTTP/3 results: %d rows, %v", len(observed), err)
	}
}

func TestDoQMessageCoverage(t *testing.T) {
	query := []byte{0, 17, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1}
	check := func(message []byte, closed, gap, reset bool, want DoQMessageState) {
		t.Helper()
		stream := quicLocatedStream{packets: []int{3}, stream: QUICStream{Data: message, Complete: closed, Gap: gap, Reset: reset}}
		got := parseDoQMessage(stream, false)
		if got.State != want || !slices.Equal(got.PacketIndices, []int{3}) || (got.DNS != nil) != (want == DoQComplete) {
			t.Fatalf("want %d, got %+v", want, got)
		}
	}
	check(query, true, false, false, DoQComplete)
	check(query, false, false, false, DoQIncomplete)
	check(query[:5], false, true, false, DoQIncomplete)
	check(query, false, false, true, DoQReset)
	check(query[:5], true, false, false, DoQMalformed)
	check(append(bytes.Clone(query), query...), true, false, false, DoQMalformed)
	wrongID := bytes.Clone(query)
	binary.BigEndian.PutUint16(wrongID[2:], 7)
	check(wrongID, true, false, false, DoQMalformed)
	axfr := bytes.Clone(query)
	binary.BigEndian.PutUint16(axfr[15:], 252)
	check(axfr, true, false, false, DoQUnsupported)
}
