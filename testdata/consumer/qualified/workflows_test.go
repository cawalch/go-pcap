package qualified_test

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	pcap "github.com/cawalch/go-pcap"
)

type sourceCounter struct {
	io.ReaderAt
	bytes, calls int64
}

func (c *sourceCounter) ReadAt(p []byte, off int64) (int, error) {
	n, err := c.ReaderAt.ReadAt(p, off)
	c.bytes += int64(n)
	c.calls++
	return n, err
}

func fixture(t testing.TB, name string) (string, []byte) {
	t.Helper()
	path := filepath.Join("..", "..", "deployments", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, data
}

func verifyInputs[T any](t *testing.T, name string,
	readSlice func(*pcap.Capture, []byte) ([]T, error),
	readSeekable func(*pcap.Capture, io.ReaderAt) ([]T, error),
) []T {
	t.Helper()
	path, data := fixture(t, name)
	capture, err := pcap.New(data)
	if err != nil {
		t.Fatal(err)
	}
	fromBytes, err := readSlice(capture, data)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	source := &sourceCounter{ReaderAt: file}
	capture, err = pcap.NewFromReaderAt(source, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	fromReader, err := readSeekable(capture, source)
	if err != nil || !reflect.DeepEqual(fromBytes, fromReader) {
		t.Fatalf("seekable and slice evidence differ: %v", err)
	}
	t.Logf("%s: input=%d bytes, open and scan=%d bytes in %d ReaderAt calls, rows=%d",
		name, len(data), source.bytes, source.calls, len(fromReader))
	return fromReader
}

func TestTaggedTLSConfiguration(t *testing.T) {
	rows := verifyInputs(t, "tls-names.pcapng", (*pcap.Capture).TLS, (*pcap.Capture).TLSFromReaderAt)
	want := []struct {
		sni          string
		match, known bool
	}{
		{"match.example", true, true},
		{"different.example", false, true},
		{"opaque.example", false, false},
	}
	if len(rows) != len(want) {
		t.Fatalf("got %d TLS rows, want %d", len(rows), len(want))
	}
	for i, row := range rows {
		match, known := row.Handshake.ServerNameMatch()
		expected := want[i]
		if row.FlowIndex != i || row.Handshake.ClientHello.SNI != expected.sni || match != expected.match || known != expected.known {
			t.Fatalf("flow %d SNI=%q match=%t known=%t", row.FlowIndex, row.Handshake.ClientHello.SNI, match, known)
		}
	}
}

func TestTaggedResolverDiagnostic(t *testing.T) {
	rows := verifyInputs(t, "dns-transactions.pcap", (*pcap.Capture).DNSTransactions, (*pcap.Capture).DNSTransactionsFromReaderAt)
	pairings := make(map[int]pcap.DNSTransaction)
	for _, tx := range rows {
		if tx.Query != nil {
			pairings[tx.Query.PacketIndex] = tx
		}
	}
	positive := pairings[0]
	elapsed, measured := positive.Elapsed()
	if positive.Pairing != pcap.DNSPaired || positive.Reply == nil || positive.Reply.PacketIndex != 1 ||
		positive.Reply.Message.RCode != 0 || !measured || elapsed != 8*time.Millisecond {
		t.Fatalf("positive reply: %+v, elapsed %v", positive, elapsed)
	}
	negative := pairings[2]
	if negative.Pairing != pcap.DNSPaired || negative.Reply == nil || negative.Reply.PacketIndex != 3 || negative.Reply.Message.RCode != 3 {
		t.Fatalf("negative reply: %+v", negative)
	}
	if pairings[8].Pairing != pcap.DNSAmbiguous || pairings[9].Pairing != pcap.DNSAmbiguous ||
		pairings[12].Pairing != pcap.DNSNoReplyObserved || pairings[12].Reply != nil {
		t.Fatalf("missing or ambiguous evidence: %+v", pairings)
	}
}

func TestTaggedHTTPContent(t *testing.T) {
	rows := verifyInputs(t, "http1-transactions.pcapng", (*pcap.Capture).HTTP1Transactions, (*pcap.Capture).HTTP1TransactionsFromReaderAt)
	byTarget := make(map[string]pcap.HTTP1Transaction)
	for _, tx := range rows {
		byTarget[tx.Request.Target] = tx
	}
	positive := byTarget["/upload"]
	if positive.Pairing != pcap.HTTP1ResponseConfirmed || positive.Request.PacketIndex != 4 ||
		string(positive.Request.Body) != "data" || positive.Response == nil || positive.Response.PacketIndex != 9 ||
		positive.Response.BodyState != pcap.HTTPBodyComplete || string(positive.Response.Body) != "upload accepted\n" {
		t.Fatalf("positive content: %+v", positive)
	}
	negative := byTarget["/pipelined"]
	if negative.Pairing != pcap.HTTP1ResponseConfirmed || negative.Response == nil || negative.Response.StatusCode != 204 ||
		negative.Response.PacketIndex != 10 || negative.Response.BodyState != pcap.HTTPBodyComplete || len(negative.Response.Body) != 0 {
		t.Fatalf("complete negative control: %+v", negative)
	}
	unknown := byTarget["/after-gap"]
	if unknown.Pairing != pcap.HTTP1ResponseAmbiguous || unknown.Request.PacketIndex != 18 || unknown.Response != nil {
		t.Fatalf("ambiguous response: %+v", unknown)
	}
}

func TestTaggedCoverageSignals(t *testing.T) {
	_, data := fixture(t, "http1-transactions.pcapng")
	prefix := data[:len(data)-2]
	c, err := pcap.NewWithLength(prefix, int64(len(data)))
	if err != nil || !c.InputTruncated() {
		t.Fatalf("incomplete tail was not reported: %v", err)
	}
	rows, err := c.HTTP1Transactions(prefix)
	if err != nil || len(rows) == 0 || rows[0].Request.Target != "/upload" ||
		rows[0].Pairing != pcap.HTTP1ResponseConfirmed {
		t.Fatalf("earlier complete exchange unavailable: %v", err)
	}

	var tooManyQuestions [12]byte
	binary.BigEndian.PutUint16(tooManyQuestions[4:6], pcap.MaxDNSQuestions+1)
	if _, err := pcap.ParseDNS(tooManyQuestions[:]); !errors.Is(err, pcap.ErrDNSLimit) {
		t.Fatalf("oversized DNS question count: %v", err)
	}
}

func BenchmarkTaggedWorkflows(b *testing.B) {
	b.Run("TLS", func(b *testing.B) {
		benchmarkSeekable(b, "tls-names.pcapng", (*pcap.Capture).TLSFromReaderAt)
	})
	b.Run("DNS", func(b *testing.B) {
		benchmarkSeekable(b, "dns-transactions.pcap", (*pcap.Capture).DNSTransactionsFromReaderAt)
	})
	b.Run("HTTP", func(b *testing.B) {
		benchmarkSeekable(b, "http1-transactions.pcapng", (*pcap.Capture).HTTP1TransactionsFromReaderAt)
	})
}

func benchmarkSeekable[T any](b *testing.B, name string, read func(*pcap.Capture, io.ReaderAt) ([]T, error)) {
	path, data := fixture(b, name)
	file, err := os.Open(path)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	source := &sourceCounter{ReaderAt: file}
	b.ReportAllocs()
	for b.Loop() {
		capture, err := pcap.NewFromReaderAt(source, int64(len(data)))
		if err != nil {
			b.Fatal(err)
		}
		rows, err := read(capture, source)
		if err != nil || len(rows) == 0 {
			b.Fatalf("empty evidence: %v", err)
		}
	}
	b.ReportMetric(float64(source.bytes)/float64(b.N), "read-B/op")
	b.ReportMetric(float64(source.calls)/float64(b.N), "reads/op")
}
