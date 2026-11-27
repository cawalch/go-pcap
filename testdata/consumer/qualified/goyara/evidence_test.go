package goyarapcap_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/cawalch/go-yara/compiler"
)

const rule = `import "pcap"
rule observed_name_evidence {
  condition:
    pcap.tls[0].flow_index == 0 and pcap.tls[0].server_name_match and
    pcap.tls[1].flow_index == 1 and defined pcap.tls[1].server_name_match and
    not pcap.tls[1].server_name_match and
    pcap.tls[2].flow_index == 2 and not defined pcap.tls[2].server_name_match
}`

type inputCounter struct {
	*bytes.Reader
	sequential, random, calls int64
}

func (r *inputCounter) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.sequential += int64(n)
	return n, err
}

func (r *inputCounter) ReadAt(p []byte, off int64) (int, error) {
	n, err := r.Reader.ReadAt(p, off)
	r.random += int64(n)
	r.calls++
	return n, err
}

func makeScanner(t testing.TB) (*compiler.CompiledProgram, []byte) {
	t.Helper()
	data, err := os.ReadFile("../../../deployments/tls-names.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	program, err := compiler.NewCompiler().CompileSource(rule)
	if err != nil {
		t.Fatal(err)
	}
	return program, data
}

func TestGoYARATaggedPCAP(t *testing.T) {
	program, data := makeScanner(t)
	scanner := program.NewScanner()
	defer scanner.Close()
	fromSlice, err := scanner.Scan(data)
	if err != nil || !fromSlice.RuleResults["observed_name_evidence"] {
		t.Fatalf("go-yara slice evidence did not match: %v", err)
	}
	source := &inputCounter{Reader: bytes.NewReader(data)}
	fromReader, err := scanner.ScanReader(source)
	if err != nil || !fromReader.RuleResults["observed_name_evidence"] || source.random == 0 {
		t.Fatalf("go-yara seekable evidence did not match: %v", err)
	}
	t.Logf("input=%d bytes, sequential=%d bytes, random=%d bytes in %d ReadAt calls",
		len(data), source.sequential, source.random, source.calls)
}

func BenchmarkGoYARATaggedPCAP(b *testing.B) {
	program, data := makeScanner(b)
	scanner := program.NewScanner()
	defer scanner.Close()
	source := &inputCounter{Reader: bytes.NewReader(nil)}
	b.ReportAllocs()
	for b.Loop() {
		source.Reset(data)
		rows, err := scanner.ScanReader(source)
		if err != nil || !rows.RuleResults["observed_name_evidence"] {
			b.Fatalf("go-yara evidence did not match: %v", err)
		}
	}
	b.ReportMetric(float64(source.sequential)/float64(b.N), "seq-read-B/op")
	b.ReportMetric(float64(source.random)/float64(b.N), "readat-B/op")
	b.ReportMetric(float64(source.calls)/float64(b.N), "readat-calls/op")
}
