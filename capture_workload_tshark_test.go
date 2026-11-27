package pcap_test

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	pcap "github.com/cawalch/go-pcap"
)

func TestEmbeddedCaptureWorkloadTShark(t *testing.T) {
	if os.Getenv("GO_PCAP_COMPARE_TSHARK") != "1" {
		t.Skip("set GO_PCAP_COMPARE_TSHARK=1 to compare with TShark")
	}
	tshark, err := exec.LookPath("tshark")
	if err != nil {
		t.Fatal(err)
	}
	raw := workloadCapture(t, true)
	path := filepath.Join(t.TempDir(), "mixed.pcapng")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		run  func() []string
	}{
		{"embedded", func() []string { return embeddedWorkloadRule(t, path, int64(len(raw))) }},
		{"tshark", func() []string {
			const filter = `(dns.qry.name == "trace.example" && dns.a == 198.51.100.80) || tls.handshake.extensions_server_name == "trace.example" || (http.request.method == "GET" && http.request.uri == "/reused")`
			out, err := exec.CommandContext(t.Context(), tshark, "-n", "-r", path, "-Y", filter, "-T", "fields",
				"-e", "frame.number", "-e", "dns.qry.name", "-e", "dns.a", "-e", "tls.handshake.extensions_server_name", "-e", "http.request.uri").Output()
			if err != nil {
				t.Fatal(err)
			}
			return strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
		}},
	}
	want := tests[0].run()
	if len(want) != 3 {
		t.Fatalf("expected three rule observations, got %q", want)
	}
	if got := tests[1].run(); !slices.Equal(got, want) {
		t.Fatalf("TShark returned %q, embedded returned %q", got, want)
	}
	var times [2][]time.Duration
	for i := range 10 {
		for _, j := range [2]int{i % 2, (i + 1) % 2} {
			start := time.Now()
			got := tests[j].run()
			times[j] = append(times[j], time.Since(start))
			if !slices.Equal(got, want) {
				t.Fatalf("%s returned %q, want %q", tests[j].name, got, want)
			}
		}
	}
	for i, test := range tests {
		slices.Sort(times[i])
		median := (times[i][4] + times[i][5]) / 2
		t.Logf("%s median %s, %d external launches, zero per-run temporary file bytes", test.name, median, i)
	}
	t.Logf("%d shared input bytes, %d TShark stdout bytes, matched %q", len(raw), len(strings.Join(want, "\n"))+1, want)
}

func embeddedWorkloadRule(t *testing.T, path string, size int64) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	}()
	capture, err := pcap.NewFromReaderAt(f, size)
	if err != nil {
		t.Fatal(err)
	}
	dns, err := capture.DNSFromReaderAt(f)
	if err != nil {
		t.Fatal(err)
	}
	tls, err := capture.TLSHandshakeEvidenceFromReaderAt(f, nil)
	if err != nil {
		t.Fatal(err)
	}
	http, err := capture.HTTP1TransactionsFromReaderAt(f)
	if err != nil {
		t.Fatal(err)
	}
	var rows []string
	for _, row := range dns {
		if len(row.Message.Questions) == 1 && row.Message.Questions[0].Name == "trace.example" {
			for _, answer := range row.Message.Answers {
				if answer.Address == netip.MustParseAddr("198.51.100.80") {
					rows = append(rows, fmt.Sprintf("%d\ttrace.example\t198.51.100.80\t\t", row.PacketIndex+1))
				}
			}
		}
	}
	for _, row := range tls {
		if row.Handshake.ClientHello.SNI == "trace.example" && len(row.ClientHello.PacketIndices) == 1 {
			rows = append(rows, fmt.Sprintf("%d\t\t\ttrace.example\t", row.ClientHello.PacketIndices[0]+1))
		}
	}
	for _, row := range http {
		if row.Request.Method == "GET" && row.Request.Target == "/reused" {
			rows = append(rows, fmt.Sprintf("%d\t\t\t\t/reused", row.Request.PacketIndex+1))
		}
	}
	return rows
}
