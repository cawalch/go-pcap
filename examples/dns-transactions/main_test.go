package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cawalch/go-pcap"
)

func TestTransactionCapture(t *testing.T) {
	const path = "../../testdata/deployments/dns-transactions.pcap"
	const want = `flow=0 query_frame=1 id=0001 name="ok.example" type=1 class=1 reply_frame=2 header_rcode=0 elapsed=8ms
flow=0 query_frame=3 id=0001 name="missing.example" type=1 class=1 reply_frame=4 header_rcode=3 elapsed=5ms
flow=1 query_frame=5 id=0002 name="slow.example" type=1 class=1 reply_frame=8 header_rcode=0 elapsed=1.2s
flow=1 query_frame=6 id=0003 name="fast.example" type=1 class=1 reply_frame=7 header_rcode=0 elapsed=6ms
flow=0 query_frame=9 id=0004 name="retry.example" type=1 class=1 ambiguous
flow=0 query_frame=10 id=0004 name="retry.example" type=1 class=1 ambiguous
flow=0 reply_frame=11 id=0004 name="retry.example" type=1 class=1 header_rcode=0 ambiguous
flow=0 reply_frame=12 id=0005 name="orphan.example" type=1 class=1 header_rcode=2 no_query_observed
flow=0 query_frame=13 id=0006 name="pending.example" type=1 class=1 no_reply_observed
`
	var out bytes.Buffer
	if err := run(path, nil, &out, options{}); err != nil {
		t.Fatal(err)
	}
	if out.String() != want {
		t.Fatalf("ReaderAt report:\n%s", &out)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	reader, writer := io.Pipe()
	defer func() { _ = reader.Close() }()
	go func() {
		_, err := writer.Write(data)
		_ = writer.CloseWithError(err)
	}()
	out.Reset()
	if err := run("-", reader, &out, options{}); err != nil {
		t.Fatal(err)
	}
	if out.String() != want {
		t.Fatalf("piped report:\n%s", &out)
	}
	c, err := pcap.New(data)
	if err != nil {
		t.Fatal(err)
	}
	records, err := c.DNS(data)
	if err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := report(&out, records); err != nil {
		t.Fatal(err)
	}
	if out.String() != want {
		t.Fatalf("slice report:\n%s", &out)
	}
}

func TestICMPReport(t *testing.T) {
	data, err := os.ReadFile("../../testdata/deployments/dns-transactions.pcap")
	if err != nil {
		t.Fatal(err)
	}
	c, err := pcap.New(data)
	if err != nil {
		t.Fatal(err)
	}
	var capture bytes.Buffer
	writer, err := pcap.NewPCAPWriter(&capture, pcap.LinkTypeEthernet, 65535)
	if err != nil {
		t.Fatal(err)
	}
	var query []byte
	for pkt, err := range c.PacketSeq(data) {
		if err != nil {
			t.Fatal(err)
		}
		frame, err := c.PacketPayload(data, pkt)
		if err != nil {
			t.Fatal(err)
		}
		if err := writer.WritePacket(pkt.TimestampNs, frame); err != nil {
			t.Fatal(err)
		}
		query = frame
	}
	// Quote the pending query's IPv4 and UDP headers, ending before DNS.
	const ipOffset, icmpOffset, quoteBytes = 14, 34, 28
	wire := make([]byte, icmpOffset+8+quoteBytes)
	binary.BigEndian.PutUint16(wire[12:14], pcap.EtherTypeIPv4)
	ip := wire[ipOffset:icmpOffset]
	ip[0], ip[8], ip[9] = 0x45, 64, pcap.IPProtoICMP
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(wire)-ipOffset))
	copy(ip[12:16], []byte{192, 0, 2, 1})
	copy(ip[16:20], query[ipOffset+12:ipOffset+16])
	wire[icmpOffset], wire[icmpOffset+1] = 3, 3
	copy(wire[icmpOffset+8:], query[ipOffset:ipOffset+quoteBytes])
	for _, ts := range []int64{1_700_000_002_000_000_000, 1_700_000_002_002_000_000} {
		if err := writer.WritePacket(ts, wire); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "icmp-dns.pcap")
	if err := os.WriteFile(path, capture.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	var plain, withICMP bytes.Buffer
	if err := run(path, nil, &plain, options{}); err != nil {
		t.Fatal(err)
	}
	if err := run(path, nil, &withICMP, options{icmp: true}); err != nil {
		t.Fatal(err)
	}
	const want = "flow=0 icmp_ip=4 icmp_type=3 icmp_code=3 quoted_src=192.0.2.14:53000 quoted_dst=192.0.2.53:53 count=2 first_error_frame=14 last_error_frame=15\n"
	if !strings.HasSuffix(plain.String(), "name=\"pending.example\" type=1 class=1 no_reply_observed\n") ||
		withICMP.String() != plain.String()+want {
		t.Fatalf("ICMP report:\n%s", &withICMP)
	}
}

func TestTCPZeroWindowReport(t *testing.T) {
	data, err := os.ReadFile("../../testdata/deployments/dns-transactions.pcap")
	if err != nil {
		t.Fatal(err)
	}
	c, err := pcap.New(data)
	if err != nil {
		t.Fatal(err)
	}
	for pkt, err := range c.PacketSeq(data) {
		if err != nil {
			t.Fatal(err)
		}
		// The resolver sent TCP responses in frames seven and eight.
		if pkt.Index == 6 || pkt.Index == 7 {
			const windowOffset = 14 + 20 + 14
			start := pkt.PayloadOffset + windowOffset
			clear(data[start : start+2])
		}
	}

	var plain, withWindow bytes.Buffer
	if err := run("-", bytes.NewReader(data), &plain, options{}); err != nil {
		t.Fatal(err)
	}
	if err := run("-", bytes.NewReader(data), &withWindow, options{tcpZeroWindow: true}); err != nil {
		t.Fatal(err)
	}
	const want = "flow=1 tcp_zero_window_src=192.0.2.53:53 tcp_zero_window_dst=192.0.2.14:53000 count=2 first_zero_window_frame=7 last_zero_window_frame=8\n"
	if withWindow.String() != plain.String()+want {
		t.Fatalf("zero-window report:\n%s", &withWindow)
	}
}
