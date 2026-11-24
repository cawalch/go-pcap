package main

import (
	"bytes"
	"os"
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
	if err := run(path, &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != want {
		t.Fatalf("ReaderAt report:\n%s", &out)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
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
