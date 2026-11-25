package main

import (
	"bytes"
	"testing"

	"github.com/cawalch/go-pcap"
)

func TestRun(t *testing.T) {
	const source = "../../testdata/keyed-http1-export.pcapng"
	var out bytes.Buffer
	if err := run(source, "/missing", &out); err == nil || out.Len() != 0 {
		t.Fatalf("missing path: %v, wrote %d", err, out.Len())
	}
	if err := run(source, "/second", &out); err != nil {
		t.Fatal(err)
	}
	c, err := pcap.New(out.Bytes())
	if err != nil || c.PacketCount != 11 || len(c.Secrets) != 0 {
		t.Fatalf("selected capture %+v, %v", c, err)
	}
}
