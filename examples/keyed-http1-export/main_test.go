package main

import (
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cawalch/go-pcap"
)

func TestRun(t *testing.T) {
	const source = "../../testdata/keyed-http1-export.pcapng"
	var out bytes.Buffer
	if err := run(source, "/missing", nil, &out); err == nil || out.Len() != 0 {
		t.Fatalf("missing path: %v, wrote %d", err, out.Len())
	}
	if err := run(source, "/second", nil, &out); err != nil {
		t.Fatal(err)
	}
	c, err := pcap.New(out.Bytes())
	if err != nil || c.PacketCount != 11 || len(c.Secrets) != 0 {
		t.Fatalf("selected capture %+v, %v", c, err)
	}

	raw, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	for _, part := range [][]byte{raw[:len(raw)/2], raw[len(raw)/2:]} {
		writer := gzip.NewWriter(&compressed)
		if _, err := writer.Write(part); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "capture.pcapng.gz")
	if err := os.WriteFile(path, compressed.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	var fromGzip bytes.Buffer
	if err := run(path, "/second", nil, &fromGzip); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fromGzip.Bytes(), out.Bytes()) {
		t.Fatal("gzip export differs from plain file export")
	}

	compressed.Bytes()[compressed.Len()-8] ^= 0xff
	fromGzip.Reset()
	if err := run("-", "/second", &compressed, &fromGzip); !errors.Is(err, gzip.ErrChecksum) || fromGzip.Len() != 0 {
		t.Fatalf("invalid piped gzip: %v, wrote %d", err, fromGzip.Len())
	}
}
