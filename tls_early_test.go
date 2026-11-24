package pcap

import (
	"bytes"
	"os"
	"testing"
)

// The DSB holds the public example secrets for RFC 8448 section 4.
func TestTLS13EarlyDataCapture(t *testing.T) {
	raw, err := os.ReadFile("testdata/rfc8448-0rtt.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Secrets) != 1 {
		t.Fatalf("got %d secret blocks", len(c.Secrets))
	}
	var withoutEarly, onlyEarly, wrongEarly []byte
	for line := range bytes.Lines(c.Secrets[0].Data) {
		if bytes.HasPrefix(line, []byte("CLIENT_EARLY_TRAFFIC_SECRET ")) {
			onlyEarly = bytes.Clone(line)
			fields := bytes.Fields(line)
			wrongEarly = append(wrongEarly, bytes.Replace(line, fields[2], bytes.Repeat([]byte("0"), len(fields[2])), 1)...)
		} else {
			withoutEarly = append(withoutEarly, line...)
			wrongEarly = append(wrongEarly, line...)
		}
	}
	later := make([]byte, 50)
	for i := range later {
		later[i] = byte(i)
	}
	early := []byte("ABCDEF")
	for _, tc := range []struct {
		name                 string
		keys, client, server []byte
	}{
		{"embedded", nil, append(bytes.Clone(early), later...), later},
		{"missing early key", withoutEarly, later, later},
		{"incorrect early key", wrongEarly, later, later},
		{"early key alone", onlyEarly, early, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			capture := *c
			if tc.keys != nil {
				capture.Secrets = nil
			}
			streams, err := capture.DecryptedTLSStreams(raw, tc.keys)
			if err != nil || len(streams) != 1 {
				t.Fatalf("got %d streams, err %v", len(streams), err)
			}
			if !bytes.Equal(streams[0].Client.Data, tc.client) || !bytes.Equal(streams[0].Server.Data, tc.server) {
				t.Fatalf("client %x, server %x", streams[0].Client.Data, streams[0].Server.Data)
			}
		})
	}
}

func TestTLS13EarlyDataEpochs(t *testing.T) {
	early, app := bytes.Repeat([]byte{1}, 48), bytes.Repeat([]byte{2}, 32)
	sealEarly := func(seq uint64, text string) []byte {
		return encryptTLS13AppDataRecord(t, early, TLS_AES_256_GCM_SHA384, seq, TLSRecordApplicationData, []byte(text))
	}
	wire := bytes.Join([][]byte{
		sealEarly(0, "first "), sealEarly(1, "second "),
		encryptTLS13AppDataRecord(t, app, TLS_AES_128_GCM_SHA256, 0, TLSRecordApplicationData, []byte("later")),
		sealEarly(2, "out of epoch"),
	}, nil)
	_, got, err := decryptTLS13Records(wire, TLS_AES_128_GCM_SHA256, nil, app, early, nil)
	if err != nil || string(got) != "first second later" {
		t.Fatalf("got %q, err %v", got, err)
	}
}
