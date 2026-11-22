package pcap

import (
	"bytes"
	"testing"
)

func TestTLSResumption(t *testing.T) {
	id := []byte{0, 1, 2, 3}
	hello := func(server bool, sid, exts []byte, random [32]byte) []byte {
		record := testKeyShareHello(server, random, exts)
		body := append([]byte{}, record[9:43]...)
		body = append(body, byte(len(sid)))
		body = append(body, sid...)
		return wrapTLSHandshakeRecord(record[5], append(body, record[44:]...))
	}
	ticket := testTLSExtension(TLSExtSessionTicket, nil)
	v13 := testTLSExtension(TLSExtSupportedVersions, []byte{3, 4})
	psk := append(bytes.Clone(v13), testTLSExtension(TLSExtPreSharedKey, []byte{0, 0})...)
	client12 := hello(false, id, ticket, [32]byte{})
	client13 := hello(false, id, testTLSExtension(TLSExtPreSharedKey, []byte{1}), [32]byte{})
	server12 := hello(true, id, ticket, [32]byte{})
	server13 := hello(true, id, psk, [32]byte{})
	retry := hello(true, id, v13, helloRetryRandom)
	ccs := []byte{TLSRecordChangeCipherSpec, 3, 3, 0, 1, 1}
	encrypted := append(bytes.Clone(ccs), []byte{TLSRecordHandshake, 3, 3, 0, 4, 0xff, 0xff, 0xff, 0xff}...)
	certs := buildTLSServerHelloAndCertRecords(t)[len(buildTLSServerHelloRecord()):]
	// Record framing still reports truncation after the plaintext epoch.
	short := append(bytes.Clone(server12), encrypted[:len(encrypted)-1]...)
	parsed, err := ParseTLSRecords(short)
	if err != nil || !parsed.Anomalies.TruncatedRecord {
		t.Fatalf("truncated encrypted record: %+v, %v", parsed.Anomalies, err)
	}
	for _, tc := range []struct {
		name           string
		client, server []byte
		resumed        bool
	}{
		{"session ID echo", client12, server12, true},
		{"different ID", client12, hello(true, []byte{9}, ticket, [32]byte{}), false},
		{"empty IDs", hello(false, nil, nil, [32]byte{}), hello(true, nil, nil, [32]byte{}), false},
		{"certificate", client12, append(bytes.Clone(server12), certs...), false},
		{"PSK selected", client13, server13, true},
		{"compatibility ID and offer only", client13, hello(true, id, v13, [32]byte{}), false},
		{"malformed selection", client13, hello(true, id, append(bytes.Clone(v13), testTLSExtension(TLSExtPreSharedKey, []byte{0})...), [32]byte{}), false},
		{"retry only", client13, hello(true, id, psk, helloRetryRandom), false},
		{"retry then selection", client13, append(append(bytes.Clone(retry), ccs...), server13...), true},
		{"encrypted Finished", client12, append(bytes.Clone(server12), encrypted...), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := keyShareCapture(tc.client, tc.server, 1)
			c, err := New(raw)
			if err != nil {
				t.Fatal(err)
			}
			r := bytes.NewReader(raw)
			cr, err := NewFromReaderAt(r, r.Size())
			if err != nil {
				t.Fatal(err)
			}
			checkReaderParity(t, raw, c.TLS, cr.TLSFromReaderAt)
			rows, err := c.TLS(raw)
			if err != nil || len(rows) != 1 {
				t.Fatalf("records %d, err %v", len(rows), err)
			}
			direct, err := ParseTLSRecords(append(bytes.Clone(tc.client), tc.server...))
			if err != nil {
				t.Fatal(err)
			}
			for _, hs := range []TLSHandshake{direct, rows[0].Handshake} {
				if hs.IsResumed != tc.resumed {
					t.Fatalf("IsResumed = %t, want %t", hs.IsResumed, tc.resumed)
				}
				if bytes.Equal(tc.client, client12) && !hs.ClientHello.HasSessionTicket ||
					bytes.Equal(tc.client, client13) && !hs.ClientHello.HasPSK ||
					bytes.Equal(tc.server, server12) && !hs.ServerHello.HasSessionTicket ||
					bytes.Equal(tc.server, server13) && !hs.ServerHello.HasPSK {
					t.Fatal("missing hello extension")
				}
				if tc.name == "retry then selection" && !hs.ServerHello.IsHelloRetryRequest {
					t.Fatal("lost first hello")
				}
			}
		})
	}
}
