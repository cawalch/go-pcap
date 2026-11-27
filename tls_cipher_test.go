package pcap

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"os"
	"testing"
)

func TestTLS12AndTLS13CipherCoverage(t *testing.T) {
	data, err := os.ReadFile("testdata/tls/cipher-coverage.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	capture, err := New(data)
	if err != nil {
		t.Fatal(err)
	}
	source := bytes.NewReader(data)
	reader, err := NewFromReaderAt(source, source.Size())
	if err != nil {
		t.Fatal(err)
	}
	records := checkReaderParity(t, data, capture.TLS, reader.TLSFromReaderAt)
	suites := []uint16{
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		TLS_AES_128_GCM_SHA256, tls.TLS_CHACHA20_POLY1305_SHA256,
	}
	if len(records) != len(suites) {
		t.Fatalf("TLS returned %d records, want %d", len(records), len(suites))
	}
	keyLog, err := capture.TLSKeyLog(nil)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := capture.Streams(data)
	if err != nil || len(wire) != len(suites) {
		t.Fatalf("Streams returned %d records, err=%v", len(wire), err)
	}
	for i, record := range records {
		hs := record.Handshake
		if !hs.HasClientHello || !hs.HasServerHello || hs.ServerHello.CipherSuite != suites[i] {
			t.Fatalf("flow %d visible selected suite = %#04x, want %#04x", i, hs.ServerHello.CipherSuite, suites[i])
		}
		entry := keyLog.Entries[hs.ClientHello.Random]
		if i < 2 && len(entry.MasterSecret) == 0 || i >= 2 && len(entry.ClientTrafficSecret0) == 0 {
			t.Fatalf("flow %d lacks the associated test secret", i)
		}
	}

	client, server := records[1].Handshake.ClientHello, records[1].Handshake.ServerHello
	master := keyLog.Entries[client.Random].MasterSecret
	if plain, err := DecryptTLS12Records(wire[1].Client.Data, server.CipherSuite, master, client.Random, server.Random, true); len(plain) != 0 || !errors.Is(err, ErrInvalidTLS) {
		t.Fatalf("TLS 1.2 ChaCha20 plaintext = %q, err=%v", plain, err)
	}
	hs := records[3].Handshake
	appSecret := keyLog.Entries[hs.ClientHello.Random].ClientTrafficSecret0
	if handshake, app, err := DecryptTLS13Records(wire[3].Client.Data, hs.ServerHello.CipherSuite, nil, appSecret); len(handshake) != 0 || len(app) != 0 || !errors.Is(err, ErrInvalidTLS) {
		t.Fatalf("TLS 1.3 ChaCha20 handshake = %x, application = %q, err=%v", handshake, app, err)
	}

	transactions := checkReaderParity(t, data,
		func(data []byte) ([]KeyedHTTP1Transaction, error) {
			return capture.KeyedHTTP1Transactions(data, nil)
		},
		func(r io.ReaderAt) ([]KeyedHTTP1Transaction, error) {
			return reader.KeyedHTTP1TransactionsFromReaderAt(r, nil)
		})
	if len(transactions) != 2 {
		t.Fatalf("keyed HTTP returned %d transactions, want two AES-GCM controls", len(transactions))
	}
	for i, tx := range transactions {
		if tx.Request.FlowIndex != 2*i || tx.Request.Target != "/response" ||
			tx.Response == nil || tx.Response.StatusCode != 200 || string(tx.Response.Body) != "cipher fixture" {
			t.Fatalf("AES-GCM control %d: %+v", i, tx)
		}
	}
	withoutKeys := *capture
	withoutKeys.Secrets = nil
	if tx, err := withoutKeys.KeyedHTTP1Transactions(data, nil); err != nil || len(tx) != 0 {
		t.Fatalf("keyless capture returned %d transactions, err=%v", len(tx), err)
	}
}
