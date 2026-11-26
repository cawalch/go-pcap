package pcap

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"io"
	"os"
	"slices"
	"testing"
)

const (
	tls12CBCFixture      = "testdata/tls/tls12-cbc.pcapng"
	tls12CBCRequest      = "GET /response HTTP/1.0\r\nHost: example.test\r\n\r\n"
	tls12CBCResponse     = "HTTP/1.0 200 OK\r\nContent-Length: 11\r\n\r\ncbc fixture"
	tls12CBCFixtureSuite = TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
)

func TestTLS12CBCOpenSSLFixture(t *testing.T) {
	raw, err := os.ReadFile(tls12CBCFixture)
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	source := bytes.NewReader(raw)
	reader, err := NewFromReaderAt(source, source.Size())
	if err != nil {
		t.Fatal(err)
	}
	keys, err := c.TLSKeyLog(nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		suite uint16
		etm   bool
	}{
		{TLS_RSA_WITH_AES_128_CBC_SHA, true},
		{TLS_RSA_WITH_AES_256_CBC_SHA, false},
		{TLS_RSA_WITH_AES_256_CBC_SHA256, true},
		{TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, false},
		{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, true},
		{TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, false},
		{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, false},
		{TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, true},
	}
	wire, err := c.Streams(raw)
	if err != nil || len(wire) != len(want) {
		t.Fatalf("wire streams = %d, %v", len(wire), err)
	}
	for i, stream := range wire {
		client, err := ParseTLSRecords(stream.Client.Data)
		if err != nil || !client.HasClientHello {
			t.Fatalf("flow %d client hello: %v", i, err)
		}
		server, err := ParseTLSRecords(stream.Server.Data)
		if err != nil || !server.HasServerHello {
			t.Fatalf("flow %d server hello: %v", i, err)
		}
		if server.ServerHello.CipherSuite != want[i].suite ||
			slices.Contains(server.ServerHello.Extensions, tlsExtEncryptThenMAC) != want[i].etm {
			t.Fatalf("flow %d suite or layout mismatch", i)
		}
		master := keys.Entries[client.ClientHello.Random].MasterSecret
		for _, direction := range []struct {
			stream   []byte
			expected string
			client   bool
		}{
			{stream.Client.Data, tls12CBCRequest, true},
			{stream.Server.Data, tls12CBCResponse, false},
		} {
			plain, err := DecryptTLS12Records(direction.stream, want[i].suite, master, client.ClientHello.Random, server.ServerHello.Random, direction.client)
			if err != nil || string(plain) != direction.expected {
				t.Fatalf("flow %d client=%v plaintext = %q, %v", i, direction.client, plain, err)
			}
		}
	}

	plain, err := c.DecryptedTLSStreams(raw, nil)
	if err != nil || len(plain) != len(want) {
		t.Fatalf("decrypted streams = %d, %v", len(plain), err)
	}
	for i, stream := range plain {
		if string(stream.Client.Data) != tls12CBCRequest || string(stream.Server.Data) != tls12CBCResponse {
			t.Fatalf("flow %d client = %q, server = %q", i, stream.Client.Data, stream.Server.Data)
		}
	}
	readerWire, err := collectStreams(reader.tcpReaderAt(source), 0, nil, tcpWireNone)
	if err != nil {
		t.Fatal(err)
	}
	readerPlain := decryptTLSStreams(readerWire, keys)
	if len(readerPlain) != len(plain) {
		t.Fatalf("ReaderAt decrypted streams = %d, want %d", len(readerPlain), len(plain))
	}
	for i, stream := range readerPlain {
		if stream.FlowIndex != plain[i].FlowIndex || !bytes.Equal(stream.Client.Data, plain[i].Client.Data) ||
			!bytes.Equal(stream.Server.Data, plain[i].Server.Data) {
			t.Fatalf("ReaderAt plaintext differs for flow %d", i)
		}
	}
	web, err := c.Web(raw)
	if err != nil || len(web.HTTP) != 2*len(want) {
		t.Fatalf("Web HTTP records = %d, %v", len(web.HTTP), err)
	}
	for _, record := range web.HTTP {
		if !record.IsDecrypted {
			t.Fatalf("Web record is missing decryption annotation: %+v", record)
		}
	}
	tx := checkReaderParity(t, raw,
		func(data []byte) ([]KeyedHTTP1Transaction, error) { return c.KeyedHTTP1Transactions(data, nil) },
		func(r io.ReaderAt) ([]KeyedHTTP1Transaction, error) {
			return reader.KeyedHTTP1TransactionsFromReaderAt(r, nil)
		})
	if len(tx) != len(want) {
		t.Fatalf("keyed transactions = %d, want %d", len(tx), len(want))
	}
	for _, transaction := range tx {
		if transaction.Response == nil || len(transaction.RequestRecords) == 0 || len(transaction.ResponseRecords) == 0 {
			t.Fatalf("missing response or ciphertext provenance: %+v", transaction)
		}
	}
}

func sealTLS12CBCTestRecord(p *tls12CBCProtection, seq uint64, payload []byte, extraBlocks int, badPadding, badMAC bool) []byte {
	const typ = TLSRecordApplicationData
	plain := bytes.Clone(payload)
	if p.mode == tls12CBCMACThenEncrypt {
		mac := p.recordMAC(seq, typ, TLSVersion12, payload)
		if badMAC {
			mac[0] ^= 1
		}
		plain = append(plain, mac...)
	}
	padding := aes.BlockSize - len(plain)%aes.BlockSize + extraBlocks*aes.BlockSize
	plain = append(plain, bytes.Repeat([]byte{byte(padding - 1)}, padding)...)
	if badPadding {
		plain[len(plain)-1] ^= 1
	}
	iv := [aes.BlockSize]byte{0x42, byte(seq)}
	body := append(bytes.Clone(iv[:]), plain...)
	cipher.NewCBCEncrypter(p.block, iv[:]).CryptBlocks(body[aes.BlockSize:], plain)
	if p.mode == tls12CBCEncryptThenMAC {
		mac := p.recordMAC(seq, typ, TLSVersion12, body)
		if badMAC {
			mac[0] ^= 1
		}
		body = append(body, mac...)
	}
	record := binary.BigEndian.AppendUint16([]byte{typ, 3, 3}, uint16(len(body)))
	return append(record, body...)
}

func TestTLS12CBCRejectsUnauthenticatedRecords(t *testing.T) {
	var master [48]byte
	client, server := [32]byte{1}, [32]byte{2}
	for _, mode := range []tls12CBCMode{tls12CBCMACThenEncrypt, tls12CBCEncryptThenMAC} {
		p, err := tls12CBCSuiteParams(tls12CBCFixtureSuite).trafficProtection(master[:], client, server, true, mode)
		if err != nil {
			t.Fatal(err)
		}
		other := p
		if mode == tls12CBCMACThenEncrypt {
			other.mode = tls12CBCEncryptThenMAC
		} else {
			other.mode = tls12CBCMACThenEncrypt
		}
		first := sealTLS12CBCTestRecord(&p, 0, []byte("accepted"), 0, false, false)
		tail := sealTLS12CBCTestRecord(&p, 2, []byte("ignored"), 0, false, false)
		for _, bad := range [][]byte{
			sealTLS12CBCTestRecord(&p, 1, []byte("bad MAC"), 0, false, true),
			sealTLS12CBCTestRecord(&p, 1, []byte("bad padding"), 0, true, false),
			sealTLS12CBCTestRecord(&other, 1, []byte("layout changed"), 0, false, false),
			{TLSRecordChangeCipherSpec, 3, 3, 0, 1, 1},
		} {
			stream := append(append(bytes.Clone(first), bad...), tail...)
			plain, err := DecryptTLS12Records(stream, tls12CBCFixtureSuite, master[:], client, server, true)
			if err != nil || string(plain) != "accepted" {
				t.Fatalf("mode %d accepted data beyond failure: %q, %v", mode, plain, err)
			}
		}
	}
}

func TestTLS12CBCPaddingLimits(t *testing.T) {
	for _, n := range []int{1, 16, 17, 255, 256} {
		padding := bytes.Repeat([]byte{byte(n - 1)}, n)
		data := append([]byte("content"), padding...)
		if size, ok := tls12CBCUnpad(data); size != len("content") || ok != 1 {
			t.Fatalf("valid padding of length %d gives %d, %d", n, size, ok)
		}
		if n > 1 {
			data[len("content")] ^= 1
			if _, ok := tls12CBCUnpad(data); ok != 0 {
				t.Fatalf("accepted malformed padding of length %d", n)
			}
		}
	}
	if _, ok := tls12CBCUnpad([]byte{0xff}); ok != 0 {
		t.Fatal("accepted padding beyond the complete record")
	}
	var random [32]byte
	var master [48]byte
	for _, mode := range []tls12CBCMode{tls12CBCMACThenEncrypt, tls12CBCEncryptThenMAC} {
		p, err := tls12CBCSuiteParams(tls12CBCFixtureSuite).trafficProtection(master[:], random, random, true, mode)
		if err != nil {
			t.Fatal(err)
		}
		payload := []byte("16-byte payload!")
		record := sealTLS12CBCTestRecord(&p, 0, payload, 15, false, false)
		plain, ok := p.open(0, TLSRecordApplicationData, TLSVersion12, record[5:])
		if !ok || !bytes.Equal(plain, payload) {
			t.Fatalf("mode %d maximum-padding record = %q, %v", mode, plain, ok)
		}
	}
}

func FuzzTLS12CBCOpen(f *testing.F) {
	var random [32]byte
	var master [48]byte
	params := tls12CBCSuiteParams(tls12CBCFixtureSuite)
	for _, mode := range []tls12CBCMode{tls12CBCMACThenEncrypt, tls12CBCEncryptThenMAC} {
		p, err := params.trafficProtection(master[:], random, random, true, mode)
		if err != nil {
			f.Fatal(err)
		}
		record := sealTLS12CBCTestRecord(&p, 0, []byte("fixture"), 0, false, false)
		f.Add(record[5:], mode == tls12CBCEncryptThenMAC)
	}
	f.Fuzz(func(t *testing.T, body []byte, etm bool) {
		if len(body) > MaxTLSRecordBytes {
			return
		}
		mode := tls12CBCMACThenEncrypt
		if etm {
			mode = tls12CBCEncryptThenMAC
		}
		p, err := params.trafficProtection(master[:], random, random, true, mode)
		if err != nil {
			t.Fatal(err)
		}
		if plain, ok := p.open(0, TLSRecordApplicationData, TLSVersion12, body); ok && len(plain) > len(body) {
			t.Fatalf("plaintext exceeds record body: %d > %d", len(plain), len(body))
		}
	})
}

func BenchmarkTLS12CBCFixture(b *testing.B) {
	raw, err := os.ReadFile(tls12CBCFixture)
	if err != nil {
		b.Fatal(err)
	}
	c, err := New(raw)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		streams, err := c.DecryptedTLSStreams(raw, nil)
		if err != nil || len(streams) != 8 {
			b.Fatalf("decrypted streams = %d, %v", len(streams), err)
		}
	}
}
