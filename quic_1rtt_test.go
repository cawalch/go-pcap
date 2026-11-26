package pcap

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
)

// The first four vectors come from complete aioquic 1.3.0 handshakes between
// two in-memory endpoints. TShark 4.6.10 independently confirmed the packet
// numbers and STREAM data using the TLS key logs. The edge vectors use
// aioquic's packet protector with synthetic inputs.
type quic1RTTVector struct {
	Name           string
	Version        uint32
	CipherSuite    uint16 `json:"cipher_suite"`
	KeyLog         string `json:"key_log"`
	DestinationCID []byte `json:"destination_cid"`
	ExpectedNumber uint64 `json:"expected_number"`
	PacketNumber   uint64 `json:"packet_number"`
	Packet         []byte
	Plaintext      []byte
	InvalidHeader  bool `json:"invalid_header"`
}

func readQUIC1RTTVectors() ([]quic1RTTVector, error) {
	data, err := os.ReadFile("testdata/quic-1rtt-vectors.json")
	if err != nil {
		return nil, err
	}
	var vectors []quic1RTTVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		return nil, err
	}
	if len(vectors) == 0 {
		return nil, errors.New("missing QUIC vectors")
	}
	return vectors, nil
}

func (v quic1RTTVector) decoder() (*QUIC1RTTDecoder, error) {
	log, err := ParseTLSKeyLog([]byte(v.KeyLog))
	if err != nil {
		return nil, err
	}
	for _, entry := range log.Entries {
		secret := entry.ClientTrafficSecret0
		if len(secret) == 0 {
			secret = entry.ServerTrafficSecret0
		}
		return NewQUIC1RTTDecoder(v.Version, v.CipherSuite, secret)
	}
	return nil, errors.New("missing QUIC traffic secret")
}

func TestQUIC1RTTDecoder(t *testing.T) {
	vectors, err := readQUIC1RTTVectors()
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			decoder, err := v.decoder()
			if err != nil {
				t.Fatal(err)
			}
			wire := bytes.Clone(v.Packet)
			number, payload, err := decoder.Open(v.Packet, v.DestinationCID, v.ExpectedNumber)
			if v.InvalidHeader {
				if number != 0 || payload != nil || !errors.Is(err, ErrInvalidQUIC) {
					t.Fatalf("invalid header returned %d, %x, %v", number, payload, err)
				}
				return
			}
			if err != nil || number != v.PacketNumber || !bytes.Equal(payload, v.Plaintext) {
				t.Fatalf("Open returned %d, %x, %v", number, payload, err)
			}
			_, again, err := decoder.Open(v.Packet, v.DestinationCID, v.ExpectedNumber)
			if err != nil {
				t.Fatal(err)
			}
			payload[0] ^= 0xff
			if !bytes.Equal(v.Packet, wire) || !bytes.Equal(again, v.Plaintext) {
				t.Fatal("wire input or another result changed")
			}
		})
	}
}

func TestQUIC1RTTRejectsBadContext(t *testing.T) {
	vectors, err := readQUIC1RTTVectors()
	if err != nil {
		t.Fatal(err)
	}
	v := vectors[0]
	decoder, err := v.decoder()
	if err != nil {
		t.Fatal(err)
	}
	badTag := bytes.Clone(v.Packet)
	badTag[len(badTag)-1] ^= 1
	longHeader := bytes.Clone(v.Packet)
	longHeader[0] |= 0x80
	wrongCID := bytes.Clone(v.DestinationCID)
	wrongCID[0] ^= 1
	for _, tc := range []struct {
		name     string
		decoder  *QUIC1RTTDecoder
		packet   []byte
		cid      []byte
		expected uint64
		want     error
	}{
		{"oversize", decoder, make([]byte, maxQUICUDPPayloadBytes+1), v.DestinationCID, 0, ErrQUICLimit},
		{"short sample", decoder, v.Packet[:1+len(v.DestinationCID)+19], v.DestinationCID, 0, ErrInvalidQUIC},
		{"empty packet", decoder, nil, v.DestinationCID, 0, ErrInvalidQUIC},
		{"long header", decoder, longHeader, v.DestinationCID, 0, ErrInvalidQUIC},
		{"wrong cid", decoder, v.Packet, wrongCID, 0, ErrInvalidQUIC},
		{"large cid", decoder, v.Packet, make([]byte, MaxQUICConnIDBytes+1), 0, ErrInvalidQUIC},
		{"bad tag", decoder, badTag, v.DestinationCID, v.ExpectedNumber, ErrInvalidQUIC},
		{"distant packet number", decoder, v.Packet, v.DestinationCID, 1 << 20, ErrInvalidQUIC},
		{"overflowing packet number", decoder, v.Packet, v.DestinationCID, quicPacketNumberLimit + 1, ErrInvalidQUIC},
		{"uninitialized decoder", &QUIC1RTTDecoder{}, v.Packet, v.DestinationCID, 0, ErrInvalidQUIC},
	} {
		t.Run(tc.name, func(t *testing.T) {
			number, payload, err := tc.decoder.Open(tc.packet, tc.cid, tc.expected)
			if number != 0 || payload != nil || !errors.Is(err, tc.want) {
				t.Fatalf("Open returned %d, %x, %v, want %v", number, payload, err, tc.want)
			}
		})
	}

	for _, tc := range []struct {
		version   uint32
		suite     uint16
		secretLen int
	}{
		{QUICVersionNegotiation, TLS_AES_128_GCM_SHA256, 32},
		{QUICVersion1, tls.TLS_CHACHA20_POLY1305_SHA256, 32},
		{QUICVersion1, TLS_AES_128_GCM_SHA256, 31},
		{QUICVersion2, TLS_AES_256_GCM_SHA384, 32},
	} {
		if decoder, err := NewQUIC1RTTDecoder(tc.version, tc.suite, make([]byte, tc.secretLen)); decoder != nil || !errors.Is(err, ErrInvalidQUIC) {
			t.Fatalf("NewQUIC1RTTDecoder(%#x, %#x, %d bytes) returned %v, %v", tc.version, tc.suite, tc.secretLen, decoder, err)
		}
	}
	wrongSecret, err := NewQUIC1RTTDecoder(v.Version, v.CipherSuite, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if number, payload, err := wrongSecret.Open(v.Packet, v.DestinationCID, v.ExpectedNumber); number != 0 || payload != nil || !errors.Is(err, ErrInvalidQUIC) {
		t.Fatalf("wrong secret returned %d, %x, %v", number, payload, err)
	}
}

func TestQUIC1RTTPacketNumberWindow(t *testing.T) {
	for _, tc := range []struct {
		truncated uint64
		expected  uint64
		length    int
		want      uint64
	}{
		{0, 128, 1, 256},   // The earlier tie moves forward.
		{128, 256, 1, 384}, // The later tie stays in the window.
		{255, 256, 1, 255}, // A reordered packet crosses the window boundary.
		{255, 0, 1, 255},   // Reconstruction cannot subtract below zero.
		{42, 1<<24 | 40, 3, 1<<24 | 42},
	} {
		if got := decodeQUICPacketNumber(tc.truncated, tc.expected, tc.length); got != tc.want {
			t.Errorf("packet number %d near %d = %d, want %d", tc.truncated, tc.expected, got, tc.want)
		}
	}
}

func FuzzQUIC1RTTOpen(f *testing.F) {
	vectors, err := readQUIC1RTTVectors()
	if err != nil {
		f.Fatal(err)
	}
	decoder, err := vectors[0].decoder()
	if err != nil {
		f.Fatal(err)
	}
	for _, v := range vectors {
		f.Add(v.Packet, v.DestinationCID, v.ExpectedNumber)
	}
	f.Fuzz(func(t *testing.T, packet, dcid []byte, expected uint64) {
		number, payload, err := decoder.Open(packet, dcid, expected)
		if err != nil && (number != 0 || payload != nil) {
			t.Fatal("Open returned partial data on error")
		}
	})
}

func BenchmarkQUIC1RTTOpen(b *testing.B) {
	vectors, err := readQUIC1RTTVectors()
	if err != nil {
		b.Fatal(err)
	}
	v := vectors[0]
	decoder, err := v.decoder()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(v.Packet)))
	for b.Loop() {
		if _, _, err := decoder.Open(v.Packet, v.DestinationCID, v.ExpectedNumber); err != nil {
			b.Fatal(err)
		}
	}
}

func ExampleQUIC1RTTDecoder_Open() {
	vectors, err := readQUIC1RTTVectors()
	if err != nil {
		panic(err)
	}
	v := vectors[0]
	decoder, err := v.decoder()
	if err != nil {
		panic(err)
	}
	number, frames, err := decoder.Open(v.Packet, v.DestinationCID, v.ExpectedNumber)
	if err != nil {
		panic(err)
	}
	fmt.Printf("packet %d with %d authenticated frame bytes\n", number, len(frames))
	// Output:
	// packet 5 with 28 authenticated frame bytes
}
