package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"testing"
)

func TestDNSOverTLSCaptureParity(t *testing.T) {
	clientIP := [4]byte{192, 0, 2, 1}
	serverIP := [4]byte{192, 0, 2, 2}
	const clientPort = 53000
	const serverPort = 853
	clientKey := bytes.Repeat([]byte{0xaa}, 32)
	serverKey := bytes.Repeat([]byte{0xbb}, 32)
	random := bytes.Repeat([]byte{0x42}, 32)
	keys := fmt.Appendf(nil, "CLIENT_TRAFFIC_SECRET_0 %x %x\nSERVER_TRAFFIC_SECRET_0 %x %x\n", random, clientKey, random, serverKey)
	wrongKey := bytes.Repeat([]byte{0xcc}, 32)
	wrongKeys := fmt.Appendf(nil, "CLIENT_TRAFFIC_SECRET_0 %x %x\nSERVER_TRAFFIC_SECRET_0 %x %x\n", random, wrongKey, random, wrongKey)

	framed := func(wire []byte) []byte {
		return append(binary.BigEndian.AppendUint16(nil, uint16(len(wire))), wire...)
	}
	query := []byte(dohTestQuery)
	nextQuery := bytes.Clone(query)
	binary.BigEndian.PutUint16(nextQuery, 0x4567)
	requests := append(framed(query), framed(nextQuery)...)
	serverReply := framed(buildDNSQueryResponsePacket())
	// One TLS record has just the first prefix byte. The next contains
	// the remaining prefix byte, first message and a second complete message.
	client := append(buildTLS13ClientHelloRecord("resolver.example", "dot"),
		encryptTLS13AppDataRecord(t, clientKey, TLS_AES_128_GCM_SHA256, 0, TLSRecordApplicationData, requests[:1])...)
	client = append(client, encryptTLS13AppDataRecord(t, clientKey, TLS_AES_128_GCM_SHA256, 1, TLSRecordApplicationData, requests[1:])...)
	server := testKeyShareHello(true, [32]byte{1}, testTLSExtension(TLSExtSupportedVersions, []byte{3, 4}))
	server = append(server, encryptTLS13AppDataRecord(t, serverKey, TLS_AES_128_GCM_SHA256, 0, TLSRecordApplicationData, serverReply)...)

	// Both flows carry the same authentic ciphertext, so the unrelated flow
	// checks port selection as well as preservation of capture flow indices.
	frames := [][]byte{
		buildEthernetIPv4TCPFrame(clientIP, serverIP, clientPort, 443, 1, 0, TCPFlagACK, client),
		buildEthernetIPv4TCPFrame(serverIP, clientIP, 443, clientPort, 1, 0, TCPFlagACK, server),
		buildEthernetIPv4TCPFrame(clientIP, serverIP, clientPort, serverPort, 1, 0, TCPFlagACK, client),
		buildEthernetIPv4TCPFrame(serverIP, clientIP, serverPort, clientPort, 1, 0, TCPFlagACK, server),
	}
	// Verify that both readers preserve complete messages before broken DNS
	// framing, while a known TCP gap makes the whole affected direction unusable.
	for _, tc := range []struct {
		name         string
		tail         []byte
		gap          uint32
		wantRequests int
	}{
		{"incomplete final message", []byte{0, 20, 1, 2, 3}, 0, 2},
		{"undersized message before another query", append([]byte{0, 1, 0}, framed(query)...), 0, 2},
		{"gap in client direction", framed(query), 1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := encryptTLS13AppDataRecord(t, clientKey, TLS_AES_128_GCM_SHA256, 2, TLSRecordApplicationData, tc.tail)
			tail := buildEthernetIPv4TCPFrame(clientIP, serverIP, clientPort, serverPort, 1+uint32(len(client))+tc.gap, 0, TCPFlagACK, app)
			raw := buildPCAPNGFixture(binary.LittleEndian, keys, append(frames, tail))
			rows := dotCaptureParity(t, raw, nil)
			if len(rows) != tc.wantRequests+1 {
				t.Fatalf("got %d messages, want %d requests and one response", len(rows), tc.wantRequests)
			}
			for i, row := range rows {
				if row.Message.IsResponse != (i == tc.wantRequests) || row.FlowIndex != 1 {
					t.Fatalf("unexpected direction or flow at row %d: %+v", i, row)
				}
			}
		})
	}
	t.Run("reader failure in last flow", func(t *testing.T) {
		raw := buildPCAPNGFixture(binary.LittleEndian, keys, frames)
		source := bytes.NewReader(raw)
		c, err := NewFromReaderAt(source, source.Size())
		if err != nil {
			t.Fatal(err)
		}
		off := bytes.LastIndex(raw, server)
		if off < 0 {
			t.Fatal("missing TLS server bytes")
		}
		failAt := int64(off + len(server) - 1)
		injected := errors.New("unavailable server ciphertext")
		rows, err := c.DNSOverTLSFromReaderAt(readAtFunc(func(p []byte, off int64) (int, error) {
			if off <= failAt && failAt-off < int64(len(p)) {
				return 0, injected
			}
			return source.ReadAt(p, off)
		}), nil)
		if rows != nil || !errors.Is(err, injected) {
			t.Fatalf("got %d records and %v, want nil and injected error", len(rows), err)
		}
	})
	for _, tc := range []struct {
		name               string
		embedded, external []byte
		want               int
	}{
		{"embedded keys", keys, nil, 3},
		{"external keys", nil, keys, 3},
		{"missing keys", nil, nil, 0},
		{"wrong keys", nil, wrongKeys, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := buildPCAPNGFixture(binary.LittleEndian, tc.embedded, frames)
			rows := dotCaptureParity(t, raw, tc.external)
			if len(rows) != tc.want {
				t.Fatalf("got %d DNS records, want %d", len(rows), tc.want)
			}
			for i, row := range rows {
				src, dst := netip.AddrFrom4(clientIP), netip.AddrFrom4(serverIP)
				sp, dp := uint16(clientPort), uint16(serverPort)
				id := uint16(0x1337)
				if i == 1 {
					id = 0x4567
				}
				reply := i == 2
				if reply {
					src, dst = dst, src
					sp, dp = dp, sp
				}
				if row.FlowIndex != 1 || row.SrcAddr != src || row.DstAddr != dst || row.SrcPort != sp || row.DstPort != dp ||
					row.Message.IsResponse != reply || row.Message.TransactionID != id || len(row.Message.Questions) != 1 ||
					row.Message.Questions[0].Name != "c2.example.com" {
					t.Fatalf("record %d = %+v", i, row)
				}
				if reply && (len(row.Message.Answers) != 2 || row.Message.Answers[1].Address != netip.MustParseAddr("203.0.113.42")) {
					t.Fatalf("response answers = %+v", row.Message.Answers)
				}
			}
		})
	}
}

func dotCaptureParity(t *testing.T, raw, keys []byte) []DNSOverTLSRecord {
	t.Helper()
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	source := bytes.NewReader(raw)
	index, err := NewFromReaderAt(source, source.Size())
	if err != nil {
		t.Fatal(err)
	}
	return checkReaderParity(t, raw,
		func(data []byte) ([]DNSOverTLSRecord, error) { return c.DNSOverTLS(data, keys) },
		func(r io.ReaderAt) ([]DNSOverTLSRecord, error) { return index.DNSOverTLSFromReaderAt(r, keys) })
}
