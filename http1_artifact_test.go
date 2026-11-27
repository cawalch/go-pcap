package pcap

import (
	"bytes"
	"fmt"
	"os"
	"reflect"
	"slices"
	"testing"
)

func TestHTTP1ResponseArtifactCoverage(t *testing.T) {
	const entity = "report alpha\n"
	const full = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\n" + entity
	gzip := compressHTTPTestBody(t, "gzip", []byte(entity))
	chunkedGzip := fmt.Sprintf("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n%x\r\n%s\r\n0\r\n\r\n", len(gzip), gzip)
	oversized := bytes.Repeat([]byte{'x'}, MaxHTTPBodyBytes+1)
	compressed := compressHTTPTestBody(t, "gzip", oversized)
	decodedLimit := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nContent-Encoding: gzip\r\n\r\n%s", len(compressed), compressed)
	for _, tc := range []struct {
		name, request, response, body string
		state                         HTTPBodyState
		coverage                      HTTP1ArtifactCoverage
	}{
		{"content length", txGET, full, entity, HTTPBodyComplete, HTTP1ArtifactComplete},
		{"chunked gzip", txGET, chunkedGzip, entity, HTTPBodyComplete, HTTP1ArtifactComplete},
		{"empty entity", txGET, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", "", HTTPBodyComplete, HTTP1ArtifactComplete},
		{"missing response", txGET, "", "", HTTPBodyUnknown, HTTP1ArtifactUnavailable},
		{"clipped entity", txGET, full[:len(full)-6], "report ", HTTPBodyPartial, HTTP1ArtifactPartial},
		{"no retained prefix", txGET, full[:len(full)-len(entity)], "", HTTPBodyPartial, HTTP1ArtifactUnavailable},
		{"decoded limit", txGET, decodedLimit, string(oversized[:MaxHTTPBodyBytes]), HTTPBodyPartial, HTTP1ArtifactPartial},
		{"unsupported coding", txGET, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Encoding: br\r\n\r\nabc", "", HTTPBodyUnsupported, HTTP1ArtifactUnavailable},
		{"invalid chunk", txGET, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nG\r\nabc\r\n", "", HTTPBodyUnknown, HTTP1ArtifactUnavailable},
		{"range", txGET, "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 7-12/13\r\nContent-Length: 6\r\n\r\nalpha\n", "alpha\n", HTTPBodyComplete, HTTP1ArtifactPartial},
		{"206 alone", txGET, "HTTP/1.1 206 Partial Content\r\nContent-Length: 6\r\n\r\nalpha\n", "alpha\n", HTTPBodyComplete, HTTP1ArtifactPartial},
		{"range marker on 200", txGET, "HTTP/1.1 200 OK\r\ncontent-range: bytes 7-12/13\r\nContent-Length: 6\r\n\r\nalpha\n", "alpha\n", HTTPBodyComplete, HTTP1ArtifactPartial},
		{"HEAD", "HEAD / HTTP/1.1\r\n\r\n", full[:len(full)-len(entity)], "", HTTPBodyComplete, HTTP1ArtifactUnavailable},
		{"CONNECT", "CONNECT trace.example:443 HTTP/1.1\r\n\r\n", "HTTP/1.1 200 Connection Established\r\n\r\ntunnel", "", HTTPBodyComplete, HTTP1ArtifactUnavailable},
		{"switching protocols", txGET, "HTTP/1.1 101 Switching Protocols\r\n\r\nprotocol bytes", "", HTTPBodyComplete, HTTP1ArtifactUnavailable},
		{"no content", txGET, "HTTP/1.1 204 No Content\r\n\r\n", "", HTTPBodyComplete, HTTP1ArtifactUnavailable},
		{"reset content", txGET, "HTTP/1.1 205 Reset Content\r\nContent-Length: 0\r\n\r\n", "", HTTPBodyComplete, HTTP1ArtifactUnavailable},
		{"not modified", txGET, "HTTP/1.1 304 Not Modified\r\nContent-Length: 13\r\n\r\n", "", HTTPBodyComplete, HTTP1ArtifactUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frames := append(txOpening(), txFrame(false, 101, 201, TCPFlagACK, tc.request))
			wantPackets, wantResponse, wantOffset := []int{2}, -1, -1
			if tc.response != "" {
				frames = append(frames, txFrame(true, 201, 101+uint32(len(tc.request)), TCPFlagACK, tc.response))
				wantPackets, wantResponse, wantOffset = []int{2, 3}, 3, 0
			}
			rows, _, _ := txScan(t, frames)
			if len(rows) != 1 {
				t.Fatalf("transactions = %d", len(rows))
			}
			a := rows[0].ResponseArtifact()
			if a.Coverage != tc.coverage || a.BodyState != tc.state || !bytes.Equal(a.Body, []byte(tc.body)) {
				t.Fatalf("coverage = %v, body state = %v, bytes = %d", a.Coverage, a.BodyState, len(a.Body))
			}
			if a.ID != (HTTP1TransactionID{PacketIndex: 2}) || a.ResponsePacketIndex != wantResponse ||
				a.ResponsePacketPayloadOffset != wantOffset || !slices.Equal(a.ExchangePacketIndices, wantPackets) {
				t.Fatalf("transaction = %v, response packet = %d:%d, exchange packets = %v", a.ID, a.ResponsePacketIndex, a.ResponsePacketPayloadOffset, a.ExchangePacketIndices)
			}
			if len(a.Body) != 0 && &a.Body[0] != &rows[0].Response.Body[0] || &a.ExchangePacketIndices[0] != &rows[0].PacketIndices[0] {
				t.Fatal("artifact does not share the transaction slices")
			}
		})
	}
}

func TestHTTP1ResponseArtifactOriginalPackets(t *testing.T) {
	raw, err := os.ReadFile("testdata/deployments/http1-transactions.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	capture, packets := readWrittenPackets(t, raw)
	frames := make([][]byte, 0, len(packets)+1)
	for _, packet := range packets {
		frame, err := capture.PacketPayload(raw, packet)
		if err != nil {
			t.Fatal(err)
		}
		frames = append(frames, frame)
		if packet.Index == 9 {
			// Retransmit the final response start before its shared continuation.
			frames = append(frames, frame)
		}
	}
	rows, raw, capture := txScan(t, frames)
	if len(rows) != 5 {
		t.Fatalf("transactions = %d", len(rows))
	}
	const entity = "upload accepted\n" // Standalone bytes compressed by the fixture generator.
	want := HTTP1ResponseArtifact{
		ID: HTTP1TransactionID{PacketIndex: 4}, Coverage: HTTP1ArtifactComplete,
		BodyState: HTTPBodyComplete, Body: []byte(entity), ResponsePacketIndex: 9,
		ExchangePacketIndices: []int{4, 5, 6, 7, 9, 11}, SharedPackets: true,
	}
	if a := rows[0].ResponseArtifact(); !reflect.DeepEqual(a, want) {
		t.Fatalf("upload artifact = %+v, want %+v", a, want)
	}
	shared := rows[1].ResponseArtifact()
	if shared.ID != (HTTP1TransactionID{PacketIndex: 7, PacketPayloadOffset: 4}) ||
		shared.Coverage != HTTP1ArtifactUnavailable || shared.BodyState != HTTPBodyComplete || len(shared.Body) != 0 ||
		shared.ResponsePacketIndex != 11 || shared.ResponsePacketPayloadOffset != 28 ||
		!shared.SharedPackets || !slices.Equal(shared.ExchangePacketIndices, []int{7, 11}) {
		t.Fatalf("pipelined artifact = %+v", shared)
	}

	view, err := capture.SelectTenant(TenantScope{})
	if err != nil {
		t.Fatal(err)
	}
	scoped := checkReaderParity(t, raw, view.HTTP1Transactions, view.HTTP1TransactionsFromReaderAt)
	if len(scoped) != len(rows) {
		t.Fatalf("tenant transactions = %d", len(scoped))
	}
	for i, tx := range scoped {
		if a := tx.ResponseArtifact(); !reflect.DeepEqual(a, rows[i].ResponseArtifact()) {
			t.Fatalf("tenant artifact %d = %+v, want %+v", i, a, rows[i].ResponseArtifact())
		}
	}
}
