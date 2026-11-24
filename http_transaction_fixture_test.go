package pcap

import (
	"bytes"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"testing"
)

func TestHTTP1TransactionCapture(t *testing.T) {
	const path = "testdata/deployments/http1-transactions.pcapng"
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	capture, packets := readWrittenPackets(t, raw)
	reader, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	index, err := NewFromReaderAt(reader, int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := capture.HTTP1Transactions(raw)
	if err != nil {
		t.Fatal(err)
	}
	other, err := index.HTTP1TransactionsFromReaderAt(reader)
	if err != nil || !reflect.DeepEqual(rows, other) {
		t.Fatalf("ReaderAt = %+v, %v; slice = %+v", other, err, rows)
	}

	// TShark frame numbers are one-based. The packet indices below identify
	// the original zero-based frames, including positions within shared packets.
	cases := []struct {
		target, method, requestBody, responseBody string
		request, requestOffset                    int
		status, response, responseOffset          int
		pairing                                   HTTP1Pairing
		shared                                    bool
		evidence, exported                        []int
	}{
		{
			target: "/upload", method: "POST", requestBody: "data", responseBody: "upload accepted\n",
			request: 4, status: 200, response: 9, pairing: HTTP1ResponseConfirmed, shared: true,
			evidence: []int{4, 5, 6, 7, 9, 10}, exported: []int{1, 2, 4, 5, 6, 7, 9, 10},
		},
		{
			target: "/pipelined", method: "GET", request: 7, requestOffset: 4,
			status: 204, response: 10, responseOffset: 28, pairing: HTTP1ResponseConfirmed, shared: true,
			evidence: []int{7, 10}, exported: []int{1, 2, 4, 5, 6, 7, 9, 10},
		},
		{
			target: "/reused", method: "GET", request: 15, status: 200, response: 16,
			responseBody: "reused", pairing: HTTP1ResponseConfirmed,
			evidence: []int{15, 16}, exported: []int{12, 13, 15, 16},
		},
		{
			target: "/missing", method: "GET", request: 17, pairing: HTTP1ResponseAmbiguous,
			evidence: []int{17}, exported: []int{17},
		},
		{
			target: "/after-gap", method: "GET", request: 18, pairing: HTTP1ResponseAmbiguous,
			evidence: []int{18}, exported: []int{18},
		},
	}
	if len(rows) != len(cases) {
		t.Fatalf("transactions = %+v", rows)
	}
	for i, tc := range cases {
		t.Run(tc.target[1:], func(t *testing.T) {
			row := rows[i]
			req := row.Request
			if req.Target != tc.target || req.Method != tc.method || req.Version != "1.1" || req.Authority != "trace.example" ||
				req.PacketIndex != tc.request || req.PacketPayloadOffset != tc.requestOffset ||
				req.TimestampNs != packets[tc.request].TimestampNs || req.FlowIndex != 1 ||
				req.Source != netip.MustParseAddrPort("192.0.2.14:50000") ||
				req.Destination != netip.MustParseAddrPort("198.51.100.80:80") ||
				req.BodyState != HTTPBodyComplete || string(req.Body) != tc.requestBody {
				t.Fatalf("request = %+v", req)
			}
			if row.Pairing != tc.pairing || row.SharedPackets != tc.shared || !slices.Equal(row.PacketIndices, tc.evidence) {
				t.Fatalf("pairing = %v, shared = %t, packet indices = %v", row.Pairing, row.SharedPackets, row.PacketIndices)
			}
			resp := row.Response
			if tc.pairing == HTTP1ResponseConfirmed {
				if resp == nil || resp.PacketIndex != tc.response || resp.PacketPayloadOffset != tc.responseOffset ||
					resp.TimestampNs != packets[tc.response].TimestampNs || resp.Version != "1.1" ||
					resp.StatusCode != tc.status || resp.BodyState != HTTPBodyComplete || string(resp.Body) != tc.responseBody {
					t.Fatalf("response = %+v", resp)
				}
			} else if resp != nil {
				t.Fatalf("ambiguous request has response %+v", resp)
			}

			var out, readerOut bytes.Buffer
			if err := capture.ExtractHTTP1TransactionPCAPNG(raw, &out, row.ID()); err != nil {
				t.Fatal(err)
			}
			if err := index.ExtractHTTP1TransactionPCAPNGFromReaderAt(reader, &readerOut, row.ID()); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(out.Bytes(), readerOut.Bytes()) {
				t.Fatal("slice and ReaderAt exports differ")
			}
			carved, selected := readWrittenPackets(t, out.Bytes())
			if len(selected) != len(tc.exported) || len(carved.Interfaces) != 1 {
				t.Fatalf("export has %d packets on %d interfaces, want %d on 1", len(selected), len(carved.Interfaces), len(tc.exported))
			}
			for j, packetIndex := range tc.exported {
				want, got := packets[packetIndex], selected[j]
				original, err := capture.PacketPayload(raw, want)
				if err != nil {
					t.Fatal(err)
				}
				copied, err := carved.PacketPayload(out.Bytes(), got)
				if err != nil {
					t.Fatal(err)
				}
				if want.InterfaceID != 1 {
					t.Fatalf("unexpected original interface for packet %d: %d", packetIndex, want.InterfaceID)
				}
				want.Index, want.InterfaceID, want.PayloadOffset = j, 0, got.PayloadOffset
				if got != want || !bytes.Equal(original, copied) {
					t.Fatalf("packet %d = %+v, want %+v with original bytes", j, got, want)
				}
			}
			if bytes.Contains(out.Bytes(), []byte("request start")) {
				t.Fatal("export includes the source packet comment")
			}

			reopened, err := carved.HTTP1Transactions(out.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			localRequest := slices.Index(tc.exported, tc.request)
			match := slices.IndexFunc(reopened, func(r HTTP1Transaction) bool {
				return r.Request.PacketIndex == localRequest && r.Request.PacketPayloadOffset == tc.requestOffset
			})
			if match < 0 || reopened[match].Request.Target != tc.target || string(reopened[match].Request.Body) != tc.requestBody {
				t.Fatalf("reopened transactions = %+v", reopened)
			}
			reconstructed := reopened[match].Response
			if resp != nil {
				if reopened[match].Pairing != HTTP1ResponseConfirmed || reconstructed == nil ||
					reconstructed.PacketIndex != slices.Index(tc.exported, tc.response) ||
					reconstructed.PacketPayloadOffset != tc.responseOffset || reconstructed.StatusCode != tc.status ||
					reconstructed.BodyState != resp.BodyState || !bytes.Equal(reconstructed.Body, resp.Body) {
					t.Fatalf("response after reopening = %+v", reconstructed)
				}
			} else if reconstructed != nil {
				t.Fatalf("request-only export reopened with response %+v", reconstructed)
			}
		})
	}
}
