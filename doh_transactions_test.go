package pcap

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"slices"
	"testing"
)

func TestDNSOverHTTPSTransactionsEndpointFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/doh-exchanges.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := os.ReadFile("testdata/doh-exchanges.keys")
	if err != nil {
		t.Fatal(err)
	}
	capture, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	rows := checkReaderParity(t, raw,
		func(b []byte) ([]DoHTransaction, error) { return capture.DoHTransactions(b, keys) },
		func(r io.ReaderAt) ([]DoHTransaction, error) { return capture.DoHTransactionsFromReaderAt(r, keys) })
	if len(rows) != 8 {
		t.Fatalf("got %d DoH exchanges, want 8", len(rows))
	}
	for i, row := range rows {
		j := i % 4
		transport, stream, query, reply := DoHHTTP2, uint64(j*2+1), 10+j, 19-j
		if i >= 4 {
			transport, stream, query, reply = DoHHTTP3, uint64(j*4), 29+j, 38-j
		}
		name := []string{"one.example", "two.example", "error.example", "partial.example"}[j]
		status := []int{200, 200, 503, 200}[j]
		state := []DoHMessageState{DoHComplete, DoHComplete, DoHNoDNSResponse, DoHIncomplete}[j]
		if row.Transport != transport || row.StreamID != stream || row.StatusCode != status ||
			row.Query.State != DoHComplete || row.Query.DNS == nil || row.Query.DNS.IsResponse ||
			len(row.Query.DNS.Questions) != 1 || row.Query.DNS.Questions[0].Name != name ||
			!slices.Equal(row.Query.PacketIndices, []int{query}) ||
			row.Reply.State != state || !slices.Equal(row.Reply.PacketIndices, []int{reply}) {
			t.Fatalf("row %d = %+v", i, row)
		}
		if transport == DoHHTTP2 {
			if row.ConnectionIndex != -1 || row.HTTP2ID.StreamID != uint32(stream) || row.HTTP2ID.OpeningPacket != 0 ||
				len(row.Query.TLSRecords) == 0 || len(row.Reply.TLSRecords) == 0 || len(row.ALPNPacketIndices) != 0 {
				t.Fatalf("HTTP/2 provenance: %+v", row)
			}
		} else if row.ConnectionIndex != 0 || len(row.ALPNPacketIndices) == 0 ||
			len(row.Query.TLSRecords) != 0 || len(row.Reply.TLSRecords) != 0 {
			t.Fatalf("HTTP/3 provenance: %+v", row)
		}
		if row.Query.DNS.TransactionID != 0 {
			t.Fatalf("query DNS ID = %d", row.Query.DNS.TransactionID)
		}
		if j < 2 {
			dns := row.Reply.DNS
			if dns == nil || !dns.IsResponse || dns.TransactionID != 0 ||
				len(dns.Questions) != 1 || dns.Questions[0].Name != name ||
				len(dns.Answers) != 1 || dns.Answers[0].Address.String() != []string{"192.0.2.10", "192.0.2.11"}[j] {
				t.Fatalf("row %d picked an unrelated answer: %+v", i, dns)
			}
		} else if row.Reply.DNS != nil {
			t.Fatalf("row %d unexpectedly has a DNS answer: %+v", i, row.Reply)
		}
	}
	if len(rows[5].Query.QPACKPacketIndices) == 0 {
		t.Fatal("HTTP/3 POST lost the QPACK context")
	}
	if observed, err := capture.DoHTransactions(raw, nil); err != nil || len(observed) != 0 {
		t.Fatalf("keyless scan: %d rows, %v", len(observed), err)
	}
	// Result packet indexes must survive mutation of another call's result.
	rows[0].Query.PacketIndices[0] = -1
	rows[0].Query.TLSRecords[0].PacketIndices[0] = -1
	again, err := capture.DoHTransactions(raw, keys)
	if err != nil || len(again) == 0 || len(again[0].Query.TLSRecords) == 0 ||
		!slices.Equal(again[0].Query.PacketIndices, []int{10}) ||
		!slices.Equal(again[0].Query.TLSRecords[0].PacketIndices, []int{10}) {
		t.Fatalf("new call did not recover its own packet evidence: %d rows, %v", len(again), err)
	}
}

func TestDNSOverHTTPSMessageCoverage(t *testing.T) {
	const media = "application/dns-message"
	get := HTTP2HeaderBlock{Method: "GET", Path: "/?dns=" + base64.RawURLEncoding.EncodeToString([]byte(dohTestQuery))}
	post := HTTP2HeaderBlock{Method: "POST", Headers: []HTTPHeader{{"content-type", media}}}
	reply := HTTP2HeaderBlock{Status: "200", Headers: []HTTPHeader{{"content-type", media}}}
	for _, tc := range []struct {
		name    string
		headers HTTP2HeaderBlock
		body    []byte
		state   HTTPBodyState
		capped  bool
		invalid bool
		want    DoHMessageState
	}{
		{"GET headers are enough", get, nil, HTTPBodyPartial, false, false, DoHComplete},
		{"incomplete POST cannot decode a whole-looking prefix", post, []byte(dohTestQuery), HTTPBodyPartial, false, false, DoHIncomplete},
		{"invalid POST body", post, nil, HTTPBodyUnknown, false, false, DoHMalformed},
		{"POST cap", post, []byte(dohTestQuery), HTTPBodyPartial, true, false, DoHLimited},
		{"invalid HTTP framing", get, nil, HTTPBodyUnknown, false, true, DoHMalformed},
		{"reply direction mismatch", reply, []byte(dohTestQuery), HTTPBodyComplete, false, false, DoHMalformed},
		{"oversize DNS payload", post, make([]byte, 1<<16), HTTPBodyComplete, false, false, DoHLimited},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := dohBudget{bytes: MaxTotalStreamBytes, entries: maxDoHDNSEntriesPerScan}
			got, match, err := b.message(tc.headers, tc.body, tc.state, tc.capped, tc.invalid)
			if err != nil || !match || got.State != tc.want || (got.DNS != nil) != (tc.want == DoHComplete) {
				t.Fatalf("message %+v, match %t, error %v, want state %v", got, match, err, tc.want)
			}
		})
	}
	for _, b := range []dohBudget{
		{bytes: MaxTotalStreamBytes, entries: 0},
		{bytes: len(dohTestQuery) - 1, entries: maxDoHDNSEntriesPerScan},
	} {
		if _, _, err := b.message(post, []byte(dohTestQuery), HTTPBodyComplete, false, false); !errors.Is(err, ErrDNSLimit) {
			t.Fatalf("aggregate DoH budget: %v", err)
		}
	}
}

func TestDNSOverHTTPSUnavailableHTTP3Headers(t *testing.T) {
	b := dohBudget{bytes: MaxTotalStreamBytes, entries: maxDoHDNSEntriesPerScan}
	request := &HTTP3MessageEvidence{
		Sections: []HTTP3SectionEvidence{{QPACKFieldSection: QPACKFieldSection{State: QPACKBlocked}}},
	}
	tx := KeyedHTTP3Transaction{Request: request, Response: &HTTP3MessageEvidence{}}
	if _, match, err := dohFromHTTP3(&tx, &b); match || err != nil {
		t.Fatalf("blocked request headers: match %t, error %v", match, err)
	}
	request.Sections = []HTTP3SectionEvidence{{Kind: HTTP3InitialSection, QPACKFieldSection: QPACKFieldSection{
		State: QPACKDecoded, Headers: []HTTPHeader{{":method", "GET"}, {":scheme", "https"},
			{":path", "/?dns=" + base64.RawURLEncoding.EncodeToString([]byte(dohTestQuery))}},
	}}}
	tx.Response.Sections = []HTTP3SectionEvidence{{QPACKFieldSection: QPACKFieldSection{State: QPACKBlocked}}}
	tx.Response.PacketIndices = []int{3}
	row, match, err := dohFromHTTP3(&tx, &b)
	if !match || err != nil || row.Query.State != DoHComplete || row.Reply.State != DoHUnseen ||
		!slices.Equal(row.Reply.PacketIndices, []int{3}) || row.Reply.DNS != nil {
		t.Fatalf("blocked response: row %+v, match %t, error %v", row, match, err)
	}
}

func TestDNSOverHTTPSMissingQUICHandshakeKeys(t *testing.T) {
	raw, err := os.ReadFile("testdata/doh-exchanges.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := os.ReadFile("testdata/doh-exchanges.keys")
	if err != nil {
		t.Fatal(err)
	}
	var applicationKeys []byte
	for line := range bytes.Lines(keys) {
		if bytes.HasPrefix(line, []byte("CLIENT_TRAFFIC_SECRET_0 ")) ||
			bytes.HasPrefix(line, []byte("SERVER_TRAFFIC_SECRET_0 ")) {
			applicationKeys = append(applicationKeys, line...)
		}
	}
	capture, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := capture.DoHTransactions(raw, applicationKeys)
	if err != nil || slices.ContainsFunc(rows, func(row DoHTransaction) bool { return row.Transport == DoHHTTP3 }) {
		t.Fatalf("QUIC DoH without authenticated ALPN: %d rows, %v", len(rows), err)
	}
}
