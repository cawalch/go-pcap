package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestHTTP1RequestEvidencePacketIdentity(t *testing.T) {
	client, server := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	packet := func(seq uint32, payload string) []byte {
		return buildEthernetIPv4TCPFrame(client, server, 53000, 80, seq, 1, TCPFlagACK, []byte(payload))
	}
	const (
		first  = "POST http://Api.Example:80/a%2Fb?Key=x HTTP/1.1\r\nhOSt:\t wrong.example \t\r\nX-Test: first\r\nx-test:\tsecond \r\n \tfolded\r\nContent-Length: 4\r\n\r\nDATA"
		second = "GET /two HTTP/1.1\r\nHost: Api.Example \t\r\nHost: other\r\n\r\n"
		third  = "GET /three HTTP/1.1\r\n\r\n"
		fourth = "GET /four HTTP/1.1\r\nContent-Length: 0\r\n\r\n"
	)
	split := len(first) - 2
	raw := buildPCAPNGFixture(binary.LittleEndian, nil, [][]byte{
		packet(100+uint32(split), first[split:]+second),
		packet(100, first[:split]+"xx"+second+third+fourth), // conflicting overlap, then more requests
		packet(100+uint32(split), first[split:]+second),     // retransmission
		packet(101+uint32(len(first+second+third+fourth)), "GET /past-gap HTTP/1.1\r\n\r\n"),
		buildEthernetIPv4TCPFrame(client, server, 53000, 80, 9000, 0, TCPFlagSYN, nil),
		packet(9001, "CONNECT Origin.Example:443 HTTP/1.1\r\n\r\nGET /tunnel HTTP/1.1\r\n\r\n"),
	})
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.HTTP1RequestEvidence(raw)
	if err != nil {
		t.Fatal(err)
	}
	reader := bytes.NewReader(raw)
	index, err := NewFromReaderAt(reader, int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	other, err := index.HTTP1RequestEvidenceFromReaderAt(reader)
	if err != nil || !reflect.DeepEqual(got, other) {
		t.Fatalf("ReaderAt evidence = %+v, %v; slice = %+v", other, err, got)
	}
	packets, err := c.Packets(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		packet, offset    int
		target, authority string
	}{
		{0, 2, "/two", "Api.Example"},
		{1, 0, "http://Api.Example:80/a%2Fb?Key=x", "Api.Example:80"},
		{1, len(first + second), "/three", ""},
		{1, len(first + second + third), "/four", ""},
		{5, 0, "Origin.Example:443", "Origin.Example:443"},
	}
	if len(got) != len(want) {
		t.Fatalf("evidence = %+v", got)
	}
	for i, r := range got {
		w := want[i]
		if r.PacketIndex != w.packet || r.PacketPayloadOffset != w.offset || r.FlowIndex != 0 || r.TimestampNs != packets[w.packet].TimestampNs ||
			r.Source != netip.AddrPortFrom(netip.AddrFrom4(client), 53000) || r.Destination != netip.AddrPortFrom(netip.AddrFrom4(server), 80) ||
			r.Target != w.target || r.Authority != w.authority || r.Version != "1.1" || r.BodyState != HTTPBodyComplete {
			t.Fatalf("row %d = %+v", i, r)
		}
		if i < 4 && r.TCPAnomalies != (StreamAnomalies{MidstreamPickup: true, SequenceGap: true, OverlapConflict: true, Retransmission: true}) || i == 4 && r.TCPAnomalies.Any() {
			t.Fatalf("row %d TCP anomalies = %+v", i, r.TCPAnomalies)
		}
	}
	clear(raw)
	wantHeaders := []HTTPHeader{{"hOSt", "\t wrong.example \t"}, {"X-Test", " first"}, {"x-test", "\tsecond \r\n \tfolded"}, {"Content-Length", " 4"}}
	if got[1].Method != "POST" || string(got[1].Body) != "DATA" || got[1].Anomalies != (HTTPAnomalies{ObsFoldHeader: true}) || !slices.Equal(got[1].Headers, wantHeaders) {
		t.Fatalf("retained POST evidence = %+v", got[1])
	}
}

func TestHTTP1RequestEvidenceBodies(t *testing.T) {
	payload := []byte("request body from gzip")
	gzip := compressHTTPTestBody(t, "gzip", payload)
	checksum := bytes.Clone(gzip)
	checksum[len(checksum)-8] ^= 1
	chunk := func(data []byte, terminal string) []byte {
		return fmt.Appendf(nil, "%x\r\n%s\r\n%x\r\n%s\r\n%s", 7, data[:7], len(data)-7, data[7:], terminal)
	}
	const (
		chunked      = "Transfer-Encoding: chunked\r\n"
		gzipEncoding = "Content-Encoding: gzip\r\n"
		next         = "GET /next HTTP/1.1\r\n\r\n"
	)
	for _, tc := range []struct {
		name, fields string
		wire, body   []byte
		state        HTTPBodyState
		anomalies    HTTPAnomalies
		pipeline     bool
	}{
		{"empty", "", nil, nil, HTTPBodyComplete, HTTPAnomalies{}, true},
		{"length", "Content-Length: 3\r\n", []byte("abc"), []byte("abc"), HTTPBodyComplete, HTTPAnomalies{}, true},
		{"length cut by gap", "Content-Length: 5\r\n", []byte("ab"), []byte("ab"), HTTPBodyPartial, HTTPAnomalies{TruncatedBody: true}, false},
		{"invalid length", "Content-Length: junk\r\n", []byte("abc"), nil, HTTPBodyUnknown, HTTPAnomalies{}, false},
		{"space before length colon", "Content-Length : 3\r\n", []byte("abc" + next), nil, HTTPBodyUnknown, HTTPAnomalies{}, false},
		{"invalid length whitespace", "Content-Length: \xc2\xa03\r\n", []byte("abc" + next), nil, HTTPBodyUnknown, HTTPAnomalies{}, false},
		{"conflicting length", "Content-Length: 1,2\r\n", []byte("abc"), nil, HTTPBodyUnknown, HTTPAnomalies{MultipleContentLength: true}, false},
		{"chunked gzip", chunked + gzipEncoding, chunk(gzip, "0\r\nX-Trailer: value\r\n\r\n"), payload, HTTPBodyComplete, HTTPAnomalies{}, true},
		{"truncated chunk", chunked, []byte("8\r\nabc"), []byte("abc"), HTTPBodyPartial, HTTPAnomalies{TruncatedBody: true}, false},
		{"malformed chunk", chunked, []byte("3\r\nabc!"), nil, HTTPBodyUnknown, HTTPAnomalies{TruncatedBody: true}, false},
		{"positive chunk sign", chunked, []byte("+1\r\na\r\n0\r\n\r\n" + next), nil, HTTPBodyUnknown, HTTPAnomalies{TruncatedBody: true}, false},
		{"negative chunk sign", chunked, []byte("-0\r\n\r\n" + next), nil, HTTPBodyUnknown, HTTPAnomalies{TruncatedBody: true}, false},
		{"malformed trailer", chunked, []byte("3\r\nabc\r\n0\r\nmalformed\r\n\r\n"), nil, HTTPBodyUnknown, HTTPAnomalies{}, false},
		{"truncated chunk terminator", chunked + gzipEncoding, chunk(gzip, "0\r\n"), payload, HTTPBodyPartial, HTTPAnomalies{TruncatedBody: true}, false},
		{"truncated gzip footer", chunked + gzipEncoding, chunk(gzip[:len(gzip)-1], "0\r\n\r\n"), payload, HTTPBodyPartial, HTTPAnomalies{InvalidContentEncoding: true}, true},
		{"invalid gzip checksum", chunked + gzipEncoding, chunk(checksum, "0\r\n\r\n"), nil, HTTPBodyUnknown, HTTPAnomalies{InvalidContentEncoding: true}, true},
		{"opaque content coding", chunked + "Content-Encoding: br\r\n", []byte("3\r\nabc\r\n0\r\n\r\n"), nil, HTTPBodyUnsupported, HTTPAnomalies{}, true},
		{"opaque transfer before chunked", "Transfer-Encoding: gzip, chunked\r\n", []byte("3\r\nabc\r\n0\r\n\r\n"), nil, HTTPBodyUnsupported, HTTPAnomalies{}, true},
		{"opaque transfer with unknown boundary", "Transfer-Encoding: gzip\r\n", gzip, nil, HTTPBodyUnsupported, HTTPAnomalies{}, false},
		{"upgrade boundary", "Upgrade: websocket\r\nConnection: upgrade\r\n", []byte(next), nil, HTTPBodyComplete, HTTPAnomalies{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := append([]byte("POST / HTTP/1.1\r\n"+tc.fields+"\r\n"), tc.wire...)
			if tc.pipeline {
				data = append(data, next...)
			}
			const split = 9
			client, server := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
			packets := [][]byte{
				buildEthernetIPv4TCPFrame(client, server, 50000, 80, 1, 1, TCPFlagACK, data[:split]),
				buildEthernetIPv4TCPFrame(client, server, 50000, 80, 1+split, 1, TCPFlagACK, data[split:]),
			}
			if tc.name == "length cut by gap" {
				packets = append(packets, buildEthernetIPv4TCPFrame(client, server, 50000, 80, uint32(len(data)+2), 1, TCPFlagACK, []byte(next)))
			}
			raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, packets)
			c, err := New(raw)
			if err != nil {
				t.Fatal(err)
			}
			rows := checkReaderParity(t, raw, c.HTTP1RequestEvidence, c.HTTP1RequestEvidenceFromReaderAt)
			if len(rows) == 0 || len(rows) > 2 || (len(rows) == 2) != tc.pipeline {
				t.Fatalf("requests = %+v", rows)
			}
			r := rows[0]
			if r.PacketIndex != 0 || r.PacketPayloadOffset != 0 || r.BodyState != tc.state || !bytes.Equal(r.Body, tc.body) || r.Anomalies != tc.anomalies || r.BodyLimitExceeded {
				t.Fatalf("request = %+v", r)
			}
			if r.TCPAnomalies.SequenceGap != (tc.name == "length cut by gap") {
				t.Fatalf("TCP anomalies = %+v", r.TCPAnomalies)
			}
			if tc.pipeline && (rows[1].Target != "/next" || rows[1].PacketIndex != 1 || rows[1].PacketPayloadOffset != len(data)-len(next)-split) {
				t.Fatalf("next request = %+v", rows[1])
			}
		})
	}
}

func TestHTTP1RequestEvidenceInvalidStartLine(t *testing.T) {
	for _, line := range []string{"GET /space here HTTP/1.1", "GET /control\x00byte HTTP/1.1", "GET /path HTTP/1.X"} {
		raw := http1RequestEvidenceCapture([]byte(line + "\r\n\r\n"))
		c, err := New(raw)
		if err != nil {
			t.Fatal(err)
		}
		legacy, err := c.HTTPRequests(raw)
		if err != nil || len(legacy) != 1 {
			t.Fatalf("legacy observations for %q = %d, %v", line, len(legacy), err)
		}
		if rows := checkReaderParity(t, raw, c.HTTP1RequestEvidence, c.HTTP1RequestEvidenceFromReaderAt); len(rows) != 0 {
			t.Fatalf("evidence for %q = %+v", line, rows)
		}
	}
}

func TestHTTP1RequestEvidenceInvalidHost(t *testing.T) {
	raw := http1RequestEvidenceCapture([]byte("GET / HTTP/1.1\r\nHost : first.invalid\r\nHost: second.example\r\n\r\n"))
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	rows := checkReaderParity(t, raw, c.HTTP1RequestEvidence, c.HTTP1RequestEvidenceFromReaderAt)
	if len(rows) != 1 || rows[0].Authority != "second.example" || rows[0].BodyState != HTTPBodyUnknown || len(rows[0].Headers) != 2 || rows[0].Headers[0].Name != "Host " {
		t.Fatalf("evidence = %+v", rows)
	}
}

func TestHTTP1RequestEvidenceBodyLimit(t *testing.T) {
	plain := bytes.Repeat([]byte("a"), MaxHTTPBodyBytes+1)
	gzip := compressHTTPTestBody(t, "gzip", plain)
	request := fmt.Appendf(nil, "POST / HTTP/1.1\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n%s", len(gzip), gzip)
	raw := http1RequestEvidenceCapture(request)
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	rows := checkReaderParity(t, raw, c.HTTP1RequestEvidence, c.HTTP1RequestEvidenceFromReaderAt)
	if len(rows) != 1 {
		t.Fatalf("requests = %d", len(rows))
	}
	r := rows[0]
	if r.BodyState != HTTPBodyPartial || !r.BodyLimitExceeded || !r.Anomalies.DecompressionLimitExceeded || !bytes.Equal(r.Body, plain[:MaxHTTPBodyBytes]) {
		t.Fatalf("state = %d, limit = %t, anomalies = %+v, bytes = %d", r.BodyState, r.BodyLimitExceeded, r.Anomalies, len(r.Body))
	}
}

func TestHTTP1RequestEvidenceScanBudgets(t *testing.T) {
	const n = MaxHTTPDecodedBodyBytesPerScan / MaxHTTPBodyBytes
	const request = "GET / HTTP/1.1\r\n\r\n"
	gzip := compressHTTPTestBody(t, "gzip", bytes.Repeat([]byte("a"), MaxHTTPBodyBytes))
	bad := bytes.Clone(gzip)
	bad[len(bad)-8] ^= 1
	post := func(encoded []byte) []byte {
		return fmt.Appendf(nil, "POST / HTTP/1.1\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n%s", len(encoded), encoded)
	}
	for _, tc := range []struct {
		name string
		wire []byte
		want error
	}{
		{"message count", []byte(strings.Repeat(request, MaxHTTPMessagesPerScan+1)), ErrHTTPLimit},
		{"header count", []byte("GET / HTTP/1.1\r\n" + strings.Repeat("X: a\r\n", MaxHTTPHeaders+1) + "\r\n"), ErrHTTPLimit},
		{"retained bytes", bytes.Repeat(post(gzip), n), ErrHTTPLimit},
		{"failed decompressions count", append(bytes.Repeat(post(bad), n), post(gzip)...), errHTTPDecodeBudget},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := http1RequestEvidenceCapture(tc.wire)
			c, err := New(raw)
			if err != nil {
				t.Fatal(err)
			}
			slice, sliceErr := c.HTTP1RequestEvidence(raw)
			reader, readerErr := c.HTTP1RequestEvidenceFromReaderAt(bytes.NewReader(raw))
			if slice != nil || reader != nil || !errors.Is(sliceErr, tc.want) || !errors.Is(readerErr, tc.want) {
				t.Fatalf("slice = (%d, %v), ReaderAt = (%d, %v), want %v", len(slice), sliceErr, len(reader), readerErr, tc.want)
			}
		})
	}
}

func TestHTTP1RequestEvidenceStreamLimit(t *testing.T) {
	const first = "GET /empty HTTP/1.1\r\nContent-Length: 0\r\n\r\n"
	wire := fmt.Appendf([]byte(first), "POST /large HTTP/1.1\r\nContent-Length: %d\r\n\r\n", MaxFlowStreamBytes)
	size := len(wire)
	wire = append(wire, bytes.Repeat([]byte("x"), MaxFlowStreamBytes)...)
	raw := http1RequestEvidenceCapture(wire)
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	rows := checkReaderParity(t, raw, c.HTTP1RequestEvidence, c.HTTP1RequestEvidenceFromReaderAt)
	if len(rows) != 2 || rows[0].BodyState != HTTPBodyComplete || len(rows[0].Body) != 0 || !rows[0].TCPAnomalies.Truncated ||
		rows[1].BodyState != HTTPBodyPartial || len(rows[1].Body) != MaxFlowStreamBytes-size || !rows[1].TCPAnomalies.Truncated || !rows[1].Anomalies.TruncatedBody {
		t.Fatalf("evidence did not distinguish an empty body from TCP truncation, rows = %d", len(rows))
	}
}

func http1RequestEvidenceCapture(data []byte) []byte {
	client, server := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	seq := uint32(1)
	var packets [][]byte
	for part := range slices.Chunk(data, 32<<10) {
		packets = append(packets, buildEthernetIPv4TCPFrame(client, server, 50000, 80, seq, 1, TCPFlagACK, part))
		seq += uint32(len(part))
	}
	return buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, packets)
}

func ExampleCapture_HTTP1RequestEvidence() {
	data := http1RequestEvidenceCapture([]byte("POST /upload HTTP/1.1\r\nHost: app.example\r\nContent-Length: 4\r\n\r\ndata"))
	c, err := New(data)
	if err != nil {
		panic(err)
	}
	rows, err := c.HTTP1RequestEvidence(data)
	if err != nil {
		panic(err)
	}
	for _, r := range rows {
		fmt.Printf("frame=%d tcp_offset=%d %s %s %s body=%q complete=%t\n",
			r.PacketIndex+1, r.PacketPayloadOffset, r.Method, r.Authority, r.Target, r.Body, r.BodyState == HTTPBodyComplete)
	}
	// Output:
	// frame=1 tcp_offset=0 POST app.example /upload body="data" complete=true
}
