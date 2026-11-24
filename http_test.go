package pcap

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestHTTPRequestJA4HAndChunkedResponseCarving(t *testing.T) {
	rawReq := []byte("POST /gate.php HTTP/1.1\r\n" +
		"Host: c2.example.com\r\n" +
		"User-Agent: Mozilla/5.0\r\n" +
		"Accept-Language: en-US,en;q=0.9\r\n" +
		"Referer: https://c2.example.com/index.html\r\n" +
		"Cookie: z_token=999; a_sid=123\r\n" +
		"Content-Type: application/octet-stream\r\n" +
		"Content-Length: 10\r\n" +
		"\r\n" +
		"MZ_PAYLOAD")

	req, consumed, err := ParseHTTPRequest(rawReq)
	if err != nil {
		t.Fatalf("ParseHTTPRequest() error = %v", err)
	}
	if consumed != len(rawReq) || req.Method != "POST" || req.Path != "/gate.php" || req.Host != "c2.example.com" {
		t.Fatalf("HTTPRequest = %+v (consumed=%d)", req, consumed)
	}
	if string(req.Body) != "MZ_PAYLOAD" || req.CookieCount != 2 {
		t.Fatalf("Body=%q, CookieCount=%d", req.Body, req.CookieCount)
	}
	wantJA4H := "po11cr05enus_b43fff474339_5ac59ab507d3_be8d5d33fe4b"
	if req.JA4H != wantJA4H {
		t.Fatalf("HTTPRequest.JA4H = %q, want %q", req.JA4H, wantJA4H)
	}

	rawResp := []byte("HTTP/1.1 200 OK\r\n" +
		"Server: nginx\r\n" +
		"Content-Type: application/x-msdownload\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"\r\n" +
		"4\r\nMZ\x90\x00\r\n" +
		"6\r\nPE\x00\x00\x64\x86\r\n" +
		"0\r\n\r\n")

	resp, _, err := ParseHTTPResponse(rawResp)
	if err != nil {
		t.Fatalf("ParseHTTPResponse() error = %v", err)
	}
	if resp.StatusCode != 200 || resp.Server != "nginx" || !bytes.Equal(resp.Body, []byte("MZ\x90\x00PE\x00\x00\x64\x86")) {
		t.Fatalf("HTTPResponse = %+v, body=%x", resp, resp.Body)
	}
}

func TestHTTPBoundsAndLimits(t *testing.T) {
	if _, _, err := ParseHTTPRequest([]byte("INVALID_Method / HTTP/1.1\r\n\r\n")); !errors.Is(err, ErrInvalidHTTP) {
		t.Fatalf("ParseHTTPRequest(bad method) err = %v, want ErrInvalidHTTP", err)
	}
	if _, _, err := ParseHTTPRequest([]byte("GET / HTTP/2.0\r\n\r\n")); !errors.Is(err, ErrInvalidHTTP) {
		t.Fatalf("ParseHTTPRequest(HTTP/2.0) err = %v, want ErrInvalidHTTP", err)
	}

	var hdrBomb bytes.Buffer
	hdrBomb.WriteString("GET / HTTP/1.1\r\n")
	for range MaxHTTPHeaders + 1 {
		hdrBomb.WriteString("X-Test: 1\r\n")
	}
	hdrBomb.WriteString("\r\n")
	if _, _, err := ParseHTTPRequest(hdrBomb.Bytes()); !errors.Is(err, ErrHTTPLimit) {
		t.Fatalf("ParseHTTPRequest(header bomb) err = %v, want ErrHTTPLimit", err)
	}

	if _, _, err := ParseHTTPResponse([]byte("HTTP/1.1 999 Bad\r\n\r\n")); !errors.Is(err, ErrInvalidHTTP) {
		t.Fatalf("ParseHTTPResponse(status 999) err = %v, want ErrInvalidHTTP", err)
	}

	// Chunk size near MaxInt32 must not wrap offset+chunkSize on 32-bit targets.
	chunkOverflow := []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n7fffffff\r\nabcd")
	resp, _, err := ParseHTTPResponse(chunkOverflow)
	if err != nil {
		t.Fatalf("ParseHTTPResponse(max chunk size) err = %v", err)
	}
	if string(resp.Body) != "abcd" {
		t.Fatalf("ParseHTTPResponse(max chunk size) Body = %q, want %q", resp.Body, "abcd")
	}
}

func TestJA4HLargeCookieParity(t *testing.T) {
	value := strings.Repeat("a", 1200)
	request := "GET / HTTP/1.1\r\nHost: localhost\r\nCookie: z=2; a=" + value + "\r\nCookie: z=1\r\n\r\n"
	req, _, err := ParseHTTPRequest([]byte(request))
	const want = "ge11cn010000_4a823118b9ba_5521d8d1ef21_cda9743fbd5c"
	if err != nil || req.CookieCount != 3 || req.JA4H != want {
		t.Fatalf("got %q (%d cookies), %v; want %q", req.JA4H, req.CookieCount, err, want)
	}
}

func TestHTTPKeepAlivePipeliningAndChunkedTrailers(t *testing.T) {
	clientStream := []byte(
		"GET /first HTTP/1.1\r\nHost: keepalive.example\r\n\r\n" +
			"POST /second HTTP/1.1\r\nHost: keepalive.example\r\nContent-Length: 4\r\n\r\nBODY",
	)
	gzipOK := compressHTTPTestBody(t, "gzip", []byte("ok"))
	gzipEnd := compressHTTPTestBody(t, "gzip", []byte("end"))
	serverStream := fmt.Appendf(nil,
		"HTTP/1.1 204 No Content\r\nServer: srv\r\n\r\n"+
			"HTTP/1.1 304 Not Modified\r\nContent-Length: 12\r\n\r\n"+
			"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n0\r\nX-Trailer: done\r\n\r\n"+
			"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n%s",
		len(gzipOK), gzipOK, len(gzipEnd), gzipEnd,
	)

	// Verify 304 with Content-Length ends strictly at the header boundary.
	notMod := []byte("HTTP/1.1 304 Not Modified\r\nContent-Length: 12\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
	resp304, consumed304, err := ParseHTTPResponse(notMod)
	if err != nil {
		t.Fatalf("ParseHTTPResponse(304) error = %v", err)
	}
	const want304HeaderLen = len("HTTP/1.1 304 Not Modified\r\nContent-Length: 12\r\n\r\n")
	if consumed304 != want304HeaderLen || len(resp304.Body) != 0 || resp304.BodyLength != 0 {
		t.Fatalf("304 response = (consumed=%d, body=%q), want (consumed=%d, empty body)", consumed304, resp304.Body, want304HeaderLen)
	}
	resp200, consumed200, err := ParseHTTPResponse(notMod[consumed304:])
	if err != nil || resp200.StatusCode != 200 || string(resp200.Body) != "hi" || consumed304+consumed200 != len(notMod) {
		t.Fatalf("following 200 response = (%+v, consumed=%d, err=%v)", resp200, consumed200, err)
	}

	f1 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 45000, 80, 1, 1, TCPFlagPSH|TCPFlagACK, clientStream)
	f2 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1}, 80, 45000, 1, 1+uint32(len(clientStream)), TCPFlagPSH|TCPFlagACK, serverStream)
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{f1, f2})
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	recs, err := c.HTTP(raw)
	if err != nil {
		t.Fatalf("Capture.HTTP() error = %v", err)
	}
	if len(recs) != 6 {
		t.Fatalf("Capture.HTTP() len = %d, want 6 (%+v)", len(recs), recs)
	}
	if recs[0].IsResponse || recs[0].Request.Path != "/first" || len(recs[0].Request.Body) != 0 {
		t.Fatalf("rec[0] = %+v, want bodyless GET /first", recs[0])
	}
	if recs[1].IsResponse || recs[1].Request.Path != "/second" || string(recs[1].Request.Body) != "BODY" {
		t.Fatalf("rec[1] = %+v, want POST /second with BODY", recs[1])
	}
	if !recs[2].IsResponse || recs[2].Response.StatusCode != 204 || len(recs[2].Response.Body) != 0 {
		t.Fatalf("rec[2] = %+v, want bodyless 204", recs[2])
	}
	if !recs[3].IsResponse || recs[3].Response.StatusCode != 304 || len(recs[3].Response.Body) != 0 {
		t.Fatalf("rec[3] = %+v, want bodyless 304 with Content-Length", recs[3])
	}
	if !recs[4].IsResponse || !recs[4].Response.IsDecompressed || string(recs[4].Response.Body) != "ok" {
		t.Fatalf("rec[4] = %+v, want chunked response with trailer", recs[4])
	}
	if !recs[5].IsResponse || !recs[5].Response.IsDecompressed || string(recs[5].Response.Body) != "end" {
		t.Fatalf("rec[5] = %+v, want trailing 200 end", recs[5])
	}
}

func compressHTTPTestBody(t testing.TB, coding string, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	var w io.WriteCloser
	switch coding {
	case "gzip":
		w = gzip.NewWriter(&buf)
	case "zlib":
		w = zlib.NewWriter(&buf)
	case "raw":
		var err error
		w, err = flate.NewWriter(&buf, flate.BestSpeed)
		if err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unexpected test coding %q", coding)
	}
	if _, err := w.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestHTTPContentDecoding(t *testing.T) {
	payload := []byte("carved HTTP payload")
	gz := compressHTTPTestBody(t, "gzip", payload)
	zlibBody := compressHTTPTestBody(t, "zlib", payload)
	corruptZlib := bytes.Clone(zlibBody)
	corruptZlib[len(corruptZlib)-1] ^= 1
	corruptGzip := bytes.Clone(gz)
	corruptGzip[len(corruptGzip)-8] ^= 1

	for _, tc := range []struct {
		name, coding string
		wire, want   []byte
		decoded      bool
		invalid      bool
	}{
		{"gzip", "GZip", gz, payload, true, false},
		{"alias", "x-gzip", gz, payload, true, false},
		{"gzip members", "gzip", append(bytes.Clone(gz), gz...), bytes.Repeat(payload, 2), true, false},
		{"zlib", "deflate", zlibBody, payload, true, false},
		{"raw deflate", "deflate", compressHTTPTestBody(t, "raw", payload), payload, true, false},
		{"empty decoded gzip", "gzip", compressHTTPTestBody(t, "gzip", nil), nil, true, false},
		{"zlib checksum", "deflate", corruptZlib, corruptZlib, false, true},
		{"gzip checksum", "gzip", corruptGzip, corruptGzip, false, true},
		{"truncated gzip", "gzip", gz[:len(gz)-1], gz[:len(gz)-1], false, true},
		{"gzip header", "gzip", []byte("not gzip"), []byte("not gzip"), false, true},
		{"unsupported coding", "br", gz, gz, false, false},
		{"stacked codings", "gzip, br", gz, gz, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			header := fmt.Sprintf("POST /upload HTTP/1.1\r\ncontent-encoding: %s\r\nContent-Length: %d\r\n\r\n", tc.coding, len(tc.wire))
			next := "GET /next HTTP/1.1\r\n\r\n"
			stream := append(append([]byte(header), tc.wire...), next...)
			req, consumed, err := ParseHTTPRequest(stream)
			if err != nil || consumed != len(header)+len(tc.wire) ||
				req.BodyOffset != len(header) || req.BodyLength != len(tc.want) || !bytes.Equal(req.Body, tc.want) ||
				req.ContentEncoding != tc.coding || req.IsDecompressed != tc.decoded ||
				req.Anomalies != (HTTPAnomalies{InvalidContentEncoding: tc.invalid}) {
				t.Fatalf("request = %+v, consumed = %d, err = %v", req, consumed, err)
			}
			follow, _, err := ParseHTTPRequest(stream[consumed:])
			if err != nil || follow.Path != "/next" {
				t.Fatalf("following request = %+v, err = %v", follow, err)
			}
			clear(stream[:consumed])
			if !bytes.Equal(req.Body, tc.want) {
				t.Fatal("changing the input changed the returned body")
			}
		})
	}

	t.Run("multiple fields", func(t *testing.T) {
		header := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n", len(gz))
		resp, _, err := ParseHTTPResponse(append([]byte(header), gz...))
		if err != nil || resp.ContentEncoding != "gzip, gzip" || resp.IsDecompressed ||
			resp.Anomalies != (HTTPAnomalies{}) || !bytes.Equal(resp.Body, gz) {
			t.Fatalf("response = %+v, err = %v", resp, err)
		}
	})

	t.Run("bodyless response", func(t *testing.T) {
		header := "HTTP/1.1 304 Not Modified\r\nContent-Encoding: gzip\r\nContent-Length: 100\r\n\r\n"
		resp, consumed, err := ParseHTTPResponse([]byte(header + "HTTP/1.1 200 OK\r\n\r\n"))
		if err != nil || consumed != len(header) || resp.BodyOffset != len(header) || len(resp.Body) != 0 ||
			resp.ContentEncoding != "gzip" || resp.IsDecompressed || resp.Anomalies != (HTTPAnomalies{}) {
			t.Fatalf("response = %+v, consumed = %d, err = %v", resp, consumed, err)
		}
	})
}

func TestHTTPContentDecodingSizeLimit(t *testing.T) {
	for _, coding := range []string{"gzip", "deflate"} {
		t.Run(coding, func(t *testing.T) {
			for _, length := range []int{MaxHTTPBodyBytes, MaxHTTPBodyBytes + 4096} {
				payload := bytes.Repeat([]byte("a"), length)
				format := coding
				if coding == "deflate" {
					format = "zlib"
				}
				wire := compressHTTPTestBody(t, format, payload)
				header := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Encoding: %s\r\nTransfer-Encoding: chunked\r\n\r\n", coding)
				message := fmt.Appendf([]byte(header), "%x\r\n%s\r\n%x\r\n%s\r\n0\r\nX-Trailer: done\r\n\r\n",
					7, wire[:7], len(wire)-7, wire[7:])
				stream := append(bytes.Clone(message), "HTTP/1.1 204 No Content\r\n\r\n"...)
				resp, consumed, err := ParseHTTPResponse(stream)
				if err != nil || consumed != len(message) || resp.BodyOffset != len(header) ||
					!resp.IsDecompressed || resp.ContentEncoding != coding || resp.BodyLength != MaxHTTPBodyBytes ||
					resp.Anomalies != (HTTPAnomalies{DecompressionLimitExceeded: length > MaxHTTPBodyBytes}) ||
					!bytes.Equal(resp.Body, payload[:MaxHTTPBodyBytes]) {
					t.Fatalf("length %d: consumed = %d, offset = %d, decoded = %t, body length = %d, anomalies = %+v, err = %v",
						length, consumed, resp.BodyOffset, resp.IsDecompressed, resp.BodyLength, resp.Anomalies, err)
				}
				follow, _, err := ParseHTTPResponse(stream[consumed:])
				if err != nil || follow.StatusCode != 204 {
					t.Fatalf("following response = %+v, err = %v", follow, err)
				}
			}
		})
	}
}

func TestCaptureHTTPDecodedBodyBudget(t *testing.T) {
	gz := compressHTTPTestBody(t, "gzip", bytes.Repeat([]byte("x"), MaxHTTPBodyBytes))
	bad := bytes.Clone(gz)
	bad[len(bad)-8] ^= 1
	small := compressHTTPTestBody(t, "gzip", []byte("x"))
	gzHeader := fmt.Sprintf("Content-Encoding: gzip\r\nContent-Length: %d\r\n\r\n", len(gz))
	n := MaxHTTPDecodedBodyBytesPerScan / MaxHTTPBodyBytes
	for _, tc := range []struct {
		name   string
		client []byte
		extra  bool
	}{
		{"exact budget", gz, false},
		{"over budget", gz, true},
		{"failed decoding counts", bad, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := bytes.Repeat(append([]byte("POST / HTTP/1.1\r\n"+gzHeader), tc.client...), n/2)
			server := bytes.Repeat(append([]byte("HTTP/1.1 200 OK\r\n"+gzHeader), gz...), n/2)
			if tc.extra {
				server = fmt.Appendf(server, "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n%s", len(small), small)
			}
			clientAddr, serverAddr := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
			var frames [][]byte
			seq := uint32(1)
			for chunk := range slices.Chunk(client, 32<<10) {
				frames = append(frames, buildEthernetIPv4TCPFrame(clientAddr, serverAddr, 45000, 80, seq, 1, TCPFlagPSH|TCPFlagACK, chunk))
				seq += uint32(len(chunk))
			}
			ack := seq
			seq = 1
			for chunk := range slices.Chunk(server, 32<<10) {
				frames = append(frames, buildEthernetIPv4TCPFrame(serverAddr, clientAddr, 80, 45000, seq, ack, TCPFlagPSH|TCPFlagACK, chunk))
				seq += uint32(len(chunk))
			}
			raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
			c, err := New(raw)
			if err != nil {
				t.Fatal(err)
			}
			records, err := c.HTTP(raw)
			if tc.extra {
				if records != nil || !errors.Is(err, ErrHTTPLimit) {
					t.Fatalf("Capture.HTTP() = (%d records, %v), want no records and ErrHTTPLimit", len(records), err)
				}
				return
			}
			if err != nil || len(records) != n {
				t.Fatalf("Capture.HTTP() = (%d records, %v), want %d records", len(records), err, n)
			}
			firstRequestLen := len("POST / HTTP/1.1\r\n") + len(gzHeader) + len(gz)
			firstResponseLen := len("HTTP/1.1 200 OK\r\n") + len(gzHeader) + len(gz)
			if records[1].Request.BodyOffset != firstRequestLen+len("POST / HTTP/1.1\r\n")+len(gzHeader) ||
				records[n/2+1].Response.BodyOffset != firstResponseLen+len("HTTP/1.1 200 OK\r\n")+len(gzHeader) ||
				!records[1].Request.IsDecompressed || !records[n/2+1].Response.IsDecompressed {
				t.Fatal("Capture.HTTP() lost wire offsets or decoded content after a pipelined message")
			}
		})
	}
}

func TestHTTPFraming(t *testing.T) {
	for _, tc := range []struct {
		name, fields, payload, body string
		flags                       HTTPAnomalies
	}{
		{"equal lengths", "Content-Length: 01, 1\r\n", "x", "x", HTTPAnomalies{}},
		{"conflicting lengths", "Content-Length: 1\r\nContent-Length: 2\r\n", "xyz", "", HTTPAnomalies{MultipleContentLength: true}},
		{"short body", "Content-Length: 9\r\n", "x", "x", HTTPAnomalies{TruncatedBody: true}},
		{"short chunks", "Transfer-Encoding: chunked\r\n", "1\r\nx\r\n0\r\n", "x", HTTPAnomalies{TruncatedBody: true}},
		{"missing delimiter", "Transfer-Encoding: chunked\r\n", "1\r\nx0\r\n\r\n", "x", HTTPAnomalies{TruncatedBody: true}},
		{"nonchunked token", "Transfer-Encoding: xchunked\r\nContent-Length: 1\r\n", "xyz", "", HTTPAnomalies{TransferEncodingWithContentLength: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := []byte("POST / HTTP/1.1\r\n" + tc.fields + "\r\n" + tc.payload)
			r, n, err := ParseHTTPRequest(wire)
			if err != nil || n != len(wire) || string(r.Body) != tc.body || r.Anomalies != tc.flags {
				t.Fatalf("consumed %d/%d, body %q, flags %+v, err %v", n, len(wire), r.Body, r.Anomalies, err)
			}
		})
	}
}

func TestHTTPFramingCaptureParity(t *testing.T) {
	first := "POST /first HTTP/1.1\r\nX-Note: one\r\n two\r\nContent-Length: 17\r\nTransfer-Encoding: Chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n"
	next := "GET /next HTTP/1.1\r\n\r\n"
	src, dst := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	frame := buildEthernetIPv4TCPFrame(src, dst, 45000, 80, 1, 1, TCPFlagPSH|TCPFlagACK, []byte(first+next))
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{frame})
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	want, err := c.HTTP(raw)
	if err != nil || len(want) != 2 {
		t.Fatalf("HTTP returned %d records, %v", len(want), err)
	}
	r := want[0].Request
	if r.Headers[0].Value != "one two" || string(r.Body) != "x" || r.Anomalies != (HTTPAnomalies{ObsFoldHeader: true, TransferEncodingWithContentLength: true}) || want[1].Request.Path != "/next" || want[1].Request.BodyOffset != len(first+next) {
		t.Fatalf("unexpected records %+v", want)
	}
	reader := bytes.NewReader(raw)
	index, err := NewFromReaderAt(reader, int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	var meta []streamMetadata
	streams, err := collectStreams(ipFrameSource{capture: index, reader: reader, needsPayload: func(f Frame, _ []byte) bool { return f.IPProtocol == IPProtoTCP }}, 0, &meta, tcpWireUnanchored)
	if err != nil {
		t.Fatal(err)
	}
	var got []HTTPRecord
	if err := scanHTTPStreams(streams, meta, nil, &got, nil, nil); err != nil || !reflect.DeepEqual(want, got) {
		t.Fatalf("ReaderAt mismatch: %+v, %v", got, err)
	}
}

func TestHTTPResponseFraming(t *testing.T) {
	for _, tc := range []struct {
		head, wire, body string
		flags            HTTPAnomalies
	}{
		{"200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 2", "1\r\nx\r\n0\r\nTrailer: yes\r\n\r\n", "x", HTTPAnomalies{TransferEncodingWithContentLength: true}},
		{"200 OK\r\nContent-Length: 1,2", "ignored", "", HTTPAnomalies{MultipleContentLength: true}},
		{"200 OK\r\nContent-Length: 4294967296", "x", "x", HTTPAnomalies{TruncatedBody: true}},
		{"304 Unmodified\r\nContent-Length: 99", "", "", HTTPAnomalies{}},
	} {
		raw := []byte("HTTP/1.1 " + tc.head + "\r\n\r\n" + tc.wire)
		r, n, err := ParseHTTPResponse(raw)
		if err != nil || n != len(raw) || string(r.Body) != tc.body || r.Anomalies != tc.flags {
			t.Fatalf("%q: consumed %d/%d, body %q, flags %+v, err %v", tc.head, n, len(raw), r.Body, r.Anomalies, err)
		}
	}
}

func TestHTTPCaptureHEADAndInterimResponses(t *testing.T) {
	a, b := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	req := "HEAD /first HTTP/1.1\r\n\r\nGET /next HTTP/1.1\r\n\r\n"
	resp := "HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 41\r\nContent-Encoding: gzip\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nnext"
	for _, tunnel := range []bool{false, true} {
		client, server := req, resp
		offset := 0
		if tunnel {
			client = proxyRequest + client
			server = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 Tunnel Established\r\n\r\n" + server
			offset = 3
		}
		raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{
			buildEthernetIPv4TCPFrame(b, a, 80, 5000, 1, 0, TCPFlagACK, []byte(server)),
			buildEthernetIPv4TCPFrame(a, b, 5000, 80, 1, 0, TCPFlagACK, []byte(client)),
		})
		c, err := New(raw)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := c.HTTP(raw)
		if err != nil || len(rows) != offset+5 {
			t.Fatalf("tunnel %v: %+v, %v", tunnel, rows, err)
		}
		web, err := c.Web(raw)
		if err != nil || !reflect.DeepEqual(rows, web.HTTP) {
			t.Fatalf("Web tunnel %v: %+v, %v", tunnel, web.HTTP, err)
		}
		got := rows[offset:]
		if got[0].Request.Method != "HEAD" || got[0].SrcPort != 5000 || got[1].Request.Path != "/next" ||
			got[2].Response.StatusCode != 103 || got[3].Response.StatusCode != 200 || got[3].Response.BodyLength != 0 || got[3].Response.Anomalies != (HTTPAnomalies{}) ||
			got[4].SrcPort != 80 || string(got[4].Response.Body) != "next" || got[4].Response.BodyOffset != len(server)-4 {
			t.Fatalf("tunnel %v: %+v", tunnel, got)
		}
	}
}

func TestHTTPCaptureStopsAtKnownTCPGap(t *testing.T) {
	a, b := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	prefix := "GET /ok HTTP/1.1\r\n\r\nGET /fa"
	reply := "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\na"
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{
		buildEthernetIPv4TCPFrame(a, b, 5000, 80, 1, 0, TCPFlagACK, []byte(prefix)),
		buildEthernetIPv4TCPFrame(a, b, 5000, 80, uint32(len(prefix)+22), 0, TCPFlagACK, []byte("ke HTTP/1.1\r\n\r\n")),
		buildEthernetIPv4TCPFrame(b, a, 80, 5000, 1, 0, TCPFlagACK, []byte(reply)),
		buildEthernetIPv4TCPFrame(b, a, 80, 5000, uint32(len(reply)+22), 0, TCPFlagACK, []byte("bcd")),
		buildEthernetIPv4TCPFrame(a, b, 5000, 80, 1000, 0, TCPFlagSYN, nil),
		buildEthernetIPv4TCPFrame(a, b, 5000, 80, 1010, 0, TCPFlagACK, []byte("GET /after-gap HTTP/1.1\r\n\r\n")),
	})
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := c.HTTP(raw)
	if err != nil || len(rows) != 2 || rows[0].Request.Path != "/ok" || string(rows[1].Response.Body) != "a" || !rows[1].Response.Anomalies.TruncatedBody {
		t.Fatalf("%+v, %v", rows, err)
	}
	web, err := c.Web(raw)
	if err != nil || !reflect.DeepEqual(rows, web.HTTP) {
		t.Fatalf("Web = %+v, %v", web.HTTP, err)
	}
	reqs, err := c.HTTPRequests(raw)
	if err != nil || len(reqs) != 1 || reqs[0].Path != "/ok" {
		t.Fatalf("HTTPRequests = %+v, %v", reqs, err)
	}
	checkReaderParity(t, raw, c.HTTPRequests, c.HTTPRequestsFromReaderAt)
}

func TestHTTPCaptureKeepsValidRequestDirection(t *testing.T) {
	client, server := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	for _, body := range []string{"GET is supported on this server\r\n", "GET /in-body HTTP/1.1\r\n\r\n"} {
		raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{
			buildEthernetIPv4TCPFrame(client, server, 5000, 80, 1000, 4000, TCPFlagACK, []byte("GET /request HTTP/1.1\r\n\r\n")),
			buildEthernetIPv4TCPFrame(server, client, 80, 5000, 4000, 1000, TCPFlagACK, []byte(body)),
		})
		c, err := New(raw)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := c.HTTP(raw)
		if err != nil || len(rows) != 1 || rows[0].SrcPort != 5000 || rows[0].Request.Path != "/request" {
			t.Fatalf("body %q: %+v, %v", body, rows, err)
		}
		web, err := c.Web(raw)
		if err != nil || !reflect.DeepEqual(rows, web.HTTP) {
			t.Fatalf("Web body %q: %+v, %v", body, web.HTTP, err)
		}
	}
}

func TestHTTPCaptureDoesNotPairEarlierResponse(t *testing.T) {
	client, server := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	const (
		firstResponse = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nprev"
		clientSeq     = 1000
		serverSeq     = 4000
	)
	for _, tc := range []struct {
		name, request, response string
		acknowledgements        bool
	}{
		{"TCP-ACK", "HEAD /head HTTP/1.1\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n", true},
		{"capture-order", "HEAD /head HTTP/1.1\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n", false},
		{"CONNECT", proxyRequest, "HTTP/1.1 200 Connection Established\r\n\r\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var previousACK, currentACK uint32
			if tc.acknowledgements {
				previousACK, currentACK = clientSeq, clientSeq+uint32(len(tc.request))
			}
			earlier := buildEthernetIPv4TCPFrame(server, client, 80, 5000, serverSeq, previousACK, TCPFlagACK, []byte(firstResponse))
			request := buildEthernetIPv4TCPFrame(client, server, 5000, 80, clientSeq, serverSeq+uint32(len(firstResponse)), TCPFlagACK, []byte(tc.request))
			response := buildEthernetIPv4TCPFrame(server, client, 80, 5000, serverSeq+uint32(len(firstResponse)), currentACK, TCPFlagACK, []byte(tc.response))
			packets := [][]byte{earlier, request, response}
			if tc.acknowledgements {
				// TCP acknowledgements still distinguish the records when
				// independent capture points reverse the first two packets.
				packets[0], packets[1] = packets[1], packets[0]
			}
			raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, packets)
			c, err := New(raw)
			if err != nil {
				t.Fatal(err)
			}
			rows, err := c.HTTP(raw)
			if err != nil || len(rows) != 3 || string(rows[1].Response.Body) != "prev" ||
				rows[2].Response.StatusCode != 200 || rows[2].Response.BodyLength != 0 || rows[2].Response.Anomalies.TruncatedBody {
				t.Fatalf("HTTP %s: %+v, %v", tc.name, rows, err)
			}
			web, err := c.Web(raw)
			if err != nil || !reflect.DeepEqual(rows, web.HTTP) {
				t.Fatalf("Web %s: %+v, %v", tc.name, web.HTTP, err)
			}
		})
	}
}
