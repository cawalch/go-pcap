package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
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
	serverStream := []byte(
		"HTTP/1.1 204 No Content\r\nServer: srv\r\n\r\n" +
			"HTTP/1.1 304 Not Modified\r\nContent-Length: 12\r\n\r\n" +
			"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\nX-Trailer: done\r\n\r\n" +
			"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nend",
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
	if !recs[4].IsResponse || string(recs[4].Response.Body) != "ok" {
		t.Fatalf("rec[4] = %+v, want chunked response with trailer", recs[4])
	}
	if !recs[5].IsResponse || string(recs[5].Response.Body) != "end" {
		t.Fatalf("rec[5] = %+v, want trailing 200 end", recs[5])
	}
}
