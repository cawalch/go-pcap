package pcap

import (
	"bytes"
	"errors"
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
	wantJA4H := "po11cr05enus_" +
		truncSHA256Hex12([]byte("Host,User-Agent,Accept-Language,Content-Type,Content-Length")) + "_" +
		truncSHA256Hex12([]byte("a_sid,z_token")) + "_" +
		truncSHA256Hex12([]byte("a_sid=123,z_token=999"))
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
}
