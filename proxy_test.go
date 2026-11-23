package pcap

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

const proxyRequest = "CONNECT proxy-target.example:443 HTTP/1.1\r\n\r\n"
const proxyResponse = "HTTP/1.1 200 Connection established\r\n\r\n"

func TestUnwrapProxyStream(t *testing.T) {
	// RFC 1928 greeting, no-auth selection and IPv4 bind reply.
	reply := []byte{5, 0, 5, 0, 0, 1, 127, 0, 0, 1, 0, 80}
	for _, test := range []struct {
		name, host string
		c, s       []byte
	}{
		{"http-connect", "2001:db8::1", []byte("CONNECT [2001:db8::1]:443 HTTP/1.0\r\n\r\n"), []byte(proxyResponse)},
		{"socks5", "192.0.2.1", []byte{5, 2, 2, 0, 5, 1, 0, 1, 192, 0, 2, 1, 1, 187}, reply},
		{"socks5", "abc", []byte{5, 1, 0, 5, 1, 0, 3, 3, 'a', 'b', 'c', 1, 187}, reply},
		{"socks5", "::1", []byte{5, 1, 0, 5, 1, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 187}, reply},
	} {
		checkMiss := func(c, s []byte) {
			t.Helper()
			a, b, typ, host, port, ok := UnwrapProxyStream(c, s)
			if ok || !bytes.Equal(c, a) || !bytes.Equal(s, b) || typ != "" || host != "" || port != 0 {
				t.Fatalf("partial %s recognized: %d/%d", test.name, len(c), len(s))
			}
		}
		for n := range len(test.c) {
			checkMiss(test.c[:n], test.s)
		}
		for n := range len(test.s) {
			checkMiss(test.c, test.s[:n])
		}
		c, s := append(bytes.Clone(test.c), 'C'), append(bytes.Clone(test.s), 'S')
		a, b, typ, host, port, ok := UnwrapProxyStream(c, s)
		if !ok || typ != test.name || host != test.host || port != 443 || len(a) != 1 || len(b) != 1 || &a[0] != &c[len(test.c)] || &b[0] != &s[len(test.s)] {
			t.Fatalf("unwrap %s %s: %s %s %d %t", test.name, test.host, typ, host, port, ok)
		}
	}
	for _, tc := range []struct{ c, s string }{
		{proxyRequest, "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"},
		{proxyRequest, "HTTP/1.1 2000\r\n\r\n"},
		{"CONNECT invalid:65536 HTTP/1.1\r\n\r\n", proxyResponse},
		{proxyRequest[:len(proxyRequest)-2] + "X: " + strings.Repeat("x", 4096) + "\r\n\r\n", proxyResponse},
		{proxyRequest, proxyResponse[:len(proxyResponse)-2] + "X: " + strings.Repeat("x", 4096) + "\r\n\r\n"},
		{"\x05\x01\x02\x05\x01\x00\x01\x7f\x00\x00\x01\x01\xbb", string(reply)},
	} {
		if _, _, _, _, _, ok := UnwrapProxyStream([]byte(tc.c), []byte(tc.s)); ok {
			t.Fatal("accepted failed or invalid handshake")
		}
	}
}

func proxyTestCapture(t *testing.T, request, response []byte) (*Capture, []byte) {
	t.Helper()
	client, server := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	// Capture the server's bytes first to exercise stream orientation.
	frames := [][]byte{
		buildEthernetIPv4TCPFrame(server, client, 3128, 51000, 1, 1, TCPFlagACK, append([]byte(proxyResponse), response...)),
		buildEthernetIPv4TCPFrame(client, server, 51000, 3128, 1, 1, TCPFlagACK, append([]byte(proxyRequest), request...)),
	}
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	return c, raw
}

func TestProxyCaptureProtocols(t *testing.T) {
	t.Run("HTTP", func(t *testing.T) {
		c, raw := proxyTestCapture(t, []byte("POST /inner HTTP/1.1\r\nHost: inner.example\r\nContent-Length: 1\r\n\r\nQ"), []byte("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nR"))
		rows, err := c.HTTP(raw)
		if err != nil || len(rows) != 4 || rows[0].Request.Method != "CONNECT" || rows[0].Request.Path != "proxy-target.example:443" || len(rows[1].Response.Body) != 0 || rows[2].Request.Path != "/inner" || rows[2].Request.Host != "inner.example" || rows[3].Response.StatusCode != 200 || rows[2].SrcPort != 51000 {
			t.Fatalf("HTTP: %+v %v", rows, err)
		}
		streams, err := c.Streams(raw)
		if err != nil || len(streams) != 1 {
			t.Fatal(streams, err)
		}
		if streams[0].Client.Data[rows[3].Response.BodyOffset] != 'R' || streams[0].Server.Data[rows[2].Request.BodyOffset] != 'Q' {
			t.Fatal("wire body offsets")
		}
	})
	t.Run("TLS", func(t *testing.T) {
		secret := bytes.Repeat([]byte{0xaa}, 32)
		req := append(buildTLS13ClientHelloRecord("inner.example", "h2"), encryptTLS13AppDataRecord(t, secret, TLS_AES_128_GCM_SHA256, 0, TLSRecordApplicationData, []byte("request"))...)
		resp := append(buildTLSServerHelloRecord(), encryptTLS13AppDataRecord(t, secret, TLS_AES_128_GCM_SHA256, 0, TLSRecordApplicationData, []byte("response"))...)
		c, raw := proxyTestCapture(t, req, resp)
		outer, err := c.HTTP(raw)
		if err != nil || len(outer) != 2 || outer[0].Request.Path != "proxy-target.example:443" || outer[1].Response.StatusCode != 200 || len(outer[1].Response.Body) != 0 {
			t.Fatal(outer, err)
		}
		checkReaderParity(t, raw, c.TLS, c.TLSFromReaderAt)
		tls, err := c.TLSWithKeyLog(raw, nil)
		if err != nil || len(tls) != 1 || tls[0].Handshake.ClientHello.SNI != "inner.example" || !tls[0].Handshake.HasServerHello {
			t.Fatal(tls, err)
		}
		random := bytes.Repeat([]byte{0x42}, 32)
		log := []byte(fmt.Sprintf("CLIENT_TRAFFIC_SECRET_0 %x %x\nSERVER_TRAFFIC_SECRET_0 %x %x\n", random, secret, random, secret))
		plain, err := c.DecryptedTLSStreams(raw, log)
		if err != nil || len(plain) != 1 || string(plain[0].Client.Data) != "request" || string(plain[0].Server.Data) != "response" {
			t.Fatal(plain, err)
		}
	})
	t.Run("HTTP2", func(t *testing.T) {
		settings := buildHTTP2Frame(HTTP2FrameSettings, 0, 0, nil)
		c, raw := proxyTestCapture(t, append(bytes.Clone(HTTP2ClientPreface), settings...), settings)
		rows, err := c.HTTP2(raw)
		if err != nil || len(rows) != 2 || !rows[0].Summary.HasClientPreface || !rows[1].IsServer {
			t.Fatal(rows, err)
		}
	})
	t.Run("SSH", func(t *testing.T) {
		c, raw := proxyTestCapture(t, []byte("SSH-2.0-client\r\n"), []byte("SSH-2.0-server\r\n"))
		rows, err := c.SSH(raw)
		if err != nil || len(rows) != 1 || rows[0].Handshake.ClientBanner != "SSH-2.0-client" || rows[0].Handshake.ServerBanner != "SSH-2.0-server" {
			t.Fatal(rows, err)
		}
	})
	t.Run("SMB", func(t *testing.T) {
		c, raw := proxyTestCapture(t, nil, buildSMB2SessionSetupNTLMChallenge())
		rows, err := c.SMB(raw)
		if err != nil || len(rows) != 1 || !rows[0].Message.HasNTLM {
			t.Fatal(rows, err)
		}
	})
	t.Run("RDP", func(t *testing.T) {
		c, raw := proxyTestCapture(t, buildRDPConnReqPDU("fixture", 1), buildRDPConnConfirmPDU(1))
		rows, err := c.RDP(raw)
		if err != nil || len(rows) != 2 || !rows[0].Negotiation.HasNegReq || !rows[1].Negotiation.HasNegRsp {
			t.Fatal(rows, err)
		}
	})
}
