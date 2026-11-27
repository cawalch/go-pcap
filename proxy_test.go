package pcap

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
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
	clientBytes := append([]byte(proxyRequest), request...)
	serverBytes := append([]byte(proxyResponse), response...)
	frames := [][]byte{
		buildEthernetIPv4TCPFrame(server, client, 3128, 51000, 1, 1+uint32(len(clientBytes)), TCPFlagACK, serverBytes),
		buildEthernetIPv4TCPFrame(client, server, 51000, 3128, 1, 1+uint32(len(serverBytes)), TCPFlagACK, clientBytes),
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

// enterpriseTestCapture sends the client suffix before the prefix, then
// retransmits the prefix. A nonzero gap moves just the selected suffix.
func enterpriseTestCapture(t *testing.T, clientData, serverData []byte, split int, gap uint32, proxied, serverGap bool) (*Capture, []byte) {
	t.Helper()
	client, server := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	const clientPort = 51000
	serverPort := uint16(55000)
	if proxied {
		clientData = append([]byte(proxyRequest), clientData...)
		serverData = append([]byte(proxyResponse), serverData...)
		split += len(proxyRequest)
		serverPort = 3128
	}
	const clientSeq, serverSeq = 1001, 2001
	frame := func(fromClient bool, seq uint32, flags uint8, payload []byte) []byte {
		if fromClient {
			return buildEthernetIPv4TCPFrame(client, server, clientPort, serverPort, seq, serverSeq, flags, payload)
		}
		return buildEthernetIPv4TCPFrame(server, client, serverPort, clientPort, seq, clientSeq, flags, payload)
	}
	frames := [][]byte{
		frame(true, clientSeq-1, TCPFlagSYN, nil),
		frame(false, serverSeq-1, TCPFlagSYN|TCPFlagACK, nil),
	}
	clientGap := gap
	if serverGap {
		clientGap = 0
	}
	frames = append(frames,
		frame(true, clientSeq+uint32(split)+clientGap, TCPFlagPSH|TCPFlagACK, clientData[split:]),
		frame(true, clientSeq, TCPFlagPSH|TCPFlagACK, clientData[:split]),
		frame(true, clientSeq, TCPFlagPSH|TCPFlagACK, clientData[:split]),
	)
	if serverGap {
		// A gap in the CONNECT response prevents establishing the tunnel.
		split = len(proxyResponse) - 2
		frames = append(frames,
			frame(false, serverSeq, TCPFlagPSH|TCPFlagACK, serverData[:split]),
			frame(false, serverSeq+uint32(split)+gap, TCPFlagPSH|TCPFlagACK, serverData[split:]),
		)
	} else {
		frames = append(frames, frame(false, serverSeq, TCPFlagPSH|TCPFlagACK, serverData))
	}
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	return c, raw
}

func TestSMBRDPSSHDirectionalTCPGaps(t *testing.T) {
	for _, proxied := range []bool{false, true} {
		name := "direct"
		if proxied {
			name = "CONNECT"
		}
		t.Run(name+"/SMB", func(t *testing.T) {
			first := smbSessionFrame(smbNameRequest(SMB2CommandCreate, "first.txt"))
			second := smbSessionFrame(smbNameRequest(SMB2CommandCreate, "second.txt"))
			session := buildSMB2SessionSetupNTLMChallenge()
			c, raw := enterpriseTestCapture(t, append(bytes.Clone(first), second...), session, len(first)+len(second)-4, 0, proxied, false)
			full, err := c.SMB(raw)
			if err != nil || len(full) != 3 || full[0].Message.FileName != "first.txt" || full[1].Message.FileName != "second.txt" || !full[2].Message.HasNTLM {
				t.Fatalf("contiguous SMB = %+v, %v", full, err)
			}
			c, raw = enterpriseTestCapture(t, append(bytes.Clone(first), second...), session, len(first)+len(second)-4, 32, proxied, false)
			rows, err := c.SMB(raw)
			want := []SMB2Record{full[0], full[2]}
			if err != nil || !reflect.DeepEqual(rows, want) {
				t.Fatalf("gapped SMB = %+v, %v; want %+v", rows, err, want)
			}
		})
		t.Run(name+"/RDP", func(t *testing.T) {
			req := buildRDPConnReqPDU("fixture", RDPProtoTLS)
			resp := buildRDPConnConfirmPDU(RDPProtoTLS)
			c, raw := enterpriseTestCapture(t, req, resp, len(req)-4, 0, proxied, false)
			full, err := c.RDP(raw)
			if err != nil || len(full) != 2 || full[0].Negotiation.Cookie != "fixture" || !full[1].Negotiation.HasNegRsp {
				t.Fatalf("contiguous RDP = %+v, %v", full, err)
			}
			c, raw = enterpriseTestCapture(t, req, resp, len(req)-4, 32, proxied, false)
			rows, err := c.RDP(raw)
			if err != nil || !reflect.DeepEqual(rows, full[1:]) {
				t.Fatalf("gapped RDP = %+v, %v; want %+v", rows, err, full[1:])
			}
		})
		t.Run(name+"/SSH", func(t *testing.T) {
			client, server := sshHandshakeFixture()
			c, raw := enterpriseTestCapture(t, client, server, len(client)-8, 0, proxied, false)
			full, err := c.SSH(raw)
			if err != nil || len(full) != 1 || full[0].Handshake.HASSH == "" || full[0].Handshake.HASSHServer == "" || full[0].JA4SSH == "" {
				t.Fatalf("contiguous SSH = %+v, %v", full, err)
			}
			c, raw = enterpriseTestCapture(t, client, server, len(client)-8, 32, proxied, false)
			rows, err := c.SSH(raw)
			full[0].Handshake.HasClientKex = false
			full[0].Handshake.ClientKex = SSHKexInit{}
			full[0].Handshake.HASSH = ""
			if err != nil || !reflect.DeepEqual(rows, full) {
				t.Fatalf("gapped SSH = %+v, %v; want %+v", rows, err, full)
			}
		})
	}
}

func TestSMBRDPSSHTunnelRequiresContiguousProxyResponse(t *testing.T) {
	client, server := sshHandshakeFixture()
	c, raw := enterpriseTestCapture(t, client, server, 5, 32, true, true)
	if rows, err := c.SSH(raw); err != nil || len(rows) != 0 {
		t.Fatalf("SSH inside an unconfirmed tunnel = %+v, %v", rows, err)
	}
	c, raw = enterpriseTestCapture(t, nil, buildSMB2SessionSetupNTLMChallenge(), 0, 32, true, true)
	if rows, err := c.SMB(raw); err != nil || len(rows) != 0 {
		t.Fatalf("SMB inside an unconfirmed tunnel = %+v, %v", rows, err)
	}
	c, raw = enterpriseTestCapture(t, buildRDPConnReqPDU("fixture", RDPProtoTLS), buildRDPConnConfirmPDU(RDPProtoTLS), 5, 32, true, true)
	if rows, err := c.RDP(raw); err != nil || len(rows) != 0 {
		t.Fatalf("RDP inside an unconfirmed tunnel = %+v, %v", rows, err)
	}
}
