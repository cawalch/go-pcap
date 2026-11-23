package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"
)

// Repeat a mix of clear and keyed HTTP/1 and HTTP/2, CONNECT, SSH and UDP.
// Split TCP payloads across packets so the benchmark includes reassembly.
func webWorkload(t testing.TB, groups int) []byte {
	t.Helper()
	body := bytes.Repeat([]byte("x"), 4096)
	get := []byte("GET /files HTTP/1.1\r\nHost: web.example\r\n\r\n")
	ok := append(fmt.Appendf(nil, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", len(body)), body...)
	h2 := append(bytes.Clone(HTTP2ClientPreface), buildHTTP2Frame(HTTP2FrameHeaders, 5, 1, []byte{0x82, 0x87, 0x84})...)
	h2OK := buildHTTP2Frame(HTTP2FrameSettings, 0, 0, nil)
	h2OK = append(h2OK, buildHTTP2Frame(HTTP2FrameHeaders, 4, 1, []byte{0x88})...)
	h2OK = append(h2OK, buildHTTP2Frame(HTTP2FrameData, 1, 1, body)...)

	clientKey, serverKey := bytes.Repeat([]byte{0xab}, 32), bytes.Repeat([]byte{0xcd}, 32)
	random := bytes.Repeat([]byte{0x42}, 32)
	keys := fmt.Appendf(nil, "CLIENT_TRAFFIC_SECRET_0 %x %x\nSERVER_TRAFFIC_SECRET_0 %x %x\n", random, clientKey, random, serverKey)
	keyed := func(hello, key, plain []byte) []byte {
		return append(hello, encryptTLS13AppDataRecord(t, key, TLS_AES_128_GCM_SHA256, 0, TLSRecordApplicationData, plain)...)
	}
	type exchange struct {
		port              uint16
		request, response []byte
	}
	exchanges := []exchange{
		{80, get, ok},
		{8080, h2, h2OK},
		{443, keyed(buildTLS13ClientHelloRecord("web.example", "http/1.1"), clientKey, get), keyed(buildTLSServerHelloRecord(), serverKey, ok)},
		{3128, append([]byte(proxyRequest), keyed(buildTLS13ClientHelloRecord("web.example", "h2"), clientKey, h2)...), append([]byte(proxyResponse), keyed(buildTLSServerHelloRecord(), serverKey, h2OK)...)},
		{22, []byte("SSH-2.0-client\r\n"), []byte("SSH-2.0-server\r\n")},
	}
	client, server := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	var frames [][]byte
	add := func(src, dst [4]byte, sp, dp uint16, data []byte) {
		for off := 0; off < len(data); off += 1200 {
			frames = append(frames, buildEthernetIPv4TCPFrame(src, dst, sp, dp, uint32(1+off), 0, TCPFlagACK, data[off:min(off+1200, len(data))]))
		}
	}
	for i := range groups {
		for j, e := range exchanges {
			port := uint16(30000 + i*len(exchanges) + j)
			add(client, server, port, e.port, e.request)
			add(server, client, e.port, port, e.response)
		}
		frames = append(frames, buildEthernetIPv4UDPFrame(client, server, uint16(10000+i), 9999, []byte("opaque")))
	}
	return buildPCAPNGFixture(binary.LittleEndian, keys, frames)
}

func separateWeb(c *Capture, data []byte) (WebRecords, error) {
	var out WebRecords
	var err error
	if out.TLS, err = c.TLS(data); err != nil {
		return WebRecords{}, err
	}
	if out.HTTP, err = c.HTTP(data); err != nil {
		return WebRecords{}, err
	}
	out.HTTP2, err = c.HTTP2(data)
	return out, err
}

func checkWebParity(t *testing.T, raw []byte) WebRecords {
	t.Helper()
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	want, err := separateWeb(c, raw)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Web(raw)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("combined web records differ from separate scans (err %v)", err)
	}
	return got
}

func TestWebParity(t *testing.T) {
	out := checkWebParity(t, webWorkload(t, 1))
	var keyed1, keyed2 int
	for _, r := range out.HTTP {
		if r.IsDecrypted {
			keyed1++
		}
	}
	for _, r := range out.HTTP2 {
		if r.IsDecrypted {
			keyed2++
		}
	}
	if len(out.TLS) != 2 || keyed1 != 2 || keyed2 != 2 {
		t.Fatalf("TLS=%d decrypted HTTP=%d HTTP2=%d", len(out.TLS), keyed1, keyed2)
	}
	for _, name := range []string{"client", "proxy", "iot"} {
		raw, err := os.ReadFile("testdata/deployments/" + name + ".pcapng")
		if err != nil {
			t.Fatal(err)
		}
		checkWebParity(t, raw)
	}
}

func TestWebLimit(t *testing.T) {
	// CONNECT yields clear HTTP records before the inner HPACK block fails.
	block := bytes.Repeat([]byte{0x82}, MaxHTTPHeaders+1)
	inner := append(bytes.Clone(HTTP2ClientPreface), buildHTTP2Frame(HTTP2FrameHeaders, 4, 1, block)...)
	c, raw := proxyTestCapture(t, inner, nil)
	_, want := c.HTTP2(raw)
	got, err := c.Web(raw)
	if !errors.Is(want, ErrHTTPLimit) || !errors.Is(err, ErrHTTPLimit) || !reflect.DeepEqual(got, WebRecords{}) {
		t.Fatalf("HTTP2 error %v, Web error %v, result %+v", want, err, got)
	}
	web, ws, err := c.WebWithWebSockets(raw)
	if !errors.Is(err, ErrHTTPLimit) || !reflect.DeepEqual(web, WebRecords{}) || ws != nil {
		t.Fatalf("combined scan returned partial results or unexpected error: %v", err)
	}
}

func BenchmarkWebAnalysis(b *testing.B) {
	raw := webWorkload(b, 24)
	c, err := New(raw)
	if err != nil {
		b.Fatal(err)
	}
	for _, impl := range []struct {
		name string
		scan func(*Capture, []byte) (WebRecords, error)
	}{
		{"separate", separateWeb}, {"shared", (*Capture).Web},
	} {
		b.Run(impl.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(raw)))
			for b.Loop() {
				out, err := impl.scan(c, raw)
				if err != nil || len(out.TLS) != 48 {
					b.Fatal(len(out.TLS), err)
				}
			}
		})
	}
}

func TestWebWithWebSocketsParity(t *testing.T) {
	raw := wsMixedCapture(t)
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, keyed := range []bool{true, false} {
		if !keyed {
			c.Secrets = nil
		}
		wantWeb, err := c.Web(raw)
		if err != nil {
			t.Fatal(err)
		}
		wantWS, err := c.WebSockets(raw)
		if err != nil {
			t.Fatal(err)
		}
		web, ws, err := c.WebWithWebSockets(raw)
		if err != nil || !reflect.DeepEqual(web, wantWeb) || !reflect.DeepEqual(ws, wantWS) {
			t.Fatalf("combined scan differs from separate scans (keyed=%t, err=%v)", keyed, err)
		}
	}
}

func BenchmarkWebWithWebSockets(b *testing.B) {
	raw := wsMixedCapture(b)
	c, err := New(raw)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		w, ws, err := c.WebWithWebSockets(raw)
		if err != nil || len(w.TLS) != 49 || len(ws) != 4 {
			b.Fatal(len(w.TLS), len(ws), err)
		}
	}
}
