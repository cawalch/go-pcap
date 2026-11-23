package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

const wsRequest = "GET /chat HTTP/1.1\r\nHost: web.example\r\nConnection: Upgrade\r\nUpgrade: WebSocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
const wsResponse = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"

func wsTestFrame(first byte, mask bool, payload []byte) []byte {
	var flag byte
	if mask {
		flag = 128
	}
	p := []byte{first}
	switch {
	case len(payload) < 126:
		p = append(p, flag|byte(len(payload)))
	case len(payload) <= 65535:
		p = binary.BigEndian.AppendUint16(append(p, flag|126), uint16(len(payload)))
	default:
		p = binary.BigEndian.AppendUint64(append(p, flag|127), uint64(len(payload)))
	}
	key := []byte{0x37, 0xfa, 0x21, 0x3d}
	if mask {
		p = append(p, key...)
	}
	start := len(p)
	p = append(p, payload...)
	if mask {
		for i := range payload {
			p[start+i] ^= key[i&3]
		}
	}
	return p
}

func TestWebSocketFrames(t *testing.T) {
	// RFC 6455 section 5.7 masked "Hello".
	wire := []byte{0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58}
	copyWire := bytes.Clone(wire)
	m, e := ParseWebSocketFrames(wire)
	if e != nil || len(m) != 1 || string(m[0].Payload) != "Hello" || !bytes.Equal(wire, copyWire) {
		t.Fatal(m, e)
	}
	for _, mask := range []bool{false, true} {
		// UTF-8 code point split across frames. Each masking key starts at zero.
		p := wsTestFrame(1, mask, []byte{0xe2})
		p = append(p, wsTestFrame(0x89, mask, []byte("ping"))...)
		p = append(p, wsTestFrame(0, mask, []byte{0x82})...)
		p = append(p, wsTestFrame(0x80, mask, []byte{0xac})...)
		p = append(p, wsTestFrame(0x8a, mask, nil)...)
		p = append(p, wsTestFrame(0x88, mask, []byte{3, 232})...)
		m, e := ParseWebSocketFrames(p)
		want := []WebSocketMessage{{9, []byte("ping")}, {1, []byte("€")}, {10, nil}, {8, []byte{3, 232}}}
		if e != nil || !reflect.DeepEqual(m, want) {
			t.Fatal(m, e)
		}
	}
	for _, n := range []int{125, 126, 65535, 65536, MaxHTTPBodyBytes} {
		payload := bytes.Repeat([]byte{255}, n)
		frame := wsTestFrame(0x82, true, payload)
		got, e := ParseWebSocketFrames(frame)
		clear(frame)
		if e != nil || len(got) != 1 || !bytes.Equal(got[0].Payload, payload) {
			t.Fatal(n, e)
		}
	}
}

func TestWebSocketBounds(t *testing.T) {
	for _, p := range [][]byte{{0x81}, {0xc1, 0}, {0x83, 0}, {0x80, 0}, {1, 0}, {1, 0, 0x82, 0}, {0x09, 0}, {0x89, 126}, {0x81, 126, 0, 1}, {0x82, 127, 0, 0, 0, 0, 0, 0, 255, 255}, {0x82, 127, 128, 0, 0, 0, 0, 0, 0, 0}, {0x82, 129, 0, 0}, {0x81, 1, 0xff}, {0x88, 1, 0}, {0x88, 3, 3, 232, 0xff}, {0x81, 0, 0x82, 128, 0, 0, 0, 0}} {
		if _, e := ParseWebSocketFrames(p); !errors.Is(e, ErrInvalidWebSocket) {
			t.Errorf("%x: %v", p, e)
		}
	}
	oversize := binary.BigEndian.AppendUint64([]byte{0x82, 127}, MaxHTTPBodyBytes+1)
	fragment := wsTestFrame(2, false, make([]byte, MaxHTTPBodyBytes))
	fragment = append(fragment, 0x80, 1, 0)
	atLimit := bytes.Repeat([]byte{0x82, 0}, MaxWebSocketFramesPerStream)
	if m, e := ParseWebSocketFrames(atLimit); e != nil || len(m) != MaxWebSocketFramesPerStream {
		t.Fatal(len(m), e)
	}
	for _, p := range [][]byte{oversize, fragment, append(atLimit, 0x82, 0)} {
		if _, e := ParseWebSocketFrames(p); !errors.Is(e, ErrWebSocketLimit) {
			t.Fatal(e)
		}
	}
	left := 1
	if e := walkWebSocketFrames([]byte{0x82, 1, 0, 0x82, 1, 1}, false, &left, func(WebSocketMessage) error { return nil }); !errors.Is(e, ErrWebSocketLimit) {
		t.Fatal(e)
	}
}

func TestWebSocketUpgrade(t *testing.T) {
	req, resp := []byte(wsRequest), []byte(wsResponse)
	cf := wsTestFrame(0x81, true, []byte("a"))
	sf := wsTestFrame(0x82, false, []byte("b"))
	rq := append(bytes.Clone(req), cf...)
	rs := append(bytes.Clone(resp), sf...)
	check := func(c, s, wc, ws []byte) {
		t.Helper()
		gc, gs := wsUpgraded(c, s)
		if !bytes.Equal(gc, wc) || !bytes.Equal(gs, ws) {
			t.Fatalf("got %x / %x; want %x / %x", gc, gs, wc, ws)
		}
	}
	check(rq, rs, cf, sf)
	check(nil, rs, nil, sf)
	check(rq, nil, cf, nil)
	check(rq, []byte("HTTP/1.1 403 Forbidden\r\n\r\n"), nil, nil)
	check(rq, bytes.ReplaceAll(rs, []byte("Upgrade: websocket"), []byte("Upgrade: h2c")), nil, nil)
	check(rq, append([]byte("HTTP/1.1 100 Continue\r\n\r\n"), rs...), cf, sf)
	previous := []byte("HEAD /before HTTP/1.1\r\nHost: web.example\r\n\r\n")
	check(append(previous, rq...), append([]byte("HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n"), rs...), cf, sf)
	fake := append(fmt.Appendf(nil, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", len(rs)), rs...)
	check(rq, fake, nil, nil)
}

func wsMixedCapture(t testing.TB) []byte {
	// Append a second PcapNG section to the existing 144-flow web workload.
	raw := webWorkload(t, 24)
	client, server := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	cKey, sKey := bytes.Repeat([]byte{0xab}, 32), bytes.Repeat([]byte{0xcd}, 32)
	request := append([]byte(wsRequest), wsTestFrame(1, true, []byte("sen"))...)
	request = append(request, wsTestFrame(0x80, true, []byte("sor"))...)
	reply := append([]byte(wsResponse), wsTestFrame(0x82, false, []byte{0, 1, 2})...)
	var frames [][]byte
	for i := range 2 {
		port := uint16(51000 + i)
		c, s := request, reply
		dp := uint16(80)
		if i == 1 {
			dp = 443
			c = append(buildTLS13ClientHelloRecord("ws.example", "http/1.1"), encryptTLS13AppDataRecord(t, cKey, TLS_AES_128_GCM_SHA256, 0, TLSRecordApplicationData, c)...)
			s = append(buildTLSServerHelloRecord(), encryptTLS13AppDataRecord(t, sKey, TLS_AES_128_GCM_SHA256, 0, TLSRecordApplicationData, s)...)
		}
		// Server direction appears first; split a client frame across TCP packets.
		cut := len(c) - 2
		frames = append(frames, buildEthernetIPv4TCPFrame(server, client, dp, port, 1, 0, TCPFlagACK, s), buildEthernetIPv4TCPFrame(client, server, port, dp, 1, 0, TCPFlagACK, c[:cut]), buildEthernetIPv4TCPFrame(client, server, port, dp, uint32(1+cut), 0, TCPFlagACK, c[cut:]))
	}
	return append(raw, buildPCAPNGFixture(binary.LittleEndian, nil, frames)...)
}

func TestCaptureWebSockets(t *testing.T) {
	raw := wsMixedCapture(t)
	c, e := New(raw)
	if e != nil {
		t.Fatal(e)
	}
	got, e := c.WebSockets(raw)
	if e != nil || len(got) != 4 {
		t.Fatal(got, e)
	}
	for i, r := range got {
		server := i%2 == 1
		if r.IsServer != server || r.IsDecrypted != (i >= 2) || r.FlowIndex != 144+i/2 {
			t.Fatal(r)
		}
		if server {
			if r.DstPort != uint16(51000+i/2) || r.Message.Opcode != 2 || !bytes.Equal(r.Message.Payload, []byte{0, 1, 2}) {
				t.Fatal(r)
			}
		} else if r.SrcPort != uint16(51000+i/2) || r.Message.Opcode != 1 || string(r.Message.Payload) != "sensor" {
			t.Fatal(r)
		}
	}
	c.Secrets = nil
	if got, e := c.WebSockets(raw); e != nil || len(got) != 2 {
		t.Fatal(got, e)
	}
}

func BenchmarkWebSocketsMixed(b *testing.B) {
	raw := wsMixedCapture(b)
	c, e := New(raw)
	if e != nil {
		b.Fatal(e)
	}
	b.ReportAllocs()
	for b.Loop() {
		m, e := c.WebSockets(raw)
		if e != nil || len(m) != 4 {
			b.Fatal(len(m), e)
		}
	}
}

func FuzzWebSocketFrames(f *testing.F) {
	f.Add([]byte{1, 1, 'a', 0x89, 0, 0x80, 1, 'b'})
	f.Add(wsTestFrame(0x81, true, []byte("hello")))
	f.Fuzz(func(t *testing.T, p []byte) {
		m, _ := ParseWebSocketFrames(p)
		if len(m) > MaxWebSocketFramesPerStream {
			t.Fatal(len(m))
		}
		for _, v := range m {
			if len(v.Payload) > MaxHTTPBodyBytes {
				t.Fatal(len(v.Payload))
			}
		}
	})
}

func TestWebSocketCaptureBounds(t *testing.T) {
	client, server := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	run := func(cdata, sdata, tail []byte) ([]WebSocketRecord, error) {
		frames := [][]byte{
			buildEthernetIPv4TCPFrame(client, server, 12345, 80, 1, 0, TCPFlagACK, cdata),
			buildEthernetIPv4TCPFrame(server, client, 80, 12345, 1, 0, TCPFlagACK, sdata),
		}
		if tail != nil {
			frames = append(frames, buildEthernetIPv4TCPFrame(client, server, 12345, 80, uint32(len(cdata)+3), 0, TCPFlagACK, tail))
		}
		raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
		c, err := New(raw)
		if err != nil {
			t.Fatal(err)
		}
		return c.WebSockets(raw)
	}
	serverFrames := append([]byte(wsResponse), wsTestFrame(0x82, false, []byte("ok"))...)
	for _, test := range []struct {
		name         string
		client, tail []byte
	}{
		{"unmasked client", append([]byte(wsRequest), wsTestFrame(0x81, false, []byte("bad"))...), nil},
		{"gap", []byte(wsRequest), wsTestFrame(0x81, true, []byte("gap"))},
		{"missing client handshake", wsTestFrame(0x81, true, []byte("unknown boundary")), nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			m, err := run(test.client, serverFrames, test.tail)
			if err != nil || len(m) != 1 || !m[0].IsServer || string(m[0].Message.Payload) != "ok" {
				t.Fatal(m, err)
			}
		})
	}
	m, err := run(append([]byte(wsRequest), wsTestFrame(0x82, true, nil)...), append([]byte(wsResponse), []byte{0x81, 127, 0, 0, 0, 1, 0, 0, 0, 0}...), nil)
	if !errors.Is(err, ErrWebSocketLimit) || m != nil {
		t.Fatal(m, err)
	}
}

func TestWebSocketCaptureRecordLimit(t *testing.T) {
	var frames [][]byte
	wire := append([]byte(wsRequest), bytes.Repeat(wsTestFrame(0x82, true, nil), MaxWebSocketFramesPerStream)...)
	for i := 0; i <= MaxHTTPMessagesPerScan/MaxWebSocketFramesPerStream; i++ {
		frames = append(frames, buildEthernetIPv4TCPFrame([4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}, uint16(12000+i), 80, 1, 0, TCPFlagACK, wire))
	}
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	if records, err := c.WebSockets(raw); records != nil || !errors.Is(err, ErrWebSocketLimit) {
		t.Fatal(len(records), err)
	}
}
