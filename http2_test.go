package pcap

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
)

func buildHTTP2Frame(frameType, flags uint8, streamID uint32, payload []byte) []byte {
	out := make([]byte, 9+len(payload))
	out[0] = byte(len(payload) >> 16)
	out[1] = byte(len(payload) >> 8)
	out[2] = byte(len(payload))
	out[3] = frameType
	out[4] = flags
	binary.BigEndian.PutUint32(out[5:9], streamID&0x7fffffff)
	copy(out[9:], payload)
	return out
}

func TestParseHTTP2FramesAndCaptureHTTP2(t *testing.T) {
	var stream bytes.Buffer
	stream.Write(HTTP2ClientPreface)

	// SETTINGS frame with HEADER_TABLE_SIZE (1) = 65536 and INITIAL_WINDOW_SIZE (4) = 6291456.
	var settingsPayload [12]byte
	binary.BigEndian.PutUint16(settingsPayload[0:2], 1)
	binary.BigEndian.PutUint32(settingsPayload[2:6], 65536)
	binary.BigEndian.PutUint16(settingsPayload[6:8], 4)
	binary.BigEndian.PutUint32(settingsPayload[8:12], 6291456)
	stream.Write(buildHTTP2Frame(HTTP2FrameSettings, 0, 0, settingsPayload[:]))

	// WINDOW_UPDATE frame on stream 0: increment = 15663105.
	var wuPayload [4]byte
	binary.BigEndian.PutUint32(wuPayload[:], 15663105)
	stream.Write(buildHTTP2Frame(HTTP2FrameWindowUpdate, 0, 0, wuPayload[:]))

	// Unpadded DATA frame on stream 1 ("hello ") and padded DATA frame on stream 1 ("world").
	stream.Write(buildHTTP2Frame(HTTP2FrameData, 0, 1, []byte("hello ")))
	paddedData := append([]byte{3}, []byte("world\x00\x00\x00")...)
	stream.Write(buildHTTP2Frame(HTTP2FrameData, 0x08, 1, paddedData))

	sum, err := ParseHTTP2Frames(stream.Bytes())
	if err != nil {
		t.Fatalf("ParseHTTP2Frames() error = %v", err)
	}
	if !sum.HasClientPreface || sum.FrameCount != 4 {
		t.Fatalf("HTTP2Summary = %+v", sum)
	}
	if sum.SettingsFingerprint != "1:65536;4:6291456" {
		t.Fatalf("SettingsFingerprint = %q, want 1:65536;4:6291456", sum.SettingsFingerprint)
	}
	if sum.WindowUpdate != 15663105 {
		t.Fatalf("WindowUpdate = %d, want 15663105", sum.WindowUpdate)
	}
	if len(sum.Streams) != 1 || sum.Streams[0].StreamID != 1 || string(sum.Streams[0].Data) != "hello world" {
		t.Fatalf("Streams = %+v", sum.Streams)
	}

	// Test Capture.HTTP2 over a cleartext h2c TCP stream.
	f1 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 51000, 80, 1, 0, TCPFlagSYN, nil)
	f2 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 51000, 80, 2, 1, TCPFlagPSH|TCPFlagACK, stream.Bytes())
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{f1, f2})
	cap, err := New(raw)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	records, err := cap.HTTP2(raw)
	if err != nil || len(records) != 1 {
		t.Fatalf("Capture.HTTP2() = (%d, %v), want 1", len(records), err)
	}
	if records[0].Summary.SettingsFingerprint != "1:65536;4:6291456" || string(records[0].Summary.Streams[0].Data) != "hello world" {
		t.Fatalf("HTTP2Record = %+v", records[0])
	}

	// Non-HTTP/2 bytes return ErrInvalidHTTP.
	if _, err := ParseHTTP2Frames([]byte("GET / HTTP/1.1\r\n\r\n")); !errors.Is(err, ErrInvalidHTTP) {
		t.Fatalf("ParseHTTP2Frames(HTTP/1.1) err = %v, want ErrInvalidHTTP", err)
	}

	// Server stream starting with >6 SETTINGS, extension frame (ALTSVC 0x0a),
	// per-stream WINDOW_UPDATE (ignored), connection WINDOW_UPDATE, stream-0 DATA (ignored),
	// and stream-1 DATA must all parse cleanly.
	var srv bytes.Buffer
	var bigSettings [48]byte // 8 settings (> 36 bytes)
	for i := range 8 {
		binary.BigEndian.PutUint16(bigSettings[i*6:i*6+2], uint16(i+1))
		binary.BigEndian.PutUint32(bigSettings[i*6+2:i*6+6], uint32(100+i))
	}
	srv.Write(buildHTTP2Frame(HTTP2FrameSettings, 0, 0, bigSettings[:]))
	srv.Write(buildHTTP2Frame(0x0a, 0, 0, []byte("altsvc-ext"))) // extension frame
	var perStreamWU, connWU [4]byte
	binary.BigEndian.PutUint32(perStreamWU[:], 1111)
	binary.BigEndian.PutUint32(connWU[:], 2222)
	srv.Write(buildHTTP2Frame(HTTP2FrameWindowUpdate, 0, 1, perStreamWU[:]))
	srv.Write(buildHTTP2Frame(HTTP2FrameWindowUpdate, 0, 0, connWU[:]))
	srv.Write(buildHTTP2Frame(HTTP2FrameData, 0, 0, []byte("invalid-stream-0")))
	srv.Write(buildHTTP2Frame(HTTP2FrameData, 0, 1, []byte("after-ext")))

	srvSum, err := ParseHTTP2Frames(srv.Bytes())
	if err != nil {
		t.Fatalf("ParseHTTP2Frames(server >6 settings + ext) err = %v", err)
	}
	if len(srvSum.Settings) != 8 || srvSum.WindowUpdate != 2222 || len(srvSum.Streams) != 1 || string(srvSum.Streams[0].Data) != "after-ext" {
		t.Fatalf("srvSum = %+v", srvSum)
	}

	// Non-empty SETTINGS ACK on server stream must be rejected.
	if _, err := ParseHTTP2Frames(buildHTTP2Frame(HTTP2FrameSettings, 0x01, 0, bigSettings[:6])); !errors.Is(err, ErrInvalidHTTP) {
		t.Fatalf("ParseHTTP2Frames(non-empty SETTINGS ACK) err = %v, want ErrInvalidHTTP", err)
	}
}

// Include cleartext and encrypted traffic in the same packet order for each
// key-log case so only the decryption work differs.
func mixedWebCapture(t testing.TB, h2, keyed bool) ([]byte, *Capture) {
	t.Helper()
	body := []byte("hello")
	alpn := "http/1.1"
	req := []byte("POST /sample HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello")
	if h2 {
		alpn = "h2"
		req = append(bytes.Clone(HTTP2ClientPreface), buildHTTP2Frame(HTTP2FrameHeaders, 4, 1, []byte{0x83, 0x87, 0x84})...)
		req = append(req, buildHTTP2Frame(HTTP2FrameData, 1, 1, body)...)
	}
	client, server := [4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}
	var frames [][]byte
	for i := range 32 {
		frames = append(frames, buildEthernetIPv4TCPFrame(client, server, uint16(30000+i), 80, 1, 0, TCPFlagACK, req))
	}
	secret := bytes.Repeat([]byte{0xab}, 32)
	encrypted := encryptTLS13AppDataRecord(t, secret, TLS_AES_128_GCM_SHA256, 0, TLSRecordApplicationData, req)
	hello := append(buildTLS13ClientHelloRecord("example.org", alpn), encrypted...)
	frames = append(frames, buildEthernetIPv4TCPFrame(client, server, 40000, 443, 1, 0, TCPFlagACK, hello), buildEthernetIPv4TCPFrame(server, client, 443, 40000, 1, 0, TCPFlagACK, buildTLSServerHelloAndCertRecords(t)))
	var keys []byte
	if keyed {
		keys = fmt.Appendf(nil, "CLIENT_TRAFFIC_SECRET_0 %x %x\n", bytes.Repeat([]byte{0x42}, 32), secret)
	}
	raw := buildPCAPNGFixture(binary.LittleEndian, keys, frames)
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	return raw, c
}

func TestMixedWebCapture(t *testing.T) {
	for _, keyed := range []bool{false, true} {
		want := 32
		if keyed {
			want++
		}
		raw, c := mixedWebCapture(t, false, keyed)
		records, err := c.HTTP(raw)
		if err != nil || len(records) != want {
			t.Fatalf("HTTP keyed %v: %d, %v", keyed, len(records), err)
		}
		for i, r := range records {
			if r.FlowIndex != i || r.IsDecrypted != (i == 32) || string(r.Request.Body) != "hello" {
				t.Fatalf("HTTP record %d: %+v", i, r)
			}
		}
		raw, c = mixedWebCapture(t, true, keyed)
		h2, err := c.HTTP2(raw)
		if err != nil {
			t.Fatal(err)
		}
		if len(h2) != want {
			t.Fatalf("HTTP2 keyed %v: %d records, want %d", keyed, len(h2), want)
		}
		for i, r := range h2 {
			if !r.Summary.HasClientPreface || r.FlowIndex != i || r.IsDecrypted != (i == 32) || len(r.Summary.Streams) != 1 || string(r.Summary.Streams[0].Data) != "hello" {
				t.Fatalf("HTTP2 record %d: %+v", i, r)
			}
			blocks := r.Summary.Streams[0].HeaderBlocks
			if len(blocks) != 1 || blocks[0].Method != "POST" || blocks[0].Path != "/" {
				t.Fatalf("HTTP/2 transaction on flow %d: %+v", i, blocks)
			}
		}
		for _, scan := range []func() error{
			func() error { _, err := c.HTTP(nil); return err },
			func() error { _, err := c.HTTP2(nil); return err },
		} {
			if err := scan(); !errors.Is(err, ErrInvalidHeader) {
				t.Fatalf("missing PcapNG data: %v", err)
			}
		}
		_, err = c.DecryptedTLSStreams(nil, nil)
		if keyed && !errors.Is(err, ErrInvalidHeader) || !keyed && err != nil {
			t.Fatalf("standalone decryption, keyed %v: %v", keyed, err)
		}
	}
}

// RFC 7541 appendix C.4, across three request streams in one direction.
var rfc7541HuffmanRequests = []string{
	"828684418cf1e3c2e5f23a6ba0ab90f4ff",
	"828684be5886a8eb10649cbf",
	"828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf",
}

func TestHTTP2HPACKRequests(t *testing.T) {
	var wire bytes.Buffer
	wire.Write(HTTP2ClientPreface)
	wire.Write(buildHTTP2Frame(HTTP2FrameSettings, 0, 0, []byte{0, 1, 0, 1, 0, 0}))
	wire.Write(buildHTTP2Frame(HTTP2FrameWindowUpdate, 0, 0, []byte{0, 0, 0, 42}))
	wire.Write(buildHTTP2Frame(HTTP2FramePriority, 0, 3, []byte{128, 0, 0, 0, 200}))
	for i, encoded := range rfc7541HuffmanRequests {
		block, err := hex.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		id := uint32(1 + 2*i)
		wire.Write(buildHTTP2Frame(HTTP2FrameHeaders, 0x28, id, append([]byte{1, 0, 0, 0, 0, 0, block[0]}, 0)))
		wire.Write(buildHTTP2Frame(HTTP2FrameContinuation, 4, id, block[1:]))
	}
	wire.Write(buildHTTP2Frame(HTTP2FrameData, 0, 1, []byte("first")))
	sum, err := ParseHTTP2Frames(wire.Bytes())
	if err != nil || sum.HeadersIncomplete || len(sum.Streams) != 3 || sum.AkamaiFingerprint != "1:65536|42|3:1:0:201|m,s,p,a" {
		t.Fatalf("%+v %v", sum, err)
	}
	for _, st := range sum.Streams {
		if len(st.HeaderBlocks) != 1 || st.HeaderBlocks[0].Authority != "www.example.com" || st.HeaderBlocks[0].Method != "GET" {
			t.Fatal(st)
		}
	}
	if sum.Streams[2].HeaderBlocks[0].Headers[4] != (HTTPHeader{"custom-key", "custom-value"}) || string(sum.Streams[0].Data) != "first" {
		t.Fatal(sum.Streams)
	}
	srv := buildHTTP2Frame(HTTP2FrameSettings, 0, 0, nil)
	srv = append(srv, buildHTTP2Frame(HTTP2FrameHeaders, 4, 1, []byte{0x88})...)
	srv = append(srv, buildHTTP2Frame(HTTP2FrameHeaders, 4, 1, []byte{0x10, 1, 'x', 1, 'y'})...)
	src, dst := [4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{
		buildEthernetIPv4TCPFrame(src, dst, 50000, 80, 1, 0, TCPFlagACK, wire.Bytes()),
		buildEthernetIPv4TCPFrame(dst, src, 80, 50000, 2, 0, TCPFlagACK, srv)})
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := c.HTTP2(raw)
	if err != nil || len(rows) != 2 {
		t.Fatalf("%v %v", rows, err)
	}
	blocks := rows[1].Summary.Streams[0].HeaderBlocks
	if !rows[1].IsServer || len(blocks) != 2 || blocks[0].Status != "200" || blocks[1].Headers[0] != (HTTPHeader{"x", "y"}) {
		t.Fatal(rows)
	}
}

func TestHTTP2HPACKBounds(t *testing.T) {
	// Literal with an indexed name and a value length of 8,193.
	longValue := append([]byte{0x01, 0x7f, 0x82, 0x3f}, bytes.Repeat([]byte{'a'}, MaxHTTPHeaderLineBytes+1)...)
	for _, tc := range []struct {
		name  string
		data  []byte
		limit bool
	}{
		{"oversize-table", []byte{0x3f, 0xe2, 0x1f}, true},
		{"over-field-count", bytes.Repeat([]byte{0x82}, MaxHTTPHeaders+1), true},
		{"over-block-size", make([]byte, MaxHTTP2HeaderBlockBytes+1), true},
		{"over-value-size", longValue, true},
		{"truncated-overlong-value", longValue[:len(longValue)-1], false},
		{"zero-index", []byte{0x80}, false},
		{"bad-index", []byte{0xbe}, false},
		{"integer-overflow", append([]byte{0xff}, bytes.Repeat([]byte{0xff}, 16)...), false},
		{"eos-as-data", []byte{0, 0x84, 255, 255, 255, 255, 0}, false},
		{"bad-padding", []byte{0, 0x81, 0, 0}, false},
		{"late-size-update", []byte{0x82, 0x20}, false},
		{"entry-evicted", []byte{0x20, 0x40, 1, 'a', 1, 'b', 0xbe}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := append(bytes.Clone(HTTP2ClientPreface), buildHTTP2Frame(HTTP2FrameHeaders, 4, 1, tc.data)...)
			s, err := ParseHTTP2Frames(src)
			if tc.limit {
				if !errors.Is(err, ErrHTTPLimit) {
					t.Fatalf("expected limit, got %v", err)
				}
			} else if err != nil || !s.HeadersIncomplete || len(s.Streams) != 0 {
				t.Fatalf("%+v: %v", s, err)
			}
		})
	}
	for _, tail := range [][]byte{nil, buildHTTP2Frame(HTTP2FrameContinuation, 4, 3, []byte{0x84}), buildHTTP2Frame(HTTP2FrameData, 0, 1, []byte("partial"))} {
		src := append(bytes.Clone(HTTP2ClientPreface), buildHTTP2Frame(HTTP2FrameHeaders, 0, 1, []byte{0x82})...)
		s, err := ParseHTTP2Frames(append(src, tail...))
		if err != nil || !s.HeadersIncomplete {
			t.Fatalf("%+v %v", s, err)
		}
	}
}

func TestHTTP2PushPromiseCompressionContext(t *testing.T) {
	src := buildHTTP2Frame(HTTP2FrameSettings, 0, 0, nil)
	src = append(src, buildHTTP2Frame(HTTP2FramePushPromise, 0, 1, []byte{0, 0, 0, 2, 0x40, 1, 'x'})...)
	src = append(src, buildHTTP2Frame(HTTP2FrameContinuation, 4, 1, []byte{1, 'y'})...)
	src = append(src, buildHTTP2Frame(HTTP2FrameHeaders, 4, 1, []byte{0xbe, 0x88})...)
	sum, err := ParseHTTP2Frames(src)
	if err != nil || sum.HeadersIncomplete || len(sum.Streams) != 2 || sum.Streams[0].StreamID != 2 || sum.Streams[1].HeaderBlocks[0].Headers[0] != (HTTPHeader{"x", "y"}) {
		t.Fatalf("%+v %v", sum, err)
	}
}

func TestHTTP2CaptureGapSuppressesDirectionalHeaders(t *testing.T) {
	a, b := [4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}
	first := append(bytes.Clone(HTTP2ClientPreface), buildHTTP2Frame(HTTP2FrameHeaders, 4, 1, []byte{0x82, 0x41, 1, 'a'})...)
	// The missing frame could have inserted a different :authority at index 62.
	last := buildHTTP2Frame(HTTP2FrameHeaders, 4, 3, []byte{0x82, 0xbe})
	response := append(buildHTTP2Frame(HTTP2FrameSettings, 0, 0, nil), buildHTTP2Frame(HTTP2FrameHeaders, 4, 3, []byte{0x88})...)
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{
		buildEthernetIPv4TCPFrame(a, b, 40001, 80, 1, 0, TCPFlagACK, first),
		buildEthernetIPv4TCPFrame(a, b, 40001, 80, uint32(1+len(first)+16), 0, TCPFlagACK, last),
		buildEthernetIPv4TCPFrame(b, a, 80, 40001, 1, 0, TCPFlagACK, response)})
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	r, err := c.HTTP2(raw)
	if err != nil || len(r) != 2 || !r[0].Summary.HeadersIncomplete || r[0].Summary.AkamaiFingerprint != "" || len(r[0].Summary.Streams) != 0 || r[1].Summary.HeadersIncomplete || r[1].Summary.Streams[0].HeaderBlocks[0].Status != "200" {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestHTTP2RolesWithServerFirst(t *testing.T) {
	client, server := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	settings := buildHTTP2Frame(HTTP2FrameSettings, 0, 0, nil)
	for _, preface := range []bool{true, false} {
		clientData := settings
		if preface {
			clientData = append(bytes.Clone(HTTP2ClientPreface), settings...)
		}
		data := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{
			buildEthernetIPv4TCPFrame(server, client, 80, 40000, 99, 10, TCPFlagSYN|TCPFlagACK, nil),
			buildEthernetIPv4TCPFrame(client, server, 40000, 80, 10, 100, TCPFlagACK, clientData),
			buildEthernetIPv4TCPFrame(server, client, 80, 40000, 100, 10, TCPFlagACK, settings),
		})
		c, err := New(data)
		if err != nil {
			t.Fatal(err)
		}
		direct, err := c.HTTP2(data)
		if err != nil {
			t.Fatal(err)
		}
		web, err := c.Web(data)
		if err != nil {
			t.Fatal(err)
		}
		for _, records := range [][]HTTP2Record{direct, web.HTTP2} {
			if len(records) != 2 || records[0].SrcPort != 80 || records[0].IsServer != preface ||
				records[1].SrcPort != 40000 || records[1].IsServer == preface || records[1].Summary.HasClientPreface != preface {
				t.Fatalf("preface %t: %+v", preface, records)
			}
		}
	}
}
