package pcap

import (
	"bytes"
	"encoding/binary"
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
		req = append(bytes.Clone(HTTP2ClientPreface), buildHTTP2Frame(HTTP2FrameData, 1, 1, body)...)
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
		var seen int
		for _, r := range h2 {
			if !r.Summary.HasClientPreface {
				continue
			}
			if r.FlowIndex != seen || r.IsDecrypted != (seen == 32) || len(r.Summary.Streams) != 1 || string(r.Summary.Streams[0].Data) != "hello" {
				t.Fatalf("HTTP2 record %d: %+v", seen, r)
			}
			seen++
		}
		if seen != want {
			t.Fatalf("HTTP2 keyed %v: %d records, want %d", keyed, seen, want)
		}
	}
}
