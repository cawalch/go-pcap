package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestHTTPRequestPacketEvidence(t *testing.T) {
	src, dst := [4]byte{192, 0, 2, 10}, [4]byte{192, 0, 2, 80}
	packet := func(port uint16, seq int, payload []byte) []byte {
		return buildEthernetIPv4TCPFrame(src, dst, 50000, port, uint32(seq), 1, TCPFlagACK, payload)
	}
	first := "GET /one HTTP/1.1\r\nHost: web.example\r\n\r\n"
	second := "GET /two HTTP/1.1\r\nHost: web.example\r\n\r\n"
	one := buildHTTP2Frame(HTTP2FrameHeaders, 0, 1, []byte{0x82})
	continuation := buildHTTP2Frame(HTTP2FrameContinuation, 4, 1, []byte{0x86, 0x84})
	two := buildHTTP2Frame(HTTP2FrameHeaders, 4, 3, []byte{0x82, 0x86, 0x84})
	frames := [][]byte{
		packet(80, 1, []byte(first[:2])),
		packet(81, 1, HTTP2ClientPreface),
		packet(81, 1+len(HTTP2ClientPreface), one[:1]),
		packet(80, 3, []byte(first[2:]+second+second)),
		packet(80, 3, []byte(first[2:]+second+second)), // retransmission
		packet(81, 2+len(HTTP2ClientPreface), bytes.Join([][]byte{one[1:], continuation, two}, nil)),
		packet(80, 2+len(first+second+second), []byte(second)),                   // past a gap
		buildEthernetIPv4TCPFrame(src, dst, 50000, 80, 9000, 0, TCPFlagSYN, nil), // same tuple, new session
		packet(80, 9001, []byte(first)),
	}
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.HTTPRequests(raw)
	if err != nil {
		t.Fatal(err)
	}
	wantPackets := []int{0, 2, 3, 3, 5, 8}
	wantPaths := []string{"/one", "/", "/two", "/two", "/", "/one"}
	wantIDs := []uint32{0, 1, 0, 0, 3, 0}
	if len(got) != len(wantPackets) {
		t.Fatalf("requests: %+v", got)
	}
	for i, r := range got {
		idx := wantPackets[i]
		wantTime := (1700000000+int64(idx))*1e9 + int64(idx+1)*500000
		if r.PacketIndex != idx || r.TimestampNs != wantTime || r.StreamID != wantIDs[i] || r.Path != wantPaths[i] || r.Method != "GET" || (r.FlowIndex == 1) != (r.StreamID != 0) {
			t.Fatalf("request %d: %+v", i, r)
		}
	}
	reader := bytes.NewReader(raw)
	index, err := NewFromReaderAt(reader, int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	other, err := index.HTTPRequestsFromReaderAt(reader)
	if err != nil || !reflect.DeepEqual(got, other) {
		t.Fatalf("ReaderAt: %+v, %v", other, err)
	}
}

func TestHTTPRequestObservationLimit(t *testing.T) {
	// Keep each IPv4 datagram below its size limit.
	const request = "GET / HTTP/1.0\r\n\r\n"
	var frames [][]byte
	seq := 1
	for n := MaxHTTPMessagesPerScan + 1; n > 0; {
		count := min(1000, n)
		body := strings.Repeat(request, count)
		frames = append(frames, buildEthernetIPv4TCPFrame([4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}, 1234, 80, uint32(seq), 1, TCPFlagACK, []byte(body)))
		seq += len(body)
		n -= count
	}
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := c.HTTPRequests(raw)
	if rows != nil || !errors.Is(err, ErrHTTPLimit) {
		t.Fatalf("got %d observations, %v", len(rows), err)
	}
}

func ExampleCapture_HTTPRequests() {
	packet := buildEthernetIPv4TCPFrame([4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}, 53000, 80, 1, 1, TCPFlagACK, []byte("GET /health HTTP/1.1\r\nHost: app.example\r\n\r\n"))
	data := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{packet})
	c, err := New(data)
	if err != nil {
		panic(err)
	}
	rows, err := c.HTTPRequests(data)
	if err != nil {
		panic(err)
	}
	for _, r := range rows {
		fmt.Printf("frame=%d time_ns=%d %s %s%s\n", r.PacketIndex+1, r.TimestampNs, r.Method, r.Authority, r.Path)
	}
	// Output:
	// frame=1 time_ns=1700000000000500000 GET app.example/health
}
