package pcap

import (
	"bytes"
	"os"
	"reflect"
	"testing"
)

func observedHTTP2Frames(t *testing.T, stream []byte, gap bool) (HTTP2Summary, []http2FrameEvent) {
	t.Helper()
	remaining := MaxHTTP2DecodedHeaderBytes
	var events []http2FrameEvent
	sum, err := readHTTP2Frames(stream, &remaining, gap, nil, func(event http2FrameEvent) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return sum, events
}

func TestHTTP2FrameCapture(t *testing.T) {
	raw, err := os.ReadFile("testdata/deployments/http2-frames.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	streams, err := c.Streams(raw)
	if err != nil || len(streams) != 1 {
		t.Fatalf("Streams = %d, %v", len(streams), err)
	}

	request := func(method string) HTTP2HeaderBlock {
		return HTTP2HeaderBlock{
			Method: method, Scheme: "http", Path: "/", Authority: "trace.example",
			Headers: []HTTPHeader{{":method", method}, {":scheme", "http"}, {":path", "/"}, {":authority", "trace.example"}},
		}
	}
	for _, tc := range []struct {
		name   string
		stream StreamBuffer
		events []http2FrameEvent
		body   string
	}{
		{
			name: "client", stream: streams[0].Client, body: "pcap",
			events: []http2FrameEvent{
				{frame: http2Range{24, 33}, kind: HTTP2FrameSettings},
				{frame: http2Range{33, 42}, kind: HTTP2FrameSettings, flags: 1},
				{frame: http2Range{42, 69}, kind: HTTP2FrameHeaders, flags: 4, streamID: 1,
					header: http2HeaderEvent{block: request("POST"), start: 42, streamID: 1, kind: HTTP2FrameHeaders}},
				{frame: http2Range{69, 80}, kind: HTTP2FrameHeaders, flags: 1, streamID: 3},
				{frame: http2Range{80, 91}, kind: HTTP2FrameContinuation, flags: 4, streamID: 3, endStream: true,
					header: http2HeaderEvent{block: request("GET"), start: 69, streamID: 3, kind: HTTP2FrameHeaders}},
				{frame: http2Range{91, 107}, kind: HTTP2FrameData, flags: 9, streamID: 1, endStream: true, data: http2Range{101, 105}},
			},
		},
		{
			name: "server", stream: streams[0].Server, body: "ok",
			events: []http2FrameEvent{
				{frame: http2Range{0, 9}, kind: HTTP2FrameSettings},
				{frame: http2Range{9, 18}, kind: HTTP2FrameSettings, flags: 1},
				{frame: http2Range{18, 28}, kind: HTTP2FrameHeaders, flags: 5, streamID: 3, endStream: true,
					header: http2HeaderEvent{block: HTTP2HeaderBlock{Status: "204", Headers: []HTTPHeader{{":status", "204"}}},
						start: 18, streamID: 3, kind: HTTP2FrameHeaders}},
				{frame: http2Range{28, 38}, kind: HTTP2FrameHeaders, flags: 4, streamID: 1,
					header: http2HeaderEvent{block: HTTP2HeaderBlock{Status: "200", Headers: []HTTPHeader{{":status", "200"}}},
						start: 28, streamID: 1, kind: HTTP2FrameHeaders}},
				{frame: http2Range{38, 49}, kind: HTTP2FrameData, flags: 1, streamID: 1, endStream: true, data: http2Range{47, 49}},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sum, got := observedHTTP2Frames(t, tc.stream.Data, tc.stream.Anomalies.SequenceGap)
			if sum.HeadersIncomplete || sum.FrameCount != len(tc.events) || len(got) != len(tc.events) {
				t.Fatalf("Summary = %+v, %d events, want %d complete frames", sum, len(got), len(tc.events))
			}
			for i, want := range tc.events {
				if !reflect.DeepEqual(got[i], want) {
					t.Errorf("Event %d = %+v, want %+v", i, got[i], want)
				}
			}
			data := got[len(got)-1].data
			if body := string(tc.stream.Data[data.start:data.end]); body != tc.body {
				t.Errorf("Body = %q, want %q", body, tc.body)
			}
		})
	}
}

func TestHTTP2FrameEndSignals(t *testing.T) {
	stream := bytes.Clone(HTTP2ClientPreface)
	stream = append(stream, buildHTTP2Frame(HTTP2FrameHeaders, 0, 1, []byte{0x82})...)
	// CONTINUATION ignores the bit used for END_STREAM by HEADERS and DATA.
	stream = append(stream, buildHTTP2Frame(HTTP2FrameContinuation, 5, 1, []byte{0x84})...)
	stream = append(stream, buildHTTP2Frame(HTTP2FrameRSTStream, 0, 1, []byte{0, 0, 0, 8})...)
	stream = append(stream, buildHTTP2Frame(HTTP2FrameGoAway, 0, 0, []byte{0, 0, 0, 1, 0, 0, 0, 0})...)
	stream = append(stream, buildHTTP2Frame(HTTP2FrameData, 9, 3, []byte{2, 0, 0})...)
	sum, events := observedHTTP2Frames(t, stream, false)
	if sum.HeadersIncomplete || len(events) != 5 {
		t.Fatalf("Summary = %+v, events = %+v", sum, events)
	}
	if events[1].header.block.Method != "GET" || events[1].endStream ||
		events[2].kind != HTTP2FrameRSTStream || events[2].streamID != 1 || events[2].frame != (http2Range{44, 57}) || events[2].endStream ||
		events[3].kind != HTTP2FrameGoAway || events[3].endStream {
		t.Errorf("Continuation, reset or GOAWAY events = %+v", events[1:4])
	}
	if e := events[4]; !e.endStream || e.streamID != 3 || e.data != (http2Range{84, 84}) {
		t.Errorf("Empty padded END_STREAM DATA = %+v", e)
	}
}

func TestHTTP2FramePushPromise(t *testing.T) {
	stream := buildHTTP2Frame(HTTP2FrameSettings, 0, 0, nil)
	stream = append(stream, buildHTTP2Frame(HTTP2FramePushPromise, 1, 1, []byte{0, 0, 0, 2, 0x82})...)
	stream = append(stream, buildHTTP2Frame(HTTP2FrameContinuation, 4, 1, []byte{0x84})...)
	sum, events := observedHTTP2Frames(t, stream, false)
	if sum.HeadersIncomplete || len(events) != 3 {
		t.Fatalf("Summary = %+v, events = %+v", sum, events)
	}
	e := events[2]
	if e.frame != (http2Range{23, 33}) || e.streamID != 1 || e.endStream || e.header.start != 9 ||
		e.header.streamID != 2 || e.header.kind != HTTP2FramePushPromise || e.header.block.Method != "GET" {
		t.Errorf("Completed push promise = %+v", e)
	}
}

func TestHTTP2FrameVisitorStops(t *testing.T) {
	settings := buildHTTP2Frame(HTTP2FrameSettings, 0, 0, nil)
	open := buildHTTP2Frame(HTTP2FrameHeaders, 1, 1, []byte{0x82})
	data := buildHTTP2Frame(HTTP2FrameData, 1, 1, []byte("a body"))
	next := buildHTTP2Frame(HTTP2FrameHeaders, 5, 3, []byte{0x82})
	for _, tc := range []struct {
		name              string
		frames            [][]byte
		gap               bool
		headersIncomplete bool
		events            int
		end               int
	}{
		{"missing continuation", [][]byte{open}, false, true, 2, 19},
		{"interrupted continuation", [][]byte{open, data, next}, false, true, 2, 19},
		{"wrong stream continuation", [][]byte{open, buildHTTP2Frame(HTTP2FrameContinuation, 4, 3, []byte{0x84}), next}, false, true, 2, 19},
		{"truncated continuation", [][]byte{open, buildHTTP2Frame(HTTP2FrameContinuation, 4, 1, []byte{0x84})[:9]}, false, true, 2, 19},
		{"truncated frame header", [][]byte{data[:6]}, false, false, 1, 9},
		{"truncated DATA", [][]byte{data[:len(data)-1]}, false, false, 1, 9},
		{"invalid HPACK index", [][]byte{buildHTTP2Frame(HTTP2FrameHeaders, 5, 1, []byte{0xbe}), data, next}, false, true, 1, 9},
		{"invalid DATA padding", [][]byte{buildHTTP2Frame(HTTP2FrameData, 8, 1, []byte{1}), data}, false, false, 1, 9},
		{"short reset", [][]byte{buildHTTP2Frame(HTTP2FrameRSTStream, 0, 1, []byte{0, 0, 8}), data}, false, false, 1, 9},
		{"connection reset", [][]byte{buildHTTP2Frame(HTTP2FrameRSTStream, 0, 0, []byte{0, 0, 0, 8}), data}, false, false, 1, 9},
		{"sequence gap", [][]byte{data, next}, true, true, 0, 0},
		{"frame limit", [][]byte{bytes.Repeat(settings, MaxHTTP2FramesPerStream-1), data}, false, false, MaxHTTP2FramesPerStream, 9 * MaxHTTP2FramesPerStream},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stream := append(bytes.Clone(settings), bytes.Join(tc.frames, nil)...)
			sum, events := observedHTTP2Frames(t, stream, tc.gap)
			if sum.HeadersIncomplete != tc.headersIncomplete || len(events) != tc.events {
				t.Fatalf("HeadersIncomplete = %v, %d events, want %v, %d", sum.HeadersIncomplete, len(events), tc.headersIncomplete, tc.events)
			}
			end := 0
			for _, e := range events {
				if e.endStream || e.header.streamID != 0 {
					t.Errorf("Unexpected confirmation = %+v", e)
				}
				end = e.frame.end
			}
			if end != tc.end {
				t.Errorf("Last visited byte = %d out of %d, want %d", end, len(stream), tc.end)
			}
		})
	}
}
