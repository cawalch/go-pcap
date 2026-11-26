package pcap

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"
)

func TestHTTP3FramesFromKeyedCapture(t *testing.T) {
	// Synthetic v1 capture from aioquic 1.3.0 with its own embedded TLS keys.
	// TShark 4.6.10 independently recovered the frame types, lengths, and DATA.
	raw, err := os.ReadFile("testdata/http3-framing.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	connections := keyedQUICBoth(t, raw, nil)
	if len(connections) != 1 {
		t.Fatalf("connections = %d", len(connections))
	}
	for _, tc := range []struct {
		name        string
		packets     []QUIC1RTTPacket
		control     uint64
		headerBytes int
		body        string
	}{
		{"client", connections[0].Client, 2, 22, "request"},
		{"server", connections[0].Server, 3, 3, "response"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			streams, err := keyedQUICStreamData(tc.packets)
			if err != nil {
				t.Fatal(err)
			}
			seen := make(map[HTTP3StreamKind]bool)
			for _, stream := range streams {
				framing, err := ParseHTTP3Stream(stream)
				if err != nil {
					t.Fatalf("stream %d: %v", stream.ID, err)
				}
				seen[framing.Kind] = true
				switch framing.Kind {
				case HTTP3StreamRequest:
					want := []HTTP3Frame{
						{Type: HTTP3FrameHeaders, Offset: 0, PayloadOffset: 2, PayloadLength: tc.headerBytes},
						{Type: HTTP3FrameData, Offset: 2 + tc.headerBytes, PayloadOffset: 4 + tc.headerBytes, PayloadLength: len(tc.body)},
					}
					if framing.ID != 0 || framing.Incomplete || framing.Truncated || !reflect.DeepEqual(framing.Frames, want) {
						t.Fatalf("request stream = %+v", framing)
					}
					frame := framing.Frames[1]
					if data := stream.Data[frame.PayloadOffset : frame.PayloadOffset+frame.PayloadLength]; string(data) != tc.body {
						t.Fatalf("DATA = %q, want %q", data, tc.body)
					}
				case HTTP3StreamControl:
					if framing.ID != tc.control || !framing.Incomplete || framing.Truncated ||
						len(framing.Frames) == 0 || framing.Frames[0] != (HTTP3Frame{Type: HTTP3FrameSettings, Offset: 1, PayloadOffset: 3, PayloadLength: 9}) {
						t.Fatalf("control stream = %+v", framing)
					}
				case HTTP3StreamQPACKEncoder, HTTP3StreamQPACKDecoder:
					if len(framing.Frames) != 0 {
						t.Fatalf("QPACK stream = %+v", framing)
					}
				}
			}
			for _, kind := range []HTTP3StreamKind{HTTP3StreamRequest, HTTP3StreamControl, HTTP3StreamQPACKEncoder, HTTP3StreamQPACKDecoder} {
				if !seen[kind] {
					t.Fatalf("stream kind %d missing", kind)
				}
			}
		})
	}
}

func TestHTTP3StreamKindsAndUnknownFrames(t *testing.T) {
	got, err := ParseHTTP3Stream(QUICStream{ID: 7, Complete: true, Data: []byte{1, 0x40, 0x44, 0x40, 0x21, 1, 'x', 1, 0}})
	want := HTTP3Stream{
		ID: 7, Kind: HTTP3StreamPush, StreamType: 1, PushID: 68, HeaderLength: 3,
		Frames: []HTTP3Frame{
			{Type: 0x21, Offset: 3, PayloadOffset: 6, PayloadLength: 1},
			{Type: HTTP3FrameHeaders, Offset: 7, PayloadOffset: 9},
		},
	}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("push stream = %+v, %v", got, err)
	}
	got, err = ParseHTTP3Stream(QUICStream{ID: 2, Data: []byte{0x40, 0x41, 0xff}})
	if err != nil || got.Kind != HTTP3StreamUnknown || got.StreamType != 65 ||
		got.HeaderLength != 2 || !got.Incomplete || got.Truncated || len(got.Frames) != 0 {
		t.Fatalf("extension stream = %+v, %v", got, err)
	}
}

func TestHTTP3TruncatedStream(t *testing.T) {
	for _, tc := range []struct {
		name   string
		stream QUICStream
		frames int
	}{
		{"stream type", QUICStream{ID: 2, Data: []byte{0x40}, Gap: true}, 0},
		{"push ID", QUICStream{ID: 3, Data: []byte{1, 0x40}, Reset: true}, 0},
		{"frame type", QUICStream{Data: []byte{1, 0, 0x80}}, 1},
		{"frame length", QUICStream{Data: []byte{1, 0, 0, 0x40}, Gap: true}, 1},
		{"payload", QUICStream{Data: []byte{1, 0, 0, 2, 'x'}, Reset: true}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseHTTP3Stream(tc.stream)
			if err != nil || !got.Truncated || !got.Incomplete || len(got.Frames) != tc.frames {
				t.Fatalf("incomplete stream = %+v, %v", got, err)
			}
			tc.stream.Complete, tc.stream.Gap, tc.stream.Reset = true, false, false
			if got, err := ParseHTTP3Stream(tc.stream); got.Frames != nil || !errors.Is(err, ErrInvalidHTTP3) {
				t.Fatalf("clean FIN = %+v, %v", got, err)
			}
		})
	}
	got, err := ParseHTTP3Stream(QUICStream{Data: []byte{1, 0}, Gap: true})
	if err != nil || !got.Incomplete || got.Truncated || len(got.Frames) != 1 {
		t.Fatalf("gap after frame boundary = %+v, %v", got, err)
	}
}

func TestHTTP3PlacementAndLimits(t *testing.T) {
	for _, tc := range []struct {
		stream QUICStream
		want   error
	}{
		{QUICStream{ID: 1}, ErrInvalidHTTP3},
		{QUICStream{ID: 1 << 62}, ErrInvalidHTTP3},
		{QUICStream{ID: 2, Data: []byte{1, 0}}, ErrInvalidHTTP3},
		{QUICStream{ID: 3, Data: []byte{1, 0, HTTP3FramePushPromise, 0}}, ErrInvalidHTTP3},
		{QUICStream{ID: 2, Data: []byte{0}, Complete: true}, ErrInvalidHTTP3},
		{QUICStream{ID: 2, Data: []byte{0, HTTP3FrameGoAway, 0}}, ErrInvalidHTTP3},
		{QUICStream{ID: 2, Data: []byte{0, HTTP3FrameSettings, 0, HTTP3FrameSettings, 0}}, ErrInvalidHTTP3},
		{QUICStream{ID: 2, Data: []byte{0, HTTP3FrameSettings, 0, HTTP3FrameData, 0}}, ErrInvalidHTTP3},
		{QUICStream{Data: []byte{HTTP3FrameSettings, 0}}, ErrInvalidHTTP3},
		{QUICStream{Data: []byte{0x06, 0}}, ErrInvalidHTTP3},
		{QUICStream{Data: make([]byte, MaxQUICStreamBytes+1)}, ErrHTTP3Limit},
		{QUICStream{Data: appendQUICStreamTestVarint([]byte{HTTP3FrameData}, 1<<62-1)}, ErrHTTP3Limit},
		{QUICStream{Data: bytes.Repeat([]byte{HTTP3FrameData, 0}, MaxHTTP3FramesPerStream+1)}, ErrHTTP3Limit},
	} {
		if got, err := ParseHTTP3Stream(tc.stream); got.Frames != nil || !errors.Is(err, tc.want) {
			t.Fatalf("stream ID %d length %d = %+v, %v, want %v", tc.stream.ID, len(tc.stream.Data), got, err, tc.want)
		}
	}
	exact := bytes.Repeat([]byte{HTTP3FrameData, 0}, MaxHTTP3FramesPerStream)
	got, err := ParseHTTP3Stream(QUICStream{Data: exact, Complete: true})
	if err != nil || len(got.Frames) != MaxHTTP3FramesPerStream {
		t.Fatalf("exact frame limit = %d frames, %v", len(got.Frames), err)
	}
}

func FuzzParseHTTP3Stream(f *testing.F) {
	f.Add(uint64(0), []byte{1, 0, 0, 2, 'x'}, false)
	f.Add(uint64(3), []byte{0, 4, 0}, true)
	f.Add(uint64(7), []byte{1, 0, 1, 0}, true)
	f.Fuzz(func(t *testing.T, id uint64, data []byte, complete bool) {
		out, err := ParseHTTP3Stream(QUICStream{ID: id, Data: data, Complete: complete})
		if err != nil && len(out.Frames) > 0 {
			t.Fatal("partial frames on error")
		}
		offset := out.HeaderLength
		for _, frame := range out.Frames {
			if frame.Offset != offset || frame.PayloadOffset < frame.Offset ||
				frame.PayloadLength > len(data)-frame.PayloadOffset {
				t.Fatal("invalid frame range")
			}
			offset = frame.PayloadOffset + frame.PayloadLength
		}
	})
}

func BenchmarkParseHTTP3Stream(b *testing.B) {
	frame := append([]byte{HTTP3FrameData, 0x41, 0}, make([]byte, 256)...)
	data := append([]byte{HTTP3FrameHeaders, 2, 0, 0}, bytes.Repeat(frame, 256)...)
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	for b.Loop() {
		result, err := ParseHTTP3Stream(QUICStream{Data: data, Complete: true})
		if err != nil || len(result.Frames) != 257 {
			b.Fatalf("framing failed: %v", err)
		}
	}
}

func ExampleParseHTTP3Stream() {
	// Data starts at offset zero after directional QUIC reassembly.
	stream := QUICStream{ID: 0, Data: []byte{1, 2, 0, 0, 0, 2, 'o', 'k'}, Complete: true}
	parsed, err := ParseHTTP3Stream(stream)
	if err != nil {
		panic(err)
	}
	for _, frame := range parsed.Frames {
		if frame.Type == HTTP3FrameData {
			fmt.Println(string(stream.Data[frame.PayloadOffset : frame.PayloadOffset+frame.PayloadLength]))
		}
	}
	// Output:
	// ok
}
