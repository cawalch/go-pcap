package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestQUICStreamIndependentPackets(t *testing.T) {
	vectors, err := readQUIC1RTTVectors()
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors {
		if !strings.HasPrefix(v.Name, "version_") {
			continue
		}
		t.Run(v.Name, func(t *testing.T) {
			decoder, err := v.decoder()
			if err != nil {
				t.Fatal(err)
			}
			_, packet, err := decoder.Open(v.Packet, v.DestinationCID, v.ExpectedNumber)
			if err != nil {
				t.Fatal(err)
			}
			streams, err := ReassembleQUIC1RTTStreams([][]byte{packet})
			if err != nil || len(streams) != 1 {
				t.Fatalf("streams = %v, %v", streams, err)
			}
			clear(packet)
			s := streams[0]
			if s.ID != 0 || string(s.Data) != "fixture-"+v.Name || !s.Complete || s.Gap || s.Reset {
				t.Fatalf("stream = %+v", s)
			}
		})
	}
}

func TestQUICStreamOrderingAndBoundaries(t *testing.T) {
	tail := []byte{0x0f, 0x04, 0x04, 0x02, 'e', 'f'}
	packets := [][]byte{
		tail,
		{0x0a, 0x04, 0x05, 'a', 'b', 'c', 'd', 'e', 0x0d, 0x01, 0x04, 'g'},
		tail,
		{0x0a, 0x01, 0x02, 'a', 'b', 0x04, 0x03, 0x00, 0x04},
		{0x0a, 0x03, 0x02, 'x', 'y', 0x0b, 0x08, 0x00},
		{0x08, 0x09, 'u'},
		{0x0b, 0x0a, 0x01, 'v', 0x04, 0x0a, 0x00, 0x01},
	}
	want := []QUICStream{
		{ID: 1, Data: []byte("ab"), Gap: true},
		{ID: 3, Data: []byte("xy"), Gap: true, Reset: true},
		{ID: 4, Data: []byte("abcdef"), Complete: true},
		{ID: 8, Complete: true},
		{ID: 9, Data: []byte("u")},
		{ID: 10, Data: []byte("v"), Reset: true},
	}
	for range 2 {
		got, err := ReassembleQUIC1RTTStreams(packets)
		equal := slices.EqualFunc(got, want, func(a, b QUICStream) bool {
			return a.ID == b.ID && bytes.Equal(a.Data, b.Data) &&
				a.Gap == b.Gap && a.Complete == b.Complete && a.Reset == b.Reset
		})
		if err != nil || !equal {
			t.Fatalf("streams = %+v, %v", got, err)
		}
		slices.Reverse(packets)
	}
}

func TestQUICStreamSkipsControlFrames(t *testing.T) {
	packet := []byte{
		0x00, 0x01,
		0x02, 3, 0, 1, 0, 0, 0, // ACK with one extra range.
		0x03, 3, 0, 0, 0, 0, 0, 0, // ACK_ECN.
		0x05, 0, 0, 0x06, 0, 1, 'x', 0x07, 1, 'x',
		0x10, 0, 0x11, 0, 0, 0x12, 0, 0x13, 0, 0x14, 0, 0x15, 0, 0,
		0x16, 0, 0x17, 0,
		0x18, 1, 0, 1, 'c', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0x19, 0,
		0x1a, 0, 0, 0, 0, 0, 0, 0, 0,
		0x1b, 0, 0, 0, 0, 0, 0, 0, 0,
		0x1c, 0, 0, 1, 'x', 0x1d, 0, 1, 'x',
		0x1e, 0x31, 2, 0x0b, 0xff,
		0x0b, 0, 2, 'o', 'k',
		0x30, 0x0b, 0xff, // The remainder is DATAGRAM data.
	}
	got, err := ReassembleQUIC1RTTStreams([][]byte{packet})
	if err != nil || len(got) != 1 || !got[0].Complete || string(got[0].Data) != "ok" {
		t.Fatalf("streams = %+v, %v", got, err)
	}
}

// QUIC frame fields allow a longer varint representation. Frame types have
// their own requirement to use the shortest representation.
func appendQUICStreamTestVarint(b []byte, v uint64) []byte {
	return binary.BigEndian.AppendUint64(b, v|0xc000000000000000)
}

func TestQUICStreamRejectsInconsistentInput(t *testing.T) {
	for _, tc := range []struct {
		name    string
		packets [][]byte
	}{
		{"empty payload", [][]byte{nil}},
		{"partial stream", [][]byte{{0x0a, 0, 2, 'a'}, {0x01}}},
		{"partial ACK", [][]byte{{0x03, 0, 0, 0, 0, 0}}},
		{"partial connection ID", [][]byte{{0x18, 1, 0, 1, 0}}},
		{"invalid connection ID length", [][]byte{{0x18, 1, 0, 0}}},
		{"unknown frame", [][]byte{{0x0b, 0, 1, 'a', 0x1f}}},
		{"nonminimal frame type", [][]byte{{0x40, 0x01}}},
		{"conflicting overlap", [][]byte{{0x0e, 0, 4, 2, 'a', 'b'}, {0x0e, 0, 5, 1, 'c'}}},
		{"conflicting FIN", [][]byte{{0x0f, 0, 2, 0}, {0x0f, 0, 3, 0}}},
		{"late size below data", [][]byte{{0x0a, 0, 2, 'a', 'b'}, {0x04, 0, 0, 1}}},
		{"late data beyond final size", [][]byte{{0x04, 0, 0, 1}, {0x0a, 0, 2, 'a', 'b'}}},
		{"offset overflow", [][]byte{append(appendQUICStreamTestVarint([]byte{0x0e, 0}, quicPacketNumberLimit-1), 1, 'a')}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := ReassembleQUIC1RTTStreams(tc.packets)
			if out != nil || !errors.Is(err, ErrInvalidQUIC) {
				t.Fatalf("streams = %+v, %v", out, err)
			}
		})
	}
}

func TestQUICStreamLimits(t *testing.T) {
	padded := make([]byte, maxQUICUDPPayloadBytes)
	overBytes := make([][]byte, MaxQUICStreamInputBytes/len(padded)+1)
	for i := range overBytes {
		overBytes[i] = padded
	}
	var overStreams []byte
	for i := range MaxQUICStreams + 1 {
		overStreams = appendQUICStreamTestVarint(append(overStreams, 0x0b), uint64(i))
		overStreams = append(overStreams, 0)
	}
	overFrames := bytes.Repeat([]byte{0x0b, 0, 0}, MaxQUICStreamFrames+1)
	for _, tc := range []struct {
		name    string
		packets [][]byte
	}{
		{"packet count", make([][]byte, MaxQUICStreamPackets+1)},
		{"packet size", [][]byte{make([]byte, maxQUICUDPPayloadBytes+1)}},
		{"total bytes", overBytes},
		{"stream count", [][]byte{overStreams}},
		{"frame count", [][]byte{overFrames}},
		{"stream size", [][]byte{appendQUICStreamTestVarint([]byte{0x04, 0, 0}, MaxQUICStreamBytes+1)}},
		{"ACK ranges", [][]byte{appendQUICStreamTestVarint([]byte{0x02, 0, 0}, 257)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := ReassembleQUIC1RTTStreams(tc.packets)
			if out != nil || !errors.Is(err, ErrQUICLimit) {
				t.Fatalf("streams = %+v, %v", out, err)
			}
		})
	}
	sparse := append(appendQUICStreamTestVarint([]byte{0x0f, 0}, MaxQUICStreamBytes-1), 1, 'a')
	out, err := ReassembleQUIC1RTTStreams([][]byte{sparse})
	if err != nil || len(out) != 1 || !out[0].Gap || out[0].Complete || len(out[0].Data) > 0 {
		t.Fatalf("sparse stream = %+v, %v", out, err)
	}
}

func FuzzReassembleQUIC1RTTStreams(f *testing.F) {
	f.Add([]byte{0x0a, 0, 2, 'a', 'b'}, []byte{0x0d, 0, 2, 'c'})
	f.Add([]byte{0x04, 1, 0, 4}, []byte{0x0e, 1, 3, 1, 'x'})
	f.Fuzz(func(t *testing.T, a, b []byte) {
		out, err := ReassembleQUIC1RTTStreams([][]byte{a, b})
		if err != nil && out != nil {
			t.Fatal("partial streams on error")
		}
		for i, stream := range out {
			if stream.Complete && (stream.Gap || stream.Reset) ||
				len(stream.Data) > MaxQUICStreamBytes ||
				i > 0 && out[i-1].ID >= stream.ID {
				t.Fatal("invalid stream state")
			}
		}
	})
}

func BenchmarkReassembleQUIC1RTTStreams(b *testing.B) {
	const payloadSize = 1024
	payload := make([]byte, payloadSize)
	packets := make([][]byte, 64)
	for i := range packets {
		header := appendQUICStreamTestVarint([]byte{0x0c, 0}, uint64(i*payloadSize))
		packets[i] = append(header, payload...)
	}
	packets[len(packets)-1][0] |= 0x01
	slices.Reverse(packets)
	b.ReportAllocs()
	b.SetBytes(int64(len(packets) * payloadSize))
	for b.Loop() {
		out, err := ReassembleQUIC1RTTStreams(packets)
		if err != nil || len(out) != 1 || !out[0].Complete {
			b.Fatalf("reassembly failed: %v", err)
		}
	}
}

func ExampleReassembleQUIC1RTTStreams() {
	// These are two authenticated packet payloads for the same sender.
	packets := [][]byte{
		{0x0d, 0, 3, 'l', 'o'},
		{0x0a, 0, 3, 'h', 'e', 'l'},
	}
	streams, err := ReassembleQUIC1RTTStreams(packets)
	if err != nil {
		panic(err)
	}
	for _, stream := range streams {
		fmt.Printf("stream %d complete=%t data=%q\n", stream.ID, stream.Complete, stream.Data)
	}
	// Output:
	// stream 0 complete=true data="hello"
}
