package pcap

import (
	"bytes"
	"slices"
	"testing"
)

func TestReassembleTCPContiguousAtWrap(t *testing.T) {
	const base uint32 = 0xfffffff8
	const payload = "hello world!"
	var segments []TCPSegmentInput
	type write struct {
		packet int
		end    int
		seq    uint32
		gap    bool
	}
	var wanted []write
	for i := range len(payload) {
		seq := base + uint32(i)
		segment := TCPSegmentInput{Seq: seq, Payload: []byte{payload[i]}, InvalidChecksum: i == 1}
		if i == 0 {
			segment.Seq--
			segment.Flags = TCPFlagSYN
		} else if i%4 == 0 {
			segments = append(segments, TCPSegmentInput{Flags: TCPFlagACK})
		}
		wanted = append(wanted, write{len(segments), i + 1, seq, false})
		segments = append(segments, segment)
	}

	for _, limit := range []int{len(payload), len(payload) - 1} {
		var writes []write
		got, used, err := reassembleTCPWithBudget(segments, int64(limit), func(packet, end int, seq uint32, gap bool) {
			writes = append(writes, write{packet, end, seq, gap})
		})
		wantAnomalies := StreamAnomalies{Truncated: limit < len(payload)}
		if err != nil || !bytes.Equal(got.Data, []byte(payload[:limit])) || used != int64(limit) ||
			got.Anomalies != wantAnomalies || got.GapCount != 0 || got.OverlapCount != 0 ||
			!slices.Equal(writes, wanted[:limit]) {
			t.Fatalf("limit %d: reassembly = %+v, %d bytes, %v, writes = %+v", limit, got, used, err, writes)
		}
	}
}

func BenchmarkReassembleTCPBatch(b *testing.B) {
	payload := make([]byte, 100)
	segments := make([]TCPSegmentInput, 2000)
	for i := range segments {
		segments[i] = TCPSegmentInput{Seq: uint32(i * len(payload)), Payload: payload}
	}
	for _, reverseTail := range []bool{false, true} {
		name := "InOrder"
		input := segments
		if reverseTail {
			name = "ReorderedTail"
			input = slices.Clone(segments)
			last := len(input) - 1
			input[last-1], input[last] = input[last], input[last-1]
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				stream, err := ReassembleTCP(input)
				if err != nil || len(stream.Data) != len(input)*len(payload) {
					b.Fatalf("reassembly = %d bytes, %v", len(stream.Data), err)
				}
			}
		})
	}
}
