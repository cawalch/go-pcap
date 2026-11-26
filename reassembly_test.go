package pcap

import (
	"encoding/binary"
	"errors"
	"testing"
)

func TestReassembleTCPOutOfOrderGapAndOverlapConflict(t *testing.T) {
	// 1. Out-of-order segments with SYN.
	segs := []TCPSegmentInput{
		{Seq: 1000, Flags: TCPFlagSYN, Payload: nil},
		{Seq: 1006, Flags: TCPFlagACK, Payload: []byte("world")},
		{Seq: 1001, Flags: TCPFlagACK, Payload: []byte("hello")},
	}
	res, err := ReassembleTCP(segs)
	if err != nil {
		t.Fatalf("ReassembleTCP() err = %v", err)
	}
	if string(res.Data) != "helloworld" || res.Anomalies.Any() {
		t.Fatalf("ReassembleTCP() = (%q, %+v), want (\"helloworld\", no anomalies)", res.Data, res.Anomalies)
	}

	// 2. Identical retransmission sets Retransmission but NOT OverlapConflict.
	retransSegs := []TCPSegmentInput{
		{Seq: 10, Flags: TCPFlagSYN},
		{Seq: 11, Flags: TCPFlagACK, Payload: []byte("abcdef")},
		{Seq: 11, Flags: TCPFlagACK, Payload: []byte("abcdef")},
	}
	resRetrans, err := ReassembleTCP(retransSegs)
	if err != nil {
		t.Fatalf("ReassembleTCP(retrans) err = %v", err)
	}
	if string(resRetrans.Data) != "abcdef" || !resRetrans.Anomalies.Retransmission || resRetrans.Anomalies.OverlapConflict {
		t.Fatalf("ReassembleTCP(retrans) = (%q, %+v)", resRetrans.Data, resRetrans.Anomalies)
	}

	// 3. Conflicting overlapping segment retains first-seen bytes and sets OverlapConflict.
	conflictSegs := []TCPSegmentInput{
		{Seq: 10, Flags: TCPFlagSYN},
		{Seq: 11, Flags: TCPFlagACK, Payload: []byte("SAFE_COMMAND")},
		{Seq: 11, Flags: TCPFlagACK, Payload: []byte("EVIL_PAYLOAD_TAIL")},
	}
	resConflict, err := ReassembleTCP(conflictSegs)
	if err != nil {
		t.Fatalf("ReassembleTCP(conflict) err = %v", err)
	}
	if string(resConflict.Data) != "SAFE_COMMAND_TAIL" || !resConflict.Anomalies.OverlapConflict {
		t.Fatalf("ReassembleTCP(conflict) = (%q, %+v), want first-seen prefix + OverlapConflict", resConflict.Data, resConflict.Anomalies)
	}

	// 4. Sequence gap + midstream pickup.
	gapSegs := []TCPSegmentInput{
		{Seq: 500, Flags: TCPFlagACK, Payload: []byte("part1")},
		{Seq: 510, Flags: TCPFlagACK, Payload: []byte("part2")},
	}
	resGap, err := ReassembleTCP(gapSegs)
	if err != nil {
		t.Fatalf("ReassembleTCP(gap) err = %v", err)
	}
	if string(resGap.Data) != "part1part2" || !resGap.Anomalies.MidstreamPickup || !resGap.Anomalies.SequenceGap || resGap.GapBytes != 5 {
		t.Fatalf("ReassembleTCP(gap) = (%q, gapBytes=%d, %+v)", resGap.Data, resGap.GapBytes, resGap.Anomalies)
	}
}

func TestReassembleTCPLimits(t *testing.T) {
	tooMany := make([]TCPSegmentInput, MaxSegmentsPerFlow+1)
	if _, err := ReassembleTCP(tooMany); !errors.Is(err, ErrReassemblyLimit) {
		t.Fatalf("ReassembleTCP(tooMany) err = %v, want ErrReassemblyLimit", err)
	}

	segs := []TCPSegmentInput{
		{Seq: 1, Flags: TCPFlagSYN},
		{Seq: 2, Flags: TCPFlagACK, Payload: []byte("0123456789abcdef")},
	}
	buf, used, err := reassembleTCPWithBudget(segs, 6, nil)
	if err != nil {
		t.Fatalf("reassembleTCPWithBudget() err = %v", err)
	}
	if used != 6 || string(buf.Data) != "012345" || !buf.Anomalies.Truncated {
		t.Fatalf("reassembleTCPWithBudget(6) = (%q, used=%d, %+v)", buf.Data, used, buf.Anomalies)
	}
}

func TestMidstreamSequenceOrder(t *testing.T) {
	for _, start := range []uint32{100, 0xfffffffe} {
		for _, reverse := range []bool{false, true} {
			segs := []TCPSegmentInput{{Seq: start, Payload: []byte("abc")}, {Seq: start + 3, Payload: []byte("def")}}
			if reverse {
				segs[0], segs[1] = segs[1], segs[0]
			}
			want := StreamAnomalies{MidstreamPickup: true}
			buf, err := ReassembleTCP(segs)
			if err != nil || string(buf.Data) != "abcdef" || buf.Anomalies != want {
				t.Fatalf("start %x reverse %v: %+v, %v", start, reverse, buf, err)
			}
			var frames [][]byte
			for _, seg := range segs {
				frames = append(frames, buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 12345, 443, seg.Seq, 0, TCPFlagACK, seg.Payload))
			}
			raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
			c, err := New(raw)
			if err != nil {
				t.Fatal(err)
			}
			streams, err := c.Streams(raw)
			if err != nil || len(streams) != 1 || string(streams[0].Client.Data) != "abcdef" || streams[0].Client.Anomalies != want {
				t.Fatalf("streams = %+v, %v", streams, err)
			}
		}
	}
}

func TestReassemblyReservationWithGapsAndRetransmissions(t *testing.T) {
	segs := []TCPSegmentInput{
		{Seq: 20, Payload: []byte("abcd")},
		{Seq: 22, Payload: []byte("cd")},
		{Seq: 1 << 28, Payload: []byte("efgh")},
	}
	buf, used, err := reassembleTCPWithBudget(segs, 6, nil)
	if err != nil || used != 6 || string(buf.Data) != "abcdef" || !buf.Anomalies.Truncated || !buf.Anomalies.SequenceGap || !buf.Anomalies.Retransmission || buf.Anomalies.OverlapConflict {
		t.Fatalf("reassembly: %+v, %d bytes, %v", buf, used, err)
	}
}

func TestCollectStreamsSkipsFragmentedAndTruncatedTCP(t *testing.T) {
	fragTCP := buildEthernetIPv4FragmentFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, IPProtoTCP, 0x1111, 0, true, []byte("fragmented_tcp_bytes"))
	badTCP := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 1234, 80, 1, 1, TCPFlagACK, []byte("bad"))
	badTCP[34+12] = 3 << 4 // invalid data offset (< 5)
	goodTCP := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 3}, [4]byte{10, 0, 0, 4}, 40000, 443, 10, 1, TCPFlagACK, []byte("valid"))

	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{fragTCP, badTCP, goodTCP})
	c, err := New(raw)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	streams, err := c.Streams(raw)
	if err != nil {
		t.Fatalf("Streams() error = %v", err)
	}
	if len(streams) != 1 || streams[0].SrcPort != 40000 || streams[0].DstPort != 443 || string(streams[0].Client.Data) != "valid" {
		t.Fatalf("Streams() = %+v, want only the valid TCP stream", streams)
	}
}

func TestNestedOverlapCaptureOrder(t *testing.T) {
	// The earliest packet supplies the middle, the second supplies the flanks.
	segments := []TCPSegmentInput{{Seq: 14, Payload: []byte("AA")}, {Seq: 12, Payload: []byte("bbbbbb")}, {Seq: 10, Payload: []byte("cccccccccc")}}
	var owners []byte
	res, _, err := reassembleTCPWithBudget(segments, MaxFlowStreamBytes, func(segment, end int, _ uint32, _ bool) {
		for len(owners) < end {
			owners = append(owners, byte('0'+segment))
		}
	})
	if err != nil || !res.Anomalies.OverlapConflict || res.OverlapBytes != 8 || string(res.Data) != "ccbbAAbbcc" || string(owners) != "2211001122" {
		t.Fatalf("result=%+v owners=%s err=%v", res, owners, err)
	}
	res, _, err = reassembleTCPWithBudget(segments, 5, nil)
	if err != nil || !res.Anomalies.Truncated || string(res.Data) != "ccbbA" {
		t.Fatalf("bounded result=%+v err=%v", res, err)
	}
}

func TestStreamsSeparateReusedConnections(t *testing.T) {
	a, b := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	open := buildEthernetIPv4TCPFrame(a, b, 45000, 80, 0, 0, TCPFlagSYN, nil)
	frames := [][]byte{
		buildEthernetIPv4UDPFrame(a, b, 43000, 53, nil),
		buildEthernetIPv4TCPFrame(b, a, 80, 45000, 10, 1, TCPFlagSYN|TCPFlagACK, nil),
		open, open,
		buildEthernetIPv4TCPFrame(a, b, 45000, 80, 1, 11, TCPFlagACK, []byte("first")),
		buildEthernetIPv4TCPFrame(a, b, 46000, 80, 1, 0, TCPFlagACK, []byte("other")),
		buildEthernetIPv4TCPFrame(a, b, 45000, 80, 2, 0, TCPFlagSYN, []byte("second")),
		buildEthernetIPv4TCPFrame(b, a, 80, 45000, 3, 9, TCPFlagACK, []byte("reply")),
	}
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Streams(raw)
	if err != nil || len(got) != 3 {
		t.Fatalf("streams = %+v, %v", got, err)
	}
	if got[0].FlowIndex != 1 || got[0].SrcPort != 80 || string(got[0].Server.Data) != "first" ||
		got[1].FlowIndex != 2 || string(got[1].Client.Data) != "other" ||
		got[2].FlowIndex != 1 || got[2].SrcPort != 45000 || string(got[2].Client.Data) != "second" || string(got[2].Server.Data) != "reply" {
		t.Fatalf("streams = %+v", got)
	}
}

func TestStreamsReorderedFastOpenHandshake(t *testing.T) {
	a, b := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	const seq = uint32(0xfffffffd)
	payload := []byte("fast")
	after := seq + 1 + uint32(len(payload))
	syn := buildEthernetIPv4TCPFrame(a, b, 5000, 80, seq, 0, TCPFlagSYN, payload)
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{
		buildEthernetIPv4TCPFrame(b, a, 80, 5000, 99, after, TCPFlagSYN|TCPFlagACK, nil),
		syn, syn,
		buildEthernetIPv4TCPFrame(a, b, 5000, 80, after, 100, TCPFlagACK, []byte(" open")),
		buildEthernetIPv4TCPFrame(a, b, 5000, 80, 400, 0, TCPFlagSYN, []byte("fresh")),
	})
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Streams(raw)
	if err != nil || len(got) != 2 || got[0].SrcPort != 80 || string(got[0].Server.Data) != "fast open" || string(got[1].Client.Data) != "fresh" {
		t.Fatalf("Streams = %+v, %v", got, err)
	}
}

func TestStreamsReusedTupleSharesDirectionalSegmentLimit(t *testing.T) {
	var frames [][]byte
	for seq := 0; seq <= MaxSegmentsPerFlow; seq++ {
		frames = append(frames, buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 1000, 80, uint32(seq), 0, TCPFlagSYN, nil))
	}
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := c.Streams(raw); got != nil || !errors.Is(err, ErrReassemblyLimit) {
		t.Fatalf("Streams returned %d streams, %v", len(got), err)
	}
}

func TestReusedTupleSharesDirectionalByteLimit(t *testing.T) {
	a, b := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	payload := make([]byte, 32<<10)
	var frames [][]byte
	for seq := 0; seq < MaxFlowStreamBytes; seq += len(payload) {
		frames = append(frames, buildEthernetIPv4TCPFrame(a, b, 5000, 80, uint32(seq), 0, TCPFlagACK, payload))
	}
	frames = append(frames,
		buildEthernetIPv4TCPFrame(b, a, 80, 5000, 100, 0, TCPFlagSYN, []byte("new")),
		buildEthernetIPv4TCPFrame(a, b, 5000, 80, 200, 0, TCPFlagACK, []byte("over budget")),
	)
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	streams, err := c.Streams(raw)
	if err != nil || len(streams) != 2 {
		t.Fatalf("Streams returned %d streams, %v", len(streams), err)
	}
	if len(streams[0].Client.Data) != MaxFlowStreamBytes || string(streams[1].Client.Data) != "new" || len(streams[1].Server.Data) != 0 || !streams[1].Server.Anomalies.Truncated {
		t.Fatalf("directional byte limit: first %d bytes, second %+v", len(streams[0].Client.Data), streams[1])
	}
}

func TestReassembleTCPChecksumEvidence(t *testing.T) {
	for _, tc := range []struct {
		name                string
		firstBad, secondBad bool
		want                string
	}{
		{"unchecked", false, false, "stale bytes"},
		{"mismatch on first copy", true, false, "sfreshbytes"},
		{"mismatch on second copy", false, true, "stale bytes"},
		{"both flagged", true, true, "stale bytes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ReassembleTCP([]TCPSegmentInput{
				{Seq: 40, InvalidChecksum: tc.firstBad, Payload: []byte("stale bytes")},
				{Seq: 41, InvalidChecksum: tc.secondBad, Payload: []byte("fresh")},
			})
			if err != nil || string(result.Data) != tc.want || !result.Anomalies.OverlapConflict ||
				!result.Anomalies.Retransmission || result.OverlapBytes != 5 {
				t.Fatalf("got %q, %+v, %v. Want %q with five conflicting overlap bytes", result.Data, result.Anomalies, err, tc.want)
			}
		})
	}
}
