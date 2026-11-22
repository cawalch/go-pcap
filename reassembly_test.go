package pcap

import (
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
	buf, used, err := reassembleTCPWithBudget(segs, 6)
	if err != nil {
		t.Fatalf("reassembleTCPWithBudget() err = %v", err)
	}
	if used != 6 || string(buf.Data) != "012345" || !buf.Anomalies.Truncated {
		t.Fatalf("reassembleTCPWithBudget(6) = (%q, used=%d, %+v)", buf.Data, used, buf.Anomalies)
	}
}
