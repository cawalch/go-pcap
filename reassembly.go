package pcap

import (
	"bytes"
	"cmp"
	"fmt"
	"net/netip"
	"slices"
)

// StreamAnomalies reports TCP reassembly anomalies observed in one direction of
// a flow.
type StreamAnomalies struct {
	MidstreamPickup bool
	SequenceGap     bool
	OverlapConflict bool
	Retransmission  bool
	Truncated       bool
}

// Any reports whether any TCP stream reassembly anomaly occurred.
func (a StreamAnomalies) Any() bool {
	return a.MidstreamPickup ||
		a.SequenceGap ||
		a.OverlapConflict ||
		a.Retransmission ||
		a.Truncated
}

// StreamBuffer contains the reassembled payload and anomaly counters for one
// direction of a TCP connection.
type StreamBuffer struct {
	Data         []byte
	GapCount     int
	GapBytes     uint64
	OverlapCount int
	OverlapBytes uint64
	Anomalies    StreamAnomalies
}

// TCPStream pairs a bidirectional 5-tuple flow index with its reassembled
// client-to-server and server-to-client byte streams.
type TCPStream struct {
	FlowIndex int
	SrcAddr   netip.Addr
	DstAddr   netip.Addr
	SrcPort   uint16
	DstPort   uint16
	Client    StreamBuffer
	Server    StreamBuffer
}

// TCPSegmentInput represents one directional TCP packet for [ReassembleTCP].
type TCPSegmentInput struct {
	Seq     uint32
	Flags   uint8
	Payload []byte
}

type normSegment struct {
	relStart int64
	relEnd   int64
	payload  []byte
	order    int
}

// ReassembleTCP reassembles directional TCP segments in sequence order using
// first-seen-wins overlap resolution.
//
// If overlapping segments contain differing payload bytes at the same sequence
// position, ReassembleTCP retains the first-seen bytes and sets
// [StreamAnomalies.OverlapConflict]. If sequence gaps exist between segments,
// it sets [StreamAnomalies.SequenceGap] and concatenates the available ranges
// without zero-filling the gap.
func ReassembleTCP(segments []TCPSegmentInput) (StreamBuffer, error) {
	out, _, err := reassembleTCPWithBudget(segments, MaxFlowStreamBytes)
	return out, err
}

func reassembleTCPWithBudget(segments []TCPSegmentInput, remainingBudget int64) (StreamBuffer, int64, error) {
	if len(segments) > MaxSegmentsPerFlow {
		return StreamBuffer{}, 0, fmt.Errorf("%w: %d segments exceed %d", ErrReassemblyLimit, len(segments), MaxSegmentsPerFlow)
	}
	var out StreamBuffer
	if len(segments) == 0 {
		return out, 0, nil
	}

	var baseSeq uint32
	haveBase := false
	hasSYN := false

	for i := range segments {
		seg := &segments[i]
		if (seg.Flags & TCPFlagSYN) != 0 {
			baseSeq = seg.Seq + 1
			haveBase = true
			hasSYN = true
			break
		}
		if !haveBase && len(seg.Payload) > 0 {
			baseSeq = seg.Seq
			haveBase = true
		}
	}

	if !haveBase {
		return out, 0, nil
	}
	if !hasSYN {
		out.Anomalies.MidstreamPickup = true
	}

	norm := make([]normSegment, 0, len(segments))
	for i := range segments {
		seg := &segments[i]
		if len(seg.Payload) == 0 {
			continue
		}
		seq := seg.Seq
		if (seg.Flags & TCPFlagSYN) != 0 {
			seq++
		}
		rel := int64(int32(seq - baseSeq))
		if rel < 0 {
			// Segment precedes the chosen initial sequence number.
			trim := -rel
			if trim >= int64(len(seg.Payload)) {
				out.Anomalies.Retransmission = true
				out.OverlapCount++
				continue
			}
			norm = append(norm, normSegment{
				relStart: 0,
				relEnd:   int64(len(seg.Payload)) - trim,
				payload:  seg.Payload[trim:],
				order:    i,
			})
			out.Anomalies.Retransmission = true
			out.OverlapCount++
			out.OverlapBytes += uint64(trim)
			continue
		}
		norm = append(norm, normSegment{
			relStart: rel,
			relEnd:   rel + int64(len(seg.Payload)),
			payload:  seg.Payload,
			order:    i,
		})
	}

	if len(norm) == 0 {
		return out, 0, nil
	}

	// Sort by relative start offset, then by arrival order so first-seen segments
	// take precedence on overlaps.
	slices.SortFunc(norm, func(a, b normSegment) int {
		if c := cmp.Compare(a.relStart, b.relStart); c != 0 {
			return c
		}
		return cmp.Compare(a.order, b.order)
	})

	maxBytes := min(int64(MaxFlowStreamBytes), remainingBudget)
	var buf bytes.Buffer
	var cursor int64

	for i := range norm {
		seg := &norm[i]
		if seg.relStart > cursor {
			out.Anomalies.SequenceGap = true
			out.GapCount++
			out.GapBytes += uint64(seg.relStart - cursor)
			cursor = seg.relStart
		}

		var newPayload []byte
		if seg.relStart < cursor {
			out.Anomalies.Retransmission = true
			out.OverlapCount++
			overlapEnd := min(seg.relEnd, cursor)
			overlapLen := overlapEnd - seg.relStart
			out.OverlapBytes += uint64(overlapLen)

			// Check whether the overlapping prefix disagrees with already-written bytes.
			// Only check when no sequence gap occurred or within the contiguous tail.
			written := buf.Bytes()
			if int64(len(written)) >= overlapLen && cursor == seg.relStart+int64(len(written)) {
				existing := written[:overlapLen]
				if !bytes.Equal(existing, seg.payload[:overlapLen]) {
					out.Anomalies.OverlapConflict = true
				}
			} else if overlapLen <= int64(len(written)) {
				// Compare against the trailing overlapLen bytes written just before cursor.
				existing := written[int64(len(written))-(cursor-seg.relStart) : int64(len(written))-(cursor-overlapEnd)]
				if !bytes.Equal(existing, seg.payload[:overlapLen]) {
					out.Anomalies.OverlapConflict = true
				}
			}

			if seg.relEnd <= cursor {
				continue
			}
			newPayload = seg.payload[cursor-seg.relStart:]
		} else {
			newPayload = seg.payload
		}

		avail := maxBytes - int64(buf.Len())
		if avail <= 0 {
			out.Anomalies.Truncated = true
			break
		}
		if int64(len(newPayload)) > avail {
			newPayload = newPayload[:avail]
			out.Anomalies.Truncated = true
		}
		buf.Write(newPayload)
		cursor += int64(len(newPayload))
		if out.Anomalies.Truncated {
			break
		}
	}

	out.Data = buf.Bytes()
	return out, int64(len(out.Data)), nil
}

type flowSegments struct {
	flowIndex int
	srcAddr   netip.Addr
	dstAddr   netip.Addr
	srcPort   uint16
	dstPort   uint16
	client    []TCPSegmentInput
	server    []TCPSegmentInput
}

// Streams reassembles bounded TCP byte streams for all TCP flows in the capture
// in deterministic first-seen flow order.
func (c *Capture) Streams(data []byte) ([]TCPStream, error) {
	packets, err := c.Packets(data)
	if err != nil {
		return nil, err
	}
	if len(packets) == 0 {
		return nil, nil
	}

	r := SafeReader{data: data, size: int64(len(data))}
	flowIndexByKey := make(map[flowKey]int)
	tcpSlotByFlow := make(map[int]int)
	var collected []flowSegments
	nextFlowIdx := 0

	for i := range packets {
		pkt := &packets[i]
		payload, err := r.Slice(pkt.PayloadOffset, pkt.PayloadLength)
		if err != nil {
			return nil, err
		}
		frame, err := DecodeFrame(payload, pkt.LinkType)
		if err != nil || frame.IPVersion == 0 {
			continue
		}
		key, _ := makeCanonicalFlowKey(frame.IPProtocol, frame.SrcAddr, frame.SrcPort, frame.DstAddr, frame.DstPort)
		flowIdx, exists := flowIndexByKey[key]
		if !exists {
			if nextFlowIdx >= MaxFlows {
				return nil, fmt.Errorf("%w: exceeds %d", ErrFlowLimit, MaxFlows)
			}
			flowIdx = nextFlowIdx
			nextFlowIdx++
			flowIndexByKey[key] = flowIdx
		}
		if frame.IPProtocol != IPProtoTCP {
			continue
		}

		slot, hasSlot := tcpSlotByFlow[flowIdx]
		if !hasSlot {
			slot = len(collected)
			tcpSlotByFlow[flowIdx] = slot
			collected = append(collected, flowSegments{
				flowIndex: flowIdx,
				srcAddr:   frame.SrcAddr,
				dstAddr:   frame.DstAddr,
				srcPort:   frame.SrcPort,
				dstPort:   frame.DstPort,
			})
		}

		entry := &collected[slot]
		var l4Payload []byte
		if frame.PayloadLength > 0 && uint64(frame.PayloadOffset)+uint64(frame.PayloadLength) <= uint64(len(payload)) {
			l4Payload = payload[frame.PayloadOffset : frame.PayloadOffset+frame.PayloadLength]
		}
		seg := TCPSegmentInput{
			Seq:     frame.TCPSeq,
			Flags:   frame.TCPFlags,
			Payload: l4Payload,
		}
		if frame.SrcAddr == entry.srcAddr && frame.SrcPort == entry.srcPort {
			if len(entry.client) >= MaxSegmentsPerFlow {
				return nil, fmt.Errorf("%w: flow %d client segments exceed %d", ErrReassemblyLimit, flowIdx, MaxSegmentsPerFlow)
			}
			entry.client = append(entry.client, seg)
		} else {
			if len(entry.server) >= MaxSegmentsPerFlow {
				return nil, fmt.Errorf("%w: flow %d server segments exceed %d", ErrReassemblyLimit, flowIdx, MaxSegmentsPerFlow)
			}
			entry.server = append(entry.server, seg)
		}
	}

	if len(collected) == 0 {
		return nil, nil
	}

	streams := make([]TCPStream, 0, len(collected))
	remainingBudget := int64(MaxTotalStreamBytes)

	for i := range collected {
		entry := &collected[i]
		clientBuf, usedClient, err := reassembleTCPWithBudget(entry.client, remainingBudget)
		if err != nil {
			return nil, err
		}
		remainingBudget -= usedClient

		serverBuf, usedServer, err := reassembleTCPWithBudget(entry.server, remainingBudget)
		if err != nil {
			return nil, err
		}
		remainingBudget -= usedServer

		streams = append(streams, TCPStream{
			FlowIndex: entry.flowIndex,
			SrcAddr:   entry.srcAddr,
			DstAddr:   entry.dstAddr,
			SrcPort:   entry.srcPort,
			DstPort:   entry.dstPort,
			Client:    clientBuf,
			Server:    serverBuf,
		})
	}

	return streams, nil
}
