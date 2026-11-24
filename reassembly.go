package pcap

import (
	"bytes"
	"cmp"
	"container/heap"
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

// TCPStream holds one connection on a bidirectional five-tuple. Connections
// that reuse the tuple share a FlowIndex. Client follows the first observed
// packet in this connection and Server follows the reverse direction.
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
	out, _, err := reassembleTCPWithBudget(segments, MaxFlowStreamBytes, nil)
	return out, err
}

func reassembleTCPWithBudget(segments []TCPSegmentInput, remainingBudget int64, written func(segment, end int, gap bool)) (StreamBuffer, int64, error) {
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

	var inline [8]normSegment
	norm := inline[:0]
	if len(segments) > len(inline) {
		norm = make([]normSegment, 0, len(segments))
	}
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
		if hasSYN && rel < 0 {
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

	// Sequence order identifies contiguous ranges. Capture order resolves ownership.
	slices.SortFunc(norm, func(a, b normSegment) int {
		if c := cmp.Compare(a.relStart, b.relStart); c != 0 {
			return c
		}
		return cmp.Compare(a.order, b.order)
	})

	maxBytes := min(int64(MaxFlowStreamBytes), remainingBudget)
	var buf bytes.Buffer
	var cursor int64
	// Midstream input can begin after bytes captured later in packet order.
	if !hasSYN && len(norm) > 0 {
		cursor = norm[0].relStart
	}

	// Size the result from distinct captured ranges. Reserving the whole
	// sequence span would charge gaps and retransmissions to the heap.
	if len(norm) > 1 {
		end := cursor
		var size int64
		for i := range norm {
			seg := &norm[i]
			if seg.relEnd > end {
				size += seg.relEnd - max(end, seg.relStart)
				end = seg.relEnd
				if size >= maxBytes {
					size = maxBytes
					break
				}
			}
		}
		buf.Grow(int(size))
	}

	for i := 0; i < len(norm); {
		seg := &norm[i]
		gap := seg.relStart > cursor
		if gap {
			out.Anomalies.SequenceGap = true
			out.GapCount++
			out.GapBytes += uint64(seg.relStart - cursor)
		}

		// All segments in this group share at least one byte with a predecessor.
		// Adjacent non-overlapping segments stay on the single-copy path.
		end := seg.relEnd
		j := i + 1
		for j < len(norm) && norm[j].relStart < end {
			next := norm[j]
			out.Anomalies.Retransmission = true
			out.OverlapCount++
			out.OverlapBytes += uint64(min(next.relEnd, end) - next.relStart)
			end = max(end, next.relEnd)
			j++
		}
		length := min(end-seg.relStart, maxBytes-int64(buf.Len()))
		if length > 0 {
			if j == i+1 {
				buf.Write(seg.payload[:length])
				if written != nil {
					written(seg.order, buf.Len(), gap)
				}
			} else if appendTCPOverlap(&buf, norm[i:j], length, gap, written) {
				out.Anomalies.OverlapConflict = true
			}
		}
		if length < end-seg.relStart {
			out.Anomalies.Truncated = true
			break
		}
		cursor = end
		i = j
	}

	out.Data = buf.Bytes()
	return out, int64(len(out.Data)), nil
}

// appendTCPOverlap emits each range from the first captured segment covering it.
// The heap changes only at segment boundaries, independent of the sequence span.
func appendTCPOverlap(buf *bytes.Buffer, group []normSegment, length int64, gap bool, written func(int, int, bool)) bool {
	start := group[0].relStart
	limit := start + length
	offset := buf.Len()
	var active captureOrderHeap
	next := 0
	for pos := start; pos < limit; {
		for next < len(group) && group[next].relStart <= pos {
			heap.Push(&active, group[next])
			next++
		}
		for active[0].relEnd <= pos {
			heap.Pop(&active)
		}
		owner := active[0]
		end := min(limit, owner.relEnd)
		if next < len(group) {
			end = min(end, group[next].relStart)
		}
		buf.Write(owner.payload[pos-owner.relStart : end-owner.relStart])
		if written != nil {
			written(owner.order, buf.Len(), gap)
		}
		gap = false
		pos = end
	}
	data := buf.Bytes()[offset:]
	for _, seg := range group {
		if seg.relStart >= limit {
			break
		}
		end := min(limit, seg.relEnd)
		if !bytes.Equal(data[seg.relStart-start:end-start], seg.payload[:end-seg.relStart]) {
			return true
		}
	}
	return false
}

type captureOrderHeap []normSegment

func (h captureOrderHeap) Len() int           { return len(h) }
func (h captureOrderHeap) Less(i, j int) bool { return h[i].order < h[j].order }
func (h captureOrderHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *captureOrderHeap) Push(x any)        { *h = append(*h, x.(normSegment)) }
func (h *captureOrderHeap) Pop() any {
	a := *h
	last := a[len(a)-1]
	*h = a[:len(a)-1]
	return last
}

type flowSegments struct {
	flowIndex        int
	firstPacket      int
	srcAddr, dstAddr netip.Addr
	srcPort, dstPort uint16
	client, server   []TCPSegmentInput
	canonical        bool
}

// A SYN-ACK can be observed before its matching SYN.
type tcpOpening struct {
	seq       uint32
	canonical bool
	known     bool
	inferred  bool
}

func (o *tcpOpening) observe(frame *Frame, canonical bool) bool {
	switch frame.TCPFlags & (TCPFlagSYN | TCPFlagACK) {
	case TCPFlagSYN:
		opening := tcpOpening{seq: frame.TCPSeq, canonical: canonical, known: true}
		changed := *o != opening
		// Fast Open allows the SYN-ACK to acknowledge data on the SYN.
		if o.inferred && o.canonical == canonical && o.seq-frame.TCPSeq <= frame.PayloadLength {
			changed = false
		}
		*o = opening
		return changed
	case TCPFlagSYN | TCPFlagACK:
		if !o.known {
			*o = tcpOpening{seq: frame.TCPAck - 1, canonical: !canonical, known: true, inferred: true}
		}
	}
	return false
}

// All connections on a five-tuple share the same per-direction limits.
type tcpFlowBudget struct {
	segments [2]int
	bytes    [2]int64
}

func tcpSide(canonical bool) int {
	if canonical {
		return 0
	}
	return 1
}

func (b *tcpFlowBudget) addSegment(side int) error {
	if b.segments[side] >= MaxSegmentsPerFlow {
		return fmt.Errorf("%w: flow direction exceeds %d segments", ErrReassemblyLimit, MaxSegmentsPerFlow)
	}
	b.segments[side]++
	return nil
}

func (b *tcpFlowBudget) reassemble(side int, segments []TCPSegmentInput, remaining *int64, written func(int, int, bool)) (StreamBuffer, error) {
	budget := min(*remaining, MaxFlowStreamBytes-b.bytes[side])
	buf, used, err := reassembleTCPWithBudget(segments, budget, written)
	b.bytes[side] += used
	*remaining -= used
	return buf, err
}

type tcpFlowUsage struct {
	opening tcpOpening
	budget  tcpFlowBudget
	slot    int // One-based index of the current connection.
}

// streamMetadata describes the packet and byte boundaries used by dissectors.
type streamMetadata struct {
	firstPacket                int
	clientPrefix, serverPrefix int
}

// Streams reassembles TCP connections in order of their first observed packet.
// An opening SYN after midstream traffic or with a different initial sequence
// number starts a new connection on the same [FlowSummary].
func (c *Capture) Streams(data []byte) ([]TCPStream, error) {
	return collectStreams(ipFrameSource{capture: c, data: data}, 0, nil)
}

// A nonzero port restricts reassembly after global flow indices are assigned.
func collectStreams(source ipFrameSource, port uint16, meta *[]streamMetadata) ([]TCPStream, error) {
	var table flowIndexTable
	var inline [8]tcpFlowUsage
	usage := inline[:0]
	var collected []flowSegments

	err := source.walk(func(pkt PacketRecord, frame Frame, l4 []byte) error {
		key, canonical := makeCanonicalFlowKey(frame.IPProtocol, frame.SrcAddr, frame.SrcPort, frame.DstAddr, frame.DstPort)
		flowIdx, _, err := table.lookupOrInsert(key)
		if err != nil {
			return err
		}
		if frame.IPProtocol != IPProtoTCP || !frame.hasPorts || frame.Anomalies.IPFragment || frame.Anomalies.TruncatedLayer || frame.Anomalies.InvalidTCPDataOffset {
			return nil
		}
		if port != 0 && frame.SrcPort != port && frame.DstPort != port {
			return nil
		}

		if flowIdx >= len(usage) {
			usage = append(usage, make([]tcpFlowUsage, flowIdx+1-len(usage))...)
		}
		state := &usage[flowIdx]
		if changed := state.opening.observe(&frame, canonical); state.slot == 0 || changed {
			if len(collected) >= MaxFlows {
				return fmt.Errorf("%w: exceeds %d TCP connections", ErrFlowLimit, MaxFlows)
			}
			state.slot = len(collected) + 1
			collected = append(collected, flowSegments{
				flowIndex: flowIdx, firstPacket: pkt.Index,
				srcAddr: frame.SrcAddr, dstAddr: frame.DstAddr,
				srcPort: frame.SrcPort, dstPort: frame.DstPort,
				canonical: canonical,
			})
		}
		if err := state.budget.addSegment(tcpSide(canonical)); err != nil {
			return err
		}
		entry := &collected[state.slot-1]
		seg := TCPSegmentInput{Seq: frame.TCPSeq, Flags: frame.TCPFlags, Payload: l4}
		if canonical == entry.canonical {
			entry.client = append(entry.client, seg)
		} else {
			entry.server = append(entry.server, seg)
		}
		return nil
	})
	if err != nil || len(collected) == 0 {
		return nil, err
	}

	streams := make([]TCPStream, 0, len(collected))
	if meta != nil {
		*meta = make([]streamMetadata, 0, len(collected))
	}
	remaining := int64(MaxTotalStreamBytes)
	for i := range collected {
		entry := &collected[i]
		st := TCPStream{
			FlowIndex: entry.flowIndex, SrcAddr: entry.srcAddr, DstAddr: entry.dstAddr,
			SrcPort: entry.srcPort, DstPort: entry.dstPort,
		}
		info := streamMetadata{firstPacket: entry.firstPacket}
		state := &usage[entry.flowIndex]
		for dir, segments := range [2][]TCPSegmentInput{entry.client, entry.server} {
			side := tcpSide(entry.canonical)
			if dir == 1 {
				side = 1 - side
			}
			prefix := 0
			var written func(int, int, bool)
			if meta != nil {
				gapped := false
				written = func(_ int, end int, gap bool) {
					gapped = gapped || gap
					if !gapped {
						prefix = end
					}
				}
			}
			buf, err := state.budget.reassemble(side, segments, &remaining, written)
			if err != nil {
				return nil, err
			}
			if dir == 0 {
				st.Client, info.clientPrefix = buf, prefix
			} else {
				st.Server, info.serverPrefix = buf, prefix
			}
		}
		streams = append(streams, st)
		if meta != nil {
			*meta = append(*meta, info)
		}
	}
	return streams, nil
}
