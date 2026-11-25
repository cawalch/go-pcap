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

type tcpWriteObserver func(segment, end int, seq uint32, gap bool)

func reassembleTCPWithBudget(segments []TCPSegmentInput, remainingBudget int64, written tcpWriteObserver) (StreamBuffer, int64, error) {
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
					written(seg.order, buf.Len(), baseSeq+uint32(seg.relStart), gap)
				}
			} else if appendTCPOverlap(&buf, norm[i:j], length, baseSeq, gap, written) {
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
func appendTCPOverlap(buf *bytes.Buffer, group []normSegment, length int64, baseSeq uint32, gap bool, written tcpWriteObserver) bool {
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
			written(owner.order, buf.Len(), baseSeq+uint32(pos), gap)
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

func (b *tcpFlowBudget) reassemble(side int, segments []TCPSegmentInput, remaining *int64, written tcpWriteObserver) (StreamBuffer, error) {
	budget := min(*remaining, MaxFlowStreamBytes-b.bytes[side])
	buf, used, err := reassembleTCPWithBudget(segments, budget, written)
	b.bytes[side] += used
	*remaining -= used
	return buf, err
}

type tcpObservationKey struct {
	flow        flowKey
	interfaceID uint32
}

type tcpStreamOpening struct {
	opening tcpOpening
	slot    int // One-based index of the current connection.
}

type tcpFlowUsage struct {
	tcpStreamOpening
	budget tcpFlowBudget
}

// streamMetadata describes the packet and byte boundaries used by dissectors.
type streamMetadata struct {
	firstPacket                int
	clientPrefix, serverPrefix int
	wire                       [2]tcpWireDirection
	confirmedOpening           bool
}

// A packet index and its TCP acknowledgement describe a captured payload.
type tcpPacketEvidence struct {
	index uint32
	ack   uint32
}

type tcpWireSpan struct {
	end    uint32
	packet tcpPacketEvidence
}

type tcpWireDirection struct {
	seq                     uint32 // Sequence number of byte zero in the contiguous prefix.
	spans                   []tcpWireSpan
	truncated, gapBeforeFIN bool
	sharedLimit             bool // Earlier openings reduced this direction's reassembly allowance.
}

type tcpWireMode uint8

const (
	tcpWireNone tcpWireMode = iota
	tcpWireUnanchored
	tcpWireAll
)

type tcpWireCapture struct {
	synDirections uint8
	packets       [2][]tcpPacketEvidence // Indexed by direction and segment.
	tails         [2]tcpWireTail
}

type tcpWireTail struct {
	fin, declaredEnd, lastEnd  uint32
	hasFIN, isTruncated        bool
	unknownTruncation          bool
	synSeq, synAck, synPayload uint32
	synFlags                   uint8
	inconsistent               bool
	reset, lastPayload         int // One-based packet indices.
}

func (wire *tcpWireCapture) observe(dir, segment int, index int, frame *Frame, hasPayload bool, mode tcpWireMode, missing int64) {
	if mode == tcpWireAll {
		tail := &wire.tails[dir]
		flags := frame.TCPFlags
		if flags&TCPFlagSYN != 0 {
			if tail.synFlags == 0 {
				tail.synSeq, tail.synAck, tail.synPayload, tail.synFlags = frame.TCPSeq, frame.TCPAck, frame.PayloadLength, flags
			} else if tail.synSeq != frame.TCPSeq || (flags^tail.synFlags)&TCPFlagACK != 0 || flags&TCPFlagACK != 0 && frame.TCPAck != tail.synAck {
				tail.inconsistent = true
			}
		}
		end := frame.TCPSeq + frame.PayloadLength
		if flags&TCPFlagSYN != 0 {
			end++
		}
		if hasPayload {
			if tail.lastPayload == 0 || int32(end-tail.lastEnd) > 0 {
				tail.lastEnd = end
			}
			tail.lastPayload = index + 1
			tail.inconsistent = tail.inconsistent || flags&(TCPFlagACK|TCPFlagSYN) == 0
		}
		if flags&TCPFlagRST != 0 && tail.reset == 0 {
			tail.reset = index + 1
		}
		switch {
		case missing < 0:
			tail.unknownTruncation = true
		case missing > 0:
			end += uint32(missing)
			if !tail.isTruncated || int32(end-tail.declaredEnd) > 0 {
				tail.declaredEnd, tail.isTruncated = end, true
			}
		case flags&TCPFlagFIN != 0:
			tail.inconsistent = tail.inconsistent || tail.hasFIN && end != tail.fin
			tail.fin, tail.hasFIN = end, true
		}
	}
	if frame.TCPFlags&TCPFlagSYN != 0 {
		wire.synDirections |= 1 << dir
	}
	// Both observed SYNs anchor the prefixes. No packet evidence is needed
	// when both directions opened before the first captured payload.
	if !hasPayload || mode == tcpWireUnanchored && wire.synDirections == 3 && wire.packets[0] == nil && wire.packets[1] == nil {
		return
	}
	packets := wire.packets[dir]
	packets = append(packets, make([]tcpPacketEvidence, segment+1-len(packets))...)
	packets[segment].index = uint32(index)
	if frame.TCPFlags&TCPFlagACK != 0 {
		packets[segment].ack = frame.TCPAck
	}
	wire.packets[dir] = packets
}

func (wire *tcpWireCapture) confirmedOpening() bool {
	a, b := &wire.tails[0], &wire.tails[1]
	if a.synFlags&TCPFlagACK != 0 {
		a, b = b, a
	}
	for _, t := range wire.tails {
		if t.hasFIN && t.lastPayload != 0 && int32(t.lastEnd-t.fin) > 0 {
			return false
		}
	}
	last := max(a.lastPayload, b.lastPayload)
	return a.synFlags&(TCPFlagSYN|TCPFlagACK) == TCPFlagSYN && b.synFlags&(TCPFlagSYN|TCPFlagACK) == TCPFlagSYN|TCPFlagACK &&
		b.synAck-(a.synSeq+1) <= a.synPayload && !a.inconsistent && !b.inconsistent &&
		(a.reset == 0 || last <= a.reset) && (b.reset == 0 || last <= b.reset)
}

func (wire *tcpWireDirection) add(end int, seq uint32, packet tcpPacketEvidence) {
	if len(wire.spans) == 0 {
		wire.seq = seq
	}
	if last := len(wire.spans) - 1; last >= 0 && wire.spans[last].packet == packet {
		wire.spans[last].end = uint32(end)
		return
	}
	wire.spans = append(wire.spans, tcpWireSpan{end: uint32(end), packet: packet})
}

// Streams reassembles TCP connections in order of their first observed packet.
// An opening SYN after midstream traffic or with a different initial sequence
// number starts a new connection on the same [FlowSummary].
// Set [Capture.SeparateTCPInterfaces] to track openings per PcapNG interface.
func (c *Capture) Streams(data []byte) ([]TCPStream, error) {
	return collectStreams(ipFrameSource{capture: c, data: data}, 0, nil, tcpWireNone)
}

// A nonzero port restricts reassembly after global flow indices are assigned.
func collectStreams(source ipFrameSource, port uint16, meta *[]streamMetadata, trackWire tcpWireMode) ([]TCPStream, error) {
	var table flowIndexTable
	var inline [8]tcpFlowUsage
	usage := inline[:0]
	var collected []flowSegments
	var wire []tcpWireCapture
	var interfaces map[tcpObservationKey]*tcpStreamOpening

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
		active := &state.tcpStreamOpening
		if pkt.InterfaceID != 0 && source.capture.SeparateTCPInterfaces {
			if interfaces == nil {
				interfaces = make(map[tcpObservationKey]*tcpStreamOpening)
			}
			key := tcpObservationKey{flow: key, interfaceID: pkt.InterfaceID}
			active = interfaces[key]
			if active == nil {
				opening := new(tcpStreamOpening)
				interfaces[key] = opening
				active = opening
			}
		}
		if changed := active.opening.observe(&frame, canonical); active.slot == 0 || changed {
			if len(collected) >= MaxFlows {
				return fmt.Errorf("%w: exceeds %d TCP connections", ErrFlowLimit, MaxFlows)
			}
			active.slot = len(collected) + 1
			collected = append(collected, flowSegments{
				flowIndex: flowIdx, firstPacket: pkt.Index,
				srcAddr: frame.SrcAddr, dstAddr: frame.DstAddr,
				srcPort: frame.SrcPort, dstPort: frame.DstPort,
				canonical: canonical,
			})
			if trackWire != tcpWireNone {
				wire = append(wire, tcpWireCapture{})
			}
		}
		if err := state.budget.addSegment(tcpSide(canonical)); err != nil {
			return err
		}
		entry := &collected[active.slot-1]
		dir, segments := 0, &entry.client
		if canonical != entry.canonical {
			dir, segments = 1, &entry.server
		}
		*segments = append(*segments, TCPSegmentInput{Seq: frame.TCPSeq, Flags: frame.TCPFlags, Payload: l4})
		if trackWire != tcpWireNone {
			var missing int64
			if trackWire == tcpWireAll && frame.Anomalies.IPTotalLengthExceedsFrame {
				missing, err = truncatedTCPPayload(source, pkt, &frame)
				if err != nil {
					return err
				}
			}
			wire[active.slot-1].observe(dir, len(*segments)-1, pkt.Index, &frame, len(l4) != 0, trackWire, missing)
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
		if trackWire == tcpWireAll {
			info.confirmedOpening = wire[i].confirmedOpening()
		}
		state := &usage[entry.flowIndex]
		for dir, segments := range [2][]TCPSegmentInput{entry.client, entry.server} {
			side := tcpSide(entry.canonical)
			if dir == 1 {
				side = 1 - side
			}
			prefix := 0
			var written tcpWriteObserver
			if meta != nil {
				var packets []tcpPacketEvidence
				if trackWire != tcpWireNone {
					packets = wire[i].packets[dir]
				}
				gapped := false
				written = func(segment, end int, seq uint32, gap bool) {
					gapped = gapped || gap
					if !gapped {
						prefix = end
						if len(packets) != 0 {
							info.wire[dir].add(end, seq, packets[segment])
						}
					}
				}
			}
			reduced := state.budget.bytes[side] != 0 || remaining < MaxFlowStreamBytes
			buf, err := state.budget.reassemble(side, segments, &remaining, written)
			if err != nil {
				return nil, err
			}
			if trackWire == tcpWireAll {
				info.wire[dir].sharedLimit = buf.Anomalies.Truncated && reduced
			}
			if trackWire == tcpWireAll && prefix > 0 {
				d := &info.wire[dir]
				tail := &wire[i].tails[dir]
				end := d.seq + uint32(prefix)
				d.truncated = tail.unknownTruncation || tail.isTruncated && int32(tail.declaredEnd-end) > 0
				d.gapBeforeFIN = tail.hasFIN && int32(tail.fin-end) > 0
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
