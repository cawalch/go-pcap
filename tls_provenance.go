package pcap

import (
	"encoding/binary"
	"slices"
)

const (
	maxTLSProvenanceRecords = 65_536  // Records inspected across both directions, including control records.
	maxTLSProvenanceRanges  = 262_144 // Packet span intersections before deduplication.
)

type tlsStopReason uint8

const (
	tlsStopEnd tlsStopReason = iota // End of captured input; a TCP close is not implied.
	tlsStopGap
	tlsStopTruncated
	tlsStopMissingKey
	tlsStopAuthentication
	tlsStopInvalidRecord
	tlsStopUnsupported
	tlsStopLimit
)

type tlsProvenanceBoundary struct {
	wireOffset int // Offset in the directional TCP stream, including any proxy prefix.
	reason     tlsStopReason
}

// Both intervals are half-open. The wire interval includes the TLS header and
// covers the entire record. It does not map individual plaintext bytes.
type tlsApplicationRecord struct {
	plainStart, plainEnd int
	wireStart, wireEnd   int
	packets              []int // Unique original packet indices in capture order.
	early                bool  // Authenticated with the early key; acceptance is unknown.
}

type tlsDirectionProvenance struct {
	records []tlsApplicationRecord
	// A later TLS 1.3 application epoch can authenticate independently after
	// opaque records. Its logical offsets start at zero in the recovered bytes.
	before tlsProvenanceBoundary
	stop   tlsProvenanceBoundary
}

type tlsProvenanceStream struct {
	TCPStream
	openingPacket  int // First observed packet in this opening, including SYN if captured first.
	client, server tlsDirectionProvenance
}

type tlsProvenanceBudget struct {
	records, ranges int
}

type tlsRecordMapper struct {
	tlsDirectionProvenance
	budget       *tlsProvenanceBudget
	spans        []tcpWireSpan
	spanIndex    int
	prefix       int
	inputStop    tlsStopReason
	earlyOffered bool
}

func (p *tlsRecordMapper) stopAt(offset int, reason tlsStopReason) {
	p.stop = tlsProvenanceBoundary{p.prefix + offset, reason}
}

func (p *tlsRecordMapper) finish(offset, size int) {
	if p.before.reason != tlsStopEnd && len(p.records) == 0 {
		p.stop, p.before = p.before, tlsProvenanceBoundary{}
	}
	if p.stop.reason != tlsStopEnd {
		return
	}
	reason := p.inputStop
	if offset != size && reason == tlsStopEnd {
		reason = tlsStopTruncated
	}
	p.stopAt(offset, reason)
}

func (p *tlsRecordMapper) inspect(offset int) bool {
	if p.budget.records == 0 {
		p.stopAt(offset, tlsStopLimit)
		return false
	}
	p.budget.records--
	return true
}

func (p *tlsRecordMapper) application(start, end, plainStart, n int, early bool) bool {
	if n > MaxFlowStreamBytes-plainStart {
		p.stopAt(start, tlsStopLimit)
		return false
	}
	wireStart, wireEnd := p.prefix+start, p.prefix+end
	if len(p.spans) == 0 || int(p.spans[len(p.spans)-1].end) < wireEnd {
		p.stopAt(start, tlsStopTruncated)
		return false
	}
	for int(p.spans[p.spanIndex].end) <= wireStart {
		p.spanIndex++
	}
	last := p.spanIndex
	for ; ; last++ {
		if last-p.spanIndex >= p.budget.ranges {
			p.stopAt(start, tlsStopLimit)
			return false
		}
		if int(p.spans[last].end) >= wireEnd {
			break
		}
	}
	p.budget.ranges -= last - p.spanIndex + 1
	packets := make([]int, 0, last-p.spanIndex+1)
	for _, span := range p.spans[p.spanIndex : last+1] {
		packets = append(packets, int(span.packet.index))
	}
	p.spanIndex = last
	slices.Sort(packets)
	p.records = append(p.records, tlsApplicationRecord{
		plainStart: plainStart, plainEnd: plainStart + n, wireStart: wireStart, wireEnd: wireEnd,
		packets: slices.Compact(packets), early: early,
	})
	return true
}

// Read the declared length of the IP datagram carrying TCP. The observed
// payload end can be earlier than the packet end when a tunnel clips its inner
// datagram. An outer length anomaly alone need not mean that TCP lost bytes.
// A negative result marks unknown extent when the layer list is exhausted.
func truncatedTCPPayload(source ipFrameSource, pkt PacketRecord, frame *Frame) (int64, error) {
	layers := frame.LayerSlices()
	if len(layers) == 0 || layers[len(layers)-1].Proto != LayerTCP {
		return -1, nil
	}
	capturedEnd := int64(frame.PayloadOffset) + int64(frame.PayloadLength)
	for _, layer := range slices.Backward(layers) {
		off := int64(layer.Offset)
		lengthOffset, declaredEnd := off+2, off
		switch layer.Proto {
		case LayerIPv4:
		case LayerIPv6:
			lengthOffset, declaredEnd = off+4, off+40
		default:
			continue
		}
		if lengthOffset+2 > int64(frame.PayloadOffset) || capturedEnd > pkt.PayloadLength {
			return 0, ErrOutOfBounds
		}
		at := pkt.PayloadOffset + lengthOffset
		if at < pkt.PayloadOffset {
			return 0, ErrIntegerOverflow
		}
		var length uint16
		if source.needsPayload != nil {
			var field [2]byte
			if err := readExactAt(source.reader, field[:], at, source.capture.fileSize); err != nil {
				return 0, err
			}
			length = binary.BigEndian.Uint16(field[:])
		} else {
			var err error
			length, err = NewSafeReader(source.data).ReadUint16BE(at)
			if err != nil {
				return 0, err
			}
		}
		return max(0, declaredEnd+int64(length)-capturedEnd), nil
	}
	return -1, nil
}

// Reassemble the contiguous TCP prefix and recover record provenance for each
// TLS opening. The source supplies either capture bytes or a ReaderAt.
func scanTLSProvenance(source ipFrameSource, extraKeyLog []byte) ([]tlsProvenanceStream, error) {
	keys, err := source.capture.TLSKeyLog(extraKeyLog)
	if err != nil {
		return nil, err
	}
	if source.needsPayload != nil && source.reader != nil {
		// Count the stream walk and the opt-in length reads against the same
		// physical read budget. The wrapper hides the underlying file
		// descriptor so the stream walk won't prefetch extra bytes.
		source.reader = &scanReadBudget{r: source.reader, remaining: MaxReaderAtScanBytes}
	}
	var meta []streamMetadata
	streams, err := collectStreams(source, 0, &meta, tcpWireAll)
	if err != nil {
		return nil, err
	}
	budget := tlsProvenanceBudget{records: maxTLSProvenanceRecords, ranges: maxTLSProvenanceRanges}
	var out []tlsProvenanceStream
	for i, wire := range streams {
		info := &meta[i]
		dirs := [2]tlsRecordMapper{
			{budget: &budget, spans: info.wire[0].spans},
			{budget: &budget, spans: info.wire[1].spans},
		}
		for j, anomalies := range [2]StreamAnomalies{wire.Client.Anomalies, wire.Server.Anomalies} {
			if anomalies.Truncated {
				dirs[j].inputStop = tlsStopLimit
			}
			if anomalies.SequenceGap || info.wire[j].gapBeforeFIN {
				dirs[j].inputStop = tlsStopGap
			}
			if info.wire[j].truncated {
				dirs[j].inputStop = tlsStopTruncated
			}
		}
		wire.Client.Data = wire.Client.Data[:info.clientPrefix]
		wire.Server.Data = wire.Server.Data[:info.serverPrefix]
		inner, co, so := proxyStream(wire)
		if inner.SrcAddr != wire.SrcAddr || inner.SrcPort != wire.SrcPort {
			dirs[0], dirs[1] = dirs[1], dirs[0]
		}
		dirs[0].prefix, dirs[1].prefix = co, so
		decoded, ok := decryptTLSStream(inner, keys, &dirs)
		if ok {
			out = append(out, tlsProvenanceStream{TCPStream: decoded, openingPacket: info.firstPacket,
				client: dirs[0].tlsDirectionProvenance, server: dirs[1].tlsDirectionProvenance})
		}
	}
	return out, nil
}
