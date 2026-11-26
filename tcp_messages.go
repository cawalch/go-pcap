package pcap

import (
	"encoding/binary"
	"net/netip"
)

// Collect only the TCP directions needed by a length-prefixed dissector.
// Preserve first-seen order when applying the aggregate reassembly budget.
type tcpMessageCollector struct {
	flows              map[flowKey]tcpMessageFlow
	interfaces         map[tcpObservationKey]*tcpMessageOpening
	directions         []tcpMessageDirection
	separateInterfaces bool
	onPair             func(srcPort, dstPort uint16, first, peer int)
}

type tcpMessageOpening struct {
	opening    tcpOpening
	directions [2]int // One-based direction indices for the current connection.
}

type tcpMessageFlow struct {
	tcpMessageOpening
	budget tcpFlowBudget
}

type tcpMessageDirection struct {
	src, dst  netip.AddrPort
	flowIndex int
	segments  []TCPSegmentInput
	packets   []messagePacket
}

type messagePacket struct {
	index     int
	timestamp int64
}

func collectTCPMessages(source ipFrameSource) (tcpMessageCollector, error) {
	collector := tcpMessageCollector{separateInterfaces: source.capture != nil && source.capture.SeparateTCPInterfaces}
	err := walkTCPMessagePackets(source, collector.add)
	return collector, err
}

func walkTCPMessagePackets(source ipFrameSource, visit func(PacketRecord, Frame, int, []byte) error) error {
	var table flowIndexTable
	remaining := MaxTotalStreamBytes
	return source.walk(func(pkt PacketRecord, f Frame, payload []byte) error {
		key, _ := makeCanonicalFlowKey(f.IPProtocol, f.SrcAddr, f.SrcPort, f.DstAddr, f.DstPort)
		flow, _, err := table.lookupOrInsert(key)
		if err != nil || f.IPProtocol != IPProtoTCP {
			return err
		}
		if len(payload) > remaining {
			return ErrReassemblyLimit
		}
		remaining -= len(payload)
		return visit(pkt, f, flow, payload)
	})
}

func (c *tcpMessageCollector) add(pkt PacketRecord, frame Frame, flow int, payload []byte) error {
	if !keepTCPMessageSegment(&frame, len(payload), TCPFlagSYN) {
		return nil
	}
	_, err := c.addSegment(pkt, frame, flow, payload)
	return err
}

func keepTCPMessageSegment(frame *Frame, payloadLen int, keepFlags uint8) bool {
	return frame.hasPorts && !frame.Anomalies.IPFragment && !frame.Anomalies.TruncatedLayer && !frame.Anomalies.InvalidTCPDataOffset &&
		(payloadLen != 0 || frame.TCPFlags&keepFlags != 0)
}

// Return the one-based indices of this direction and its peer in the same opening.
func (c *tcpMessageCollector) addSegment(pkt PacketRecord, frame Frame, flow int, payload []byte) ([2]int, error) {
	key, canonical := makeCanonicalFlowKey(IPProtoTCP, frame.SrcAddr, frame.SrcPort, frame.DstAddr, frame.DstPort)
	if c.flows == nil {
		c.flows = make(map[flowKey]tcpMessageFlow)
	}
	state, seen := c.flows[key]
	if !seen && len(c.flows) >= MaxFlows {
		return [2]int{}, ErrFlowLimit
	}
	active := &state.tcpMessageOpening
	if pkt.InterfaceID != 0 && c.separateInterfaces {
		if c.interfaces == nil {
			c.interfaces = make(map[tcpObservationKey]*tcpMessageOpening)
		}
		key := tcpObservationKey{flow: key, interfaceID: pkt.InterfaceID}
		active = c.interfaces[key]
		if active == nil {
			opening := new(tcpMessageOpening)
			c.interfaces[key] = opening
			active = opening
		}
	}
	if active.opening.observe(&frame, canonical) {
		active.directions = [2]int{}
	}
	side := tcpSide(canonical)
	if err := state.budget.addSegment(side); err != nil {
		return [2]int{}, err
	}
	if active.directions[side] == 0 {
		if len(c.directions) >= 2*MaxFlows {
			return [2]int{}, ErrFlowLimit
		}
		c.directions = append(c.directions, tcpMessageDirection{
			src: netip.AddrPortFrom(frame.SrcAddr, frame.SrcPort), dst: netip.AddrPortFrom(frame.DstAddr, frame.DstPort), flowIndex: flow,
		})
		active.directions[side] = len(c.directions)
		if peer := active.directions[1-side]; peer != 0 && c.onPair != nil {
			c.onPair(frame.SrcPort, frame.DstPort, pkt.Index, c.directions[peer-1].packets[0].index)
		}
	}
	dir := &c.directions[active.directions[side]-1]
	c.flows[key] = state
	dir.segments = append(dir.segments, TCPSegmentInput{Seq: frame.TCPSeq, Flags: frame.TCPFlags, Payload: payload})
	dir.packets = append(dir.packets, messagePacket{pkt.Index, pkt.TimestampNs})
	return [2]int{active.directions[side], active.directions[1-side]}, nil
}

// Attribute each message to the packet supplying the first byte of its
// length prefix. Stop at a gap because framing beyond it is unknown.
func (c *tcpMessageCollector) walk(prefix, minSize, maxSize int, visit func(*tcpMessageDirection, messagePacket, []byte) error) error {
	return c.walkContiguous(func(dir *tcpMessageDirection, data []byte, spans []packetSpan, _ StreamAnomalies) error {
		spanIndex := 0
		for off := 0; len(data)-off >= prefix; {
			var length uint32
			if prefix == 2 {
				length = uint32(binary.BigEndian.Uint16(data[off:]))
			} else {
				length = binary.BigEndian.Uint32(data[off:])
			}
			if length < uint32(minSize) || length > uint32(maxSize) || int(length) > len(data)-off-prefix {
				break
			}
			for off >= spans[spanIndex].end {
				spanIndex++
			}
			start := off + prefix
			if err := visit(dir, dir.packets[spans[spanIndex].segment], data[start:start+int(length)]); err != nil {
				return err
			}
			off = start + int(length)
		}
		return nil
	})
}

type packetSpan struct {
	end          int
	segment, seq uint32
}

// Supply the contiguous prefix and the contributing segment for each byte range.
func (c *tcpMessageCollector) walkContiguous(visit func(*tcpMessageDirection, []byte, []packetSpan, StreamAnomalies) error) error {
	remaining := int64(MaxTotalStreamBytes)
	var spans []packetSpan
	for i := range c.directions {
		if remaining == 0 {
			break
		}
		dir := &c.directions[i]
		data, nextSpans, anomalies, err := c.contiguous(dir, &remaining, spans)
		if err != nil {
			return err
		}
		spans = nextSpans
		if len(data) == 0 {
			continue
		}
		if err := visit(dir, data, spans, anomalies); err != nil {
			return err
		}
	}
	return nil
}

func (c *tcpMessageCollector) contiguous(dir *tcpMessageDirection, remaining *int64, spans []packetSpan) ([]byte, []packetSpan, StreamAnomalies, error) {
	spans = spans[:0]
	gapSeen := false
	key, canonical := makeCanonicalFlowKey(IPProtoTCP, dir.src.Addr(), dir.src.Port(), dir.dst.Addr(), dir.dst.Port())
	state := c.flows[key]
	buf, err := state.budget.reassemble(tcpSide(canonical), dir.segments, remaining, func(segment, end int, seq uint32, gap bool) {
		gapSeen = gapSeen || gap
		if !gapSeen {
			spans = append(spans, packetSpan{end: end, segment: uint32(segment), seq: seq})
		}
	})
	if err != nil {
		return nil, nil, StreamAnomalies{}, err
	}
	c.flows[key] = state
	if len(spans) == 0 {
		return nil, spans, buf.Anomalies, nil
	}
	data := buf.Data[:spans[len(spans)-1].end]
	return data, spans, buf.Anomalies, nil
}
