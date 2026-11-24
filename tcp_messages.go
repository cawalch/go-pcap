package pcap

import (
	"encoding/binary"
	"net/netip"
)

// Collect only the TCP directions needed by a length-prefixed dissector.
// Preserve first-seen order when applying the aggregate reassembly budget.
type tcpMessageCollector struct {
	flows      map[flowKey]tcpMessageFlow
	directions []tcpMessageDirection
}

type tcpMessageFlow struct {
	opening    tcpOpening
	directions [2]int // One-based direction indices for the current connection.
	budget     tcpFlowBudget
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

func (c *tcpMessageCollector) add(pkt PacketRecord, frame Frame, flow int, payload []byte) error {
	if !frame.hasPorts || frame.Anomalies.IPFragment || frame.Anomalies.TruncatedLayer || frame.Anomalies.InvalidTCPDataOffset || len(payload) == 0 && frame.TCPFlags&TCPFlagSYN == 0 {
		return nil
	}
	key, canonical := makeCanonicalFlowKey(IPProtoTCP, frame.SrcAddr, frame.SrcPort, frame.DstAddr, frame.DstPort)
	if c.flows == nil {
		c.flows = make(map[flowKey]tcpMessageFlow)
	}
	state, seen := c.flows[key]
	if !seen && len(c.flows) >= MaxFlows {
		return ErrFlowLimit
	}
	if state.opening.observe(&frame, canonical) {
		state.directions = [2]int{}
	}
	side := tcpSide(canonical)
	if err := state.budget.addSegment(side); err != nil {
		return err
	}
	if state.directions[side] == 0 {
		if len(c.directions) >= 2*MaxFlows {
			return ErrFlowLimit
		}
		c.directions = append(c.directions, tcpMessageDirection{
			src: netip.AddrPortFrom(frame.SrcAddr, frame.SrcPort), dst: netip.AddrPortFrom(frame.DstAddr, frame.DstPort), flowIndex: flow,
		})
		state.directions[side] = len(c.directions)
	}
	dir := &c.directions[state.directions[side]-1]
	c.flows[key] = state
	dir.segments = append(dir.segments, TCPSegmentInput{Seq: frame.TCPSeq, Flags: frame.TCPFlags, Payload: payload})
	dir.packets = append(dir.packets, messagePacket{pkt.Index, pkt.TimestampNs})
	return nil
}

// Attribute each message to the packet supplying the first byte of its
// length prefix. Stop at a gap because framing beyond it is unknown.
func (c *tcpMessageCollector) walk(prefix, minSize, maxSize int, visit func(*tcpMessageDirection, messagePacket, []byte) error) error {
	return c.walkContiguous(func(dir *tcpMessageDirection, data []byte, spans []packetSpan) error {
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

type packetSpan struct{ end, segment int }

// Supply the contiguous prefix and the contributing segment for each byte range.
func (c *tcpMessageCollector) walkContiguous(visit func(*tcpMessageDirection, []byte, []packetSpan) error) error {
	remaining := int64(MaxTotalStreamBytes)
	var spans []packetSpan
	for i := range c.directions {
		if remaining == 0 {
			break
		}
		dir := &c.directions[i]
		spans = spans[:0]
		gapSeen := false
		key, canonical := makeCanonicalFlowKey(IPProtoTCP, dir.src.Addr(), dir.src.Port(), dir.dst.Addr(), dir.dst.Port())
		state := c.flows[key]
		buf, err := state.budget.reassemble(tcpSide(canonical), dir.segments, &remaining, func(segment, end int, _ uint32, gap bool) {
			gapSeen = gapSeen || gap
			if !gapSeen {
				spans = append(spans, packetSpan{end, segment})
			}
		})
		if err != nil {
			return err
		}
		c.flows[key] = state
		if len(spans) == 0 {
			continue
		}
		data := buf.Data[:spans[len(spans)-1].end]
		if err := visit(dir, data, spans); err != nil {
			return err
		}
	}
	return nil
}
