package pcap

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// Collect only the TCP directions needed by a length-prefixed dissector.
// Preserve first-seen order when applying the aggregate reassembly budget.
type tcpMessageCollector struct {
	byEndpoints map[[2]netip.AddrPort]int
	directions  []tcpMessageDirection
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
	if !frame.hasPorts || frame.Anomalies.IPFragment || frame.Anomalies.TruncatedLayer || frame.Anomalies.InvalidTCPDataOffset || len(payload) == 0 {
		return nil
	}
	key := [2]netip.AddrPort{netip.AddrPortFrom(frame.SrcAddr, frame.SrcPort), netip.AddrPortFrom(frame.DstAddr, frame.DstPort)}
	i, ok := c.byEndpoints[key]
	if !ok {
		if c.byEndpoints == nil {
			c.byEndpoints = make(map[[2]netip.AddrPort]int)
		}
		if len(c.directions) >= 2*MaxFlows {
			return ErrFlowLimit
		}
		i = len(c.directions)
		c.byEndpoints[key] = i
		c.directions = append(c.directions, tcpMessageDirection{src: key[0], dst: key[1], flowIndex: flow})
	}
	dir := &c.directions[i]
	if len(dir.segments) >= MaxSegmentsPerFlow {
		return fmt.Errorf("%w: too many TCP message segments", ErrReassemblyLimit)
	}
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
		buf, used, err := reassembleTCPWithBudget(dir.segments, remaining, func(segment, end int, gap bool) {
			gapSeen = gapSeen || gap
			if !gapSeen {
				spans = append(spans, packetSpan{end, segment})
			}
		})
		if err != nil {
			return err
		}
		remaining -= used
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
