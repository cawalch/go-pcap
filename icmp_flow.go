package pcap

import (
	"fmt"
	"io"
)

// MaxICMPFlowErrorGroups bounds distinct quoted directions and error codes
// collected by [Capture.ICMPFlowErrors].
const MaxICMPFlowErrorGroups = 16_384

// ICMPFlowErrorSummary describes observed ICMP errors quoting one direction of
// a TCP or UDP flow. FlowIndex uses the order of [Capture.Flows]. Quote retains
// the direction in the ICMP message. Type and Code use the ICMP family of
// Quote.IPVersion. First and last refer to capture order.
type ICMPFlowErrorSummary struct {
	FlowIndex        int
	Quote            ICMPEmbeddedPacket
	Type             uint8
	Code             uint8
	Count            int
	FirstPacketIndex int
	LastPacketIndex  int
	FirstTimestampNs int64
	LastTimestampNs  int64
}

// ICMPFlowErrors groups supported ICMP error quotes by TCP or UDP direction,
// type, and code, in first-observed order. A group requires a matching
// transport tuple observed elsewhere in the capture. Each group provides
// flow-level evidence across the packets that share the quoted tuple.
//
// Incomplete quotes without ports and fragmented outer errors are skipped.
// An error or [ErrFlowLimit] returns no summaries.
func (c *Capture) ICMPFlowErrors(data []byte) ([]ICMPFlowErrorSummary, error) {
	if err := c.validateContainer(); err != nil {
		return nil, err
	}
	if c.PacketCount == 0 {
		return nil, nil
	}
	var scan icmpFlowErrorScan
	r := NewSafeReader(data)
	err := c.walkPackets(r, func(pkt PacketRecord) error {
		wire, err := r.Slice(pkt.PayloadOffset, pkt.PayloadLength)
		if err != nil {
			return err
		}
		frame, err := decodeCaptureFrame(wire, pkt.LinkType)
		if err != nil || frame.IPVersion == 0 {
			return nil
		}
		return scan.observe(pkt, frame, wire)
	})
	if err != nil {
		return nil, err
	}
	return scan.matched(), nil
}

// ICMPFlowErrorsFromReaderAt is the file-backed equivalent of
// [Capture.ICMPFlowErrors]. Reads share [MaxReaderAtScanBytes].
func (c *Capture) ICMPFlowErrorsFromReaderAt(r io.ReaderAt) ([]ICMPFlowErrorSummary, error) {
	if err := c.validateContainer(); err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("%w: nil ReaderAt", ErrInvalidHeader)
	}
	if c.PacketCount == 0 {
		return nil, nil
	}
	var scan icmpFlowErrorScan
	budget := scanReadBudget{r: r, remaining: MaxReaderAtScanBytes}
	if err := c.walkFlowPrefixes(&budget, scan.observe); err != nil {
		return nil, err
	}
	return scan.matched(), nil
}

type icmpFlowErrorKey struct {
	quote ICMPEmbeddedPacket
	typ   uint8
	code  uint8
}

type icmpFlowErrorScan struct {
	flows    flowIndexTable
	hasPorts []bool
	index    map[icmpFlowErrorKey]int
	groups   []ICMPFlowErrorSummary
}

func (s *icmpFlowErrorScan) observe(pkt PacketRecord, frame Frame, wire []byte) error {
	key, _ := makeCanonicalFlowKey(frame.IPProtocol, frame.SrcAddr, frame.SrcPort, frame.DstAddr, frame.DstPort)
	i, exists, err := s.flows.lookupOrInsert(key)
	if err != nil {
		return err
	}
	if !exists {
		s.hasPorts = append(s.hasPorts, frame.hasPorts)
	} else if frame.hasPorts {
		s.hasPorts[i] = true
	}
	if (frame.IPProtocol != IPProtoICMP && frame.IPProtocol != IPProtoIPv6ICMP) || frame.Anomalies.IPFragment {
		return nil
	}
	q, ok := frame.ICMPEmbeddedPacket(wire)
	if !ok || !q.HasPorts || q.IPVersion != frame.IPVersion {
		return nil
	}
	group := icmpFlowErrorKey{quote: q, typ: frame.ICMPType, code: frame.ICMPCode}
	if i, found := s.index[group]; found {
		s.groups[i].Count++
		s.groups[i].LastPacketIndex = pkt.Index
		s.groups[i].LastTimestampNs = pkt.TimestampNs
		return nil
	}
	if len(s.groups) == MaxICMPFlowErrorGroups {
		return fmt.Errorf("%w: exceeds %d ICMP error groups", ErrFlowLimit, MaxICMPFlowErrorGroups)
	}
	if s.index == nil {
		s.index = make(map[icmpFlowErrorKey]int)
	}
	s.index[group] = len(s.groups)
	s.groups = append(s.groups, ICMPFlowErrorSummary{
		Quote: q, Type: frame.ICMPType, Code: frame.ICMPCode, Count: 1,
		FirstPacketIndex: pkt.Index, LastPacketIndex: pkt.Index,
		FirstTimestampNs: pkt.TimestampNs, LastTimestampNs: pkt.TimestampNs,
	})
	return nil
}

func (s *icmpFlowErrorScan) matched() []ICMPFlowErrorSummary {
	var out []ICMPFlowErrorSummary
	for _, group := range s.groups {
		q := group.Quote
		key, _ := makeCanonicalFlowKey(q.IPProtocol, q.SrcAddr, q.SrcPort, q.DstAddr, q.DstPort)
		if i, found := s.flows.lookup(key); found && s.hasPorts[i] {
			group.FlowIndex = i
			out = append(out, group)
		}
	}
	return out
}

func (t *flowIndexTable) lookup(k flowKey) (int, bool) {
	if t.overflow != nil {
		i, found := t.overflow[k]
		return i, found
	}
	for i := range t.count {
		if t.inlineKeys[i] == k {
			return t.inlineIdx[i], true
		}
	}
	return 0, false
}
