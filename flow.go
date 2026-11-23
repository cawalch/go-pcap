package pcap

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// TCPTimestamp holds the raw timestamp option from one observed TCP segment.
type TCPTimestamp struct {
	TSval   uint32 // Timestamp value sent by this endpoint.
	TSecr   uint32 // Timestamp echo reply sent by this endpoint.
	Present bool   // True even when both observed values are zero.
}

// FlowSummary aggregates bidirectional packet, byte, flag, JA4T, JA4L, and
// process metadata for a 5-tuple network flow.
type FlowSummary struct {
	Protocol         uint8
	TCPFlags         uint8
	SrcPort          uint16
	DstPort          uint16
	SrcAddr          netip.Addr
	DstAddr          netip.Addr
	PacketCount      int
	ClientPackets    int
	ServerPackets    int
	ClientBytes      uint64
	ServerBytes      uint64
	FirstTimestampNs int64
	LastTimestampNs  int64
	ClientJA4T       string
	ServerJA4TS      string
	// SYNTimestamp is the first valid timestamp observed on a SYN without ACK.
	SYNTimestamp TCPTimestamp
	// SYNACKTimestamp is the first valid timestamp observed on a SYN with ACK.
	SYNACKTimestamp TCPTimestamp
	ClientJA4L      string
	ServerJA4L      string
	ProcessID       uint32
	UserID          uint32
	ProcessName     string
	ProcessArgs     string
	ContainerID     string
	HasProcessID    bool
	HasUserID       bool
	// PortsUnavailable reports that no packet in the summary supplied transport ports.
	PortsUnavailable bool
	Anomalies        FrameAnomalies
}

type flowKey struct {
	proto uint8
	addrA netip.Addr
	addrB netip.Addr
	portA uint16
	portB uint16
}

func makeCanonicalFlowKey(proto uint8, src netip.Addr, srcPort uint16, dst netip.Addr, dstPort uint16) (flowKey, bool) {
	cmp := src.Compare(dst)
	if cmp < 0 || (cmp == 0 && srcPort <= dstPort) {
		return flowKey{
			proto: proto,
			addrA: src,
			addrB: dst,
			portA: srcPort,
			portB: dstPort,
		}, true
	}
	return flowKey{
		proto: proto,
		addrA: dst,
		addrB: src,
		portA: dstPort,
		portB: srcPort,
	}, false
}

// flowIndexTable indexes canonical 5-tuple flow keys without heap allocations
// when a capture contains up to 12 flows, spilling to an open-addressed table
// for larger flow counts.
type flowIndexTable struct {
	inlineKeys [12]flowKey
	inlineIdx  [12]int
	count      int
	overflow   map[flowKey]int
}

func (t *flowIndexTable) lookupOrInsert(k flowKey) (idx int, exists bool, err error) {
	if t.overflow != nil {
		if idx, ok := t.overflow[k]; ok {
			return idx, true, nil
		}
		if t.count >= MaxFlows {
			return 0, false, fmt.Errorf("%w: exceeds %d", ErrFlowLimit, MaxFlows)
		}
		idx = t.count
		t.count++
		t.overflow[k] = idx
		return idx, false, nil
	}
	for i := range t.count {
		if t.inlineKeys[i] == k {
			return t.inlineIdx[i], true, nil
		}
	}
	if t.count < len(t.inlineKeys) {
		idx = t.count
		t.inlineKeys[idx] = k
		t.inlineIdx[idx] = idx
		t.count++
		return idx, false, nil
	}
	t.overflow = make(map[flowKey]int, 32)
	for i := range t.count {
		t.overflow[t.inlineKeys[i]] = t.inlineIdx[i]
	}
	idx = t.count
	t.count++
	t.overflow[k] = idx
	return idx, false, nil
}

// Flows decodes all packets in the capture and aggregates IPv4/IPv6 flows in
// deterministic first-seen order without allocating intermediate packet slices.
// Non-IP packets (such as ARP) are skipped.
func (c *Capture) Flows(data []byte) ([]FlowSummary, error) {
	if err := c.validateContainer(); err != nil {
		return nil, err
	}
	if c.PacketCount == 0 {
		return nil, nil
	}

	r := SafeReader{data: data, size: int64(len(data))}
	var acc flowAccumulator

	err := c.walkPackets(&r, func(pkt PacketRecord) error {
		payload, err := r.Slice(pkt.PayloadOffset, pkt.PayloadLength)
		if err != nil {
			return err
		}
		frame, err := DecodeFrame(payload, pkt.LinkType)
		if err != nil || frame.IPVersion == 0 {
			return nil
		}

		return acc.observe(&pkt, &frame, payload)
	})
	if err != nil {
		return nil, err
	}

	return acc.flows, nil
}

type tcpHandshakeTime struct {
	synNs      int64
	synAckNs   int64
	hasSYN     bool
	hasSYNACK  bool
	hasClientL bool
}

type flowAccumulator struct {
	table   flowIndexTable
	flows   []FlowSummary
	hsTimes []tcpHandshakeTime
}

func (acc *flowAccumulator) observe(pkt *PacketRecord, frame *Frame, payload []byte) error {
	key, _ := makeCanonicalFlowKey(frame.IPProtocol, frame.SrcAddr, frame.SrcPort, frame.DstAddr, frame.DstPort)
	idx, exists, err := acc.table.lookupOrInsert(key)
	if err != nil {
		return err
	}
	if !exists {
		acc.flows = append(acc.flows, FlowSummary{
			Protocol:         frame.IPProtocol,
			SrcAddr:          frame.SrcAddr,
			DstAddr:          frame.DstAddr,
			SrcPort:          frame.SrcPort,
			DstPort:          frame.DstPort,
			FirstTimestampNs: pkt.TimestampNs,
			LastTimestampNs:  pkt.TimestampNs,
			ProcessID:        pkt.ProcessID,
			UserID:           pkt.UserID,
			ProcessName:      pkt.ProcessName,
			ProcessArgs:      pkt.ProcessArgs,
			ContainerID:      pkt.ContainerID,
			HasProcessID:     pkt.HasProcessID,
			HasUserID:        pkt.HasUserID,
			PortsUnavailable: !frame.hasPorts,
		})
		acc.hsTimes = append(acc.hsTimes, tcpHandshakeTime{})
	}

	flow := &acc.flows[idx]
	if flow.PortsUnavailable && frame.hasPorts {
		flow.PortsUnavailable = false
	}
	hst := &acc.hsTimes[idx]
	flow.PacketCount++
	if pkt.TimestampNs < flow.FirstTimestampNs {
		flow.FirstTimestampNs = pkt.TimestampNs
	}
	if pkt.TimestampNs > flow.LastTimestampNs {
		flow.LastTimestampNs = pkt.TimestampNs
	}
	if !flow.HasProcessID && pkt.HasProcessID {
		flow.ProcessID = pkt.ProcessID
		flow.HasProcessID = true
	}
	if !flow.HasUserID && pkt.HasUserID {
		flow.UserID = pkt.UserID
		flow.HasUserID = true
	}
	if flow.ProcessName == "" && pkt.ProcessName != "" {
		flow.ProcessName = pkt.ProcessName
	}
	if flow.ProcessArgs == "" && pkt.ProcessArgs != "" {
		flow.ProcessArgs = pkt.ProcessArgs
	}
	if flow.ContainerID == "" && pkt.ContainerID != "" {
		flow.ContainerID = pkt.ContainerID
	}
	if frame.TCPFlags&TCPFlagSYN != 0 && frame.TCPOptionsLength != 0 {
		flow.observeTCPTimestamp(frame, payload)
	}
	flow.TCPFlags |= frame.TCPFlags
	flow.Anomalies = mergeFrameAnomalies(flow.Anomalies, frame.Anomalies)

	if frame.SrcAddr == flow.SrcAddr && frame.SrcPort == flow.SrcPort {
		flow.ClientPackets++
		flow.ClientBytes += uint64(frame.PayloadLength)
		if (frame.TCPFlags & (TCPFlagSYN | TCPFlagACK)) == TCPFlagSYN {
			if flow.ClientJA4T == "" {
				if fp, ok := frame.JA4T(payload); ok {
					flow.ClientJA4T = fp
				}
			}
			if !hst.hasSYN {
				hst.synNs = pkt.TimestampNs
				hst.hasSYN = true
			}
		} else if hst.hasSYNACK && !hst.hasClientL && (frame.TCPFlags&TCPFlagACK) != 0 {
			flow.ClientJA4L = JA4L(pkt.TimestampNs-hst.synAckNs, frame.TTL)
			hst.hasClientL = true
		}
	} else {
		flow.ServerPackets++
		flow.ServerBytes += uint64(frame.PayloadLength)
		if (frame.TCPFlags & (TCPFlagSYN | TCPFlagACK)) == (TCPFlagSYN | TCPFlagACK) {
			if flow.ServerJA4TS == "" {
				if fp, ok := frame.JA4T(payload); ok {
					flow.ServerJA4TS = fp
				}
			}
			if hst.hasSYN && !hst.hasSYNACK {
				hst.synAckNs = pkt.TimestampNs
				hst.hasSYNACK = true
				flow.ServerJA4L = JA4L(pkt.TimestampNs-hst.synNs, frame.TTL)
			}
		}
	}
	return nil
}

func mergeFrameAnomalies(a, b FrameAnomalies) FrameAnomalies {
	return FrameAnomalies{
		TruncatedLayer:            a.TruncatedLayer || b.TruncatedLayer,
		InvalidIPHeaderLength:     a.InvalidIPHeaderLength || b.InvalidIPHeaderLength,
		IPTotalLengthExceedsFrame: a.IPTotalLengthExceedsFrame || b.IPTotalLengthExceedsFrame,
		IPFragment:                a.IPFragment || b.IPFragment,
		IPFragmentOverlapConflict: a.IPFragmentOverlapConflict || b.IPFragmentOverlapConflict,
		InvalidTCPDataOffset:      a.InvalidTCPDataOffset || b.InvalidTCPDataOffset,
		VLANDepthExceeded:         a.VLANDepthExceeded || b.VLANDepthExceeded,
		MPLSDepthExceeded:         a.MPLSDepthExceeded || b.MPLSDepthExceeded,
		IPv6ExtLimitExceeded:      a.IPv6ExtLimitExceeded || b.IPv6ExtLimitExceeded,
	}
}

// observeTCPTimestamp selects by handshake flags even when a SYN-ACK was
// captured first. Keep a candidate local until the option list is validated.
func (flow *FlowSummary) observeTCPTimestamp(frame *Frame, data []byte) {
	dst := &flow.SYNTimestamp
	if frame.TCPFlags&TCPFlagACK != 0 {
		dst = &flow.SYNACKTimestamp
	}
	end := uint64(frame.TCPOptionsOffset) + uint64(frame.TCPOptionsLength)
	if dst.Present || frame.TCPOptionsLength > 40 || end > uint64(len(data)) {
		return
	}
	var ts TCPTimestamp
	options := data[frame.TCPOptionsOffset:end]
	for len(options) > 0 && options[0] != tcpOptKindEOL {
		if options[0] == tcpOptKindNOP {
			options = options[1:]
			continue
		}
		if len(options) < 2 || options[1] < 2 || int(options[1]) > len(options) {
			return
		}
		n := int(options[1])
		if options[0] == 8 { // TCP Timestamps option
			if n != 10 || ts.Present {
				return
			}
			ts = TCPTimestamp{
				TSval:   binary.BigEndian.Uint32(options[2:6]),
				TSecr:   binary.BigEndian.Uint32(options[6:10]),
				Present: true,
			}
		}
		options = options[n:]
	}
	*dst = ts
}
