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
	// ClientJA4L and ServerJA4L use the first matched three-way handshake
	// that completes in capture order. If none completes, ServerJA4L uses
	// the first matching SYN and SYN-ACK pair.
	ClientJA4L   string
	ServerJA4L   string
	ProcessID    uint32
	UserID       uint32
	ProcessName  string
	ProcessArgs  string
	ContainerID  string
	HasProcessID bool
	HasUserID    bool
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
// See [Capture.UnsupportedLinkTypePackets] for link-type coverage.
func (c *Capture) Flows(data []byte) ([]FlowSummary, error) {
	if err := c.validateContainer(); err != nil {
		return nil, err
	}
	if c.PacketCount == 0 {
		return nil, nil
	}

	r := SafeReader{data: data, size: int64(len(data))}
	acc := flowAccumulator{separateInterfaces: c.SeparateTCPInterfaces && len(c.Interfaces) > 1}

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
	synNs, synAckNs           int64
	synNext, synAckNext       uint32
	synPayload, synAckPayload uint32
	synAckTTL                 uint8
	clientCanonical           bool
	hasSYN, hasSYNACK         bool
	reportedServer            bool
}

type flowAccumulator struct {
	table              flowIndexTable
	flows              []FlowSummary
	hsTimes            []tcpHandshakeTime
	hsInterfaces       map[int]map[uint32]tcpHandshakeTime
	pendingInterfaces  int
	separateInterfaces bool
}

func (hs *tcpHandshakeTime) observe(flow *FlowSummary, frame *Frame, canonical bool, timestamp int64) {
	flags := frame.TCPFlags & (TCPFlagSYN | TCPFlagACK | TCPFlagRST)
	switch flags {
	case TCPFlagSYN:
		next := frame.TCPSeq + 1
		if !hs.hasSYN || canonical != hs.clientCanonical || next != hs.synNext {
			*hs = tcpHandshakeTime{synNs: timestamp, synNext: next, clientCanonical: canonical, hasSYN: true}
		}
		hs.synPayload = max(hs.synPayload, frame.PayloadLength)
	case TCPFlagSYN | TCPFlagACK:
		// Fast Open can acknowledge part or all of the payload on a SYN.
		if !hs.hasSYN || canonical == hs.clientCanonical || frame.TCPAck-hs.synNext > hs.synPayload {
			return
		}
		next := frame.TCPSeq + 1
		if !hs.hasSYNACK || next != hs.synAckNext {
			hs.hasSYNACK = true
			hs.synAckNs, hs.synAckNext, hs.synAckTTL = timestamp, next, frame.TTL
			hs.synAckPayload = 0
			hs.reportedServer = flow.ServerJA4L == ""
			if hs.reportedServer {
				flow.ServerJA4L = JA4L(timestamp-hs.synNs, frame.TTL)
			}
		}
		hs.synAckPayload = max(hs.synAckPayload, frame.PayloadLength)
	case TCPFlagACK:
		if hs.hasSYNACK && canonical == hs.clientCanonical &&
			frame.TCPSeq-hs.synNext <= hs.synPayload && frame.TCPAck-hs.synAckNext <= hs.synAckPayload {
			if !hs.reportedServer {
				flow.ServerJA4L = JA4L(hs.synAckNs-hs.synNs, hs.synAckTTL)
			}
			flow.ClientJA4L = JA4L(timestamp-hs.synAckNs, frame.TTL)
		}
	case TCPFlagRST, TCPFlagRST | TCPFlagACK:
		if !hs.hasSYN {
			return
		}
		hasAck := flags&TCPFlagACK != 0
		if canonical == hs.clientCanonical {
			if frame.TCPSeq-hs.synNext > hs.synPayload ||
				hs.hasSYNACK && hasAck && frame.TCPAck-hs.synAckNext > hs.synAckPayload {
				return
			}
		} else if hasAck {
			if frame.TCPAck-hs.synNext > hs.synPayload {
				return
			}
		} else if !hs.hasSYNACK || frame.TCPSeq-hs.synAckNext > hs.synAckPayload {
			return
		}
		*hs = tcpHandshakeTime{}
	}
}

// Preserve the first attribution. Only an observation of the same PID can
// supply missing fields once any process metadata has been recorded.
func (flow *FlowSummary) observeProcess(pkt *PacketRecord) {
	if !pkt.HasProcessID && !pkt.HasUserID && pkt.ProcessName == "" && pkt.ProcessArgs == "" && pkt.ContainerID == "" {
		return
	}
	if flow.HasProcessID {
		if !pkt.HasProcessID || pkt.ProcessID != flow.ProcessID {
			return
		}
	} else if flow.ProcessName != "" || flow.HasUserID || flow.ProcessArgs != "" || flow.ContainerID != "" {
		return
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
}

func (acc *flowAccumulator) observe(pkt *PacketRecord, frame *Frame, payload []byte) error {
	key, canonical := makeCanonicalFlowKey(frame.IPProtocol, frame.SrcAddr, frame.SrcPort, frame.DstAddr, frame.DstPort)
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
			PortsUnavailable: !frame.hasPorts,
		})
		if !acc.separateInterfaces {
			acc.hsTimes = append(acc.hsTimes, tcpHandshakeTime{})
		}
	}

	flow := &acc.flows[idx]
	if flow.PortsUnavailable && frame.hasPorts {
		flow.PortsUnavailable = false
	}
	flow.PacketCount++
	if pkt.TimestampNs < flow.FirstTimestampNs {
		flow.FirstTimestampNs = pkt.TimestampNs
	}
	if pkt.TimestampNs > flow.LastTimestampNs {
		flow.LastTimestampNs = pkt.TimestampNs
	}
	flow.observeProcess(pkt)
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
		}
	}
	flags := frame.TCPFlags & (TCPFlagSYN | TCPFlagACK | TCPFlagRST)
	if flags == 0 || flow.ClientJA4L != "" ||
		!acc.separateInterfaces && flags&TCPFlagSYN == 0 && !acc.hsTimes[idx].hasSYN ||
		!frame.hasPorts || frame.Anomalies.IPFragment || frame.Anomalies.TruncatedLayer || frame.Anomalies.InvalidTCPDataOffset {
		return nil
	}
	if !acc.separateInterfaces {
		acc.hsTimes[idx].observe(flow, frame, canonical, pkt.TimestampNs)
		return nil
	}
	return acc.observeInterfaceHandshake(idx, flow, pkt, frame, canonical)
}

func (acc *flowAccumulator) observeInterfaceHandshake(idx int, flow *FlowSummary, pkt *PacketRecord, frame *Frame, canonical bool) error {
	byInterface := acc.hsInterfaces[idx]
	hs, pending := byInterface[pkt.InterfaceID]
	hs.observe(flow, frame, canonical, pkt.TimestampNs)
	if flow.ClientJA4L != "" {
		acc.pendingInterfaces -= len(byInterface)
		delete(acc.hsInterfaces, idx)
		return nil
	}
	if !hs.hasSYN {
		if pending {
			acc.pendingInterfaces--
			delete(byInterface, pkt.InterfaceID)
			if len(byInterface) == 0 {
				delete(acc.hsInterfaces, idx)
			}
		}
		return nil
	}
	if !pending {
		if acc.pendingInterfaces >= MaxFlows {
			return fmt.Errorf("%w: exceeds %d interface-specific TCP handshakes", ErrFlowLimit, MaxFlows)
		}
		acc.pendingInterfaces++
	}
	if byInterface == nil {
		if acc.hsInterfaces == nil {
			acc.hsInterfaces = make(map[int]map[uint32]tcpHandshakeTime)
		}
		byInterface = make(map[uint32]tcpHandshakeTime)
		acc.hsInterfaces[idx] = byInterface
	}
	byInterface[pkt.InterfaceID] = hs
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
