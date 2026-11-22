package pcap

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// LayerSpan describes one protocol layer's byte range inside a frame buffer.
type LayerSpan struct {
	Proto  LayerProto
	Offset uint32
	Length uint32
}

// FrameAnomalies reports non-fatal structural anomalies in a decoded frame.
type FrameAnomalies struct {
	TruncatedLayer            bool
	InvalidIPHeaderLength     bool
	IPTotalLengthExceedsFrame bool
	IPFragment                bool
	IPFragmentOverlapConflict bool
	InvalidTCPDataOffset      bool
	VLANDepthExceeded         bool
	MPLSDepthExceeded         bool
	IPv6ExtLimitExceeded      bool
}

// Any reports whether any frame anomaly was recorded.
func (a FrameAnomalies) Any() bool {
	return a.TruncatedLayer ||
		a.InvalidIPHeaderLength ||
		a.IPTotalLengthExceedsFrame ||
		a.IPFragment ||
		a.IPFragmentOverlapConflict ||
		a.InvalidTCPDataOffset ||
		a.VLANDepthExceeded ||
		a.MPLSDepthExceeded ||
		a.IPv6ExtLimitExceeded
}

// Frame contains the decoded L2–L4 headers and layer offsets of a single packet.
// It uses a fixed-capacity layer array and value types so [DecodeFrame] performs
// zero heap allocations.
type Frame struct {
	LinkType   LinkType
	EtherType  uint16
	VLANCount  uint8
	VLANTags   [MaxVLANTags]uint16
	LayerCount uint8
	Layers     [MaxFrameLayers]LayerSpan

	// Network layer (IPv4 / IPv6).
	IPVersion       uint8
	IPProtocol      uint8
	TTL             uint8
	IPID            uint32
	IPFragOffset    uint16 // Fragment offset in bytes (8-byte units * 8)
	IPMoreFragments bool
	SrcAddr         netip.Addr
	DstAddr         netip.Addr

	// Transport layer (TCP / UDP / ICMP).
	SrcPort          uint16
	DstPort          uint16
	TCPSeq           uint32
	TCPAck           uint32
	TCPFlags         uint8
	TCPWindow        uint16
	TCPOptionsOffset uint32
	TCPOptionsLength uint32
	ICMPType         uint8
	ICMPCode         uint8

	// Inner transport payload span within the frame slice passed to DecodeFrame.
	PayloadOffset uint32
	PayloadLength uint32

	Anomalies FrameAnomalies
}

// LayerSlices returns the active layer spans in decoding order.
func (f *Frame) LayerSlices() []LayerSpan {
	if f == nil {
		return nil
	}
	return f.Layers[:f.LayerCount]
}

func (f *Frame) pushLayer(proto LayerProto, offset, length int64) {
	if int(f.LayerCount) >= MaxFrameLayers {
		return
	}
	f.Layers[f.LayerCount] = LayerSpan{
		Proto:  proto,
		Offset: uint32(offset),
		Length: uint32(length),
	}
	f.LayerCount++
}

// DecodeFrame decodes link, network, and transport headers from data according
// to linkType without allocating on the heap.
//
// It returns [ErrInvalidFrame] if linkType is unsupported or the outer link
// header is shorter than its minimum size. Truncated inner network or transport
// headers are recorded in [Frame.Anomalies] without discarding outer layers.
func DecodeFrame(data []byte, linkType LinkType) (Frame, error) {
	r := NewSafeReader(data)
	f := Frame{LinkType: linkType}

	var offset int64
	switch linkType {
	case LinkTypeEthernet:
		if r.Size() < 14 {
			return Frame{}, fmt.Errorf("%w: Ethernet header shorter than 14 bytes", ErrInvalidFrame)
		}
		etherType, _ := r.ReadUint16BE(12)
		f.EtherType = etherType
		f.pushLayer(LayerEthernet, 0, 14)
		offset = 14

		for isVLANEtherType(f.EtherType) {
			if int(f.VLANCount) >= MaxVLANTags {
				f.Anomalies.VLANDepthExceeded = true
				return f, nil
			}
			if r.Size()-offset < 4 {
				f.Anomalies.TruncatedLayer = true
				return f, nil
			}
			tci, _ := r.ReadUint16BE(offset)
			nextEther, _ := r.ReadUint16BE(offset + 2)
			f.VLANTags[f.VLANCount] = tci & 0x0fff
			f.VLANCount++
			f.EtherType = nextEther
			f.pushLayer(LayerVLAN, offset, 4)
			offset += 4
		}

	case LinkTypeLinuxSLL:
		if r.Size() < 16 {
			return Frame{}, fmt.Errorf("%w: Linux SLL header shorter than 16 bytes", ErrInvalidFrame)
		}
		proto, _ := r.ReadUint16BE(14)
		f.EtherType = proto
		f.pushLayer(LayerLinuxSLL, 0, 16)
		offset = 16

	case LinkTypeLinuxSLL2:
		if r.Size() < 20 {
			return Frame{}, fmt.Errorf("%w: Linux SLL2 header shorter than 20 bytes", ErrInvalidFrame)
		}
		proto, _ := r.ReadUint16BE(0)
		f.EtherType = proto
		f.pushLayer(LayerLinuxSLL2, 0, 20)
		offset = 20

	case LinkTypeNull:
		if r.Size() < 4 {
			return Frame{}, fmt.Errorf("%w: BSD Loopback header shorter than 4 bytes", ErrInvalidFrame)
		}
		famLE, _ := r.ReadUint32(0)
		famBE, _ := r.ReadUint32BE(0)
		fam := famLE
		if famLE > 0xffff && famBE <= 0xffff {
			fam = famBE
		}
		switch fam {
		case 2:
			f.EtherType = EtherTypeIPv4
		case 24, 28, 30:
			f.EtherType = EtherTypeIPv6
		}
		f.pushLayer(LayerLoopback, 0, 4)
		offset = 4

	case LinkTypeRaw, LinkTypeIPv4, LinkTypeIPv6:
		if r.Size() < 1 {
			return Frame{}, fmt.Errorf("%w: empty Raw IP frame", ErrInvalidFrame)
		}
		ver := data[0] >> 4
		switch {
		case linkType == LinkTypeIPv4 || (linkType == LinkTypeRaw && ver == 4):
			f.EtherType = EtherTypeIPv4
		case linkType == LinkTypeIPv6 || (linkType == LinkTypeRaw && ver == 6):
			f.EtherType = EtherTypeIPv6
		default:
			return Frame{}, fmt.Errorf("%w: unrecognized Raw IP version %d", ErrInvalidFrame, ver)
		}
		f.pushLayer(LayerRawIP, 0, 0)
		offset = 0

	default:
		return Frame{}, fmt.Errorf("%w: unsupported link type %d", ErrInvalidFrame, linkType)
	}

	dispatchEtherType(r, offset, &f)
	return f, nil
}

func dispatchEtherType(r *SafeReader, offset int64, f *Frame) {
	// Peel PPPoE Session (0x8864) or MPLS label stacks (0x8847 / 0x8848) before L3 dispatch.
	if f.EtherType == EtherTypePPPoESession {
		if r.Size()-offset < 8 {
			f.Anomalies.TruncatedLayer = true
			return
		}
		pppProto, _ := r.ReadUint16BE(offset + 6)
		f.pushLayer(LayerPPPoE, offset, 8)
		offset += 8
		switch pppProto {
		case 0x0021:
			f.EtherType = EtherTypeIPv4
		case 0x0057:
			f.EtherType = EtherTypeIPv6
		default:
			f.PayloadOffset = uint32(offset)
			if r.Size() > offset {
				f.PayloadLength = uint32(r.Size() - offset)
			}
			return
		}
	}

	if f.EtherType == EtherTypeMPLSUnicast || f.EtherType == EtherTypeMPLSMulticast {
		mplsStart := offset
		labels := 0
		for {
			if labels >= MaxMPLSLabels {
				f.Anomalies.MPLSDepthExceeded = true
				return
			}
			if r.Size()-offset < 4 {
				f.Anomalies.TruncatedLayer = true
				return
			}
			bos := (r.data[offset+2] & 0x01) != 0
			offset += 4
			labels++
			if bos {
				break
			}
		}
		f.pushLayer(LayerMPLS, mplsStart, offset-mplsStart)
		if r.Size() <= offset {
			f.Anomalies.TruncatedLayer = true
			return
		}
		switch r.data[offset] >> 4 {
		case 4:
			f.EtherType = EtherTypeIPv4
		case 6:
			f.EtherType = EtherTypeIPv6
		default:
			f.PayloadOffset = uint32(offset)
			f.PayloadLength = uint32(r.Size() - offset)
			return
		}
	}

	switch f.EtherType {
	case EtherTypeIPv4:
		decodeIPv4(r, offset, f)
	case EtherTypeIPv6:
		decodeIPv6(r, offset, f)
	case EtherTypeARP:
		avail := r.Size() - offset
		if avail < 28 {
			f.Anomalies.TruncatedLayer = true
			return
		}
		f.pushLayer(LayerARP, offset, 28)
		f.PayloadOffset = uint32(offset + 28)
	default:
		f.PayloadOffset = uint32(offset)
		if r.Size() > offset {
			f.PayloadLength = uint32(r.Size() - offset)
		}
	}
}

func isVLANEtherType(et uint16) bool {
	return et == EtherTypeVLAN || et == EtherTypeQinQ || et == EtherTypeQinQLegacy
}

func decodeIPv4(r *SafeReader, offset int64, f *Frame) {
	avail := r.Size() - offset
	if avail < 20 {
		f.Anomalies.TruncatedLayer = true
		return
	}
	vihl := r.data[offset]
	ver := vihl >> 4
	ihl := int64(vihl&0x0f) * 4
	if ver != 4 || ihl < 20 {
		f.Anomalies.InvalidIPHeaderLength = true
		return
	}
	if ihl > avail {
		f.Anomalies.TruncatedLayer = true
		return
	}

	totalLenU16, _ := r.ReadUint16BE(offset + 2)
	totalLen := int64(totalLenU16)
	if totalLen < ihl {
		f.Anomalies.InvalidIPHeaderLength = true
		return
	}
	ipBound := r.Size()
	if offset+totalLen <= r.Size() {
		ipBound = offset + totalLen
	} else {
		f.Anomalies.IPTotalLengthExceedsFrame = true
	}

	ipID, _ := r.ReadUint16BE(offset + 4)
	fragWord, _ := r.ReadUint16BE(offset + 6)
	moreFragments := (fragWord & 0x2000) != 0
	fragOffset := (fragWord & 0x1fff) * 8

	f.IPVersion = 4
	f.IPID = uint32(ipID)
	f.IPFragOffset = fragOffset
	f.IPMoreFragments = moreFragments
	f.TTL = r.data[offset+8]
	f.IPProtocol = r.data[offset+9]
	f.SrcAddr = netip.AddrFrom4([4]byte(r.data[offset+12 : offset+16]))
	f.DstAddr = netip.AddrFrom4([4]byte(r.data[offset+16 : offset+20]))
	f.pushLayer(LayerIPv4, offset, ihl)

	l4Offset := offset + ihl
	l4Length := ipBound - l4Offset
	if moreFragments || fragOffset != 0 {
		f.Anomalies.IPFragment = true
		f.PayloadOffset = uint32(l4Offset)
		if l4Length > 0 {
			f.PayloadLength = uint32(l4Length)
		}
		return
	}

	decodeTransport(r, l4Offset, ipBound, f.IPProtocol, f)
}

func decodeIPv6(r *SafeReader, offset int64, f *Frame) {
	avail := r.Size() - offset
	if avail < 40 {
		f.Anomalies.TruncatedLayer = true
		return
	}
	ver := r.data[offset] >> 4
	if ver != 6 {
		f.Anomalies.InvalidIPHeaderLength = true
		return
	}
	payloadLenU16, _ := r.ReadUint16BE(offset + 4)
	nextHeader := r.data[offset+6]
	hopLimit := r.data[offset+7]

	ipBound := r.Size()
	declaredEnd := offset + 40 + int64(payloadLenU16)
	if declaredEnd <= r.Size() {
		ipBound = declaredEnd
	} else {
		f.Anomalies.IPTotalLengthExceedsFrame = true
	}

	f.IPVersion = 6
	f.TTL = hopLimit
	f.IPProtocol = nextHeader
	f.SrcAddr = netip.AddrFrom16([16]byte(r.data[offset+8 : offset+24]))
	f.DstAddr = netip.AddrFrom16([16]byte(r.data[offset+24 : offset+40]))
	f.pushLayer(LayerIPv6, offset, 40)

	cur := offset + 40
	extCount := 0
	for isIPv6ExtHeader(nextHeader) {
		if extCount >= MaxIPv6ExtHeaders {
			f.Anomalies.IPv6ExtLimitExceeded = true
			return
		}
		extCount++
		if ipBound-cur < 8 {
			f.Anomalies.TruncatedLayer = true
			return
		}
		nh := r.data[cur]
		var extLen int64
		switch nextHeader {
		case IPProtoIPv6Frag:
			extLen = 8
			fragWord := binary.BigEndian.Uint16(r.data[cur+2 : cur+4])
			f.IPFragOffset = fragWord & 0xfff8
			f.IPMoreFragments = (fragWord & 0x0001) != 0
			f.IPID = binary.BigEndian.Uint32(r.data[cur+4 : cur+8])
			if (fragWord & 0xfff9) != 0 {
				f.Anomalies.IPFragment = true
			}
		case IPProtoAH:
			extLen = (int64(r.data[cur+1]) + 2) * 4
		default:
			extLen = (int64(r.data[cur+1]) + 1) * 8
		}
		if extLen <= 0 || cur+extLen > ipBound {
			f.Anomalies.TruncatedLayer = true
			return
		}
		f.pushLayer(LayerIPv6Ext, cur, extLen)
		nextHeader = nh
		f.IPProtocol = nextHeader
		cur += extLen
		if f.Anomalies.IPFragment {
			if f.IPFragOffset == 0 && shortFragmentHeader(nextHeader, r.data[cur:ipBound]) {
				f.Anomalies.TruncatedLayer = true
			}
			f.PayloadOffset = uint32(cur)
			if ipBound > cur {
				f.PayloadLength = uint32(ipBound - cur)
			}
			return
		}
	}

	decodeTransport(r, cur, ipBound, nextHeader, f)
}

func isIPv6ExtHeader(proto uint8) bool {
	switch proto {
	case IPProtoHopByHop, IPProtoIPv6Route, IPProtoIPv6Frag, IPProtoIPv6Opts, IPProtoAH:
		return true
	default:
		return false
	}
}

func decodeTransport(r *SafeReader, offset, ipBound int64, proto uint8, f *Frame) {
	avail := ipBound - offset
	if avail <= 0 {
		f.PayloadOffset = uint32(offset)
		return
	}

	switch proto {
	case IPProtoTCP:
		if avail < 20 {
			f.Anomalies.TruncatedLayer = true
			return
		}
		f.SrcPort = binary.BigEndian.Uint16(r.data[offset : offset+2])
		f.DstPort = binary.BigEndian.Uint16(r.data[offset+2 : offset+4])
		f.TCPSeq = binary.BigEndian.Uint32(r.data[offset+4 : offset+8])
		f.TCPAck = binary.BigEndian.Uint32(r.data[offset+8 : offset+12])
		dataOff := int64(r.data[offset+12]>>4) * 4
		f.TCPFlags = r.data[offset+13]
		f.TCPWindow = binary.BigEndian.Uint16(r.data[offset+14 : offset+16])
		if dataOff < 20 {
			f.Anomalies.InvalidTCPDataOffset = true
			return
		}
		if dataOff > avail {
			f.Anomalies.TruncatedLayer = true
			return
		}
		if dataOff > 20 {
			f.TCPOptionsOffset = uint32(offset + 20)
			f.TCPOptionsLength = uint32(dataOff - 20)
		}
		f.pushLayer(LayerTCP, offset, dataOff)
		f.PayloadOffset = uint32(offset + dataOff)
		f.PayloadLength = uint32(avail - dataOff)

	case IPProtoUDP:
		if avail < 8 {
			f.Anomalies.TruncatedLayer = true
			return
		}
		f.SrcPort = binary.BigEndian.Uint16(r.data[offset : offset+2])
		f.DstPort = binary.BigEndian.Uint16(r.data[offset+2 : offset+4])
		f.pushLayer(LayerUDP, offset, 8)
		udpPayloadOff := offset + 8
		udpPayloadLen := avail - 8
		f.PayloadOffset = uint32(udpPayloadOff)
		f.PayloadLength = uint32(udpPayloadLen)

		// Peel VXLAN (UDP port 4789, 8-byte VXLAN header with I-flag 0x08 + inner 14-byte Ethernet)
		// or Geneve (UDP port 6081, 8 + OptLen*4 header) when space permits in Layers.
		if int(f.LayerCount)+2 <= MaxFrameLayers {
			if f.DstPort == 4789 && udpPayloadLen >= 8+14 && r.data[udpPayloadOff] == 0x08 {
				f.pushLayer(LayerVXLAN, udpPayloadOff, 8)
				decodeInnerEthernet(r, udpPayloadOff+8, f)
			} else if f.DstPort == 6081 && udpPayloadLen >= 8 {
				optLen := int64(r.data[udpPayloadOff]&0x3f) * 4
				geneveHdrLen := 8 + optLen
				protoType := binary.BigEndian.Uint16(r.data[udpPayloadOff+2 : udpPayloadOff+4])
				if udpPayloadLen >= geneveHdrLen {
					f.pushLayer(LayerGeneve, udpPayloadOff, geneveHdrLen)
					innerOff := udpPayloadOff + geneveHdrLen
					switch protoType {
					case EtherTypeTransparentBr:
						decodeInnerEthernet(r, innerOff, f)
					case EtherTypeIPv4, EtherTypeIPv6:
						f.EtherType = protoType
						dispatchEtherType(r, innerOff, f)
					}
				}
			}
		}

	case IPProtoGRE:
		decodeGRE(r, offset, ipBound, f)

	case IPProtoICMP, IPProtoIPv6ICMP:
		if avail < 4 {
			f.Anomalies.TruncatedLayer = true
			return
		}
		f.ICMPType = r.data[offset]
		f.ICMPCode = r.data[offset+1]
		layer := LayerICMPv4
		if proto == IPProtoIPv6ICMP {
			layer = LayerICMPv6
		}
		hdrLen := min(int64(8), avail)
		f.pushLayer(layer, offset, hdrLen)
		f.PayloadOffset = uint32(offset + hdrLen)
		f.PayloadLength = uint32(avail - hdrLen)

	default:
		f.PayloadOffset = uint32(offset)
		f.PayloadLength = uint32(avail)
	}
}

func decodeGRE(r *SafeReader, offset, ipBound int64, f *Frame) {
	avail := ipBound - offset
	if avail < 4 {
		f.Anomalies.TruncatedLayer = true
		return
	}
	flagsVer := binary.BigEndian.Uint16(r.data[offset : offset+2])
	if (flagsVer & 0x0007) != 0 {
		// Unsupported GRE version (only standard GRE v0 is peeled).
		f.PayloadOffset = uint32(offset)
		f.PayloadLength = uint32(avail)
		return
	}
	protoType := binary.BigEndian.Uint16(r.data[offset+2 : offset+4])
	greLen := int64(4)
	if (flagsVer & 0x8000) != 0 {
		greLen += 4 // Checksum + Reserved1
	}
	if (flagsVer & 0x2000) != 0 {
		greLen += 4 // Key
	}
	if (flagsVer & 0x1000) != 0 {
		greLen += 4 // Sequence Number
	}
	if greLen > avail {
		f.Anomalies.TruncatedLayer = true
		return
	}
	f.pushLayer(LayerGRE, offset, greLen)
	innerOff := offset + greLen
	if int(f.LayerCount) >= MaxFrameLayers {
		f.PayloadOffset = uint32(innerOff)
		f.PayloadLength = uint32(ipBound - innerOff)
		return
	}
	switch protoType {
	case EtherTypeTransparentBr:
		decodeInnerEthernet(r, innerOff, f)
	case EtherTypeIPv4, EtherTypeIPv6, EtherTypeMPLSUnicast, EtherTypeMPLSMulticast, EtherTypePPPoESession:
		f.EtherType = protoType
		dispatchEtherType(r, innerOff, f)
	default:
		f.PayloadOffset = uint32(innerOff)
		f.PayloadLength = uint32(ipBound - innerOff)
	}
}

func decodeInnerEthernet(r *SafeReader, offset int64, f *Frame) {
	if r.Size()-offset < 14 {
		f.Anomalies.TruncatedLayer = true
		return
	}
	f.EtherType = binary.BigEndian.Uint16(r.data[offset+12 : offset+14])
	f.pushLayer(LayerEthernet, offset, 14)
	cur := offset + 14
	for isVLANEtherType(f.EtherType) {
		if int(f.VLANCount) >= MaxVLANTags {
			f.Anomalies.VLANDepthExceeded = true
			return
		}
		if r.Size()-cur < 4 {
			f.Anomalies.TruncatedLayer = true
			return
		}
		tci := binary.BigEndian.Uint16(r.data[cur : cur+2])
		nextEther := binary.BigEndian.Uint16(r.data[cur+2 : cur+4])
		f.VLANTags[f.VLANCount] = tci & 0x0fff
		f.VLANCount++
		f.EtherType = nextEther
		f.pushLayer(LayerVLAN, cur, 4)
		cur += 4
	}
	dispatchEtherType(r, cur, f)
}

// FlowSummary aggregates bidirectional packet, byte, flag, JA4T, JA4L, and
// process metadata for a 5-tuple network flow.
type FlowSummary struct {
	Protocol         uint8
	SrcAddr          netip.Addr
	DstAddr          netip.Addr
	SrcPort          uint16
	DstPort          uint16
	PacketCount      int
	ClientPackets    int
	ServerPackets    int
	ClientBytes      uint64
	ServerBytes      uint64
	FirstTimestampNs int64
	LastTimestampNs  int64
	TCPFlags         uint8
	ClientJA4T       string
	ServerJA4TS      string
	ClientJA4L       string
	ServerJA4L       string
	ProcessID        uint32
	UserID           uint32
	ProcessName      string
	ProcessArgs      string
	ContainerID      string
	HasProcessID     bool
	HasUserID        bool
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
	type tcpHandshakeTime struct {
		synNs      int64
		synAckNs   int64
		hasSYN     bool
		hasSYNACK  bool
		hasClientL bool
	}
	var table flowIndexTable
	var flows []FlowSummary
	var hsTimes []tcpHandshakeTime

	err := c.walkPackets(&r, func(pkt PacketRecord) error {
		payload, err := r.Slice(pkt.PayloadOffset, pkt.PayloadLength)
		if err != nil {
			return err
		}
		frame, err := DecodeFrame(payload, pkt.LinkType)
		if err != nil || frame.IPVersion == 0 {
			return nil
		}

		key, _ := makeCanonicalFlowKey(frame.IPProtocol, frame.SrcAddr, frame.SrcPort, frame.DstAddr, frame.DstPort)
		idx, exists, err := table.lookupOrInsert(key)
		if err != nil {
			return err
		}
		if !exists {
			flows = append(flows, FlowSummary{
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
			})
			hsTimes = append(hsTimes, tcpHandshakeTime{})
		}

		flow := &flows[idx]
		hst := &hsTimes[idx]
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
	})
	if err != nil {
		return nil, err
	}

	return flows, nil
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
