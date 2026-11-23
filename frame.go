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
	hasPorts        bool
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
		if len(data) < 14 {
			return Frame{}, fmt.Errorf("%w: Ethernet header shorter than 14 bytes", ErrInvalidFrame)
		}
		f.EtherType = binary.BigEndian.Uint16(data[12:14])
		f.pushLayer(LayerEthernet, 0, 14)
		offset = 14

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

	dispatchEtherType(r, offset, r.Size(), &f)
	return f, nil
}

func peelVLANTags(r *SafeReader, offset, bound int64, f *Frame) (int64, bool) {
	for isVLANEtherType(f.EtherType) {
		if int(f.VLANCount) >= MaxVLANTags {
			f.Anomalies.VLANDepthExceeded = true
			return offset, false
		}
		if bound-offset < 4 {
			f.Anomalies.TruncatedLayer = true
			return offset, false
		}
		tci := binary.BigEndian.Uint16(r.data[offset : offset+2])
		nextEther := binary.BigEndian.Uint16(r.data[offset+2 : offset+4])
		f.VLANTags[f.VLANCount] = tci & 0x0fff
		f.VLANCount++
		f.EtherType = nextEther
		f.pushLayer(LayerVLAN, offset, 4)
		offset += 4
	}
	return offset, true
}

func dispatchEtherType(r *SafeReader, offset, bound int64, f *Frame) {
	var ok bool
	offset, ok = peelVLANTags(r, offset, bound, f)
	if !ok {
		return
	}

	// Peel PPPoE Session (0x8864) or MPLS label stacks (0x8847 / 0x8848) before L3 dispatch.
	if f.EtherType == EtherTypePPPoESession {
		if bound-offset < 8 {
			f.Anomalies.TruncatedLayer = true
			return
		}
		pppProto := binary.BigEndian.Uint16(r.data[offset+6 : offset+8])
		f.pushLayer(LayerPPPoE, offset, 8)
		offset += 8
		switch pppProto {
		case 0x0021:
			f.EtherType = EtherTypeIPv4
		case 0x0057:
			f.EtherType = EtherTypeIPv6
		default:
			f.PayloadOffset = uint32(offset)
			if bound > offset {
				f.PayloadLength = uint32(bound - offset)
			} else {
				f.PayloadLength = 0
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
			if bound-offset < 4 {
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
		if bound <= offset {
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
			f.PayloadLength = uint32(bound - offset)
			return
		}
	}

	switch f.EtherType {
	case EtherTypeIPv4:
		decodeIPv4(r, offset, bound, f)
	case EtherTypeIPv6:
		decodeIPv6(r, offset, bound, f)
	case EtherTypeARP:
		avail := bound - offset
		if avail < 28 {
			f.Anomalies.TruncatedLayer = true
			return
		}
		f.pushLayer(LayerARP, offset, 28)
		f.PayloadOffset = uint32(offset + 28)
		f.PayloadLength = 0
	default:
		f.PayloadOffset = uint32(offset)
		if bound > offset {
			f.PayloadLength = uint32(bound - offset)
		} else {
			f.PayloadLength = 0
		}
	}
}

func isVLANEtherType(et uint16) bool {
	return et == EtherTypeVLAN || et == EtherTypeQinQ || et == EtherTypeQinQLegacy
}

func resetTransportFields(f *Frame) {
	f.hasPorts = false
	f.SrcPort = 0
	f.DstPort = 0
	f.TCPSeq = 0
	f.TCPAck = 0
	f.TCPFlags = 0
	f.TCPWindow = 0
	f.TCPOptionsOffset = 0
	f.TCPOptionsLength = 0
	f.ICMPType = 0
	f.ICMPCode = 0
	f.PayloadOffset = 0
	f.PayloadLength = 0
}

func decodeIPv4(r *SafeReader, offset, bound int64, f *Frame) {
	avail := bound - offset
	if avail < 20 {
		f.Anomalies.TruncatedLayer = true
		return
	}
	ip := r.data[offset : offset+20]
	vihl := ip[0]
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

	totalLen := int64(binary.BigEndian.Uint16(ip[2:4]))
	if totalLen < ihl {
		f.Anomalies.InvalidIPHeaderLength = true
		return
	}
	ipBound := bound
	if offset+totalLen <= bound {
		ipBound = offset + totalLen
	} else {
		f.Anomalies.IPTotalLengthExceedsFrame = true
	}

	ipID := binary.BigEndian.Uint16(ip[4:6])
	fragWord := binary.BigEndian.Uint16(ip[6:8])
	moreFragments := (fragWord & 0x2000) != 0
	fragOffset := (fragWord & 0x1fff) * 8

	resetTransportFields(f)
	f.IPVersion = 4
	f.IPID = uint32(ipID)
	f.IPFragOffset = fragOffset
	f.IPMoreFragments = moreFragments
	f.TTL = ip[8]
	f.IPProtocol = ip[9]
	f.SrcAddr = netip.AddrFrom4([4]byte(ip[12:16]))
	f.DstAddr = netip.AddrFrom4([4]byte(ip[16:20]))
	f.pushLayer(LayerIPv4, offset, ihl)

	l4Offset := offset + ihl
	l4Length := ipBound - l4Offset
	if moreFragments || fragOffset != 0 {
		f.Anomalies.IPFragment = true
		f.PayloadOffset = uint32(l4Offset)
		if l4Length > 0 {
			f.PayloadLength = uint32(l4Length)
		} else {
			f.PayloadLength = 0
		}
		return
	}

	decodeTransport(r, l4Offset, ipBound, f.IPProtocol, f)
}

func decodeIPv6(r *SafeReader, offset, bound int64, f *Frame) {
	avail := bound - offset
	if avail < 40 {
		f.Anomalies.TruncatedLayer = true
		return
	}
	ver := r.data[offset] >> 4
	if ver != 6 {
		f.Anomalies.InvalidIPHeaderLength = true
		return
	}
	payloadLenU16 := binary.BigEndian.Uint16(r.data[offset+4 : offset+6])
	nextHeader := r.data[offset+6]
	hopLimit := r.data[offset+7]

	ipBound := bound
	declaredEnd := offset + 40 + int64(payloadLenU16)
	if declaredEnd <= bound {
		ipBound = declaredEnd
	} else {
		f.Anomalies.IPTotalLengthExceedsFrame = true
	}

	resetTransportFields(f)
	f.IPVersion = 6
	f.IPID = 0
	f.IPFragOffset = 0
	f.IPMoreFragments = false
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
			} else {
				f.PayloadLength = 0
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
		f.PayloadLength = 0
		return
	}

	switch proto {
	case IPProtoTCP:
		if avail < 20 {
			f.Anomalies.TruncatedLayer = true
			return
		}
		tcp := r.data[offset : offset+20]
		f.hasPorts = true
		f.SrcPort = binary.BigEndian.Uint16(tcp[0:2])
		f.DstPort = binary.BigEndian.Uint16(tcp[2:4])
		f.TCPSeq = binary.BigEndian.Uint32(tcp[4:8])
		f.TCPAck = binary.BigEndian.Uint32(tcp[8:12])
		dataOff := int64(tcp[12]>>4) * 4
		f.TCPFlags = tcp[13]
		f.TCPWindow = binary.BigEndian.Uint16(tcp[14:16])
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
		f.hasPorts = true
		f.SrcPort = binary.BigEndian.Uint16(r.data[offset : offset+2])
		f.DstPort = binary.BigEndian.Uint16(r.data[offset+2 : offset+4])
		udpLen := int64(binary.BigEndian.Uint16(r.data[offset+4 : offset+6]))
		udpBound := ipBound
		if udpLen > 0 {
			if udpLen < 8 {
				f.Anomalies.TruncatedLayer = true
				udpBound = offset + 8
			} else if udpLen > avail {
				if !f.Anomalies.IPTotalLengthExceedsFrame {
					f.Anomalies.TruncatedLayer = true
				}
			} else {
				udpBound = offset + udpLen
			}
		}
		f.pushLayer(LayerUDP, offset, 8)
		udpPayloadOff := offset + 8
		udpPayloadLen := udpBound - udpPayloadOff
		f.PayloadOffset = uint32(udpPayloadOff)
		f.PayloadLength = uint32(udpPayloadLen)

		// Peel VXLAN (UDP port 4789, 8-byte VXLAN header with I-flag 0x08 + inner 14-byte Ethernet)
		// or Geneve (UDP port 6081, 8 + OptLen*4 header) when space permits in Layers.
		if int(f.LayerCount)+2 <= MaxFrameLayers {
			if f.DstPort == 4789 && udpPayloadLen >= 8+14 && r.data[udpPayloadOff] == 0x08 {
				f.pushLayer(LayerVXLAN, udpPayloadOff, 8)
				f.PayloadOffset = 0
				f.PayloadLength = 0
				decodeInnerEthernet(r, udpPayloadOff+8, udpBound, f)
			} else if f.DstPort == 6081 && udpPayloadLen >= 8 {
				optLen := int64(r.data[udpPayloadOff]&0x3f) * 4
				geneveHdrLen := 8 + optLen
				protoType := binary.BigEndian.Uint16(r.data[udpPayloadOff+2 : udpPayloadOff+4])
				if udpPayloadLen >= geneveHdrLen {
					f.pushLayer(LayerGeneve, udpPayloadOff, geneveHdrLen)
					innerOff := udpPayloadOff + geneveHdrLen
					switch protoType {
					case EtherTypeTransparentBr:
						f.PayloadOffset = 0
						f.PayloadLength = 0
						decodeInnerEthernet(r, innerOff, udpBound, f)
					case EtherTypeIPv4, EtherTypeIPv6:
						f.PayloadOffset = 0
						f.PayloadLength = 0
						f.EtherType = protoType
						dispatchEtherType(r, innerOff, udpBound, f)
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
		f.PayloadOffset = 0
		f.PayloadLength = 0
		decodeInnerEthernet(r, innerOff, ipBound, f)
	case EtherTypeIPv4, EtherTypeIPv6, EtherTypeMPLSUnicast, EtherTypeMPLSMulticast, EtherTypePPPoESession, EtherTypeVLAN, EtherTypeQinQ, EtherTypeQinQLegacy:
		f.PayloadOffset = 0
		f.PayloadLength = 0
		f.EtherType = protoType
		dispatchEtherType(r, innerOff, ipBound, f)
	default:
		f.PayloadOffset = uint32(innerOff)
		f.PayloadLength = uint32(ipBound - innerOff)
	}
}

func decodeInnerEthernet(r *SafeReader, offset, bound int64, f *Frame) {
	if bound-offset < 14 {
		f.Anomalies.TruncatedLayer = true
		return
	}
	f.EtherType = binary.BigEndian.Uint16(r.data[offset+12 : offset+14])
	f.pushLayer(LayerEthernet, offset, 14)
	dispatchEtherType(r, offset+14, bound, f)
}
