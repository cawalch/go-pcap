package pcap

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
)

// IPFragmentInput describes one IPv4 or IPv6 fragment for [DefragmentIP].
type IPFragmentInput struct {
	SrcAddr        netip.Addr
	DstAddr        netip.Addr
	Protocol       uint8
	Identification uint32
	FragmentOffset int // Byte offset in the reassembled L4 payload (8-byte units * 8)
	MoreFragments  bool
	Payload        []byte
}

type normIPFrag struct {
	start   int
	end     int
	payload []byte
	order   int
}

// DefragmentIP reassembles a single IPv4 or IPv6 packet's L4 payload from its
// fragments. Supply addresses to identify the IP version. For IPv6, any
// overlap (including identical bytes) discards the datagram and sets
// IPFragmentOverlapConflict. Submit atomic IPv6 packets independently.
//
// It returns [ErrFragmentLimit] if len(fragments) exceeds
// [MaxFragmentsPerGroup] or if any fragment extends beyond
// [MaxReassembledIPPacketBytes]. For IPv4, if overlapping fragments disagree on bytes at
// the same offset, DefragmentIP retains the first-seen bytes and sets
// [FrameAnomalies.IPFragmentOverlapConflict]. If a gap remains or the final
// fragment (MoreFragments == false) is missing, it sets
// [FrameAnomalies.TruncatedLayer].
func DefragmentIP(fragments []IPFragmentInput) ([]byte, FrameAnomalies, error) {
	var anomalies FrameAnomalies
	if len(fragments) == 0 {
		return nil, anomalies, nil
	}
	if len(fragments) > MaxFragmentsPerGroup {
		return nil, anomalies, fmt.Errorf("%w: %d fragments exceed %d", ErrFragmentLimit, len(fragments), MaxFragmentsPerGroup)
	}

	var storage [MaxFragmentsPerGroup]normIPFrag
	norm := storage[:0]
	ipv6 := fragments[0].SrcAddr.Is6()
	seenTerminal := false

	for i := range fragments {
		frag := &fragments[i]
		if ipv6 && frag.FragmentOffset == 0 && frag.MoreFragments && shortFragmentHeader(frag.Protocol, frag.Payload) {
			anomalies.TruncatedLayer = true
			return nil, anomalies, nil
		}
		if frag.FragmentOffset < 0 || len(frag.Payload) == 0 {
			continue
		}
		if frag.FragmentOffset > MaxReassembledIPPacketBytes-len(frag.Payload) {
			return nil, anomalies, fmt.Errorf("%w: fragment at %d exceeds %d", ErrFragmentLimit, frag.FragmentOffset, MaxReassembledIPPacketBytes)
		}
		end := frag.FragmentOffset + len(frag.Payload)
		if !frag.MoreFragments {
			seenTerminal = true
		}
		norm = append(norm, normIPFrag{
			start:   frag.FragmentOffset,
			end:     end,
			payload: frag.Payload,
			order:   i,
		})
	}

	if len(norm) == 0 {
		return nil, anomalies, nil
	}
	if !seenTerminal {
		anomalies.TruncatedLayer = true
	}

	slices.SortFunc(norm, func(a, b normIPFrag) int {
		if c := cmp.Compare(a.start, b.start); c != 0 {
			return c
		}
		return cmp.Compare(a.order, b.order)
	})

	if ipv6 {
		end := 0
		for _, f := range norm {
			if f.start < end {
				anomalies.IPFragmentOverlapConflict = true
				return nil, anomalies, nil
			}
			if f.start > end {
				anomalies.TruncatedLayer = true
			}
			end = f.end
		}
		if anomalies.TruncatedLayer {
			return nil, anomalies, nil
		}
		out := make([]byte, end)
		for _, f := range norm {
			copy(out[f.start:f.end], f.payload)
		}
		return out, anomalies, nil
	}

	var buf bytes.Buffer
	cursor := 0
	for i := range norm {
		f := &norm[i]
		if f.start > cursor {
			anomalies.TruncatedLayer = true
			cursor = f.start
		}
		if f.start < cursor {
			overlapEnd := min(f.end, cursor)
			overlapLen := overlapEnd - f.start
			written := buf.Bytes()
			if len(written) >= cursor && f.start >= 0 && overlapEnd <= len(written) {
				if !bytes.Equal(written[f.start:overlapEnd], f.payload[:overlapLen]) {
					anomalies.IPFragmentOverlapConflict = true
				}
			}
			if f.end <= cursor {
				continue
			}
			buf.Write(f.payload[cursor-f.start:])
			cursor = f.end
		} else {
			buf.Write(f.payload)
			cursor = f.end
		}
	}

	return buf.Bytes(), anomalies, nil
}

// A fragmented IPv6 datagram must carry the complete transport header
// in its first fragment (RFC 8200, section 4.5).
func shortFragmentHeader(proto uint8, payload []byte) bool {
	switch proto {
	case IPProtoUDP, IPProtoIPv6ICMP:
		return len(payload) < 8
	case IPProtoTCP:
		return len(payload) < 20 || payload[12]>>4 < 5 || int(payload[12]>>4)*4 > len(payload)
	}
	return false
}

type ipFragKey struct {
	srcAddr  netip.Addr
	dstAddr  netip.Addr
	ipID     uint32
	version  uint8
	protocol uint8
}

type ipFragGroup struct {
	frags       []IPFragmentInput
	hasZero     bool
	hasTerminal bool
	done        bool
}

type ipFragAccumulator struct {
	groups map[ipFragKey]*ipFragGroup
}

func (a *ipFragAccumulator) addUDPFragment(frame *Frame, packetPayload []byte) (udpPayload []byte, srcPort, dstPort uint16, ok bool) {
	if (frame.PayloadLength == 0 && frame.IPVersion != 6) || uint64(frame.PayloadOffset)+uint64(frame.PayloadLength) > uint64(len(packetPayload)) {
		return nil, 0, 0, false
	}
	if a.groups == nil {
		a.groups = make(map[ipFragKey]*ipFragGroup)
	}
	key := ipFragKey{
		srcAddr:  frame.SrcAddr,
		dstAddr:  frame.DstAddr,
		ipID:     frame.IPID,
		version:  frame.IPVersion,
		protocol: frame.IPProtocol,
	}
	g, exists := a.groups[key]
	if !exists {
		if len(a.groups) >= MaxFragmentGroups {
			return nil, 0, 0, false
		}
		g = &ipFragGroup{}
		a.groups[key] = g
	}
	if g.done || len(g.frags) >= MaxFragmentsPerGroup {
		return nil, 0, 0, false
	}

	fragBytes := packetPayload[frame.PayloadOffset : frame.PayloadOffset+frame.PayloadLength]
	if frame.IPVersion == 6 && frame.Anomalies.TruncatedLayer {
		g.done = true
		g.frags = nil
		return nil, 0, 0, false
	}
	g.frags = append(g.frags, IPFragmentInput{
		SrcAddr:        frame.SrcAddr,
		DstAddr:        frame.DstAddr,
		Protocol:       frame.IPProtocol,
		Identification: frame.IPID,
		FragmentOffset: int(frame.IPFragOffset),
		MoreFragments:  frame.IPMoreFragments,
		Payload:        fragBytes,
	})
	if frame.IPFragOffset == 0 {
		g.hasZero = true
	}
	if !frame.IPMoreFragments {
		g.hasTerminal = true
	}
	if !g.hasZero || !g.hasTerminal {
		return nil, 0, 0, false
	}

	reassembled, anomalies, err := DefragmentIP(g.frags)
	if frame.IPVersion == 6 && anomalies.IPFragmentOverlapConflict {
		g.done = true
		g.frags = nil
	}
	if err != nil || anomalies.TruncatedLayer || len(reassembled) < 8 {
		return nil, 0, 0, false
	}
	g.done = true
	g.frags = nil
	srcPort = binary.BigEndian.Uint16(reassembled[0:2])
	dstPort = binary.BigEndian.Uint16(reassembled[2:4])
	return reassembled[8:], srcPort, dstPort, true
}
