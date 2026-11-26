package pcap

import (
	"io"
	"net/netip"
)

// TCPZeroWindowSummary counts packets advertising a zero TCP receive window
// from Source to Destination. FlowIndex uses the order of [Capture.Flows].
// The packet indices are zero-based. First and last refer to capture order.
type TCPZeroWindowSummary struct {
	FlowIndex        int
	Source           netip.AddrPort
	Destination      netip.AddrPort
	Count            int
	FirstPacketIndex int
	LastPacketIndex  int
	FirstTimestampNs int64
	LastTimestampNs  int64
}

// TCPZeroWindows groups zero receive window advertisements by flow direction
// in first-observed order. A qualifying packet has a complete TCP header, a
// zero window and ACK set, with SYN, FIN and RST clear. The scan skips fragments.
// Counts include repeated observations. A five-tuple can span several
// connections and capture interfaces. The summaries describe captured packets
// and do not estimate the duration of a closed window.
//
// The scan uses [MaxFlows] and returns no summaries on error.
func (c *Capture) TCPZeroWindows(data []byte) ([]TCPZeroWindowSummary, error) {
	return scanTCPZeroWindows(ipFrameSource{capture: c, data: data})
}

// TCPZeroWindowsFromReaderAt is the file-backed equivalent of
// [Capture.TCPZeroWindows]. Reads share [MaxReaderAtScanBytes].
func (c *Capture) TCPZeroWindowsFromReaderAt(r io.ReaderAt) ([]TCPZeroWindowSummary, error) {
	return scanTCPZeroWindows(ipFrameSource{
		capture: c, reader: r, needsPayload: func(Frame, []byte) bool { return false },
	})
}

func scanTCPZeroWindows(source ipFrameSource) ([]TCPZeroWindowSummary, error) {
	const flags = TCPFlagACK | TCPFlagSYN | TCPFlagFIN | TCPFlagRST
	type direction struct {
		flow      int
		canonical bool
	}
	var flows flowIndexTable
	var index map[direction]int
	var groups []TCPZeroWindowSummary
	err := source.walk(func(pkt PacketRecord, f Frame, _ []byte) error {
		key, canonical := makeCanonicalFlowKey(f.IPProtocol, f.SrcAddr, f.SrcPort, f.DstAddr, f.DstPort)
		flow, _, err := flows.lookupOrInsert(key)
		if err != nil {
			return err
		}
		if f.IPProtocol != IPProtoTCP || f.TCPWindow != 0 || f.TCPFlags&flags != TCPFlagACK ||
			f.Anomalies.IPFragment || f.LayerCount == 0 || f.Layers[f.LayerCount-1].Proto != LayerTCP {
			return nil
		}

		d := direction{flow, canonical}
		i, found := index[d]
		if !found {
			if index == nil {
				index = make(map[direction]int)
			}
			i = len(groups)
			index[d] = i
			groups = append(groups, TCPZeroWindowSummary{
				FlowIndex:        flow,
				Source:           netip.AddrPortFrom(f.SrcAddr, f.SrcPort),
				Destination:      netip.AddrPortFrom(f.DstAddr, f.DstPort),
				FirstPacketIndex: pkt.Index,
				FirstTimestampNs: pkt.TimestampNs,
			})
		}
		group := &groups[i]
		group.Count++
		group.LastPacketIndex = pkt.Index
		group.LastTimestampNs = pkt.TimestampNs
		return nil
	})
	if err != nil {
		return nil, err
	}
	return groups, nil
}
