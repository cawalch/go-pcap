package pcap

import (
	"cmp"
	"errors"
	"io"
	"net/netip"
	"slices"
)

// DCERPCRecord identifies a connection-oriented fragment in a capture.
// PacketIndex and TimestampNs identify the packet supplying its first byte.
type DCERPCRecord struct {
	PacketIndex int
	TimestampNs int64
	FlowIndex   int
	Source      netip.AddrPort
	Destination netip.AddrPort
	Message     DCERPCMessage
}

// DCERPC reports connection-oriented RPC fragments from the contiguous prefix
// of each TCP direction on any port. Results follow packet order. A scan error
// discards the result.
func (c *Capture) DCERPC(data []byte) ([]DCERPCRecord, error) {
	return scanDCERPC(ipFrameSource{capture: c, data: data})
}

// DCERPCFromReaderAt is the bounded ReaderAt equivalent of [Capture.DCERPC].
// Packet metadata and payload reads share [MaxReaderAtScanBytes].
func (c *Capture) DCERPCFromReaderAt(r io.ReaderAt) ([]DCERPCRecord, error) {
	return scanDCERPC(c.tcpReaderAt(r))
}

func scanDCERPC(source ipFrameSource) ([]DCERPCRecord, error) {
	collector, err := collectTCPMessages(source)
	if err != nil {
		return nil, err
	}
	var records []DCERPCRecord
	contexts := MaxDCERPCContextsPerScan
	err = collector.walkContiguous(func(dir *tcpMessageDirection, data []byte, spans []packetSpan, _ StreamAnomalies) error {
		if len(data) < 2 || data[0] != 5 || data[1] != 0 {
			return nil
		}
		span := 0
		for off := 0; off < len(data); {
			fragment, order, err := readDCERPCFragment(data[off:])
			if err != nil {
				break
			}
			msg, err := parseDCERPCFragment(fragment, order)
			if errors.Is(err, ErrDCERPCLimit) {
				return err
			}
			if err == nil {
				if len(records) == MaxDCERPCRecordsPerScan || len(msg.Contexts) > contexts {
					return ErrDCERPCLimit
				}
				contexts -= len(msg.Contexts)
				for spans[span].end <= off {
					span++
				}
				pkt := dir.packets[spans[span].segment]
				records = append(records, DCERPCRecord{
					PacketIndex: pkt.index, TimestampNs: pkt.timestamp, FlowIndex: dir.flowIndex,
					Source: dir.src, Destination: dir.dst, Message: msg,
				})
			}
			off += len(fragment)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.SortStableFunc(records, func(a, b DCERPCRecord) int { return cmp.Compare(a.PacketIndex, b.PacketIndex) })
	return records, nil
}
