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
	SMB2Command uint16 // Zero for a fragment carried directly over TCP.
}

// DCERPC reports connection-oriented RPC fragments from the contiguous prefix
// of each TCP direction on any port, including verified SMB2 named-pipe
// transfers on TCP port 139 or 445. Results follow packet order.
// A scan error discards the result.
func (c *Capture) DCERPC(data []byte) ([]DCERPCRecord, error) {
	return scanDCERPC(ipFrameSource{capture: c, data: data})
}

// DCERPCFromReaderAt is the bounded ReaderAt equivalent of [Capture.DCERPC].
// Packet metadata and payload reads share [MaxReaderAtScanBytes].
func (c *Capture) DCERPCFromReaderAt(r io.ReaderAt) ([]DCERPCRecord, error) {
	return scanDCERPC(c.tcpReaderAt(r))
}

func scanDCERPC(source ipFrameSource) ([]DCERPCRecord, error) {
	var smb smbRPCScan
	collector := tcpMessageCollector{
		separateInterfaces: source.capture != nil && source.capture.SeparateTCPInterfaces,
		onPair:             smb.pairOpening,
	}
	err := walkTCPMessagePackets(source, collector.add)
	if err != nil {
		return nil, err
	}
	var records []DCERPCRecord
	contexts := MaxDCERPCContextsPerScan
	emit := func(dir *tcpMessageDirection, pkt messagePacket, msg DCERPCMessage, smbCommand uint16) error {
		if len(records) == MaxDCERPCRecordsPerScan || len(msg.Contexts) > contexts {
			return ErrDCERPCLimit
		}
		contexts -= len(msg.Contexts)
		records = append(records, DCERPCRecord{
			PacketIndex: pkt.index, TimestampNs: pkt.timestamp, FlowIndex: dir.flowIndex,
			Source: dir.src, Destination: dir.dst, Message: msg, SMB2Command: smbCommand,
		})
		return nil
	}
	err = collector.walkContiguous(func(dir *tcpMessageDirection, data []byte, spans []packetSpan, _ StreamAnomalies) error {
		if !hasDCERPCPrefix(data) {
			if isRPCSMBPort(dir.src.Port(), dir.dst.Port()) {
				return smb.collect(dir, data, spans)
			}
			return nil
		}
		span := 0
		return walkDCERPCFragments(data, func(off int, msg DCERPCMessage) error {
			for spans[span].end <= off {
				span++
			}
			return emit(dir, dir.packets[spans[span].segment], msg, 0)
		})
	})
	if err != nil {
		return nil, err
	}
	if err := smb.walk(emit); err != nil {
		return nil, err
	}
	slices.SortStableFunc(records, func(a, b DCERPCRecord) int { return cmp.Compare(a.PacketIndex, b.PacketIndex) })
	return records, nil
}

func hasDCERPCPrefix(data []byte) bool {
	return len(data) >= 2 && data[0] == 5 && data[1] == 0
}

func walkDCERPCFragments(data []byte, visit func(int, DCERPCMessage) error) error {
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
			if err := visit(off, msg); err != nil {
				return err
			}
		}
		off += len(fragment)
	}
	return nil
}
