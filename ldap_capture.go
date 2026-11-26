package pcap

import (
	"cmp"
	"errors"
	"io"
	"net/netip"
	"slices"
)

const ldapPort = 389

// LDAPRecord identifies a request in a capture. For TCP, PacketIndex and
// TimestampNs identify the packet supplying the first byte of the message.
type LDAPRecord struct {
	PacketIndex int
	TimestampNs int64
	FlowIndex   int
	Source      netip.AddrPort
	Destination netip.AddrPort
	IPProtocol  uint8
	Message     LDAPMessage
}

// LDAP reports cleartext Bind and Search requests on TCP port 389 and
// LDAPMessage Search requests in complete UDP datagrams on port 389.
// TCP parsing uses each connection's contiguous prefix. Results follow
// packet order and own their metadata. A scan error discards the result.
func (c *Capture) LDAP(data []byte) ([]LDAPRecord, error) {
	return scanLDAP(ipFrameSource{capture: c, data: data})
}

// LDAPFromReaderAt is the bounded ReaderAt equivalent of [Capture.LDAP].
// Packet metadata and selected payload reads share [MaxReaderAtScanBytes].
func (c *Capture) LDAPFromReaderAt(r io.ReaderAt) ([]LDAPRecord, error) {
	return scanLDAP(ipFrameSource{
		capture: c, reader: r,
		needsPayload: func(f Frame, _ []byte) bool { return ldapCaptureFrame(f) },
	})
}

func ldapCaptureFrame(f Frame) bool {
	if !f.hasPorts || f.SrcPort != ldapPort && f.DstPort != ldapPort ||
		f.Anomalies.IPFragment || f.Anomalies.TruncatedLayer {
		return false
	}
	return f.IPProtocol == IPProtoTCP && !f.Anomalies.InvalidTCPDataOffset ||
		f.IPProtocol == IPProtoUDP && !f.Anomalies.IPTotalLengthExceedsFrame
}

type ldapScanUsage struct {
	records, text int
}

func (u *ldapScanUsage) add(msg LDAPMessage) error {
	text := len(msg.BindDN) + len(msg.SASLMechanism) + len(msg.BaseDN) + len(msg.Filter)
	for _, attr := range msg.Attributes {
		text += len(attr)
	}
	if u.records == MaxLDAPRecordsPerScan || text > MaxLDAPTextBytesPerScan-u.text {
		return ErrLDAPLimit
	}
	u.records++
	u.text += text
	return nil
}

func ldapMessagePrefix(data []byte) []byte {
	tag, _, rest, ok := readBERTLV(data)
	if !ok || tag != 0x30 {
		return nil
	}
	return data[:len(data)-len(rest)]
}

func scanLDAP(source ipFrameSource) ([]LDAPRecord, error) {
	var table flowIndexTable
	var records []LDAPRecord
	var usage ldapScanUsage
	remainingTCP := MaxTotalStreamBytes
	add := func(wire []byte, record LDAPRecord) error {
		message, err := ParseLDAP(wire)
		if errors.Is(err, ErrLDAPLimit) {
			return err
		}
		if err != nil || record.IPProtocol == IPProtoUDP && message.Operation != LDAPSearchRequest {
			return nil
		}
		if err := usage.add(message); err != nil {
			return err
		}
		record.Message = message
		records = append(records, record)
		return nil
	}
	tcp := tcpMessageCollector{separateInterfaces: source.capture != nil && source.capture.SeparateTCPInterfaces}
	err := source.walk(func(pkt PacketRecord, f Frame, payload []byte) error {
		key, _ := makeCanonicalFlowKey(f.IPProtocol, f.SrcAddr, f.SrcPort, f.DstAddr, f.DstPort)
		flow, _, err := table.lookupOrInsert(key)
		if err != nil || !ldapCaptureFrame(f) {
			return err
		}
		if f.IPProtocol == IPProtoTCP {
			if len(payload) > remainingTCP {
				return ErrReassemblyLimit
			}
			remainingTCP -= len(payload)
			return tcp.add(pkt, f, flow, payload)
		}
		return add(payload, LDAPRecord{
			PacketIndex: pkt.Index, TimestampNs: pkt.TimestampNs, FlowIndex: flow, IPProtocol: IPProtoUDP,
			Source: netip.AddrPortFrom(f.SrcAddr, f.SrcPort), Destination: netip.AddrPortFrom(f.DstAddr, f.DstPort),
		})
	})
	if err != nil {
		return nil, err
	}
	err = tcp.walkContiguous(func(dir *tcpMessageDirection, data []byte, spans []packetSpan, _ StreamAnomalies) error {
		span := 0
		for off := 0; off < len(data); {
			wire := ldapMessagePrefix(data[off:])
			if wire == nil {
				break
			}
			for spans[span].end <= off {
				span++
			}
			pkt := dir.packets[spans[span].segment]
			if err := add(wire, LDAPRecord{
				PacketIndex: pkt.index, TimestampNs: pkt.timestamp, FlowIndex: dir.flowIndex, IPProtocol: IPProtoTCP,
				Source: dir.src, Destination: dir.dst,
			}); err != nil {
				return err
			}
			off += len(wire)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.SortStableFunc(records, func(a, b LDAPRecord) int { return cmp.Compare(a.PacketIndex, b.PacketIndex) })
	return records, nil
}
