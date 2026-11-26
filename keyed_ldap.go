package pcap

import (
	"errors"
	"io"
	"net/netip"
	"slices"
)

const ldapsPort = 636

// KeyedLDAPRecord describes a request in authenticated LDAPS app data.
// PlaintextOffset is relative to the recovered client direction. Records
// contains the whole authenticated TLS records intersecting the request.
// PacketIndices is the sorted union of the packets supplying those records.
type KeyedLDAPRecord struct {
	OpeningPacket   int
	FlowIndex       int
	Source          netip.AddrPort
	Destination     netip.AddrPort
	PlaintextOffset int
	Message         LDAPMessage
	Records         []TLSRecordEvidence
	PacketIndices   []int
	Coverage        TLSPlaintextCoverage
}

// KeyedLDAP extracts Bind and Search requests from authenticated TLS 1.2
// or TLS 1.3 application data on TCP port 636. It uses embedded PcapNG
// decryption secrets and optional NSS key log bytes. Results are ordered
// by TCP opening and plaintext offset and retain no keys or credentials.
func (c *Capture) KeyedLDAP(data, extraKeyLog []byte) ([]KeyedLDAPRecord, error) {
	return scanKeyedLDAP(ipFrameSource{capture: c, data: data}, extraKeyLog)
}

// KeyedLDAPFromReaderAt is the bounded ReaderAt equivalent of
// [Capture.KeyedLDAP]. All reads share [MaxReaderAtScanBytes].
func (c *Capture) KeyedLDAPFromReaderAt(r io.ReaderAt, extraKeyLog []byte) ([]KeyedLDAPRecord, error) {
	return scanKeyedLDAP(ipFrameSource{capture: c, reader: r, needsPayload: func(f Frame, _ []byte) bool {
		return f.IPProtocol == IPProtoTCP && (f.SrcPort == ldapsPort || f.DstPort == ldapsPort)
	}}, extraKeyLog)
}

func scanKeyedLDAP(source ipFrameSource, extraKeyLog []byte) ([]KeyedLDAPRecord, error) {
	streams, err := scanTLSProvenanceOnPort(source, extraKeyLog, ldapsPort)
	if err != nil {
		return nil, err
	}
	var rows []KeyedLDAPRecord
	var usage ldapScanUsage
	evidenceBudget := maxTLSProvenanceRanges
	for _, stream := range streams {
		data := stream.Client.Data
		for off := 0; off < len(data); {
			wire := ldapMessagePrefix(data[off:])
			if wire == nil {
				break
			}
			start := off
			off += len(wire)
			msg, err := ParseLDAP(wire)
			if errors.Is(err, ErrLDAPLimit) {
				return nil, err
			}
			if err != nil {
				continue
			}
			var packets []int
			records, err := stream.client.evidence(start, off, false, &packets, &evidenceBudget)
			if err != nil {
				return nil, ErrLDAPLimit
			}
			if len(records) == 0 || records[0].PlaintextStart > start || records[len(records)-1].PlaintextEnd < off {
				break
			}
			if err := usage.add(msg); err != nil {
				return nil, err
			}
			slices.Sort(packets)
			rows = append(rows, KeyedLDAPRecord{
				OpeningPacket: stream.openingPacket, FlowIndex: stream.FlowIndex,
				Source:          netip.AddrPortFrom(stream.SrcAddr, stream.SrcPort),
				Destination:     netip.AddrPortFrom(stream.DstAddr, stream.DstPort),
				PlaintextOffset: start, Message: msg, Records: records,
				PacketIndices: slices.Compact(packets), Coverage: stream.client.coverage(len(data)),
			})
		}
	}
	return rows, nil
}
