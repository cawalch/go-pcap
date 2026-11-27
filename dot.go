package pcap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
)

const dnsOverTLSPort = 853

// DNSOverTLSRecord pairs a DNS message recovered from authenticated TLS
// application data with its capture flow index and directional endpoints.
type DNSOverTLSRecord struct {
	FlowIndex        int
	SrcAddr, DstAddr netip.Addr
	SrcPort, DstPort uint16
	Message          DNSMessage
}

// DNSOverTLS extracts length-prefixed DNS messages from TLS on TCP port 853.
// It uses embedded TLS key logs and optional extraKeyLog bytes in NSS format.
// Records follow first-seen flow order, client direction first, then wire order
// within each direction. A known TCP gap excludes that direction. An incomplete
// or undersized frame ends its direction. A DNS parse error skips that frame.
// It returns no records on scan errors, including exceeding [MaxDNSMessagesPerScan].
func (c *Capture) DNSOverTLS(data, extraKeyLog []byte) ([]DNSOverTLSRecord, error) {
	return scanDNSOverTLS(ipFrameSource{capture: c, data: data}, extraKeyLog)
}

// DNSOverTLSFromReaderAt extracts the same messages as [Capture.DNSOverTLS]
// under [MaxReaderAtScanBytes]. Only TCP/853 flows need full TCP payloads.
func (c *Capture) DNSOverTLSFromReaderAt(r io.ReaderAt, extraKeyLog []byte) ([]DNSOverTLSRecord, error) {
	if r == nil {
		return nil, ErrInvalidHeader
	}
	return scanDNSOverTLS(c.dotReaderAt(r), extraKeyLog)
}

func (c *Capture) dotReaderAt(r io.ReaderAt) ipFrameSource {
	return ipFrameSource{capture: c, reader: r, needsPayload: func(f Frame, _ []byte) bool {
		return f.IPProtocol == IPProtoTCP && (f.SrcPort == dnsOverTLSPort || f.DstPort == dnsOverTLSPort)
	}}
}

func scanDNSOverTLS(source ipFrameSource, extraKeyLog []byte) ([]DNSOverTLSRecord, error) {
	keys, err := source.capture.TLSKeyLog(extraKeyLog)
	if err != nil || len(keys.Entries) == 0 {
		return nil, err
	}
	streams, err := collectStreams(source, dnsOverTLSPort, nil, tcpWireNone)
	if err != nil {
		return nil, err
	}
	var records []DNSOverTLSRecord
	for _, stream := range decryptTLSStreams(streams, keys) {
		record := DNSOverTLSRecord{FlowIndex: stream.FlowIndex, SrcAddr: stream.SrcAddr, DstAddr: stream.DstAddr, SrcPort: stream.SrcPort, DstPort: stream.DstPort}
		for i, dir := range [...]StreamBuffer{stream.Client, stream.Server} {
			if i == 1 {
				record.SrcAddr, record.DstAddr = stream.DstAddr, stream.SrcAddr
				record.SrcPort, record.DstPort = stream.DstPort, stream.SrcPort
			}
			if dir.Anomalies.SequenceGap {
				continue
			}
			for data := dir.Data; len(data) >= 2; {
				n := int(binary.BigEndian.Uint16(data))
				data = data[2:]
				if n < 12 || n > len(data) {
					break
				}
				msg, err := ParseDNS(data[:n])
				data = data[n:]
				if err != nil {
					continue
				}
				if len(records) == MaxDNSMessagesPerScan {
					return nil, fmt.Errorf("%w: exceeds %d messages", ErrDNSLimit, MaxDNSMessagesPerScan)
				}
				record.Message = msg
				records = append(records, record)
			}
		}
	}
	return records, nil
}

// DNSOverTLSMessage contains one observed length-framed DNS message and the
// whole authenticated TLS records that supplied its length prefix and body.
// PacketIndices lists the distinct original packets supplying those records.
// DNSRecord.PacketIndex marks when the contiguous prefix through this message
// became available. It includes the arrival of any preceding out-of-order
// records. TimestampNs is zero. The caller owns the result.
type DNSOverTLSMessage struct {
	DNSRecord
	Records       []TLSRecordEvidence
	PacketIndices []int
}

// DNSOverTLSTransaction is a paired lookup or an unpaired observation within
// one TLS connection. OpeningPacket identifies the first observed TCP packet
// of that opening. Query and Reply are both present only for [DNSPaired].
type DNSOverTLSTransaction struct {
	OpeningPacket int
	Pairing       DNSPairing
	Query, Reply  *DNSOverTLSMessage
}

// DNSOverTLSOpeningCoverage identifies a TCP/853 opening with paired TLS
// hellos. OpeningPacket and FlowIndex identify the original capture. TLS
// coverage describes each recovered direction. IncompleteFrame identifies
// an undersized or incomplete DNS frame at the end of the parsed prefix.
// If EarlyDataOffered is true, the scan reports TLS coverage for the opening
// and skips DNS framing because acceptance of early data is unknown.
type DNSOverTLSOpeningCoverage struct {
	OpeningPacket, FlowIndex                     int
	Client, Server                               netip.AddrPort
	ClientCoverage, ServerCoverage               TLSDirectionCoverage
	ClientIncompleteFrame, ServerIncompleteFrame bool
	EarlyDataOffered                             bool
}

// DNSOverTLSAnalysis contains DNS transaction evidence and recognized TLS
// openings in opening order. An opening can have no transactions.
type DNSOverTLSAnalysis struct {
	Transactions []DNSOverTLSTransaction
	Openings     []DNSOverTLSOpeningCoverage
}

// AnalyzeDNSOverTLS pairs authenticated queries and replies on TCP/853 by
// their message ID and question. Pairing separates interfaces and observed
// TCP openings. A missing SYN can hide reuse of the same five-tuple. Ordinary
// single-question lookups are supported. Responses without an echoed
// question, zone transfers and other unsupported layouts have [DNSUnsupported]
// pairing. Complete frames with invalid DNS syntax are skipped. Results within
// an opening follow the first observation's capture order.
//
// Missing keys or ciphertext leave coverage, subject to observing both TLS
// hellos. On scan errors, including a DNS parse limit or exhausting the
// aggregate message, DNS record, or packet-reference allowance, it returns a zero result.
func (c *Capture) AnalyzeDNSOverTLS(data, extraKeyLog []byte) (DNSOverTLSAnalysis, error) {
	return analyzeDNSOverTLS(ipFrameSource{capture: c, data: data}, extraKeyLog)
}

// AnalyzeDNSOverTLSFromReaderAt is the seekable equivalent of
// [Capture.AnalyzeDNSOverTLS]. Only TCP/853 needs full payloads. Capture reads
// share [MaxReaderAtScanBytes].
func (c *Capture) AnalyzeDNSOverTLSFromReaderAt(r io.ReaderAt, extraKeyLog []byte) (DNSOverTLSAnalysis, error) {
	if r == nil {
		return DNSOverTLSAnalysis{}, ErrInvalidHeader
	}
	return analyzeDNSOverTLS(c.dotReaderAt(r), extraKeyLog)
}

type dnsOverTLSBudget struct {
	messages, records, references int
}

type dnsOverTLSOpeningScan struct {
	messages     map[*DNSRecord]*DNSOverTLSMessage
	observations []dnsTransactionObservation
}

func analyzeDNSOverTLS(source ipFrameSource, keys []byte) (DNSOverTLSAnalysis, error) {
	if err := source.capture.validateContainer(); err != nil {
		return DNSOverTLSAnalysis{}, err
	}
	capture := *source.capture
	capture.SeparateTCPInterfaces = true
	source.capture = &capture
	streams, err := scanTLSProvenanceOnPort(source, keys, dnsOverTLSPort)
	if err != nil {
		return DNSOverTLSAnalysis{}, err
	}
	var out DNSOverTLSAnalysis
	budget := dnsOverTLSBudget{
		messages: MaxDNSMessagesPerScan, records: MaxDNSMessagesPerScan, references: maxTLSProvenanceRanges,
	}
	for i := range streams {
		s := &streams[i]
		if s.DstPort != dnsOverTLSPort {
			continue
		}
		opening := DNSOverTLSOpeningCoverage{
			OpeningPacket: s.openingPacket, FlowIndex: s.FlowIndex,
			Client: netip.AddrPortFrom(s.SrcAddr, s.SrcPort), Server: netip.AddrPortFrom(s.DstAddr, s.DstPort),
			ClientCoverage:   annotatedTLSCoverage(&s.client, len(s.Client.Data)),
			ServerCoverage:   annotatedTLSCoverage(&s.server, len(s.Server.Data)),
			EarlyDataOffered: s.earlyOffered || s.firstRegularRecord() != 0,
		}
		if !opening.EarlyDataOffered {
			scan := dnsOverTLSOpeningScan{messages: make(map[*DNSRecord]*DNSOverTLSMessage)}
			opening.ClientIncompleteFrame, err = scan.read(&opening, false, s.Client.Data, &s.client, &budget)
			if err != nil {
				return DNSOverTLSAnalysis{}, err
			}
			opening.ServerIncompleteFrame, err = scan.read(&opening, true, s.Server.Data, &s.server, &budget)
			if err != nil {
				return DNSOverTLSAnalysis{}, err
			}
			for _, row := range pairDNSObservations(scan.observations) {
				out.Transactions = append(out.Transactions, DNSOverTLSTransaction{
					OpeningPacket: opening.OpeningPacket, Pairing: row.Pairing,
					Query: scan.messages[row.Query], Reply: scan.messages[row.Reply],
				})
			}
		}
		out.Openings = append(out.Openings, opening)
	}
	return out, nil
}

func (s *dnsOverTLSOpeningScan) read(opening *DNSOverTLSOpeningCoverage, server bool, data []byte, direction *tlsDirectionProvenance, budget *dnsOverTLSBudget) (bool, error) {
	src, dst := opening.Client, opening.Server
	if server {
		src, dst = dst, src
	}
	// A later TLS record can arrive before an earlier record in this direction.
	// Keep DNS wire order for messages made available by the same packet.
	packetIndex, nextRecord := -1, 0
	for start := 0; start < len(data); {
		if len(data)-start < 2 {
			return true, nil
		}
		n := int(binary.BigEndian.Uint16(data[start:]))
		if n < 12 || n > len(data)-start-2 {
			return true, nil
		}
		end := start + 2 + n
		for nextRecord < len(direction.records) && direction.records[nextRecord].plainStart < end {
			r := &direction.records[nextRecord]
			packetIndex = max(packetIndex, r.packets[len(r.packets)-1])
			nextRecord++
		}
		wire := data[start+2 : end]
		message, err := ParseDNS(wire)
		if errors.Is(err, ErrDNSLimit) {
			return false, err
		}
		if err == nil {
			records := len(message.Questions) + len(message.Answers) + len(message.Authorities) + len(message.Additionals)
			if budget.messages == 0 || records > budget.records {
				return false, ErrDNSLimit
			}
			budget.messages--
			budget.records -= records
			evidence := new(DNSOverTLSMessage)
			evidence.Records, err = direction.evidence(start, end, false, &evidence.PacketIndices, &budget.references)
			if err != nil {
				return false, fmt.Errorf("%w: DoT packet evidence exceeds %d references", ErrDNSLimit, maxTLSProvenanceRanges)
			}
			slices.Sort(evidence.PacketIndices)
			evidence.PacketIndices = slices.Compact(evidence.PacketIndices)
			evidence.DNSRecord = DNSRecord{
				PacketIndex: packetIndex, FlowIndex: opening.FlowIndex,
				SrcAddr: src.Addr(), DstAddr: dst.Addr(), SrcPort: src.Port(), DstPort: dst.Port(), Message: message,
			}
			key := dnsTransactionKey{client: opening.Client, resolver: opening.Server, opening: opening.OpeningPacket, id: message.TransactionID}
			if server == message.IsResponse {
				key.setQuestion(&message, wire)
			}
			record := &evidence.DNSRecord
			s.messages[record] = evidence
			s.observations = append(s.observations, dnsTransactionObservation{record, key})
		}
		start = end
	}
	return false, nil
}
