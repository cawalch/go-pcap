package pcap

import (
	"cmp"
	"io"
	"net/netip"
	"slices"
	"time"
)

// DNSPairing describes the observed relationship between a unicast query and reply.
type DNSPairing uint8

const (
	// DNSUnsupported covers observations outside single-question standard lookups.
	DNSUnsupported DNSPairing = iota
	// DNSPaired identifies one observed query and its matching reply.
	DNSPaired
	// DNSNoReplyObserved identifies a query without a matching observed reply.
	DNSNoReplyObserved
	// DNSNoQueryObserved identifies a reply without an outstanding matching query.
	DNSNoQueryObserved
	// DNSAmbiguous identifies an observation whose pairing key had overlapping queries.
	DNSAmbiguous
)

// DNSTransaction retains the original records for one paired lookup or one
// unpaired observation. Query and Reply are both present only for [DNSPaired].
// The caller owns the records and their decoded fields.
type DNSTransaction struct {
	Pairing      DNSPairing
	Query, Reply *DNSRecord
}

// Elapsed returns the capture time between a paired query and reply. It returns
// false when either timestamp is zero or negative, or the clock moved backward.
func (t DNSTransaction) Elapsed() (time.Duration, bool) {
	if t.Pairing != DNSPaired || t.Query == nil || t.Reply == nil ||
		t.Query.TimestampNs <= 0 || t.Reply.TimestampNs < t.Query.TimestampNs {
		return 0, false
	}
	return time.Duration(t.Reply.TimestampNs - t.Query.TimestampNs), true
}

// DNSTransactions pairs standard single-question unicast DNS on UDP or TCP port
// 53 in capture packet order. Each PcapNG interface is an independent observation
// point for fragment reassembly, TCP openings, and pairing. Connections without
// an observed new opening can be indistinguishable when their five-tuple is reused.
// Output follows the first record in each row. At most [MaxDNSMessagesPerScan]
// decoded records contribute to the scan. A scan or limit error discards the result.
func (c *Capture) DNSTransactions(data []byte) ([]DNSTransaction, error) {
	return scanDNSTransactions(ipFrameSource{capture: c, data: data}, false)
}

// DNSTransactionsFromReaderAt is the bounded ReaderAt equivalent of
// [Capture.DNSTransactions]. All metadata and payload reads share [MaxReaderAtScanBytes].
func (c *Capture) DNSTransactionsFromReaderAt(r io.ReaderAt) ([]DNSTransaction, error) {
	return scanDNSTransactions(c.dnsTransactionReaderAt(r), false)
}

func (c *Capture) dnsTransactionReaderAt(r io.ReaderAt) ipFrameSource {
	return ipFrameSource{
		capture: c, reader: r, borrowUDPPayload: true,
		needsPayload: func(f Frame, _ []byte) bool {
			return dnsUnicast(f.SrcAddr) && dnsUnicast(f.DstAddr) && (f.mayContainUDPFragment() ||
				(f.IPProtocol == IPProtoUDP || f.IPProtocol == IPProtoTCP) && (f.SrcPort == 53 || f.DstPort == 53))
		},
	}
}

type dnsTransactionKey struct {
	client, resolver netip.AddrPort
	opening          int    // First retained TCP packet, or -1 for UDP.
	iface            uint32 // UDP scope. A TCP opening is already unique per capture.
	id, qtype, class uint16
	name             string // Case-folded wire labels, including lengths.
}

type dnsTransactionObservation struct {
	record *DNSRecord
	key    dnsTransactionKey
}

func scanDNSTransactions(source ipFrameSource, directAnswersOnly bool) ([]DNSTransaction, error) {
	var observations []dnsTransactionObservation
	record := func(pkt messagePacket, flow int, src, dst netip.AddrPort, wire []byte, iface uint32, opening int) error {
		m, err := ParseDNS(wire)
		if err != nil {
			return nil
		}
		client, resolver := src, dst
		if m.IsResponse {
			client, resolver = dst, src
		}
		if resolver.Port() != 53 {
			return nil
		}
		if len(observations) >= MaxDNSMessagesPerScan {
			return ErrDNSLimit
		}
		key := dnsTransactionKey{client: client, resolver: resolver, iface: iface, opening: opening, id: m.TransactionID}
		key.setQuestion(&m, wire)
		if directAnswersOnly && m.IsResponse {
			m.Answers = retainDirectDNSAnswers(&m, wire, key.name)
		}
		r := &DNSRecord{
			PacketIndex: pkt.index, TimestampNs: pkt.timestamp, FlowIndex: flow,
			SrcAddr: src.Addr(), DstAddr: dst.Addr(), SrcPort: src.Port(), DstPort: dst.Port(), Message: m,
		}
		observations = append(observations, dnsTransactionObservation{r, key})
		return nil
	}

	var flows flowIndexTable
	defrag := ipFragAccumulator{separateInterfaces: true}
	tcp := tcpMessageCollector{separateInterfaces: true}
	// Index the first packet of the later direction to the first packet
	// observed in its peer. Each mapping belongs to one TCP opening.
	peerOpening := make(map[int]int)
	err := source.walk(func(pkt PacketRecord, f Frame, l4 []byte) error {
		key, _ := makeCanonicalFlowKey(f.IPProtocol, f.SrcAddr, f.SrcPort, f.DstAddr, f.DstPort)
		flow, _, err := flows.lookupOrInsert(key)
		if err != nil || !dnsUnicast(f.SrcAddr) || !dnsUnicast(f.DstAddr) {
			return err
		}
		if f.mayContainUDPFragment() {
			var ok bool
			l4, f.SrcPort, f.DstPort, ok = defrag.addUDPFragment(&f, l4, pkt.InterfaceID)
			if !ok {
				return nil
			}
			f.IPProtocol = IPProtoUDP
		}
		if f.SrcPort != 53 && f.DstPort != 53 {
			return nil
		}
		switch f.IPProtocol {
		case IPProtoUDP:
			src, dst := netip.AddrPortFrom(f.SrcAddr, f.SrcPort), netip.AddrPortFrom(f.DstAddr, f.DstPort)
			return record(messagePacket{pkt.Index, pkt.TimestampNs}, flow, src, dst, l4, pkt.InterfaceID, -1)
		case IPProtoTCP:
			if !keepTCPMessageSegment(&f, len(l4), TCPFlagSYN) {
				return nil
			}
			prior := len(tcp.directions)
			dirs, err := tcp.addSegment(pkt, f, flow, l4)
			if err == nil && len(tcp.directions) > prior && dirs[1] != 0 {
				peerOpening[pkt.Index] = tcp.directions[dirs[1]-1].packets[0].index
			}
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	err = tcp.walk(2, 12, 65535, directAnswersOnly, func(dir *tcpMessageDirection, pkt messagePacket, wire []byte) error {
		opening := dir.packets[0].index
		if peer, ok := peerOpening[opening]; ok {
			opening = peer
		}
		return record(pkt, dir.flowIndex, dir.src, dir.dst, wire, 0, opening)
	})
	if err != nil {
		return nil, err
	}
	return pairDNSObservations(observations), nil
}

func pairDNSObservations(observations []dnsTransactionObservation) []DNSTransaction {
	slices.SortStableFunc(observations, func(a, b dnsTransactionObservation) int {
		return cmp.Compare(a.record.PacketIndex, b.record.PacketIndex)
	})
	var rows []DNSTransaction
	pending := make(map[dnsTransactionKey]int)
	for _, obs := range observations {
		r := obs.record
		row := DNSTransaction{Query: r}
		if r.Message.IsResponse {
			row.Query, row.Reply = nil, r
		}
		if obs.key.name != "" {
			prior, exists := pending[obs.key]
			switch {
			case exists && prior < 0:
				row.Pairing = DNSAmbiguous
			case row.Query != nil && exists:
				rows[prior].Pairing, row.Pairing = DNSAmbiguous, DNSAmbiguous
				pending[obs.key] = -1
			case row.Query != nil:
				row.Pairing = DNSNoReplyObserved
				pending[obs.key] = len(rows)
			case exists:
				rows[prior].Pairing, rows[prior].Reply = DNSPaired, row.Reply
				delete(pending, obs.key)
				continue
			default:
				row.Pairing = DNSNoQueryObserved
			}
		}
		rows = append(rows, row)
	}
	return rows
}

// setQuestion limits pairing to an ordinary lookup with one wire question.
func (k *dnsTransactionKey) setQuestion(m *DNSMessage, wire []byte) {
	if m.Opcode != 0 || m.Anomalies.Any() || m.QuestionCount != 1 || len(m.Questions) != 1 {
		return
	}
	q := &m.Questions[0]
	// IXFR and AXFR can have multiple replies on a TCP stream.
	if q.Type != 251 && q.Type != 252 {
		k.qtype, k.class, k.name = q.Type, q.Class, dnsPairingName(wire[12:])
	}
}

func dnsUnicast(addr netip.Addr) bool {
	return !addr.IsMulticast() && !addr.IsUnspecified() && addr != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

// Match label boundaries even when a label contains a literal dot. The first
// question has no preceding domain name to reference through compression.
func dnsPairingName(wire []byte) string {
	var name [MaxDNSNameBytes]byte
	for i := 0; i < len(wire) && i < len(name); {
		n := int(wire[i])
		if n == 0 {
			return string(name[:i+1])
		}
		if n > 63 || i+1+n > len(wire) || i+1+n >= len(name) {
			break
		}
		name[i] = byte(n)
		i++
		for _, c := range wire[i : i+n] {
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			name[i] = c
			i++
		}
	}
	return ""
}
