package pcap

import (
	"cmp"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"slices"
	"sort"
	"time"
)

const (
	// MaxDNSHTTP1AnswersPerScan bounds unique lookup and address pairs retained
	// while linking DNS replies to HTTP/1 requests.
	MaxDNSHTTP1AnswersPerScan = MaxDNSMessagesPerScan
	// MaxDNSHTTP1ChecksPerScan bounds candidate checks across all requests.
	MaxDNSHTTP1ChecksPerScan = 1 << 20
)

// ErrDNSHTTP1Limit indicates that the link scan exceeded an answer or work limit.
var ErrDNSHTTP1Limit = errors.New("DNS to HTTP/1 link limit exceeded")

// ErrInvalidDNSHTTP1Options indicates an empty capture identity or nonpositive age.
var ErrInvalidDNSHTTP1Options = errors.New("DNS to HTTP/1 links require capture identity and positive maximum age")

// DNSHTTP1LinkStatus describes the observed agreement between DNS and HTTP/1.
type DNSHTTP1LinkStatus uint8

const (
	// DNSHTTP1Unresolved indicates that the evidence cannot establish a unique
	// candidate, for example when a reply or a usable timestamp is missing.
	DNSHTTP1Unresolved DNSHTTP1LinkStatus = iota
	// DNSHTTP1CandidateObserved indicates one eligible observed lookup.
	DNSHTTP1CandidateObserved
	// DNSHTTP1Ambiguous indicates at least two eligible observed lookups.
	DNSHTTP1Ambiguous
)

// DNSHTTP1AnswerEvidence locates a paired direct DNS answer in the original
// capture. Packet indices are zero-based and identify the packet that
// completes each DNS message, including reassembled UDP and TCP messages.
// TTL is in seconds. Name is the decoded question name.
type DNSHTTP1AnswerEvidence struct {
	Name                               string
	TransactionID                      uint16
	QueryPacket, ReplyPacket           int
	QueryTimestampNs, ReplyTimestampNs int64
	TTL                                uint32
}

// DNSHTTP1Link identifies one cleartext request and its observed DNS candidates.
// OpeningPacket is the original client SYN index, or -1 if unavailable.
// Candidates retains up to the two latest eligible replies in capture order.
// An unresolved link can retain one eligible reply if another lookup lacks
// usable timing. A candidate establishes address and time agreement.
type DNSHTTP1Link struct {
	RequestID           HTTP1TransactionID
	OpeningPacket       int
	RequestTimestampNs  int64
	Client, Destination netip.AddrPort
	Status              DNSHTTP1LinkStatus
	Candidates          []DNSHTTP1AnswerEvidence
}

// CommunityID returns the TCP tuple's [FlowSummary.CommunityID] with the given
// seed. The capture identity, tenant scope and opening or request packet
// distinguish observations that reuse that tuple.
func (l DNSHTTP1Link) CommunityID(seed uint16) string {
	flow := FlowSummary{
		Protocol: IPProtoTCP, SrcAddr: l.Client.Addr(), DstAddr: l.Destination.Addr(),
		SrcPort: l.Client.Port(), DstPort: l.Destination.Port(),
	}
	return flow.CommunityID(seed)
}

// DNSHTTP1Evidence holds links from one caller-identified capture and tenant
// scope. Links follow original request packet order and TCP payload offset.
// The result owns Scope and the link and candidate slices.
type DNSHTTP1Evidence struct {
	CaptureID string
	Scope     TenantScope
	Links     []DNSHTTP1Link
}

// DNSHTTP1Links checks paired direct unicast A and AAAA answers against
// subsequent cleartext HTTP/1 requests from the same client to the answered
// address. It uses original packet indices and positive, nondecreasing query,
// reply and request timestamps. A candidate's age is at most maxAge and
// strictly below its observed TTL. The comparison uses endpoint addresses.
// Requests with conflicting TCP overlap have unresolved links.
// captureID must be nonempty and maxAge must be positive. Protocol or
// correlation limit errors discard the result.
func (t *TenantCapture) DNSHTTP1Links(data []byte, captureID string, maxAge time.Duration) (DNSHTTP1Evidence, error) {
	source := ipFrameSource{capture: t.capture, data: data, scope: &t.scope}
	return t.scanDNSHTTP1(source, source, captureID, maxAge)
}

// DNSHTTP1LinksFromReaderAt is the ReaderAt equivalent of
// [TenantCapture.DNSHTTP1Links]. Both scans share [MaxReaderAtScanBytes] of reads
// from the caller's reader.
func (t *TenantCapture) DNSHTTP1LinksFromReaderAt(r io.ReaderAt, captureID string, maxAge time.Duration) (DNSHTTP1Evidence, error) {
	if r == nil {
		return DNSHTTP1Evidence{}, ErrInvalidHeader
	}
	budget := &scanReadBudget{r: r, remaining: MaxReaderAtScanBytes}
	dns, http := t.capture.dnsTransactionReaderAt(budget), t.capture.tcpReaderAt(budget)
	dns.scope, http.scope = &t.scope, &t.scope
	return t.scanDNSHTTP1(dns, http, captureID, maxAge)
}

func (t *TenantCapture) scanDNSHTTP1(dnsSource, httpSource ipFrameSource, captureID string, maxAge time.Duration) (DNSHTTP1Evidence, error) {
	if captureID == "" || maxAge <= 0 {
		return DNSHTTP1Evidence{}, ErrInvalidDNSHTTP1Options
	}
	dns, err := scanDNSTransactions(dnsSource, true)
	if err != nil {
		return DNSHTTP1Evidence{}, err
	}
	answers, err := indexDNSHTTP1Answers(dns)
	if err != nil {
		return DNSHTTP1Evidence{}, err
	}
	openings := make(map[HTTP1TransactionID]int)
	requests, err := scanHTTP1Transactions(httpSource, nil, openings)
	if err != nil {
		return DNSHTTP1Evidence{}, err
	}
	result := DNSHTTP1Evidence{CaptureID: captureID, Scope: cloneTenantScope(t.scope)}
	checks := MaxDNSHTTP1ChecksPerScan
	for _, tx := range requests {
		req := tx.Request
		link := DNSHTTP1Link{
			RequestID: tx.ID(), OpeningPacket: -1, RequestTimestampNs: req.TimestampNs,
			Client: req.Source, Destination: req.Destination,
		}
		if opening, ok := openings[link.RequestID]; ok {
			link.OpeningPacket = opening
		}
		if !req.TCPAnomalies.OverlapConflict {
			key := dnsHTTP1Key{req.Source.Addr(), req.Destination.Addr()}
			if err := link.selectCandidates(answers[key], maxAge, &checks); err != nil {
				return DNSHTTP1Evidence{}, err
			}
		}
		result.Links = append(result.Links, link)
	}
	return result, nil
}

type dnsHTTP1Key struct {
	client, destination netip.Addr
}

// DNS answer slices in this path contain only direct records. Deduplicate
// repeated copies of an address in one reply using their shortest TTL.
func indexDNSHTTP1Answers(rows []DNSTransaction) (map[dnsHTTP1Key][]DNSHTTP1AnswerEvidence, error) {
	answers := make(map[dnsHTTP1Key][]DNSHTTP1AnswerEvidence)
	byAddress := make(map[netip.Addr]uint32)
	count := 0
	for _, row := range rows {
		if row.Pairing != DNSPaired || len(row.Reply.Message.Answers) == 0 {
			continue
		}
		query, reply := row.Query, row.Reply
		clear(byAddress)
		for _, rr := range reply.Message.Answers {
			ttl := rr.TTL
			if ttl >= 1<<31 { // RFC 2181 section 8 treats a set high bit as zero.
				ttl = 0
			}
			if previous, ok := byAddress[rr.Address]; !ok || ttl < previous {
				byAddress[rr.Address] = ttl
			}
		}
		for addr, ttl := range byAddress {
			if ttl == 0 {
				continue
			}
			if count == MaxDNSHTTP1AnswersPerScan {
				return nil, ErrDNSHTTP1Limit
			}
			count++
			key := dnsHTTP1Key{query.SrcAddr, addr}
			answers[key] = append(answers[key], DNSHTTP1AnswerEvidence{
				Name: query.Message.Questions[0].Name, TransactionID: query.Message.TransactionID,
				QueryPacket: query.PacketIndex, ReplyPacket: reply.PacketIndex,
				QueryTimestampNs: query.TimestampNs, ReplyTimestampNs: reply.TimestampNs, TTL: ttl,
			})
		}
	}
	for _, list := range answers {
		slices.SortStableFunc(list, func(a, b DNSHTTP1AnswerEvidence) int {
			return cmp.Compare(a.ReplyPacket, b.ReplyPacket)
		})
	}
	return answers, nil
}

func (l *DNSHTTP1Link) selectCandidates(list []DNSHTTP1AnswerEvidence, maxAge time.Duration, checks *int) error {
	if l.RequestTimestampNs <= 0 {
		return nil
	}
	end := sort.Search(len(list), func(i int) bool { return list[i].ReplyPacket >= l.RequestID.PacketIndex })
	var candidates [2]DNSHTTP1AnswerEvidence
	count, timingIncomplete := 0, false
	for i := end - 1; i >= 0; i-- {
		if *checks == 0 {
			return ErrDNSHTTP1Limit
		}
		*checks = *checks - 1
		answer := list[i]
		if answer.QueryTimestampNs <= 0 || answer.ReplyTimestampNs < answer.QueryTimestampNs ||
			l.RequestTimestampNs < answer.ReplyTimestampNs {
			timingIncomplete = true
			continue
		}
		age := time.Duration(l.RequestTimestampNs - answer.ReplyTimestampNs)
		if age > maxAge || age >= time.Duration(answer.TTL)*time.Second {
			continue
		}
		candidates[count] = answer
		count++
		if count == len(candidates) {
			l.Status = DNSHTTP1Ambiguous
			break
		}
	}
	if count == 1 && !timingIncomplete {
		l.Status = DNSHTTP1CandidateObserved
	}
	if count != 0 {
		slices.Reverse(candidates[:count])
		l.Candidates = slices.Clone(candidates[:count])
	}
	return nil
}

// The transaction key preserves DNS label boundaries. Compare answer owners
// using their original labels so a literal dot cannot impersonate a boundary.
func retainDirectDNSAnswers(m *DNSMessage, wire []byte, name string) []DNSResourceRecord {
	if name == "" || m.Truncated || m.RCode != DNSRCodeSuccess {
		return nil
	}
	q := m.Questions[0]
	if q.Class != 1 || (q.Type != DNSTypeA && q.Type != DNSTypeAAAA) {
		return nil
	}
	if slices.ContainsFunc(m.Additionals, func(rr DNSResourceRecord) bool {
		return rr.Type == DNSTypeOPT && rr.TTL>>24 != 0
	}) {
		return nil
	}
	owner := 12 + len(name) + 4
	kept := m.Answers[:0]
	for _, rr := range m.Answers {
		start := owner
		owner = int(rr.DataOffset + rr.DataLength)
		if rr.Class != q.Class || (rr.Type != q.Type && rr.Type != DNSTypeCNAME) ||
			!matchesDNSWireName(wire, start, name) {
			continue
		}
		if rr.Type == DNSTypeCNAME {
			return nil
		}
		if rr.Address.IsValid() && dnsUnicast(rr.Address) {
			kept = append(kept, rr)
		}
	}
	clear(m.Answers[len(kept):])
	return kept
}

func matchesDNSWireName(wire []byte, offset int, name string) bool {
	pos, jumps := 0, 0
	for offset >= 12 && offset < len(wire) && pos < len(name) {
		size := int(wire[offset])
		if size&0xc0 == 0xc0 {
			if offset+1 >= len(wire) || jumps == MaxDNSCompressionJumps {
				return false
			}
			ptr := int(binary.BigEndian.Uint16(wire[offset:offset+2]) & 0x3fff)
			if ptr >= offset {
				return false
			}
			offset = ptr
			jumps++
			continue
		}
		if size > 63 || size != int(name[pos]) || size > min(len(wire)-offset-1, len(name)-pos-1) {
			return false
		}
		if size == 0 {
			return pos+1 == len(name)
		}
		for n, ch := range wire[offset+1 : offset+1+size] {
			if ch >= 'A' && ch <= 'Z' {
				ch += 'a' - 'A'
			}
			if ch != name[pos+1+n] {
				return false
			}
		}
		offset += 1 + size
		pos += 1 + size
	}
	return false
}
