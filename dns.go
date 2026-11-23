package pcap

import (
	"cmp"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strings"
)

// DNSAnomalies reports non-fatal structural anomalies in a DNS message.
type DNSAnomalies struct {
	TruncatedSection      bool
	InvalidCompressionPtr bool
	OversizeName          bool
	InvalidRDataLength    bool
}

// Any reports whether any DNS anomaly was detected.
func (a DNSAnomalies) Any() bool {
	return a.TruncatedSection ||
		a.InvalidCompressionPtr ||
		a.OversizeName ||
		a.InvalidRDataLength
}

// DNSQuestion represents one question entry in a DNS message.
type DNSQuestion struct {
	Name  string
	Type  uint16
	Class uint16
}

// DNSResourceRecord represents one answer, authority, or additional record in a
// DNS message.
type DNSResourceRecord struct {
	Name           string
	Type           uint16
	Class          uint16
	TTL            uint32
	Address        netip.Addr
	Target         string
	TXT            []string
	DataOffset     uint32
	DataLength     uint32
	ServiceBinding *DNSServiceBinding // Present for a successfully decoded SVCB or HTTPS record.
}

// DNSServiceBinding contains the observed SVCB or HTTPS parameters. The
// enclosing record's Target is the target name (empty for the DNS root).
type DNSServiceBinding struct {
	Priority     uint16 // Zero identifies AliasMode.
	Port         uint16
	HasPort      bool
	HasECHConfig bool // A nonempty ech parameter was present.
	ALPN         []string
}

// EDNSUDPPayloadSize returns the advertised UDP payload size of an OPT record,
// or zero for other record types.
func (r DNSResourceRecord) EDNSUDPPayloadSize() uint16 {
	if r.Type == DNSTypeOPT {
		return r.Class
	}
	return 0
}

// EDNSDOBit reports whether an OPT record has the DNSSEC OK flag set.
func (r DNSResourceRecord) EDNSDOBit() bool {
	return r.Type == DNSTypeOPT && r.TTL&0x8000 != 0
}

// DNSMessage contains a parsed DNS query or response message.
type DNSMessage struct {
	TransactionID      uint16
	Flags              uint16
	IsResponse         bool
	Opcode             uint8
	Authoritative      bool
	Truncated          bool
	RecursionDesired   bool
	RecursionAvailable bool
	RCode              uint8
	QuestionCount      uint16
	AnswerCount        uint16
	AuthorityCount     uint16
	AdditionalCount    uint16
	Questions          []DNSQuestion
	Answers            []DNSResourceRecord
	Authorities        []DNSResourceRecord
	Additionals        []DNSResourceRecord
	Anomalies          DNSAnomalies
}

// DNSRecord associates a parsed [DNSMessage] with its packet and flow indices
// in a [Capture].
// For TCP, PacketIndex and TimestampNs identify the packet containing the first length-prefix byte.
type DNSRecord struct {
	PacketIndex int
	FlowIndex   int
	SrcAddr     netip.Addr
	DstAddr     netip.Addr
	SrcPort     uint16
	DstPort     uint16
	TimestampNs int64
	Message     DNSMessage
}

// ParseDNS parses a single DNS message from payload (without a 2-byte TCP
// length prefix). It returns [ErrInvalidDNS] if payload is shorter than the
// 12-byte DNS header, or [ErrDNSLimit] if question/record counts or label
// compression jumps exceed configured limits.
func ParseDNS(payload []byte) (DNSMessage, error) {
	if len(payload) < 12 {
		return DNSMessage{}, fmt.Errorf("%w: message shorter than 12-byte header", ErrInvalidDNS)
	}
	txID := binary.BigEndian.Uint16(payload[0:2])
	flags := binary.BigEndian.Uint16(payload[2:4])
	qdCount := binary.BigEndian.Uint16(payload[4:6])
	anCount := binary.BigEndian.Uint16(payload[6:8])
	nsCount := binary.BigEndian.Uint16(payload[8:10])
	arCount := binary.BigEndian.Uint16(payload[10:12])

	if qdCount > MaxDNSQuestions {
		return DNSMessage{}, fmt.Errorf("%w: question count %d exceeds %d", ErrDNSLimit, qdCount, MaxDNSQuestions)
	}
	totalRR := int(anCount) + int(nsCount) + int(arCount)
	if totalRR > MaxDNSResourceRecords {
		return DNSMessage{}, fmt.Errorf("%w: resource record count %d exceeds %d", ErrDNSLimit, totalRR, MaxDNSResourceRecords)
	}

	msg := DNSMessage{
		TransactionID:      txID,
		Flags:              flags,
		IsResponse:         (flags & 0x8000) != 0,
		Opcode:             uint8((flags >> 11) & 0x0f),
		Authoritative:      (flags & 0x0400) != 0,
		Truncated:          (flags & 0x0200) != 0,
		RecursionDesired:   (flags & 0x0100) != 0,
		RecursionAvailable: (flags & 0x0080) != 0,
		RCode:              uint8(flags & 0x000f),
		QuestionCount:      qdCount,
		AnswerCount:        anCount,
		AuthorityCount:     nsCount,
		AdditionalCount:    arCount,
	}

	offset := 12
	if qdCount > 0 {
		msg.Questions = make([]DNSQuestion, 0, qdCount)
	}
	for range qdCount {
		name, nextOff, err := decodeDNSName(payload, offset, &msg.Anomalies)
		if err != nil {
			return DNSMessage{}, err
		}
		if nextOff+4 > len(payload) {
			msg.Anomalies.TruncatedSection = true
			return msg, nil
		}
		qType := binary.BigEndian.Uint16(payload[nextOff : nextOff+2])
		qClass := binary.BigEndian.Uint16(payload[nextOff+2 : nextOff+4])
		msg.Questions = append(msg.Questions, DNSQuestion{
			Name:  name,
			Type:  qType,
			Class: qClass,
		})
		offset = nextOff + 4
	}

	var err error
	if anCount > 0 {
		msg.Answers, offset, err = decodeDNSRecordSection(payload, offset, int(anCount), &msg.Anomalies)
		if err != nil {
			return DNSMessage{}, err
		}
	}
	if nsCount > 0 && !msg.Anomalies.TruncatedSection {
		msg.Authorities, offset, err = decodeDNSRecordSection(payload, offset, int(nsCount), &msg.Anomalies)
		if err != nil {
			return DNSMessage{}, err
		}
	}
	if arCount > 0 && !msg.Anomalies.TruncatedSection {
		msg.Additionals, _, err = decodeDNSRecordSection(payload, offset, int(arCount), &msg.Anomalies)
		if err != nil {
			return DNSMessage{}, err
		}
	}

	return msg, nil
}

func decodeDNSRecordSection(
	payload []byte,
	offset int,
	count int,
	anomalies *DNSAnomalies,
) ([]DNSResourceRecord, int, error) {
	records := make([]DNSResourceRecord, 0, count)
	for range count {
		if offset >= len(payload) {
			anomalies.TruncatedSection = true
			break
		}
		name, nextOff, err := decodeDNSName(payload, offset, anomalies)
		if err != nil {
			return nil, offset, err
		}
		if nextOff+10 > len(payload) {
			anomalies.TruncatedSection = true
			break
		}
		rrType := binary.BigEndian.Uint16(payload[nextOff : nextOff+2])
		rrClass := binary.BigEndian.Uint16(payload[nextOff+2 : nextOff+4])
		ttl := binary.BigEndian.Uint32(payload[nextOff+4 : nextOff+8])
		rdLen := int(binary.BigEndian.Uint16(payload[nextOff+8 : nextOff+10]))
		rdataStart := nextOff + 10
		rdataEnd := rdataStart + rdLen
		if rdataEnd > len(payload) {
			anomalies.TruncatedSection = true
			anomalies.InvalidRDataLength = true
			break
		}

		rec := DNSResourceRecord{
			Name:       name,
			Type:       rrType,
			Class:      rrClass,
			TTL:        ttl,
			DataOffset: uint32(rdataStart),
			DataLength: uint32(rdLen),
		}

		switch rrType {
		case DNSTypeA:
			if rdLen == 4 {
				rec.Address = netip.AddrFrom4([4]byte(payload[rdataStart:rdataEnd]))
			} else {
				anomalies.InvalidRDataLength = true
			}
		case DNSTypeAAAA:
			if rdLen == 16 {
				rec.Address = netip.AddrFrom16([16]byte(payload[rdataStart:rdataEnd]))
			} else {
				anomalies.InvalidRDataLength = true
			}
		case DNSTypeCNAME, DNSTypeNS, DNSTypePTR:
			target, _, err := decodeDNSNameBounded(payload, rdataStart, rdataEnd, true, anomalies)
			if err != nil {
				return nil, offset, err
			}
			rec.Target = target
		case DNSTypeMX:
			if rdLen >= 3 {
				target, _, err := decodeDNSNameBounded(payload, rdataStart+2, rdataEnd, true, anomalies)
				if err != nil {
					return nil, offset, err
				}
				rec.Target = target
			} else {
				anomalies.InvalidRDataLength = true
			}
		case DNSTypeSVCB, DNSTypeHTTPS:
			if err := decodeDNSServiceBinding(payload[rdataStart:rdataEnd], &rec, anomalies); err != nil {
				return nil, offset, err
			}
		case DNSTypeTXT:
			rec.TXT = decodeDNSTXT(payload[rdataStart:rdataEnd], anomalies)
		}

		records = append(records, rec)
		offset = rdataEnd
	}
	return records, offset, nil
}

// RFC 9460 encodes the priority, an uncompressed target, then key/length/value
// parameters in strictly increasing key order. Commit metadata after framing
// the entire record so a malformed tail cannot publish a partial advertisement.
func decodeDNSServiceBinding(data []byte, rec *DNSResourceRecord, anomalies *DNSAnomalies) error {
	if len(data) < 3 {
		anomalies.InvalidRDataLength = true
		return nil
	}
	var nameAnomalies DNSAnomalies
	target, off, err := decodeDNSNameBounded(data, 2, len(data), false, &nameAnomalies)
	if err != nil {
		return err
	}
	if off-2 > MaxDNSNameBytes {
		return fmt.Errorf("%w: SVCB target exceeds %d wire bytes", ErrDNSLimit, MaxDNSNameBytes)
	}
	if nameAnomalies.TruncatedSection {
		anomalies.InvalidRDataLength = true
		return nil
	}
	binding := DNSServiceBinding{Priority: binary.BigEndian.Uint16(data)}
	prev := -1
	for params := data[off:]; len(params) > 0; {
		if len(params) < 4 {
			anomalies.InvalidRDataLength = true
			return nil
		}
		key := int(binary.BigEndian.Uint16(params))
		n := int(binary.BigEndian.Uint16(params[2:]))
		if key <= prev || n > len(params)-4 {
			anomalies.InvalidRDataLength = true
			return nil
		}
		value := params[4 : 4+n]
		prev = key
		params = params[4+n:]
		if binding.Priority == 0 {
			continue // AliasMode ignores parameter values.
		}
		switch key {
		case 1: // alpn
			binding.ALPN, err = decodeSVCBALPN(value)
			if err != nil {
				return err
			}
			if binding.ALPN == nil {
				anomalies.InvalidRDataLength = true
				return nil
			}
		case 3: // port
			if n != 2 {
				anomalies.InvalidRDataLength = true
				return nil
			}
			binding.Port = binary.BigEndian.Uint16(value)
			binding.HasPort = true
		case 5: // ech
			binding.HasECHConfig = n > 0
		}
	}
	rec.Target = target
	rec.ServiceBinding = &binding
	return nil
}

// Validate the length-prefixed IDs before copying their common backing string.
func decodeSVCBALPN(value []byte) ([]string, error) {
	count := 0
	for i := 0; i < len(value); {
		n := int(value[i])
		if n == 0 || n > len(value)-i-1 {
			return nil, nil
		}
		count++
		if count > MaxDNSALPNProtocols {
			return nil, fmt.Errorf("%w: more than %d ALPN identifiers", ErrDNSLimit, MaxDNSALPNProtocols)
		}
		i += 1 + n
	}
	if count == 0 {
		return nil, nil
	}
	wire := string(value)
	ids := make([]string, count)
	for i := range ids {
		end := 1 + int(wire[0])
		ids[i] = wire[1:end]
		wire = wire[end:]
	}
	return ids, nil
}

func decodeDNSTXT(rdata []byte, anomalies *DNSAnomalies) []string {
	var out []string
	i := 0
	for i < len(rdata) {
		if len(out) >= MaxDNSTXTStrings {
			break
		}
		txtLen := int(rdata[i])
		i++
		if i+txtLen > len(rdata) {
			anomalies.InvalidRDataLength = true
			break
		}
		out = append(out, string(rdata[i:i+txtLen]))
		i += txtLen
	}
	return out
}

func decodeDNSName(payload []byte, start int, anomalies *DNSAnomalies) (string, int, error) {
	return decodeDNSNameBounded(payload, start, len(payload), true, anomalies)
}

func decodeDNSNameBounded(payload []byte, start int, limit int, allowCompression bool, anomalies *DNSAnomalies) (string, int, error) {
	if start < 0 || start >= limit || limit > len(payload) {
		anomalies.TruncatedSection = true
		return "", limit, nil
	}

	var buf [MaxDNSNameBytes]byte
	outLen := 0
	cur := start
	bound := limit
	nextOffset := -1
	jumps := 0

	for {
		if cur >= bound {
			anomalies.TruncatedSection = true
			if nextOffset < 0 {
				nextOffset = bound
			}
			return string(buf[:outLen]), nextOffset, nil
		}
		b := payload[cur]
		if b == 0 {
			cur++
			if nextOffset < 0 {
				nextOffset = cur
			}
			return string(buf[:outLen]), nextOffset, nil
		}

		switch b & 0xc0 {
		case 0x00:
			labelLen := int(b & 0x3f)
			cur++
			if cur+labelLen > bound {
				anomalies.TruncatedSection = true
				if nextOffset < 0 {
					nextOffset = bound
				}
				return string(buf[:outLen]), nextOffset, nil
			}
			sep := 0
			if outLen > 0 {
				sep = 1
			}
			if outLen+sep+labelLen > MaxDNSNameBytes {
				anomalies.OversizeName = true
				return "", 0, fmt.Errorf("%w: DNS name exceeds %d bytes", ErrDNSLimit, MaxDNSNameBytes)
			}
			if sep == 1 {
				buf[outLen] = '.'
				outLen++
			}
			copy(buf[outLen:], payload[cur:cur+labelLen])
			outLen += labelLen
			cur += labelLen

		case 0xc0:
			if !allowCompression {
				anomalies.InvalidCompressionPtr = true
				return "", 0, fmt.Errorf("%w: compressed SVCB target", ErrInvalidDNS)
			}
			if cur+1 >= bound {
				anomalies.TruncatedSection = true
				if nextOffset < 0 {
					nextOffset = bound
				}
				return string(buf[:outLen]), nextOffset, nil
			}
			ptr := int(binary.BigEndian.Uint16(payload[cur:cur+2]) & 0x3fff)
			if nextOffset < 0 {
				nextOffset = cur + 2
			}
			jumps++
			if jumps > MaxDNSCompressionJumps {
				anomalies.InvalidCompressionPtr = true
				return "", 0, fmt.Errorf("%w: DNS label compression exceeds %d jumps", ErrDNSLimit, MaxDNSCompressionJumps)
			}
			if ptr < 12 || ptr >= cur || ptr >= len(payload) {
				anomalies.InvalidCompressionPtr = true
				return "", 0, fmt.Errorf("%w: invalid DNS compression pointer %d at offset %d", ErrInvalidDNS, ptr, cur)
			}
			cur = ptr
			bound = len(payload)

		default:
			anomalies.InvalidCompressionPtr = true
			return "", 0, fmt.Errorf("%w: unsupported DNS label prefix %#x", ErrInvalidDNS, b&0xc0)
		}
	}
}

func isDNSPort(port uint16) bool {
	return port == 53 || port == 5353 || port == 5355
}

// DNS extracts and parses DNS messages across all UDP (ports 53, 5353, 5355)
// and TCP (port 53 length-prefixed) packets in the capture.
func (c *Capture) DNS(data []byte) ([]DNSRecord, error) {
	return scanDNS(ipFrameSource{capture: c, data: data})
}

func scanDNS(source ipFrameSource) ([]DNSRecord, error) {

	var table flowIndexTable
	var defrag ipFragAccumulator
	var records []DNSRecord
	var tcp tcpMessageCollector

	err := source.walk(func(pkt PacketRecord, frame Frame, l4 []byte) error {

		if frame.Anomalies.IPFragment && frame.IPProtocol == IPProtoUDP {
			udpPayload, srcPort, dstPort, ok := defrag.addUDPFragment(&frame, l4)
			if !ok {
				return nil
			}
			frame.SrcPort = srcPort
			frame.DstPort = dstPort
			key, _ := makeCanonicalFlowKey(frame.IPProtocol, frame.SrcAddr, frame.SrcPort, frame.DstAddr, frame.DstPort)
			flowIdx, _, err := table.lookupOrInsert(key)
			if err != nil {
				return err
			}
			if !isDNSPort(srcPort) && !isDNSPort(dstPort) {
				return nil
			}
			msg, err := ParseDNS(udpPayload)
			if err != nil {
				return nil
			}
			if len(records) >= MaxDNSMessagesPerScan {
				return fmt.Errorf("%w: exceeds %d messages", ErrDNSLimit, MaxDNSMessagesPerScan)
			}
			records = append(records, DNSRecord{
				PacketIndex: pkt.Index,
				FlowIndex:   flowIdx,
				SrcAddr:     frame.SrcAddr,
				DstAddr:     frame.DstAddr,
				SrcPort:     srcPort,
				DstPort:     dstPort,
				TimestampNs: pkt.TimestampNs,
				Message:     msg,
			})
			return nil
		}

		key, _ := makeCanonicalFlowKey(frame.IPProtocol, frame.SrcAddr, frame.SrcPort, frame.DstAddr, frame.DstPort)
		flowIdx, _, err := table.lookupOrInsert(key)
		if err != nil {
			return err
		}

		if frame.PayloadLength == 0 || !isDNSPort(frame.SrcPort) && !isDNSPort(frame.DstPort) {
			return nil
		}

		switch frame.IPProtocol {
		case IPProtoUDP:
			msg, err := ParseDNS(l4)
			if err != nil {
				return nil
			}
			if len(records) >= MaxDNSMessagesPerScan {
				return fmt.Errorf("%w: exceeds %d messages", ErrDNSLimit, MaxDNSMessagesPerScan)
			}
			records = append(records, DNSRecord{
				PacketIndex: pkt.Index,
				FlowIndex:   flowIdx,
				SrcAddr:     frame.SrcAddr,
				DstAddr:     frame.DstAddr,
				SrcPort:     frame.SrcPort,
				DstPort:     frame.DstPort,
				TimestampNs: pkt.TimestampNs,
				Message:     msg,
			})

		case IPProtoTCP:
			return tcp.add(pkt, frame, flowIdx, l4)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	err = tcp.walk(2, 12, 65535, func(dir *tcpMessageDirection, pkt messagePacket, data []byte) error {
		msg, err := ParseDNS(data)
		if err != nil {
			return nil
		}
		if len(records) >= MaxDNSMessagesPerScan {
			return fmt.Errorf("%w: exceeds %d messages", ErrDNSLimit, MaxDNSMessagesPerScan)
		}
		records = append(records, DNSRecord{PacketIndex: pkt.index, TimestampNs: pkt.timestamp, FlowIndex: dir.flowIndex, SrcAddr: dir.src.Addr(), DstAddr: dir.dst.Addr(), SrcPort: dir.src.Port(), DstPort: dir.dst.Port(), Message: msg})
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(tcp.directions) > 0 {
		slices.SortStableFunc(records, func(a, b DNSRecord) int { return cmp.Compare(a.PacketIndex, b.PacketIndex) })
	}
	return records, nil
}

// HasDNSQuery reports whether any DNS message in the capture contains a question
// matching qname (case-insensitive ASCII comparison, ignoring a trailing dot).
func (c *Capture) HasDNSQuery(data []byte, qname string) (bool, error) {
	if err := c.validateContainer(); err != nil {
		return false, err
	}
	if c.PacketCount == 0 {
		return false, nil
	}
	target := strings.TrimSuffix(qname, ".")
	r := SafeReader{data: data, size: int64(len(data))}
	var defrag ipFragAccumulator
	found := false
	var tcp tcpMessageCollector

	err := c.walkPackets(&r, func(pkt PacketRecord) error {
		payload, err := r.Slice(pkt.PayloadOffset, pkt.PayloadLength)
		if err != nil {
			return err
		}
		frame, err := DecodeFrame(payload, pkt.LinkType)
		if err != nil || frame.IPVersion == 0 || frame.PayloadLength == 0 {
			return nil
		}
		if frame.Anomalies.IPFragment && frame.IPProtocol == IPProtoUDP {
			udpPayload, srcPort, dstPort, ok := defrag.addUDPFragment(&frame, payload[frame.PayloadOffset:frame.PayloadOffset+frame.PayloadLength])
			if !ok || (!isDNSPort(srcPort) && !isDNSPort(dstPort)) {
				return nil
			}
			if dnsPayloadHasQuery(udpPayload, target) {
				found = true
				return errStopWalk
			}
			return nil
		}
		if !isDNSPort(frame.SrcPort) && !isDNSPort(frame.DstPort) {
			return nil
		}
		if frame.IPProtocol == IPProtoTCP {
			return tcp.add(pkt, frame, 0, payload[frame.PayloadOffset:frame.PayloadOffset+frame.PayloadLength])
		}
		if frame.IPProtocol != IPProtoUDP {
			return nil
		}
		l4 := payload[frame.PayloadOffset : frame.PayloadOffset+frame.PayloadLength]
		if dnsPayloadHasQuery(l4, target) {
			found = true
			return errStopWalk
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	if found {
		return true, nil
	}
	err = tcp.walk(2, 12, 65535, func(_ *tcpMessageDirection, _ messagePacket, data []byte) error {
		if dnsPayloadHasQuery(data, target) {
			return errStopWalk
		}
		return nil
	})
	if errors.Is(err, errStopWalk) {
		return true, nil
	}
	return false, err
}

func dnsPayloadHasQuery(payload []byte, target string) bool {
	if len(payload) < 12 {
		return false
	}
	qdCount := binary.BigEndian.Uint16(payload[4:6])
	if qdCount == 0 || qdCount > MaxDNSQuestions {
		return false
	}
	offset := 12
	var anomalies DNSAnomalies
	for range qdCount {
		name, nextOff, err := decodeDNSName(payload, offset, &anomalies)
		if err != nil {
			return false
		}
		if strings.EqualFold(strings.TrimSuffix(name, "."), target) {
			return true
		}
		if nextOff+4 > len(payload) {
			return false
		}
		offset = nextOff + 4
	}
	return false
}

// DNSDomainStats aggregates per-apex-domain behavioral indicators for DNS
// tunneling and command-and-control triage.
type DNSDomainStats struct {
	Domain               string
	QueryCount           int
	UniqueSubdomains     int
	NXDomainCount        int
	MaxLabelLength       int
	MaxSubdomainEntropy  float64
	MeanSubdomainEntropy float64
	EncodedCharRatio     float64
	TXTAnswerBytes       uint64
	TunnelScore          float64
}

// DNSLabelEntropy computes the Shannon entropy (in bits per byte, [0.0, 8.0])
// of the subdomain prefix of qname (excluding its final two registrable apex
// labels, or over the entire name if qname has two or fewer labels).
func DNSLabelEntropy(qname string) float64 {
	sub, apex := splitDNSSubdomainAndApex(qname)
	if sub == "" {
		sub = apex
	}
	if sub == "" {
		return 0
	}
	var counts [256]int
	total := 0
	for i := range len(sub) {
		b := sub[i]
		if b == '.' {
			continue
		}
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		counts[b]++
		total++
	}
	if total <= 1 {
		return 0
	}
	invTotal := 1.0 / float64(total)
	var entropy float64
	for _, c := range counts {
		if c > 0 {
			p := float64(c) * invTotal
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

var commonMultiLabelPublicSuffixes = map[string]struct{}{
	"co.uk": {}, "org.uk": {}, "ac.uk": {}, "gov.uk": {}, "me.uk": {}, "net.uk": {},
	"com.au": {}, "net.au": {}, "org.au": {}, "edu.au": {}, "gov.au": {},
	"co.jp": {}, "ne.jp": {}, "or.jp": {}, "ac.jp": {}, "go.jp": {},
	"co.nz": {}, "org.nz": {}, "govt.nz": {},
	"co.za": {}, "org.za": {}, "gov.za": {},
	"com.br": {}, "org.br": {}, "gov.br": {},
	"com.cn": {}, "net.cn": {}, "org.cn": {}, "gov.cn": {},
	"com.mx": {}, "org.mx": {}, "gob.mx": {},
	"co.in": {}, "net.in": {}, "org.in": {}, "gov.in": {},
	"co.kr": {}, "or.kr": {}, "go.kr": {},
	"com.sg": {}, "org.sg": {}, "gov.sg": {},
	"com.hk": {}, "org.hk": {}, "gov.hk": {},
	"com.tw": {}, "org.tw": {}, "gov.tw": {},
	"co.il": {}, "org.il": {}, "gov.il": {},
	"com.tr": {}, "org.tr": {}, "gov.tr": {},
	"co.id": {}, "or.id": {}, "go.id": {},
	"com.ar": {}, "com.my": {}, "com.ph": {}, "com.vn": {}, "com.ua": {},
	"co.th": {}, "in.th": {}, "ac.th": {},
}

func splitDNSSubdomainAndApex(qname string) (subdomain string, apex string) {
	clean := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(qname)), ".")
	if clean == "" {
		return "", ""
	}
	lastDot := strings.LastIndexByte(clean, '.')
	if lastDot <= 0 {
		return "", clean
	}
	secondLastDot := strings.LastIndexByte(clean[:lastDot], '.')
	if secondLastDot < 0 {
		return "", clean
	}
	tail2 := clean[secondLastDot+1:]
	if _, ok := commonMultiLabelPublicSuffixes[tail2]; ok {
		thirdLastDot := strings.LastIndexByte(clean[:secondLastDot], '.')
		if thirdLastDot < 0 {
			return "", clean
		}
		return clean[:thirdLastDot], clean[thirdLastDot+1:]
	}
	return clean[:secondLastDot], tail2
}

// DNSDomainStats aggregates DNS query entropy, label lengths, unique subdomain
// counts, NXDOMAIN ratios, and TXT payload volumes grouped by apex domain in
// deterministic first-seen order.
func (c *Capture) DNSDomainStats(data []byte) ([]DNSDomainStats, error) {
	records, err := c.DNS(data)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, nil
	}

	type domainAccum struct {
		domain         string
		queryCount     int
		subdomains     map[string]struct{}
		nxCount        int
		maxLabelLen    int
		maxEntropy     float64
		sumEntropy     float64
		entropySamples int
		encodedChars   int
		totalChars     int
		txtBytes       uint64
	}

	indexByDomain := make(map[string]int)
	var accums []domainAccum

	for i := range records {
		msg := &records[i].Message
		for qIdx := range msg.Questions {
			qname := msg.Questions[qIdx].Name
			sub, apex := splitDNSSubdomainAndApex(qname)
			if apex == "" {
				continue
			}
			idx, exists := indexByDomain[apex]
			if !exists {
				idx = len(accums)
				indexByDomain[apex] = idx
				accums = append(accums, domainAccum{
					domain:     apex,
					subdomains: make(map[string]struct{}),
				})
			}
			da := &accums[idx]
			if msg.IsResponse {
				if msg.RCode == DNSRCodeNameError {
					da.nxCount++
				}
				continue
			}
			da.queryCount++
			if sub != "" {
				if len(da.subdomains) < MaxDNSMessagesPerScan {
					da.subdomains[sub] = struct{}{}
				}
				ent := DNSLabelEntropy(qname)
				if ent > da.maxEntropy {
					da.maxEntropy = ent
				}
				da.sumEntropy += ent
				da.entropySamples++
				for label := range strings.SplitSeq(sub, ".") {
					if len(label) > da.maxLabelLen {
						da.maxLabelLen = len(label)
					}
					for j := range len(label) {
						ch := label[j]
						da.totalChars++
						if (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' {
							da.encodedChars++
						}
					}
				}
			}
		}

		for aIdx := range msg.Answers {
			ans := &msg.Answers[aIdx]
			if ans.Type == DNSTypeTXT {
				_, apex := splitDNSSubdomainAndApex(ans.Name)
				if idx, ok := indexByDomain[apex]; ok {
					accums[idx].txtBytes += uint64(ans.DataLength)
				}
			}
		}
	}

	out := make([]DNSDomainStats, len(accums))
	for i := range accums {
		da := &accums[i]
		var meanEnt float64
		if da.entropySamples > 0 {
			meanEnt = da.sumEntropy / float64(da.entropySamples)
		}
		var encRatio float64
		if da.totalChars > 0 {
			encRatio = float64(da.encodedChars) / float64(da.totalChars)
		}
		// Composite tunnel score in [0.0, 1.0]: weighted combination of normalized entropy (ent/4.5),
		// max label length (len/63), and unique subdomain fan-out.
		entScore := min(1.0, meanEnt/4.5)
		lenScore := min(1.0, float64(da.maxLabelLen)/63.0)
		uniqScore := 0.0
		if da.queryCount > 0 {
			uniqScore = min(1.0, float64(len(da.subdomains))/float64(max(da.queryCount, 1)))
		}
		tunnelScore := 0.45*entScore + 0.35*lenScore + 0.20*uniqScore

		out[i] = DNSDomainStats{
			Domain:               da.domain,
			QueryCount:           da.queryCount,
			UniqueSubdomains:     len(da.subdomains),
			NXDomainCount:        da.nxCount,
			MaxLabelLength:       da.maxLabelLen,
			MaxSubdomainEntropy:  da.maxEntropy,
			MeanSubdomainEntropy: meanEnt,
			EncodedCharRatio:     encRatio,
			TXTAnswerBytes:       da.txtBytes,
			TunnelScore:          tunnelScore,
		}
	}
	return out, nil
}

// DNSSourceStats aggregates per-client-IP DNS query and NXDOMAIN DGA burst
// indicators across all queried apex domains.
type DNSSourceStats struct {
	SrcAddr             netip.Addr
	QueryCount          int
	ResponseCount       int
	NXDomainCount       int
	UniqueApexes        int
	UniqueNXDomainApex  int
	NXDomainRatio       float64
	MaxSubdomainEntropy float64
	DGAScore            float64
}

// DNSSourceStats aggregates per-source-IP DNS query counts, NXDOMAIN counts,
// unique apex fan-out, and a composite DGAScore in [0.0, 1.0] in deterministic
// first-seen order.
func (c *Capture) DNSSourceStats(data []byte) ([]DNSSourceStats, error) {
	records, err := c.DNS(data)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, nil
	}

	type srcAccum struct {
		addr       netip.Addr
		queries    int
		responses  int
		nxCount    int
		apexes     map[string]struct{}
		nxApexes   map[string]struct{}
		maxEntropy float64
	}

	indexBySrc := make(map[netip.Addr]int)
	var accums []srcAccum
	getAccum := func(addr netip.Addr) *srcAccum {
		idx, exists := indexBySrc[addr]
		if !exists {
			idx = len(accums)
			indexBySrc[addr] = idx
			accums = append(accums, srcAccum{
				addr:     addr,
				apexes:   make(map[string]struct{}),
				nxApexes: make(map[string]struct{}),
			})
		}
		return &accums[idx]
	}

	for i := range records {
		rec := &records[i]
		msg := &rec.Message
		clientAddr := rec.SrcAddr
		if msg.IsResponse {
			clientAddr = rec.DstAddr
		}
		if !clientAddr.IsValid() {
			continue
		}
		sa := getAccum(clientAddr)
		if msg.IsResponse {
			sa.responses++
			if msg.RCode == DNSRCodeNameError {
				sa.nxCount++
			}
		} else {
			sa.queries++
		}
		for qIdx := range msg.Questions {
			qname := msg.Questions[qIdx].Name
			_, apex := splitDNSSubdomainAndApex(qname)
			if apex == "" {
				continue
			}
			if msg.IsResponse {
				if msg.RCode == DNSRCodeNameError && len(sa.nxApexes) < MaxDNSMessagesPerScan {
					sa.nxApexes[apex] = struct{}{}
				}
				continue
			}
			if len(sa.apexes) < MaxDNSMessagesPerScan {
				sa.apexes[apex] = struct{}{}
			}
			if ent := DNSLabelEntropy(qname); ent > sa.maxEntropy {
				sa.maxEntropy = ent
			}
		}
	}

	out := make([]DNSSourceStats, len(accums))
	for i := range accums {
		sa := &accums[i]
		denom := max(sa.responses, sa.queries)
		var nxRatio float64
		if denom > 0 {
			nxRatio = min(1.0, float64(sa.nxCount)/float64(denom))
		}
		var dgaScore float64
		if sa.nxCount >= 5 && len(sa.nxApexes) >= 3 {
			fanOutScore := min(1.0, float64(len(sa.nxApexes))/15.0)
			entScore := min(1.0, sa.maxEntropy/4.0)
			dgaScore = 0.45*nxRatio + 0.35*fanOutScore + 0.20*entScore
		}
		out[i] = DNSSourceStats{
			SrcAddr:             sa.addr,
			QueryCount:          sa.queries,
			ResponseCount:       sa.responses,
			NXDomainCount:       sa.nxCount,
			UniqueApexes:        len(sa.apexes),
			UniqueNXDomainApex:  len(sa.nxApexes),
			NXDomainRatio:       nxRatio,
			MaxSubdomainEntropy: sa.maxEntropy,
			DGAScore:            dgaScore,
		}
	}
	return out, nil
}
