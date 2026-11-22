package pcap

import (
	"encoding/binary"
	"fmt"
	"net/netip"
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
	Name       string
	Type       uint16
	Class      uint16
	TTL        uint32
	Address    netip.Addr
	Target     string
	TXT        []string
	DataOffset uint32
	DataLength uint32
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
			target, _, err := decodeDNSNameBounded(payload, rdataStart, rdataEnd, anomalies)
			if err != nil {
				return nil, offset, err
			}
			rec.Target = target
		case DNSTypeMX:
			if rdLen >= 3 {
				target, _, err := decodeDNSNameBounded(payload, rdataStart+2, rdataEnd, anomalies)
				if err != nil {
					return nil, offset, err
				}
				rec.Target = target
			} else {
				anomalies.InvalidRDataLength = true
			}
		case DNSTypeTXT:
			rec.TXT = decodeDNSTXT(payload[rdataStart:rdataEnd], anomalies)
		}

		records = append(records, rec)
		offset = rdataEnd
	}
	return records, offset, nil
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
	return decodeDNSNameBounded(payload, start, len(payload), anomalies)
}

func decodeDNSNameBounded(payload []byte, start int, limit int, anomalies *DNSAnomalies) (string, int, error) {
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
			if ptr >= cur || ptr >= len(payload) {
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
	packets, err := c.Packets(data)
	if err != nil {
		return nil, err
	}
	if len(packets) == 0 {
		return nil, nil
	}

	r := SafeReader{data: data, size: int64(len(data))}
	flowIndexByKey := make(map[flowKey]int)
	nextFlowIdx := 0
	var records []DNSRecord

	for i := range packets {
		pkt := &packets[i]
		payload, err := r.Slice(pkt.PayloadOffset, pkt.PayloadLength)
		if err != nil {
			return nil, err
		}
		frame, err := DecodeFrame(payload, pkt.LinkType)
		if err != nil || frame.IPVersion == 0 {
			continue
		}

		key, _ := makeCanonicalFlowKey(frame.IPProtocol, frame.SrcAddr, frame.SrcPort, frame.DstAddr, frame.DstPort)
		flowIdx, exists := flowIndexByKey[key]
		if !exists {
			if nextFlowIdx >= MaxFlows {
				return nil, fmt.Errorf("%w: exceeds %d", ErrFlowLimit, MaxFlows)
			}
			flowIdx = nextFlowIdx
			nextFlowIdx++
			flowIndexByKey[key] = flowIdx
		}

		if frame.PayloadLength == 0 || !isDNSPort(frame.SrcPort) && !isDNSPort(frame.DstPort) {
			continue
		}
		l4 := payload[frame.PayloadOffset : frame.PayloadOffset+frame.PayloadLength]

		switch frame.IPProtocol {
		case IPProtoUDP:
			msg, err := ParseDNS(l4)
			if err != nil {
				continue
			}
			if len(records) >= MaxDNSMessagesPerScan {
				return nil, fmt.Errorf("%w: exceeds %d messages", ErrDNSLimit, MaxDNSMessagesPerScan)
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
			if len(l4) < 14 {
				continue
			}
			dnsLen := int(binary.BigEndian.Uint16(l4[0:2]))
			if dnsLen < 12 || 2+dnsLen > len(l4) {
				continue
			}
			msg, err := ParseDNS(l4[2 : 2+dnsLen])
			if err != nil {
				continue
			}
			if len(records) >= MaxDNSMessagesPerScan {
				return nil, fmt.Errorf("%w: exceeds %d messages", ErrDNSLimit, MaxDNSMessagesPerScan)
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
		}
	}

	return records, nil
}

// HasDNSQuery reports whether any DNS message in the capture contains a question
// matching qname (case-insensitive ASCII comparison, ignoring a trailing dot).
func (c *Capture) HasDNSQuery(data []byte, qname string) (bool, error) {
	if err := c.validateContainer(); err != nil {
		return false, err
	}
	target := strings.TrimSuffix(qname, ".")
	packets, err := c.Packets(data)
	if err != nil {
		return false, err
	}
	r := SafeReader{data: data, size: int64(len(data))}

	for i := range packets {
		pkt := &packets[i]
		payload, err := r.Slice(pkt.PayloadOffset, pkt.PayloadLength)
		if err != nil {
			return false, err
		}
		frame, err := DecodeFrame(payload, pkt.LinkType)
		if err != nil || frame.IPVersion == 0 || frame.PayloadLength == 0 {
			continue
		}
		if !isDNSPort(frame.SrcPort) && !isDNSPort(frame.DstPort) {
			continue
		}
		l4 := payload[frame.PayloadOffset : frame.PayloadOffset+frame.PayloadLength]
		dnsPayload := l4
		if frame.IPProtocol == IPProtoTCP {
			if len(l4) < 14 {
				continue
			}
			dnsLen := int(binary.BigEndian.Uint16(l4[0:2]))
			if dnsLen < 12 || 2+dnsLen > len(l4) {
				continue
			}
			dnsPayload = l4[2 : 2+dnsLen]
		} else if frame.IPProtocol != IPProtoUDP {
			continue
		}
		if dnsPayloadHasQuery(dnsPayload, target) {
			return true, nil
		}
	}
	return false, nil
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
