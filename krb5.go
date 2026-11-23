package pcap

import (
	"cmp"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"math"
	"net/netip"
	"slices"
)

// KRB5Message contains metadata parsed from a Kerberos v5 AS-REQ, AS-REP,
// TGS-REQ, TGS-REP, or KRB-ERROR message (RFC 4120).
type KRB5Message struct {
	PVNO         int
	MsgType      uint8
	Realm        string
	ClientNames  []string
	ServiceNames []string
	ETypes       []int32
	ErrorCode    int32
	HasRC4HMAC   bool
}

// KRB5Record associates a parsed [KRB5Message] with its 5-tuple UDP or TCP flow
// in a [Capture].
// For TCP, PacketIndex identifies the packet containing the first record-mark byte.
type KRB5Record struct {
	PacketIndex int
	FlowIndex   int
	SrcAddr     netip.Addr
	DstAddr     netip.Addr
	SrcPort     uint16
	DstPort     uint16
	Message     KRB5Message
}

func isKRB5ApplicationTag(b byte) bool {
	switch b {
	case 0x60 | KRB5MsgASReq, 0x60 | KRB5MsgASRep, 0x60 | KRB5MsgTGSReq, 0x60 | KRB5MsgTGSRep, 0x60 | KRB5MsgError:
		return true
	default:
		return false
	}
}

func isKnownKRB5MsgType(tag int) bool {
	switch tag {
	case int(KRB5MsgASReq), int(KRB5MsgASRep), int(KRB5MsgTGSReq), int(KRB5MsgTGSRep), int(KRB5MsgError):
		return true
	default:
		return false
	}
}

// ParseKRB5 parses a Kerberos v5 message (AS-REQ, AS-REP, TGS-REQ, TGS-REP, or
// KRB-ERROR) from buf (with or without a 4-byte TCP record mark length prefix).
func ParseKRB5(buf []byte) (KRB5Message, error) {
	if len(buf) >= 5 && !isKRB5ApplicationTag(buf[0]) && (buf[0]&0x80) == 0 && (buf[4]&0x60) == 0x60 {
		recLen := int(binary.BigEndian.Uint32(buf[0:4]) & 0x7fffffff)
		if recLen > MaxKRB5PacketBytes {
			return KRB5Message{}, fmt.Errorf("%w: Kerberos TCP record length %d exceeds %d", ErrKRB5Limit, recLen, MaxKRB5PacketBytes)
		}
		if 4+recLen <= len(buf) {
			buf = buf[4 : 4+recLen]
		} else {
			buf = buf[4:]
		}
	}
	if len(buf) < 8 || len(buf) > MaxKRB5PacketBytes {
		return KRB5Message{}, fmt.Errorf("%w: invalid Kerberos v5 message length %d", ErrInvalidKRB5, len(buf))
	}

	var app asn1.RawValue
	if _, err := asn1.Unmarshal(buf, &app); err != nil || app.Class != asn1.ClassApplication || !app.IsCompound {
		return KRB5Message{}, fmt.Errorf("%w: missing Kerberos APPLICATION tag", ErrInvalidKRB5)
	}
	if !isKnownKRB5MsgType(app.Tag) {
		return KRB5Message{}, fmt.Errorf("%w: unsupported Kerberos message type %d", ErrInvalidKRB5, app.Tag)
	}

	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(app.Bytes, &seq); err != nil || seq.Tag != asn1.TagSequence {
		return KRB5Message{}, fmt.Errorf("%w: missing inner Kerberos SEQUENCE", ErrInvalidKRB5)
	}

	msgType := uint8(app.Tag)
	msg := KRB5Message{MsgType: msgType}
	rest := seq.Bytes
	for len(rest) > 0 {
		var field asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &field)
		if err != nil {
			return KRB5Message{}, fmt.Errorf("%w: malformed Kerberos field", ErrInvalidKRB5)
		}
		if field.Class != asn1.ClassContextSpecific {
			continue
		}

		switch msgType {
		case KRB5MsgASReq, KRB5MsgTGSReq:
			switch field.Tag {
			case 1:
				var pvno int
				if _, err := asn1.Unmarshal(field.Bytes, &pvno); err == nil {
					msg.PVNO = pvno
				}
			case 2:
				var mt int
				if _, err := asn1.Unmarshal(field.Bytes, &mt); err == nil && isKnownKRB5MsgType(mt) {
					msg.MsgType = uint8(mt)
				}
			case 4:
				parseKRB5KDCReqBody(field.Bytes, &msg)
			}

		case KRB5MsgASRep, KRB5MsgTGSRep:
			switch field.Tag {
			case 0:
				var pvno int
				if _, err := asn1.Unmarshal(field.Bytes, &pvno); err == nil {
					msg.PVNO = pvno
				}
			case 1:
				var mt int
				if _, err := asn1.Unmarshal(field.Bytes, &mt); err == nil && isKnownKRB5MsgType(mt) {
					msg.MsgType = uint8(mt)
				}
			case 3:
				msg.Realm = parseASN1String(field.Bytes)
			case 4:
				msg.ClientNames = parseKRB5PrincipalName(field.Bytes)
			case 5:
				parseKRB5Ticket(field.Bytes, &msg)
			case 6:
				if et, ok := parseKRB5EncryptedDataEType(field.Bytes); ok {
					appendKRB5EType(&msg, et)
				}
			}

		case KRB5MsgError:
			switch field.Tag {
			case 0:
				var pvno int
				if _, err := asn1.Unmarshal(field.Bytes, &pvno); err == nil {
					msg.PVNO = pvno
				}
			case 1:
				var mt int
				if _, err := asn1.Unmarshal(field.Bytes, &mt); err == nil && isKnownKRB5MsgType(mt) {
					msg.MsgType = uint8(mt)
				}
			case 6:
				var code int64
				if _, err := asn1.Unmarshal(field.Bytes, &code); err == nil && code >= math.MinInt32 && code <= math.MaxInt32 {
					msg.ErrorCode = int32(code)
				}
			case 9:
				msg.Realm = parseASN1String(field.Bytes)
			case 10:
				msg.ServiceNames = parseKRB5PrincipalName(field.Bytes)
			}
		}
	}

	if msg.PVNO != 5 {
		return KRB5Message{}, fmt.Errorf("%w: unsupported Kerberos pvno %d", ErrInvalidKRB5, msg.PVNO)
	}
	return msg, nil
}

func appendKRB5EType(msg *KRB5Message, et int32) {
	if et == KRB5ETypeRC4HMAC {
		msg.HasRC4HMAC = true
	}
	if len(msg.ETypes) >= MaxKRB5ETypes || slices.Contains(msg.ETypes, et) {
		return
	}
	msg.ETypes = append(msg.ETypes, et)
}

func parseKRB5Ticket(raw []byte, msg *KRB5Message) {
	var app asn1.RawValue
	if _, err := asn1.Unmarshal(raw, &app); err != nil || app.Class != asn1.ClassApplication || !app.IsCompound || app.Tag != 1 {
		return
	}
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(app.Bytes, &seq); err != nil || seq.Tag != asn1.TagSequence {
		return
	}
	rest := seq.Bytes
	for len(rest) > 0 {
		var f asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &f)
		if err != nil {
			break
		}
		if f.Class != asn1.ClassContextSpecific {
			continue
		}
		switch f.Tag {
		case 2:
			msg.ServiceNames = parseKRB5PrincipalName(f.Bytes)
		case 3:
			if et, ok := parseKRB5EncryptedDataEType(f.Bytes); ok {
				appendKRB5EType(msg, et)
			}
		}
	}
}

func parseKRB5EncryptedDataEType(raw []byte) (int32, bool) {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(raw, &seq); err != nil || seq.Tag != asn1.TagSequence {
		return 0, false
	}
	rest := seq.Bytes
	for len(rest) > 0 {
		var f asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &f)
		if err != nil {
			break
		}
		if f.Class == asn1.ClassContextSpecific && f.Tag == 0 {
			var v int64
			if _, err := asn1.Unmarshal(f.Bytes, &v); err == nil && v >= math.MinInt32 && v <= math.MaxInt32 {
				return int32(v), true
			}
			return 0, false
		}
	}
	return 0, false
}

func parseKRB5KDCReqBody(raw []byte, msg *KRB5Message) {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(raw, &seq); err != nil {
		return
	}
	rest := seq.Bytes
	for len(rest) > 0 {
		var f asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &f)
		if err != nil {
			break
		}
		if f.Class != asn1.ClassContextSpecific {
			continue
		}
		switch f.Tag {
		case 1:
			msg.ClientNames = parseKRB5PrincipalName(f.Bytes)
		case 2:
			msg.Realm = parseASN1String(f.Bytes)
		case 3:
			msg.ServiceNames = parseKRB5PrincipalName(f.Bytes)
		case 8:
			msg.ETypes = parseKRB5ETypeSeq(f.Bytes)
			for _, et := range msg.ETypes {
				if et == KRB5ETypeRC4HMAC {
					msg.HasRC4HMAC = true
				}
			}
		}
	}
}

func parseKRB5PrincipalName(raw []byte) []string {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(raw, &seq); err != nil {
		return nil
	}
	rest := seq.Bytes
	var names []string
	for len(rest) > 0 {
		var f asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &f)
		if err != nil {
			break
		}
		if f.Class == asn1.ClassContextSpecific && f.Tag == 1 {
			var nameSeq asn1.RawValue
			if _, err := asn1.Unmarshal(f.Bytes, &nameSeq); err != nil {
				break
			}
			nRest := nameSeq.Bytes
			for len(nRest) > 0 && len(names) < MaxKRB5PrincipalParts {
				var item asn1.RawValue
				nRest, err = asn1.Unmarshal(nRest, &item)
				if err != nil {
					break
				}
				names = append(names, string(item.Bytes))
			}
		}
	}
	return names
}

func parseKRB5ETypeSeq(raw []byte) []int32 {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(raw, &seq); err != nil {
		return nil
	}
	rest := seq.Bytes
	var out []int32
	for len(rest) > 0 && len(out) < MaxKRB5ETypes {
		var v int64
		var err error
		rest, err = asn1.Unmarshal(rest, &v)
		if err != nil {
			break
		}
		if v < math.MinInt32 || v > math.MaxInt32 {
			continue
		}
		out = append(out, int32(v))
	}
	return out
}

func parseASN1String(raw []byte) string {
	var val asn1.RawValue
	if _, err := asn1.Unmarshal(raw, &val); err != nil {
		return ""
	}
	return string(val.Bytes)
}

// Kerberos extracts Kerberos v5 messages across all UDP packets and
// reassembled TCP streams on port 88 in the capture.
func (c *Capture) Kerberos(data []byte) ([]KRB5Record, error) {
	if err := c.validateContainer(); err != nil {
		return nil, err
	}
	if c.PacketCount == 0 {
		return nil, nil
	}

	r := SafeReader{data: data, size: int64(len(data))}
	var table flowIndexTable
	var records []KRB5Record
	var tcp tcpMessageCollector

	err := c.walkPackets(&r, func(pkt PacketRecord) error {
		payload, err := r.Slice(pkt.PayloadOffset, pkt.PayloadLength)
		if err != nil {
			return err
		}
		frame, err := DecodeFrame(payload, pkt.LinkType)
		if err != nil || frame.IPVersion == 0 {
			return nil
		}
		key, _ := makeCanonicalFlowKey(frame.IPProtocol, frame.SrcAddr, frame.SrcPort, frame.DstAddr, frame.DstPort)
		flowIdx, _, err := table.lookupOrInsert(key)
		if err != nil {
			return err
		}
		if frame.SrcPort != 88 && frame.DstPort != 88 {
			return nil
		}
		if frame.IPProtocol == IPProtoTCP {
			return tcp.add(pkt, frame, flowIdx, payload[frame.PayloadOffset:frame.PayloadOffset+frame.PayloadLength])
		}
		if frame.IPProtocol != IPProtoUDP || frame.PayloadLength == 0 || frame.Anomalies.IPFragment {
			return nil
		}
		l4 := payload[frame.PayloadOffset : frame.PayloadOffset+frame.PayloadLength]
		msg, err := ParseKRB5(l4)
		if err != nil {
			return nil
		}
		if len(records) >= MaxKRB5RecordsPerScan {
			return fmt.Errorf("%w: exceeds %d Kerberos records", ErrKRB5Limit, MaxKRB5RecordsPerScan)
		}
		records = append(records, KRB5Record{
			PacketIndex: pkt.Index,
			FlowIndex:   flowIdx,
			SrcAddr:     frame.SrcAddr,
			DstAddr:     frame.DstAddr,
			SrcPort:     frame.SrcPort,
			DstPort:     frame.DstPort,
			Message:     msg,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}

	err = tcp.walk(4, 8, MaxKRB5PacketBytes, func(dir *tcpMessageDirection, pkt messagePacket, data []byte) error {
		msg, err := ParseKRB5(data)
		if err != nil {
			return nil
		}
		if len(records) >= MaxKRB5RecordsPerScan {
			return fmt.Errorf("%w: exceeds %d Kerberos records", ErrKRB5Limit, MaxKRB5RecordsPerScan)
		}
		records = append(records, KRB5Record{PacketIndex: pkt.index, FlowIndex: dir.flowIndex, SrcAddr: dir.src.Addr(), DstAddr: dir.dst.Addr(), SrcPort: dir.src.Port(), DstPort: dir.dst.Port(), Message: msg})
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(tcp.directions) > 0 {
		slices.SortStableFunc(records, func(a, b KRB5Record) int { return cmp.Compare(a.PacketIndex, b.PacketIndex) })
	}
	return records, nil
}
