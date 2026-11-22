package pcap

import (
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"net/netip"
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
type KRB5Record struct {
	PacketIndex int
	FlowIndex   int
	SrcAddr     netip.Addr
	DstAddr     netip.Addr
	SrcPort     uint16
	DstPort     uint16
	Message     KRB5Message
}

// ParseKRB5 parses a Kerberos v5 message (AS-REQ, AS-REP, TGS-REQ, TGS-REP, or
// KRB-ERROR) from buf (with or without a 4-byte TCP record mark length prefix).
func ParseKRB5(buf []byte) (KRB5Message, error) {
	if len(buf) >= 5 && (buf[0]&0x80) == 0 && (buf[4]&0x60) == 0x60 {
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

	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(app.Bytes, &seq); err != nil || seq.Tag != asn1.TagSequence {
		return KRB5Message{}, fmt.Errorf("%w: missing inner Kerberos SEQUENCE", ErrInvalidKRB5)
	}

	msg := KRB5Message{MsgType: uint8(app.Tag)}
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

		switch msg.MsgType {
		case KRB5MsgASReq, KRB5MsgTGSReq:
			switch field.Tag {
			case 1:
				var pvno int
				if _, err := asn1.Unmarshal(field.Bytes, &pvno); err == nil {
					msg.PVNO = pvno
				}
			case 2:
				var mt int
				if _, err := asn1.Unmarshal(field.Bytes, &mt); err == nil && mt > 0 {
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
				if _, err := asn1.Unmarshal(field.Bytes, &mt); err == nil && mt > 0 {
					msg.MsgType = uint8(mt)
				}
			case 3:
				msg.Realm = parseASN1String(field.Bytes)
			case 4:
				msg.ClientNames = parseKRB5PrincipalName(field.Bytes)
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
				if _, err := asn1.Unmarshal(field.Bytes, &mt); err == nil && mt > 0 {
					msg.MsgType = uint8(mt)
				}
			case 6:
				var code int
				if _, err := asn1.Unmarshal(field.Bytes, &code); err == nil {
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
		var v int
		var err error
		rest, err = asn1.Unmarshal(rest, &v)
		if err != nil {
			break
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

// Kerberos extracts Kerberos v5 messages across all UDP and TCP packets on port
// 88 in the capture.
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

	err := c.walkPackets(&r, func(pkt PacketRecord) error {
		payload, err := r.Slice(pkt.PayloadOffset, pkt.PayloadLength)
		if err != nil {
			return err
		}
		frame, err := DecodeFrame(payload, pkt.LinkType)
		if err != nil || frame.IPVersion == 0 || frame.PayloadLength == 0 {
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
	return records, nil
}
