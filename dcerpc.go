package pcap

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// DCERPCPacketType identifies a connection-oriented DCE/RPC PDU.
type DCERPCPacketType uint8

// Packet types supported by [ParseDCERPC].
const (
	DCERPCRequest      DCERPCPacketType = 0
	DCERPCResponse     DCERPCPacketType = 2
	DCERPCBind         DCERPCPacketType = 11
	DCERPCBindAck      DCERPCPacketType = 12
	DCERPCAlterContext DCERPCPacketType = 14
)

const (
	dcerpcHeaderBytes      = 16
	dcerpcAuthTrailerBytes = 8
	dcerpcSyntaxBytes      = 20
	dcerpcContextBytes     = 4 + dcerpcSyntaxBytes
)

// DCERPCContext describes one offered presentation context from a Bind or
// Alter Context PDU. AbstractSyntaxUUID is a lowercase interface UUID.
type DCERPCContext struct {
	ContextID             uint16
	AbstractSyntaxUUID    string
	InterfaceVersionMajor uint16
	InterfaceVersionMinor uint16
}

// DCERPCMessage carries metadata from one connection-oriented DCE/RPC
// fragment. ContextID applies to requests and responses. Opnum applies to
// requests. Contexts contains Bind or Alter Context offers in wire order.
type DCERPCMessage struct {
	PacketType     DCERPCPacketType
	Flags          uint8
	FragmentLength uint16
	CallID         uint32
	ContextID      uint16
	Opnum          uint16
	Contexts       []DCERPCContext
}

// ParseDCERPC parses the first complete connection-oriented DCE/RPC 5.0
// fragment in buf. FragmentLength gives the number of bytes consumed.
// It parses metadata from Request, Response, Bind, Bind Ack, and Alter
// Context PDUs. Stub bytes, authentication tokens, and transfer syntax
// details stay opaque. The result owns its context list and UUID strings.
// Malformed or unsupported fragments return [ErrInvalidDCERPC].
// Oversized context and result lists return [ErrDCERPCLimit].
func ParseDCERPC(buf []byte) (DCERPCMessage, error) {
	if len(buf) < dcerpcHeaderBytes || buf[0] != 5 || buf[1] != 0 {
		return DCERPCMessage{}, fmt.Errorf("%w: expected DCE/RPC 5.0 header", ErrInvalidDCERPC)
	}
	var order binary.ByteOrder
	switch buf[4] {
	case 0x00:
		order = binary.BigEndian
	case 0x10:
		order = binary.LittleEndian
	default:
		return DCERPCMessage{}, fmt.Errorf("%w: unsupported data representation %#x", ErrInvalidDCERPC, buf[4])
	}

	length := order.Uint16(buf[8:10])
	end := int(length)
	if end < dcerpcHeaderBytes || end > len(buf) {
		return DCERPCMessage{}, fmt.Errorf("%w: fragment length %d", ErrInvalidDCERPC, length)
	}
	if authLength := int(order.Uint16(buf[10:12])); authLength != 0 {
		trailer := end - authLength - dcerpcAuthTrailerBytes
		if trailer < dcerpcHeaderBytes || int(buf[trailer+2]) > trailer-dcerpcHeaderBytes {
			return DCERPCMessage{}, fmt.Errorf("%w: authentication trailer bounds", ErrInvalidDCERPC)
		}
		end = trailer - int(buf[trailer+2])
	}

	body := buf[dcerpcHeaderBytes:end]
	out := DCERPCMessage{
		PacketType: DCERPCPacketType(buf[2]), Flags: buf[3],
		FragmentLength: length, CallID: order.Uint32(buf[12:16]),
	}
	switch out.PacketType {
	case DCERPCRequest, DCERPCResponse:
		// Request flags can declare an optional 16-byte object UUID.
		fixed := 8
		if out.PacketType == DCERPCRequest && out.Flags&0x80 != 0 {
			fixed += 16
		}
		if len(body) < fixed {
			return DCERPCMessage{}, fmt.Errorf("%w: truncated call header", ErrInvalidDCERPC)
		}
		out.ContextID = order.Uint16(body[4:6])
		if out.PacketType == DCERPCRequest {
			out.Opnum = order.Uint16(body[6:8])
		}
	case DCERPCBind, DCERPCAlterContext:
		contexts, err := parseDCERPCContexts(body, order)
		if err != nil {
			return DCERPCMessage{}, err
		}
		out.Contexts = contexts
	case DCERPCBindAck:
		if err := checkDCERPCBindAck(body, order); err != nil {
			return DCERPCMessage{}, err
		}
	default:
		return DCERPCMessage{}, fmt.Errorf("%w: unsupported packet type %d", ErrInvalidDCERPC, out.PacketType)
	}
	return out, nil
}

func parseDCERPCContexts(body []byte, order binary.ByteOrder) ([]DCERPCContext, error) {
	if len(body) < 12 {
		return nil, fmt.Errorf("%w: truncated presentation context list", ErrInvalidDCERPC)
	}
	count := int(body[8])
	body = body[12:]
	if count > MaxDCERPCContexts {
		return nil, ErrDCERPCLimit
	}
	if count > len(body)/(dcerpcContextBytes+dcerpcSyntaxBytes) {
		return nil, fmt.Errorf("%w: truncated presentation contexts", ErrInvalidDCERPC)
	}
	var contexts []DCERPCContext
	if count > 0 {
		contexts = make([]DCERPCContext, 0, count)
	}
	for range count {
		if len(body) < dcerpcContextBytes {
			return nil, fmt.Errorf("%w: truncated presentation context", ErrInvalidDCERPC)
		}
		transfers := int(body[2])
		if transfers == 0 || transfers > (len(body)-dcerpcContextBytes)/dcerpcSyntaxBytes {
			return nil, fmt.Errorf("%w: transfer syntax count %d", ErrInvalidDCERPC, transfers)
		}
		version := order.Uint32(body[20:24])
		contexts = append(contexts, DCERPCContext{
			ContextID:             order.Uint16(body[:2]),
			AbstractSyntaxUUID:    dcerpcUUID(body[4:20], order),
			InterfaceVersionMajor: uint16(version),
			InterfaceVersionMinor: uint16(version >> 16),
		})
		body = body[dcerpcContextBytes+transfers*dcerpcSyntaxBytes:]
	}
	if len(body) != 0 {
		return nil, fmt.Errorf("%w: trailing presentation context bytes", ErrInvalidDCERPC)
	}
	return contexts, nil
}

func checkDCERPCBindAck(body []byte, order binary.ByteOrder) error {
	if len(body) < 10 {
		return fmt.Errorf("%w: truncated Bind Ack secondary address", ErrInvalidDCERPC)
	}
	// The result list starts on a four-byte boundary after the address.
	results := (10 + int(order.Uint16(body[8:10])) + 3) &^ 3
	if results > len(body)-4 {
		return fmt.Errorf("%w: truncated Bind Ack result list", ErrInvalidDCERPC)
	}
	count := int(body[results])
	if count > MaxDCERPCContexts {
		return ErrDCERPCLimit
	}
	if len(body)-results-4 != count*(4+dcerpcSyntaxBytes) {
		return fmt.Errorf("%w: Bind Ack result list length", ErrInvalidDCERPC)
	}
	return nil
}

// The first three UUID fields follow the PDU's byte order. The last eight
// bytes appear in wire order in the canonical representation.
func dcerpcUUID(raw []byte, order binary.ByteOrder) string {
	id := [16]byte(raw)
	binary.BigEndian.PutUint32(id[:4], order.Uint32(raw[:4]))
	binary.BigEndian.PutUint16(id[4:6], order.Uint16(raw[4:6]))
	binary.BigEndian.PutUint16(id[6:8], order.Uint16(raw[6:8]))
	var text [36]byte
	text[8], text[13], text[18], text[23] = '-', '-', '-', '-'
	hex.Encode(text[:8], id[:4])
	hex.Encode(text[9:13], id[4:6])
	hex.Encode(text[14:18], id[6:8])
	hex.Encode(text[19:23], id[8:10])
	hex.Encode(text[24:], id[10:])
	return string(text[:])
}
