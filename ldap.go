package pcap

import "fmt"

// LDAP operation tags reported by [ParseLDAP].
const (
	LDAPBindRequest   uint8 = 0
	LDAPSearchRequest uint8 = 3
)

// LDAPMessage contains the metadata of a decoded LDAP BindRequest or
// SearchRequest. DNs and requested attributes preserve the captured values.
// Filter is rendered in RFC 4515 syntax. Authentication credentials are
// discarded during parsing.
type LDAPMessage struct {
	MessageID     int
	Operation     uint8
	Version       int
	BindDN        string
	AuthType      string
	SASLMechanism string
	BaseDN        string
	Scope         uint8
	Filter        string
	Attributes    []string
}

// ParseLDAP parses one complete LDAPv3 message carrying a BindRequest or
// SearchRequest. It accepts definite BER lengths, including non-minimal
// encodings, and skips the optional controls envelope. The returned metadata
// owns its strings and attribute slice. Malformed or unsupported messages
// return [ErrInvalidLDAP]. Exceeding a documented bound returns [ErrLDAPLimit].
func ParseLDAP(buf []byte) (LDAPMessage, error) {
	if len(buf) > MaxLDAPPacketBytes {
		return LDAPMessage{}, ErrLDAPLimit
	}
	tag, body, rest, ok := readBERTLV(buf)
	if !ok || tag != 0x30 || len(rest) != 0 {
		return LDAPMessage{}, fmt.Errorf("%w: expected one LDAPMessage SEQUENCE", ErrInvalidLDAP)
	}
	message := ldapBERCursor{rest: body}
	id := ldapInteger(message.take(0x02))
	op, body := message.next()
	if len(message.rest) != 0 {
		message.take(0xa0)
	}
	if id <= 0 || !message.done() {
		return LDAPMessage{}, fmt.Errorf("%w: message ID or controls", ErrInvalidLDAP)
	}

	out := LDAPMessage{MessageID: id}
	switch op {
	case 0x60:
		out.Operation = LDAPBindRequest
		if err := parseLDAPBind(body, &out); err != nil {
			return LDAPMessage{}, err
		}
	case 0x63:
		out.Operation = LDAPSearchRequest
		if err := parseLDAPSearch(body, &out); err != nil {
			return LDAPMessage{}, err
		}
	default:
		return LDAPMessage{}, fmt.Errorf("%w: unsupported operation tag %#x", ErrInvalidLDAP, op)
	}
	return out, nil
}

func parseLDAPBind(body []byte, out *LDAPMessage) error {
	request := ldapBERCursor{rest: body}
	version := ldapInteger(request.take(0x02))
	dn := request.take(0x04)
	authTag, auth := request.next()
	if version < 1 || version > 127 || !request.done() {
		return fmt.Errorf("%w: BindRequest fields", ErrInvalidLDAP)
	}
	switch authTag {
	case 0x80: // Simple authentication. The value is a password.
		out.AuthType = "simple"
	case 0xa3:
		sasl := ldapBERCursor{rest: auth}
		mechanism := sasl.take(0x04)
		if len(sasl.rest) != 0 {
			sasl.take(0x04) // Optional SASL credentials.
		}
		if len(mechanism) == 0 || !sasl.done() {
			return fmt.Errorf("%w: SASL credentials framing", ErrInvalidLDAP)
		}
		out.AuthType = "sasl"
		out.SASLMechanism = string(mechanism)
	default:
		return fmt.Errorf("%w: unsupported authentication tag %#x", ErrInvalidLDAP, authTag)
	}
	out.Version, out.BindDN = version, string(dn)
	return nil
}

func parseLDAPSearch(body []byte, out *LDAPMessage) error {
	request := ldapBERCursor{rest: body}
	base := request.take(0x04)
	scope := ldapInteger(request.take(0x0a))
	aliases := ldapInteger(request.take(0x0a))
	size := ldapInteger(request.take(0x02))
	seconds := ldapInteger(request.take(0x02))
	typesOnly := request.take(0x01)
	filterTag, filter := request.next()
	attributes := request.take(0x30)
	if !request.done() || scope < 0 || scope > 2 || aliases < 0 || aliases > 3 ||
		size < 0 || seconds < 0 || !ldapBoolean(typesOnly) {
		return fmt.Errorf("%w: SearchRequest fields", ErrInvalidLDAP)
	}
	rendered, err := renderLDAPFilter(filterTag, filter)
	if err != nil {
		return err
	}
	attrs := ldapBERCursor{rest: attributes}
	for len(attrs.rest) != 0 {
		if len(out.Attributes) == MaxLDAPAttributes {
			return ErrLDAPLimit
		}
		v := attrs.take(0x04)
		if len(v) == 0 {
			return fmt.Errorf("%w: attribute selector", ErrInvalidLDAP)
		}
		out.Attributes = append(out.Attributes, string(v))
	}
	out.BaseDN, out.Scope, out.Filter = string(base), uint8(scope), rendered
	return nil
}

func ldapInteger(value []byte) int {
	if len(value) == 0 || len(value) > 4 || value[0]&0x80 != 0 ||
		len(value) > 1 && value[0] == 0 && value[1]&0x80 == 0 {
		return -1
	}
	n := 0
	for _, b := range value {
		n = n<<8 | int(b)
	}
	return n
}

func ldapBoolean(value []byte) bool {
	return len(value) == 1 && (value[0] == 0 || value[0] == 0xff)
}

type ldapBERCursor struct {
	rest    []byte
	invalid bool
}

func (c *ldapBERCursor) next() (byte, []byte) {
	tag, value, rest, ok := readBERTLV(c.rest)
	c.rest = rest
	c.invalid = c.invalid || !ok
	return tag, value
}

func (c *ldapBERCursor) take(want byte) []byte {
	tag, value := c.next()
	if tag != want {
		c.invalid = true
		return nil
	}
	return value
}

func (c *ldapBERCursor) done() bool {
	return !c.invalid && len(c.rest) == 0
}

// LDAP envelope and operation tags use the one-byte identifier form.
// RFC 4511 §5.1 requires definite lengths. Allow up to four length octets
// and check the declared length before converting it to an index.
func readBERTLV(buf []byte) (tag byte, value, rest []byte, ok bool) {
	if len(buf) < 2 || buf[0]&0x1f == 0x1f {
		return 0, nil, nil, false
	}
	header := 2
	length := uint32(buf[1])
	if buf[1]&0x80 != 0 {
		n := int(buf[1] & 0x7f)
		if n == 0 || n > 4 || n > len(buf)-header {
			return 0, nil, nil, false
		}
		length = 0
		for _, b := range buf[header : header+n] {
			length = length<<8 | uint32(b)
		}
		header += n
	}
	if uint64(length) > uint64(len(buf)-header) {
		return 0, nil, nil, false
	}
	end := header + int(length)
	return buf[0], buf[header:end], buf[end:], true
}
