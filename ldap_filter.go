package pcap

import (
	"bytes"
	"fmt"
	"strings"
)

func renderLDAPFilter(tag byte, body []byte) (string, error) {
	var out strings.Builder
	if err := appendLDAPFilter(&out, tag, body, 0); err != nil {
		return "", err
	}
	return out.String(), nil
}

func appendLDAPFilter(out *strings.Builder, tag byte, body []byte, depth int) error {
	if depth >= MaxLDAPFilterDepth || out.Len() >= MaxLDAPFilterBytes {
		return ErrLDAPLimit
	}
	out.WriteByte('(')
	switch tag {
	case 0xa0, 0xa1, 0xa2:
		switch tag {
		case 0xa0:
			out.WriteByte('&')
		case 0xa1:
			out.WriteByte('|')
		case 0xa2:
			out.WriteByte('!')
		}
		children := ldapBERCursor{rest: body}
		for len(children.rest) != 0 {
			childTag, child := children.next()
			if children.invalid || tag == 0xa2 && len(children.rest) != 0 {
				return fmt.Errorf("%w: filter children", ErrInvalidLDAP)
			}
			if err := appendLDAPFilter(out, childTag, child, depth+1); err != nil {
				return err
			}
		}
		if len(body) == 0 {
			return fmt.Errorf("%w: empty filter group", ErrInvalidLDAP)
		}
	case 0x87: // Present.
		if err := appendLDAPFilterName(out, body, true); err != nil {
			return err
		}
		out.WriteString("=*")
	case 0xa3, 0xa5, 0xa6, 0xa8: // Attribute value assertions.
		assertion := ldapBERCursor{rest: body}
		attribute := assertion.take(0x04)
		value := assertion.take(0x04)
		if !assertion.done() {
			return fmt.Errorf("%w: attribute value assertion", ErrInvalidLDAP)
		}
		if err := appendLDAPFilterName(out, attribute, true); err != nil {
			return err
		}
		switch tag {
		case 0xa5:
			out.WriteByte('>')
		case 0xa6:
			out.WriteByte('<')
		case 0xa8:
			out.WriteByte('~')
		}
		out.WriteByte('=')
		if err := appendLDAPAssertionValue(out, value); err != nil {
			return err
		}
	case 0xa4:
		if err := appendLDAPSubstringFilter(out, body); err != nil {
			return err
		}
	case 0xa9:
		if err := appendLDAPExtensibleFilter(out, body); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%w: unsupported filter tag %#x", ErrInvalidLDAP, tag)
	}
	out.WriteByte(')')
	if out.Len() > MaxLDAPFilterBytes {
		return ErrLDAPLimit
	}
	return nil
}

func appendLDAPSubstringFilter(out *strings.Builder, body []byte) error {
	fields := ldapBERCursor{rest: body}
	attribute := fields.take(0x04)
	terms := fields.take(0x30)
	if !fields.done() || len(terms) == 0 {
		return fmt.Errorf("%w: substring filter", ErrInvalidLDAP)
	}
	if err := appendLDAPFilterName(out, attribute, true); err != nil {
		return err
	}
	out.WriteByte('=')
	if terms[0] != 0x80 {
		out.WriteByte('*')
	}
	parts := ldapBERCursor{rest: terms}
	for first := true; len(parts.rest) != 0; first = false {
		tag, value := parts.next()
		if len(value) == 0 {
			return fmt.Errorf("%w: empty substring assertion", ErrInvalidLDAP)
		}
		switch tag {
		case 0x80:
			if !first {
				return fmt.Errorf("%w: substring initial position", ErrInvalidLDAP)
			}
		case 0x81:
		case 0x82:
			if len(parts.rest) != 0 {
				return fmt.Errorf("%w: substring final position", ErrInvalidLDAP)
			}
		default:
			return fmt.Errorf("%w: substring assertion", ErrInvalidLDAP)
		}
		if err := appendLDAPAssertionValue(out, value); err != nil {
			return err
		}
		if tag != 0x82 {
			out.WriteByte('*')
		}
	}
	return nil
}

func appendLDAPExtensibleFilter(out *strings.Builder, body []byte) error {
	fields := ldapBERCursor{rest: body}
	var rule, attribute []byte
	if len(fields.rest) != 0 && fields.rest[0] == 0x81 {
		rule = fields.take(0x81)
	}
	if len(fields.rest) != 0 && fields.rest[0] == 0x82 {
		attribute = fields.take(0x82)
	}
	value := fields.take(0x83)
	withDN := false
	if len(fields.rest) != 0 {
		flag := fields.take(0x84)
		if !ldapBoolean(flag) {
			return fmt.Errorf("%w: extensible filter dnAttributes", ErrInvalidLDAP)
		}
		withDN = flag[0] == 0xff
	}
	if !fields.done() || rule == nil && attribute == nil {
		return fmt.Errorf("%w: extensible filter fields", ErrInvalidLDAP)
	}
	if attribute != nil {
		if err := appendLDAPFilterName(out, attribute, true); err != nil {
			return err
		}
	}
	if withDN {
		out.WriteString(":dn")
	}
	if rule != nil {
		out.WriteByte(':')
		if err := appendLDAPFilterName(out, rule, false); err != nil {
			return err
		}
	}
	out.WriteString(":=")
	return appendLDAPAssertionValue(out, value)
}

func appendLDAPAssertionValue(out *strings.Builder, value []byte) error {
	const hexDigits = "0123456789abcdef"
	if len(value) > MaxLDAPFilterBytes-out.Len() {
		return ErrLDAPLimit
	}
	for _, b := range value {
		switch {
		case b < 0x20 || b >= 0x7f || b == '(' || b == ')' || b == '*' || b == '\\':
			if out.Len() > MaxLDAPFilterBytes-3 {
				return ErrLDAPLimit
			}
			out.WriteByte('\\')
			out.WriteByte(hexDigits[b>>4])
			out.WriteByte(hexDigits[b&0xf])
		default:
			if out.Len() == MaxLDAPFilterBytes {
				return ErrLDAPLimit
			}
			out.WriteByte(b)
		}
	}
	return nil
}

func appendLDAPFilterName(out *strings.Builder, name []byte, allowOptions bool) error {
	if len(name) > MaxLDAPFilterBytes-out.Len() {
		return ErrLDAPLimit
	}
	base, options, hasOptions := bytes.Cut(name, []byte(";"))
	if !isLDAPOID(base) || hasOptions && !allowOptions {
		return fmt.Errorf("%w: filter attribute or matching rule name", ErrInvalidLDAP)
	}
	for hasOptions {
		var option []byte
		option, options, hasOptions = bytes.Cut(options, []byte(";"))
		if len(option) == 0 || !isLDAPKey(option) {
			return fmt.Errorf("%w: filter attribute option", ErrInvalidLDAP)
		}
	}
	out.Write(name)
	return nil
}

func isLDAPOID(name []byte) bool {
	if len(name) == 0 {
		return false
	}
	if isLDAPLetter(name[0]) {
		return isLDAPKey(name)
	}
	part, rest, hasDot := bytes.Cut(name, []byte("."))
	if !hasDot {
		return false
	}
	for {
		if len(part) == 0 || len(part) > 1 && part[0] == '0' {
			return false
		}
		for _, b := range part {
			if b < '0' || b > '9' {
				return false
			}
		}
		if !hasDot {
			return true
		}
		part, rest, hasDot = bytes.Cut(rest, []byte("."))
	}
}

func isLDAPLetter(b byte) bool {
	return 'a' <= b && b <= 'z' || 'A' <= b && b <= 'Z'
}

func isLDAPKey(s []byte) bool {
	for _, b := range s {
		if !isLDAPLetter(b) && (b < '0' || b > '9') && b != '-' {
			return false
		}
	}
	return true
}
