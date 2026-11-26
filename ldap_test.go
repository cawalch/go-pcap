package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestParseLDAPBind(t *testing.T) {
	const password = "fixture-only-password"
	const credentials = "fixture-only-sasl-credentials"
	simple := ldapTestMessage(0x60, []byte{2, 1, 3}, ldapTestText(4, "cn=reader"),
		ldapTestText(0x80, password))
	// A long-form length with a leading zero is valid BER.
	simple = append([]byte{0x30, 0x82, 0, simple[1]}, simple[2:]...)
	sasl := ldapTestMessage(0x60, []byte{2, 1, 3}, ldapTestText(4, ""),
		ldapTestTLV(0xa3, ldapTestText(4, "EXTERNAL"), ldapTestText(4, credentials)))

	for _, tc := range []struct {
		wire []byte
		want LDAPMessage
	}{
		{simple, LDAPMessage{MessageID: 1, Operation: LDAPBindRequest, Version: 3, BindDN: "cn=reader", AuthType: "simple"}},
		{sasl, LDAPMessage{MessageID: 1, Operation: LDAPBindRequest, Version: 3, AuthType: "sasl", SASLMechanism: "EXTERNAL"}},
	} {
		msg, err := ParseLDAP(tc.wire)
		if err != nil {
			t.Fatal(err)
		}
		clear(tc.wire)
		if !reflect.DeepEqual(msg, tc.want) {
			t.Fatalf("got %+v, want %+v", msg, tc.want)
		}
		if text := fmt.Sprint(msg); strings.Contains(text, password) || strings.Contains(text, credentials) {
			t.Fatal("returned metadata contains authentication credentials")
		}
	}
}

func TestParseLDAPSearchFilters(t *testing.T) {
	filter := ldapTestTLV(0xa0,
		ldapTestTLV(0xa1, ldapTestText(0x87, "objectClass"), ldapTestAssertion(0xa3, "cn", "a()*\\\x00\xff")),
		ldapTestTLV(0xa2, ldapTestAssertion(0xa5, "uidNumber", "1000")),
		ldapTestAssertion(0xa6, "uidNumber", "2000"),
		ldapTestAssertion(0xa8, "sn", "Doe"),
		ldapTestTLV(0xa4, ldapTestText(4, "cn;lang-en"), ldapTestTLV(0x30,
			ldapTestText(0x80, "First"), ldapTestText(0x81, "*"), ldapTestText(0x82, "Last"))),
		ldapTestTLV(0xa9, ldapTestText(0x81, "1.2.3"), ldapTestText(0x82, "cn"),
			ldapTestText(0x83, "Alice"), []byte{0x84, 1, 0xff}),
	)
	wire := ldapTestSearch(filter, ldapTestText(4, "cn"), ldapTestText(4, "uid"), ldapTestText(4, "cn"))
	// Attach a control to the message envelope.
	_, message, _, ok := readBERTLV(wire)
	if !ok {
		t.Fatal("bad LDAP search fixture")
	}
	wire = ldapTestTLV(0x30, message, ldapTestTLV(0xa0, ldapTestTLV(0x30, ldapTestText(4, "1.2.3"))))
	msg, err := ParseLDAP(wire)
	if err != nil {
		t.Fatal(err)
	}
	clear(wire)
	wantFilter := "(&(|(objectClass=*)(cn=a\\28\\29\\2a\\5c\\00\\ff))(!(uidNumber>=1000))(uidNumber<=2000)(sn~=Doe)(cn;lang-en=First*\\2a*Last)(cn:dn:1.2.3:=Alice))"
	if msg.MessageID != 1 || msg.Operation != LDAPSearchRequest || msg.Scope != 2 ||
		msg.BaseDN != "dc=example,dc=test" || msg.Filter != wantFilter ||
		!slices.Equal(msg.Attributes, []string{"cn", "uid", "cn"}) {
		t.Fatalf("wrong search metadata: %+v", msg)
	}

	for _, tc := range []struct {
		filter []byte
		want   string
	}{
		{ldapTestTLV(0xa4, ldapTestText(4, "cn"), ldapTestTLV(0x30, ldapTestText(0x82, "end"))), "(cn=*end)"},
		{ldapTestTLV(0xa4, ldapTestText(4, "cn"), ldapTestTLV(0x30, ldapTestText(0x80, "start"))), "(cn=start*)"},
		{ldapTestTLV(0xa9, ldapTestText(0x81, "1.2.3"), ldapTestText(0x83, "value")), "(:1.2.3:=value)"},
		{ldapTestTLV(0xa9, ldapTestText(0x82, "cn"), ldapTestText(0x83, "")), "(cn:=)"},
	} {
		msg, err := ParseLDAP(ldapTestSearch(tc.filter))
		if err != nil || msg.Filter != tc.want {
			t.Fatalf("got %q, %v, want %q", msg.Filter, err, tc.want)
		}
	}
}

func TestParseLDAPRejectsMalformed(t *testing.T) {
	valid := ldapTestSearch(ldapTestText(0x87, "cn"))
	for n := range valid {
		if _, err := ParseLDAP(valid[:n]); !errors.Is(err, ErrInvalidLDAP) {
			t.Fatalf("truncation at %d returned %v", n, err)
		}
	}
	for _, wire := range [][]byte{
		append(bytes.Clone(valid), 0),
		{0x30, 0x80, 0, 0},
		{0x30, 0x84, 0xff, 0xff, 0xff, 0xff},
		{0x30, 0x85, 0, 0, 0, 0, 0},
		{0x3f, 0x10, 0, 0},
		ldapTestMessage(0x61),
		ldapTestTLV(0x30, []byte{0x02, 0x01, 0x00, 0x60, 0x00}),
		ldapTestMessage(0x60, []byte{2, 1, 3}, ldapTestText(4, ""), ldapTestTLV(0xa3, ldapTestText(4, ""))),
		ldapTestSearch(ldapTestText(0x87, "cn)(objectClass")),
		ldapTestSearch(ldapTestText(0x87, "1.02.3")),
		ldapTestSearch(ldapTestText(0x87, "cn;")),
		ldapTestSearch(ldapTestTLV(0xa0)),
		ldapTestSearch(ldapTestTLV(0xa2, ldapTestText(0x87, "cn"), ldapTestText(0x87, "sn"))),
		ldapTestSearch(ldapTestTLV(0xa4, ldapTestText(4, "cn"), ldapTestTLV(0x30,
			ldapTestText(0x82, "last"), ldapTestText(0x81, "any")))),
		ldapTestSearch(ldapTestTLV(0xa4, ldapTestText(4, "cn"), ldapTestTLV(0x30, ldapTestText(0x80, "")))),
		ldapTestSearch(ldapTestTLV(0xa9, ldapTestText(0x83, "value"))),
	} {
		got, err := ParseLDAP(wire)
		if !errors.Is(err, ErrInvalidLDAP) || !reflect.DeepEqual(got, LDAPMessage{}) {
			t.Fatalf("malformed LDAP returned %+v, %v", got, err)
		}
	}
}

func TestParseLDAPLimits(t *testing.T) {
	var attrs [][]byte
	for range MaxLDAPAttributes {
		attrs = append(attrs, ldapTestText(4, "cn"))
	}
	present := ldapTestText(0x87, "cn")
	if msg, err := ParseLDAP(ldapTestSearch(present, attrs...)); err != nil || len(msg.Attributes) != MaxLDAPAttributes {
		t.Fatalf("attribute limit: %d, %v", len(msg.Attributes), err)
	}
	filter := present
	for range MaxLDAPFilterDepth - 1 {
		filter = ldapTestTLV(0xa2, filter)
	}
	if _, err := ParseLDAP(ldapTestSearch(filter)); err != nil {
		t.Fatalf("filter depth at limit: %v", err)
	}
	value := strings.Repeat("x", MaxLDAPFilterBytes-len("(cn=)"))
	if msg, err := ParseLDAP(ldapTestSearch(ldapTestAssertion(0xa3, "cn", value))); err != nil || len(msg.Filter) != MaxLDAPFilterBytes {
		t.Fatalf("rendered length at limit: %d, %v", len(msg.Filter), err)
	}
	for _, wire := range [][]byte{
		make([]byte, MaxLDAPPacketBytes+1),
		ldapTestSearch(present, append(attrs, ldapTestText(4, "sn"))...),
		ldapTestSearch(ldapTestTLV(0xa2, filter)),
		ldapTestSearch(ldapTestAssertion(0xa3, "cn", value+"x")),
		ldapTestSearch(ldapTestAssertion(0xa3, "cn", strings.Repeat("\x00", MaxLDAPFilterBytes/3))),
	} {
		got, err := ParseLDAP(wire)
		if !errors.Is(err, ErrLDAPLimit) || !reflect.DeepEqual(got, LDAPMessage{}) {
			t.Fatalf("oversized LDAP returned %+v, %v", got, err)
		}
	}
}

func BenchmarkParseLDAP(b *testing.B) {
	search := ldapTestTLV(0xa0, ldapTestText(0x87, "objectClass"), ldapTestAssertion(0xa3, "cn", "Alice"))
	for _, tc := range []struct {
		name string
		wire []byte
	}{
		{"bind", ldapTestMessage(0x60, []byte{2, 1, 3}, ldapTestText(4, "cn=reader"), ldapTestText(0x80, ""))},
		{"search", ldapTestSearch(search, ldapTestText(4, "cn"), ldapTestText(4, "uid"))},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.SetBytes(int64(len(tc.wire)))
			b.ReportAllocs()
			for b.Loop() {
				if _, err := ParseLDAP(tc.wire); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func ldapTestSearch(filter []byte, attrs ...[]byte) []byte {
	return ldapTestMessage(0x63, ldapTestText(4, "dc=example,dc=test"), []byte{
		0x0a, 1, 2, 0x0a, 1, 0, 2, 1, 0, 2, 1, 0, 1, 1, 0,
	}, filter, ldapTestTLV(0x30, attrs...))
}

func ldapTestAssertion(tag byte, attribute, value string) []byte {
	return ldapTestTLV(tag, ldapTestText(4, attribute), ldapTestText(4, value))
}

func ldapTestMessage(tag byte, fields ...[]byte) []byte {
	return ldapTestTLV(0x30, []byte{2, 1, 1}, ldapTestTLV(tag, fields...))
}

func ldapTestText(tag byte, value string) []byte {
	return ldapTestTLV(tag, []byte(value))
}

func ldapTestTLV(tag byte, parts ...[]byte) []byte {
	body := bytes.Join(parts, nil)
	n := len(body)
	header := []byte{tag}
	switch {
	case n < 128:
		header = append(header, byte(n))
	case n < 256:
		header = append(header, 0x81, byte(n))
	default:
		header = binary.BigEndian.AppendUint16(append(header, 0x82), uint16(n))
	}
	return append(header, body...)
}
