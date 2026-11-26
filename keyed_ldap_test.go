package pcap

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"slices"
	"testing"
)

func TestKeyedLDAPCoverageAndReaderAt(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version uint16
	}{
		{"TLS 1.2", TLSVersion12},
		{"TLS 1.3", TLSVersion13},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newKeyedProtocolFixture(t, tc.version, "ldap")
			bind := ldapTestMessage(0x60, []byte{2, 1, 3}, ldapTestText(4, "cn=reader"), ldapTestText(0x80, "fixture-only"))
			search := ldapTestSearch(ldapTestText(0x87, "objectClass"))
			packet := len(f.packets)
			f.send(false, TCPFlagACK, f.seal(false, 0, TLSRecordApplicationData, string(bind[:1])))
			second := f.seal(false, 1, TLSRecordApplicationData, string(append(bytes.Clone(bind[1:]), search...)))
			f.send(false, TCPFlagACK, second[:6])
			f.send(false, TCPFlagACK, second[6:])
			bad := f.seal(false, 2, TLSRecordApplicationData, string(search))
			bad[len(bad)-1] ^= 1
			f.send(false, TCPFlagACK, bad)

			offPort := keyedCapture(t, f.keys, f.packets)
			for _, frame := range f.packets {
				for _, off := range []int{34, 36} {
					if binary.BigEndian.Uint16(frame[off:]) == 443 {
						binary.BigEndian.PutUint16(frame[off:], ldapsPort)
					}
				}
			}
			raw := keyedCapture(t, f.keys, f.packets)
			c, err := New(raw)
			if err != nil {
				t.Fatal(err)
			}
			rows, err := c.KeyedLDAP(raw, nil)
			if err != nil || len(rows) != 2 {
				t.Fatalf("got %d records, %v", len(rows), err)
			}
			r := bytes.NewReader(raw)
			index, err := NewFromReaderAt(r, int64(len(raw)))
			if err != nil {
				t.Fatal(err)
			}
			at, err := index.KeyedLDAPFromReaderAt(r, nil)
			if err != nil || !reflect.DeepEqual(rows, at) {
				t.Fatalf("ReaderAt mismatch: %v, %v", at, err)
			}
			first, secondRow := rows[0], rows[1]
			if first.OpeningPacket != 0 || first.FlowIndex != 0 || first.Destination.Port() != ldapsPort ||
				first.PlaintextOffset != 0 || first.Message.AuthType != "simple" || first.Message.BindDN != "cn=reader" ||
				len(first.Records) != 2 || !slices.Equal(first.PacketIndices, []int{packet, packet + 1, packet + 2}) ||
				!first.Coverage.IncompleteTail {
				t.Fatalf("Bind: %+v", first)
			}
			if secondRow.PlaintextOffset != len(bind) || secondRow.Message.Filter != "(objectClass=*)" ||
				len(secondRow.Records) != 1 || !slices.Equal(secondRow.PacketIndices, []int{packet + 1, packet + 2}) {
				t.Fatalf("Search: %+v", secondRow)
			}

			withoutKey := keyedCapture(t, nil, f.packets)
			for _, input := range [][]byte{offPort, withoutKey} {
				c, err := New(input)
				if err != nil {
					t.Fatal(err)
				}
				if rows, err := c.KeyedLDAP(input, nil); err != nil || len(rows) != 0 {
					t.Fatalf("unexpected evidence: %v, %v", rows, err)
				}
			}
			c, err = New(withoutKey)
			if err != nil {
				t.Fatal(err)
			}
			if extra, err := c.KeyedLDAP(withoutKey, f.keys); err != nil || !reflect.DeepEqual(rows, extra) {
				t.Fatalf("extra key log mismatch: %v, %v", extra, err)
			}
		})
	}
}
