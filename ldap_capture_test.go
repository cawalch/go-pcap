package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func TestLDAPCaptureParityAndProvenance(t *testing.T) {
	src, dst := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	bind := ldapTestMessage(0x60, []byte{2, 1, 3}, ldapTestText(4, "cn=reader"), ldapTestText(0x80, "fixture-only"))
	search := ldapTestSearch(ldapTestText(0x87, "objectClass"), ldapTestText(4, "cn"))
	tcp := func(seq uint32, flags uint8, data []byte) []byte {
		return buildEthernetIPv4TCPFrame(src, dst, 50100, ldapPort, seq, 0, flags, data)
	}
	udp := func(port uint16, data []byte) []byte {
		return buildEthernetIPv4UDPFrame(src, dst, 50200, port, data)
	}
	tail := bytes.Join([][]byte{bind[1:], ldapTestMessage(0x61), search, search}, nil)
	truncated := udp(ldapPort, search)
	frames := [][]byte{
		udp(53, search),
		tcp(100, TCPFlagSYN, nil),
		tcp(101, TCPFlagACK, bind[:1]),
		udp(ldapPort, search),
		tcp(102, TCPFlagACK, tail),
		tcp(102, TCPFlagACK, tail),
		tcp(10000, TCPFlagACK, search),
		udp(ldapPort, bind),
		truncated[:len(truncated)-1],
		udp(ldapPort, append(bytes.Clone(search), 0)),
	}
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := c.LDAP(raw)
	if err != nil {
		t.Fatal(err)
	}
	gotAt, err := c.LDAPFromReaderAt(bytes.NewReader(raw))
	if err != nil || !reflect.DeepEqual(rows, gotAt) {
		t.Fatalf("ReaderAt parity: %v, %v", gotAt, err)
	}
	packets, err := c.Packets(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 {
		t.Fatalf("got %d rows, want 4", len(rows))
	}
	for i, want := range []struct {
		packet, flow int
		proto, op    uint8
		port         uint16
	}{
		{2, 1, IPProtoTCP, LDAPBindRequest, 50100},
		{3, 2, IPProtoUDP, LDAPSearchRequest, 50200},
		{4, 1, IPProtoTCP, LDAPSearchRequest, 50100},
		{4, 1, IPProtoTCP, LDAPSearchRequest, 50100},
	} {
		got := rows[i]
		if got.PacketIndex != want.packet || got.TimestampNs != packets[want.packet].TimestampNs ||
			got.FlowIndex != want.flow || got.IPProtocol != want.proto || got.Message.Operation != want.op ||
			got.Source.Port() != want.port || got.Destination.Port() != ldapPort {
			t.Fatalf("row %d: %+v, want %+v", i, got, want)
		}
	}
	if rows[0].Message.BindDN != "cn=reader" || rows[1].Message.Filter != "(objectClass=*)" {
		t.Fatalf("wrong request metadata: %+v", rows)
	}
}

func TestLDAPCaptureLimitDiscardsResults(t *testing.T) {
	wire := ldapTestSearch(ldapTestText(0x87, "cn"))
	frame := buildEthernetIPv4UDPFrame([4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}, 50100, ldapPort, wire)
	datagrams := make([][]byte, MaxLDAPRecordsPerScan+1)
	for i := range datagrams {
		datagrams[i] = frame
	}
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, datagrams)
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, scan := range []func() ([]LDAPRecord, error){
		func() ([]LDAPRecord, error) { return c.LDAP(raw) },
		func() ([]LDAPRecord, error) { return c.LDAPFromReaderAt(bytes.NewReader(raw)) },
	} {
		if got, err := scan(); got != nil || !errors.Is(err, ErrLDAPLimit) {
			t.Fatalf("over-limit scan returned %d records, %v", len(got), err)
		}
	}
}

func BenchmarkLDAPCapture(b *testing.B) {
	src, dst := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	background := buildEthernetIPv4UDPFrame(src, dst, 50100, 53, make([]byte, 1400))
	wire := ldapTestSearch(ldapTestText(0x87, "objectClass"), ldapTestText(4, "cn"))
	request := buildEthernetIPv4UDPFrame(src, dst, 50100, ldapPort, wire)
	frames := make([][]byte, 256)
	for i := range frames {
		frames[i] = background
		if i%64 == 0 {
			frames[i] = request
		}
	}
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
	c, err := New(raw)
	if err != nil {
		b.Fatal(err)
	}
	r := bytes.NewReader(raw)
	for _, workload := range []struct {
		name string
		scan func() ([]LDAPRecord, error)
	}{
		{"slice", func() ([]LDAPRecord, error) { return c.LDAP(raw) }},
		{"reader", func() ([]LDAPRecord, error) { return c.LDAPFromReaderAt(r) }},
	} {
		b.Run(workload.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				records, err := workload.scan()
				if err != nil || len(records) != 4 {
					b.Fatalf("got %d records, %v", len(records), err)
				}
			}
		})
	}
}

func ExampleCapture_LDAP() {
	wire := ldapTestSearch(ldapTestText(0x87, "objectClass"), ldapTestText(4, "cn"))
	frame := buildEthernetIPv4UDPFrame([4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}, 50100, ldapPort, wire)
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{frame})
	c, err := New(raw)
	if err != nil {
		panic(err)
	}
	records, err := c.LDAP(raw)
	if err != nil {
		panic(err)
	}
	fmt.Println(records[0].PacketIndex, records[0].Message.Filter, records[0].Message.Attributes)
	// Output:
	// 0 (objectClass=*) [cn]
}
