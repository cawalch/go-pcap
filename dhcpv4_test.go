package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"testing"
)

func dhcpv4Message(op, client byte, opts ...byte) []byte {
	p := make([]byte, 240)
	p[0], p[1], p[2] = op, 1, 6
	p[28], p[33] = 2, client
	binary.BigEndian.PutUint32(p[4:], 0x12340000+uint32(client))
	binary.BigEndian.PutUint32(p[236:], 0x63825363)
	return append(p, opts...)
}

func TestDHCPv4Exchange(t *testing.T) {
	lease := [4]byte{192, 0, 2, 10}
	server := [4]byte{192, 0, 2, 1}
	broadcast := [4]byte{255, 255, 255, 255}
	discover := dhcpv4Message(1, 1, 53, 1, 1, 255)
	offer := dhcpv4Message(2, 1, 53, 1, 2, 255)
	copy(offer[16:], lease[:])
	request := dhcpv4Message(1, 1, 53, 1, 3, 50, 4, 192, 0, 2, 10, 255)
	renew := dhcpv4Message(1, 1, 53, 1, 3, 255)
	copy(renew[12:], lease[:])
	ack := dhcpv4Message(2, 1, 53, 1, 5, 54, 4, 192, 0, 2, 1, 51, 4, 0, 0, 0x0e, 0x10, 61, 3, 0, 1, 2, 12, 3, 'i', 'o', 't', 255)
	copy(ack[16:], lease[:])
	copy(ack[20:], []byte{192, 0, 2, 12})
	copy(ack[24:], []byte{192, 0, 2, 254})
	reused := bytes.Clone(ack)
	reused[33], reused[7], reused[259] = 2, 2, 3
	nak := dhcpv4Message(2, 2, 53, 1, 6, 255)
	frames := [][]byte{
		buildEthernetIPv4UDPFrame(server, broadcast, 53, 53, make([]byte, 1400)),
		buildEthernetIPv4UDPFrame([4]byte{}, broadcast, 68, 67, discover),
		buildEthernetIPv4UDPFrame(server, broadcast, 67, 68, offer),
		buildEthernetIPv4UDPFrame([4]byte{}, broadcast, 68, 67, request),
		buildEthernetIPv4UDPFrame(lease, server, 68, 67, renew),
		buildEthernetIPv4UDPFrame(server, [4]byte{192, 0, 2, 254}, 67, 67, ack),
		buildEthernetIPv4UDPFrame(server, broadcast, 67, 68, nak),
		buildEthernetIPv4UDPFrame(server, broadcast, 67, 68, reused),
	}
	var sink bytes.Buffer
	opts := PCAPNGWriterOptions{LinkType: LinkTypeEthernet}
	w, err := NewPCAPNGWriter(&sink, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.AddInterface(opts); err != nil {
		t.Fatal(err)
	}
	for i, p := range frames {
		if err = w.WritePacket(PacketRecord{InterfaceID: uint32(i % 2), TimestampNs: int64(i+1) * 1e9}, p); err != nil {
			t.Fatal(err)
		}
	}
	raw := sink.Bytes()
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	records, err := c.DHCPv4(raw)
	if err != nil || len(records) != 7 {
		t.Fatalf("slice = %+v, %v", records, err)
	}
	r := bytes.NewReader(raw)
	c, err = NewFromReaderAt(r, int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.DHCPv4FromReaderAt(r)
	if err != nil || !reflect.DeepEqual(got, records) {
		t.Fatalf("ReaderAt = %+v, %v", got, err)
	}
	for i, typ := range []DHCPv4MessageType{DHCPv4Discover, DHCPv4Offer, DHCPv4Request, DHCPv4Request, DHCPv4ACK, DHCPv4NAK, DHCPv4ACK} {
		v := got[i]
		if v.MessageType != typ || v.PacketIndex != i+1 || v.TimestampNs != int64(i+2)*1e9 || v.InterfaceID != uint32((i+1)%2) {
			t.Fatalf("record %d = %+v", i, v)
		}
	}
	a := netip.AddrFrom4(lease)
	if got[1].YourAddr != a || got[2].YourAddr.IsValid() || got[2].RequestedAddr != a || got[3].ClientAddr != a || got[3].RequestedAddr.IsValid() {
		t.Fatalf("offer/request/renew = %+v", got[1:4])
	}
	v := got[4]
	if v.YourAddr != a || v.NextServerAddr.String() != "192.0.2.12" || v.RelayAddr.String() != "192.0.2.254" || v.ServerIdentifier != netip.AddrFrom4(server) || !v.HasLease || v.LeaseSeconds != 3600 || !v.HasHostname || v.Hostname != "iot" || !bytes.Equal(v.ClientIdentifier, []byte{0, 1, 2}) || v.ClientHardwareAddr.String() != "02:00:00:00:00:01" || v.TransactionID != 0x12340001 || v.HardwareType != 1 {
		t.Fatalf("relayed ACK = %+v", v)
	}
	if v = got[6]; v.YourAddr != a || v.ClientHardwareAddr[5] != 2 || bytes.Equal(v.ClientIdentifier, got[4].ClientIdentifier) || v.TransactionID != 0x12340002 {
		t.Fatalf("reused ACK = %+v", v)
	}
	if got[5].YourAddr.IsValid() || got[5].HasLease || got[5].HasHostname || got[5].ClientIdentifier != nil {
		t.Fatalf("NAK = %+v", got[5])
	}
}

func TestDHCPv4OptionBounds(t *testing.T) {
	msg := dhcpv4Message(2, 1, 0, 52, 1, 3, 53, 1, 5, 255, 190)
	msg[2] = 0
	copy(msg[108:], []byte{12, 0, 51, 4, 0, 0, 0, 0, 255})
	copy(msg[44:], []byte{12, 1, 'b', 61, 2, 0, 1, 255})
	r, ok := parseDHCPv4(msg)
	if !ok || r.ClientHardwareAddr != nil || !r.HasHostname || r.Hostname != "" || !r.HasLease || r.LeaseSeconds != 0 || !bytes.Equal(r.ClientIdentifier, []byte{0, 1}) {
		t.Fatalf("overload = %+v, %v", r, ok)
	}
	tests := map[string][]byte{
		"short": msg[:239], "missing end": dhcpv4Message(1, 1, 53, 1, 1), "missing type": dhcpv4Message(1, 1, 255),
		"truncated option": dhcpv4Message(1, 1, 53, 1, 1, 12, 5, 'x'), "missing length": dhcpv4Message(1, 1, 53, 1, 1, 12),
		"address length": dhcpv4Message(1, 1, 53, 1, 1, 50, 3, 0, 0, 0, 255), "type length": dhcpv4Message(1, 1, 53, 0, 255),
		"lease length": dhcpv4Message(1, 1, 53, 1, 1, 51, 0, 255), "client id length": dhcpv4Message(1, 1, 53, 1, 1, 61, 1, 0, 255),
		"overload flags": dhcpv4Message(1, 1, 53, 1, 1, 52, 1, 4, 255), "missing overloaded end": dhcpv4Message(1, 1, 53, 1, 1, 52, 1, 1, 255),
		"wrong operation": dhcpv4Message(1, 1, 53, 1, 5, 255), "oversized": append(bytes.Clone(msg), make([]byte, maxDHCPv4Bytes-len(msg)+1)...),
	}
	for name, off := range map[string]int{"cookie": 236, "hardware length": 2, "hardware type": 1, "operation": 0} {
		p := dhcpv4Message(1, 1, 53, 1, 1, 255)
		p[off] = 0
		if off == 2 {
			p[off] = 17
		}
		tests[name] = p
	}
	options := append([]byte{53, 1, 1}, bytes.Repeat([]byte{200, 0}, maxDHCPv4Options-1)...)
	if _, ok := parseDHCPv4(dhcpv4Message(1, 1, append(options, 255)...)); !ok {
		t.Fatal("at option limit")
	}
	tests["too many options"] = dhcpv4Message(1, 1, append(options, 200, 0, 255)...)
	for name, p := range tests {
		t.Run(name, func(t *testing.T) {
			if _, ok := parseDHCPv4(p); ok {
				t.Fatal("accepted malformed message")
			}
		})
	}
}

func TestDHCPv4ReaderBounds(t *testing.T) {
	msg := dhcpv4Message(1, 1, 53, 1, 1, 255)
	frame := func(port uint16, p []byte) []byte {
		return buildEthernetIPv4UDPFrame([4]byte{}, [4]byte{255, 255, 255, 255}, 68, port, p)
	}
	valid := frame(67, msg)
	fragment := bytes.Clone(valid)
	fragment[20] = 0x20
	frames := [][]byte{frame(10000, make([]byte, 32000)), frame(67, make([]byte, maxDHCPv4Bytes+1)), valid[:len(valid)-1], fragment, valid}
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	r := &measuredReaderAt{Reader: bytes.NewReader(raw)}
	a, err := c.DHCPv4FromReaderAt(r)
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.DHCPv4(raw)
	if err != nil || len(a) != 1 || a[0].PacketIndex != 4 || !reflect.DeepEqual(a, b) || r.bytesRead > 2048 {
		t.Fatalf("records=%+v, slice=%+v, read %d bytes, err %v", a, b, r.bytesRead, err)
	}
	frames = make([][]byte, maxDHCPv4Records+1)
	for i := range frames {
		frames[i] = valid
	}
	raw = buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
	c, err = New(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, reader := range []bool{false, true} {
		if reader {
			a, err = c.DHCPv4FromReaderAt(bytes.NewReader(raw))
		} else {
			a, err = c.DHCPv4(raw)
		}
		if a != nil || !errors.Is(err, ErrDHCPv4Limit) {
			t.Fatalf("reader %v: got %d, %v", reader, len(a), err)
		}
	}
}

func ExampleCapture_DHCPv4() {
	ack := dhcpv4Message(2, 1, 53, 1, 5, 51, 4, 0, 0, 14, 16, 255)
	copy(ack[16:], []byte{192, 0, 2, 10})
	frame := buildEthernetIPv4UDPFrame([4]byte{192, 0, 2, 1}, [4]byte{255, 255, 255, 255}, 67, 68, ack)
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{frame})
	c, err := New(raw)
	if err != nil {
		panic(err)
	}
	records, err := c.DHCPv4(raw)
	if err != nil {
		panic(err)
	}
	for _, r := range records {
		if r.MessageType == DHCPv4ACK && r.YourAddr.IsValid() {
			fmt.Println(r.ClientHardwareAddr, r.YourAddr, r.LeaseSeconds)
		}
	}
	// Output: 02:00:00:00:00:01 192.0.2.10 3600
}
