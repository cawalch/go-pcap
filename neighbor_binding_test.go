package pcap

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"testing"
)

func neighborARPWithMAC(op, last byte) []byte {
	p := neighborARP(op)
	p[27] = last
	return p
}

func TestNeighborBindingChangesARP(t *testing.T) {
	frames := [][]byte{neighborARPWithMAC(2, 1), neighborARPWithMAC(1, 1)}
	for _, ip := range [][4]byte{{0, 0, 0, 0}, {224, 0, 0, 1}, {255, 255, 255, 255}} {
		for _, last := range []byte{1, 2} {
			p := neighborARPWithMAC(2, last)
			copy(p[28:32], ip[:])
			frames = append(frames, p)
		}
	}
	group, zero := neighborARP(2), neighborARP(2)
	group[22] = 1
	clear(zero[22:28])
	frames = append(frames, group, zero)
	firstChange := len(frames)
	frames = append(frames, neighborARPWithMAC(2, 2), neighborARPWithMAC(2, 2), neighborARPWithMAC(2, 1))
	data := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
	c, err := New(data)
	if err != nil {
		t.Fatal(err)
	}
	changes, err := c.NeighborBindingChanges(data)
	if err != nil || len(changes) != 2 {
		t.Fatalf("got %+v, %v", changes, err)
	}
	first := changes[0]
	if first.Addr.String() != "192.0.2.1" || first.Previous.PacketIndex != 1 || first.Previous.Operation != ARPRequest ||
		first.Previous.HardwareAddr != [6]byte{2, 0, 0, 0, 0, 1} || first.Current.PacketIndex != firstChange ||
		first.Current.Operation != ARPReply || first.Current.HardwareAddr != [6]byte{2, 0, 0, 0, 0, 2} {
		t.Fatalf("first change %+v", first)
	}
	if previous := changes[1].Previous; previous.PacketIndex != firstChange+1 || previous.HardwareAddr != first.Current.HardwareAddr {
		t.Fatalf("previous observation of second change %+v", previous)
	}
	if current := changes[1].Current; current.PacketIndex != firstChange+2 || current.HardwareAddr != first.Previous.HardwareAddr {
		t.Fatalf("second change %+v", current)
	}
}

func TestNeighborBindingChangesIPv6(t *testing.T) {
	frames := [][]byte{
		neighborIPv6(135, 0, "fe80::2", "ff02::1:ff00:3", "fe80::3", 1, 1, 2, 0, 0, 0, 0, 1),
		neighborIPv6(135, 0, "::", "ff02::1:ff00:2", "fe80::2"),
		neighborIPv6(136, 0, "fe80::1", "ff02::1", "fe80::2"),
		neighborIPv6(136, 0x20, "fe80::1", "ff02::1", "fe80::2", 2, 1, 2, 0, 0, 0, 0, 2),
		neighborIPv6(136, 0, "fe80::1", "ff02::1", "fe80::3", 2, 1, 2, 0, 0, 0, 0, 3),
		neighborIPv6(136, 0x40, "fe80::1", "fe80::4", "fe80::2", 2, 1, 2, 0, 0, 0, 0, 3),
	}
	data := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
	c, err := New(data)
	if err != nil {
		t.Fatal(err)
	}
	changes, err := c.NeighborBindingChanges(data)
	if err != nil || len(changes) != 2 {
		t.Fatalf("got %+v, %v", changes, err)
	}
	first, second := changes[0], changes[1]
	if first.Addr.String() != "fe80::2" || first.Previous.PacketIndex != 0 || first.Previous.Operation != NeighborSolicitation ||
		first.Current.PacketIndex != 3 || first.Current.Operation != NeighborAdvertisement || first.Current.Solicited || !first.Current.Override {
		t.Fatalf("first change %+v", first)
	}
	if second.Addr != first.Addr || second.Previous != first.Current || second.Current.PacketIndex != 5 ||
		!second.Current.Solicited || second.Current.Override || second.Current.HardwareAddr != [6]byte{2, 0, 0, 0, 0, 3} {
		t.Fatalf("second change %+v", second)
	}
}

func TestNeighborBindingChangesScope(t *testing.T) {
	tagged := func(last byte, tags ...uint16) []byte {
		arp := neighborARPWithMAC(2, last)
		p := bytes.Clone(arp[:12])
		for _, tag := range tags {
			p = binary.BigEndian.AppendUint16(p, EtherTypeVLAN)
			p = binary.BigEndian.AppendUint16(p, tag)
		}
		return append(p, arp[12:]...)
	}
	cooked := func(ifIndex uint32, last byte) []byte {
		header := make([]byte, 20)
		binary.BigEndian.PutUint16(header, EtherTypeARP)
		binary.BigEndian.PutUint32(header[4:], ifIndex)
		binary.BigEndian.PutUint16(header[8:], 1)
		header[11] = 6
		return append(header, neighborARPWithMAC(2, last)[14:]...)
	}
	var buf bytes.Buffer
	eth := PCAPNGWriterOptions{LinkType: LinkTypeEthernet}
	w, err := NewPCAPNGWriter(&buf, eth)
	if err != nil {
		t.Fatal(err)
	}
	for _, opts := range []PCAPNGWriterOptions{eth, {LinkType: LinkTypeLinuxSLL2}} {
		if _, err := w.AddInterface(opts); err != nil {
			t.Fatal(err)
		}
	}
	for i, p := range []struct {
		interfaceID uint32
		frame       []byte
	}{
		{0, tagged(1)},
		{1, tagged(2)},
		{0, tagged(2, 0)},
		{0, tagged(2, 10, 20)},
		{0, tagged(1, 20, 10)},
		{0, tagged(2, 20, 10|0x8000)},
		{0, tagged(2)},
		{2, cooked(5, 2)},
		{2, cooked(6, 1)},
		{2, cooked(6, 2)},
		{2, cooked(0, 1)},
		{2, cooked(0, 2)},
	} {
		// The decreasing timestamps ensure that capture order takes precedence.
		if err := w.WritePacket(PacketRecord{TimestampNs: int64(120 - i), InterfaceID: p.interfaceID}, p.frame); err != nil {
			t.Fatal(err)
		}
	}
	w, err = NewPCAPNGWriter(&buf, eth)
	if err != nil {
		t.Fatal(err)
	}
	for _, last := range []byte{1, 2} {
		if err := w.WritePacket(PacketRecord{}, tagged(last)); err != nil {
			t.Fatal(err)
		}
	}
	data := buf.Bytes()
	c, err := New(data)
	if err != nil {
		t.Fatal(err)
	}
	changes, err := c.NeighborBindingChanges(data)
	if err != nil || len(changes) != 4 {
		t.Fatalf("got %+v, %v", changes, err)
	}
	if change := changes[0]; change.InterfaceID != 0 || change.LinkType != LinkTypeEthernet || change.VLANCount != 2 ||
		change.VLANTags != [MaxVLANTags]uint16{20, 10} || change.Previous.PacketIndex != 4 || change.Current.PacketIndex != 5 ||
		change.Previous.TimestampNs != 116 || change.Current.TimestampNs != 115 {
		t.Fatalf("tagged change %+v", change)
	}
	if change := changes[1]; change.InterfaceID != 0 || change.VLANCount != 0 || change.Previous.PacketIndex != 0 || change.Current.PacketIndex != 6 {
		t.Fatalf("untagged change %+v", change)
	}
	if change := changes[2]; change.InterfaceID != 2 || change.LinkType != LinkTypeLinuxSLL2 || change.LinkInterfaceIndex != 6 ||
		change.Previous.PacketIndex != 8 || change.Current.PacketIndex != 9 {
		t.Fatalf("cooked change %+v", change)
	}
	if change := changes[3]; change.InterfaceID != 3 || change.Previous.PacketIndex != 12 || change.Current.PacketIndex != 13 {
		t.Fatalf("second section change %+v", change)
	}
	r := bytes.NewReader(data)
	c, err = NewFromReaderAt(r, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.NeighborBindingChangesFromReaderAt(r)
	if err != nil || !slices.Equal(got, changes) {
		t.Fatalf("ReaderAt got %+v, %v", got, err)
	}
}

func ExampleCapture_NeighborBindingChanges() {
	data := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535,
		[][]byte{neighborARPWithMAC(1, 1), neighborARPWithMAC(2, 2)})
	c, err := New(data)
	if err != nil {
		panic(err)
	}
	changes, err := c.NeighborBindingChanges(data)
	if err != nil {
		panic(err)
	}
	for _, change := range changes {
		fmt.Println(change.Addr, net.HardwareAddr(change.Previous.HardwareAddr[:]), net.HardwareAddr(change.Current.HardwareAddr[:]))
	}
	// Output: 192.0.2.1 02:00:00:00:00:01 02:00:00:00:00:02
}

func ExampleCapture_NeighborBindingChangesFromReaderAt() {
	data := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535,
		[][]byte{neighborARPWithMAC(1, 1), neighborARPWithMAC(2, 2)})
	r := bytes.NewReader(data)
	c, err := NewFromReaderAt(r, r.Size())
	if err != nil {
		panic(err)
	}
	changes, err := c.NeighborBindingChangesFromReaderAt(r)
	if err != nil {
		panic(err)
	}
	addr := netip.MustParseAddr("192.0.2.1")
	for _, change := range changes {
		if change.Addr == addr {
			fmt.Println(change.Previous.PacketIndex, change.Current.PacketIndex)
		}
	}
	// Output: 0 1
}
