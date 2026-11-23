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

func neighborARP(op byte) []byte {
	return []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2, 0, 0, 0, 0, 1, 0x08, 0x06,
		0, 1, 8, 0, 6, 4, 0, op, 2, 0, 0, 0, 0, 1, 192, 0, 2, 1,
		2, 0, 0, 0, 0, 2, 192, 0, 2, 2,
	}
}

func neighborIPv6(typ, flags byte, src, dst, target string, opts ...byte) []byte {
	p := make([]byte, 14+40+24+len(opts))
	p[12], p[13] = 0x86, 0xdd
	ip := p[14:]
	ip[0], ip[6], ip[7] = 0x60, 58, 255
	binary.BigEndian.PutUint16(ip[4:], uint16(len(ip)-40))
	copy(ip[8:], netip.MustParseAddr(src).AsSlice())
	copy(ip[24:], netip.MustParseAddr(dst).AsSlice())
	m := ip[40:]
	m[0], m[4] = typ, flags
	copy(m[8:], netip.MustParseAddr(target).AsSlice())
	copy(m[24:], opts)
	pseudo := append([]byte{}, ip[8:40]...)
	pseudo = binary.BigEndian.AppendUint32(pseudo, uint32(len(m)))
	pseudo = append(pseudo, 0, 0, 0, 58)
	pseudo = append(pseudo, m...)
	if len(pseudo)%2 != 0 {
		pseudo = append(pseudo, 0)
	}
	var sum uint32
	for i := 0; i < len(pseudo); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudo[i:]))
		sum = (sum >> 16) + (sum & 65535)
	}
	binary.BigEndian.PutUint16(m[2:], ^uint16(sum))
	return p
}

func TestNeighborObservations(t *testing.T) {
	arp := neighborARP(1)
	clear(arp[28:32])
	clear(arp[32:38])
	vlan := append(bytes.Clone(arp[:12]), 0x81, 0, 0, 3)
	vlan = append(vlan, arp[12:]...)
	ns := neighborIPv6(135, 0, "fe80::1", "ff02::1:ff00:2", "fe80::2", 1, 1, 2, 0, 0, 0, 0, 1)
	na := neighborIPv6(136, 0xe0, "fe80::2", "fe80::1", "fe80::2", 2, 1, 2, 0, 0, 0, 0, 2)
	probe := neighborIPv6(135, 0, "::", "ff02::1:ff00:2", "fe80::2")
	bare := neighborIPv6(136, 0, "fe80::2", "ff02::1", "fe80::2")
	// Put a long hop-by-hop extension before ICMPv6, beyond the read prefix.
	ext := append(bytes.Clone(na[:54]), make([]byte, 256)...)
	ext[20], ext[54], ext[55] = 0, 58, 31
	ext = append(ext, na[54:]...)
	binary.BigEndian.PutUint16(ext[18:], uint16(len(ext)-54))
	frames := [][]byte{vlan, neighborARP(2), ns, na, na, probe, bare, ext}
	var b bytes.Buffer
	opts := PCAPNGWriterOptions{LinkType: LinkTypeEthernet}
	w, err := NewPCAPNGWriter(&b, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.AddInterface(opts); err != nil {
		t.Fatal(err)
	}
	for i, f := range frames {
		if err = w.WritePacket(PacketRecord{TimestampNs: int64(i+1) * 12345, InterfaceID: uint32(i % 2)}, f); err != nil {
			t.Fatal(err)
		}
	}
	data := b.Bytes()
	c, err := New(data)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := c.Neighbors(data)
	if err != nil || len(rs) != len(frames) {
		t.Fatalf("got %+v, %v", rs, err)
	}
	r := bytes.NewReader(data)
	c, err = NewFromReaderAt(r, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.NeighborsFromReaderAt(r)
	if err != nil || !reflect.DeepEqual(got, rs) {
		t.Fatalf("ReaderAt got %+v, %v", got, err)
	}
	for i, rec := range rs {
		if rec.PacketIndex != i || rec.TimestampNs != int64(i+1)*12345 || rec.InterfaceID != uint32(i%2) {
			t.Fatalf("attribution %+v", rec)
		}
	}
	if a := rs[0]; a.Operation != ARPRequest || !a.SourceAddr.IsUnspecified() || a.TargetAddr.String() != "192.0.2.2" || a.SourceHardwareAddr.String() != "02:00:00:00:00:01" || a.TargetHardwareAddr.String() != "00:00:00:00:00:00" {
		t.Fatalf("probe %+v", a)
	}
	if a := rs[1]; a.Operation != ARPReply || a.SourceAddr.String() != "192.0.2.1" || a.TargetHardwareAddr.String() != "02:00:00:00:00:02" {
		t.Fatalf("reply %+v", a)
	}
	if n := rs[2]; n.Operation != NeighborSolicitation || n.SourceAddr.String() != "fe80::1" || n.TargetAddr.String() != "fe80::2" || n.SourceHardwareAddr.String() != "02:00:00:00:00:01" || n.TargetHardwareAddr != nil {
		t.Fatalf("NS %+v", n)
	}
	for _, i := range []int{3, 4, 7} {
		if n := rs[i]; n.Operation != NeighborAdvertisement || n.TargetAddr.String() != "fe80::2" || n.TargetHardwareAddr.String() != "02:00:00:00:00:02" || n.SourceHardwareAddr != nil || !n.Router || !n.Solicited || !n.Override {
			t.Fatalf("NA %+v", n)
		}
	}
	if !rs[5].SourceAddr.IsUnspecified() || rs[5].SourceHardwareAddr != nil || rs[6].TargetHardwareAddr != nil {
		t.Fatal(rs[5:7])
	}
}

func TestNeighborRejectsMalformed(t *testing.T) {
	nd := func(opts ...byte) []byte { return neighborIPv6(136, 0, "fe80::1", "fe80::2", "fe80::1", opts...) }
	mutate := func(f []byte, offset int, val byte) []byte { f[offset] = val; return f }
	atomic := nd()
	head := append(bytes.Clone(atomic[:54]), 58, 0, 0, 0, 0, 0, 0, 1)
	atomic = append(head, atomic[54:]...)
	atomic[20] = 44
	binary.BigEndian.PutUint16(atomic[18:], uint16(len(atomic)-54))
	tests := map[string][]byte{
		"fragment header":  atomic,
		"multicast source": neighborIPv6(135, 0, "ff02::1", "fe80::2", "fe80::2"),
		"short ARP":        neighborARP(1)[:41], "ARP lengths": mutate(neighborARP(1), 19, 16), "ARP protocol": mutate(neighborARP(1), 16, 0x86),
		"ARP hardware": mutate(neighborARP(1), 15, 2), "ARP operation": neighborARP(3),
		"bad checksum": mutate(nd(), 57, 1), "hop limit": mutate(nd(), 21, 64), "code": mutate(nd(), 55, 1), "short target": nd()[:75],
		"multicast target":       neighborIPv6(135, 0, "fe80::1", "ff02::1", "ff02::1"),
		"multicast solicited":    neighborIPv6(136, 0x40, "fe80::1", "ff02::1", "fe80::1"),
		"DAD with source option": neighborIPv6(135, 0, "::", "ff02::1:ff00:1", "fe80::1", 1, 1, 0, 0, 0, 0, 0, 1),
		"DAD wrong group":        neighborIPv6(135, 0, "::", "ff02::1:ff00:2", "fe80::1"),
		"option length zero":     nd(2, 0), "short option": nd(1), "option overruns": nd(2, 1, 0), "non-Ethernet option": nd(append([]byte{2, 2}, make([]byte, 14)...)...),
		"oversize": nd(make([]byte, maxNeighborIPv6Payload)...),
	}
	for name, p := range tests {
		t.Run(name, func(t *testing.T) {
			raw := buildClassicPCAP(binary.BigEndian, false, LinkTypeEthernet, 65535, [][]byte{p})
			c, err := New(raw)
			if err != nil {
				t.Fatal(err)
			}
			got, err := c.Neighbors(raw)
			if err != nil || len(got) != 0 {
				t.Fatalf("got %+v, %v", got, err)
			}
		})
	}
}

func TestNeighborScanLimits(t *testing.T) {
	frames := make([][]byte, maxNeighborRecords+1)
	for i := range frames {
		frames[i] = neighborARP(1)
	}
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Neighbors(raw)
	if got != nil || !errors.Is(err, ErrNeighborLimit) {
		t.Fatalf("got %d, %v", len(got), err)
	}
	frames = [][]byte{buildEthernetIPv4UDPFrame([4]byte{}, [4]byte{}, 1000, 2000, make([]byte, 32000)), neighborARP(2)}
	raw = buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
	c, err = New(raw)
	if err != nil {
		t.Fatal(err)
	}
	r := &measuredReaderAt{Reader: bytes.NewReader(raw)}
	got, err = c.NeighborsFromReaderAt(r)
	if err != nil || len(got) != 1 || r.bytesRead > 200 {
		t.Fatalf("got %d, read %d, %v", len(got), r.bytesRead, err)
	}
}

func ExampleCapture_Neighbors() {
	data := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{neighborARP(2)})
	c, err := New(data)
	if err != nil {
		panic(err)
	}
	records, err := c.Neighbors(data)
	if err != nil {
		panic(err)
	}
	for _, r := range records {
		if r.Operation == ARPReply {
			fmt.Println(r.PacketIndex, r.SourceAddr, r.SourceHardwareAddr)
		}
	}
	// Output: 0 192.0.2.1 02:00:00:00:00:01
}

func BenchmarkNeighborsMostlyUnrelated(b *testing.B) {
	background := buildEthernetIPv4UDPFrame([4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}, 12000, 12001, make([]byte, 1400))
	arp := neighborARP(2)
	na := neighborIPv6(136, 0x60, "fe80::2", "fe80::1", "fe80::2", 2, 1, 2, 0, 0, 0, 0, 2)
	frames := make([][]byte, 1024)
	for i := range frames {
		frames[i] = background
		switch i % 256 {
		case 0:
			frames[i] = arp
		case 128:
			frames[i] = na
		}
	}
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
	c, err := New(raw)
	if err != nil {
		b.Fatal(err)
	}
	r := &measuredReaderAt{Reader: bytes.NewReader(raw)}
	b.ReportAllocs()
	for b.Loop() {
		records, err := c.NeighborsFromReaderAt(r)
		if err != nil || len(records) != 8 {
			b.Fatalf("got %d, %v", len(records), err)
		}
	}
	b.ReportMetric(float64(r.calls)/float64(b.N), "reads/op")
	b.ReportMetric(float64(r.bytesRead)/float64(b.N), "read-B/op")
}
