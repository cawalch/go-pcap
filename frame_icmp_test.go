package pcap

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"testing"
)

func icmpErrorFrame(version, typ uint8, quote []byte) []byte {
	body := append([]byte{typ, 0, 0, 0, 0, 0, 0, 0}, quote...)
	if version == 4 {
		return ipipIPv4(IPProtoICMP, body)
	}
	return ipipIPv6(IPProtoIPv6ICMP, body)
}

func TestICMPEmbeddedPacketFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/framing/icmp-errors.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	capture, packets := readWrittenPackets(t, raw)
	r := bytes.NewReader(raw)
	file, err := NewFromReaderAt(r, r.Size())
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		outerSrc, outerDst string
		innerSrc, innerDst string
		srcPort, dstPort   uint16
		version, protocol  uint8
	}{
		{"192.0.2.1", "198.51.100.10", "198.51.100.10", "203.0.113.20", 40000, 8080, 4, IPProtoICMP},
		{"2001:db8::1", "2001:db8:1::10", "2001:db8:1::10", "2001:db8:1::20", 41000, 8443, 6, IPProtoIPv6ICMP},
	}
	if len(packets) != len(want) {
		t.Fatalf("got %d packets, want %d", len(packets), len(want))
	}
	flows := checkReaderParity(t, raw, capture.Flows, file.FlowsFromReaderAt)
	if len(flows) != len(want) {
		t.Fatalf("flows = %+v", flows)
	}
	for i, pkt := range packets {
		sliceData, err := capture.PacketPayload(raw, pkt)
		if err != nil {
			t.Fatal(err)
		}
		readerData, err := file.PacketPayloadFromReaderAt(r, pkt)
		if err != nil {
			t.Fatal(err)
		}
		expected := want[i]
		for _, data := range [][]byte{sliceData, readerData} {
			f, err := DecodeFrame(data, pkt.LinkType)
			if err != nil {
				t.Fatal(err)
			}
			quote, ok := f.ICMPEmbeddedPacket(data)
			if !ok || !quote.HasPorts || quote.IPVersion != expected.version || quote.IPProtocol != IPProtoTCP ||
				quote.SrcAddr.String() != expected.innerSrc || quote.DstAddr.String() != expected.innerDst ||
				quote.SrcPort != expected.srcPort || quote.DstPort != expected.dstPort {
				t.Fatalf("packet %d quote = %+v, %v", i, quote, ok)
			}
			if f.SrcAddr.String() != expected.outerSrc || f.DstAddr.String() != expected.outerDst ||
				f.IPProtocol != expected.protocol || f.SrcPort != 0 || f.DstPort != 0 {
				t.Fatalf("packet %d outer frame = %+v", i, f)
			}
		}
		flow := flows[i]
		if flow.SrcAddr.String() != expected.outerSrc || flow.DstAddr.String() != expected.outerDst ||
			flow.Protocol != expected.protocol || !flow.PortsUnavailable || flow.CommunityID(0) != "" {
			t.Fatalf("flow %d = %+v", i, flow)
		}
	}
}

func TestICMPEmbeddedPacketTypes(t *testing.T) {
	tcp := framingIPv4TCP(nil)[20:]
	for _, tc := range []struct {
		version uint8
		quote   []byte
		types   []uint8
		echo    uint8
	}{
		{4, ipipIPv4(IPProtoTCP, tcp)[:28], []uint8{3, 4, 11, 12}, 8},
		{6, ipipIPv6(IPProtoTCP, tcp)[:44], []uint8{1, 2, 3}, 128},
	} {
		for _, typ := range tc.types {
			wire := icmpErrorFrame(tc.version, typ, tc.quote)
			f, err := DecodeFrame(wire, LinkTypeRaw)
			quote, ok := f.ICMPEmbeddedPacket(wire)
			if err != nil || !ok || !quote.HasPorts || quote.SrcPort != 5000 || quote.DstPort != 443 {
				t.Fatalf("IPv%d type %d quote = %+v, %v, %v", tc.version, typ, quote, ok, err)
			}
		}
		wire := icmpErrorFrame(tc.version, tc.echo, tc.quote)
		f, err := DecodeFrame(wire, LinkTypeRaw)
		if _, ok := f.ICMPEmbeddedPacket(wire); err != nil || ok {
			t.Fatalf("IPv%d echo decoded as an error (%v)", tc.version, err)
		}
	}
}

func TestICMPEmbeddedPacketBounds(t *testing.T) {
	tcp := framingIPv4TCP(nil)[20:]
	ip4 := ipipIPv4(IPProtoTCP, tcp)
	short := bytes.Clone(ip4)
	binary.BigEndian.PutUint16(short[2:4], 20)
	fragment := bytes.Clone(ip4)
	binary.BigEndian.PutUint16(fragment[6:8], 1)
	invalidIHL := bytes.Clone(ip4)
	invalidIHL[0] = 0x44
	for _, tc := range []struct {
		name      string
		quote     []byte
		wantValid bool
	}{
		{"short fixed header", ip4[:19], false},
		{"invalid IHL", invalidIHL, false},
		{"three port bytes", ip4[:23], true},
		{"ports beyond declared IPv4 length", short, true},
		{"non-initial IPv4 fragment", fragment, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := icmpErrorFrame(4, 3, tc.quote)
			f, err := DecodeFrame(wire, LinkTypeRaw)
			quote, ok := f.ICMPEmbeddedPacket(wire)
			if err != nil || ok != tc.wantValid || quote.HasPorts {
				t.Fatalf("quote = %+v, %v, %v", quote, ok, err)
			}
			if _, ok := f.ICMPEmbeddedPacket(wire[:len(wire)-1]); ok {
				t.Fatal("decoded bytes shorter than the recorded ICMP payload span")
			}
		})
	}

	// Bytes after the multipart length field must never be read as ports.
	v4 := icmpErrorFrame(4, 3, ip4)
	v4[25] = 5 // 20-byte quote.
	v6 := icmpErrorFrame(6, 1, ipipIPv6(IPProtoTCP, tcp))
	v6[44] = 5 // 40-byte quote.
	for _, wire := range [][]byte{v4, v6} {
		f, err := DecodeFrame(wire, LinkTypeRaw)
		quote, ok := f.ICMPEmbeddedPacket(wire)
		if err != nil || !ok || quote.HasPorts {
			t.Fatalf("length-bounded quote = %+v, %v, %v", quote, ok, err)
		}
	}
}

func TestICMPEmbeddedPacketIPv6Extensions(t *testing.T) {
	tcp := framingIPv4TCP(nil)[20:]
	hop := []byte{IPProtoTCP, 0, 0, 0, 0, 0, 0, 0}
	udp := []byte{IPProtoUDP, 0, 0, 0, 0, 0, 0, 0, 0, 53, 0x15, 0xb3}
	fragment := []byte{IPProtoTCP, 0, 0, 8, 0, 0, 0, 1}
	deep := make([]byte, (MaxIPv6ExtHeaders+1)*8)
	deep[len(deep)-8] = IPProtoTCP
	for _, tc := range []struct {
		name      string
		proto     uint8
		payload   []byte
		wantProto uint8
		wantPorts bool
	}{
		{"hop-by-hop and four port bytes", IPProtoHopByHop, append(bytes.Clone(hop), tcp[:4]...), IPProtoTCP, true},
		{"destination options and UDP ports", IPProtoIPv6Opts, udp, IPProtoUDP, true},
		{"truncated extension", IPProtoHopByHop, hop[:7], IPProtoHopByHop, false},
		{"non-initial fragment", IPProtoIPv6Frag, append(fragment, tcp...), IPProtoTCP, false},
		{"extension limit", IPProtoHopByHop, append(deep, tcp...), IPProtoHopByHop, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := icmpErrorFrame(6, 3, ipipIPv6(tc.proto, tc.payload))
			f, err := DecodeFrame(wire, LinkTypeRaw)
			quote, ok := f.ICMPEmbeddedPacket(wire)
			if err != nil || !ok || quote.IPProtocol != tc.wantProto || quote.HasPorts != tc.wantPorts {
				t.Fatalf("quote = %+v, %v, %v", quote, ok, err)
			}
		})
	}
}

func BenchmarkFrameICMPEmbeddedPacket(b *testing.B) {
	wire := icmpErrorFrame(4, 3, framingIPv4TCP(nil)[:28])
	f, err := DecodeFrame(wire, LinkTypeRaw)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if quote, ok := f.ICMPEmbeddedPacket(wire); !ok || !quote.HasPorts {
			b.Fatal(quote, ok)
		}
	}
}

func ExampleFrame_ICMPEmbeddedPacket() {
	raw, err := os.ReadFile("testdata/framing/icmp-errors.pcapng")
	if err != nil {
		panic(err)
	}
	c, err := New(raw)
	if err != nil {
		panic(err)
	}
	for pkt, err := range c.PacketSeq(raw) {
		if err != nil {
			panic(err)
		}
		data, err := c.PacketPayload(raw, pkt)
		if err != nil {
			panic(err)
		}
		f, err := DecodeFrame(data, pkt.LinkType)
		if err != nil {
			panic(err)
		}
		if quote, ok := f.ICMPEmbeddedPacket(data); ok && quote.HasPorts && quote.IPProtocol == IPProtoTCP {
			fmt.Printf("ICMP from %s quotes TCP %d → %d\n", f.SrcAddr, quote.SrcPort, quote.DstPort)
		}
	}
	// Output:
	// ICMP from 192.0.2.1 quotes TCP 40000 → 8080
	// ICMP from 2001:db8::1 quotes TCP 41000 → 8443
}
