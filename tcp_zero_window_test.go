package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"reflect"
	"testing"
)

func TestTCPZeroWindows(t *testing.T) {
	client, server := [4]byte{192, 0, 2, 14}, [4]byte{192, 0, 2, 53}
	udp := buildEthernetIPv4UDPFrame(client, server, 53000, 53, nil)
	tcp := buildEthernetIPv4TCPFrame(client, server, 53000, 53, 5, 11, TCPFlagACK, []byte{2})
	tcp[48], tcp[49] = 0, 0
	reverse := buildEthernetIPv4TCPFrame(server, client, 53, 53000, 11, 5, TCPFlagACK, nil)
	positive := bytes.Clone(reverse)
	reverse[48], reverse[49] = 0, 0
	malformed := bytes.Clone(reverse)
	malformed[46] = 4 << 4
	partial := bytes.Clone(reverse)
	partial[46] = 6 << 4
	fragment := bytes.Clone(tcp)
	fragment[20] |= 0x20
	ip6 := append(bytes.Clone(tcp[:14]), ipipIPv6(IPProtoTCP, tcp[34:])...)
	binary.BigEndian.PutUint16(ip6[12:14], EtherTypeIPv6)
	frames := [][]byte{udp, tcp, positive, reverse, malformed, partial, fragment}
	for _, flags := range []uint8{TCPFlagSYN | TCPFlagACK, TCPFlagFIN | TCPFlagACK, TCPFlagRST | TCPFlagACK, TCPFlagPSH} {
		control := bytes.Clone(reverse)
		control[47] = flags
		frames = append(frames, control)
	}
	frames = append(frames, ip6, tcp)

	var capture bytes.Buffer
	w, err := NewPCAPNGWriter(&capture, PCAPNGWriterOptions{LinkType: LinkTypeEthernet})
	if err != nil {
		t.Fatal(err)
	}
	for i, data := range frames {
		if err := w.WritePacket(PacketRecord{TimestampNs: int64(100 - i), OriginalLen: uint32(len(data))}, data); err != nil {
			t.Fatal(err)
		}
	}
	raw := capture.Bytes()
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	got := checkReaderParity(t, raw, c.TCPZeroWindows, c.TCPZeroWindowsFromReaderAt)
	source := netip.AddrPortFrom(netip.AddrFrom4(client), 53000)
	destination := netip.AddrPortFrom(netip.AddrFrom4(server), 53)
	frame6, err := DecodeFrame(ip6, LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	want := []TCPZeroWindowSummary{
		{1, source, destination, 2, 1, 12, 99, 88},
		{1, destination, source, 1, 3, 3, 97, 97},
		{3, netip.AddrPortFrom(frame6.SrcAddr, 53000), netip.AddrPortFrom(frame6.DstAddr, 53), 1, 11, 11, 89, 89},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("summaries = %+v, want %+v", got, want)
	}
	flows := checkReaderParity(t, raw, c.Flows, c.FlowsFromReaderAt)
	for _, group := range got {
		flow := flows[group.FlowIndex]
		k, _ := makeCanonicalFlowKey(flow.Protocol, flow.SrcAddr, flow.SrcPort, flow.DstAddr, flow.DstPort)
		wantKey, _ := makeCanonicalFlowKey(IPProtoTCP, group.Source.Addr(), group.Source.Port(), group.Destination.Addr(), group.Destination.Port())
		if k != wantKey {
			t.Fatalf("wrong flow at index %d: %+v", group.FlowIndex, flow)
		}
	}
}

func TestTCPZeroWindowsFlowLimit(t *testing.T) {
	frames := make([][]byte, MaxFlows+1)
	for i := range frames {
		src := [4]byte{192, 0, byte(i >> 16), byte(i >> 8)}
		frames[i] = buildEthernetIPv4TCPFrame(src, [4]byte{203, 0, 113, 20}, uint16(i), 53, 5, 11, TCPFlagACK, nil)
	}
	frames[0][48], frames[0][49] = 0, 0
	raw := buildClassicPCAP(binary.LittleEndian, true, LinkTypeEthernet, 65535, frames)
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := c.TCPZeroWindows(raw); got != nil || !errors.Is(err, ErrFlowLimit) {
		t.Fatalf("slice limit = %+v, %v", got, err)
	}
	if got, err := c.TCPZeroWindowsFromReaderAt(bytes.NewReader(raw)); got != nil || !errors.Is(err, ErrFlowLimit) {
		t.Fatalf("ReaderAt limit = %+v, %v", got, err)
	}
}

func BenchmarkTCPZeroWindows(b *testing.B) {
	src, dst := [4]byte{192, 0, 2, 14}, [4]byte{192, 0, 2, 53}
	data := buildEthernetIPv4TCPFrame(src, dst, 53000, 53, 5, 11, TCPFlagACK, make([]byte, 1460))
	zero := buildEthernetIPv4TCPFrame(dst, src, 53, 53000, 11, 5, TCPFlagACK, nil)
	zero[48], zero[49] = 0, 0
	frames := make([][]byte, 512)
	for i := range frames {
		frames[i] = data
		if i%8 == 7 {
			frames[i] = zero
		}
	}
	raw := buildClassicPCAP(binary.LittleEndian, true, LinkTypeEthernet, 65535, frames)
	c, err := New(raw)
	if err != nil {
		b.Fatal(err)
	}
	r := bytes.NewReader(raw)
	b.Run("Slice", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			groups, err := c.TCPZeroWindows(raw)
			if err != nil || len(groups) != 1 {
				b.Fatalf("summaries = %d, %v", len(groups), err)
			}
		}
	})
	b.Run("ReaderAt", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			groups, err := c.TCPZeroWindowsFromReaderAt(r)
			if err != nil || len(groups) != 1 {
				b.Fatalf("summaries = %d, %v", len(groups), err)
			}
		}
	})
}
