package pcap

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

// Build an Ethernet frame carrying the exact tuple from a reference vector.
func communityIDFrame(proto uint8, src, dst netip.Addr, sport, dport uint16) []byte {
	var frame []byte
	if proto == IPProtoTCP {
		frame = buildEthernetIPv4TCPFrame([4]byte{}, [4]byte{}, sport, dport, 1, 0, TCPFlagACK, nil)
	} else {
		frame = buildEthernetIPv4UDPFrame([4]byte{}, [4]byte{}, sport, dport, nil)
	}
	if src.Is4() {
		copy(frame[26:30], src.AsSlice())
		copy(frame[30:34], dst.AsSlice())
		return frame
	}
	ip := make([]byte, 14+40)
	binary.BigEndian.PutUint16(ip[12:14], EtherTypeIPv6)
	ip[14], ip[20], ip[21] = 0x60, proto, 64
	binary.BigEndian.PutUint16(ip[18:20], uint16(len(frame)-34))
	copy(ip[22:38], src.AsSlice())
	copy(ip[38:54], dst.AsSlice())
	return append(ip, frame[34:]...)
}

func TestCommunityID(t *testing.T) {
	// The first three tuples and their reverse directions appear in Corelight's
	// baseline_deflt.json and baseline_seed1.json at community-id-spec@b1fe530.
	// IPv6 UDP edge cases use Corelight's pycommunityid@5748e0c reference.
	for _, tc := range []struct {
		proto        uint8
		src, dst     string
		sport, dport uint16
		want         [2]string
	}{
		{6, "128.232.110.120", "66.35.250.204", 34855, 80, [2]string{"1:LQU9qZlK+B5F3KDmev6m5PMibrg=", "1:3V71V58M3Ksw/yuFALMcW0LAHvc="}},
		{17, "192.168.1.52", "8.8.8.8", 54585, 53, [2]string{"1:d/FP5EW3wiY1vCndhwleRRKHowQ=", "1:Q9We8WO3piVF8yEQBNJF4uiSVrI="}},
		{6, "2001:470:e5bf:dead:4957:2174:e82c:4887", "2607:f8b0:400c:c03::1a", 63943, 25, [2]string{"1:/qFaeAR+gFe1KYjMzVDsMv+wgU4=", "1:eJYTW6AOzFLlSUoESovMjnu7rMw="}},
		{17, "2001:db8::1", "2001:db8::1", 55443, 0, [2]string{"1:6CVX3ZfOvHrwz0tMRlabeZgJPwE=", "1:mWSmVWOAybWdmyxrglIbd+tF7gQ="}},
		{17, "::ffff:192.0.2.1", "::ffff:192.0.2.2", 0, 0, [2]string{"1:oZS6uhdK15KUVuWJ2a0PUoBzuUk=", "1:FMVGW2WBwZFypxE+pqR7J5eAvmo="}},
	} {
		src, dst := netip.MustParseAddr(tc.src), netip.MustParseAddr(tc.dst)
		frames := [][]byte{communityIDFrame(tc.proto, src, dst, tc.sport, tc.dport), communityIDFrame(tc.proto, dst, src, tc.dport, tc.sport)}
		for range 2 {
			for _, raw := range [][]byte{buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames), buildPCAPNGFixture(binary.BigEndian, nil, frames)} {
				for _, f := range singleFlowBothReaders(t, raw) {
					for seed, want := range tc.want {
						if got := f.CommunityID(uint16(seed)); got != want {
							t.Fatalf("%+v seed %d: got %q, want %q", f, seed, got, want)
						}
					}
				}
			}
			frames[0], frames[1] = frames[1], frames[0]
		}
	}
}

func singleFlowBothReaders(t *testing.T, raw []byte) [2]FlowSummary {
	t.Helper()
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	flows, err := c.Flows(raw)
	if err != nil || len(flows) != 1 {
		t.Fatalf("Flows: %d, %v", len(flows), err)
	}
	r := bytes.NewReader(raw)
	cr, err := NewFromReaderAt(r, r.Size())
	if err != nil {
		t.Fatal(err)
	}
	readFlows, err := cr.FlowsFromReaderAt(r)
	if err != nil || len(readFlows) != 1 {
		t.Fatalf("FlowsFromReaderAt: %d, %v", len(readFlows), err)
	}
	return [2]FlowSummary{flows[0], readFlows[0]}
}

func TestCommunityIDIncomplete(t *testing.T) {
	addr := netip.MustParseAddr("127.0.0.1")
	for _, f := range []*FlowSummary{nil, {}, {Protocol: IPProtoTCP, SrcAddr: addr}, {Protocol: IPProtoTCP, SrcAddr: addr, DstAddr: netip.IPv6Loopback()}, {Protocol: IPProtoICMP, SrcAddr: addr, DstAddr: addr}} {
		if got := f.CommunityID(0); got != "" {
			t.Fatal(got)
		}
	}
	full := communityIDFrame(IPProtoUDP, addr, addr, 0, 0)
	for i, frames := range [][][]byte{{full[:34]}, {full[:34], full}, {full, full[:34]}} {
		raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
		for _, f := range singleFlowBothReaders(t, raw) {
			if got := f.CommunityID(0); (got == "") != (i == 0) {
				t.Fatalf("case %d: %q", i, got)
			}
		}
	}
}

func TestCommunityIDIgnoresIPv6Zone(t *testing.T) {
	addr := netip.MustParseAddr("2001:db8::1")
	f := FlowSummary{
		Protocol: IPProtoUDP, SrcAddr: addr.WithZone("a"), DstAddr: addr.WithZone("b"),
		SrcPort: 55443, DstPort: 0,
	}
	if got := f.CommunityID(0); got != "1:6CVX3ZfOvHrwz0tMRlabeZgJPwE=" {
		t.Fatal(got)
	}
}
