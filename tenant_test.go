package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"testing"
)

func TestTenantVXLANIdentity(t *testing.T) {
	a, b, c := [4]byte{203, 0, 113, 1}, [4]byte{203, 0, 113, 2}, [4]byte{203, 0, 113, 3}
	inner := buildEthernetIPv4UDPFrame([4]byte{192, 0, 2, 1}, [4]byte{198, 51, 100, 1}, 53000, 53, make([]byte, 512))
	tag := func(frame []byte) []byte {
		// Insert VLAN 42 before the original Ethernet type.
		return slices.Concat(frame[:12], []byte{0x81, 0, 0, 42}, frame[12:])
	}
	encap := func(src, dst [4]byte, frame []byte) []byte {
		return buildEthernetIPv4UDPFrame(src, dst, 43000, 4789, slices.Concat([]byte{8, 0, 0, 0, 0, 0, 0, 0}, frame))
	}
	tunnel := encap(a, b, inner)
	double := tag(encap(a, b, tag(inner)))
	raw := buildPCAPNGFixture(binary.LittleEndian, nil, [][]byte{
		tunnel, encap(b, a, inner), encap(a, c, inner), encap(a, b, tag(inner)), tag(tunnel), double,
		tunnel[:45], // Outer IP and UDP are present. The VNI is unobserved.
	})
	capture, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	vx := VXLANScope{EndpointA: netip.AddrFrom4(a), EndpointB: netip.AddrFrom4(b)}
	scopes := []struct {
		scope TenantScope
		count int
	}{
		{TenantScope{}, 0},
		{TenantScope{VXLAN: &vx}, 2},
		{TenantScope{VLANs: []uint16{42}, VXLAN: &vx}, 1},
		{TenantScope{VLANs: []uint16{42}, VXLAN: &VXLANScope{
			EndpointA: vx.EndpointA, EndpointB: vx.EndpointB, InnerVLANs: []uint16{42},
		}}, 1},
	}
	for i, tc := range scopes {
		scope := tc.scope
		if scope.VXLAN != nil {
			original := *scope.VXLAN
			scope.VXLAN = &original
		}
		view, err := capture.SelectTenant(scope)
		if err != nil {
			t.Fatalf("scope %d: %v", i, err)
		}
		// Caller mutations must not change the view.
		if len(scope.VLANs) > 0 {
			scope.VLANs[0] = 999
		}
		if scope.VXLAN != nil {
			scope.VXLAN.VNI = 999
			if len(scope.VXLAN.InnerVLANs) > 0 {
				scope.VXLAN.InnerVLANs[0] = 999
			}
		}
		flows, err := view.Flows(raw)
		fromReader, readerErr := view.FlowsFromReaderAt(bytes.NewReader(raw))
		if err != nil || readerErr != nil || !slices.Equal(flows, fromReader) {
			t.Fatalf("scope %d: slice=%+v reader=%+v errors=%v, %v", i, flows, fromReader, err, readerErr)
		}
		if tc.count == 0 && len(flows) != 0 ||
			tc.count > 0 && (len(flows) != 1 || flows[0].PacketCount != tc.count || flows[0].ClientBytes != uint64(tc.count*512)) {
			t.Fatalf("scope %d: flows=%+v, want %d packets", i, flows, tc.count)
		}
	}

	for _, invalid := range []TenantScope{
		{InterfaceID: 1},
		{VLANs: []uint16{4096}},
		{VLANs: []uint16{1, 2, 3}, VXLAN: &vx},
		{VXLAN: &VXLANScope{EndpointA: vx.EndpointA}},
		{VXLAN: &VXLANScope{VNI: 1 << 24, EndpointA: vx.EndpointA, EndpointB: vx.EndpointB}},
	} {
		if _, err := capture.SelectTenant(invalid); !errors.Is(err, ErrInvalidTenantScope) {
			t.Errorf("scope %+v: got %v, want ErrInvalidTenantScope", invalid, err)
		}
	}
}

func TestTenantReaderAtSkipsOtherInterface(t *testing.T) {
	var buffer bytes.Buffer
	w, err := NewPCAPNGWriter(&buffer, PCAPNGWriterOptions{LinkType: LinkTypeEthernet})
	if err != nil {
		t.Fatal(err)
	}
	other, err := w.AddInterface(PCAPNGWriterOptions{LinkType: LinkTypeEthernet})
	if err != nil {
		t.Fatal(err)
	}
	a, b := [4]byte{192, 0, 2, 1}, [4]byte{198, 51, 100, 1}
	dns := buildDNSQueryResponsePacket()
	dns = append(dns, make([]byte, 512-len(dns))...)
	for _, packet := range []struct {
		iface uint32
		frame []byte
	}{
		{other, buildEthernetIPv4TCPFrame(a, b, 53001, 53, 1, 0, TCPFlagACK, make([]byte, 512))},
		{0, buildEthernetIPv4UDPFrame(b, a, 53, 53000, dns)},
		{0, buildEthernetIPv4TCPFrame(a, b, 53000, 443, 1, 0, TCPFlagACK, buildTLS13ClientHelloRecord("scoped.example", "h2"))},
	} {
		if err := w.WritePacket(PacketRecord{InterfaceID: packet.iface}, packet.frame); err != nil {
			t.Fatal(err)
		}
	}
	raw := buffer.Bytes()
	capture, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	view, err := capture.SelectTenant(TenantScope{})
	if err != nil {
		t.Fatal(err)
	}
	packets, err := capture.Packets(raw)
	if err != nil {
		t.Fatal(err)
	}
	r := tenantRestrictedReader{ReaderAt: bytes.NewReader(raw), packet: packets[0]}
	flows, err := view.FlowsFromReaderAt(r)
	if err != nil || len(flows) != 2 || flows[0].PacketCount != 1 || flows[0].ClientBytes != 512 {
		t.Fatalf("flows=%+v error=%v", flows, err)
	}
	if _, err := view.DNSFromReaderAt(r); err != nil {
		t.Fatal(err)
	}
	transactions, err := view.DNSTransactionsFromReaderAt(r)
	if err != nil || len(transactions) != 1 || transactions[0].Pairing != DNSNoQueryObserved ||
		transactions[0].Reply == nil || transactions[0].Reply.PacketIndex != 1 || transactions[0].Reply.FlowIndex != 0 {
		t.Fatalf("DNS=%+v error=%v", transactions, err)
	}
	hellos, err := view.TLSHandshakeEvidenceFromReaderAt(r, nil)
	if err != nil || len(hellos) != 1 || hellos[0].OpeningPacket != 2 || hellos[0].FlowIndex != 1 {
		t.Fatalf("TLS=%+v error=%v", hellos, err)
	}
	mixedDNS, err := capture.DNSTransactions(raw)
	if err != nil || len(mixedDNS) != 1 || mixedDNS[0].Reply == nil || mixedDNS[0].Reply.FlowIndex != 1 {
		t.Fatalf("unscoped DNS=%+v error=%v", mixedDNS, err)
	}
	mixedTLS, err := capture.TLSHandshakeEvidence(raw, nil)
	if err != nil || len(mixedTLS) != 1 || mixedTLS[0].FlowIndex != 2 {
		t.Fatalf("unscoped TLS=%+v error=%v", mixedTLS, err)
	}
}

func TestTenantDNSTLSEvidence(t *testing.T) {
	file, err := os.Open("testdata/framing/tenant-scope.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	raw, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewFromReaderAt(file, int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	packets, err := c.Packets(raw)
	if err != nil || len(packets) != 77 {
		t.Fatalf("fixture has %d packets: %v", len(packets), err)
	}

	a, b := netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.113.2")
	for i, tc := range []struct {
		name  string
		scope TenantScope
	}{
		{"plain", TenantScope{}},
		{"vlan11", TenantScope{VLANs: []uint16{100, 11}}},
		{"vlan12", TenantScope{VLANs: []uint16{100, 12}}},
		{"vni201", TenantScope{VXLAN: &VXLANScope{VNI: 201, EndpointA: a, EndpointB: b}}},
		{"vni202", TenantScope{VXLAN: &VXLANScope{VNI: 202, EndpointA: a, EndpointB: b}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			view, err := c.SelectTenant(tc.scope)
			if err != nil {
				t.Fatal(err)
			}
			dns := checkReaderParity(t, raw, view.DNSTransactions, view.DNSTransactionsFromReaderAt)
			tls := checkReaderParity(t, raw,
				func(data []byte) ([]TLSHandshakeEvidence, error) { return view.TLSHandshakeEvidence(data, nil) },
				func(r io.ReaderAt) ([]TLSHandshakeEvidence, error) {
					return view.TLSHandshakeEvidenceFromReaderAt(r, nil)
				},
			)
			seekDNS, err := view.DNSTransactionsFromReaderAt(file)
			if err != nil || !reflect.DeepEqual(seekDNS, dns) {
				t.Fatalf("file DNS = %+v, %v; slice = %+v", seekDNS, err, dns)
			}
			seekTLS, err := view.TLSHandshakeEvidenceFromReaderAt(file, nil)
			if err != nil || !reflect.DeepEqual(seekTLS, tls) {
				t.Fatalf("file TLS = %+v, %v; slice = %+v", seekTLS, err, tls)
			}

			name := tc.name + ".mirror.example"
			if len(dns) != 1 || dns[0].Query == nil || dns[0].Query.PacketIndex != 30+i ||
				len(dns[0].Query.Message.Questions) != 1 || dns[0].Query.Message.Questions[0].Name != name {
				t.Fatalf("DNS query = %+v", dns)
			}
			if len(tls) != 1 || tls[0].OpeningPacket != 43+i || tls[0].Handshake.ClientHello.SNI != name ||
				!slices.Equal(tls[0].ClientHello.PacketIndices, []int{58 + i, 63 + i}) {
				t.Fatalf("TLS opening and ClientHello = %+v", tls)
			}
			if i < 4 {
				reply := dns[0].Reply
				if dns[0].Pairing != DNSPaired || reply == nil || reply.PacketIndex != 39+i ||
					reply.FlowIndex != dns[0].Query.FlowIndex || len(reply.Message.Answers) != 1 ||
					reply.Message.Answers[0].Address != netip.AddrFrom4([4]byte{198, 51, 100, byte(21 + i)}) {
					t.Fatalf("DNS reply = %+v", dns)
				}
				if !tls[0].Handshake.HasServerHello || !slices.Equal(tls[0].ServerHello.PacketIndices, []int{73 + i}) {
					t.Fatalf("TLS ServerHello = %+v", tls)
				}
			} else if dns[0].Pairing != DNSNoReplyObserved || dns[0].Reply != nil ||
				tls[0].Handshake.HasServerHello || len(tls[0].ServerHello.PacketIndices) != 0 {
				t.Fatalf("expected missing server direction, DNS = %+v, TLS = %+v", dns, tls)
			}

			flows, err := view.Flows(raw)
			if err != nil || len(flows) != 3 || dns[0].Query.FlowIndex != 1 || flows[1].Protocol != IPProtoUDP ||
				tls[0].FlowIndex != 2 || flows[2].Protocol != IPProtoTCP || flows[2].DstPort != 443 {
				t.Fatalf("scoped flows = %+v, %v", flows, err)
			}
			// Select the expected packet positions without using the selector.
			indices := []int{i, 5 + i, 10 + i, 15 + i, 20 + i, 25 + i, 30 + i}
			if i < 4 {
				indices = append(indices, 35+i, 39+i)
			}
			indices = append(indices, 43+i, 48+i, 53+i, 58+i, 63+i, 68+i)
			if i < 4 {
				indices = append(indices, 73+i)
			}
			checkTenantIsolatedEvidence(t, c, raw, packets, indices, dns, tls)
		})
	}
}

func checkTenantIsolatedEvidence(t *testing.T, original *Capture, raw []byte, packets []PacketRecord, indices []int,
	wantDNS []DNSTransaction, wantTLS []TLSHandshakeEvidence) {
	t.Helper()
	var subset bytes.Buffer
	w, err := NewPCAPNGWriter(&subset, PCAPNGWriterOptions{LinkType: LinkTypeEthernet})
	if err != nil {
		t.Fatal(err)
	}
	for _, index := range indices {
		pkt := packets[index]
		frame, err := original.PacketPayload(raw, pkt)
		if err != nil {
			t.Fatal(err)
		}
		if err := w.WritePacket(pkt, frame); err != nil {
			t.Fatal(err)
		}
	}
	isolated := subset.Bytes()
	c, err := New(isolated)
	if err != nil {
		t.Fatal(err)
	}
	dns := checkReaderParity(t, isolated, c.DNSTransactions, c.DNSTransactionsFromReaderAt)
	for _, row := range dns {
		for _, record := range []*DNSRecord{row.Query, row.Reply} {
			if record != nil {
				record.PacketIndex = indices[record.PacketIndex]
			}
		}
	}
	if !reflect.DeepEqual(dns, wantDNS) {
		t.Fatalf("isolated DNS = %+v; scoped = %+v", dns, wantDNS)
	}
	tls := checkReaderParity(t, isolated,
		func(data []byte) ([]TLSHandshakeEvidence, error) { return c.TLSHandshakeEvidence(data, nil) },
		func(r io.ReaderAt) ([]TLSHandshakeEvidence, error) { return c.TLSHandshakeEvidenceFromReaderAt(r, nil) },
	)
	for i := range tls {
		tls[i].OpeningPacket = indices[tls[i].OpeningPacket]
		for _, packetIndices := range [][]int{tls[i].ClientHello.PacketIndices, tls[i].ServerHello.PacketIndices} {
			for j, index := range packetIndices {
				packetIndices[j] = indices[index]
			}
		}
	}
	if !reflect.DeepEqual(tls, wantTLS) {
		t.Fatalf("isolated TLS = %+v; scoped = %+v", tls, wantTLS)
	}
}

type tenantRestrictedReader struct {
	io.ReaderAt
	packet PacketRecord
}

func (r tenantRestrictedReader) ReadAt(p []byte, offset int64) (int, error) {
	start := r.packet.PayloadOffset
	if offset < start+r.packet.PayloadLength && offset+int64(len(p)) > start {
		return 0, errors.New("read outside selected interface")
	}
	return r.ReaderAt.ReadAt(p, offset)
}
