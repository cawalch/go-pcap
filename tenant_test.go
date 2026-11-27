package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
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
	frame := buildEthernetIPv4UDPFrame(a, b, 53000, 53, make([]byte, 512))
	for _, iface := range []uint32{other, 0} {
		if err := w.WritePacket(PacketRecord{InterfaceID: iface}, frame); err != nil {
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
	if err != nil || len(flows) != 1 || flows[0].PacketCount != 1 || flows[0].ClientBytes != 512 {
		t.Fatalf("flows=%+v error=%v", flows, err)
	}
	if _, err := view.DNSFromReaderAt(r); err != nil {
		t.Fatal(err)
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
