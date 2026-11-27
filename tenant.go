package pcap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
)

// ErrInvalidTenantScope indicates a selector outside the supported Ethernet,
// VLAN, or VXLAN identity space.
var ErrInvalidTenantScope = errors.New("invalid capture tenant scope")

// TenantScope selects IP traffic on one capture-wide Ethernet interface.
// VLANs lists the outer Ethernet VLAN IDs in wire order. An empty list means
// untagged Ethernet. A nil VXLAN selects native IP on the outer Ethernet.
type TenantScope struct {
	InterfaceID uint32
	VLANs       []uint16
	VXLAN       *VXLANScope
}

// VXLANScope identifies a VXLAN network by its 24-bit VNI and the unordered
// pair of outer IP endpoints. InnerVLANs selects the inner Ethernet VLAN
// stack in wire order. An empty list means untagged inner Ethernet. The
// combined outer and inner VLAN depth cannot exceed MaxFrameLayers - 6.
type VXLANScope struct {
	VNI                  uint32
	EndpointA, EndpointB netip.Addr
	InnerVLANs           []uint16
}

// TenantCapture is a read-only analysis view of one [TenantScope]. It uses
// the original input bytes and packet indices. Flow indices refer to this
// view's first-seen flow order. The view and its capture can be read
// concurrently if the capture and underlying input remain unchanged.
type TenantCapture struct {
	capture *Capture
	scope   TenantScope
}

// SelectTenant creates a view without reading, copying, or renumbering capture
// packets. The view copies the selector. It accepts native Ethernet IP and one
// decoded VXLAN layer on an Ethernet interface. Unknown or incomplete layer
// identities are skipped. The existing scan limits apply on every call.
func (c *Capture) SelectTenant(scope TenantScope) (*TenantCapture, error) {
	if err := c.validateContainer(); err != nil {
		return nil, err
	}
	if uint64(scope.InterfaceID) >= uint64(len(c.Interfaces)) ||
		c.Interfaces[scope.InterfaceID].LinkType != LinkTypeEthernet {
		return nil, fmt.Errorf("%w: interface %d is not Ethernet", ErrInvalidTenantScope, scope.InterfaceID)
	}
	if !validTenantVLANs(scope.VLANs, MaxVLANTags) {
		return nil, ErrInvalidTenantScope
	}
	if vx := scope.VXLAN; vx != nil {
		const maxVXLANVLANs = min(MaxVLANTags, MaxFrameLayers-6)
		if vx.VNI >= 1<<24 || !vx.EndpointA.IsValid() || !vx.EndpointB.IsValid() ||
			vx.EndpointA.Is4() != vx.EndpointB.Is4() || vx.EndpointA.Zone() != "" || vx.EndpointB.Zone() != "" ||
			!validTenantVLANs(vx.InnerVLANs, maxVXLANVLANs-len(scope.VLANs)) {
			return nil, ErrInvalidTenantScope
		}
		identity := *vx
		identity.InnerVLANs = slices.Clone(vx.InnerVLANs)
		scope.VXLAN = &identity
	}
	scope.VLANs = slices.Clone(scope.VLANs)
	return &TenantCapture{capture: c, scope: scope}, nil
}

// Flows reports flows in this view using the original capture bytes.
func (t *TenantCapture) Flows(data []byte) ([]FlowSummary, error) {
	return t.capture.flows(data, &t.scope)
}

// FlowsFromReaderAt reports flows in this view using the original reader.
func (t *TenantCapture) FlowsFromReaderAt(r io.ReaderAt) ([]FlowSummary, error) {
	return t.capture.flowsFromReaderAt(r, &t.scope)
}

// DNS scans DNS messages and reassembles UDP fragments within this view.
func (t *TenantCapture) DNS(data []byte) ([]DNSRecord, error) {
	return scanDNS(ipFrameSource{capture: t.capture, data: data, scope: &t.scope})
}

// DNSFromReaderAt is the bounded reader equivalent of [TenantCapture.DNS].
func (t *TenantCapture) DNSFromReaderAt(r io.ReaderAt) ([]DNSRecord, error) {
	source := t.capture.dnsReaderAt(r)
	source.scope = &t.scope
	return scanDNS(source)
}

// HTTP1Transactions reports cleartext HTTP/1 transactions within this view.
func (t *TenantCapture) HTTP1Transactions(data []byte) ([]HTTP1Transaction, error) {
	return scanHTTP1Transactions(ipFrameSource{capture: t.capture, data: data, scope: &t.scope}, nil)
}

// HTTP1TransactionsFromReaderAt is the bounded reader equivalent of
// [TenantCapture.HTTP1Transactions].
func (t *TenantCapture) HTTP1TransactionsFromReaderAt(r io.ReaderAt) ([]HTTP1Transaction, error) {
	source := t.capture.tcpReaderAt(r)
	source.scope = &t.scope
	return scanHTTP1Transactions(source, nil)
}

func validTenantVLANs(vlans []uint16, limit int) bool {
	if len(vlans) > limit {
		return false
	}
	for _, id := range vlans {
		if id > 4095 {
			return false
		}
	}
	return true
}

func (s TenantScope) matchFrame(frame *Frame, data []byte) bool {
	if frame.Anomalies.TruncatedLayer || frame.Anomalies.VLANDepthExceeded ||
		frame.Anomalies.InvalidIPHeaderLength || frame.Anomalies.IPv6ExtLimitExceeded {
		return false
	}
	outerCount := len(s.VLANs)
	innerCount := 0
	if s.VXLAN != nil {
		innerCount = len(s.VXLAN.InnerVLANs)
	}
	if int(frame.VLANCount) != outerCount+innerCount ||
		!slices.Equal(frame.VLANTags[:outerCount], s.VLANs) {
		return false
	}
	outer, rest, ok := tenantEthernetIP(frame.LayerSlices(), outerCount)
	if !ok {
		return false
	}
	if s.VXLAN == nil {
		return tenantTransport(frame, rest)
	}
	if !slices.Equal(frame.VLANTags[outerCount:frame.VLANCount], s.VXLAN.InnerVLANs) {
		return false
	}
	for len(rest) != 0 && rest[0].Proto == LayerIPv6Ext {
		rest = rest[1:]
	}
	if len(rest) < 2 || rest[0].Proto != LayerUDP || rest[1].Proto != LayerVXLAN || rest[1].Length != 8 {
		return false
	}
	off := int(rest[1].Offset)
	if off < 0 || off > len(data)-8 || binary.BigEndian.Uint32(data[off+4:off+8])>>8 != s.VXLAN.VNI {
		return false
	}
	a, b := tenantIPPair(data, outer)
	forward := a == s.VXLAN.EndpointA && b == s.VXLAN.EndpointB
	reverse := a == s.VXLAN.EndpointB && b == s.VXLAN.EndpointA
	if !forward && !reverse {
		return false
	}
	_, rest, ok = tenantEthernetIP(rest[2:], innerCount)
	return ok && tenantTransport(frame, rest)
}

// Require a decoded Ethernet/IP path at each scope boundary. A VLAN recorded
// inside a tunnel cannot satisfy an expected VLAN on the outer link.
func tenantEthernetIP(layers []LayerSpan, vlans int) (LayerSpan, []LayerSpan, bool) {
	if len(layers) < vlans+2 || layers[0].Proto != LayerEthernet {
		return LayerSpan{}, nil, false
	}
	for _, tag := range layers[1 : 1+vlans] {
		if tag.Proto != LayerVLAN {
			return LayerSpan{}, nil, false
		}
	}
	ip := layers[1+vlans]
	return ip, layers[2+vlans:], ip.Proto == LayerIPv4 || ip.Proto == LayerIPv6
}

func tenantIPPair(data []byte, ip LayerSpan) (netip.Addr, netip.Addr) {
	off := int(ip.Offset)
	if off >= 0 {
		if ip.Proto == LayerIPv4 && off <= len(data)-20 {
			return netip.AddrFrom4([4]byte(data[off+12 : off+16])), netip.AddrFrom4([4]byte(data[off+16 : off+20]))
		}
		if ip.Proto == LayerIPv6 && off <= len(data)-40 {
			return netip.AddrFrom16([16]byte(data[off+8 : off+24])), netip.AddrFrom16([16]byte(data[off+24 : off+40]))
		}
	}
	return netip.Addr{}, netip.Addr{}
}

func tenantTransport(frame *Frame, layers []LayerSpan) bool {
	for _, layer := range layers {
		switch layer.Proto {
		case LayerIPv6Ext, LayerTCP, LayerUDP, LayerICMPv4, LayerICMPv6, LayerESP, LayerIKEv2:
		default:
			return false
		}
	}
	// A tunnel with unavailable inner framing does not establish a native
	// IP scope. Explicitly recognize these cases when no tunnel span fit.
	switch frame.IPProtocol {
	case IPProtoGRE, IPProtoIPv4Encap, IPProtoIPv6:
		return false
	case IPProtoUDP:
		return frame.DstPort != 4789 && frame.DstPort != 6081
	default:
		return true
	}
}
