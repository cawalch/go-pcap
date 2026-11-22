package pcap

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
)

// CommunityID returns the direction-independent Community ID v1 for an IPv4
// or IPv6 TCP or UDP flow. Use the same seed as the correlating tool (usually
// zero). It returns "" for missing endpoints, mixed address families,
// unsupported protocols, or captures without observed transport ports.
func (f *FlowSummary) CommunityID(seed uint16) string {
	if f == nil || f.PortsUnavailable || (f.Protocol != IPProtoTCP && f.Protocol != IPProtoUDP) ||
		!f.SrcAddr.IsValid() || f.SrcAddr.BitLen() != f.DstAddr.BitLen() {
		return ""
	}
	// Zones identify local interfaces and are absent from the wire tuple.
	k, _ := makeCanonicalFlowKey(f.Protocol, f.SrcAddr.WithZone(""), f.SrcPort, f.DstAddr.WithZone(""), f.DstPort)
	var tuple [40]byte // seed + two IPv6 addresses + protocol + padding + ports
	b := binary.BigEndian.AppendUint16(tuple[:0], seed)
	b = append(b, k.addrA.AsSlice()...)
	b = append(b, k.addrB.AsSlice()...)
	b = append(b, k.proto, 0)
	b = binary.BigEndian.AppendUint16(b, k.portA)
	b = binary.BigEndian.AppendUint16(b, k.portB)
	sum := sha1.Sum(b) // Community ID v1 specifies SHA-1.
	var out [30]byte
	copy(out[:], "1:")
	base64.StdEncoding.Encode(out[2:], sum[:])
	return string(out[:])
}
