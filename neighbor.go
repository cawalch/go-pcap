package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
)

// NeighborOperation identifies an ARP operation or ICMPv6 message type.
type NeighborOperation uint16

// Operation values reported by [Capture.Neighbors].
const (
	ARPRequest            NeighborOperation = 1
	ARPReply              NeighborOperation = 2
	NeighborSolicitation  NeighborOperation = 135
	NeighborAdvertisement NeighborOperation = 136
)

// NeighborRecord describes one packet at a capture interface. SourceAddr is
// the ARP sender protocol address or the IPv6 packet source. TargetAddr is the
// ARP or ICMPv6 target. Hardware addresses are copied from the ARP fields or
// corresponding Neighbor Discovery options. Missing options have nil addresses.
// Router, Solicited and Override are flags from a Neighbor Advertisement.
type NeighborRecord struct {
	PacketIndex        int
	TimestampNs        int64
	InterfaceID        uint32
	Operation          NeighborOperation
	SourceAddr         netip.Addr
	TargetAddr         netip.Addr
	SourceHardwareAddr net.HardwareAddr
	TargetHardwareAddr net.HardwareAddr
	Router             bool
	Solicited          bool
	Override           bool
}

// ErrNeighborLimit indicates that more than 4096 neighbor observations were encountered.
var ErrNeighborLimit = errors.New("neighbor observation count exceeds limit")

const (
	maxNeighborRecords     = 4096
	maxNeighborIPv6Payload = 4096
)

// Neighbors extracts Ethernet/IPv4 ARP requests and replies and IPv6
// Neighbor Solicitations and Advertisements, in packet order. It uses the
// same bounded scan and read budget as [Capture.NeighborsFromReaderAt].
func (c *Capture) Neighbors(data []byte) ([]NeighborRecord, error) {
	return c.NeighborsFromReaderAt(bytes.NewReader(data))
}

// NeighborsFromReaderAt reads neighbor observations under [MaxReaderAtScanBytes].
// The scan skips malformed or unsupported messages and returns [ErrNeighborLimit]
// when the observation count exceeds 4096.
func (c *Capture) NeighborsFromReaderAt(r io.ReaderAt) ([]NeighborRecord, error) {
	var records []NeighborRecord
	err := c.scanNeighbors(r, func(rec NeighborRecord, _ neighborScope) {
		records = append(records, rec)
	})
	if err != nil {
		return nil, err
	}
	return records, nil
}

type neighborScope struct {
	interfaceID        uint32
	linkType           LinkType
	linkInterfaceIndex uint32
	vlanCount          uint8
	vlanTags           [MaxVLANTags]uint16
}

func (c *Capture) scanNeighbors(r io.ReaderAt, observe func(NeighborRecord, neighborScope)) error {
	if err := c.validateContainer(); err != nil {
		return err
	}
	if r == nil {
		return ErrInvalidHeader
	}
	var count int
	var prefix [96]byte // Link, up to four VLAN tags, IPv6 and a short NDP message.
	var scratch []byte
	budget := scanReadBudget{r: r, remaining: MaxReaderAtScanBytes}
	return c.walkPacketsFromReaderAt(&budget, false, func(pkt PacketRecord) error {
		p := prefix[:min(int64(len(prefix)), pkt.PayloadLength)]
		if err := readExactAt(&budget, p, pkt.PayloadOffset, c.fileSize); err != nil {
			return err
		}
		scope := neighborScope{interfaceID: pkt.InterfaceID, linkType: pkt.LinkType}
		rec, need := decodeNeighbor(p, pkt.LinkType, &scope)
		if need > len(p) && int64(need) <= pkt.PayloadLength {
			if cap(scratch) < need {
				scratch = make([]byte, need)
			}
			full := scratch[:need]
			copy(full, p)
			if err := readExactAt(&budget, full[len(p):], pkt.PayloadOffset+int64(len(p)), c.fileSize); err != nil {
				return err
			}
			rec, _ = decodeNeighbor(full, pkt.LinkType, &scope)
		}
		if rec.Operation != 0 {
			if count == maxNeighborRecords {
				return ErrNeighborLimit
			}
			count++
			rec.PacketIndex, rec.TimestampNs, rec.InterfaceID = pkt.Index, pkt.TimestampNs, pkt.InterfaceID
			if pkt.LinkType == LinkTypeLinuxSLL2 {
				// DecodeFrame has already checked the 20-byte cooked header.
				scope.linkInterfaceIndex = binary.BigEndian.Uint32(p[4:8])
			}
			observe(rec, scope)
		}
		return nil
	})
}

// decodeNeighbor returns the required prefix length when the link-local IPv6
// datagram is a candidate but its declared bytes are not in the prefix.
func decodeNeighbor(data []byte, link LinkType, scope *neighborScope) (NeighborRecord, int) {
	f, err := DecodeFrame(data, link)
	if err != nil {
		return NeighborRecord{}, 0
	}
	layers := f.LayerSlices()
	if len(layers) == 0 {
		return NeighborRecord{}, 0
	}
	layers = layers[1:] // Outer link header. Skip VLANs, but do not follow tunnels.
	for len(layers) > 0 && layers[0].Proto == LayerVLAN {
		layers = layers[1:]
	}
	if len(layers) == 0 {
		return NeighborRecord{}, 0
	}
	scope.vlanCount, scope.vlanTags = f.VLANCount, f.VLANTags
	start := int(layers[0].Offset)
	switch layers[0].Proto {
	case LayerARP:
		p := data[start : start+28]
		op := NeighborOperation(binary.BigEndian.Uint16(p[6:]))
		if binary.BigEndian.Uint16(p) != 1 || binary.BigEndian.Uint16(p[2:]) != EtherTypeIPv4 || p[4] != 6 || p[5] != 4 || op != ARPRequest && op != ARPReply {
			return NeighborRecord{}, 0
		}
		return NeighborRecord{
			Operation:          op,
			SourceHardwareAddr: bytes.Clone(p[8:14]),
			SourceAddr:         netip.AddrFrom4([4]byte(p[14:18])),
			TargetHardwareAddr: bytes.Clone(p[18:24]),
			TargetAddr:         netip.AddrFrom4([4]byte(p[24:28])),
		}, 0
	case LayerIPv6:
		if f.IPVersion != 6 || f.TTL != 255 || f.Anomalies.IPFragment || f.Anomalies.IPv6ExtLimitExceeded {
			return NeighborRecord{}, 0
		}
		// Frame can describe an inner IPv6 packet; only inspect direct
		// neighbors of this link. Reject Fragment headers, even atomic ones.
		proto := data[start+6]
		for _, l := range layers[1:] {
			if l.Proto == LayerICMPv6 {
				break
			}
			if l.Proto != LayerIPv6Ext || proto == IPProtoIPv6Frag {
				return NeighborRecord{}, 0
			}
			proto = data[l.Offset]
		}
		if proto != IPProtoIPv6ICMP && !isIPv6ExtHeader(proto) {
			return NeighborRecord{}, 0
		}
		icmp := layers[len(layers)-1]
		kind := NeighborOperation(f.ICMPType)
		if icmp.Proto == LayerICMPv6 && (f.ICMPCode != 0 || kind != NeighborSolicitation && kind != NeighborAdvertisement) {
			return NeighborRecord{}, 0
		}
		n := int(binary.BigEndian.Uint16(data[start+4:]))
		if n > maxNeighborIPv6Payload {
			return NeighborRecord{}, 0
		}
		end := start + 40 + n
		if end > len(data) {
			return NeighborRecord{}, end
		}
		if f.Anomalies.Any() || icmp.Proto != LayerICMPv6 {
			return NeighborRecord{}, 0
		}
		return parseNeighborDiscovery(data[int(icmp.Offset):end], f.SrcAddr, f.DstAddr), 0
	}
	return NeighborRecord{}, 0
}

func parseNeighborDiscovery(p []byte, src, dst netip.Addr) NeighborRecord {
	if len(p) < 24 || src.IsMulticast() || !validNeighborChecksum(p, src, dst) {
		return NeighborRecord{}
	}
	target := netip.AddrFrom16([16]byte(p[8:24]))
	if target.IsMulticast() || target.IsUnspecified() {
		return NeighborRecord{}
	}
	rec := NeighborRecord{Operation: NeighborOperation(p[0]), SourceAddr: src, TargetAddr: target}
	want := byte(1)
	if rec.Operation == NeighborAdvertisement {
		want = 2
		rec.Router, rec.Solicited, rec.Override = p[4]&0x80 != 0, p[4]&0x40 != 0, p[4]&0x20 != 0
		if src.IsUnspecified() || dst.IsMulticast() && rec.Solicited {
			return NeighborRecord{}
		}
	} else if src.IsUnspecified() {
		// A duplicate-address-detection solicitation uses the target's
		// solicited-node multicast destination.
		solicited := [16]byte{0xff, 2, 11: 1, 12: 0xff}
		copy(solicited[13:], p[21:24])
		if dst != netip.AddrFrom16(solicited) {
			return NeighborRecord{}
		}
	}
	var hw []byte
	for options := p[24:]; len(options) > 0; {
		if len(options) < 2 {
			return NeighborRecord{}
		}
		n := int(options[1]) * 8
		if n == 0 || n > len(options) {
			return NeighborRecord{}
		}
		if options[0] == want {
			if n != 8 || src.IsUnspecified() {
				return NeighborRecord{}
			}
			if hw == nil {
				hw = options[2:8]
			}
		}
		options = options[n:]
	}
	if want == 1 {
		rec.SourceHardwareAddr = bytes.Clone(hw)
	} else {
		rec.TargetHardwareAddr = bytes.Clone(hw)
	}
	return rec
}

// validNeighborChecksum covers the IPv6 pseudoheader and ICMPv6 message.
func validNeighborChecksum(p []byte, src, dst netip.Addr) bool {
	sum := uint32(len(p)) + uint32(IPProtoIPv6ICMP)
	for _, a := range []netip.Addr{src, dst} {
		b := a.As16()
		for i := 0; i < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i:]))
		}
	}
	for len(p) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(p))
		p = p[2:]
	}
	if len(p) != 0 {
		sum += uint32(p[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return sum == 0xffff
}
