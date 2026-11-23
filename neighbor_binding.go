package pcap

import (
	"bytes"
	"io"
	"net/netip"
)

// NeighborBindingObservation identifies a packet that associates an IP
// address with a six-byte hardware address. Solicited and Override are flags
// from an IPv6 Neighbor Advertisement.
type NeighborBindingObservation struct {
	PacketIndex  int
	TimestampNs  int64
	Operation    NeighborOperation
	HardwareAddr [6]byte
	Solicited    bool
	Override     bool
}

// NeighborBindingChange pairs successive observations of different hardware
// addresses for Addr within one captured link and VLAN stack. InterfaceID
// indexes [Capture.Interfaces]. LinkInterfaceIndex is the Linux cooked v2
// interface index, or zero for Ethernet. The first VLANCount entries in
// VLANTags contain the VLAN IDs from outermost to innermost.
type NeighborBindingChange struct {
	Addr               netip.Addr
	InterfaceID        uint32
	LinkType           LinkType
	LinkInterfaceIndex uint32
	VLANCount          uint8
	VLANTags           [MaxVLANTags]uint16
	Previous           NeighborBindingObservation
	Current            NeighborBindingObservation
}

type neighborBindingKey struct {
	addr  netip.Addr
	scope neighborScope
}

// NeighborBindingChanges reports changes in observed IP and hardware-address
// associations in packet order. It compares ARP and IPv6 Neighbor
// Solicitation sender fields and IPv6 Neighbor Advertisement target fields.
// Each observation becomes the baseline for the next one on the same link.
// Associations require a unicast IP address and a nonzero unicast MAC address.
// The scan compares Ethernet packets and Linux cooked v2 packets with a
// nonzero interface index. It uses the limits of [Capture.NeighborBindingChangesFromReaderAt].
func (c *Capture) NeighborBindingChanges(data []byte) ([]NeighborBindingChange, error) {
	return c.NeighborBindingChangesFromReaderAt(bytes.NewReader(data))
}

// NeighborBindingChangesFromReaderAt reports the same changes as
// [Capture.NeighborBindingChanges] within the [MaxReaderAtScanBytes] budget.
// It returns [ErrNeighborLimit] if the scan decodes more than 4096 neighbor
// observations. Errors discard all changes.
func (c *Capture) NeighborBindingChangesFromReaderAt(r io.ReaderAt) ([]NeighborBindingChange, error) {
	var changes []NeighborBindingChange
	latest := make(map[neighborBindingKey]NeighborBindingObservation)
	err := c.scanNeighbors(r, func(rec NeighborRecord, scope neighborScope) {
		if scope.linkType != LinkTypeEthernet && (scope.linkType != LinkTypeLinuxSLL2 || scope.linkInterfaceIndex == 0) {
			return
		}
		addr, hw := rec.SourceAddr, rec.SourceHardwareAddr
		if rec.Operation == NeighborAdvertisement {
			addr, hw = rec.TargetAddr, rec.TargetHardwareAddr
		}
		if !addr.IsValid() || addr.IsUnspecified() || addr.IsMulticast() || addr == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
			return
		}
		if len(hw) != 6 || hw[0]&1 != 0 || [6]byte(hw) == [6]byte{} {
			return
		}
		current := NeighborBindingObservation{
			PacketIndex:  rec.PacketIndex,
			TimestampNs:  rec.TimestampNs,
			Operation:    rec.Operation,
			HardwareAddr: [6]byte(hw),
			Solicited:    rec.Solicited,
			Override:     rec.Override,
		}
		key := neighborBindingKey{addr: addr, scope: scope}
		previous, ok := latest[key]
		latest[key] = current
		if ok && previous.HardwareAddr != current.HardwareAddr {
			changes = append(changes, NeighborBindingChange{
				Addr:               addr,
				InterfaceID:        scope.interfaceID,
				LinkType:           scope.linkType,
				LinkInterfaceIndex: scope.linkInterfaceIndex,
				VLANCount:          scope.vlanCount,
				VLANTags:           scope.vlanTags,
				Previous:           previous,
				Current:            current,
			})
		}
	})
	if err != nil {
		return nil, err
	}
	return changes, nil
}
