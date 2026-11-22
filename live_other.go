//go:build !darwin && !linux

package pcap

import "fmt"

const LinkTypeUnknown LinkType = 0xffff

// LiveCapture represents a live interface packet capture handle.
type LiveCapture struct {
	ifaceName string
	linkType  LinkType
	snapLen   uint32
}

// OpenLive returns [ErrLiveCaptureUnsupported] on platforms without a native
// BPF or AF_PACKET implementation, after validating ifaceName and opts.
func OpenLive(ifaceName string, opts LiveOptions) (*LiveCapture, error) {
	if ifaceName == "" {
		return nil, fmt.Errorf("%w: empty interface name", ErrInvalidHeader)
	}
	if _, err := opts.normalize(); err != nil {
		return nil, err
	}
	return nil, ErrLiveCaptureUnsupported
}

// InterfaceName returns the bound network interface name.
func (lc *LiveCapture) InterfaceName() string {
	if lc == nil {
		return ""
	}
	return lc.ifaceName
}

// LinkType returns the link-layer encapsulation type.
func (lc *LiveCapture) LinkType() LinkType {
	if lc == nil {
		return LinkTypeUnknown
	}
	return lc.linkType
}

// SnapLen returns the configured snapshot length.
func (lc *LiveCapture) SnapLen() uint32 {
	if lc == nil {
		return 0
	}
	return lc.snapLen
}

// ReadPacket returns [ErrLiveCaptureUnsupported].
func (lc *LiveCapture) ReadPacket() (PacketRecord, []byte, error) {
	return PacketRecord{}, nil, ErrLiveCaptureUnsupported
}

// Close is a no-op on unsupported platforms.
func (lc *LiveCapture) Close() error {
	return nil
}
