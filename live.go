package pcap

import (
	"cmp"
	"encoding/binary"
	"fmt"
	"net"
	"slices"
	"time"
)

// LinkTypeUnknown indicates that the capture has no known link-layer type.
const LinkTypeUnknown LinkType = 0xffff

// LiveDevice describes an interface the live capture backend can inspect.
// LinkType is the backend's framing when HasLinkType is true. The device may
// still require permissions to open for capture.
type LiveDevice struct {
	Name        string
	Index       int
	MTU         int
	Flags       net.Flags
	LinkType    LinkType
	HasLinkType bool
}

// LiveDevices lists network interfaces in ascending interface-index order.
// If the backend cannot determine a supported datalink for an interface, its
// LinkType is [LinkTypeUnknown] and HasLinkType is false. On macOS, querying
// datalinks requires access to /dev/bpf. Windows reports its IPv4 socket
// framing. Linux reads each device and its datalink from the same kernel
// link record.
func LiveDevices() ([]LiveDevice, error) {
	devices, err := platformLiveDevices()
	if err != nil {
		return nil, err
	}
	slices.SortFunc(devices, func(a, b LiveDevice) int { return cmp.Compare(a.Index, b.Index) })
	return devices, nil
}

// InterfaceName returns the bound network interface name.
func (lc *LiveCapture) InterfaceName() string {
	if lc == nil {
		return ""
	}
	return lc.ifaceName
}

// LinkType returns the capture-file link type for the interface's encapsulation.
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

// BPFInstruction represents one classic Berkeley Packet Filter instruction
// (compatible with macOS/BSD BIOCSETF and Linux SO_ATTACH_FILTER).
type BPFInstruction struct {
	Code uint16
	JT   uint8
	JF   uint8
	K    uint32
}

// LiveStats reports kernel packet counters for one live capture handle.
type LiveStats struct {
	PacketsReceived uint64 // Packets counted as received by the capture backend.
	PacketsDropped  uint64 // Packets dropped because the capture buffer was full.
}

// LiveOptions configures live interface packet capture via [OpenLive].
type LiveOptions struct {
	SnapLen     uint32
	Promiscuous bool
	Immediate   bool
	BufferSize  int
	Timeout     time.Duration
	BPFFilter   []BPFInstruction
}

func (o LiveOptions) normalize() (LiveOptions, error) {
	if o.SnapLen == 0 {
		o.SnapLen = DefaultLiveSnapLen
	}
	if o.SnapLen > MaxSnapLen {
		return o, fmt.Errorf("%w: snaplen %d exceeds %d", ErrInvalidHeader, o.SnapLen, MaxSnapLen)
	}
	if o.BufferSize <= 0 {
		o.BufferSize = DefaultLiveBufferSize
	}
	if o.BufferSize > MaxSnapLen {
		return o, fmt.Errorf("%w: buffer size %d exceeds %d", ErrInvalidHeader, o.BufferSize, MaxSnapLen)
	}
	if len(o.BPFFilter) > MaxBPFFilterInstructions {
		return o, fmt.Errorf("%w: BPF filter length %d exceeds %d", ErrInvalidHeader, len(o.BPFFilter), MaxBPFFilterInstructions)
	}
	return o, nil
}

// BPFWordAlign rounds n up to a 4-byte boundary matching kernel BPF_WORDALIGN
// on 64-bit Darwin/BSD systems.
func BPFWordAlign(n int) int {
	return (n + 3) &^ 3
}

// ParseBPFBuffer parses a batch of kernel /dev/bpf packets (each prefixed by an
// 18-byte Darwin/BSD bpf_hdr with 32-bit timeval sec/usec, caplen, datalen, and
// hdrlen) into [PacketRecord] metadata whose PayloadOffset and PayloadLength
// index directly into buf.
func ParseBPFBuffer(buf []byte, linkType LinkType) ([]PacketRecord, error) {
	var records []PacketRecord
	for batch := buf; len(batch) >= 18; {
		tvSec := binary.LittleEndian.Uint32(batch[:4])
		tvUsec := binary.LittleEndian.Uint32(batch[4:8])
		capLen := binary.LittleEndian.Uint32(batch[8:12])
		origLen := binary.LittleEndian.Uint32(batch[12:16])
		hdrLen := int(binary.LittleEndian.Uint16(batch[16:18]))

		if hdrLen < 18 || capLen > MaxSnapLen {
			return nil, fmt.Errorf("%w: invalid BPF packet header (hdrLen=%d, capLen=%d)", ErrInvalidPacket, hdrLen, capLen)
		}
		recordLen := hdrLen + int(capLen) // Both fields are bounded above.
		if recordLen > len(batch) {
			return nil, fmt.Errorf("%w: BPF packet payload exceeds buffer", ErrInvalidPacket)
		}
		records = append(records, PacketRecord{})
		rec := &records[len(records)-1]
		rec.Index = len(records) - 1
		rec.LinkType = linkType
		rec.TimestampNs = int64(tvSec)*1_000_000_000 + int64(tvUsec)*1_000
		rec.CaptureLen, rec.OriginalLen = capLen, origLen
		rec.PayloadOffset = int64(len(buf) - len(batch) + hdrLen)
		rec.PayloadLength = int64(capLen)
		// The final record may omit alignment padding.
		batch = batch[min(BPFWordAlign(recordLen), len(batch)):]
	}
	return records, nil
}
