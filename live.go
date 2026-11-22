package pcap

import (
	"encoding/binary"
	"fmt"
	"time"
)

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
	offset := 0
	for offset+18 <= len(buf) {
		tvSec := binary.LittleEndian.Uint32(buf[offset : offset+4])
		tvUsec := binary.LittleEndian.Uint32(buf[offset+4 : offset+8])
		capLen := binary.LittleEndian.Uint32(buf[offset+8 : offset+12])
		origLen := binary.LittleEndian.Uint32(buf[offset+12 : offset+16])
		hdrLen := int(binary.LittleEndian.Uint16(buf[offset+16 : offset+18]))

		if hdrLen < 18 || capLen > MaxSnapLen {
			return nil, fmt.Errorf("%w: invalid BPF packet header (hdrLen=%d, capLen=%d)", ErrInvalidPacket, hdrLen, capLen)
		}
		payloadStart := offset + hdrLen
		payloadEnd := payloadStart + int(capLen)
		if payloadEnd > len(buf) {
			return nil, fmt.Errorf("%w: BPF packet payload exceeds buffer", ErrInvalidPacket)
		}
		records = append(records, PacketRecord{
			Index:         len(records),
			LinkType:      linkType,
			TimestampNs:   int64(tvSec)*1_000_000_000 + int64(tvUsec)*1_000,
			CaptureLen:    capLen,
			OriginalLen:   origLen,
			PayloadOffset: int64(payloadStart),
			PayloadLength: int64(capLen),
		})
		step := BPFWordAlign(hdrLen + int(capLen))
		if step <= 0 {
			break
		}
		offset += step
	}
	return records, nil
}
