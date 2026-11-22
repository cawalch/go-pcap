package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"iter"
	"math"
	"math/bits"
	"net/netip"
	"os"
	"strings"
)

const (
	pcapGlobalHeaderSize   = 24
	pcapPacketHeaderSize   = 16
	pcapngMinBlockSize     = 12
	pcapngSHBMinSize       = 28
	pcapngIDBMinSize       = 20
	pcapngEPBMinSize       = 32
	pcapngSPBMinSize       = 16
	pcapngDSBMinSize       = 20
	defaultTimestampResolN = 1_000 // default PcapNG 10^-6 s = 1,000 ns per unit
)

// InterfaceDescriptor describes a capture interface from a classic PCAP header
// or a PcapNG Interface Description Block (IDB).
type InterfaceDescriptor struct {
	ID          uint32
	LinkType    LinkType
	SnapLen     uint32
	Name        string
	Description string
	OS          string
	// TimestampScaleNs is the multiplier in nanoseconds per raw timestamp tick
	// when TimestampBinary is false (default 1,000 for microsecond resolution,
	// 1 for nanosecond resolution).
	TimestampScaleNs uint64
	// TimestampBinary reports whether if_tsresol uses a binary power-of-two
	// resolution (2^-TimestampExponent seconds per tick).
	TimestampBinary bool
	// TimestampExponent is the decimal (10^-N) or binary (2^-N) exponent from
	// PcapNG option if_tsresol (default 6 for 10^-6 s).
	TimestampExponent uint8
	// TimestampOffsetSec is the signed seconds offset from PcapNG option
	// if_tsoffset added to raw packet timestamps.
	TimestampOffsetSec int64
}

// DecryptionSecret holds key material from a PcapNG Decryption Secrets Block (DSB),
// such as an embedded NSS SSLKEYLOGFILE payload.
type DecryptionSecret struct {
	SecretsType   uint32
	PayloadOffset int64
	PayloadLength int64
	Data          []byte
}

// CaptureAnomalies reports non-fatal container or packet framing anomalies.
type CaptureAnomalies struct {
	TruncatedPacketBlock       bool
	CaptureLenExceedsOriginal  bool
	CaptureLenExceedsSnapLen   bool
	UnknownLinkType            bool
	TrailingBytes              bool
	UnalignedBlockLength       bool
	InvalidTimestampResolution bool
}

// Any reports whether any container anomaly was detected.
func (a CaptureAnomalies) Any() bool {
	return a.TruncatedPacketBlock ||
		a.CaptureLenExceedsOriginal ||
		a.CaptureLenExceedsSnapLen ||
		a.UnknownLinkType ||
		a.TrailingBytes ||
		a.UnalignedBlockLength ||
		a.InvalidTimestampResolution
}

// NameResolutionRecord holds an IPv4 or IPv6 address and its resolved hostnames
// from a PcapNG Name Resolution Block (NRB).
type NameResolutionRecord struct {
	Addr  netip.Addr
	Names []string
}

// InterfaceStatistics holds capture statistics from a PcapNG Interface
// Statistics Block (ISB).
type InterfaceStatistics struct {
	InterfaceID        uint32 // Index in Capture.Interfaces across all sections.
	TimestampNs        int64
	StartTimeNs        int64
	EndTimeNs          int64
	PacketsReceived    uint64
	PacketsDropped     uint64
	HasStartTime       bool
	HasEndTime         bool
	HasPacketsReceived bool
	HasPacketsDropped  bool
}

// ProcessEvent describes a Darwin Process Event Block (DPEB) or process entry
// in a PcapNG capture.
type ProcessEvent struct {
	ProcessID   uint32
	ProcessName string
}

// PacketRecord describes one captured packet's metadata and payload byte span
// within the capture buffer.
type PacketRecord struct {
	Index         int
	InterfaceID   uint32 // Index in Capture.Interfaces across all sections.
	LinkType      LinkType
	TimestampNs   int64
	CaptureLen    uint32
	OriginalLen   uint32
	PayloadOffset int64
	PayloadLength int64

	// PcapNG Enhanced Packet Block optional metadata and process attribution.
	ProcessID    uint32
	ThreadID     uint32
	UserID       uint32
	Flags        uint32
	DropCount    uint64
	ProcessName  string
	ProcessArgs  string
	ContainerID  string
	HasProcessID bool
	HasThreadID  bool
	HasUserID    bool
}

// Capture contains a parsed snapshot of a PCAP or PcapNG container's headers,
// interfaces, decryption secrets, name resolution records, interface
// statistics, process events, and extent metadata.
// If you don't modify its exported fields, you can read a Capture concurrently.
type Capture struct {
	Format         Format
	BigEndian      bool
	NanoTimestamp  bool
	VersionMajor   uint16
	VersionMinor   uint16
	SnapLen        uint32
	LinkType       LinkType
	Hardware       string
	OS             string
	UserAppl       string
	Interfaces     []InterfaceDescriptor
	Secrets        []DecryptionSecret
	NameRecords    []NameResolutionRecord
	InterfaceStats []InterfaceStatistics
	Processes      []ProcessEvent
	PacketCount    int

	fileSize       int64
	declaredExtent uint64
	anomalies      CaptureAnomalies
}

// Open reads the entire named file into memory and parses its capture container.
// If you need to control input size or I/O, read the bytes in your application
// and pass them to [New].
func Open(filename string) (*Capture, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return New(data)
}

// New parses a classic PCAP or PcapNG container from data.
// It returns an error if the leading container header is missing or invalid, or
// if any block or record violates structural invariants or work limits.
//
// New records int64(len(data)) as [Capture.FileSize]. If a trailing packet or
// PcapNG block is truncated at the end of data, New succeeds, sets
// [Capture.DeclaredExtent] to the declared end of that trailing record, and
// marks [Capture.InputTruncated].
//
// The returned [Capture] owns its metadata, interface strings, and DSB secret
// copies and retains no reference to data.
func New(data []byte) (*Capture, error) {
	return NewWithLength(data, int64(len(data)))
}

var (
	errNotPCAPOutOfBounds  = &notPCAPWrapError{cause: ErrOutOfBounds, msg: "not a PCAP or PcapNG capture: read out of bounds"}
	errNotPCAPInvalidMagic = &notPCAPWrapError{cause: ErrInvalidMagic, msg: "not a PCAP or PcapNG capture: invalid magic signature"}
)

type notPCAPWrapError struct {
	cause error
	msg   string
}

func (e *notPCAPWrapError) Error() string { return e.msg }

func (e *notPCAPWrapError) Is(target error) bool {
	return target == ErrNotPCAP || target == e.cause
}

func (e *notPCAPWrapError) Unwrap() error { return e.cause }

// NewWithLength parses a classic PCAP or PcapNG container from data while
// recording fileSize as the capture's total byte length ([Capture.FileSize]).
// Returns [ErrInvalidHeader] if fileSize is smaller than int64(len(data)).
func NewWithLength(data []byte, fileSize int64) (*Capture, error) {
	if fileSize < int64(len(data)) {
		return nil, fmt.Errorf("%w: input length %d is smaller than buffer length %d", ErrInvalidHeader, fileSize, len(data))
	}
	if len(data) < 4 {
		return nil, errNotPCAPOutOfBounds
	}
	magic := binary.LittleEndian.Uint32(data[:4])
	switch magic {
	case PCAPMagicMicroLE:
		r := SafeReader{data: data, size: int64(len(data))}
		return parseClassicPCAP(&r, fileSize, binary.LittleEndian, false)
	case PCAPMagicMicroBE:
		r := SafeReader{data: data, size: int64(len(data))}
		return parseClassicPCAP(&r, fileSize, binary.BigEndian, false)
	case PCAPMagicNanoLE:
		r := SafeReader{data: data, size: int64(len(data))}
		return parseClassicPCAP(&r, fileSize, binary.LittleEndian, true)
	case PCAPMagicNanoBE:
		r := SafeReader{data: data, size: int64(len(data))}
		return parseClassicPCAP(&r, fileSize, binary.BigEndian, true)
	case PCAPNGSectionHeaderMagic:
		r := SafeReader{data: data, size: int64(len(data))}
		return parsePCAPNG(&r, fileSize)
	default:
		return nil, errNotPCAPInvalidMagic
	}
}

// FileSize returns the byte length recorded by [New] or [NewWithLength] (or 0
// when c is nil).
func (c *Capture) FileSize() int64 {
	if c == nil {
		return 0
	}
	return c.fileSize
}

// DeclaredExtent returns the highest declared file byte offset referenced by
// the capture headers and packet/block records, or (0, false) when c is nil or
// unparsed.
func (c *Capture) DeclaredExtent() (uint64, bool) {
	if c == nil || c.Format == FormatUnknown {
		return 0, false
	}
	return c.declaredExtent, true
}

// InputTruncated reports whether [Capture.FileSize] is smaller than
// [Capture.DeclaredExtent] or a trailing record header was truncated.
func (c *Capture) InputTruncated() bool {
	if c == nil || c.Format == FormatUnknown {
		return false
	}
	if c.anomalies.TruncatedPacketBlock || c.anomalies.TrailingBytes {
		return true
	}
	return c.fileSize < 0 || c.declaredExtent > uint64(c.fileSize)
}

// Anomalies returns the structural container anomalies recorded during [New].
func (c *Capture) Anomalies() CaptureAnomalies {
	if c == nil {
		return CaptureAnomalies{}
	}
	return c.anomalies
}

// PacketPayload returns a zero-copy slice of data corresponding to pkt's
// captured frame bytes. It validates that pkt's byte range lies within data.
func (c *Capture) PacketPayload(data []byte, pkt PacketRecord) ([]byte, error) {
	if err := c.validateContainer(); err != nil {
		return nil, err
	}
	r := NewSafeReader(data)
	return r.Slice(pkt.PayloadOffset, pkt.PayloadLength)
}

// PacketSeq returns a single-pass iterator over packet records in file order
// without allocating a slice of [PacketRecord] values.
func (c *Capture) PacketSeq(data []byte) iter.Seq2[PacketRecord, error] {
	return func(yield func(PacketRecord, error) bool) {
		if err := c.validateContainer(); err != nil {
			yield(PacketRecord{}, err)
			return
		}
		r := SafeReader{data: data, size: int64(len(data))}
		stopped := false
		err := c.walkPackets(&r, func(pkt PacketRecord) error {
			if !yield(pkt, nil) {
				stopped = true
				return errStopWalk
			}
			return nil
		})
		if err != nil && !stopped {
			yield(PacketRecord{}, err)
		}
	}
}

var errStopWalk = errors.New("stop packet walk")

func (c *Capture) walkPackets(r *SafeReader, fn func(PacketRecord) error) error {
	if err := c.validateContainer(); err != nil {
		return err
	}
	switch c.Format {
	case FormatPCAP:
		order := binary.ByteOrder(binary.LittleEndian)
		if c.BigEndian {
			order = binary.BigEndian
		}
		_, _, err := scanClassicPCAPPacketsWithCallback(r, c.SnapLen, c.LinkType, order, c.NanoTimestamp, false, 0, fn)
		if errors.Is(err, errStopWalk) {
			return nil
		}
		return err
	case FormatPCAPNG:
		_, _, err := scanPCAPNGBlocksWithCallback(r, false, 0, fn)
		if errors.Is(err, errStopWalk) {
			return nil
		}
		return err
	default:
		return ErrInvalidHeader
	}
}

// ipFrameSource visits all decoded IP frames to preserve first-seen flow
// indices. Selected payloads remain valid after the visitor returns.
type ipFrameSource struct {
	capture      *Capture
	data         []byte
	reader       io.ReaderAt
	needsPayload func(Frame, []byte) bool
}

func (s ipFrameSource) walk(visit func(PacketRecord, Frame, []byte) error) error {
	if err := s.capture.validateContainer(); err != nil {
		return err
	}
	if s.needsPayload != nil {
		return s.walkReaderAt(visit)
	}
	if s.capture.PacketCount == 0 {
		return nil
	}
	r := NewSafeReader(s.data)
	return s.capture.walkPackets(r, func(pkt PacketRecord) error {
		payload, err := r.Slice(pkt.PayloadOffset, pkt.PayloadLength)
		if err != nil {
			return err
		}
		frame, err := DecodeFrame(payload, pkt.LinkType)
		if err != nil || frame.IPVersion == 0 {
			return nil
		}
		return visit(pkt, frame, payload[frame.PayloadOffset:frame.PayloadOffset+frame.PayloadLength])
	})
}

// Packets enumerates bounded packet records in file order from the original
// bytes passed to [New]. It does not copy packet payloads; use
// [Capture.PacketPayload] to slice a packet's bytes from data, or
// [Capture.PacketSeq] to stream packets without allocating a slice.
func (c *Capture) Packets(data []byte) ([]PacketRecord, error) {
	if err := c.validateContainer(); err != nil {
		return nil, err
	}
	r := SafeReader{data: data, size: int64(len(data))}
	switch c.Format {
	case FormatPCAP:
		order := binary.ByteOrder(binary.LittleEndian)
		if c.BigEndian {
			order = binary.BigEndian
		}
		_, packets, err := scanClassicPCAPPackets(r, c.SnapLen, c.LinkType, order, c.NanoTimestamp, true, c.PacketCount)
		return packets, err
	case FormatPCAPNG:
		_, packets, err := scanPCAPNGBlocks(r, true, c.PacketCount)
		return packets, err
	default:
		return nil, ErrInvalidHeader
	}
}

func (c *Capture) validateContainer() error {
	if c == nil || (c.Format != FormatPCAP && c.Format != FormatPCAPNG) {
		return fmt.Errorf("%w: capture container not parsed", ErrInvalidHeader)
	}
	return nil
}

func isKnownLinkType(lt LinkType) bool {
	switch lt {
	case LinkTypeNull, LinkTypeEthernet, LinkTypeRaw, LinkTypeLinuxSLL, LinkTypeIPv4, LinkTypeIPv6, LinkTypeLinuxSLL2:
		return true
	default:
		return false
	}
}

func parseClassicPCAP(r *SafeReader, fileSize int64, order binary.ByteOrder, nano bool) (*Capture, error) {
	if r.Size() < pcapGlobalHeaderSize {
		return nil, fmt.Errorf("%w: classic PCAP header shorter than %d bytes", ErrInvalidHeader, pcapGlobalHeaderSize)
	}
	vMajor, _ := r.ReadUint16Order(4, order)
	vMinor, _ := r.ReadUint16Order(6, order)
	if vMajor != 2 || vMinor != 4 {
		return nil, fmt.Errorf("%w: unsupported PCAP version %d.%d", ErrInvalidHeader, vMajor, vMinor)
	}
	snapLen, _ := r.ReadUint32Order(16, order)
	if snapLen > MaxSnapLen {
		return nil, fmt.Errorf("%w: snaplen %d exceeds %d", ErrInvalidHeader, snapLen, MaxSnapLen)
	}
	rawLinkType, _ := r.ReadUint32Order(20, order)
	linkType := LinkType(rawLinkType & 0xffff)

	meta, _, err := scanClassicPCAPPackets(*r, snapLen, linkType, order, nano, false, 0)
	if err != nil {
		return nil, err
	}
	if !isKnownLinkType(linkType) {
		meta.anomalies.UnknownLinkType = true
	}

	return &Capture{
		Format:         FormatPCAP,
		BigEndian:      order == binary.BigEndian,
		NanoTimestamp:  nano,
		VersionMajor:   vMajor,
		VersionMinor:   vMinor,
		SnapLen:        snapLen,
		LinkType:       linkType,
		Interfaces:     []InterfaceDescriptor{classicInterface(linkType, snapLen, nano)},
		PacketCount:    meta.packetCount,
		fileSize:       fileSize,
		declaredExtent: meta.declaredExtent,
		anomalies:      meta.anomalies,
	}, nil
}

func classicInterface(linkType LinkType, snapLen uint32, nano bool) InterfaceDescriptor {
	iface := InterfaceDescriptor{LinkType: linkType, SnapLen: snapLen, TimestampScaleNs: 1000, TimestampExponent: 6}
	if nano {
		iface.TimestampScaleNs = 1
		iface.TimestampExponent = 9
	}
	return iface
}

type scanSummary struct {
	sectionInterfaceBase int
	packetCount          int
	declaredExtent       uint64
	anomalies            CaptureAnomalies
	bigEndian            bool
	vMajor               uint16
	vMinor               uint16
	hardware             string
	os                   string
	userAppl             string
	interfaces           []InterfaceDescriptor
	secrets              []DecryptionSecret
	nameRecords          []NameResolutionRecord
	interfaceStats       []InterfaceStatistics
	processes            []ProcessEvent
}

func scanClassicPCAPPackets(
	r SafeReader,
	snapLen uint32,
	linkType LinkType,
	order binary.ByteOrder,
	nano bool,
	collect bool,
	hintCount int,
) (scanSummary, []PacketRecord, error) {
	return scanClassicPCAPPacketsWithCallback(&r, snapLen, linkType, order, nano, collect, hintCount, nil)
}

func scanClassicPCAPPacketsWithCallback(
	r *SafeReader,
	snapLen uint32,
	linkType LinkType,
	order binary.ByteOrder,
	nano bool,
	collect bool,
	hintCount int,
	cb func(PacketRecord) error,
) (scanSummary, []PacketRecord, error) {
	summary := scanSummary{
		declaredExtent: pcapGlobalHeaderSize,
	}
	var packets []PacketRecord
	if collect && hintCount > 0 {
		packets = make([]PacketRecord, 0, min(hintCount, MaxPackets))
	}
	offset := int64(pcapGlobalHeaderSize)
	size := r.Size()

	for offset < size {
		remaining := size - offset
		if remaining < pcapPacketHeaderSize {
			summary.anomalies.TrailingBytes = true
			summary.declaredExtent = max(summary.declaredExtent, uint64(offset+pcapPacketHeaderSize))
			break
		}
		tsSec, _ := r.ReadUint32Order(offset, order)
		tsSub, _ := r.ReadUint32Order(offset+4, order)
		capLen, _ := r.ReadUint32Order(offset+8, order)
		origLen, _ := r.ReadUint32Order(offset+12, order)

		if capLen > MaxSnapLen {
			return scanSummary{}, nil, fmt.Errorf("%w: packet capture length %d exceeds %d", ErrInvalidPacket, capLen, MaxSnapLen)
		}
		if capLen > origLen {
			summary.anomalies.CaptureLenExceedsOriginal = true
		}
		if snapLen > 0 && capLen > snapLen {
			summary.anomalies.CaptureLenExceedsSnapLen = true
		}

		payloadOffset := offset + pcapPacketHeaderSize
		recordEnd := uint64(payloadOffset) + uint64(capLen)
		summary.declaredExtent = max(summary.declaredExtent, recordEnd)

		if recordEnd > uint64(size) {
			summary.anomalies.TruncatedPacketBlock = true
			break
		}

		if summary.packetCount >= MaxPackets {
			return scanSummary{}, nil, fmt.Errorf("%w: exceeds %d", ErrPacketLimit, MaxPackets)
		}
		summary.packetCount++

		if collect || cb != nil {
			subNs := int64(tsSub) * 1_000
			if nano {
				subNs = int64(tsSub)
			}
			tsNs := int64(tsSec)*1_000_000_000 + subNs
			rec := PacketRecord{
				Index:         summary.packetCount - 1,
				InterfaceID:   0,
				LinkType:      linkType,
				TimestampNs:   tsNs,
				CaptureLen:    capLen,
				OriginalLen:   origLen,
				PayloadOffset: payloadOffset,
				PayloadLength: int64(capLen),
			}
			if collect {
				packets = append(packets, rec)
			}
			if cb != nil {
				if err := cb(rec); err != nil {
					return summary, packets, err
				}
			}
		}

		offset = int64(recordEnd)
	}

	return summary, packets, nil
}

func parsePCAPNG(r *SafeReader, fileSize int64) (*Capture, error) {
	meta, _, err := scanPCAPNGBlocks(*r, false, 0)
	if err != nil {
		return nil, err
	}
	var snapLen uint32
	var linkType LinkType
	if len(meta.interfaces) > 0 {
		snapLen = meta.interfaces[0].SnapLen
		linkType = meta.interfaces[0].LinkType
	}
	return &Capture{
		Format:         FormatPCAPNG,
		BigEndian:      meta.bigEndian,
		VersionMajor:   meta.vMajor,
		VersionMinor:   meta.vMinor,
		SnapLen:        snapLen,
		LinkType:       linkType,
		Hardware:       meta.hardware,
		OS:             meta.os,
		UserAppl:       meta.userAppl,
		Interfaces:     meta.interfaces,
		Secrets:        meta.secrets,
		NameRecords:    meta.nameRecords,
		InterfaceStats: meta.interfaceStats,
		Processes:      meta.processes,
		PacketCount:    meta.packetCount,
		fileSize:       fileSize,
		declaredExtent: meta.declaredExtent,
		anomalies:      meta.anomalies,
	}, nil
}

func scanPCAPNGBlocks(r SafeReader, collectPackets bool, hintCount int) (scanSummary, []PacketRecord, error) {
	return scanPCAPNGBlocksWithCallback(&r, collectPackets, hintCount, nil)
}

func scanPCAPNGBlocksWithCallback(r *SafeReader, collectPackets bool, hintCount int, cb func(PacketRecord) error) (scanSummary, []PacketRecord, error) {
	size := r.Size()
	if size < pcapngSHBMinSize {
		return scanSummary{}, nil, fmt.Errorf("%w: PcapNG section header block shorter than %d bytes", ErrInvalidHeader, pcapngSHBMinSize)
	}

	var summary scanSummary
	var packets []PacketRecord
	if collectPackets && hintCount > 0 {
		packets = make([]PacketRecord, 0, min(hintCount, MaxPackets))
	}
	var totalSecretBytes int64
	order := binary.ByteOrder(binary.LittleEndian)
	haveSection := false
	offset := int64(0)

	for offset < size {
		remaining := size - offset
		if remaining < pcapngMinBlockSize {
			if !haveSection {
				return scanSummary{}, nil, fmt.Errorf("%w: missing PcapNG section header", ErrInvalidHeader)
			}
			summary.anomalies.TrailingBytes = true
			summary.declaredExtent = max(summary.declaredExtent, uint64(offset+pcapngMinBlockSize))
			break
		}

		// For a Section Header Block, determine endianness from the byte-order magic at offset+8.
		rawTypeLE, _ := r.ReadUint32(offset)
		if rawTypeLE == BlockTypeSectionHeader {
			if remaining < pcapngSHBMinSize {
				if !haveSection {
					return scanSummary{}, nil, fmt.Errorf("%w: truncated PcapNG section header", ErrInvalidHeader)
				}
				summary.anomalies.TruncatedPacketBlock = true
				summary.declaredExtent = max(summary.declaredExtent, uint64(offset+pcapngSHBMinSize))
				break
			}
			boMagicLE, _ := r.ReadUint32(offset + 8)
			switch boMagicLE {
			case PCAPNGByteOrderMagic:
				order = binary.LittleEndian
			case 0x4d3c2b1a:
				order = binary.BigEndian
			default:
				return scanSummary{}, nil, fmt.Errorf("%w: %w", ErrInvalidHeader, ErrInvalidMagic)
			}
		} else if !haveSection {
			return scanSummary{}, nil, fmt.Errorf("%w: PcapNG must start with a Section Header Block", ErrInvalidHeader)
		}

		blockType, _ := r.ReadUint32Order(offset, order)
		blockLen, _ := r.ReadUint32Order(offset+4, order)
		if blockLen < pcapngMinBlockSize {
			return scanSummary{}, nil, fmt.Errorf("%w: block length %d smaller than minimum %d", ErrInvalidBlock, blockLen, pcapngMinBlockSize)
		}
		if blockLen%4 != 0 {
			summary.anomalies.UnalignedBlockLength = true
		}

		// PcapNG pads block bodies to 32-bit alignment before the trailing 4-byte total length.
		paddedLen := uint64(blockLen)
		if rem := paddedLen % 4; rem != 0 {
			paddedLen += 4 - rem
		}
		blockEnd := uint64(offset) + paddedLen
		summary.declaredExtent = max(summary.declaredExtent, blockEnd)

		if blockEnd > uint64(size) {
			if !haveSection {
				return scanSummary{}, nil, fmt.Errorf("%w: first PcapNG Section Header Block is truncated", ErrInvalidHeader)
			}
			summary.anomalies.TruncatedPacketBlock = true
			break
		}

		trailingLen, _ := r.ReadUint32Order(int64(blockEnd)-4, order)
		if trailingLen != blockLen {
			return scanSummary{}, nil, fmt.Errorf("%w: trailing block length %d does not match leading length %d", ErrInvalidBlock, trailingLen, blockLen)
		}

		bodyStart := offset + 8
		bodyEnd := int64(blockEnd) - 4

		switch blockType {
		case BlockTypeSectionHeader:
			if err := decodeSHB(r, bodyStart, bodyEnd, order, &summary, &haveSection); err != nil {
				return scanSummary{}, nil, err
			}
		case BlockTypeInterfaceDesc:
			if err := decodeIDB(r, bodyStart, bodyEnd, order, &summary); err != nil {
				return scanSummary{}, nil, err
			}
		case BlockTypeEnhancedPacket, BlockTypeSimplePacket:
			body := r.data[bodyStart:bodyEnd]
			var rec PacketRecord
			var err error
			if blockType == BlockTypeEnhancedPacket {
				var options int64
				rec, options, err = decodeEPBHeader(body, bodyStart+20, bodyEnd, order, &summary)
				if err == nil && options < bodyEnd {
					err = decodeEPBOptions(r.data[options:bodyEnd], order, &summary, &rec)
				}
			} else {
				rec, err = decodeSPBHeader(body, bodyStart+4, bodyEnd, order, &summary)
			}
			if err != nil {
				return scanSummary{}, nil, err
			}
			if collectPackets {
				packets = append(packets, rec)
			}
			if cb != nil {
				if err := cb(rec); err != nil {
					return scanSummary{}, nil, err
				}
			}
		case BlockTypeDecryptionSecrets:
			if err := decodeDSB(r, bodyStart, bodyEnd, order, &totalSecretBytes, &summary); err != nil {
				return scanSummary{}, nil, err
			}
		case BlockTypeNameResolution:
			if err := decodeNRB(r, bodyStart, bodyEnd, order, &summary); err != nil {
				return scanSummary{}, nil, err
			}
		case BlockTypeInterfaceStats:
			if err := decodeISB(r, bodyStart, bodyEnd, order, &summary); err != nil {
				return scanSummary{}, nil, err
			}
		case BlockTypeDarwinProcessEvent:
			if err := decodeDPEB(r, bodyStart, bodyEnd, order, &summary); err != nil {
				return scanSummary{}, nil, err
			}
		default:
			// Other blocks (vendor custom blocks) are skipped after framing validation.
		}

		offset = int64(blockEnd)
	}

	return summary, packets, nil
}

func decodeSHB(
	r *SafeReader,
	bodyStart, bodyEnd int64,
	order binary.ByteOrder,
	summary *scanSummary,
	haveSection *bool,
) error {
	if bodyEnd-bodyStart < 16 {
		return fmt.Errorf("%w: Section Header Block body too short", ErrInvalidBlock)
	}
	vMajor, _ := r.ReadUint16Order(bodyStart+4, order)
	vMinor, _ := r.ReadUint16Order(bodyStart+6, order)
	if vMajor != 1 {
		return fmt.Errorf("%w: unsupported PcapNG version %d.%d", ErrInvalidHeader, vMajor, vMinor)
	}

	summary.sectionInterfaceBase = len(summary.interfaces)
	if !*haveSection {
		summary.bigEndian = order == binary.BigEndian
		summary.vMajor = vMajor
		summary.vMinor = vMinor
		*haveSection = true
	}

	optOffset := bodyStart + 16
	return walkPCAPNGOptions(r, optOffset, bodyEnd, order, func(code uint16, val []byte) error {
		switch code {
		case optSHBHardware:
			if summary.hardware == "" {
				summary.hardware = string(val)
			}
		case optSHBOS:
			if summary.os == "" {
				summary.os = string(val)
			}
		case optSHBUserAppl:
			if summary.userAppl == "" {
				summary.userAppl = string(val)
			}
		}
		return nil
	})
}

func decodeIDB(
	r *SafeReader,
	bodyStart, bodyEnd int64,
	order binary.ByteOrder,
	summary *scanSummary,
) error {
	if bodyEnd-bodyStart < 8 {
		return fmt.Errorf("%w: Interface Description Block body too short", ErrInvalidBlock)
	}
	if len(summary.interfaces) >= MaxInterfaces {
		return fmt.Errorf("%w: exceeds %d", ErrInterfaceLimit, MaxInterfaces)
	}
	rawLink, _ := r.ReadUint16Order(bodyStart, order)
	snapLen, _ := r.ReadUint32Order(bodyStart+4, order)
	if snapLen > MaxSnapLen {
		return fmt.Errorf("%w: IDB snaplen %d exceeds %d", ErrInvalidHeader, snapLen, MaxSnapLen)
	}

	iface := InterfaceDescriptor{
		ID:                uint32(len(summary.interfaces)),
		LinkType:          LinkType(rawLink),
		SnapLen:           snapLen,
		TimestampScaleNs:  defaultTimestampResolN,
		TimestampExponent: 6,
	}
	if !isKnownLinkType(iface.LinkType) {
		summary.anomalies.UnknownLinkType = true
	}

	err := walkPCAPNGOptions(r, bodyStart+8, bodyEnd, order, func(code uint16, val []byte) error {
		switch code {
		case optIDBName:
			iface.Name = string(val)
		case optIDBDescription:
			iface.Description = string(val)
		case optIDBOS:
			iface.OS = string(val)
		case optIDBTsResol:
			if len(val) == 1 {
				applyTimestampResolution(val[0], &iface, &summary.anomalies)
			} else {
				summary.anomalies.InvalidTimestampResolution = true
			}
		case optIDBTsOffset:
			if len(val) == 8 {
				iface.TimestampOffsetSec = int64(order.Uint64(val))
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	summary.interfaces = append(summary.interfaces, iface)
	return nil
}

func applyTimestampResolution(resol uint8, iface *InterfaceDescriptor, anomalies *CaptureAnomalies) {
	exp := resol & 0x7f
	if resol&0x80 != 0 {
		if exp > 63 {
			anomalies.InvalidTimestampResolution = true
			return
		}
		iface.TimestampBinary = true
		iface.TimestampExponent = exp
		return
	}
	if exp > 9 {
		anomalies.InvalidTimestampResolution = true
		return
	}
	scale := uint64(1)
	for range 9 - exp {
		scale *= 10
	}
	iface.TimestampBinary = false
	iface.TimestampExponent = exp
	iface.TimestampScaleNs = scale
}

func scaleRawTimestampNs(rawTicks uint64, iface InterfaceDescriptor) int64 {
	var ns uint64
	var overflow bool
	if iface.TimestampBinary {
		exp := iface.TimestampExponent
		// ns = floor(rawTicks * 10^9 / 2^exp) using 128-bit unsigned arithmetic.
		hi, lo := bits.Mul64(rawTicks, 1_000_000_000)
		if exp == 0 {
			ns = lo
			overflow = hi != 0
		} else if exp <= 63 {
			ns = (lo >> exp) | (hi << (64 - exp))
			overflow = (hi >> exp) != 0
		}
	} else {
		scale := iface.TimestampScaleNs
		if scale == 0 {
			scale = defaultTimestampResolN
		}
		hi, lo := bits.Mul64(rawTicks, scale)
		ns = lo
		overflow = hi != 0
	}

	if overflow || ns > uint64(math.MaxInt64) {
		return math.MaxInt64
	}
	baseNs := int64(ns)
	if iface.TimestampOffsetSec == 0 {
		return baseNs
	}
	if iface.TimestampOffsetSec > 0 {
		if iface.TimestampOffsetSec > math.MaxInt64/1_000_000_000 {
			return math.MaxInt64
		}
		offNs := iface.TimestampOffsetSec * 1_000_000_000
		if baseNs > math.MaxInt64-offNs {
			return math.MaxInt64
		}
		return baseNs + offNs
	}
	if iface.TimestampOffsetSec < math.MinInt64/1_000_000_000 {
		return math.MinInt64
	}
	offNs := iface.TimestampOffsetSec * 1_000_000_000
	if baseNs < math.MinInt64-offNs {
		return math.MinInt64
	}
	return baseNs + offNs
}

func decodeEPBHeader(header []byte, payloadOffset, bodyEnd int64, order binary.ByteOrder, summary *scanSummary) (PacketRecord, int64, error) {
	if len(header) < 20 {
		return PacketRecord{}, 0, fmt.Errorf("%w: Enhanced Packet Block body too short", ErrInvalidBlock)
	}
	ifaceID := order.Uint32(header[0:])
	if ifaceID >= uint32(len(summary.interfaces)-summary.sectionInterfaceBase) {
		return PacketRecord{}, 0, fmt.Errorf("%w: EPB interface ID %d out of range (%d section interfaces)", ErrInvalidPacket, ifaceID, len(summary.interfaces)-summary.sectionInterfaceBase)
	}
	iface := summary.interfaces[summary.sectionInterfaceBase+int(ifaceID)]

	tsHigh := order.Uint32(header[4:])
	tsLow := order.Uint32(header[8:])
	capLen := order.Uint32(header[12:])
	origLen := order.Uint32(header[16:])

	if capLen > MaxSnapLen {
		return PacketRecord{}, 0, fmt.Errorf("%w: EPB capture length %d exceeds %d", ErrInvalidPacket, capLen, MaxSnapLen)
	}
	if capLen > origLen {
		summary.anomalies.CaptureLenExceedsOriginal = true
	}
	if iface.SnapLen > 0 && capLen > iface.SnapLen {
		summary.anomalies.CaptureLenExceedsSnapLen = true
	}

	paddedCapLen := int64(capLen)
	if rem := paddedCapLen % 4; rem != 0 {
		paddedCapLen += 4 - rem
	}
	optOffset := payloadOffset + paddedCapLen
	if paddedCapLen > bodyEnd-payloadOffset {
		return PacketRecord{}, 0, fmt.Errorf("%w: EPB capture length %d exceeds block body", ErrInvalidBlock, capLen)
	}

	if summary.packetCount >= MaxPackets {
		return PacketRecord{}, 0, fmt.Errorf("%w: exceeds %d", ErrPacketLimit, MaxPackets)
	}
	summary.packetCount++

	return PacketRecord{
		Index:         summary.packetCount - 1,
		InterfaceID:   iface.ID,
		LinkType:      iface.LinkType,
		TimestampNs:   scaleRawTimestampNs(uint64(tsHigh)<<32|uint64(tsLow), iface),
		CaptureLen:    capLen,
		OriginalLen:   origLen,
		PayloadOffset: payloadOffset,
		PayloadLength: int64(capLen),
	}, optOffset, nil
}

func decodeEPBOptions(options []byte, order binary.ByteOrder, summary *scanSummary, rec *PacketRecord) error {
	r := SafeReader{data: options, size: int64(len(options))}
	return walkPCAPNGOptions(&r, 0, r.size, order, func(code uint16, val []byte) error {
		switch code {
		case optEPBFlags:
			if len(val) == 4 {
				rec.Flags = order.Uint32(val)
			}
		case optEPBDropCount:
			if len(val) == 8 {
				rec.DropCount = order.Uint64(val)
			}
		case optEPBDarwinDPEB:
			if len(val) == 4 {
				dpebIdx := int(order.Uint32(val))
				if dpebIdx >= 0 && dpebIdx < len(summary.processes) {
					pe := summary.processes[dpebIdx]
					if !rec.HasProcessID {
						rec.ProcessID = pe.ProcessID
						rec.HasProcessID = true
					}
					if rec.ProcessName == "" {
						rec.ProcessName = pe.ProcessName
					}
				}
			}
		case optEPBProcessID:
			if len(val) == 4 {
				rec.ProcessID = order.Uint32(val)
				rec.HasProcessID = true
			}
		case optEPBThreadID:
			if len(val) == 4 {
				rec.ThreadID = order.Uint32(val)
				rec.HasThreadID = true
			}
		case optEPBProcessName:
			rec.ProcessName = string(val)
		case optEPBProcessArgs:
			rec.ProcessArgs = string(val)
		case optEPBUserID:
			if len(val) == 4 {
				rec.UserID = order.Uint32(val)
				rec.HasUserID = true
			}
		case optEPBContainerID:
			rec.ContainerID = string(val)
		}
		return nil
	})
}

func decodeSPBHeader(header []byte, payloadOffset, bodyEnd int64, order binary.ByteOrder, summary *scanSummary) (PacketRecord, error) {
	if len(header) < 4 {
		return PacketRecord{}, fmt.Errorf("%w: Simple Packet Block body too short", ErrInvalidBlock)
	}
	if len(summary.interfaces) == summary.sectionInterfaceBase {
		return PacketRecord{}, fmt.Errorf("%w: Simple Packet Block requires interface 0", ErrInvalidPacket)
	}
	iface := summary.interfaces[summary.sectionInterfaceBase]
	origLen := order.Uint32(header)

	avail := bodyEnd - payloadOffset
	capLen := origLen
	if iface.SnapLen > 0 && capLen > iface.SnapLen {
		capLen = iface.SnapLen
	}
	if int64(capLen) > avail {
		return PacketRecord{}, fmt.Errorf("%w: Simple Packet Block payload exceeds block body", ErrInvalidBlock)
	}
	if capLen > MaxSnapLen {
		return PacketRecord{}, fmt.Errorf("%w: SPB capture length %d exceeds %d", ErrInvalidPacket, capLen, MaxSnapLen)
	}
	if summary.packetCount >= MaxPackets {
		return PacketRecord{}, fmt.Errorf("%w: exceeds %d", ErrPacketLimit, MaxPackets)
	}
	summary.packetCount++

	return PacketRecord{
		Index:         summary.packetCount - 1,
		InterfaceID:   iface.ID,
		LinkType:      iface.LinkType,
		CaptureLen:    capLen,
		OriginalLen:   origLen,
		PayloadOffset: payloadOffset,
		PayloadLength: int64(capLen),
	}, nil
}

func decodeDSB(
	r *SafeReader,
	bodyStart, bodyEnd int64,
	order binary.ByteOrder,
	totalSecretBytes *int64,
	summary *scanSummary,
) error {
	if bodyEnd-bodyStart < 8 {
		return fmt.Errorf("%w: Decryption Secrets Block body too short", ErrInvalidBlock)
	}
	if len(summary.secrets) >= MaxDecryptionSecrets {
		return fmt.Errorf("%w: exceeds %d", ErrSecretLimit, MaxDecryptionSecrets)
	}
	secretsType, _ := r.ReadUint32Order(bodyStart, order)
	secretsLen, _ := r.ReadUint32Order(bodyStart+4, order)
	payloadOffset := bodyStart + 8

	if int64(secretsLen) > bodyEnd-payloadOffset {
		return fmt.Errorf("%w: DSB payload length %d exceeds block body", ErrInvalidBlock, secretsLen)
	}
	if *totalSecretBytes+int64(secretsLen) > MaxDecryptionSecretBytes {
		return fmt.Errorf("%w: total DSB bytes exceed %d", ErrSecretLimit, MaxDecryptionSecretBytes)
	}
	*totalSecretBytes += int64(secretsLen)

	raw, err := r.Slice(payloadOffset, int64(secretsLen))
	if err != nil {
		return err
	}

	paddedLen := int64(secretsLen)
	if rem := paddedLen % 4; rem != 0 {
		paddedLen += 4 - rem
	}
	optOffset := payloadOffset + paddedLen
	if optOffset < bodyEnd {
		if err := walkPCAPNGOptions(r, optOffset, bodyEnd, order, func(uint16, []byte) error { return nil }); err != nil {
			return err
		}
	}

	summary.secrets = append(summary.secrets, DecryptionSecret{
		SecretsType:   secretsType,
		PayloadOffset: payloadOffset,
		PayloadLength: int64(secretsLen),
		Data:          bytes.Clone(raw),
	})
	return nil
}

func decodeNRB(
	r *SafeReader,
	bodyStart, bodyEnd int64,
	order binary.ByteOrder,
	summary *scanSummary,
) error {
	offset := bodyStart
	for offset < bodyEnd {
		if bodyEnd-offset < 4 {
			return fmt.Errorf("%w: truncated Name Resolution Block record header", ErrInvalidBlock)
		}
		recType, _ := r.ReadUint16Order(offset, order)
		recLen, _ := r.ReadUint16Order(offset+2, order)
		offset += 4
		if recType == nrbRecordEnd {
			break
		}
		if int64(recLen) > MaxOptionStringBytes || int64(recLen) > bodyEnd-offset {
			return fmt.Errorf("%w: NRB record length %d exceeds bounds", ErrInvalidBlock, recLen)
		}
		val, err := r.Slice(offset, int64(recLen))
		if err != nil {
			return err
		}
		padded := int64(recLen)
		if rem := padded % 4; rem != 0 {
			padded += 4 - rem
		}
		offset += padded

		switch recType {
		case nrbRecordIPv4:
			if len(val) < 5 {
				return fmt.Errorf("%w: NRB IPv4 record shorter than 5 bytes", ErrInvalidBlock)
			}
			if len(summary.nameRecords) >= MaxNameResolutionRecords {
				return fmt.Errorf("%w: NRB records exceed %d", ErrOptionLimit, MaxNameResolutionRecords)
			}
			addr := netip.AddrFrom4([4]byte(val[0:4]))
			names := parseNRBNames(val[4:])
			if len(names) > 0 {
				summary.nameRecords = append(summary.nameRecords, NameResolutionRecord{Addr: addr, Names: names})
			}
		case nrbRecordIPv6:
			if len(val) < 17 {
				return fmt.Errorf("%w: NRB IPv6 record shorter than 17 bytes", ErrInvalidBlock)
			}
			if len(summary.nameRecords) >= MaxNameResolutionRecords {
				return fmt.Errorf("%w: NRB records exceed %d", ErrOptionLimit, MaxNameResolutionRecords)
			}
			addr := netip.AddrFrom16([16]byte(val[0:16]))
			names := parseNRBNames(val[16:])
			if len(names) > 0 {
				summary.nameRecords = append(summary.nameRecords, NameResolutionRecord{Addr: addr, Names: names})
			}
		}
	}
	if offset < bodyEnd {
		return walkPCAPNGOptions(r, offset, bodyEnd, order, func(uint16, []byte) error { return nil })
	}
	return nil
}

func parseNRBNames(raw []byte) []string {
	var names []string
	for part := range bytes.SplitSeq(raw, []byte{0}) {
		s := strings.TrimSpace(string(part))
		if s != "" {
			names = append(names, s)
		}
	}
	return names
}

func decodeISB(
	r *SafeReader,
	bodyStart, bodyEnd int64,
	order binary.ByteOrder,
	summary *scanSummary,
) error {
	if bodyEnd-bodyStart < 12 {
		return fmt.Errorf("%w: Interface Statistics Block body too short", ErrInvalidBlock)
	}
	if len(summary.interfaceStats) >= MaxInterfaceStats {
		return fmt.Errorf("%w: ISB count exceeds %d", ErrOptionLimit, MaxInterfaceStats)
	}
	ifaceID, _ := r.ReadUint32Order(bodyStart, order)
	if ifaceID >= uint32(len(summary.interfaces)-summary.sectionInterfaceBase) {
		return fmt.Errorf("%w: ISB interface ID %d out of range", ErrInvalidPacket, ifaceID)
	}
	iface := summary.interfaces[summary.sectionInterfaceBase+int(ifaceID)]
	tsHigh, _ := r.ReadUint32Order(bodyStart+4, order)
	tsLow, _ := r.ReadUint32Order(bodyStart+8, order)

	stat := InterfaceStatistics{
		InterfaceID: iface.ID,
		TimestampNs: scaleRawTimestampNs((uint64(tsHigh)<<32)|uint64(tsLow), iface),
	}

	optOffset := bodyStart + 12
	if optOffset < bodyEnd {
		err := walkPCAPNGOptions(r, optOffset, bodyEnd, order, func(code uint16, val []byte) error {
			switch code {
			case optISBStartTime:
				if len(val) == 8 {
					hi := order.Uint32(val[0:4])
					lo := order.Uint32(val[4:8])
					stat.StartTimeNs = scaleRawTimestampNs((uint64(hi)<<32)|uint64(lo), iface)
					stat.HasStartTime = true
				}
			case optISBEndTime:
				if len(val) == 8 {
					hi := order.Uint32(val[0:4])
					lo := order.Uint32(val[4:8])
					stat.EndTimeNs = scaleRawTimestampNs((uint64(hi)<<32)|uint64(lo), iface)
					stat.HasEndTime = true
				}
			case optISBIfRecv:
				if len(val) == 8 {
					stat.PacketsReceived = order.Uint64(val)
					stat.HasPacketsReceived = true
				}
			case optISBIfDrop:
				if len(val) == 8 {
					stat.PacketsDropped = order.Uint64(val)
					stat.HasPacketsDropped = true
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}

	summary.interfaceStats = append(summary.interfaceStats, stat)
	return nil
}

func decodeDPEB(
	r *SafeReader,
	bodyStart, bodyEnd int64,
	order binary.ByteOrder,
	summary *scanSummary,
) error {
	if bodyEnd-bodyStart < 4 {
		return fmt.Errorf("%w: Darwin Process Event Block body too short", ErrInvalidBlock)
	}
	if len(summary.processes) >= MaxProcessEvents {
		return fmt.Errorf("%w: DPEB count exceeds %d", ErrOptionLimit, MaxProcessEvents)
	}
	pid, _ := r.ReadUint32Order(bodyStart, order)
	pe := ProcessEvent{ProcessID: pid}

	optOffset := bodyStart + 4
	if optOffset < bodyEnd {
		err := walkPCAPNGOptions(r, optOffset, bodyEnd, order, func(code uint16, val []byte) error {
			if code == optDPEBProcessName {
				pe.ProcessName = strings.TrimRight(string(val), "\x00")
			}
			return nil
		})
		if err != nil {
			return err
		}
	}

	summary.processes = append(summary.processes, pe)
	return nil
}

func walkPCAPNGOptions(
	r *SafeReader,
	start, end int64,
	order binary.ByteOrder,
	fn func(code uint16, val []byte) error,
) error {
	offset := start
	count := 0
	for offset < end {
		if end-offset < 4 {
			return fmt.Errorf("%w: truncated option header", ErrInvalidBlock)
		}
		if count >= MaxOptionsPerBlock {
			return fmt.Errorf("%w: exceeds %d options", ErrOptionLimit, MaxOptionsPerBlock)
		}
		count++

		code, _ := r.ReadUint16Order(offset, order)
		length, _ := r.ReadUint16Order(offset+2, order)
		offset += 4
		if code == optEndOfOpt {
			return nil
		}
		if int64(length) > MaxOptionStringBytes {
			return fmt.Errorf("%w: option length %d exceeds %d", ErrOptionLimit, length, MaxOptionStringBytes)
		}
		if int64(length) > end-offset {
			return fmt.Errorf("%w: option value length %d exceeds block boundary", ErrInvalidBlock, length)
		}
		val, err := r.Slice(offset, int64(length))
		if err != nil {
			return err
		}
		if err := fn(code, val); err != nil {
			return err
		}
		padded := int64(length)
		if rem := padded % 4; rem != 0 {
			padded += 4 - rem
		}
		offset += padded
	}
	return nil
}
