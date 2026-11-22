package pcap

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"os"
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
	// when TimestampsBinary is false (default 1,000 for microsecond resolution,
	// 1 for nanosecond resolution).
	TimestampScaleNs uint64
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
	TruncatedPacketBlock      bool
	CaptureLenExceedsOriginal bool
	CaptureLenExceedsSnapLen  bool
	UnknownLinkType           bool
	TrailingBytes             bool
	UnalignedBlockLength      bool
}

// Any reports whether any container anomaly was detected.
func (a CaptureAnomalies) Any() bool {
	return a.TruncatedPacketBlock ||
		a.CaptureLenExceedsOriginal ||
		a.CaptureLenExceedsSnapLen ||
		a.UnknownLinkType ||
		a.TrailingBytes ||
		a.UnalignedBlockLength
}

// PacketRecord describes one captured packet's metadata and payload byte span
// within the capture buffer.
type PacketRecord struct {
	Index         int
	InterfaceID   uint32
	LinkType      LinkType
	TimestampNs   int64
	CaptureLen    uint32
	OriginalLen   uint32
	PayloadOffset int64
	PayloadLength int64

	// PcapNG Enhanced Packet Block optional metadata.
	ProcessID    uint32
	ThreadID     uint32
	Flags        uint32
	DropCount    uint64
	HasProcessID bool
	HasThreadID  bool
}

// Capture contains a parsed snapshot of a PCAP or PcapNG container's headers,
// interfaces, decryption secrets, and extent metadata.
// If you don't modify its exported fields, you can read a Capture concurrently.
type Capture struct {
	Format        Format
	BigEndian     bool
	NanoTimestamp bool
	VersionMajor  uint16
	VersionMinor  uint16
	SnapLen       uint32
	LinkType      LinkType
	Hardware      string
	OS            string
	UserAppl      string
	Interfaces    []InterfaceDescriptor
	Secrets       []DecryptionSecret
	PacketCount   int

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

// Packets enumerates bounded packet records in file order from the original
// bytes passed to [New]. It does not copy packet payloads; use
// [Capture.PacketPayload] to slice a packet's bytes from data.
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
		_, packets, err := scanClassicPCAPPackets(&r, c.SnapLen, c.LinkType, order, c.NanoTimestamp, true, c.PacketCount)
		return packets, err
	case FormatPCAPNG:
		_, packets, err := scanPCAPNGBlocks(&r, true, c.PacketCount)
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

	meta, _, err := scanClassicPCAPPackets(r, snapLen, linkType, order, nano, false, 0)
	if err != nil {
		return nil, err
	}
	if !isKnownLinkType(linkType) {
		meta.anomalies.UnknownLinkType = true
	}

	scaleNs := uint64(1_000)
	if nano {
		scaleNs = 1
	}

	return &Capture{
		Format:        FormatPCAP,
		BigEndian:     order == binary.BigEndian,
		NanoTimestamp: nano,
		VersionMajor:  vMajor,
		VersionMinor:  vMinor,
		SnapLen:       snapLen,
		LinkType:      linkType,
		Interfaces: []InterfaceDescriptor{{
			ID:               0,
			LinkType:         linkType,
			SnapLen:          snapLen,
			TimestampScaleNs: scaleNs,
		}},
		PacketCount:    meta.packetCount,
		fileSize:       fileSize,
		declaredExtent: meta.declaredExtent,
		anomalies:      meta.anomalies,
	}, nil
}

type scanSummary struct {
	packetCount    int
	declaredExtent uint64
	anomalies      CaptureAnomalies
	bigEndian      bool
	vMajor         uint16
	vMinor         uint16
	hardware       string
	os             string
	userAppl       string
	interfaces     []InterfaceDescriptor
	secrets        []DecryptionSecret
}

func scanClassicPCAPPackets(
	r *SafeReader,
	snapLen uint32,
	linkType LinkType,
	order binary.ByteOrder,
	nano bool,
	collect bool,
	hintCount int,
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

		if collect {
			subNs := int64(tsSub) * 1_000
			if nano {
				subNs = int64(tsSub)
			}
			tsNs := int64(tsSec)*1_000_000_000 + subNs
			packets = append(packets, PacketRecord{
				Index:         summary.packetCount - 1,
				InterfaceID:   0,
				LinkType:      linkType,
				TimestampNs:   tsNs,
				CaptureLen:    capLen,
				OriginalLen:   origLen,
				PayloadOffset: payloadOffset,
				PayloadLength: int64(capLen),
			})
		}

		offset = int64(recordEnd)
	}

	return summary, packets, nil
}

func parsePCAPNG(r *SafeReader, fileSize int64) (*Capture, error) {
	meta, _, err := scanPCAPNGBlocks(r, false, 0)
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
		PacketCount:    meta.packetCount,
		fileSize:       fileSize,
		declaredExtent: meta.declaredExtent,
		anomalies:      meta.anomalies,
	}, nil
}

func scanPCAPNGBlocks(r *SafeReader, collectPackets bool, hintCount int) (scanSummary, []PacketRecord, error) {
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
		case BlockTypeEnhancedPacket:
			if err := decodeEPB(r, bodyStart, bodyEnd, order, collectPackets, &summary, &packets); err != nil {
				return scanSummary{}, nil, err
			}
		case BlockTypeSimplePacket:
			if err := decodeSPB(r, bodyStart, bodyEnd, order, collectPackets, &summary, &packets); err != nil {
				return scanSummary{}, nil, err
			}
		case BlockTypeDecryptionSecrets:
			if err := decodeDSB(r, bodyStart, bodyEnd, order, &totalSecretBytes, &summary); err != nil {
				return scanSummary{}, nil, err
			}
		default:
			// Other blocks (NRB, ISB, vendor custom blocks) are skipped after framing validation.
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
		ID:               uint32(len(summary.interfaces)),
		LinkType:         LinkType(rawLink),
		SnapLen:          snapLen,
		TimestampScaleNs: defaultTimestampResolN,
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
				if scale, ok := parseTimestampResolutionNs(val[0]); ok {
					iface.TimestampScaleNs = scale
				}
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

func parseTimestampResolutionNs(resol uint8) (uint64, bool) {
	if resol&0x80 != 0 {
		// Binary power-of-two resolution is left at default microsecond scale in MVP.
		return defaultTimestampResolN, false
	}
	exp := resol & 0x7f
	if exp > 9 {
		return 1, true
	}
	scale := uint64(1)
	for range 9 - exp {
		scale *= 10
	}
	return scale, true
}

func decodeEPB(
	r *SafeReader,
	bodyStart, bodyEnd int64,
	order binary.ByteOrder,
	collect bool,
	summary *scanSummary,
	packets *[]PacketRecord,
) error {
	if bodyEnd-bodyStart < 20 {
		return fmt.Errorf("%w: Enhanced Packet Block body too short", ErrInvalidBlock)
	}
	ifaceID, _ := r.ReadUint32Order(bodyStart, order)
	if int(ifaceID) >= len(summary.interfaces) {
		return fmt.Errorf("%w: EPB interface ID %d out of range (%d interfaces)", ErrInvalidPacket, ifaceID, len(summary.interfaces))
	}
	iface := summary.interfaces[ifaceID]

	tsHigh, _ := r.ReadUint32Order(bodyStart+4, order)
	tsLow, _ := r.ReadUint32Order(bodyStart+8, order)
	capLen, _ := r.ReadUint32Order(bodyStart+12, order)
	origLen, _ := r.ReadUint32Order(bodyStart+16, order)

	if capLen > MaxSnapLen {
		return fmt.Errorf("%w: EPB capture length %d exceeds %d", ErrInvalidPacket, capLen, MaxSnapLen)
	}
	if capLen > origLen {
		summary.anomalies.CaptureLenExceedsOriginal = true
	}
	if iface.SnapLen > 0 && capLen > iface.SnapLen {
		summary.anomalies.CaptureLenExceedsSnapLen = true
	}

	payloadOffset := bodyStart + 20
	paddedCapLen := int64(capLen)
	if rem := paddedCapLen % 4; rem != 0 {
		paddedCapLen += 4 - rem
	}
	optOffset := payloadOffset + paddedCapLen
	if optOffset > bodyEnd || payloadOffset+int64(capLen) > bodyEnd {
		return fmt.Errorf("%w: EPB capture length %d exceeds block body", ErrInvalidBlock, capLen)
	}

	if summary.packetCount >= MaxPackets {
		return fmt.Errorf("%w: exceeds %d", ErrPacketLimit, MaxPackets)
	}
	summary.packetCount++

	var pid, tid, flags uint32
	var dropCount uint64
	var hasPID, hasTID bool
	if optOffset < bodyEnd {
		err := walkPCAPNGOptions(r, optOffset, bodyEnd, order, func(code uint16, val []byte) error {
			switch code {
			case optEPBFlags:
				if len(val) == 4 {
					flags = order.Uint32(val)
				}
			case optEPBDropCount:
				if len(val) == 8 {
					dropCount = order.Uint64(val)
				}
			case optEPBProcessID:
				if len(val) == 4 {
					pid = order.Uint32(val)
					hasPID = true
				}
			case optEPBThreadID:
				if len(val) == 4 {
					tid = order.Uint32(val)
					hasTID = true
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}

	if collect {
		rawTicks := (uint64(tsHigh) << 32) | uint64(tsLow)
		scale := iface.TimestampScaleNs
		if scale == 0 {
			scale = defaultTimestampResolN
		}
		var tsNs int64
		if rawTicks <= uint64(math.MaxInt64)/scale {
			tsNs = int64(rawTicks * scale)
		} else {
			tsNs = math.MaxInt64
		}
		*packets = append(*packets, PacketRecord{
			Index:         summary.packetCount - 1,
			InterfaceID:   ifaceID,
			LinkType:      iface.LinkType,
			TimestampNs:   tsNs,
			CaptureLen:    capLen,
			OriginalLen:   origLen,
			PayloadOffset: payloadOffset,
			PayloadLength: int64(capLen),
			ProcessID:     pid,
			ThreadID:      tid,
			Flags:         flags,
			DropCount:     dropCount,
			HasProcessID:  hasPID,
			HasThreadID:   hasTID,
		})
	}

	return nil
}

func decodeSPB(
	r *SafeReader,
	bodyStart, bodyEnd int64,
	order binary.ByteOrder,
	collect bool,
	summary *scanSummary,
	packets *[]PacketRecord,
) error {
	if bodyEnd-bodyStart < 4 {
		return fmt.Errorf("%w: Simple Packet Block body too short", ErrInvalidBlock)
	}
	if len(summary.interfaces) == 0 {
		return fmt.Errorf("%w: Simple Packet Block requires interface 0", ErrInvalidPacket)
	}
	iface := summary.interfaces[0]
	origLen, _ := r.ReadUint32Order(bodyStart, order)
	payloadOffset := bodyStart + 4
	avail := bodyEnd - payloadOffset
	capLen := origLen
	if iface.SnapLen > 0 && capLen > iface.SnapLen {
		capLen = iface.SnapLen
	}
	if int64(capLen) > avail {
		return fmt.Errorf("%w: Simple Packet Block payload exceeds block body", ErrInvalidBlock)
	}
	if capLen > MaxSnapLen {
		return fmt.Errorf("%w: SPB capture length %d exceeds %d", ErrInvalidPacket, capLen, MaxSnapLen)
	}
	if summary.packetCount >= MaxPackets {
		return fmt.Errorf("%w: exceeds %d", ErrPacketLimit, MaxPackets)
	}
	summary.packetCount++

	if collect {
		*packets = append(*packets, PacketRecord{
			Index:         summary.packetCount - 1,
			InterfaceID:   0,
			LinkType:      iface.LinkType,
			CaptureLen:    capLen,
			OriginalLen:   origLen,
			PayloadOffset: payloadOffset,
			PayloadLength: int64(capLen),
		})
	}
	return nil
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
