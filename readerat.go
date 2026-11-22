package pcap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// NewFromReaderAt parses a classic PCAP or PcapNG container from an [io.ReaderAt]
// of total byte length size without loading packet payloads into memory.
func NewFromReaderAt(r io.ReaderAt, size int64) (*Capture, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: nil ReaderAt", ErrInvalidHeader)
	}
	if size < 4 {
		return nil, errNotPCAPOutOfBounds
	}
	var magicBuf [4]byte
	if err := readExactAt(r, magicBuf[:], 0, size); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotPCAP, err)
	}
	magic := binary.LittleEndian.Uint32(magicBuf[:])
	switch magic {
	case PCAPMagicMicroLE:
		return parseClassicPCAPFromReaderAt(r, size, binary.LittleEndian, false)
	case PCAPMagicMicroBE:
		return parseClassicPCAPFromReaderAt(r, size, binary.BigEndian, false)
	case PCAPMagicNanoLE:
		return parseClassicPCAPFromReaderAt(r, size, binary.LittleEndian, true)
	case PCAPMagicNanoBE:
		return parseClassicPCAPFromReaderAt(r, size, binary.BigEndian, true)
	case PCAPNGSectionHeaderMagic:
		return parsePCAPNGFromReaderAt(r, size)
	default:
		return nil, errNotPCAPInvalidMagic
	}
}

// PacketsFromReaderAt enumerates bounded packet records from an [io.ReaderAt]
// without reading packet payloads into memory.
func (c *Capture) PacketsFromReaderAt(r io.ReaderAt) ([]PacketRecord, error) {
	if err := c.validateContainer(); err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("%w: nil ReaderAt", ErrInvalidHeader)
	}
	switch c.Format {
	case FormatPCAP:
		order := binary.ByteOrder(binary.LittleEndian)
		if c.BigEndian {
			order = binary.BigEndian
		}
		_, packets, err := scanClassicPCAPReaderAt(r, c.fileSize, c.SnapLen, c.LinkType, order, c.NanoTimestamp, true, c.PacketCount)
		return packets, err
	case FormatPCAPNG:
		_, packets, err := scanPCAPNGReaderAt(r, c.fileSize, true, c.PacketCount)
		return packets, err
	default:
		return nil, ErrInvalidHeader
	}
}

// PacketPayloadFromReaderAt reads and returns a newly allocated slice containing
// pkt's captured frame bytes from r.
func (c *Capture) PacketPayloadFromReaderAt(r io.ReaderAt, pkt PacketRecord) ([]byte, error) {
	if err := c.validateContainer(); err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("%w: nil ReaderAt", ErrInvalidHeader)
	}
	if pkt.PayloadOffset < 0 || pkt.PayloadLength < 0 || pkt.PayloadLength > MaxSnapLen {
		return nil, ErrOutOfBounds
	}
	end := pkt.PayloadOffset + pkt.PayloadLength
	if end < pkt.PayloadOffset {
		return nil, ErrIntegerOverflow
	}
	if end > c.fileSize {
		return nil, ErrOutOfBounds
	}
	buf := make([]byte, pkt.PayloadLength)
	if err := readExactAt(r, buf, pkt.PayloadOffset, c.fileSize); err != nil {
		return nil, err
	}
	return buf, nil
}

func readExactAt(r io.ReaderAt, buf []byte, offset, totalSize int64) error {
	if offset < 0 || int64(len(buf)) < 0 {
		return ErrOutOfBounds
	}
	end := offset + int64(len(buf))
	if end < offset {
		return ErrIntegerOverflow
	}
	if end > totalSize {
		return ErrOutOfBounds
	}
	if len(buf) == 0 {
		return nil
	}
	n, err := r.ReadAt(buf, offset)
	if n == len(buf) {
		return nil
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return ErrOutOfBounds
	}
	if err != nil {
		return err
	}
	return ErrOutOfBounds
}

func parseClassicPCAPFromReaderAt(r io.ReaderAt, size int64, order binary.ByteOrder, nano bool) (*Capture, error) {
	if size < pcapGlobalHeaderSize {
		return nil, fmt.Errorf("%w: classic PCAP header shorter than %d bytes", ErrInvalidHeader, pcapGlobalHeaderSize)
	}
	var hdr [pcapGlobalHeaderSize]byte
	if err := readExactAt(r, hdr[:], 0, size); err != nil {
		return nil, err
	}
	vMajor := order.Uint16(hdr[4:6])
	vMinor := order.Uint16(hdr[6:8])
	if vMajor != 2 || vMinor != 4 {
		return nil, fmt.Errorf("%w: unsupported PCAP version %d.%d", ErrInvalidHeader, vMajor, vMinor)
	}
	snapLen := order.Uint32(hdr[16:20])
	if snapLen > MaxSnapLen {
		return nil, fmt.Errorf("%w: snaplen %d exceeds %d", ErrInvalidHeader, snapLen, MaxSnapLen)
	}
	linkType := LinkType(order.Uint32(hdr[20:24]) & 0xffff)

	meta, _, err := scanClassicPCAPReaderAt(r, size, snapLen, linkType, order, nano, false, 0)
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
		fileSize:       size,
		declaredExtent: meta.declaredExtent,
		anomalies:      meta.anomalies,
	}, nil
}

func scanClassicPCAPReaderAt(
	r io.ReaderAt,
	size int64,
	snapLen uint32,
	linkType LinkType,
	order binary.ByteOrder,
	nano bool,
	collect bool,
	hintCount int,
) (scanSummary, []PacketRecord, error) {
	summary := scanSummary{declaredExtent: pcapGlobalHeaderSize}
	var packets []PacketRecord
	if collect && hintCount > 0 {
		packets = make([]PacketRecord, 0, min(hintCount, MaxPackets))
	}
	var hdr [pcapPacketHeaderSize]byte
	offset := int64(pcapGlobalHeaderSize)

	for offset < size {
		remaining := size - offset
		if remaining < pcapPacketHeaderSize {
			summary.anomalies.TrailingBytes = true
			summary.declaredExtent = max(summary.declaredExtent, uint64(offset+pcapPacketHeaderSize))
			break
		}
		if err := readExactAt(r, hdr[:], offset, size); err != nil {
			return scanSummary{}, nil, err
		}
		tsSec := order.Uint32(hdr[0:4])
		tsSub := order.Uint32(hdr[4:8])
		capLen := order.Uint32(hdr[8:12])
		origLen := order.Uint32(hdr[12:16])

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
			packets = append(packets, PacketRecord{
				Index:         summary.packetCount - 1,
				InterfaceID:   0,
				LinkType:      linkType,
				TimestampNs:   int64(tsSec)*1_000_000_000 + subNs,
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

func parsePCAPNGFromReaderAt(r io.ReaderAt, size int64) (*Capture, error) {
	meta, _, err := scanPCAPNGReaderAt(r, size, false, 0)
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
		fileSize:       size,
		declaredExtent: meta.declaredExtent,
		anomalies:      meta.anomalies,
	}, nil
}

func scanPCAPNGReaderAt(r io.ReaderAt, size int64, collectPackets bool, hintCount int) (scanSummary, []PacketRecord, error) {
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
	var headerBuf [28]byte

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

		readLen := min(remaining, int64(len(headerBuf)))
		if err := readExactAt(r, headerBuf[:readLen], offset, size); err != nil {
			return scanSummary{}, nil, err
		}

		rawTypeLE := binary.LittleEndian.Uint32(headerBuf[0:4])
		if rawTypeLE == BlockTypeSectionHeader {
			if remaining < pcapngSHBMinSize {
				if !haveSection {
					return scanSummary{}, nil, fmt.Errorf("%w: truncated PcapNG section header", ErrInvalidHeader)
				}
				summary.anomalies.TruncatedPacketBlock = true
				summary.declaredExtent = max(summary.declaredExtent, uint64(offset+pcapngSHBMinSize))
				break
			}
			boMagicLE := binary.LittleEndian.Uint32(headerBuf[8:12])
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

		blockType := order.Uint32(headerBuf[0:4])
		blockLen := order.Uint32(headerBuf[4:8])
		if blockLen < pcapngMinBlockSize || blockLen > MaxSnapLen+4096 {
			return scanSummary{}, nil, fmt.Errorf("%w: invalid block length %d", ErrInvalidBlock, blockLen)
		}
		if blockLen%4 != 0 {
			summary.anomalies.UnalignedBlockLength = true
		}

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

		var trailBuf [4]byte
		if err := readExactAt(r, trailBuf[:], int64(blockEnd)-4, size); err != nil {
			return scanSummary{}, nil, err
		}
		if order.Uint32(trailBuf[:]) != blockLen {
			return scanSummary{}, nil, fmt.Errorf("%w: trailing block length mismatch", ErrInvalidBlock)
		}

		// For metadata blocks (SHB, IDB, DSB) or EPB/SPB headers+options, read only the bounded block or non-payload metadata.
		blockBytes := make([]byte, paddedLen)
		if err := readExactAt(r, blockBytes, offset, size); err != nil {
			return scanSummary{}, nil, err
		}
		sr := SafeReader{data: blockBytes, size: int64(len(blockBytes))}
		bodyStart := int64(8)
		bodyEnd := int64(paddedLen) - 4

		switch blockType {
		case BlockTypeSectionHeader:
			if err := decodeSHB(&sr, bodyStart, bodyEnd, order, &summary, &haveSection); err != nil {
				return scanSummary{}, nil, err
			}
		case BlockTypeInterfaceDesc:
			if err := decodeIDB(&sr, bodyStart, bodyEnd, order, &summary); err != nil {
				return scanSummary{}, nil, err
			}
		case BlockTypeEnhancedPacket:
			prevLen := len(packets)
			if err := decodeEPB(&sr, bodyStart, bodyEnd, order, collectPackets, &summary, &packets); err != nil {
				return scanSummary{}, nil, err
			}
			if collectPackets && len(packets) > prevLen {
				packets[len(packets)-1].PayloadOffset += offset
			}
		case BlockTypeSimplePacket:
			prevLen := len(packets)
			if err := decodeSPB(&sr, bodyStart, bodyEnd, order, collectPackets, &summary, &packets); err != nil {
				return scanSummary{}, nil, err
			}
			if collectPackets && len(packets) > prevLen {
				packets[len(packets)-1].PayloadOffset += offset
			}
		case BlockTypeDecryptionSecrets:
			prevLen := len(summary.secrets)
			if err := decodeDSB(&sr, bodyStart, bodyEnd, order, &totalSecretBytes, &summary); err != nil {
				return scanSummary{}, nil, err
			}
			if len(summary.secrets) > prevLen {
				summary.secrets[len(summary.secrets)-1].PayloadOffset += offset
			}
		}

		offset = int64(blockEnd)
	}

	return summary, packets, nil
}
