package pcap

import (
	"encoding/binary"
	"io"
)

// ExtractFlowPCAPNG writes one bidirectional IP flow from data to w. flowIndex
// uses the first-seen ordering of [Capture.Flows]. The export retains the
// interfaces used by the flow and all source name records, Darwin process
// entries and decryption secrets.
// A missing flow returns [ErrOutOfBounds] without writing to w.
func (c *Capture) ExtractFlowPCAPNG(data []byte, w io.Writer, flowIndex int) error {
	return c.extractFlowPCAPNG(flowExportSource{data: *NewSafeReader(data)}, w, flowIndex, false)
}

// ExtractFlowPCAPNGFromReaderAt writes the same packets and metadata as
// [Capture.ExtractFlowPCAPNG] from the unchanged source used to open the capture.
// Selection, block framing and copying share one [MaxReaderAtScanBytes] read
// budget. Exceeding it returns an error wrapping [ErrPacketLimit]. A missing
// flow leaves w untouched. Other errors can leave partial output.
func (c *Capture) ExtractFlowPCAPNGFromReaderAt(r io.ReaderAt, w io.Writer, flowIndex int) error {
	return c.extractFlowPCAPNGFromReaderAt(r, w, flowIndex, false)
}

// ExtractFlowPacketsPCAPNG writes one bidirectional IP flow from the unchanged
// source data to w. flowIndex uses the first-seen ordering of [Capture.Flows].
// The export retains packet bytes, lengths, timestamps, and the interface
// and frame check sequence information needed to read them. It omits other
// capture and packet metadata. Packet headers and payloads still contain
// the original endpoints and application data.
// A missing flow returns [ErrOutOfBounds] without writing to w. Other errors
// can leave partial output.
func (c *Capture) ExtractFlowPacketsPCAPNG(data []byte, w io.Writer, flowIndex int) error {
	return c.extractFlowPCAPNG(flowExportSource{data: *NewSafeReader(data)}, w, flowIndex, true)
}

// ExtractFlowPacketsPCAPNGFromReaderAt writes the same output as
// [Capture.ExtractFlowPacketsPCAPNG] from the unchanged source used to open
// the capture. Selection, framing, and copying share one [MaxReaderAtScanBytes]
// budget. Exceeding it returns an error wrapping [ErrPacketLimit]. A missing
// flow leaves w untouched. Other errors can leave partial output.
func (c *Capture) ExtractFlowPacketsPCAPNGFromReaderAt(r io.ReaderAt, w io.Writer, flowIndex int) error {
	return c.extractFlowPCAPNGFromReaderAt(r, w, flowIndex, true)
}

func (c *Capture) extractFlowPCAPNGFromReaderAt(r io.ReaderAt, w io.Writer, flowIndex int, packetOnly bool) error {
	if r == nil {
		return ErrInvalidHeader
	}
	return c.extractFlowPCAPNG(flowExportSource{budget: &scanReadBudget{r: r, remaining: MaxReaderAtScanBytes}}, w, flowIndex, packetOnly)
}

type flowExportSource struct {
	data    SafeReader
	budget  *scanReadBudget
	size    int64
	scratch []byte
}

func (s *flowExportSource) read(offset, length int64) ([]byte, error) {
	if s.budget == nil {
		return s.data.Slice(offset, length)
	}
	if err := s.budget.check(length); err != nil {
		return nil, err
	}
	if int64(cap(s.scratch)) < length {
		s.scratch = make([]byte, length)
	}
	buf := s.scratch[:length]
	return buf, readExactAt(s.budget, buf, offset, s.size)
}

func (s *flowExportSource) copyRange(out *captureOutput, offset, end int64) error {
	for offset < end {
		n := end - offset
		if s.budget != nil {
			n = min(n, 32<<10)
		}
		data, err := s.read(offset, n)
		if err != nil {
			return err
		}
		if err := out.write(data); err != nil {
			return err
		}
		offset += n
	}
	return nil
}

func (c *Capture) extractFlowPCAPNG(source flowExportSource, w io.Writer, flowIndex int, packetOnly bool) error {
	if err := c.validateContainer(); err != nil {
		return err
	}
	if flowIndex < 0 || flowIndex >= MaxFlows {
		return ErrOutOfBounds
	}
	if w == nil {
		return ErrInvalidHeader
	}
	if source.budget != nil && c.PacketCount == 0 {
		return ErrOutOfBounds
	}

	var table flowIndexTable
	var found bool
	var classic *PCAPNGWriter
	var used [MaxInterfaces]bool
	var selected []uint64
	source.size = c.fileSize
	packets := packetOnlyFlowWriter{out: captureOutput{w: w}, order: binary.LittleEndian}
	if c.BigEndian {
		packets.order = binary.BigEndian
	}
	observe := func(pkt *PacketRecord, frame *Frame, payload []byte) error {
		key, _ := makeCanonicalFlowKey(frame.IPProtocol, frame.SrcAddr, frame.SrcPort, frame.DstAddr, frame.DstPort)
		idx, _, err := table.lookupOrInsert(key)
		if err != nil {
			return err
		}
		if idx != flowIndex {
			return nil
		}
		first := !found
		found = true
		if c.Format == FormatPCAP {
			if packetOnly {
				return packets.writeClassicPacket(&source, c, pkt, payload, first)
			}
			if classic == nil {
				classic, err = newPCAPNGWriter(w, PCAPNGWriterOptions{LinkType: c.LinkType, SnapLen: c.SnapLen})
				if err != nil {
					return err
				}
			}
			if int64(len(payload)) < pkt.PayloadLength {
				payload, err = source.read(pkt.PayloadOffset, pkt.PayloadLength)
				if err != nil {
					return err
				}
			}
			return classic.WritePacket(*pkt, payload)
		}
		// The block pass can copy the original timestamps, options and payloads
		// directly. At MaxPackets the selection needs only 128 KiB.
		word := pkt.Index / 64
		if word >= len(selected) {
			selected = append(selected, make([]uint64, word+1-len(selected))...)
		}
		selected[word] |= uint64(1) << uint(pkt.Index%64)
		used[pkt.InterfaceID] = true
		return nil
	}
	var err error
	if source.budget == nil {
		err = c.walkPackets(&source.data, func(pkt PacketRecord) error {
			payload, err := source.data.Slice(pkt.PayloadOffset, pkt.PayloadLength)
			if err != nil {
				return err
			}
			frame, err := DecodeFrame(payload, pkt.LinkType)
			if err != nil || frame.IPVersion == 0 {
				return nil
			}
			return observe(&pkt, &frame, payload)
		})
	} else {
		err = c.walkFlowPrefixes(source.budget, false, func(pkt PacketRecord, frame Frame, prefix []byte) error {
			return observe(&pkt, &frame, prefix)
		})
	}
	if err != nil {
		return err
	}
	if !found {
		return ErrOutOfBounds
	}
	if c.Format == FormatPCAP {
		return nil
	}

	return source.writeSelectedBlocks(w, &used, selected, packetOnly)
}

func (s *flowExportSource) writeSelectedBlocks(w io.Writer, used *[MaxInterfaces]bool, selected []uint64, packetOnly bool) error {
	out := captureOutput{w: w}
	var globalID, sectionBase, packet int
	var nextID, spbSnapLen uint32
	var sectionOffset int64
	var remap [MaxInterfaces]uint32
	var head [24]byte // Reuse scratch when rewriting a header.
	writeBlock := func(kind uint32, order binary.ByteOrder, offset, end int64) error {
		packets := packetOnlyFlowWriter{out: out, order: order}
		switch kind {
		case BlockTypeSectionHeader:
			sectionBase, nextID = globalID, 0
			// Filtering changes the length of sections with a declared size.
			if end-offset < pcapngSHBMinSize {
				return ErrInvalidBlock
			}
			if packetOnly {
				sectionOffset = offset
				return nil
			}
			header, err := s.read(offset, 24)
			if err != nil {
				return err
			}
			if s.budget == nil && order.Uint64(header[16:24]) == ^uint64(0) {
				break
			}
			copy(head[:], header)
			order.PutUint64(head[16:], ^uint64(0))
			if err := out.write(head[:]); err != nil {
				return err
			}
			offset += 24
		case BlockTypeInterfaceDesc:
			id := globalID
			if id >= MaxInterfaces {
				return ErrInterfaceLimit
			}
			globalID++
			if !used[id] {
				return nil
			}
			remap[id] = nextID
			nextID++
			if packetOnly {
				if nextID == 1 {
					version, err := s.read(sectionOffset+12, 4)
					if err != nil {
						return err
					}
					if err := packets.writeSection(order.Uint16(version), order.Uint16(version[2:])); err != nil {
						return err
					}
				}
				snapLen, err := packets.writeSourceInterface(s, offset+8, end-4)
				if id == sectionBase {
					spbSnapLen = snapLen
				}
				return err
			}
		case blockTypeLegacyPacket, BlockTypeEnhancedPacket, BlockTypeSimplePacket:
			i := packet
			packet++
			if i/64 >= len(selected) || selected[i/64]&(uint64(1)<<uint(i%64)) == 0 {
				return nil
			}
			// An SPB implicitly uses section interface zero, which is first
			// among the retained interfaces whenever one of its packets matches.
			if kind == BlockTypeSimplePacket && packetOnly {
				if end-offset < pcapngSPBMinSize || globalID == sectionBase || !used[sectionBase] {
					return ErrInvalidBlock
				}
				fixed, err := s.read(offset+8, 4)
				if err != nil {
					return err
				}
				length := order.Uint32(fixed)
				if spbSnapLen != 0 {
					length = min(length, spbSnapLen)
				}
				return packets.writeSourcePacket(s, kind, fixed, offset+12, end-4, length)
			}
			if kind != BlockTypeSimplePacket {
				if end-offset < pcapngPacketBlockMinSize {
					return ErrInvalidBlock
				}
				headerStart, headerLen := int64(0), int64(12)
				if packetOnly {
					headerStart, headerLen = 8, 20
				}
				header, err := s.read(offset+headerStart, headerLen)
				if err != nil {
					return err
				}
				fields := header[8-headerStart:]
				id := order.Uint32(fields)
				if kind == blockTypeLegacyPacket {
					id = uint32(order.Uint16(fields))
				}
				if uint64(id) >= uint64(globalID-sectionBase) {
					return ErrInvalidPacket
				}
				newID := remap[sectionBase+int(id)]
				if packetOnly {
					// Keep the fixed fields across the options read, which reuses s.scratch.
					fixed := head[:20]
					copy(fixed, fields)
					if kind == blockTypeLegacyPacket {
						order.PutUint16(fixed[:2], uint16(newID))
						order.PutUint16(fixed[2:4], 0xffff) // Drop count unavailable.
					} else {
						order.PutUint32(fixed[:4], newID)
					}
					return packets.writeSourcePacket(s, kind, fixed, offset+28, end-4, order.Uint32(fixed[12:16]))
				}
				if s.budget == nil && newID == id {
					break
				}
				copy(head[:12], header)
				if kind == blockTypeLegacyPacket {
					order.PutUint16(head[8:10], uint16(newID))
				} else {
					order.PutUint32(head[8:12], newID)
				}
				if err := out.write(head[:12]); err != nil {
					return err
				}
				offset += 12
			}
		case BlockTypeNameResolution, BlockTypeDecryptionSecrets, BlockTypeDarwinProcessEvent:
			if packetOnly {
				return nil
			}
			// Keep Darwin process blocks in their original section order so
			// primary and effective process references retain their indices.
		default:
			return nil
		}
		return s.copyRange(&out, offset, end)
	}
	if s.budget == nil {
		return walkPCAPNGBlockBytes(&s.data, &scanSummary{}, func(kind uint32, order binary.ByteOrder, offset int64, block []byte) error {
			return writeBlock(kind, order, offset, offset+int64(len(block)))
		})
	}
	_, err := scanPCAPNGReaderAt(s.budget, s.size, nil, writeBlock)
	return err
}
