package pcap

import (
	"encoding/binary"
	"io"
)

// ExtractFlowPCAPNG writes one bidirectional IP flow from data to w. flowIndex
// uses the first-seen ordering of [Capture.Flows]. The export retains the
// interfaces used by the flow and all source name records and decryption secrets.
// A missing flow returns [ErrOutOfBounds] without writing to w.
func (c *Capture) ExtractFlowPCAPNG(data []byte, w io.Writer, flowIndex int) error {
	return c.extractFlowPCAPNG(flowExportSource{data: *NewSafeReader(data)}, w, flowIndex)
}

// ExtractFlowPCAPNGFromReaderAt writes the same packets and metadata as
// [Capture.ExtractFlowPCAPNG] from the unchanged source used to open the capture.
// Selection, block framing and copying share one [MaxReaderAtScanBytes] read
// budget. Exceeding it returns an error wrapping [ErrPacketLimit]. A missing
// flow leaves w untouched. Other errors can leave partial output.
func (c *Capture) ExtractFlowPCAPNGFromReaderAt(r io.ReaderAt, w io.Writer, flowIndex int) error {
	if r == nil {
		return ErrInvalidHeader
	}
	return c.extractFlowPCAPNG(flowExportSource{budget: &scanReadBudget{r: r, remaining: MaxReaderAtScanBytes}}, w, flowIndex)
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

func (c *Capture) extractFlowPCAPNG(source flowExportSource, w io.Writer, flowIndex int) error {
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
	observe := func(pkt *PacketRecord, frame *Frame, payload []byte) error {
		key, _ := makeCanonicalFlowKey(frame.IPProtocol, frame.SrcAddr, frame.SrcPort, frame.DstAddr, frame.DstPort)
		idx, _, err := table.lookupOrInsert(key)
		if err != nil {
			return err
		}
		if idx != flowIndex {
			return nil
		}
		found = true
		if c.Format == FormatPCAP {
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
		err = c.walkFlowPrefixes(source.budget, func(pkt PacketRecord, frame Frame, prefix []byte) error {
			return observe(&pkt, &frame, prefix)
		})
	}
	if err != nil {
		return err
	}
	if !found {
		return ErrOutOfBounds
	}
	if classic != nil {
		return nil
	}

	return source.writeSelectedBlocks(w, &used, selected)
}

func (s *flowExportSource) writeSelectedBlocks(w io.Writer, used *[MaxInterfaces]bool, selected []uint64) error {
	out := captureOutput{w: w}
	var globalID, sectionBase, packet int
	var nextID uint32
	var remap [MaxInterfaces]uint32
	var head [24]byte // Reuse scratch when rewriting a header.
	writeBlock := func(kind uint32, order binary.ByteOrder, offset, end int64) error {
		switch kind {
		case BlockTypeSectionHeader:
			sectionBase, nextID = globalID, 0
			// Filtering changes the length of sections with a declared size.
			if end-offset < 28 {
				return ErrInvalidBlock
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
		case BlockTypeEnhancedPacket, BlockTypeSimplePacket:
			i := packet
			packet++
			if i/64 >= len(selected) || selected[i/64]&(uint64(1)<<uint(i%64)) == 0 {
				return nil
			}
			// An SPB implicitly uses section interface zero, which is first
			// among the retained interfaces whenever one of its packets matches.
			if kind == BlockTypeEnhancedPacket {
				if end-offset < 32 {
					return ErrInvalidBlock
				}
				header, err := s.read(offset, 12)
				if err != nil {
					return err
				}
				id := order.Uint32(header[8:12])
				if uint64(id) >= uint64(globalID-sectionBase) {
					return ErrInvalidPacket
				}
				if s.budget == nil && remap[sectionBase+int(id)] == id {
					break
				}
				copy(head[:12], header)
				order.PutUint32(head[8:], remap[sectionBase+int(id)])
				if err := out.write(head[:12]); err != nil {
					return err
				}
				offset += 12
			}
		case BlockTypeNameResolution, BlockTypeDecryptionSecrets, BlockTypeDarwinProcessEvent:
			// Darwin process references in EPB options retain their original indices.
		default:
			return nil
		}
		for offset < end {
			n := end - offset
			if s.budget != nil {
				n = min(n, 32<<10)
			}
			block, err := s.read(offset, n)
			if err != nil {
				return err
			}
			if err := out.write(block); err != nil {
				return err
			}
			offset += n
		}
		return nil
	}
	if s.budget == nil {
		return walkPCAPNGBlockBytes(&s.data, &scanSummary{}, func(kind uint32, order binary.ByteOrder, offset int64, block []byte) error {
			return writeBlock(kind, order, offset, offset+int64(len(block)))
		})
	}
	_, err := scanPCAPNGReaderAt(s.budget, s.size, nil, writeBlock)
	return err
}
