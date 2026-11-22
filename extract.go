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
	if err := c.validateContainer(); err != nil {
		return err
	}
	if flowIndex < 0 || flowIndex >= MaxFlows {
		return ErrOutOfBounds
	}
	if w == nil {
		return ErrInvalidHeader
	}

	var table flowIndexTable
	var target flowKey
	var found bool
	var classic *PCAPNGWriter
	var used [MaxInterfaces]bool
	var selected []uint64
	r := NewSafeReader(data)
	err := c.walkPackets(r, func(pkt PacketRecord) error {
		payload, err := r.Slice(pkt.PayloadOffset, pkt.PayloadLength)
		if err != nil {
			return err
		}
		frame, err := DecodeFrame(payload, pkt.LinkType)
		if err != nil || frame.IPVersion == 0 {
			return nil
		}
		key, _ := makeCanonicalFlowKey(frame.IPProtocol, frame.SrcAddr, frame.SrcPort, frame.DstAddr, frame.DstPort)
		if !found {
			idx, _, err := table.lookupOrInsert(key)
			if err != nil {
				return err
			}
			if idx != flowIndex {
				return nil
			}
			target, found = key, true
		} else if key != target {
			return nil
		}
		if c.Format == FormatPCAP {
			if classic == nil {
				classic, err = newPCAPNGWriter(w, PCAPNGWriterOptions{LinkType: c.LinkType, SnapLen: c.SnapLen})
				if err != nil {
					return err
				}
			}
			return classic.WritePacket(pkt, payload)
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
	})
	if err != nil {
		return err
	}
	if !found {
		return ErrOutOfBounds
	}
	if classic != nil {
		return nil
	}

	out := captureOutput{w: w}
	var globalID, sectionBase, packet int
	var nextID uint32
	var remap [MaxInterfaces]uint32
	var head [24]byte // Reuse scratch when rewriting a header.
	return walkPCAPNGBlockBytes(r, &scanSummary{}, func(kind uint32, order binary.ByteOrder, _ int64, block []byte) error {
		switch kind {
		case BlockTypeSectionHeader:
			sectionBase, nextID = globalID, 0
			// Filtering changes the length of sections with a declared size.
			if order.Uint64(block[16:24]) != ^uint64(0) {
				copy(head[:], block[:24])
				order.PutUint64(head[16:], ^uint64(0))
				if err := out.write(head[:]); err != nil {
					return err
				}
				block = block[24:]
			}
		case BlockTypeInterfaceDesc:
			id := globalID
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
				id := order.Uint32(block[8:12])
				mapped := remap[sectionBase+int(id)]
				if id != mapped {
					copy(head[:], block[:12])
					order.PutUint32(head[8:], mapped)
					if err := out.write(head[:12]); err != nil {
						return err
					}
					block = block[12:]
				}
			}
		case BlockTypeNameResolution, BlockTypeDecryptionSecrets, BlockTypeDarwinProcessEvent:
			// Darwin process references in EPB options retain their original indices.
		default:
			return nil
		}
		return out.write(block)
	})
}
