package pcap

import (
	"bytes"
	"encoding/binary"
)

type packetOnlyFlowWriter struct {
	out   captureOutput
	order binary.ByteOrder
}

func (w *packetOnlyFlowWriter) writeSection(major, minor uint16) error {
	var fixed [16]byte
	w.order.PutUint32(fixed[0:4], PCAPNGByteOrderMagic)
	w.order.PutUint16(fixed[4:6], major)
	w.order.PutUint16(fixed[6:8], minor)
	w.order.PutUint64(fixed[8:16], ^uint64(0)) // Unspecified section length.
	return w.writeBlock(nil, BlockTypeSectionHeader, fixed[:], nil, nil, 0, 0)
}

func (w *packetOnlyFlowWriter) writeInterface(link, snapLen uint32, resolution byte, offset [8]byte, fcsLen []byte) error {
	var fixed [8]byte
	w.order.PutUint16(fixed[0:2], uint16(link))
	w.order.PutUint32(fixed[4:8], snapLen)
	var options bytes.Buffer
	if resolution != 6 { // Microseconds are the default.
		writePCAPNGOption(&options, w.order, optIDBTsResol, []byte{resolution})
	}
	if offset != [8]byte{} {
		writePCAPNGOption(&options, w.order, optIDBTsOffset, offset[:])
	}
	if len(fcsLen) == 1 {
		writePCAPNGOption(&options, w.order, optIDBFCSLen, fcsLen)
	}
	if options.Len() != 0 {
		writePCAPNGOption(&options, w.order, optEndOfOpt, nil)
	}
	return w.writeBlock(nil, BlockTypeInterfaceDesc, fixed[:], options.Bytes(), nil, 0, 0)
}

func (w *packetOnlyFlowWriter) writeSourceInterface(source *flowExportSource, start, end int64) (uint32, error) {
	if end-start < 8 {
		return 0, ErrInvalidBlock
	}
	body, err := source.readMetadata(w.order, BlockTypeInterfaceDesc, start, end)
	if err != nil {
		return 0, err
	}
	var offset [8]byte
	var fcsLen []byte
	resolution := byte(6)
	err = walkPCAPNGOptions(body[8:], w.order, func(code uint16, val []byte) error {
		switch code {
		case optIDBTsResol:
			if len(val) == 1 {
				resolution = val[0]
			}
		case optIDBTsOffset:
			if len(val) == 8 {
				copy(offset[:], val)
			}
		case optIDBFCSLen:
			if len(val) == 1 {
				fcsLen = val
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	link, snapLen := w.order.Uint16(body[:2]), w.order.Uint32(body[4:8])
	return snapLen, w.writeInterface(uint32(link), snapLen, resolution, offset, fcsLen)
}

func (w *packetOnlyFlowWriter) writeSourcePacket(source *flowExportSource, kind uint32, fixed []byte, payloadOffset, bodyEnd int64, length uint32) error {
	payloadLength := int64(length)
	optionsStart := payloadOffset + ((payloadLength + 3) &^ 3)
	if length > MaxSnapLen || optionsStart > bodyEnd {
		return ErrInvalidBlock
	}
	var options bytes.Buffer
	if kind != BlockTypeSimplePacket && optionsStart < bodyEnd {
		body, err := source.readMetadata(w.order, kind, optionsStart, bodyEnd)
		if err != nil {
			return err
		}
		var flags uint32
		err = walkPCAPNGOptions(body, w.order, func(code uint16, val []byte) error {
			if code == optEPBFlags && len(val) == 4 {
				const fcsLenMask = 0xf << 5 // FCS length in octets (bits 5–8).
				flags = w.order.Uint32(val) & fcsLenMask
			}
			return nil
		})
		if err != nil {
			return err
		}
		if flags != 0 {
			var value [4]byte
			w.order.PutUint32(value[:], flags)
			writePCAPNGOption(&options, w.order, optEPBFlags, value[:])
			writePCAPNGOption(&options, w.order, optEndOfOpt, nil)
		}
	}
	return w.writeBlock(source, kind, fixed, options.Bytes(), nil, payloadOffset, payloadLength)
}

func (s *flowExportSource) readMetadata(order binary.ByteOrder, kind uint32, start, end int64) ([]byte, error) {
	if s.budget != nil && end-start > metadataWindowSize {
		// Read only bounded options before the end marker, even when the
		// input block has a large padding region after it.
		return readLargeMetadata(s.budget, start, end, kind, order, nil, 0)
	}
	return s.read(start, end-start)
}

func (w *packetOnlyFlowWriter) writeClassicPacket(source *flowExportSource, c *Capture, pkt *PacketRecord, payload []byte, first bool) error {
	ticks := uint64(pkt.TimestampNs)
	resolution := byte(9)
	if !c.NanoTimestamp {
		resolution = 6
		ticks /= 1_000
	}
	if first {
		header, err := source.read(20, 4)
		if err != nil {
			return err
		}
		var fcsLen []byte
		link := w.order.Uint32(header)
		if link&(1<<26) != 0 { // The classic PCAP link type field includes an FCS length.
			fcsLen = []byte{byte(link>>28) * 16} // Convert 16-bit words to bits.
		}
		if err := w.writeSection(1, 0); err != nil {
			return err
		}
		if err := w.writeInterface(uint32(c.LinkType), c.SnapLen, resolution, [8]byte{}, fcsLen); err != nil {
			return err
		}
	}
	var fixed [20]byte
	w.order.PutUint32(fixed[4:8], uint32(ticks>>32))
	w.order.PutUint32(fixed[8:12], uint32(ticks))
	w.order.PutUint32(fixed[12:16], pkt.CaptureLen)
	w.order.PutUint32(fixed[16:20], pkt.OriginalLen)
	return w.writeBlock(source, BlockTypeEnhancedPacket, fixed[:], nil, payload, pkt.PayloadOffset, pkt.PayloadLength)
}

// writeBlock writes only the supplied fields and emits fresh zero padding.
// A prefix, when supplied, contains bytes already read during classic selection.
func (w *packetOnlyFlowWriter) writeBlock(source *flowExportSource, kind uint32, fixed, options, prefix []byte, payloadOffset, payloadLength int64) error {
	padding := -payloadLength & 3
	length := uint32(12 + int64(len(fixed)+len(options)) + payloadLength + padding)
	var header [28]byte
	w.order.PutUint32(header[0:4], kind)
	w.order.PutUint32(header[4:8], length)
	copy(header[8:], fixed)
	if err := w.out.write(header[:8+len(fixed)]); err != nil {
		return err
	}
	if len(prefix) != 0 {
		if err := w.out.write(prefix); err != nil {
			return err
		}
	}
	if int64(len(prefix)) < payloadLength {
		if err := source.copyRange(&w.out, payloadOffset+int64(len(prefix)), payloadOffset+payloadLength); err != nil {
			return err
		}
	}
	var tail [7]byte
	if len(options) != 0 {
		if padding != 0 {
			if err := w.out.write(tail[:padding]); err != nil {
				return err
			}
		}
		if err := w.out.write(options); err != nil {
			return err
		}
		padding = 0
	}
	w.order.PutUint32(tail[padding:], length)
	return w.out.write(tail[:padding+4])
}
