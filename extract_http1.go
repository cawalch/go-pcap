package pcap

import (
	"encoding/binary"
	"errors"
	"io"
)

// HTTP1TransactionID identifies an HTTP/1 request in its original capture.
// PacketIndex and PacketPayloadOffset are zero-based. PacketPayloadOffset
// counts bytes from the start of the packet's TCP payload.
type HTTP1TransactionID struct {
	PacketIndex, PacketPayloadOffset int
}

// ID returns the location of the request line's first byte in the capture.
func (t HTTP1Transaction) ID() HTTP1TransactionID {
	return HTTP1TransactionID{PacketIndex: t.Request.PacketIndex, PacketPayloadOffset: t.Request.PacketPayloadOffset}
}

// ExtractHTTP1TransactionPCAPNG writes the original packets of transaction id
// from the unchanged source data to w. For a confirmed response the export
// also includes earlier packets needed to reconstruct the HTTP exchange. For
// an unconfirmed response it retains the request side, including earlier
// request packets when a shared frame needs them to recover the boundary.
//
// The export retains capture order, packet bytes, lengths, timestamps, and
// interface and frame check sequence information. It omits other capture and
// packet metadata, including decryption secrets. Earlier messages and messages
// sharing an exported packet can expose application data beyond this transaction.
// A missing or invalid id returns [ErrOutOfBounds] without writing to w. Other
// errors can leave partial output.
func (c *Capture) ExtractHTTP1TransactionPCAPNG(data []byte, w io.Writer, id HTTP1TransactionID) error {
	return c.extractHTTP1TransactionPCAPNG(flowExportSource{data: *NewSafeReader(data)}, w, id)
}

// ExtractHTTP1TransactionPCAPNGFromReaderAt writes the same output as
// [Capture.ExtractHTTP1TransactionPCAPNG] from the unchanged source used to open
// the capture. Selection, framing, and copying share one [MaxReaderAtScanBytes]
// budget. Exceeding it returns an error wrapping [ErrPacketLimit]. A missing or
// invalid id leaves w untouched. Other errors can leave partial output.
func (c *Capture) ExtractHTTP1TransactionPCAPNGFromReaderAt(r io.ReaderAt, w io.Writer, id HTTP1TransactionID) error {
	if r == nil {
		return ErrInvalidHeader
	}
	return c.extractHTTP1TransactionPCAPNG(flowExportSource{budget: &scanReadBudget{r: r, remaining: MaxReaderAtScanBytes}}, w, id)
}

type http1TransactionExportSelection struct {
	id            HTTP1TransactionID
	packetIndices []int // Sorted by original capture packet index.
	interfaces    map[int]uint32
}

func (c *Capture) extractHTTP1TransactionPCAPNG(source flowExportSource, w io.Writer, id HTTP1TransactionID) error {
	if err := c.validateContainer(); err != nil {
		return err
	}
	if id.PacketIndex < 0 || id.PacketIndex >= min(c.PacketCount, MaxPackets) ||
		id.PacketPayloadOffset < 0 || id.PacketPayloadOffset >= MaxSnapLen {
		return ErrOutOfBounds
	}
	if w == nil {
		return ErrInvalidHeader
	}
	source.size = c.fileSize
	frames := ipFrameSource{capture: c, data: source.data.data}
	if source.budget != nil {
		// Charge selection reads to the same budget as framing and copying.
		frames.reader = source.budget
		frames.needsPayload = func(f Frame, _ []byte) bool { return f.IPProtocol == IPProtoTCP }
	}
	selection := http1TransactionExportSelection{id: id}
	if c.Format == FormatPCAPNG && len(c.Interfaces) > 1 {
		selection.interfaces = make(map[int]uint32)
	}
	if _, err := scanHTTP1Transactions(frames, &selection); err != nil {
		return err
	}
	indices := selection.packetIndices
	if len(indices) == 0 {
		return ErrOutOfBounds
	}
	if c.Format == FormatPCAP {
		return c.writeSelectedClassicPackets(&source, w, indices)
	}
	var used [MaxInterfaces]bool
	selected := make([]uint64, indices[len(indices)-1]/64+1)
	for _, index := range indices {
		selected[index/64] |= uint64(1) << uint(index%64)
		used[selection.interfaces[index]] = true
	}
	return source.writeSelectedBlocks(w, &used, selected, true)
}

func (c *Capture) writeSelectedClassicPackets(source *flowExportSource, w io.Writer, indices []int) error {
	packets := packetOnlyFlowWriter{out: captureOutput{w: w}, order: binary.LittleEndian}
	if c.BigEndian {
		packets.order = binary.BigEndian
	}
	i := 0
	write := func(pkt PacketRecord) error {
		if pkt.Index != indices[i] {
			return nil
		}
		if err := packets.writeClassicPacket(source, c, &pkt, nil, i == 0); err != nil {
			return err
		}
		i++
		if i == len(indices) {
			return errStopWalk
		}
		return nil
	}
	var err error
	if source.budget == nil {
		err = c.walkPackets(&source.data, write)
	} else {
		err = c.walkPacketsFromReaderAt(source.budget, false, write)
	}
	if errors.Is(err, errStopWalk) {
		return nil
	}
	if err == nil && i != len(indices) {
		return ErrOutOfBounds
	}
	return err
}
