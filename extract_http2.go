package pcap

import (
	"fmt"
	"io"
	"slices"
)

// ExtractHTTP2TransactionPCAPNG writes original packets for the prior-knowledge
// cleartext HTTP/2 transaction identified by id in the unchanged source data.
// It includes the TCP opening, preface, and both directions' framing and HPACK
// history through the selected exchange. Earlier and interleaved streams can
// expose additional application data. A partial or anomalous exchange can need
// the entire opening to preserve its coverage. [HTTP2Transaction.PacketIndices]
// identifies the packets directly contributing to the exchange.
//
// The export retains packet order, bytes, timestamps, lengths, interfaces and
// frame check sequence information. It omits source comments and secrets.
// An invalid or missing ID returns [ErrOutOfBounds] before writing. If removing
// other openings would change a shared TCP reassembly cutoff, the export can
// return [ErrReassemblyLimit] before writing. A writer error can leave partial output.
func (c *Capture) ExtractHTTP2TransactionPCAPNG(data []byte, w io.Writer, id HTTP2TransactionID) error {
	return c.extractHTTP2TransactionPCAPNG(flowExportSource{data: *NewSafeReader(data)}, w, id)
}

// ExtractHTTP2TransactionPCAPNGFromReaderAt writes the same packet-only output
// as [Capture.ExtractHTTP2TransactionPCAPNG] from the unchanged capture source.
// Selection, framing and copying share one [MaxReaderAtScanBytes] budget.
// Exceeding it returns an error wrapping [ErrPacketLimit] and can leave partial output.
func (c *Capture) ExtractHTTP2TransactionPCAPNGFromReaderAt(r io.ReaderAt, w io.Writer, id HTTP2TransactionID) error {
	if r == nil {
		return ErrInvalidHeader
	}
	return c.extractHTTP2TransactionPCAPNG(flowExportSource{budget: &scanReadBudget{r: r, remaining: MaxReaderAtScanBytes}}, w, id)
}

type http2TransactionExportSelection struct {
	id         HTTP2TransactionID
	indices    []int
	interfaces map[int]uint32
}

func (c *Capture) extractHTTP2TransactionPCAPNG(source flowExportSource, w io.Writer, id HTTP2TransactionID) error {
	if err := c.validateContainer(); err != nil {
		return err
	}
	if id.PacketIndex < 0 || id.PacketIndex >= min(c.PacketCount, MaxPackets) ||
		id.PacketPayloadOffset < 0 || id.PacketPayloadOffset >= MaxSnapLen || id.StreamID%2 == 0 || id.StreamID > 0x7fffffff {
		return ErrOutOfBounds
	}
	if w == nil {
		return ErrInvalidHeader
	}
	source.size = c.fileSize
	frames := ipFrameSource{capture: c, data: source.data.data}
	if source.budget != nil {
		frames.reader = source.budget
		frames.needsPayload = func(f Frame, _ []byte) bool { return f.IPProtocol == IPProtoTCP }
	}
	selection := http2TransactionExportSelection{id: id}
	if c.Format == FormatPCAPNG && len(c.Interfaces) > 1 {
		selection.interfaces = make(map[int]uint32)
	}
	if _, err := scanHTTP2Transactions(frames, &selection); err != nil {
		return err
	}
	return c.writeSelectedPackets(&source, w, selection.indices, selection.interfaces)
}

func http2ExportPackets(row *HTTP2Transaction, client, server *http1Direction) ([]int, error) {
	// A gap, conflict, reset, or invalid frame later in the opening can
	// determine the selected stream's coverage without contributing bytes.
	// Keep that evidence whenever both ends are not conclusively observed.
	closed := row.Request.EndStream && row.Response != nil && row.Response.EndStream && !row.Reset &&
		!client.anomalies.Any() && !server.anomalies.Any()
	var indices []int
	for _, d := range []*http1Direction{client, server} {
		if d == nil {
			continue
		}
		if !closed {
			if d.anomalies.Truncated {
				// A previous opening on this tuple can consume some of the TCP
				// byte budget. Check what these original packets reveal alone.
				remaining := int64(MaxTotalStreamBytes)
				collector := tcpMessageCollector{flows: make(map[flowKey]tcpMessageFlow)}
				data, _, anomalies, err := collector.contiguous(d.dir, &remaining, nil)
				if err != nil {
					return nil, err
				}
				if len(data) != len(d.data) || anomalies != d.anomalies {
					return nil, fmt.Errorf("%w: cannot reproduce HTTP/2 opening's TCP reassembly cutoff in isolation", ErrReassemblyLimit)
				}
			}
			for _, p := range d.dir.packets {
				indices = append(indices, p.index)
			}
			continue
		}

		if d.syn != 0 {
			indices = append(indices, d.dir.packets[d.syn-1].index)
		}
		// A prefix starts at the preface/SETTINGS. Find its end in TCP
		// sequence order: capture order can put a needed segment much later.
		end := 0
		for _, span := range d.spans {
			if _, ok := slices.BinarySearch(row.PacketIndices, d.dir.packets[span.segment].index); ok {
				end = span.end
			}
		}
		indices, _, _ = d.packetsFor(indices, 0, end)
	}
	slices.Sort(indices)
	return slices.Compact(indices), nil
}
