package pcap

import (
	"errors"
	"fmt"
	"io"
	"reflect"
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
// other openings changes the selected evidence at a shared TCP reassembly
// cutoff, the export returns [ErrReassemblyLimit] before writing. A writer
// error can leave partial output.
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
	source     ipFrameSource
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
	frames := source.transactionFrames(c)
	selection := http2TransactionExportSelection{id: id, source: frames}
	if c.Format == FormatPCAPNG && len(c.Interfaces) > 1 {
		selection.interfaces = make(map[int]uint32)
	}
	if _, err := scanHTTP2Transactions(frames, &selection); err != nil {
		return err
	}
	return c.writeSelectedPackets(&source, w, selection.indices, selection.interfaces)
}

func http2ExportPackets(source ipFrameSource, row *HTTP2Transaction, client, server *http1Direction) ([]int, error) {
	// A gap, conflict, reset, or invalid frame later in the opening can
	// determine the selected stream's coverage without contributing bytes.
	// Keep that evidence whenever both ends are not conclusively observed.
	prefixSafe := func(a StreamAnomalies) bool {
		// A prefix starting at the preface/SETTINGS also preserves midstream
		// pickup when its original SYN was never captured.
		return !a.SequenceGap && !a.OverlapConflict && !a.Truncated && !a.Retransmission
	}
	closed := row.Request.EndStream && row.Response != nil && row.Response.EndStream && !row.Reset &&
		prefixSafe(client.anomalies) && prefixSafe(server.anomalies)
	if client.anomalies.Truncated || server != nil && server.anomalies.Truncated {
		indices, err := checkHTTP2ExportCutoff(source, row, client, server)
		if err != nil || indices != nil {
			return indices, err
		}
	}
	var indices []int
	for _, d := range []*http1Direction{client, server} {
		if d == nil {
			continue
		}
		if !closed {
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

// Reassemble this opening with an isolated budget and the original packet
// ordinals. A larger prefix can disclose more DATA or END_STREAM in a shared
// packet, or it can contain only frames unrelated to the selected exchange.
func checkHTTP2ExportCutoff(source ipFrameSource, want *HTTP2Transaction, client, server *http1Direction) ([]int, error) {
	dirs := []http1Direction{*client}
	dirs[0].peer = 0
	if server != nil {
		dirs = append(dirs, *server)
		dirs[0].peer, dirs[1].peer = 2, 1
	}
	remaining := int64(MaxTotalStreamBytes)
	collector := tcpMessageCollector{flows: make(map[flowKey]tcpMessageFlow)}
	changed := false
	for i := range dirs {
		d := &dirs[i]
		if !d.anomalies.Truncated {
			continue
		}
		data, spans, anomalies, err := collector.contiguous(d.dir, &remaining, nil)
		if err != nil {
			return nil, err
		}
		changed = changed || len(data) != len(d.data) || anomalies != d.anomalies
		d.data, d.spans, d.anomalies = data, spans, anomalies
	}
	if !changed {
		return nil, nil
	}
	// A changed cutoff can still leave the entire selected exchange intact.
	matches := func(dirs []http1Direction) (bool, error) {
		rows, err := selectHTTP2Transactions(dirs, nil)
		if errors.Is(err, ErrHTTPLimit) {
			return false, nil // Newly exposed frames can exhaust a fresh HTTP budget.
		}
		if err != nil {
			return false, err
		}
		for i := range rows {
			if rows[i].ID() == want.ID() {
				return reflect.DeepEqual(&rows[i], want), nil
			}
		}
		return false, nil
	}
	if ok, err := matches(dirs); ok || err != nil {
		return nil, err
	}

	// A clipped frame can end between packets. Keep the owners of the source
	// prefix, TCP controls and the other direction. Replaying these original
	// packets also recomputes FIN/reset consistency and overlap ownership.
	visible := make(map[int]bool)
	for _, d := range []*http1Direction{client, server} {
		if d == nil {
			continue
		}
		for i, pkt := range d.dir.packets {
			if !d.anomalies.Truncated || d.dir.segments[i].Flags&(TCPFlagSYN|TCPFlagFIN|TCPFlagRST) != 0 {
				visible[pkt.index] = true
			}
		}
		for _, span := range d.spans {
			visible[d.dir.packets[span.segment].index] = true
		}
	}
	prefix, err := collectHTTPTransactionDirections(source, nil, visible)
	if err != nil {
		return nil, err
	}
	ok, err := matches(prefix)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("%w: isolating the HTTP/2 opening changes the selected transaction", ErrReassemblyLimit)
	}
	indices := make([]int, 0, len(visible))
	for idx := range visible {
		indices = append(indices, idx)
	}
	slices.Sort(indices)
	return indices, nil
}
