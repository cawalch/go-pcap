package pcap

import (
	"io"
	"slices"
)

// ExtractKeyedHTTP2TransactionPCAPNG writes original ciphertext packets for id
// from the unchanged capture. Supply matching NSS key log bytes or use nil to
// load embedded secrets. The export omits secrets and comments, so decrypt it
// with separate keys and select its new capture-local ID.
//
// It preserves packet order, bytes, lengths, timestamps, interfaces and frame
// check sequences. It includes the TCP and TLS opening, plus both directions'
// HTTP/2 framing and HPACK history through the exchange. Earlier and concurrent
// streams can be visible. Partial, reset or anomalous exchanges can require
// the entire TCP opening to preserve their evidence.
//
// An unavailable or invalid ID returns [ErrOutOfBounds]. If whole packets
// cannot preserve a source limit, it returns [ErrReassemblyLimit]. Both errors
// occur before output. Other errors can leave partial output.
func (c *Capture) ExtractKeyedHTTP2TransactionPCAPNG(data, extraKeyLog []byte, w io.Writer, id KeyedHTTP2TransactionID) error {
	return c.extractKeyedHTTP2Transaction(flowExportSource{data: *NewSafeReader(data)}, extraKeyLog, w, id)
}

// ExtractKeyedHTTP2TransactionPCAPNGFromReaderAt writes the same output as
// [Capture.ExtractKeyedHTTP2TransactionPCAPNG] using the unchanged reader.
// Selection, TLS framing and packet copying share [MaxReaderAtScanBytes].
// Exceeding the read budget returns an error wrapping [ErrPacketLimit].
func (c *Capture) ExtractKeyedHTTP2TransactionPCAPNGFromReaderAt(r io.ReaderAt, extraKeyLog []byte, w io.Writer, id KeyedHTTP2TransactionID) error {
	if r == nil {
		return ErrInvalidHeader
	}
	return c.extractKeyedHTTP2Transaction(flowExportSource{budget: &scanReadBudget{r: r, remaining: MaxReaderAtScanBytes}}, extraKeyLog, w, id)
}

func (c *Capture) extractKeyedHTTP2Transaction(source flowExportSource, keys []byte, w io.Writer, id KeyedHTTP2TransactionID) error {
	if err := c.validateContainer(); err != nil {
		return err
	}
	if id.OpeningPacket < 0 || id.OpeningPacket >= min(c.PacketCount, MaxPackets) ||
		id.RecordWireOffset < 0 || id.RecordWireOffset >= MaxFlowStreamBytes ||
		id.OffsetInRecord < 0 || id.OffsetInRecord >= MaxTLSRecordBytes ||
		id.StreamID%2 == 0 || id.StreamID > 0x7fffffff {
		return ErrOutOfBounds
	}
	if w == nil {
		return ErrInvalidHeader
	}
	source.size = c.fileSize
	frames := source.transactionFrames(c)
	streams, err := scanTLSProvenance(frames, keys)
	if err != nil {
		return err
	}
	rows, err := keyedHTTP2Transactions(streams)
	if err != nil {
		return err
	}
	i := slices.IndexFunc(rows, func(row KeyedHTTP2Transaction) bool { return row.ID == id })
	if i < 0 {
		return ErrOutOfBounds
	}
	row := &rows[i]
	s := slices.IndexFunc(streams, func(s tlsProvenanceStream) bool { return s.openingPacket == id.OpeningPacket })
	ends := [2]int{row.RequestRecords[len(row.RequestRecords)-1].WireEnd, 0}
	if n := len(row.ResponseRecords); n != 0 {
		ends[1] = row.ResponseRecords[n-1].WireEnd
	}
	// A closed exchange needs all prior records in each direction, including
	// HPACK updates on other streams. Keep the TCP opening's tail when it
	// can change pairing, reset, frame completion or TCP overlap evidence.
	prefixSafe := func(a StreamAnomalies) bool {
		return !a.SequenceGap && !a.OverlapConflict && !a.Truncated && !a.Retransmission
	}
	keepTail := !row.Request.EndStream || row.Response == nil || !row.Response.EndStream || row.Reset ||
		row.ClientCoverage.IncompleteTail || row.ServerCoverage.IncompleteTail ||
		!prefixSafe(streams[s].Client.Anomalies) || !prefixSafe(streams[s].Server.Anomalies)
	indices, interfaces, err := streams[s].exportPrefix(frames, ends, [2]bool{keepTail, keepTail})
	if err != nil {
		return err
	}
	return c.writeSelectedPackets(&source, w, indices, interfaces)
}
