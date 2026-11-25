package pcap

import (
	"errors"
	"io"
	"slices"
)

// ExtractKeyedHTTP1TransactionPCAPNG writes original packets from the TCP
// opening of id. Supply the unchanged capture and matching NSS key log bytes,
// or nil for extraKeyLog to use embedded secrets. The packet-only PcapNG
// preserves capture order, bytes, lengths, timestamps, interfaces and frame
// check sequences. It omits decryption secrets and comments. Supply matching
// keys separately to decrypt the export, and select its new capture-local ID.
//
// A confirmed exchange includes the TCP and TLS opening and earlier records
// from both directions through the selected messages. An unconfirmed request
// can include the rest of the opening to preserve ambiguous pairing evidence.
// A partial body can include its direction's tail as evidence of missing or
// unauthenticated data. Whole packets can disclose other application data.
// If whole packets cannot preserve a source limit, the export returns
// [ErrReassemblyLimit] before writing. An unavailable or invalid id returns [ErrOutOfBounds]
// without writing. Other errors can leave partial output.
func (c *Capture) ExtractKeyedHTTP1TransactionPCAPNG(data, extraKeyLog []byte, w io.Writer, id KeyedHTTP1TransactionID) error {
	return c.extractKeyedHTTP1Transaction(flowExportSource{data: *NewSafeReader(data)}, extraKeyLog, w, id)
}

// ExtractKeyedHTTP1TransactionPCAPNGFromReaderAt writes the same output as
// [Capture.ExtractKeyedHTTP1TransactionPCAPNG] using the unchanged reader.
// Selection, TLS framing and packet copying share [MaxReaderAtScanBytes].
// Exceeding the read budget returns an error wrapping [ErrPacketLimit].
func (c *Capture) ExtractKeyedHTTP1TransactionPCAPNGFromReaderAt(r io.ReaderAt, extraKeyLog []byte, w io.Writer, id KeyedHTTP1TransactionID) error {
	if r == nil {
		return ErrInvalidHeader
	}
	return c.extractKeyedHTTP1Transaction(flowExportSource{budget: &scanReadBudget{r: r, remaining: MaxReaderAtScanBytes}}, extraKeyLog, w, id)
}

func (c *Capture) extractKeyedHTTP1Transaction(source flowExportSource, keys []byte, w io.Writer, id KeyedHTTP1TransactionID) error {
	if err := c.validateContainer(); err != nil {
		return err
	}
	if id.OpeningPacket < 0 || id.OpeningPacket >= min(c.PacketCount, MaxPackets) ||
		id.RecordWireOffset < 0 || id.RecordWireOffset >= MaxFlowStreamBytes || id.OffsetInRecord < 0 || id.OffsetInRecord >= MaxTLSRecordBytes {
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
	streams, err := scanTLSProvenance(frames, keys)
	if err != nil {
		return err
	}
	rows, err := keyedHTTP1Transactions(streams)
	if err != nil {
		return err
	}
	i := slices.IndexFunc(rows, func(r KeyedHTTP1Transaction) bool { return r.ID == id })
	if i < 0 {
		return ErrOutOfBounds
	}
	row := &rows[i]
	s := slices.IndexFunc(streams, func(s tlsProvenanceStream) bool { return s.openingPacket == id.OpeningPacket })
	// Both lookups refer to the same TLS scan. A returned request always
	// has at least one contributing record on that opening.
	ends := [2]int{row.RequestRecords[len(row.RequestRecords)-1].WireEnd, 0}
	confirmed := len(row.ResponseRecords) != 0
	if confirmed {
		ends[1] = row.ResponseRecords[len(row.ResponseRecords)-1].WireEnd
	}
	// Partial bodies need the stop evidence in that direction. An
	// unconfirmed association may depend on either direction's later traffic.
	tail := [2]bool{!confirmed || row.ClientCoverage.IncompleteTail && row.Request.BodyState == HTTPBodyPartial,
		!confirmed || row.ServerCoverage.IncompleteTail && row.Response.BodyState == HTTPBodyPartial}
	indices, interfaces, err := streams[s].exportPrefix(frames, ends, tail)
	if err != nil {
		return err
	}
	return c.writeSelectedPackets(&source, w, indices, interfaces)
}

// Reconstruct the original opening's prefix in capture order, including
// out-of-order owners of earlier records and the TCP control packets needed
// to reproduce the observed opening. Reuse the connection splitter used by
// collectStreams. The second ReaderAt walk reads only frame prefixes.
func (s *tlsProvenanceStream) exportPrefix(frames ipFrameSource, ends [2]int, tail [2]bool) ([]int, map[int]uint32, error) {
	last := s.openingPacket
	provenance := [2]*tlsDirectionProvenance{&s.client, &s.server}
	// A reassembly cap and a snaplen cut can coexist. Track the physical
	// limit independently of which reason the TLS decoder reported.
	hardEnd := [2]int{-1, -1}
	whole := [2]bool{}
	truncated := [2]bool{s.Client.Anomalies.Truncated, s.Server.Anomalies.Truncated}
	// A limit reached solely by this opening repeats with the complete
	// opening, including the opposite direction's TLS record charges.
	needsLimitContext, sharedLimit := false, false
	for dir, p := range provenance {
		needsLimitContext = needsLimitContext || tail[dir] && (truncated[dir] || p.stop.reason == tlsStopLimit)
		sharedLimit = sharedLimit || s.wire[dir].sharedLimit || p.sharedLimit
	}
	for dir, p := range provenance {
		if needsLimitContext && !sharedLimit {
			whole[dir] = true
			last = MaxPackets
			continue
		}
		spans := s.wire[dir].spans
		if truncated[dir] {
			hardEnd[dir] = 0
			if len(spans) > 0 {
				hardEnd[dir] = int(spans[len(spans)-1].end)
			}
		}
		if p.stop.reason == tlsStopLimit {
			limit := p.stop.wireOffset
			if tail[dir] {
				// A fresh scan has its own budget. Preserve an incomplete tail
				// only if a whole source packet can show part of the next TLS
				// record without exposing that entire record.
				if p.limitRecordEnd <= limit+1 || len(spans) == 0 || int(spans[len(spans)-1].end) <= limit {
					return nil, nil, ErrReassemblyLimit
				}
				ends[dir] = limit + 1
				limit = p.limitRecordEnd - 1
			}
			if hardEnd[dir] < 0 || limit < hardEnd[dir] {
				hardEnd[dir] = limit
			}
		} else if tail[dir] {
			whole[dir] = true
			last = MaxPackets
			continue
		}
		for _, span := range spans {
			last = max(last, int(span.packet.index))
			if int(span.end) >= ends[dir] {
				break
			}
		}
	}

	var indices []int
	var interfaces map[int]uint32
	var opening tcpOpening
	var openingInterface uint32
	var syn [2]bool
	if frames.needsPayload != nil {
		frames.needsPayload = func(Frame, []byte) bool { return false }
	}
	err := frames.walk(func(pkt PacketRecord, f Frame, _ []byte) error {
		if pkt.Index > last && syn[0] && syn[1] {
			return errStopWalk
		}
		if pkt.Index < s.openingPacket || f.IPProtocol != IPProtoTCP || !f.hasPorts || f.Anomalies.IPFragment || f.Anomalies.TruncatedLayer || f.Anomalies.InvalidTCPDataOffset {
			return nil
		}
		dir := 0
		switch {
		case f.SrcAddr == s.SrcAddr && f.DstAddr == s.DstAddr && f.SrcPort == s.SrcPort && f.DstPort == s.DstPort:
		case f.SrcAddr == s.DstAddr && f.DstAddr == s.SrcAddr && f.SrcPort == s.DstPort && f.DstPort == s.SrcPort:
			dir = 1
		default:
			return nil
		}
		if pkt.Index == s.openingPacket {
			openingInterface = pkt.InterfaceID
		}
		if frames.capture.SeparateTCPInterfaces && pkt.InterfaceID != openingInterface {
			return nil
		}
		if changed := opening.observe(&f, dir == 0); changed && pkt.Index != s.openingPacket {
			return errStopWalk
		}
		openingSYN := f.TCPFlags&TCPFlagSYN != 0 && !syn[dir]
		syn[dir] = syn[dir] || openingSYN
		if pkt.Index > last && !openingSYN {
			return nil
		}
		if f.PayloadLength > 0 {
			seq := f.TCPSeq
			if f.TCPFlags&TCPFlagSYN != 0 {
				seq++
			}
			start := int64(int32(seq - s.wire[dir].seq))
			end := start + int64(f.PayloadLength)
			if !openingSYN && !whole[dir] && (start >= int64(ends[dir]) || end <= 0) {
				return nil
			}
			if hardEnd[dir] >= 0 && end > int64(hardEnd[dir]) {
				return ErrReassemblyLimit
			}
		}
		indices = append(indices, pkt.Index)
		if pkt.InterfaceID != 0 {
			if interfaces == nil {
				interfaces = make(map[int]uint32)
			}
			interfaces[pkt.Index] = pkt.InterfaceID
		}
		return nil
	})
	if err != nil && !errors.Is(err, errStopWalk) {
		return nil, nil, err
	}
	return indices, interfaces, nil
}
