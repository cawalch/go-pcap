package pcap

import (
	"io"
	"net/netip"
	"slices"
	"sort"
)

// KeyedHTTP1TransactionID identifies a request in one source capture.
// OpeningPacket is the zero-based first packet of the TCP opening.
// RecordWireOffset is the offset of the TLS record header in the client TCP
// stream, including any proxy prefix. OffsetInRecord counts plaintext bytes
// from the start of that record's application data.
type KeyedHTTP1TransactionID struct {
	OpeningPacket, RecordWireOffset, OffsetInRecord int
}

// TLSRecordEvidence identifies a whole authenticated record in one direction.
// WireStart and WireEnd delimit the TLS header and ciphertext in the TCP stream.
// PlaintextStart and PlaintextEnd delimit its contribution to the recovered
// application stream. All ranges are zero-based and half-open. PacketIndices
// lists the sorted, distinct original packets supplying the record. EarlyData
// indicates a client 0-RTT record whose acceptance is unknown. CloseNotify
// identifies the authenticated alert that terminates a close-delimited entity.
type TLSRecordEvidence struct {
	WireStart, WireEnd, PlaintextStart, PlaintextEnd int
	PacketIndices                                    []int
	EarlyData, CloseNotify                           bool
}

// TLSPlaintextCoverage describes the recovered application bytes in one
// direction. OpaquePrefix reports skipped protected records before the first
// authenticated application epoch. IncompleteTail reports a gap, incomplete or
// invalid record, unavailable key, authentication failure or decryption limit.
// Reaching the end of captured input alone does not prove a TLS close.
type TLSPlaintextCoverage struct {
	Bytes                        int
	OpaquePrefix, IncompleteTail bool
}

// KeyedHTTP1Transaction contains an HTTP/1 request with complete authenticated
// headers and its optional confirmed final response. HTTP evidence uses the
// same header and body semantics as [HTTP1Transaction]. Its packet indices and
// packet payload offsets are -1 and its timestamps are zero. Use the directional
// records for capture locations. RequestPlaintextOffset and ResponsePlaintextOffset
// locate the request line and final status line in their recovered streams.
// ResponsePlaintextOffset is -1 when there is no confirmed final response.
// ResponseRecords includes interim responses preceding a confirmed final
// response. PacketIndices is the sorted, distinct union of both record lists.
// The caller owns all evidence. Records and packets can span other messages.
type KeyedHTTP1Transaction struct {
	ID                                              KeyedHTTP1TransactionID
	Request                                         HTTP1RequestEvidence
	Response                                        *HTTP1ResponseEvidence
	Pairing                                         HTTP1Pairing
	RequestPlaintextOffset, ResponsePlaintextOffset int
	RequestRecords, ResponseRecords                 []TLSRecordEvidence
	PacketIndices                                   []int
	ClientCoverage, ServerCoverage                  TLSPlaintextCoverage
}

// KeyedHTTP1Transactions selects HTTP/1 requests in authenticated TLS 1.2 or
// TLS 1.3 application data. It combines embedded PcapNG TLS secrets with
// optional NSS key log bytes. The scan shares its TLS and HTTP budgets across
// connections. Missing keys or incomplete request headers yield no request.
// Rows are ordered by opening packet, client record offset and plaintext
// offset within that record. The returned evidence retains no keys.
func (c *Capture) KeyedHTTP1Transactions(data, extraKeyLog []byte) ([]KeyedHTTP1Transaction, error) {
	return scanKeyedHTTP1(ipFrameSource{capture: c, data: data}, extraKeyLog)
}

// KeyedHTTP1TransactionsFromReaderAt is the bounded ReaderAt equivalent of
// [Capture.KeyedHTTP1Transactions]. Its reads share [MaxReaderAtScanBytes].
func (c *Capture) KeyedHTTP1TransactionsFromReaderAt(r io.ReaderAt, extraKeyLog []byte) ([]KeyedHTTP1Transaction, error) {
	return scanKeyedHTTP1(ipFrameSource{capture: c, reader: r, needsPayload: func(f Frame, _ []byte) bool { return f.IPProtocol == IPProtoTCP }}, extraKeyLog)
}

func (d *tlsDirectionProvenance) coverage(size int) TLSPlaintextCoverage {
	return TLSPlaintextCoverage{size, d.before.reason != tlsStopEnd, d.stop.reason != tlsStopEnd}
}

func (d *tlsDirectionProvenance) recordAt(offset int) int {
	return sort.Search(len(d.records), func(i int) bool { return d.records[i].plainEnd > offset })
}

// Charge repeated intersections, including a shared record's entire packet
// list each time it contributes to a different request or response.
func (d *tlsDirectionProvenance) evidence(start, end int, closed bool, packets *[]int, remaining *int) ([]TLSRecordEvidence, error) {
	var out []TLSRecordEvidence
	add := func(r *tlsApplicationRecord, closeNotify bool) error {
		cost := len(r.packets) + 1
		if cost > *remaining {
			return ErrHTTPLimit
		}
		*remaining -= cost
		out = append(out, TLSRecordEvidence{WireStart: r.wireStart, WireEnd: r.wireEnd, PlaintextStart: r.plainStart, PlaintextEnd: r.plainEnd,
			PacketIndices: slices.Clone(r.packets), EarlyData: r.early, CloseNotify: closeNotify})
		*packets = append(*packets, r.packets...)
		return nil
	}
	for i := d.recordAt(start); i < len(d.records) && d.records[i].plainStart < end; i++ {
		r := &d.records[i]
		if r.plainEnd > r.plainStart {
			if err := add(r, false); err != nil {
				return nil, err
			}
		}
	}
	if closed {
		if err := add(d.closeNotify, true); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *tlsProvenanceStream) acknowledged(request tlsApplicationRecord, response int) bool {
	reply := s.server.records[s.server.recordAt(response)]
	client, server := &s.wire[0], &s.wire[1]
	// The peer needs the complete request record to authenticate any request
	// byte in it. The first response-record packet supplies the peer's ACK.
	ackAt := func(d *tcpWireDirection, offset int) uint32 {
		i := sort.Search(len(d.spans), func(i int) bool { return int(d.spans[i].end) > offset })
		return d.spans[i].packet.ack
	}
	return int32(ackAt(server, reply.wireStart)-(client.seq+uint32(request.wireEnd))) >= 0 &&
		ackAt(client, request.wireStart)-server.seq <= uint32(reply.wireStart)
}

func scanKeyedHTTP1(source ipFrameSource, keys []byte) ([]KeyedHTTP1Transaction, error) {
	streams, err := scanTLSProvenance(source, keys)
	if err != nil {
		return nil, err
	}
	var rows []KeyedHTTP1Transaction
	budget := newHTTP1EvidenceBudget()
	remaining := maxTLSProvenanceRanges
	for i := range streams {
		s := &streams[i]
		if len(s.Client.Data) == 0 {
			continue
		}
		firstRegular := sort.Search(len(s.client.records), func(i int) bool { return !s.client.records[i].early })
		clientCoverage, serverCoverage := s.client.coverage(len(s.Client.Data)), s.server.coverage(len(s.Server.Data))
		cursor := http1ResponseCursor{data: s.Server.Data, gracefulEnd: s.server.closeNotify != nil,
			haveReverse:  len(s.Server.Data) > 0 || serverCoverage.IncompleteTail || serverCoverage.OpaquePrefix,
			uncertainEnd: serverCoverage.IncompleteTail,
			// Without an early-data offer, app-only keys can recover both regular
			// application epochs starting at sequence zero after opaque handshakes.
			canPair: s.confirmedOpening && !s.earlyOffered && firstRegular == 0 &&
				s.client.before.reason != tlsStopAuthentication && s.server.before.reason != tlsStopAuthentication &&
				!s.Client.Anomalies.OverlapConflict && !s.Server.Anomalies.OverlapConflict}
		base := 0
		visit := func(req HTTP1RequestEvidence, start, end int, known bool) error {
			start, end = base+start, base+end
			req.FlowIndex, req.Source, req.Destination = s.FlowIndex, netip.AddrPortFrom(s.SrcAddr, s.SrcPort), netip.AddrPortFrom(s.DstAddr, s.DstPort)
			req.TCPAnomalies = s.Client.Anomalies
			first := s.client.records[s.client.recordAt(start)]
			row := KeyedHTTP1Transaction{Request: req, ID: KeyedHTTP1TransactionID{s.openingPacket, first.wireStart, start - first.plainStart},
				RequestPlaintextOffset: start, ResponsePlaintextOffset: -1, ClientCoverage: clientCoverage, ServerCoverage: serverCoverage}
			var err error
			row.RequestRecords, err = s.client.evidence(start, end, false, &row.PacketIndices, &remaining)
			if err != nil {
				return err
			}
			before := cursor.offset
			response, status, closed, pairing, err := cursor.next(req.Method, known, &budget, func(off int) bool { return s.acknowledged(first, off) })
			if err != nil {
				return err
			}
			row.Pairing, row.Response = pairing, response
			if response != nil {
				response.TCPAnomalies = s.Server.Anomalies
				row.ResponsePlaintextOffset = status
				row.ResponseRecords, err = s.server.evidence(before, cursor.offset, closed, &row.PacketIndices, &remaining)
				if err != nil {
					return err
				}
			}
			slices.Sort(row.PacketIndices)
			row.PacketIndices = slices.Compact(row.PacketIndices)
			rows = append(rows, row)
			return nil
		}
		// The server might have rejected 0-RTT. Joining a partial early
		// message to regular application data could fabricate an HTTP row.
		if firstRegular > 0 {
			earlyEnd := s.client.records[firstRegular-1].plainEnd
			if err := walkHTTP1PlainRequests(s.Client.Data[:earlyEnd], &budget, visit); err != nil {
				return nil, err
			}
			base = earlyEnd
		}
		if err := walkHTTP1PlainRequests(s.Client.Data[base:], &budget, visit); err != nil {
			return nil, err
		}
	}
	return rows, nil
}
