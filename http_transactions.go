package pcap

import (
	"cmp"
	"errors"
	"io"
	"slices"
	"sort"
)

// HTTP1Pairing describes the evidence for a final response to one request.
type HTTP1Pairing uint8

const (
	// HTTP1ResponseUnseen indicates that no final response was observed.
	HTTP1ResponseUnseen HTTP1Pairing = iota
	// HTTP1ResponseAmbiguous indicates that reverse bytes were observed but
	// framing, TCP coverage or packet acknowledgements prevented association.
	HTTP1ResponseAmbiguous
	// HTTP1ResponseConfirmed indicates a final response on the same anchored
	// TCP connection, matched in HTTP/1 request order.
	HTTP1ResponseConfirmed
)

// HTTP1ResponseEvidence identifies the packet and TCP payload offset supplying
// the first status-line byte. Version omits "HTTP/". Headers retain wire order
// and raw field values. Body and its coverage have the same semantics as
// [HTTP1RequestEvidence]. The caller owns the headers and body.
type HTTP1ResponseEvidence struct {
	PacketIndex, PacketPayloadOffset, StatusCode int
	TimestampNs                                  int64
	Version                                      string
	Headers                                      []HTTPHeader
	Body                                         []byte
	BodyState                                    HTTPBodyState
	BodyLimitExceeded                            bool
	Anomalies                                    HTTPAnomalies
	TCPAnomalies                                 StreamAnomalies
}

// HTTP1Transaction associates a cleartext HTTP/1 request with an optional
// confirmed final response. Request.PacketIndex and Request.PacketPayloadOffset
// identify the transaction within the source capture. PacketIndices contains
// the sorted, distinct, zero-based packet indices supplying known message bytes,
// including interim responses preceding a confirmed final response and a FIN proving a close-delimited
// body's end. SharedPackets reports TCP payload outside those byte ranges in a
// selected packet. Identical retransmissions that supply no new bytes are
// omitted. The caller owns PacketIndices, Request and Response.
type HTTP1Transaction struct {
	Request       HTTP1RequestEvidence
	Response      *HTTP1ResponseEvidence
	Pairing       HTTP1Pairing
	PacketIndices []int
	SharedPackets bool
	// ExportIncludesPriorMessages reports that exporting this exchange also includes
	// earlier HTTP traffic needed to reconstruct the request or response.
	ExportIncludesPriorMessages bool
}

// HTTP1Transactions returns cleartext TCP requests in packet and payload-offset
// order. Pairing requires both TCP openings, contiguous HTTP/1 prefixes, and
// acknowledgements consistent with request order. Gaps stop parsing in their
// direction. Conflicting overlaps prevent pairing. The scan counts requests,
// final responses and informational responses against [MaxHTTPMessagesPerScan]
// and shares the header/body and decoding budgets of [Capture.HTTP1RequestEvidence].
func (c *Capture) HTTP1Transactions(data []byte) ([]HTTP1Transaction, error) {
	return scanHTTP1Transactions(ipFrameSource{capture: c, data: data}, nil)
}

// HTTP1TransactionsFromReaderAt is the bounded ReaderAt equivalent of
// [Capture.HTTP1Transactions]. All packet reads share [MaxReaderAtScanBytes].
func (c *Capture) HTTP1TransactionsFromReaderAt(r io.ReaderAt) ([]HTTP1Transaction, error) {
	return scanHTTP1Transactions(ipFrameSource{capture: c, reader: r, needsPayload: func(f Frame, _ []byte) bool { return f.IPProtocol == IPProtoTCP }}, nil)
}

type http1Direction struct {
	dir                      *tcpMessageDirection
	peer                     int // One-based collector direction in the same opening.
	data                     []byte
	spans                    []packetSpan
	anomalies                StreamAnomalies
	acks                     []uint32 // One entry per retained segment, including control packets.
	syn, fin, reset          int      // One-based segment indices.
	hasPayload, inconsistent bool
	lastPayload              int // One-based capture packet index.
}

func (d *http1Direction) observe(f Frame, index, size int) {
	d.acks = append(d.acks, f.TCPAck)
	slot := len(d.acks)
	if size > 0 {
		d.hasPayload = true
		d.lastPayload = index + 1
	}
	if f.TCPFlags&TCPFlagSYN != 0 && d.syn == 0 {
		d.syn = slot
	}
	if f.TCPFlags&TCPFlagFIN != 0 && !f.Anomalies.IPTotalLengthExceedsFrame && d.fin == 0 {
		d.fin = slot
	}
	if f.TCPFlags&TCPFlagRST != 0 && d.reset == 0 {
		d.reset = slot
	}
}

// Collect both contiguous directions of each observed TCP opening, with the
// packet ownership and control evidence used by the HTTP transaction readers.
func collectHTTPTransactionDirections(source ipFrameSource, export *http1TransactionExportSelection) ([]http1Direction, error) {
	collector := tcpMessageCollector{separateInterfaces: source.capture != nil && source.capture.SeparateTCPInterfaces}
	var dirs []http1Direction
	err := walkHTTPPackets(source, func(pkt PacketRecord, frame Frame, flow int, payload []byte) error {
		if !keepTCPMessageSegment(&frame, len(payload), TCPFlagSYN|TCPFlagFIN|TCPFlagRST) {
			return nil
		}
		pair, err := collector.addSegment(pkt, frame, flow, payload)
		if err != nil {
			return err
		}
		if export != nil && export.interfaces != nil && pkt.InterfaceID != 0 {
			export.interfaces[pkt.Index] = pkt.InterfaceID
		}
		if pair[0] > len(dirs) {
			dirs = append(dirs, http1Direction{})
		}
		d := &dirs[pair[0]-1]
		if pair[1] != 0 {
			d.peer, dirs[pair[1]-1].peer = pair[1], pair[0]
		}
		segs := collector.directions[pair[0]-1].segments
		if d.syn != 0 && frame.TCPFlags&TCPFlagSYN != 0 {
			open := segs[d.syn-1]
			d.inconsistent = d.inconsistent || open.Seq != frame.TCPSeq || open.Flags&TCPFlagACK != frame.TCPFlags&TCPFlagACK
		}
		if d.fin != 0 && !frame.Anomalies.IPTotalLengthExceedsFrame && frame.TCPFlags&TCPFlagFIN != 0 {
			d.inconsistent = d.inconsistent || tcpSegmentEnd(segs[d.fin-1]) != tcpSegmentEnd(segs[len(segs)-1])
		}
		d.observe(frame, pkt.Index, len(payload))
		return nil
	})
	if err != nil {
		return nil, err
	}
	remaining := int64(MaxTotalStreamBytes)
	for i := range dirs {
		d := &dirs[i]
		d.dir = &collector.directions[i]
		if d.fin != 0 {
			fin := tcpSegmentEnd(d.dir.segments[d.fin-1])
			for _, seg := range d.dir.segments {
				if len(seg.Payload) != 0 && int32(tcpSegmentEnd(seg)-fin) > 0 {
					d.inconsistent = true
					break
				}
			}
		}
		d.data, d.spans, d.anomalies, err = collector.contiguous(d.dir, &remaining, nil)
		if err != nil {
			return nil, err
		}
	}
	return dirs, nil
}

func scanHTTP1Transactions(source ipFrameSource, export *http1TransactionExportSelection) ([]HTTP1Transaction, error) {
	dirs, err := collectHTTPTransactionDirections(source, export)
	if err != nil {
		return nil, err
	}
	var rows []HTTP1Transaction
	budget := newHTTP1EvidenceBudget()
	for i := range dirs {
		client := &dirs[i]
		if !hasHTTPRequestStart(client.data) {
			continue
		}
		var server *http1Direction
		if client.peer != 0 {
			server = &dirs[client.peer-1]
		}
		var requests []http1RequestRange
		if err := walkHTTP1Evidence(client.dir, client.data, client.spans, client.anomalies, &budget, func(row HTTP1RequestEvidence, start, end int, known bool) {
			requests = append(requests, http1RequestRange{start, end, known})
			rows = append(rows, HTTP1Transaction{Request: row})
		}); err != nil {
			return nil, err
		}
		if err := pairHTTP1Requests(rows[len(rows)-len(requests):], requests, client, server, &budget, export); err != nil {
			return nil, err
		}
	}
	slices.SortFunc(rows, func(a, b HTTP1Transaction) int {
		if c := cmp.Compare(a.Request.PacketIndex, b.Request.PacketIndex); c != 0 {
			return c
		}
		return cmp.Compare(a.Request.PacketPayloadOffset, b.Request.PacketPayloadOffset)
	})
	return rows, nil
}

type http1RequestRange struct {
	start, end int
	known      bool
}

func tcpSegmentEnd(seg TCPSegmentInput) uint32 {
	end := seg.Seq + uint32(len(seg.Payload))
	if seg.Flags&TCPFlagSYN != 0 {
		end++
	}
	return end
}

func (d *http1Direction) spanAt(offset int) int {
	return sort.Search(len(d.spans), func(i int) bool { return d.spans[i].end > offset })
}

func (d *http1Direction) location(offset int) (messagePacket, int) {
	i := d.spanAt(offset)
	span := d.spans[i]
	start := 0
	if i > 0 {
		start = d.spans[i-1].end
	}
	segment := d.dir.segments[span.segment]
	payloadStart := tcpSegmentEnd(segment) - uint32(len(segment.Payload))
	return d.dir.packets[span.segment], int(span.seq-payloadStart) + offset - start
}

// Append the first-seen owners of a contiguous wire interval. Compare sequence
// numbers against whole segment payloads, including bytes lost to overlap resolution.
func (d *http1Direction) packetsFor(indices []int, start, end int) ([]int, bool, bool) {
	if end <= start {
		return indices, false, false
	}
	seq := d.spans[0].seq
	leading, trailing := false, false
	for i := d.spanAt(start); i < len(d.spans); i++ {
		span := d.spans[i]
		seg := d.dir.segments[span.segment]
		segEnd := tcpSegmentEnd(seg)
		segStart := segEnd - uint32(len(seg.Payload))
		leading = leading || int32(segStart-(seq+uint32(start))) < 0
		trailing = trailing || int32(segEnd-(seq+uint32(end))) > 0
		indices = append(indices, d.dir.packets[span.segment].index)
		if span.end >= end {
			break
		}
	}
	return indices, leading || trailing, leading
}

func http1Anchored(client, server *http1Direction) bool {
	return client.syn != 0 && server.syn != 0 && consistentHTTPOpening(client, server)
}

func consistentHTTPOpening(client, server *http1Direction) bool {
	if client.inconsistent || server.inconsistent || client.anomalies.OverlapConflict || server.anomalies.OverlapConflict {
		return false
	}
	if client.syn != 0 && server.syn != 0 {
		cs, ss := client.dir.segments[client.syn-1], server.dir.segments[server.syn-1]
		if cs.Flags&TCPFlagACK != 0 || ss.Flags&TCPFlagACK == 0 || server.acks[server.syn-1]-(cs.Seq+1) > uint32(len(cs.Payload)) {
			return false
		}
	}
	for _, d := range []*http1Direction{client, server} {
		if d.reset != 0 && max(client.lastPayload, server.lastPayload) > d.dir.packets[d.reset-1].index+1 {
			return false
		}
	}
	return true
}

func http1Acknowledged(client, server *http1Direction, request, response int) bool {
	s := server.spans[server.spanAt(response)].segment
	if server.dir.segments[s].Flags&TCPFlagACK == 0 || int32(server.acks[s]-(client.spans[0].seq+uint32(request))) <= 0 {
		return false
	}
	c := client.spans[client.spanAt(request)].segment
	if client.dir.segments[c].Flags&TCPFlagACK == 0 {
		return client.dir.segments[c].Flags&TCPFlagSYN != 0 // TCP Fast Open.
	}
	return client.acks[c]-server.spans[0].seq <= uint32(response)
}

// A FIN beyond the captured prefix identifies missing server bytes even when
// the final packet carries no payload to trigger a reassembly gap.
func (d *http1Direction) missingBeforeFIN() bool {
	return d.syn != 0 && d.fin != 0 && int32(tcpSegmentEnd(d.dir.segments[d.fin-1])-(d.dir.segments[d.syn-1].Seq+1+uint32(len(d.data)))) > 0
}

func (d *http1Direction) closedAtEnd(peer *http1Direction) bool {
	if d.fin == 0 || len(d.spans) == 0 || d.inconsistent || d.anomalies.Truncated || d.anomalies.SequenceGap {
		return false
	}
	finPacket := d.dir.packets[d.fin-1].index
	for _, side := range []*http1Direction{d, peer} {
		if side.reset != 0 && side.dir.packets[side.reset-1].index <= finPacket {
			return false
		}
	}
	return tcpSegmentEnd(d.dir.segments[d.fin-1]) == d.spans[0].seq+uint32(len(d.data))
}

func pairHTTP1Requests(rows []HTTP1Transaction, ranges []http1RequestRange, client, server *http1Direction, budget *http1EvidenceBudget, export *http1TransactionExportSelection) error {
	missing := server != nil && server.missingBeforeFIN()
	haveReverse := server != nil && (server.hasPayload || missing)
	canPair := haveReverse && http1Anchored(client, server)
	gracefulEnd := canPair && server.closedAtEnd(client)
	off := 0
	for i := range rows {
		row, req := &rows[i], ranges[i]
		var leading bool
		row.PacketIndices, row.SharedPackets, leading = client.packetsFor(nil, req.start, req.end)
		row.ExportIncludesPriorMessages = leading && req.start > 0
		start := off
		var fin bool
		canPair = canPair && req.known
		for canPair && off < len(server.data) {
			// A response can precede the request body (Expect: 100-continue).
			// Both first-byte packets must agree that the request has started.
			if !http1Acknowledged(client, server, req.start, off) {
				canPair = false
				break
			}
			response, boundary, err := parseHTTP1ResponseEvidence(server, off, row.Request.Method, gracefulEnd, budget)
			if errors.Is(err, ErrHTTPLimit) {
				return err
			}
			if err != nil {
				canPair = false
				break
			}
			off += boundary.end
			if response.StatusCode/100 == 1 && response.StatusCode != 101 {
				continue
			}
			row.Response, row.Pairing, fin = response, HTTP1ResponseConfirmed, boundary.closed
			row.ExportIncludesPriorMessages = req.start > 0 || start > 0
			if boundary.indeterminate || response.StatusCode == 101 || row.Request.Method == "CONNECT" && response.StatusCode/100 == 2 {
				canPair = false
			}
			break
		}
		if row.Response == nil && haveReverse && (!canPair || missing || off < len(server.data) || server.anomalies.SequenceGap || server.anomalies.Truncated || len(server.data) == 0) {
			row.Pairing = HTTP1ResponseAmbiguous
		}
		if off > start && row.Response != nil {
			var shared bool
			row.PacketIndices, shared, _ = server.packetsFor(row.PacketIndices, start, off)
			row.SharedPackets = row.SharedPackets || shared
			if fin {
				row.PacketIndices = append(row.PacketIndices, server.dir.packets[server.fin-1].index)
				finSeg := server.dir.segments[server.fin-1]
				row.SharedPackets = row.SharedPackets || len(finSeg.Payload) > off-start
			}
		}
		slices.Sort(row.PacketIndices)
		row.PacketIndices = slices.Compact(row.PacketIndices)
		if export != nil && row.Request.PacketIndex == export.id.PacketIndex && row.Request.PacketPayloadOffset == export.id.PacketPayloadOffset {
			if row.Pairing == HTTP1ResponseConfirmed {
				idx := []int{client.dir.packets[client.syn-1].index, server.dir.packets[server.syn-1].index}
				idx, _, _ = client.packetsFor(idx, 0, req.end)
				idx, _, _ = server.packetsFor(idx, 0, off)
				if fin {
					idx = append(idx, server.dir.packets[server.fin-1].index)
				}
				slices.Sort(idx)
				export.packetIndices = slices.Compact(idx)
			} else if leading {
				// The first exported TCP payload could start inside a previous
				// request. Include its client prefix to recover the start line.
				idx, _, _ := client.packetsFor(nil, 0, req.end)
				if client.syn != 0 {
					idx = append(idx, client.dir.packets[client.syn-1].index)
				}
				slices.Sort(idx)
				export.packetIndices = slices.Compact(idx)
			} else {
				export.packetIndices = row.PacketIndices
			}
		}
	}
	return nil
}

type http1ResponseBoundary struct {
	end                   int // Number of wire bytes known to belong to this message.
	closed, indeterminate bool
}

func parseHTTP1ResponseEvidence(server *http1Direction, offset int, method string, gracefulEnd bool, budget *http1EvidenceBudget) (*HTTP1ResponseEvidence, http1ResponseBoundary, error) {
	stream := server.data[offset:]
	version, code, _, lineEnd, err := parseHTTPStatusLine(stream)
	if err != nil {
		return nil, http1ResponseBoundary{}, err
	}
	if version[2] < '0' || version[2] > '9' || lineEnd > 12 && (stream[12] != ' ' || !validHTTPFieldValue(stream[13:lineEnd])) {
		return nil, http1ResponseBoundary{}, ErrInvalidHTTP
	}
	headers, start, framing, err := parseHTTPHeaders(stream, lineEnd+2, true)
	if err != nil {
		return nil, http1ResponseBoundary{}, err
	}
	if err := budget.charge(start); err != nil {
		return nil, http1ResponseBoundary{}, err
	}
	packet, payloadOffset := server.location(offset)
	r := &HTTP1ResponseEvidence{PacketIndex: packet.index, PacketPayloadOffset: payloadOffset, TimestampNs: packet.timestamp, Version: version, StatusCode: code, Headers: headers, Anomalies: framing.anomalies, TCPAnomalies: server.anomalies}
	if httpResponseHasNoBody(method, code) {
		r.BodyState = HTTPBodyComplete
		return r, http1ResponseBoundary{end: start}, nil
	}
	body := framing.body(stream, start, false)
	closeDelimited := !body.malformed && !framing.chunked && (framing.hasTransfer || framing.length < 0)
	fin := closeDelimited && gracefulEnd
	if closeDelimited && !fin {
		body.truncated = true
	}
	decoded := HTTP1RequestEvidence{Anomalies: framing.anomalies}
	if err := decoded.retainBody(body, framing, &budget.decode, &budget.remaining); err != nil {
		return nil, http1ResponseBoundary{}, err
	}
	r.Body, r.BodyState, r.BodyLimitExceeded, r.Anomalies = decoded.Body, decoded.BodyState, decoded.BodyLimitExceeded, decoded.Anomalies
	if body.malformed {
		return r, http1ResponseBoundary{end: body.invalidEnd, indeterminate: true}, nil
	}
	return r, http1ResponseBoundary{end: body.consumed, closed: fin}, nil
}
