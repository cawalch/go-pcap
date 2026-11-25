package pcap

import (
	"bytes"
	"cmp"
	"errors"
	"io"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// HTTP2TransactionID identifies the opening request HEADERS frame and stream
// within the original capture. PacketIndex is zero-based. PacketPayloadOffset
// counts bytes from the start of that packet's TCP payload.
type HTTP2TransactionID struct {
	PacketIndex, PacketPayloadOffset int
	StreamID                         uint32
}

// HTTP2MessageEvidence describes the initial request or final response headers,
// optional trailers and decoded entity body. Header names and values are
// HPACK-decoded, in wire order with duplicates. PacketIndex, PacketPayloadOffset
// and TimestampNs locate the initial HEADERS frame. Body offsets count logical
// entity bytes. BodyLimitExceeded marks a capped prefix, and EndStream reports
// an observed END_STREAM flag. TCPAnomalies describes the entire direction.
type HTTP2MessageEvidence struct {
	HTTP2HeaderBlock
	PacketIndex, PacketPayloadOffset int
	TimestampNs                      int64
	Trailers                         []HTTPHeader
	Body                             []byte
	BodyState                        HTTPBodyState
	BodyLimitExceeded, EndStream     bool
	TCPAnomalies                     StreamAnomalies
}

// HTTP2Pairing describes the evidence for a final HTTP/2 response.
type HTTP2Pairing uint8

const (
	// HTTP2ResponseUnseen means the scan observed no final response.
	HTTP2ResponseUnseen HTTP2Pairing = iota
	// HTTP2ResponseAmbiguous means conflicting, incomplete or invalid evidence
	// prevented association of a final response.
	HTTP2ResponseAmbiguous
	// HTTP2ResponseConfirmed means a valid final status was observed on the
	// request's stream in the same TCP opening.
	HTTP2ResponseConfirmed
)

// HTTP2Transaction describes one cleartext HTTP/2 request. Source and
// Destination follow the request direction. Informational holds preceding 1xx
// blocks. Response is nil until the final status is confirmed. Reset reports
// an observed RST_STREAM. PacketIndices contains sorted distinct zero-based
// indices supplying the selected headers, DATA, trailers and reset frames.
// SharedPackets means at least one such packet also carries other TCP payload.
// The caller owns the returned slices and response.
type HTTP2Transaction struct {
	FlowIndex            int
	Source, Destination  netip.AddrPort
	StreamID             uint32
	Request              HTTP2MessageEvidence
	Informational        []HTTP2HeaderBlock
	Response             *HTTP2MessageEvidence
	StatusCode           int // Zero until a final response is confirmed.
	Pairing              HTTP2Pairing
	Reset, SharedPackets bool
	PacketIndices        []int
}

// ID returns the capture-local location and stream ID of the opening request.
func (t HTTP2Transaction) ID() HTTP2TransactionID {
	return HTTP2TransactionID{t.Request.PacketIndex, t.Request.PacketPayloadOffset, t.StreamID}
}

// HTTP2Transactions returns prior-knowledge cleartext HTTP/2 requests in packet
// and TCP payload-offset order. It stops at gaps and invalid directional frame
// sequences. HTTP/1 upgrades and encrypted traffic are outside its coverage.
// See [HTTP2Transaction] for ownership and [MaxHTTP2FramesPerStream],
// [MaxHTTPMessagesPerScan], [MaxHTTP2DecodedHeaderBytes], [MaxHTTPBodyBytes]
// and [MaxHTTPDecodedBodyBytesPerScan] for scan and message limits.
func (c *Capture) HTTP2Transactions(data []byte) ([]HTTP2Transaction, error) {
	return scanHTTP2Transactions(ipFrameSource{capture: c, data: data}, nil)
}

// HTTP2TransactionsFromReaderAt is the bounded ReaderAt equivalent of
// [Capture.HTTP2Transactions]. All packet reads share [MaxReaderAtScanBytes].
func (c *Capture) HTTP2TransactionsFromReaderAt(r io.ReaderAt) ([]HTTP2Transaction, error) {
	return scanHTTP2Transactions(ipFrameSource{capture: c, reader: r, needsPayload: func(f Frame, _ []byte) bool { return f.IPProtocol == IPProtoTCP }}, nil)
}

type http2TransactionBudget struct {
	headers, transactions, packetRefs, bodyBytes int
	decode                                       httpDecodeBudget
}

type http2Exchange struct {
	row        HTTP2Transaction
	client     *http1Direction
	requestEnd int
	// Count selected bytes in each contributing packet to detect sharing even
	// when multiple adjacent frames in the packet belong to this transaction.
	outside                         map[int]int
	requestInvalid, responseInvalid bool
}

func scanHTTP2Transactions(source ipFrameSource, export *http2TransactionExportSelection) ([]HTTP2Transaction, error) {
	var interfaces map[int]uint32
	if export != nil {
		interfaces = export.interfaces
	}
	dirs, err := collectHTTPTransactionDirections(source, interfaces, nil)
	if err != nil {
		return nil, err
	}
	return selectHTTP2Transactions(dirs, export)
}

func selectHTTP2Transactions(dirs []http1Direction, export *http2TransactionExportSelection) ([]HTTP2Transaction, error) {
	budget := http2TransactionBudget{
		headers: MaxHTTP2DecodedHeaderBytes, transactions: MaxHTTPMessagesPerScan,
		packetRefs: MaxPackets, bodyBytes: MaxTotalStreamBytes,
		decode: httpDecodeBudget{remaining: MaxHTTPDecodedBodyBytesPerScan},
	}
	var rows []HTTP2Transaction
	for i := range dirs {
		client := &dirs[i]
		if !bytes.HasPrefix(client.data, HTTP2ClientPreface) {
			continue
		}
		first := client.data[len(HTTP2ClientPreface):]
		if !hasHTTP2InitialSettings(first) || first[4] != 0 {
			continue
		}
		requests, err := readHTTP2TransactionFrames(client, true, &budget.headers)
		if err != nil {
			return nil, err
		}
		var responses http2TransactionFrames
		var server *http1Direction
		if client.peer != 0 {
			server = &dirs[client.peer-1]
			if server.hasPayload {
				responses.incomplete = true
				if consistentHTTPOpening(client, server) && hasHTTP2InitialSettings(server.data) && server.data[4] == 0 {
					responses, err = readHTTP2TransactionFrames(server, false, &budget.headers)
					if err != nil {
						return nil, err
					}
				}
			}
			responses.incomplete = responses.incomplete || server.missingBeforeFIN()
		}
		streams := make(map[uint32]*http2Exchange)
		if err := requests.selectFrames(false, streams, responses.resets, &budget); err != nil {
			return nil, err
		}
		if err := responses.selectFrames(true, streams, requests.resets, &budget); err != nil {
			return nil, err
		}
		for _, ex := range streams {
			row := &ex.row
			if row.Response == nil && (responses.incomplete || ex.responseInvalid) {
				row.Pairing = HTTP2ResponseAmbiguous
			}
			if err := finishHTTP2Body(&row.Request, ex.requestInvalid || client.anomalies.OverlapConflict, false, &budget); err != nil {
				return nil, err
			}
			if row.Response != nil {
				if err := finishHTTP2Body(row.Response, ex.responseInvalid, httpResponseHasNoBody(row.Request.Method, row.StatusCode), &budget); err != nil {
					return nil, err
				}
			}
			for idx, outside := range ex.outside {
				row.PacketIndices = append(row.PacketIndices, idx)
				row.SharedPackets = row.SharedPackets || outside > 0
			}
			slices.Sort(row.PacketIndices)
			rows = append(rows, *row)
			if export != nil && row.ID() == export.id {
				export.indices, err = http2ExportPackets(export.source, row, client, server)
				if err != nil {
					return nil, err
				}
			}
		}
	}
	slices.SortFunc(rows, func(a, b HTTP2Transaction) int {
		if n := cmp.Compare(a.Request.PacketIndex, b.Request.PacketIndex); n != 0 {
			return n
		}
		return cmp.Compare(a.Request.PacketPayloadOffset, b.Request.PacketPayloadOffset)
	})
	return rows, nil
}

// Keep at most MaxHTTP2FramesPerStream events in each direction. Reading both
// directions before selecting allows a reset on either side to bound its peer.
type http2TransactionFrames struct {
	dir        *http1Direction
	events     []http2FrameEvent
	resets     map[uint32]http2Reset
	incomplete bool
}

type http2Reset struct {
	packet int
	endSeq uint32
}

func readHTTP2TransactionFrames(d *http1Direction, client bool, headers *int) (http2TransactionFrames, error) {
	out := http2TransactionFrames{dir: d}
	end := 0
	if client {
		end = len(HTTP2ClientPreface)
	}
	sum, err := readHTTP2Frames(d.data, headers, false, nil, func(e http2FrameEvent) error {
		end = e.frame.end
		if e.streamID%2 == 0 || e.header.kind != HTTP2FrameHeaders && e.kind != HTTP2FrameData && e.kind != HTTP2FrameRSTStream {
			return nil // Includes unfinished header fragments, pushes and connection controls.
		}
		if _, reset := out.resets[e.streamID]; reset {
			return nil
		}
		if e.kind == HTTP2FrameRSTStream {
			if out.resets == nil {
				out.resets = make(map[uint32]http2Reset)
			}
			packet, _ := d.location(e.frame.end - 1)
			out.resets[e.streamID] = http2Reset{packet: packet.index, endSeq: d.spans[0].seq + uint32(e.frame.end)}
		}
		out.events = append(out.events, e)
		return nil
	})
	if err != nil && !errors.Is(err, ErrInvalidHTTP) {
		return out, err
	}
	if sum.FrameCount == MaxHTTP2FramesPerStream && len(d.data)-end >= 9 && !sum.HeadersIncomplete {
		return out, ErrHTTPLimit
	}
	out.incomplete = err != nil || sum.HeadersIncomplete || end < len(d.data) || d.anomalies.SequenceGap || d.anomalies.Truncated
	return out, nil
}

func (f *http2TransactionFrames) selectFrames(server bool, streams map[uint32]*http2Exchange, peerResets map[uint32]http2Reset, budget *http2TransactionBudget) error {
	d := f.dir
	var lastRequest uint32
	for _, e := range f.events {
		if rst, ok := peerResets[e.streamID]; ok {
			// Bytes already in flight may arrive after a reset. An ACK of the
			// reset puts this frame after it regardless of capture order.
			seg := d.spans[d.spanAt(e.frame.start)].segment
			after := d.dir.packets[seg].index > rst.packet
			if d.dir.segments[seg].Flags&TCPFlagACK != 0 {
				after = int32(d.acks[seg]-rst.endSeq) >= 0
			}
			if after {
				continue
			}
		}
		ex := streams[e.streamID]
		start := e.frame.start
		switch {
		case e.header.kind == HTTP2FrameHeaders:
			start = e.header.start // Includes all fragments through the final CONTINUATION.
			block := e.header.block
			if !server && ex == nil {
				if e.streamID <= lastRequest {
					continue
				}
				lastRequest = e.streamID
				if !validHTTP2Fields(block, true, false) {
					continue
				}
				if budget.transactions == 0 {
					return ErrHTTPLimit
				}
				budget.transactions--
				ex = &http2Exchange{row: HTTP2Transaction{
					FlowIndex: d.dir.flowIndex, Source: d.dir.src, Destination: d.dir.dst, StreamID: e.streamID,
					Request: http2MessageAt(d, start, block, e.endStream),
				}, client: d, requestEnd: e.frame.end, outside: make(map[int]int)}
				streams[e.streamID] = ex
			} else if ex == nil || !ex.headers(d, server, e) {
				continue
			}
		case e.kind == HTTP2FrameData:
			if ex == nil {
				continue
			}
			msg := &ex.row.Request
			invalid := &ex.requestInvalid
			if server {
				msg, invalid = ex.row.Response, &ex.responseInvalid
			}
			if *invalid || msg != nil && msg.EndStream {
				continue
			}
			if msg == nil {
				*invalid = true
				continue
			}
			data := d.data[e.data.start:e.data.end]
			take := min(len(data), MaxHTTPBodyBytes-len(msg.Body))
			msg.Body = append(msg.Body, data[:take]...)
			msg.BodyLimitExceeded = msg.BodyLimitExceeded || take < len(data)
			msg.EndStream = e.endStream
		case e.kind == HTTP2FrameRSTStream && ex != nil:
			ex.row.Reset = true
		default:
			continue // Reset on an unobserved stream.
		}
		if err := ex.addPackets(d, start, e.frame.end, &budget.packetRefs); err != nil {
			return err
		}
	}
	return nil
}

func http2MessageAt(d *http1Direction, start int, block HTTP2HeaderBlock, ended bool) HTTP2MessageEvidence {
	packet, offset := d.location(start)
	return HTTP2MessageEvidence{HTTP2HeaderBlock: block, PacketIndex: packet.index, PacketPayloadOffset: offset,
		TimestampNs: packet.timestamp, TCPAnomalies: d.anomalies, EndStream: ended}
}

func validHTTP2Fields(block HTTP2HeaderBlock, request, trailers bool) bool {
	var regular bool
	seen := make(map[string]bool, 6)
	for _, h := range block.Headers {
		name, pseudo := strings.CutPrefix(h.Name, ":")
		if !validHTTPFieldName([]byte(name)) || !validHTTPFieldValue([]byte(h.Value)) || strings.ContainsAny(name, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
			return false
		}
		if !pseudo {
			switch name {
			case "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade":
				return false
			case "te":
				if !strings.EqualFold(h.Value, "trailers") {
					return false
				}
			}
			regular = true
			continue
		}
		if regular || trailers {
			return false
		}
		switch h.Name {
		case ":method", ":scheme", ":authority", ":path", ":status":
		case ":protocol":
			if !validHTTPFieldName([]byte(h.Value)) {
				return false
			}
		default:
			return false
		}
		if seen[h.Name] || request == (h.Name == ":status") {
			return false
		}
		seen[h.Name] = true
	}
	if trailers || !request {
		return true
	}
	if !validHTTPFieldName([]byte(block.Method)) {
		return false
	}
	if block.Method == "CONNECT" {
		if block.Authority == "" {
			return false
		}
		if !seen[":protocol"] {
			return !seen[":scheme"] && !seen[":path"]
		}
		return block.Scheme != "" && block.Path != ""
	}
	return !seen[":protocol"] && block.Scheme != "" && block.Path != ""
}

func (ex *http2Exchange) headers(d *http1Direction, server bool, e http2FrameEvent) bool {
	block := e.header.block
	msg, invalid := &ex.row.Request, &ex.requestInvalid
	if server {
		msg, invalid = ex.row.Response, &ex.responseInvalid
	}
	if *invalid || msg != nil && msg.EndStream {
		return false
	}
	if msg == nil {
		// The response must acknowledge the entire opening header block,
		// including its last CONTINUATION. Request DATA can still be pending.
		if !http1Acknowledged(ex.client, d, ex.requestEnd-1, e.header.start) {
			*invalid = true
			return false
		}
		status, err := strconv.Atoi(block.Status)
		if len(block.Status) != 3 || err != nil || status < 100 || status > 599 || status == 101 || !validHTTP2Fields(block, false, false) {
			*invalid = true
			return false
		}
		if status < 200 {
			if e.endStream {
				*invalid = true
				return false
			}
			ex.row.Informational = append(ex.row.Informational, block)
			return true
		}
		final := http2MessageAt(d, e.header.start, block, e.endStream)
		ex.row.Response, ex.row.StatusCode, ex.row.Pairing = &final, status, HTTP2ResponseConfirmed
		return true
	}
	if !e.endStream || !validHTTP2Fields(block, !server, true) {
		*invalid = true
		return false
	}
	msg.Trailers, msg.EndStream = block.Headers, true
	return true
}

func (ex *http2Exchange) addPackets(d *http1Direction, start, end int, remaining *int) error {
	for i := d.spanAt(start); start < end; i++ {
		span := d.spans[i]
		idx := d.dir.packets[span.segment].index
		outside, ok := ex.outside[idx]
		if !ok {
			if *remaining == 0 {
				return ErrHTTPLimit
			}
			*remaining--
			outside = len(d.dir.segments[span.segment].Payload)
		}
		stop := min(end, span.end)
		ex.outside[idx] = outside - (stop - start)
		start = stop
	}
	return nil
}

func finishHTTP2Body(msg *HTTP2MessageEvidence, invalid, bodyless bool, budget *http2TransactionBudget) error {
	wire := msg.Body
	msg.Body = nil
	if invalid || bodyless && len(wire) != 0 {
		msg.BodyState = HTTPBodyUnknown
		return nil
	}
	if bodyless {
		msg.BodyState = HTTPBodyComplete
		return nil
	}
	framing := httpFraming{length: -1}
	var encodingSeen bool
	for _, field := range msg.Headers {
		switch field.Name {
		case "content-encoding":
			if encodingSeen {
				msg.BodyState = HTTPBodyUnsupported
				return nil
			}
			framing.encoding = strings.Trim(field.Value, " \t")
			if framing.encoding == "" {
				msg.BodyState = HTTPBodyUnknown
				return nil
			}
			encodingSeen = true
		case "content-length":
			for item := range strings.SplitSeq(field.Value, ",") {
				length, err := strconv.ParseUint(strings.Trim(item, " \t"), 10, 63)
				if err != nil || framing.length >= 0 && framing.length != int64(length) {
					msg.BodyState = HTTPBodyUnknown
					return nil
				}
				framing.length = int64(length)
			}
		}
	}
	if framing.length >= 0 && !msg.BodyLimitExceeded && (int64(len(wire)) > framing.length || msg.EndStream && int64(len(wire)) != framing.length) {
		msg.BodyState = HTTPBodyUnknown
		return nil
	}
	body := httpFramedBody{data: wire, truncated: !msg.EndStream, capped: msg.BodyLimitExceeded}
	var decoded HTTP1RequestEvidence
	if err := decoded.retainBody(body, framing, &budget.decode, &budget.bodyBytes); err != nil {
		return err
	}
	msg.Body, msg.BodyState, msg.BodyLimitExceeded = decoded.Body, decoded.BodyState, decoded.BodyLimitExceeded
	return nil
}
