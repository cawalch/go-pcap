package pcap

import (
	"cmp"
	"io"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// Aggregate limits for a keyed HTTP/3 transaction scan.
const (
	MaxHTTP3TransactionFrames = 65_536
	MaxHTTP3ContextRanges     = 262_144
)

// HTTP3SectionKind identifies a field section's role in a directional message.
type HTTP3SectionKind uint8

const (
	HTTP3UnclassifiedSection HTTP3SectionKind = iota
	HTTP3InitialSection
	HTTP3InformationalSection
	HTTP3TrailerSection
)

// HTTP3SectionEvidence locates compressed fields and identifies their HTTP
// role when both the field section and the preceding message order permit it.
type HTTP3SectionEvidence struct {
	QPACKFieldSection
	Kind HTTP3SectionKind
}

// HTTP3MessageEvidence holds one observed direction of an HTTP/3 request
// stream. Sections are in wire order. PacketIndices identifies every original
// packet carrying STREAM or RESET_STREAM frames for this direction, including
// retransmissions and bytes beyond a gap. SharedPackets reports other QUIC
// frames or coalesced long headers in any such datagram. QPACKPacketIndices is
// separate supporting encoder and peer SETTINGS context for decoded dynamic
// fields. Body holds bounded decoded entity bytes with [HTTPBodyState].
// EndStream means a clean FIN at the end of the reassembled prefix. Gap and
// Reset identify missing stream bytes and an observed RESET_STREAM. Invalid
// identifies invalid HTTP framing or field semantics.
type HTTP3MessageEvidence struct {
	Sections                                                         []HTTP3SectionEvidence
	PacketIndices, QPACKPacketIndices                                []int
	Body                                                             []byte
	BodyState                                                        HTTPBodyState
	BodyLimitExceeded, EndStream, Gap, Reset, Invalid, SharedPackets bool
}

// KeyedHTTP3Transaction identifies a client-initiated bidirectional stream in
// the original keyed scan. ConnectionIndex indexes [Capture.KeyedQUICWithALPN]
// for the same capture and keys. Source and Destination follow the QUIC
// client. A nil message direction was unobserved. StatusCode is zero until a
// final response was decoded. ALPNPacketIndices locates the negotiation.
type KeyedHTTP3Transaction struct {
	ConnectionIndex, FlowIndex int
	StreamID                   uint64
	Source, Destination        netip.AddrPort
	Request, Response          *HTTP3MessageEvidence
	StatusCode                 int
	ALPNPacketIndices          []int
}

// KeyedHTTP3Transactions recovers request stream evidence on connections with
// an authenticated "h3" selection. Rows follow connection and stream ID order.
// Key selection and packet association follow [Capture.KeyedQUICWithALPN].
// A scan or aggregate resource error returns no rows.
func (c *Capture) KeyedHTTP3Transactions(data, extraKeyLog []byte) ([]KeyedHTTP3Transaction, error) {
	records, err := c.KeyedQUICWithALPN(data, extraKeyLog)
	if err != nil {
		return nil, err
	}
	return keyedHTTP3Transactions(records)
}

// KeyedHTTP3TransactionsFromReaderAt is the bounded ReaderAt equivalent of
// [Capture.KeyedHTTP3Transactions]. Both keyed packet scans share [MaxReaderAtScanBytes].
func (c *Capture) KeyedHTTP3TransactionsFromReaderAt(r io.ReaderAt, extraKeyLog []byte) ([]KeyedHTTP3Transaction, error) {
	records, err := c.KeyedQUICWithALPNFromReaderAt(r, extraKeyLog)
	if err != nil {
		return nil, err
	}
	return keyedHTTP3Transactions(records)
}

type http3SectionRef struct {
	input  QPACKSectionInput
	stream *http3LocatedStream
	step   int
}

func (d *http3Direction) decodeSections(peer *http3Direction, budget *http2TransactionBudget) error {
	var refs []http3SectionRef
	for _, s := range d.requests {
		for _, f := range s.framing.Frames {
			if f.Type != HTTP3FrameHeaders {
				continue
			}
			if len(refs) == MaxQUICStreamFrames {
				return ErrHTTP3Limit
			}
			end := f.PayloadOffset + f.PayloadLength
			step := s.arrival(end)
			in := QPACKSectionInput{StreamID: s.stream.ID, Offset: f.PayloadOffset, Data: s.stream.Data[f.PayloadOffset:end]}
			if d.encoder != nil {
				in.EncoderOffset = d.encoder.prefixAt(step)
			}
			refs = append(refs, http3SectionRef{in, s, step})
		}
	}
	// Stable ordering keeps multiple frames made available by the same QUIC
	// STREAM frame in wire order.
	slices.SortStableFunc(refs, func(a, b http3SectionRef) int { return cmp.Compare(a.step, b.step) })
	var encoder QUICStream
	if d.encoder != nil && peer.settingsKnown {
		encoder = d.encoder.stream
	}
	input := make([]QPACKSectionInput, len(refs))
	for i, ref := range refs {
		input[i] = ref.input
		if !peer.settingsKnown {
			input[i].EncoderOffset = 0
		}
	}
	rows, err := decodeQPACKSections(encoder, peer.capacity, input, &budget.headers)
	if err != nil {
		return err
	}
	for i, row := range rows {
		// Without the advertised maximum, a wrapped nonzero insert count
		// cannot be reconstructed, even if some encoder bytes were captured.
		if !peer.settingsKnown && row.State == QPACKMalformed {
			p := hpackInput(input[i].Data)
			count, err := p.prefixedInteger(255)
			if err == nil && count != 0 && len(p) > 0 {
				if _, err = p.prefixedInteger(127); err == nil {
					row.State = QPACKBlocked
				}
			}
		}
		refs[i].stream.sections = append(refs[i].stream.sections, row)
	}
	return nil
}

func keyedHTTP3Transactions(records []KeyedQUICRecord) ([]KeyedHTTP3Transaction, error) {
	budget := newHTTP2TransactionBudget()
	contextWork, frames := MaxHTTP3ContextRanges, MaxHTTP3TransactionFrames
	var rows []KeyedHTTP3Transaction
	for index := range records {
		c := &records[index]
		if c.ALPN == nil || c.ALPN.Protocol != "h3" {
			continue
		}
		client, err := locateHTTP3Streams(c.Client, false, &frames)
		if err != nil {
			return nil, err
		}
		server, err := locateHTTP3Streams(c.Server, true, &frames)
		if err != nil {
			return nil, err
		}
		if err = client.decodeSections(&server, &budget); err != nil {
			return nil, err
		}
		if err = server.decodeSections(&client, &budget); err != nil {
			return nil, err
		}
		for ci, si := 0, 0; ci < len(client.requests) || si < len(server.requests); {
			id := uint64(1 << 62)
			if ci < len(client.requests) {
				id = client.requests[ci].stream.ID
			}
			if si < len(server.requests) {
				id = min(id, server.requests[si].stream.ID)
			}
			if len(rows) == MaxHTTPMessagesPerScan || len(c.ALPN.PacketIndices) > budget.packetRefs {
				return nil, ErrHTTP3Limit
			}
			budget.packetRefs -= len(c.ALPN.PacketIndices)
			row := KeyedHTTP3Transaction{ConnectionIndex: index, FlowIndex: c.FlowIndex, StreamID: id, Source: netip.AddrPortFrom(c.SrcAddr, c.SrcPort), Destination: netip.AddrPortFrom(c.DstAddr, c.DstPort), ALPNPacketIndices: slices.Clone(c.ALPN.PacketIndices)}
			method := ""
			if ci < len(client.requests) && client.requests[ci].stream.ID == id {
				row.Request, method, _, err = client.requests[ci].message(true, "", &client, &server, &budget, &contextWork)
				if err != nil {
					return nil, err
				}
				ci++
			}
			if si < len(server.requests) && server.requests[si].stream.ID == id {
				row.Response, _, row.StatusCode, err = server.requests[si].message(false, method, &server, &client, &budget, &contextWork)
				if err != nil {
					return nil, err
				}
				si++
			}
			rows = append(rows, row)
		}
	}
	return rows, nil
}

func (s *http3LocatedStream) message(request bool, method string, dir, peer *http3Direction, budget *http2TransactionBudget, work *int) (*HTTP3MessageEvidence, string, int, error) {
	m := &HTTP3MessageEvidence{PacketIndices: s.packets, SharedPackets: s.shared, Invalid: s.invalid, EndStream: s.stream.Complete, Gap: s.stream.Gap, Reset: s.stream.Reset}
	if len(m.PacketIndices) > budget.packetRefs {
		return nil, "", 0, ErrHTTP3Limit
	}
	budget.packetRefs -= len(m.PacketIndices)
	var body HTTP2MessageEvidence
	var initial, trailers, uncertain bool
	var tunnel, possibleTunnel, opaqueData bool
	var section, status, encoderEnd int
	for _, f := range s.framing.Frames {
		// After the server accepts CONNECT, HEADERS and PUSH_PROMISE
		// cannot occur on that tunnel (RFC 9114 section 4.4). Keep their
		// packet membership and any observable QPACK section.
		if !request && tunnel && (f.Type == HTTP3FrameHeaders || f.Type == HTTP3FramePushPromise) {
			m.Invalid = true
		}
		switch f.Type {
		case HTTP3FrameHeaders:
			row := s.sections[section]
			section++
			encoderEnd = max(encoderEnd, row.EncoderOffset)
			h := HTTP3SectionEvidence{QPACKFieldSection: row}
			if row.State != QPACKDecoded {
				uncertain = true
				m.Invalid = m.Invalid || row.State == QPACKMalformed
			}
			if !uncertain && !m.Invalid {
				block := http3HeaderBlock(row.Headers)
				switch {
				case trailers || !validHTTP2Fields(block, request, initial) || request && !initial && !validHTTP3Authority(block):
					m.Invalid = true
				case initial:
					h.Kind = HTTP3TrailerSection
					trailers = true
				case request:
					h.Kind = HTTP3InitialSection
					initial = true
					method = block.Method
					// A CONNECT request has no entity. Client DATA can already carry
					// prospective tunnel bytes before the response appears.
					tunnel = method == "CONNECT"
					body.HTTP2HeaderBlock = block
				default:
					code, err := strconv.Atoi(block.Status)
					switch {
					case err != nil || len(block.Status) != 3 || code < 100 || code > 599 || code == 101:
						m.Invalid = true
					case code < 200:
						h.Kind = HTTP3InformationalSection
					default:
						h.Kind = HTTP3InitialSection
						initial = true
						status = code
						tunnel = method == "CONNECT" && code/100 == 2
						possibleTunnel = method == "" && code/100 == 2
						body.HTTP2HeaderBlock = block
					}
				}
			}
			m.Sections = append(m.Sections, h)
		case HTTP3FrameData:
			if !uncertain && (!initial || trailers) {
				m.Invalid = true
			}
			if possibleTunnel && f.PayloadLength != 0 {
				opaqueData = true
			}
			if initial && !trailers && !uncertain && !m.Invalid && !tunnel && !possibleTunnel {
				body.Body = append(body.Body, s.stream.Data[f.PayloadOffset:f.PayloadOffset+f.PayloadLength]...)
			}
		}
	}
	if initial && !trailers && !m.Invalid && !uncertain && !tunnel && s.framing.Truncated {
		// ParseHTTP3Stream lists complete frames. A gap within a DATA frame
		// still provides the entity prefix after its full type and length.
		off := 0
		if n := len(s.framing.Frames); n != 0 {
			last := s.framing.Frames[n-1]
			off = last.PayloadOffset + last.PayloadLength
		}
		tail := s.stream.Data[off:]
		if typ, n, ok := ReadQUICVarint(tail); ok && typ == HTTP3FrameData {
			if length, k, ok := ReadQUICVarint(tail[n:]); ok {
				if possibleTunnel {
					opaqueData = opaqueData || length != 0
				} else {
					body.Body = append(body.Body, tail[n+k:]...)
				}
			}
		}
	}
	if !initial && m.EndStream && !uncertain {
		m.Invalid = true
	}
	body.EndStream = m.EndStream
	if err := finishHTTP2Body(&body, m.Invalid || !initial || uncertain || opaqueData, tunnel || !request && httpResponseHasNoBody(method, status), budget); err != nil {
		return nil, "", 0, err
	}
	m.Body, m.BodyState, m.BodyLimitExceeded = body.Body, body.BodyState, body.BodyLimitExceeded
	if encoderEnd != 0 {
		indices := make(map[int]bool)
		if err := dir.encoder.contextPackets(encoderEnd, indices, work); err != nil {
			return nil, "", 0, err
		}
		if err := peer.control.contextPackets(peer.settingsEnd, indices, work); err != nil {
			return nil, "", 0, err
		}
		if len(indices) > budget.packetRefs {
			return nil, "", 0, ErrHTTP3Limit
		}
		budget.packetRefs -= len(indices)
		m.QPACKPacketIndices = slices.Sorted(maps.Keys(indices))
	}
	return m, method, status, nil
}

// Return the original encoder/SETTINGS packets intersecting the requisite
// prefix. Identical observed retransmissions can be present in this context.
func (s *http3LocatedStream) contextPackets(end int, indices map[int]bool, remaining *int) error {
	if s == nil || len(s.contributions) > *remaining {
		return ErrHTTP3Limit
	}
	*remaining -= len(s.contributions)
	for _, r := range s.contributions {
		if r.start < end {
			indices[r.packet] = true
		}
	}
	return nil
}

// RFC 9114 section 4.3.1 requires a nonempty authority for HTTP(S).
// When both forms appear they must carry the same field value.
func validHTTP3Authority(block HTTP2HeaderBlock) bool {
	if !strings.EqualFold(block.Scheme, "http") && !strings.EqualFold(block.Scheme, "https") {
		return true
	}
	var host string
	for _, field := range block.Headers {
		if field.Name != ":authority" && field.Name != "host" {
			continue
		}
		if field.Value == "" || strings.ContainsAny(field.Value, " \t@/?#") {
			return false
		}
		if field.Name == "host" {
			if host != "" {
				return false
			}
			host = field.Value
		}
	}
	return (block.Authority != "" || host != "") && (block.Authority == "" || host == "" || block.Authority == host)
}

func http3HeaderBlock(fields []HTTPHeader) HTTP2HeaderBlock {
	block := HTTP2HeaderBlock{Headers: fields}
	for _, h := range fields {
		switch h.Name {
		case ":method":
			block.Method = h.Value
		case ":authority":
			block.Authority = h.Value
		case ":path":
			block.Path = h.Value
		case ":scheme":
			block.Scheme = h.Value
		case ":status":
			block.Status = h.Value
		}
	}
	return block
}
