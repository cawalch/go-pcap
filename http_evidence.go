package pcap

import (
	"bytes"
	"cmp"
	"errors"
	"io"
	"net/netip"
	"net/url"
	"slices"
	"strings"
)

// HTTPBodyState indicates how much decoded HTTP entity content is available.
type HTTPBodyState uint8

const (
	// HTTPBodyUnknown indicates malformed framing or invalid encoded content.
	HTTPBodyUnknown HTTPBodyState = iota
	// HTTPBodyComplete indicates the full entity is available, including an empty body.
	HTTPBodyComplete
	// HTTPBodyPartial indicates an available prefix, possibly empty, due to
	// incomplete framing, incomplete encoding, or a per-message limit.
	HTTPBodyPartial
	// HTTPBodyUnsupported indicates an unsupported transfer or content coding.
	HTTPBodyUnsupported
)

// HTTP1RequestEvidence contains a cleartext HTTP/1 request with complete
// headers. PacketIndex and PacketPayloadOffset identify the first byte of the
// request line within this capture. Both are zero-based. TimestampNs is the
// packet timestamp, possibly zero. Source and Destination follow request
// direction. Connections on the same tuple share a FlowIndex.
type HTTP1RequestEvidence struct {
	PacketIndex, PacketPayloadOffset, FlowIndex int
	TimestampNs                                 int64
	Source, Destination                         netip.AddrPort
	Method                                      string
	// Target contains the request-target bytes from the start line.
	Target string
	// Version contains the HTTP version without the HTTP/ prefix.
	Version string
	// Authority contains the authority from an absolute-form or CONNECT
	// target, or the first Host field value with surrounding spaces and tabs
	// removed. An unavailable authority is empty.
	Authority string
	// Headers contains fields in wire order, including duplicates. Name and
	// Value are the bytes on either side of the colon, including whitespace
	// and any folded continuation in Value. Trailers are excluded.
	Headers []HTTPHeader
	// Body contains the available entity bytes after removing chunk framing
	// and decoding content. It is empty for unknown and unsupported states.
	// Its length counts retained bytes. The caller owns Body and Headers.
	Body      []byte
	BodyState HTTPBodyState
	// BodyLimitExceeded reports that a per-message carving or decoding limit cut the body.
	BodyLimitExceeded bool
	Anomalies         HTTPAnomalies
	// TCPAnomalies applies to the reassembled request direction, including
	// gaps, overlap conflicts and reassembly truncation outside this request.
	TCPAnomalies StreamAnomalies
}

// HTTP1RequestEvidence returns cleartext HTTP/1 requests ordered by their
// capture packet index and TCP payload offset. It inspects the contiguous
// prefix of each direction and stops after a CONNECT or Upgrade request.
// The scan shares existing TCP and HTTP limit checks and returns no evidence
// if the result exceeds [MaxHTTP1RequestEvidenceBytesPerScan].
func (c *Capture) HTTP1RequestEvidence(data []byte) ([]HTTP1RequestEvidence, error) {
	return scanHTTP1RequestEvidence(ipFrameSource{capture: c, data: data})
}

// HTTP1RequestEvidenceFromReaderAt is the bounded ReaderAt equivalent of
// [Capture.HTTP1RequestEvidence]. Reads share [MaxReaderAtScanBytes].
func (c *Capture) HTTP1RequestEvidenceFromReaderAt(r io.ReaderAt) ([]HTTP1RequestEvidence, error) {
	return scanHTTP1RequestEvidence(c.tcpReaderAt(r))
}

func scanHTTP1RequestEvidence(source ipFrameSource) ([]HTTP1RequestEvidence, error) {
	collector, err := collectHTTPRequestStreams(source)
	if err != nil {
		return nil, err
	}
	var rows []HTTP1RequestEvidence
	budget := newHTTP1EvidenceBudget()
	err = collector.walkContiguous(func(dir *tcpMessageDirection, stream []byte, spans []packetSpan, anomalies StreamAnomalies) error {
		return walkHTTP1Evidence(dir, stream, spans, anomalies, &budget, func(row HTTP1RequestEvidence, _, _ int, _ bool) {
			rows = append(rows, row)
		})
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(rows, func(a, b HTTP1RequestEvidence) int {
		if order := cmp.Compare(a.PacketIndex, b.PacketIndex); order != 0 {
			return order
		}
		return cmp.Compare(a.PacketPayloadOffset, b.PacketPayloadOffset)
	})
	return rows, nil
}

type http1EvidenceBudget struct {
	messages, remaining int
	decode              httpDecodeBudget
}

func newHTTP1EvidenceBudget() http1EvidenceBudget {
	return http1EvidenceBudget{remaining: MaxHTTP1RequestEvidenceBytesPerScan, decode: httpDecodeBudget{remaining: MaxHTTPDecodedBodyBytesPerScan}}
}

func (b *http1EvidenceBudget) charge(headers int) error {
	if b.messages >= MaxHTTPMessagesPerScan || headers > b.remaining {
		return ErrHTTPLimit
	}
	b.messages++
	b.remaining -= headers
	return nil
}

// Visit each request with its known wire interval in stream sequence order.
func walkHTTP1Evidence(dir *tcpMessageDirection, stream []byte, spans []packetSpan, anomalies StreamAnomalies, budget *http1EvidenceBudget, visit func(HTTP1RequestEvidence, int, int, bool)) error {
	spanIndex, spanStart := 0, 0
	return walkHTTP1PlainRequests(stream, budget, func(row HTTP1RequestEvidence, off, end int, known bool) error {
		for spans[spanIndex].end <= off {
			spanStart = spans[spanIndex].end
			spanIndex++
		}
		span := spans[spanIndex]
		packet := dir.packets[span.segment]
		segment := dir.segments[span.segment]
		seq := segment.Seq
		if segment.Flags&TCPFlagSYN != 0 {
			seq++
		}
		row.PacketIndex, row.PacketPayloadOffset = packet.index, int(span.seq-seq)+off-spanStart
		row.FlowIndex, row.TimestampNs = dir.flowIndex, packet.timestamp
		row.Source, row.Destination, row.TCPAnomalies = dir.src, dir.dst, anomalies
		visit(row, off, end, known)
		return nil
	})
}

func walkHTTP1PlainRequests(stream []byte, budget *http1EvidenceBudget, visit func(HTTP1RequestEvidence, int, int, bool) error) error {
	for off := 0; off < len(stream); {
		data := stream[off:]
		req, lineEnd, err := parseHTTPRequestLine(data)
		if err != nil || req.Version[2] < '0' || req.Version[2] > '9' ||
			strings.IndexFunc(req.Path, func(r rune) bool { return r <= ' ' || r == 0x7f }) >= 0 {
			break
		}
		headers, bodyStart, framing, err := parseHTTPHeaders(data, lineEnd+2, true)
		if errors.Is(err, ErrHTTPLimit) {
			return err
		}
		if err != nil {
			break
		}
		if err := budget.charge(bodyStart); err != nil {
			return err
		}
		row := HTTP1RequestEvidence{
			PacketIndex: -1, PacketPayloadOffset: -1,
			Method: req.Method, Target: req.Path, Version: req.Version, Headers: headers,
			Anomalies: framing.anomalies,
		}
		var host string
		var hostSeen, upgrade bool
		for _, h := range headers {
			if !hostSeen && strings.EqualFold(h.Name, "Host") {
				host, hostSeen = strings.Trim(h.Value, " \t"), true
			}
			upgrade = upgrade || strings.EqualFold(h.Name, "Upgrade")
		}
		row.Authority = httpRequestAuthority(req.Method, req.Path, host)
		body := framing.body(data, bodyStart, true)
		if err := row.retainBody(body, framing, &budget.decode, &budget.remaining); err != nil {
			return err
		}
		end := body.consumed
		known := !body.malformed && (!framing.hasTransfer || framing.chunked)
		if !known {
			end = max(bodyStart, body.invalidEnd)
		}
		if err := visit(row, off, off+end, known); err != nil {
			return err
		}
		if req.Method == "CONNECT" || upgrade || body.malformed {
			break
		}
		off += body.consumed
	}
	return nil
}

func httpRequestAuthority(method, target, host string) string {
	if method == "CONNECT" {
		return target
	}
	if _, authority, ok := strings.Cut(target, "://"); ok {
		if parsed, err := url.ParseRequestURI(target); err == nil && parsed.IsAbs() && parsed.Host != "" {
			if end := strings.IndexAny(authority, "/?#"); end >= 0 {
				authority = authority[:end]
			}
			return authority
		}
	}
	return host
}

func (r *HTTP1RequestEvidence) retainBody(body httpFramedBody, framing httpFraming, budget *httpDecodeBudget, remaining *int) error {
	r.Anomalies.TruncatedBody = body.truncated
	r.BodyLimitExceeded = body.capped
	if body.malformed {
		return nil
	}
	if framing.unsupportedTransfer {
		r.BodyState = HTTPBodyUnsupported
		return nil
	}
	data := body.data
	partial := body.truncated || body.capped
	if framing.encoding != "" && !strings.EqualFold(framing.encoding, "identity") {
		reader, err := httpContentReader(data, framing.encoding)
		if reader != nil {
			data, err = readHTTPContent(reader, budget)
			body.ownedData = false // The decoder reuses its scratch across messages.
		} else if err == nil {
			r.BodyState = HTTPBodyUnsupported
			return nil
		} else {
			data = nil
		}
		if err != nil {
			if errors.Is(err, errHTTPDecodeBudget) {
				return err
			}
			r.Anomalies.InvalidContentEncoding = true
			if !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
				return nil
			}
			partial = true
		}
		if len(data) > MaxHTTPBodyBytes {
			data = data[:MaxHTTPBodyBytes]
			r.Anomalies.DecompressionLimitExceeded = true
			r.BodyLimitExceeded = true
			partial = true
		}
	}
	if len(data) > *remaining {
		return ErrHTTPLimit
	}
	*remaining -= len(data)
	if !body.ownedData {
		data = bytes.Clone(data)
	}
	r.Body = data
	r.BodyState = HTTPBodyComplete
	if partial {
		r.BodyState = HTTPBodyPartial
	}
	return nil
}
