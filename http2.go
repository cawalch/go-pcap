package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// HTTP2ClientPreface is the 24-byte RFC 9113 §3.4 HTTP/2 client connection preface.
var HTTP2ClientPreface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

// HTTP/2 frame type codes (RFC 9113 §6).
const (
	HTTP2FrameData         uint8 = 0x0
	HTTP2FrameHeaders      uint8 = 0x1
	HTTP2FramePriority     uint8 = 0x2
	HTTP2FrameRSTStream    uint8 = 0x3
	HTTP2FrameSettings     uint8 = 0x4
	HTTP2FramePushPromise  uint8 = 0x5
	HTTP2FramePing         uint8 = 0x6
	HTTP2FrameGoAway       uint8 = 0x7
	HTTP2FrameWindowUpdate uint8 = 0x8
	HTTP2FrameContinuation uint8 = 0x9
)

// HTTP2Setting represents a single 6-byte parameter in an HTTP/2 SETTINGS frame.
type HTTP2Setting struct {
	ID    uint16
	Value uint32
}

// HTTP2HeaderBlock contains one complete directional HEADERS or PUSH_PROMISE
// block. Headers preserves wire order, including pseudo-headers. An absent
// pseudo-header has an empty value.
type HTTP2HeaderBlock struct {
	Method, Scheme, Authority, Path, Status string
	Headers                                 []HTTPHeader
}

// HTTP2StreamData holds DATA and decoded header blocks for one stream ID.
// Informational responses and trailers retain their own blocks in wire order.
type HTTP2StreamData struct {
	StreamID     uint32
	Data         []byte
	HeaderBlocks []HTTP2HeaderBlock
}

// HTTP2Summary contains the parsed HTTP/2 frames, SETTINGS parameters, and
// carved DATA stream bodies from a directional HTTP/2 stream.
type HTTP2Summary struct {
	HasClientPreface    bool
	FrameCount          int
	Settings            []HTTP2Setting
	SettingsFingerprint string
	WindowUpdate        uint32
	Streams             []HTTP2StreamData
	// HeadersIncomplete means a truncated or invalid HPACK block made later
	// headers undecodable. A known TCP gap suppresses headers for that direction
	// because reassembly cannot locate its missing HPACK table updates.
	HeadersIncomplete bool
	// AkamaiFingerprint is populated on the first decoded client request.
	AkamaiFingerprint string
}

// HTTP2Record associates a parsed [HTTP2Summary] with its 5-tuple TCP flow and
// indicates whether it was extracted from a decrypted TLS stream.
type HTTP2Record struct {
	FlowIndex   int
	SrcAddr     netip.Addr
	DstAddr     netip.Addr
	SrcPort     uint16
	DstPort     uint16
	IsServer    bool // The client preface identifies cleartext roles when present in one direction.
	IsDecrypted bool
	Summary     HTTP2Summary
}

// ParseHTTP2Frames parses an HTTP/2 byte stream (starting either with the
// 24-byte client connection preface or directly with a 9-byte HTTP/2 SETTINGS
// frame), extracts SETTINGS parameters and their fingerprint, and decodes header blocks and DATA by stream ID. Header field storage is
// limited to [MaxHTTP2DecodedHeaderBytes] and DATA to [MaxHTTPBodyBytes].
func ParseHTTP2Frames(stream []byte) (HTTP2Summary, error) {
	remaining := MaxHTTP2DecodedHeaderBytes
	return parseHTTP2Frames(stream, &remaining, false)
}

func parseHTTP2Frames(stream []byte, remaining *int, sequenceGap bool) (HTTP2Summary, error) {
	return readHTTP2Frames(stream, remaining, sequenceGap, nil, nil)
}

// http2Range identifies a half-open interval in the input direction.
type http2Range struct {
	start, end int
}

type http2FrameEvent struct {
	frame       http2Range
	data        http2Range // Unpadded payload interval, including an empty interval for empty DATA.
	streamID    uint32     // Stream ID in the physical frame header.
	kind, flags uint8
	endStream   bool // Confirmed on valid DATA or after decoding HEADERS that carried END_STREAM.
	header      http2HeaderEvent
}

// A header event is populated on the last frame of a decoded block. The opening
// frame may precede it, and a push targets the promised stream.
type http2HeaderEvent struct {
	block    HTTP2HeaderBlock
	start    int
	streamID uint32 // Zero when the frame did not complete a block.
	kind     uint8  // HEADERS or PUSH_PROMISE, even if the last frame was CONTINUATION.
}

// A frame visitor receives physical frames up to a truncation, frame limit,
// invalid stream event, or loss of HPACK state. Compare the last frame end
// (or the end of the preface if no frames were reported) with len(stream) to
// detect an unvisited suffix. Pass a contiguous prefix with sequenceGap false
// to observe frames before a known gap. Visitors take the place of summary
// body and header collection.
func readHTTP2Frames(stream []byte, remaining *int, sequenceGap bool, request func(offset int, streamID uint32, block HTTP2HeaderBlock) error, visit func(http2FrameEvent) error) (HTTP2Summary, error) {
	out := HTTP2Summary{HeadersIncomplete: sequenceGap}
	collectSummary := request == nil && visit == nil
	if sequenceGap {
		visit = nil
	}
	offset := 0
	if bytes.HasPrefix(stream, HTTP2ClientPreface) {
		out.HasClientPreface = true
		offset = len(HTTP2ClientPreface)
	}

	if len(stream)-offset < 9 {
		if out.HasClientPreface {
			return out, nil
		}
		return HTTP2Summary{}, fmt.Errorf("%w: buffer shorter than 9-byte HTTP/2 frame header", ErrInvalidHTTP)
	}
	// If no client preface is present, require the first frame to be a valid SETTINGS frame (type 0x04, stream 0).
	if !out.HasClientPreface {
		firstType := stream[offset+3]
		firstFlags := stream[offset+4]
		firstStream := binary.BigEndian.Uint32(stream[offset+5:offset+9]) & 0x7fffffff
		firstLen := int(stream[offset])<<16 | int(stream[offset+1])<<8 | int(stream[offset+2])
		if firstType != HTTP2FrameSettings || firstStream != 0 || (firstFlags&^0x01) != 0 || firstLen%6 != 0 || firstLen > MaxHTTP2Settings*6 || ((firstFlags&0x01) != 0 && firstLen != 0) {
			return HTTP2Summary{}, fmt.Errorf("%w: stream does not begin with HTTP/2 preface or SETTINGS frame", ErrInvalidHTTP)
		}
	}

	byID := make(map[uint32]int)
	getStream := func(id uint32) *HTTP2StreamData {
		if i, ok := byID[id]; ok {
			return &out.Streams[i]
		}
		byID[id] = len(out.Streams)
		out.Streams = append(out.Streams, HTTP2StreamData{StreamID: id})
		return &out.Streams[len(out.Streams)-1]
	}
	headers := http2Headers{table: hpackTable{limit: MaxHTTP2DynamicTableBytes}}
	var priorities []string
	var headerStart int
	var headerKind uint8
	settingsSeen := false
	totalDataBytes := 0

	for offset+9 <= len(stream) && out.FrameCount < MaxHTTP2FramesPerStream {
		fLen := int(stream[offset])<<16 | int(stream[offset+1])<<8 | int(stream[offset+2])
		fType := stream[offset+3]
		fFlags := stream[offset+4]
		streamID := binary.BigEndian.Uint32(stream[offset+5:offset+9]) & 0x7fffffff
		offset += 9

		if fLen > MaxHTTP2FramePayload || offset+fLen > len(stream) {
			if isHTTP2HeaderFrame(fType) {
				out.HeadersIncomplete = true
			}
			break
		}
		payload := stream[offset : offset+fLen]
		offset += fLen
		out.FrameCount++

		if headers.continuation != 0 && (fType != HTTP2FrameContinuation || streamID != headers.continuation) {
			out.HeadersIncomplete = true
			visit = nil
		}
		switch fType {
		case HTTP2FramePriority:
			if out.HasClientPreface && out.AkamaiFingerprint == "" && streamID != 0 && len(payload) == 5 {
				dep := binary.BigEndian.Uint32(payload)
				priorities = append(priorities, fmt.Sprintf("%d:%d:%d:%d", streamID, dep>>31, dep&0x7fffffff, int(payload[4])+1))
			}
		case HTTP2FrameHeaders, HTTP2FramePushPromise, HTTP2FrameContinuation:
			if out.HeadersIncomplete {
				continue
			}
			if fType != HTTP2FrameContinuation {
				headerStart, headerKind = offset-fLen-9, fType
			}
			block, complete, err := headers.consume(fType, fFlags, streamID, payload, remaining)
			if errors.Is(err, ErrHTTPLimit) {
				return HTTP2Summary{}, err
			}
			if err != nil {
				out.HeadersIncomplete = true
				visit = nil
				continue
			}
			if !complete {
				break
			}
			if collectSummary {
				st := getStream(headers.target)
				st.HeaderBlocks = append(st.HeaderBlocks, block)
				if out.HasClientPreface && out.AkamaiFingerprint == "" && block.Method != "" {
					out.AkamaiFingerprint = out.fingerprint(priorities, block)
				}
				continue
			}
			if request != nil && headerKind == HTTP2FrameHeaders && block.Method != "" {
				if err := request(headerStart, headers.target, block); err != nil {
					return HTTP2Summary{}, err
				}
			}
			if visit != nil {
				if err := visit(http2FrameEvent{
					frame: http2Range{offset - fLen - 9, offset}, streamID: streamID, kind: fType, flags: fFlags,
					header:    http2HeaderEvent{block: block, start: headerStart, streamID: headers.target, kind: headerKind},
					endStream: headerKind == HTTP2FrameHeaders && stream[headerStart+4]&0x01 != 0,
				}); err != nil {
					return HTTP2Summary{}, err
				}
			}
			continue
		case HTTP2FrameSettings:
			// Ignore SETTINGS ACK frames (flag 0x01 with empty payload) and non-connection streams.
			if streamID == 0 && (fFlags&0x01) == 0 && !settingsSeen && len(payload)%6 == 0 {
				settingsSeen = true
				count := min(len(payload)/6, MaxHTTP2Settings)
				out.Settings = make([]HTTP2Setting, count)
				var fpBuf [128]byte
				fp := fpBuf[:0]
				for i := range count {
					id := binary.BigEndian.Uint16(payload[i*6 : i*6+2])
					val := binary.BigEndian.Uint32(payload[i*6+2 : i*6+6])
					out.Settings[i] = HTTP2Setting{ID: id, Value: val}
					if i > 0 {
						fp = append(fp, ';')
					}
					fp = strconv.AppendUint(fp, uint64(id), 10)
					fp = append(fp, ':')
					fp = strconv.AppendUint(fp, uint64(val), 10)
				}
				out.SettingsFingerprint = string(fp)
			}

		case HTTP2FrameWindowUpdate:
			if streamID == 0 && len(payload) == 4 && out.WindowUpdate == 0 {
				out.WindowUpdate = binary.BigEndian.Uint32(payload) & 0x7fffffff
			}

		case HTTP2FrameData:
			if !collectSummary && visit == nil {
				continue
			}
			if streamID == 0 {
				visit = nil
				continue
			}
			dataStart, dataEnd := offset-fLen, offset
			if (fFlags & 0x08) != 0 {
				// PADDED flag: 1-byte Pad Length prefix.
				if len(payload) == 0 || int(payload[0]) >= len(payload) {
					visit = nil
					continue
				}
				dataStart++
				dataEnd -= int(payload[0])
			}
			if collectSummary {
				if dataEnd > dataStart && totalDataBytes < MaxHTTPBodyBytes {
					take := min(dataEnd-dataStart, MaxHTTPBodyBytes-totalDataBytes)
					st := getStream(streamID)
					st.Data = append(st.Data, stream[dataStart:dataStart+take]...)
					totalDataBytes += take
				}
				continue
			}
			if err := visit(http2FrameEvent{
				frame: http2Range{offset - fLen - 9, offset}, streamID: streamID, kind: fType, flags: fFlags,
				data: http2Range{dataStart, dataEnd}, endStream: fFlags&0x01 != 0,
			}); err != nil {
				return HTTP2Summary{}, err
			}
			continue
		case HTTP2FrameRSTStream:
			if len(payload) != 4 || streamID == 0 {
				visit = nil
			}
		}
		if visit != nil {
			if err := visit(http2FrameEvent{
				frame: http2Range{offset - fLen - 9, offset}, streamID: streamID, kind: fType, flags: fFlags,
			}); err != nil {
				return HTTP2Summary{}, err
			}
		}
	}

	if out.FrameCount == 0 && !out.HasClientPreface {
		return HTTP2Summary{}, fmt.Errorf("%w: no valid HTTP/2 frames decoded", ErrInvalidHTTP)
	}
	if headers.continuation != 0 || (len(stream)-offset >= 4 && len(stream)-offset < 9 && isHTTP2HeaderFrame(stream[offset+3])) {
		out.HeadersIncomplete = true
	}
	return out, nil
}

// HTTP2 extracts HTTP/2 frame summaries, SETTINGS fingerprints, and carved DATA
// stream payloads from both cleartext TCP streams (h2c) and DSB-decrypted TLS
// 1.2/1.3 streams.
func (c *Capture) HTTP2(data []byte) ([]HTTP2Record, error) {
	streams, err := c.Streams(data)
	if err != nil {
		return nil, err
	}
	keys, _ := c.TLSKeyLog(nil)
	var records []HTTP2Record
	if err := scanHTTPStreams(streams, nil, keys, nil, &records, nil); err != nil {
		return nil, err
	}
	return records, nil
}

func appendHTTP2FromTCPStream(st *TCPStream, isDecrypted bool, records *[]HTTP2Record, remaining *int) error {
	// TCP stream direction follows the first packet, which can come from the server.
	reversed := !isDecrypted && bytes.HasPrefix(st.Server.Data, HTTP2ClientPreface) && !bytes.HasPrefix(st.Client.Data, HTTP2ClientPreface)
	if len(st.Client.Data) >= 9 {
		sum, err := parseHTTP2Frames(st.Client.Data, remaining, st.Client.Anomalies.SequenceGap)
		if errors.Is(err, ErrHTTPLimit) {
			return err
		}
		if err == nil {
			if len(*records) >= MaxHTTPMessagesPerScan {
				return fmt.Errorf("%w: exceeds %d HTTP/2 records", ErrHTTPLimit, MaxHTTPMessagesPerScan)
			}
			*records = append(*records, HTTP2Record{
				FlowIndex:   st.FlowIndex,
				SrcAddr:     st.SrcAddr,
				DstAddr:     st.DstAddr,
				SrcPort:     st.SrcPort,
				DstPort:     st.DstPort,
				IsServer:    reversed,
				IsDecrypted: isDecrypted,
				Summary:     sum,
			})
		}
	}
	if len(st.Server.Data) >= 9 {
		sum, err := parseHTTP2Frames(st.Server.Data, remaining, st.Server.Anomalies.SequenceGap)
		if errors.Is(err, ErrHTTPLimit) {
			return err
		}
		if err == nil {
			if len(*records) >= MaxHTTPMessagesPerScan {
				return fmt.Errorf("%w: exceeds %d HTTP/2 records", ErrHTTPLimit, MaxHTTPMessagesPerScan)
			}
			*records = append(*records, HTTP2Record{
				FlowIndex:   st.FlowIndex,
				SrcAddr:     st.DstAddr,
				DstAddr:     st.SrcAddr,
				SrcPort:     st.DstPort,
				DstPort:     st.SrcPort,
				IsServer:    !reversed,
				IsDecrypted: isDecrypted,
				Summary:     sum,
			})
		}
	}
	return nil
}

// fingerprint formats the observed initial client settings, window, priorities,
// and pseudo-header order after the first request header block completes.
func (out *HTTP2Summary) fingerprint(priorities []string, block HTTP2HeaderBlock) string {
	// Four request pseudo-headers and their separators fit on the stack.
	var buf [7]byte
	order := buf[:0]
	for _, f := range block.Headers {
		switch f.Name {
		case ":method", ":scheme", ":authority", ":path":
			if len(order) != 0 {
				order = append(order, ',')
			}
			order = append(order, f.Name[1])
		}
	}
	priority := "0"
	if len(priorities) > 0 {
		priority = strings.Join(priorities, ",")
	}
	return out.SettingsFingerprint + "|" + strconv.FormatUint(uint64(out.WindowUpdate), 10) + "|" + priority + "|" + string(order)
}

func isHTTP2HeaderFrame(kind uint8) bool {
	return kind == HTTP2FrameHeaders || kind == HTTP2FramePushPromise || kind == HTTP2FrameContinuation
}

// HPACK state belongs to one direction, even when its frames serve multiple streams.
type http2Headers struct {
	table                hpackTable
	continuation, target uint32
	fragments            []byte
}

func (h *http2Headers) consume(kind, flags uint8, id uint32, p []byte, remaining *int) (HTTP2HeaderBlock, bool, error) {
	var empty HTTP2HeaderBlock
	if id == 0 || (kind == HTTP2FrameContinuation && h.continuation != id) {
		return empty, false, ErrInvalidHTTP
	}
	if kind != HTTP2FrameContinuation {
		h.target = id
		if flags&8 != 0 {
			if len(p) == 0 || int(p[0]) >= len(p) {
				return empty, false, ErrInvalidHTTP
			}
			p = p[1 : len(p)-int(p[0])]
		}
		switch {
		case kind == HTTP2FramePushPromise:
			if len(p) < 4 {
				return empty, false, ErrInvalidHTTP
			}
			h.target = binary.BigEndian.Uint32(p) & 0x7fffffff
			if h.target == 0 {
				return empty, false, ErrInvalidHTTP
			}
			p = p[4:]
		case flags&32 != 0:
			if len(p) < 5 || binary.BigEndian.Uint32(p)&0x7fffffff == id {
				return empty, false, ErrInvalidHTTP
			}
			p = p[5:]
		}
	}
	if len(p) > MaxHTTP2HeaderBlockBytes-len(h.fragments) {
		return empty, false, ErrHTTPLimit
	}
	if h.continuation != 0 || flags&4 == 0 {
		h.fragments = append(h.fragments, p...)
		if flags&4 == 0 {
			h.continuation = id
			return empty, false, nil
		}
		p = h.fragments
		h.fragments = h.fragments[:0]
	}
	h.continuation = 0
	block, err := h.table.decode(p, remaining)
	return block, err == nil, err
}
