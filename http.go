package pcap

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// HTTPHeader represents a name-value HTTP header field in wire order.
type HTTPHeader struct {
	Name  string
	Value string
}

// HTTPAnomalies reports framing and content decoding observations for one message.
type HTTPAnomalies struct {
	// MultipleContentLength reports conflicting numeric Content-Length values.
	MultipleContentLength bool
	// TransferEncodingWithContentLength reports that both fields appeared.
	TransferEncodingWithContentLength bool
	// ObsFoldHeader reports a header continued on a whitespace-prefixed line.
	ObsFoldHeader bool
	// TruncatedBody reports incomplete declared length or chunk framing.
	TruncatedBody bool
	// InvalidContentEncoding indicates a supported content coding failed to decode.
	InvalidContentEncoding bool
	// DecompressionLimitExceeded indicates Body contains the first
	// [MaxHTTPBodyBytes] bytes of a larger decoded body.
	DecompressionLimitExceeded bool
}

// HTTPRequest contains a parsed HTTP/1.x request, its FoxIO JA4H fingerprint,
// and its carved body payload.
type HTTPRequest struct {
	Method      string
	Path        string
	Version     string
	Host        string
	UserAgent   string
	ContentType string
	// ContentEncoding contains the Content-Encoding field values in wire order,
	// separated by commas if the message has multiple fields.
	ContentEncoding string
	// IsDecompressed reports whether Body contains decoded content.
	IsDecompressed bool
	Anomalies      HTTPAnomalies
	Headers        []HTTPHeader
	CookieCount    int
	Body           []byte
	// BodyOffset is the start of the wire body in the input stream.
	BodyOffset int
	// BodyLength is the number of bytes in Body after carving and any decoding.
	BodyLength int
	JA4H       string
}

// HTTPResponse contains a parsed HTTP/1.x response and its carved body payload.
type HTTPResponse struct {
	Version     string
	StatusCode  int
	StatusText  string
	Server      string
	ContentType string
	// ContentEncoding contains the Content-Encoding field values in wire order,
	// separated by commas if the message has multiple fields.
	ContentEncoding string
	// IsDecompressed reports whether Body contains decoded content.
	IsDecompressed bool
	Anomalies      HTTPAnomalies
	Headers        []HTTPHeader
	Body           []byte
	// BodyOffset is the start of the wire body in the input stream.
	BodyOffset int
	// BodyLength is the number of bytes in Body after carving and any decoding.
	BodyLength int
}

// HTTPRecord associates a parsed HTTP request or response with its flow metadata
// and indicates whether it was extracted from a decrypted TLS stream.
type HTTPRecord struct {
	FlowIndex   int
	SrcAddr     netip.Addr
	DstAddr     netip.Addr
	SrcPort     uint16
	DstPort     uint16
	IsResponse  bool
	IsDecrypted bool
	Request     HTTPRequest
	Response    HTTPResponse
}

// ParseHTTPRequest parses one HTTP/1.x request from stream, computes its JA4H
// fingerprint, and carves its body. It decodes single gzip, x-gzip, and deflate
// content codings after removing chunk framing. See [HTTPAnomalies] for framing and decoding observations.
// When framing cannot locate the next message, the byte count covers all input.
func ParseHTTPRequest(stream []byte) (HTTPRequest, int, error) {
	return parseHTTPRequest(stream, nil)
}

func parseHTTPRequestLine(stream []byte) (HTTPRequest, int, error) {
	lineEnd := httpStartLineEnd(stream)
	if lineEnd <= 0 || lineEnd > MaxHTTPHeaderLineBytes {
		return HTTPRequest{}, 0, fmt.Errorf("%w: missing or oversize HTTP request line", ErrInvalidHTTP)
	}
	reqLine := string(stream[:lineEnd])
	sp1 := strings.IndexByte(reqLine, ' ')
	sp2 := strings.LastIndexByte(reqLine, ' ')
	if sp1 <= 0 || sp2 <= sp1+1 {
		return HTTPRequest{}, 0, fmt.Errorf("%w: malformed HTTP request line", ErrInvalidHTTP)
	}
	method := reqLine[:sp1]
	path := reqLine[sp1+1 : sp2]
	protoVer := reqLine[sp2+1:]
	if !strings.HasPrefix(protoVer, "HTTP/1.") || len(protoVer) != 8 {
		return HTTPRequest{}, 0, fmt.Errorf("%w: unsupported HTTP version %q", ErrInvalidHTTP, protoVer)
	}
	if !isStandardHTTPMethod(method) {
		return HTTPRequest{}, 0, fmt.Errorf("%w: unrecognized HTTP method %q", ErrInvalidHTTP, method)
	}

	return HTTPRequest{
		Method:  method,
		Path:    path,
		Version: protoVer[5:], // "1.1" or "1.0"
	}, lineEnd, nil
}

func parseHTTPRequest(stream []byte, decodedBudget *httpDecodeBudget) (HTTPRequest, int, error) {
	req, lineEnd, err := parseHTTPRequestLine(stream)
	if err != nil {
		return HTTPRequest{}, 0, err
	}

	headers, bodyStart, framing, err := parseHTTPHeaders(stream, lineEnd+2, false)
	if err != nil {
		return HTTPRequest{}, 0, err
	}
	req.Headers = headers
	req.ContentEncoding = framing.encoding
	req.Anomalies = framing.anomalies

	var acceptLang string
	var hasCookie, hasReferer bool
	var cookieNames []string
	var cookiePairs []string

	for i := range headers {
		h := &headers[i]
		switch {
		case strings.EqualFold(h.Name, "Host"):
			if req.Host == "" {
				req.Host = h.Value
			}
		case strings.EqualFold(h.Name, "User-Agent"):
			if req.UserAgent == "" {
				req.UserAgent = h.Value
			}
		case strings.EqualFold(h.Name, "Content-Type"):
			if req.ContentType == "" {
				req.ContentType = h.Value
			}
		case strings.EqualFold(h.Name, "Accept-Language"):
			if acceptLang == "" {
				acceptLang = h.Value
			}
		case strings.EqualFold(h.Name, "Referer"):
			hasReferer = true
		case strings.EqualFold(h.Name, "Cookie"):
			hasCookie = true
			parseCookiesForJA4H(h.Value, &cookieNames, &cookiePairs)
		}
	}
	req.CookieCount = len(cookieNames)
	req.JA4H = computeJA4H(&req, hasCookie, hasReferer, acceptLang, cookieNames, cookiePairs)

	body := framing.body(stream, bodyStart, true)
	req.Anomalies.TruncatedBody = body.truncated
	req.Body, req.IsDecompressed, err = decodeHTTPContent(body.data, framing.encoding, body.ownedData, decodedBudget, &req.Anomalies)
	if err != nil {
		return HTTPRequest{}, 0, err
	}
	req.BodyOffset = bodyStart
	req.BodyLength = len(req.Body)
	return req, body.consumed, nil
}

// ParseHTTPResponse parses one HTTP/1.x response from stream and carves its body.
// It decodes single gzip, x-gzip, and deflate content codings after removing chunk
// framing. See [HTTPAnomalies] for framing and decoding observations. When framing
// cannot locate the next message, the byte count covers all input.
func ParseHTTPResponse(stream []byte) (HTTPResponse, int, error) {
	return parseHTTPResponse(stream, "", nil)
}

func parseHTTPResponse(stream []byte, method string, decodedBudget *httpDecodeBudget) (HTTPResponse, int, error) {
	ver, code, statusText, lineEnd, err := parseHTTPStatusLine(stream)
	if err != nil {
		return HTTPResponse{}, 0, err
	}
	headers, bodyStart, framing, err := parseHTTPHeaders(stream, lineEnd+2, false)
	if err != nil {
		return HTTPResponse{}, 0, err
	}
	resp := HTTPResponse{
		Version:         ver,
		StatusCode:      code,
		StatusText:      statusText,
		Headers:         headers,
		ContentEncoding: framing.encoding,
		Anomalies:       framing.anomalies,
	}
	for i := range headers {
		h := &headers[i]
		switch {
		case strings.EqualFold(h.Name, "Server"):
			if resp.Server == "" {
				resp.Server = h.Value
			}
		case strings.EqualFold(h.Name, "Content-Type"):
			if resp.ContentType == "" {
				resp.ContentType = h.Value
			}
		}
	}

	if httpResponseHasNoBody(method, code) {
		resp.BodyOffset = bodyStart
		return resp, bodyStart, nil
	}

	body := framing.body(stream, bodyStart, false)
	resp.Anomalies.TruncatedBody = body.truncated
	resp.Body, resp.IsDecompressed, err = decodeHTTPContent(body.data, framing.encoding, body.ownedData, decodedBudget, &resp.Anomalies)
	if err != nil {
		return HTTPResponse{}, 0, err
	}
	resp.BodyOffset = bodyStart
	resp.BodyLength = len(resp.Body)
	return resp, body.consumed, nil
}

func parseHTTPStatusLine(stream []byte) (string, int, string, int, error) {
	lineEnd := httpStartLineEnd(stream)
	if lineEnd <= 0 || lineEnd > MaxHTTPHeaderLineBytes {
		return "", 0, "", 0, fmt.Errorf("%w: missing or oversize HTTP status line", ErrInvalidHTTP)
	}
	statusLine := string(stream[:lineEnd])
	if !strings.HasPrefix(statusLine, "HTTP/1.") || len(statusLine) < 12 || statusLine[8] != ' ' {
		return "", 0, "", 0, fmt.Errorf("%w: malformed HTTP status line", ErrInvalidHTTP)
	}
	ver := statusLine[5:8]
	codeStr := statusLine[9:12]
	code, err := strconv.Atoi(codeStr)
	if err != nil || code < 100 || code > 599 {
		return "", 0, "", 0, fmt.Errorf("%w: invalid HTTP status code %q", ErrInvalidHTTP, codeStr)
	}
	var statusText string
	if len(statusLine) > 13 && statusLine[12] == ' ' {
		statusText = statusLine[13:]
	}

	return ver, code, statusText, lineEnd, nil
}

func httpResponseHasNoBody(method string, code int) bool {
	return method == "HEAD" || method == "CONNECT" && code/100 == 2 || code/100 == 1 || code == 204 || code == 304
}

func isStandardHTTPMethod(m string) bool {
	switch m {
	case "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE":
		return true
	default:
		return false
	}
}

type httpFraming struct {
	length                                 int64
	chunked, hasTransfer, invalidLength    bool
	strict, malformed, unsupportedTransfer bool
	encoding                               string
	anomalies                              HTTPAnomalies
}

func parseHTTPHeaders(stream []byte, start int, raw bool) (headers []HTTPHeader, bodyStart int, f httpFraming, err error) {
	offset := start
	f.length = -1
	f.strict = raw
	var encodings strings.Builder
	var encodingSeen, lengthSeen bool
	lines := 0
	for offset < len(stream) {
		relEnd := bytes.Index(stream[offset:], []byte("\r\n"))
		if relEnd < 0 {
			return nil, 0, f, fmt.Errorf("%w: unterminated HTTP headers", ErrInvalidHTTP)
		}
		if relEnd == 0 {
			// Empty line "\r\n" marks the end of headers.
			if encodings.Len() != 0 {
				f.encoding = encodings.String()
			}
			f.anomalies.TransferEncodingWithContentLength = f.hasTransfer && lengthSeen
			return headers, offset + 2, f, nil
		}
		if relEnd > MaxHTTPHeaderLineBytes {
			return nil, 0, f, fmt.Errorf("%w: header line exceeds %d bytes", ErrHTTPLimit, MaxHTTPHeaderLineBytes)
		}
		lines++
		if lines > MaxHTTPHeaders {
			return nil, 0, f, fmt.Errorf("%w: header count exceeds %d", ErrHTTPLimit, MaxHTTPHeaders)
		}
		line := stream[offset : offset+relEnd]
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 || line[0] == ' ' || line[0] == '\t' {
			return nil, 0, f, fmt.Errorf("%w: malformed HTTP header line", ErrInvalidHTTP)
		}
		rawName, rawValue := string(line[:colon]), string(line[colon+1:])
		name, val := rawName, rawValue
		if raw {
			f.malformed = f.malformed || !validHTTPFieldName(line[:colon]) || !validHTTPFieldValue(line[colon+1:])
			val = strings.Trim(val, " \t")
		} else {
			name, val = strings.TrimSpace(name), strings.TrimSpace(val)
		}
		valueStart := offset + colon + 1
		offset += relEnd + 2
		var unfolded strings.Builder
		for offset < len(stream) && (stream[offset] == ' ' || stream[offset] == '\t') {
			end := bytes.Index(stream[offset:], []byte("\r\n"))
			if end < 0 {
				return nil, 0, f, fmt.Errorf("%w: unterminated header continuation", ErrInvalidHTTP)
			}
			lines++
			if lines > MaxHTTPHeaders || end > MaxHTTPHeaderLineBytes {
				return nil, 0, f, fmt.Errorf("%w: header continuation exceeds limit", ErrHTTPLimit)
			}
			if unfolded.Len() == 0 {
				unfolded.WriteString(val)
			}
			f.anomalies.ObsFoldHeader = true
			part := bytes.Trim(stream[offset:offset+end], " \t")
			if raw && !validHTTPFieldValue(part) {
				f.malformed = true
			}
			if len(name)+1+unfolded.Len()+1+len(part) > MaxHTTPHeaderLineBytes {
				return nil, 0, f, fmt.Errorf("%w: unfolded HTTP header exceeds limit", ErrHTTPLimit)
			}
			unfolded.WriteByte(' ')
			unfolded.Write(part)
			offset += end + 2
		}
		if unfolded.Len() != 0 {
			val = unfolded.String()
			if raw {
				rawValue = string(stream[valueStart : offset-2])
			}
		}
		if raw {
			headers = append(headers, HTTPHeader{Name: rawName, Value: rawValue})
		} else {
			headers = append(headers, HTTPHeader{Name: name, Value: val})
		}

		if strings.EqualFold(name, "Content-Length") {
			lengthSeen = true
			for item := range strings.SplitSeq(val, ",") {
				item = strings.Trim(item, " \t")
				n, err := strconv.ParseUint(item, 10, 63)
				if err != nil {
					f.invalidLength = true
				} else if f.length >= 0 && f.length != int64(n) {
					f.anomalies.MultipleContentLength = true
				} else {
					f.length = int64(n)
				}
			}
		} else if strings.EqualFold(name, "Transfer-Encoding") {
			last := strings.Trim(val[strings.LastIndexByte(val, ',')+1:], " \t")
			f.chunked = strings.EqualFold(last, "chunked")
			if raw {
				f.malformed = f.malformed || last == ""
				f.chunked = f.chunked && validHTTPFieldName([]byte(last))
				f.unsupportedTransfer = f.hasTransfer || last != val || !f.chunked
			}
			f.hasTransfer = true
		} else if strings.EqualFold(name, "Content-Encoding") {
			f.malformed = f.malformed || raw && val == ""
			if !encodingSeen {
				f.encoding = val
				encodingSeen = true
			} else {
				if encodings.Len() == 0 {
					encodings.WriteString(f.encoding)
				}
				encodings.WriteString(", ")
				encodings.WriteString(val)
			}
		}
	}
	return nil, 0, f, fmt.Errorf("%w: missing end of HTTP headers", ErrInvalidHTTP)
}

func validHTTPFieldName(name []byte) bool {
	if len(name) == 0 {
		return false
	}
	for _, b := range name {
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.IndexByte("!#$%&'*+-.^_`|~", b) >= 0 {
			continue
		}
		return false
	}
	return true
}

func validHTTPFieldValue(value []byte) bool {
	for _, b := range value {
		if b < ' ' && b != '\t' || b == 0x7f {
			return false
		}
	}
	return true
}

type httpFramedBody struct {
	data                         []byte
	consumed                     int
	invalidEnd                   int // Exclusive wire offset providing the first framing error.
	truncated, capped, malformed bool
	ownedData                    bool // The caller can retain data without copying it.
}

// body consumes the remaining input when framing cannot identify the next message.
func (f httpFraming) body(stream []byte, start int, request bool) httpFramedBody {
	avail := len(stream) - start
	if f.malformed {
		return httpFramedBody{consumed: len(stream), invalidEnd: start, malformed: true}
	}
	if f.chunked {
		body := decodeChunkedBody(stream[start:], f.strict)
		body.consumed += start
		if body.malformed {
			body.invalidEnd += start
		}
		return body
	}
	if f.hasTransfer {
		if request {
			return httpFramedBody{consumed: len(stream)}
		}
		f.length = -1 // A response with a final non-chunked coding is close-delimited.
	} else if f.invalidLength || f.anomalies.MultipleContentLength {
		return httpFramedBody{consumed: len(stream), invalidEnd: start, malformed: true}
	}
	wireLen := avail
	if f.length >= 0 {
		wireLen = int(min(f.length, int64(avail)))
	} else if request {
		wireLen = 0
	}
	body := httpFramedBody{consumed: start + wireLen, truncated: f.length > int64(avail), capped: wireLen > MaxHTTPBodyBytes}
	if wireLen != 0 {
		body.data = stream[start : start+min(wireLen, MaxHTTPBodyBytes)]
	}
	return body
}

var errHTTPDecodeBudget = fmt.Errorf("%w: HTTP content decoding exceeds %d bytes per capture", ErrHTTPLimit, MaxHTTPDecodedBodyBytesPerScan)

type httpDecodeBudget struct {
	remaining int
	scratch   bytes.Buffer
}

// read reuses one output buffer during a capture scan. Successful scan
// results copy the borrowed bytes before reading another message.
func (b *httpDecodeBudget) read(r io.Reader) ([]byte, error) {
	if b == nil {
		return io.ReadAll(r)
	}
	b.scratch.Reset()
	_, err := b.scratch.ReadFrom(r)
	return b.scratch.Bytes(), err
}

func decodeHTTPContent(body []byte, encoding string, owned bool, budget *httpDecodeBudget, anomalies *HTTPAnomalies) ([]byte, bool, error) {
	if len(body) == 0 {
		return body, false, nil
	}

	if encoding != "" {
		reader, err := httpContentReader(body, encoding)
		if reader != nil {
			decoded, readErr := readHTTPContent(reader, budget)
			if errors.Is(readErr, errHTTPDecodeBudget) {
				return nil, false, readErr
			}
			if readErr == nil {
				if len(decoded) > MaxHTTPBodyBytes {
					anomalies.DecompressionLimitExceeded = true
					decoded = decoded[:MaxHTTPBodyBytes:MaxHTTPBodyBytes]
				}
				if budget != nil {
					decoded = bytes.Clone(decoded)
				}
				return decoded, true, nil
			}
			err = readErr
		}
		anomalies.InvalidContentEncoding = err != nil
	}

	if !owned {
		body = bytes.Clone(body)
	}
	return body, false, nil
}

func readHTTPContent(reader io.ReadCloser, budget *httpDecodeBudget) ([]byte, error) {
	limit := MaxHTTPBodyBytes
	if budget != nil {
		limit = min(limit, budget.remaining)
	}
	decoded, err := budget.read(io.LimitReader(reader, int64(limit)+1))
	if closeErr := reader.Close(); err == nil {
		err = closeErr
	}
	if budget != nil {
		// Failed decoding attempts still consume the work budget.
		charged := min(len(decoded), MaxHTTPBodyBytes)
		if charged > budget.remaining {
			return nil, errHTTPDecodeBudget
		}
		budget.remaining -= charged
	}
	return decoded, err
}

func httpContentReader(body []byte, encoding string) (io.ReadCloser, error) {
	switch {
	case strings.EqualFold(encoding, "gzip"), strings.EqualFold(encoding, "x-gzip"):
		reader, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		return reader, nil
	case strings.EqualFold(encoding, "deflate"):
		if len(body) >= 2 {
			reader, err := zlib.NewReader(bytes.NewReader(body))
			if !errors.Is(err, zlib.ErrHeader) {
				return reader, err
			}
		}
		return flate.NewReader(bytes.NewReader(body)), nil
	}
	return nil, nil
}

func decodeChunkedBody(raw []byte, strict bool) httpFramedBody {
	var out bytes.Buffer
	body := httpFramedBody{consumed: len(raw), truncated: true, ownedData: true}
	offset := 0
	for offset < len(raw) {
		lineEnd := bytes.Index(raw[offset:], []byte("\r\n"))
		if lineEnd <= 0 || lineEnd > MaxHTTPHeaderLineBytes {
			body.malformed = lineEnd >= 0 || len(raw)-offset > MaxHTTPHeaderLineBytes+1
			if body.malformed {
				body.invalidEnd = offset + MaxHTTPHeaderLineBytes + 2
				if lineEnd == 0 {
					body.invalidEnd = offset + 2
				}
			}
			break
		}
		line := raw[offset : offset+lineEnd]
		sizeHex := string(line)
		if !strict {
			sizeHex = strings.TrimSpace(sizeHex)
		}
		if size, _, ok := strings.Cut(sizeHex, ";"); ok {
			sizeHex = size
			if strict {
				sizeHex = strings.TrimRight(sizeHex, " \t")
			}
		}
		if strict && (len(sizeHex) == 0 || sizeHex[0] == '+' || sizeHex[0] == '-' || !validHTTPFieldValue(line)) {
			body.malformed = true
			body.invalidEnd = offset + lineEnd + 2
			break
		}
		chunkSize, err := strconv.ParseInt(sizeHex, 16, 32)
		if err != nil || chunkSize < 0 {
			body.malformed = true
			body.invalidEnd = offset + lineEnd + 2
			break
		}
		offset += lineEnd + 2
		if chunkSize == 0 {
			// Consume optional HTTP trailers up to the terminating empty line "\r\n".
			for i := range MaxHTTPHeaders + 1 {
				trEnd := bytes.Index(raw[offset:], []byte("\r\n"))
				if trEnd < 0 || trEnd > MaxHTTPHeaderLineBytes {
					if !body.malformed && (trEnd >= 0 || len(raw)-offset > MaxHTTPHeaderLineBytes+1) {
						body.malformed = true
						body.invalidEnd = offset + MaxHTTPHeaderLineBytes + 2
					}
					break
				}
				if strict && trEnd != 0 {
					name, value, found := bytes.Cut(raw[offset:offset+trEnd], []byte{':'})
					if !body.malformed && (i == MaxHTTPHeaders || !found || !validHTTPFieldName(name) || !validHTTPFieldValue(value)) {
						body.malformed = true
						body.invalidEnd = offset + trEnd + 2
					}
				}
				offset += trEnd + 2
				if trEnd == 0 {
					body.data, body.consumed, body.truncated = out.Bytes(), offset, false
					return body
				}
			}
			break
		}
		rem := len(raw) - offset
		if chunkSize > int64(rem) {
			take := min(rem, MaxHTTPBodyBytes-out.Len())
			body.capped = body.capped || take < rem
			if take > 0 {
				out.Write(raw[offset : offset+take])
			}
			break
		}
		chunkLen := int(chunkSize)
		take := min(chunkLen, MaxHTTPBodyBytes-out.Len())
		body.capped = body.capped || take < chunkLen
		if take > 0 {
			out.Write(raw[offset : offset+take])
		}
		offset += chunkLen
		if len(raw)-offset < 2 || raw[offset] != '\r' || raw[offset+1] != '\n' {
			if offset < len(raw) && raw[offset] != '\r' {
				body.malformed, body.invalidEnd = true, offset+1
			} else if len(raw)-offset >= 2 {
				body.malformed, body.invalidEnd = true, offset+2
			}
			break
		}
		offset += 2
	}
	body.data = out.Bytes()
	return body
}

func parseCookiesForJA4H(val string, names *[]string, pairs *[]string) {
	for part := range strings.SplitSeq(val, ";") {
		if len(*names) >= MaxHTTPCookies {
			return
		}
		kv := strings.TrimSpace(part)
		if kv == "" {
			continue
		}
		if eq := strings.IndexByte(kv, '='); eq > 0 {
			name := strings.TrimSpace(kv[:eq])
			*names = append(*names, name)
			*pairs = append(*pairs, name+"="+strings.TrimSpace(kv[eq+1:]))
		} else {
			*names = append(*names, kv)
			*pairs = append(*pairs, kv)
		}
	}
}

func computeJA4H(
	req *HTTPRequest,
	hasCookie bool,
	hasReferer bool,
	acceptLang string,
	cookieNames []string,
	cookiePairs []string,
) string {
	// Part a (12 chars): [method:2][version:2][c|n][r|n][header_count:2][lang:4]
	var out [64]byte
	b := out[:0]

	m := strings.ToLower(req.Method)
	if len(m) >= 2 {
		b = append(b, m[0], m[1])
	} else {
		b = append(b, "00"...)
	}
	switch req.Version {
	case "1.1":
		b = append(b, "11"...)
	case "1.0":
		b = append(b, "10"...)
	default:
		b = append(b, "00"...)
	}
	if hasCookie {
		b = append(b, 'c')
	} else {
		b = append(b, 'n')
	}
	if hasReferer {
		b = append(b, 'r')
	} else {
		b = append(b, 'n')
	}

	var hdrNamesBuf [1024]byte
	hdrNames := hdrNamesBuf[:0]
	hdrCount := 0
	for i := range req.Headers {
		name := req.Headers[i].Name
		if strings.EqualFold(name, "Cookie") || strings.EqualFold(name, "Referer") {
			continue
		}
		if hdrCount > 0 {
			hdrNames = append(hdrNames, ',')
		}
		hdrNames = append(hdrNames, name...)
		hdrCount++
	}
	b = appendTwoDigits(b, hdrCount)
	langCode := formatJA4HLanguage(acceptLang)
	b = append(b, langCode[:]...)
	b = append(b, '_')

	// Part b: truncated SHA-256 of wire-order header names (excluding Cookie and Referer).
	b = appendTruncSHA256Hex12(b, hdrNames)

	// These lists belong to this request. Hash each sorted list using the
	// header-name scratch space after the preceding hash has consumed it.
	for _, fields := range [...][]string{cookieNames, cookiePairs} {
		b = append(b, '_')
		if len(fields) == 0 {
			b = appendTruncSHA256Hex12(b, nil)
			continue
		}
		slices.Sort(fields)
		input := hdrNames[:0]
		size := len(fields) - 1 // commas between fields
		for _, field := range fields {
			size += len(field)
		}
		if size > cap(input) {
			input = make([]byte, 0, size)
		}
		for i, field := range fields {
			if i > 0 {
				input = append(input, ',')
			}
			input = append(input, field...)
		}
		b = appendTruncSHA256Hex12(b, input)
	}
	return string(b)
}

func formatJA4HLanguage(acceptLang string) [4]byte {
	out := [4]byte{'0', '0', '0', '0'}
	if acceptLang == "" {
		return out
	}
	primary := acceptLang
	if comma := strings.IndexByte(primary, ','); comma >= 0 {
		primary = primary[:comma]
	}
	if semi := strings.IndexByte(primary, ';'); semi >= 0 {
		primary = primary[:semi]
	}
	idx := 0
	for i := 0; i < len(primary) && idx < 4; i++ {
		c := primary[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			out[idx] = c
			idx++
		}
	}
	return out
}

// HTTP extracts HTTP/1.x requests, responses, JA4H fingerprints, and carved body
// payloads from both cleartext TCP streams and TLS streams decrypted via
// embedded PcapNG Decryption Secrets Blocks (DSB). Cleartext parsing ends at
// the first known gap in each direction. When requests are available, their
// methods determine response framing, including bodyless HEAD responses. HTTP uses one
// [MaxHTTPDecodedBodyBytesPerScan] budget for content decoding across all streams.
// It returns no records and an error wrapping [ErrHTTPLimit] if decoding exceeds
// the budget, including bytes produced before a decoding error.
func (c *Capture) HTTP(data []byte) ([]HTTPRecord, error) {
	var meta []streamMetadata
	streams, err := collectStreams(ipFrameSource{capture: c, data: data}, 0, &meta, tcpWireUnanchored)
	if err != nil {
		return nil, err
	}
	keys, _ := c.TLSKeyLog(nil)
	var records []HTTPRecord
	if err := scanHTTPStreams(streams, meta, keys, &records, nil, nil); err != nil {
		return nil, err
	}
	return records, nil
}

func appendClearHTTP(wire, inner *TCPStream, provenance [2]tcpWireDirection, clientOffset, serverOffset int, records *[]HTTPRecord, decodedBudget *httpDecodeBudget) error {
	innerWire := provenance
	reversed := inner.SrcAddr != wire.SrcAddr || inner.SrcPort != wire.SrcPort
	if reversed {
		innerWire[0], innerWire[1] = innerWire[1], innerWire[0]
	}
	if clientOffset != 0 {
		client, server := wire.Client.Data, wire.Server.Data
		if reversed {
			client, server = server, client
		}
		if bytes.HasPrefix(client, []byte("CONNECT ")) {
			if !matchesHTTPResponse(innerWire, server, 0, 0) {
				return appendHTTPFromTCPStream(*wire, provenance, false, records, decodedBudget, 0, 0)
			}
			// A successful CONNECT ends at the blank line in each direction.
			outer := *inner
			outer.Client.Data, outer.Server.Data = client[:clientOffset], server[:serverOffset]
			if err := appendHTTPFromTCPStream(outer, innerWire, false, records, decodedBudget, 0, 0); err != nil {
				return err
			}
		}
	}
	return appendHTTPFromTCPStream(*inner, innerWire, false, records, decodedBudget, clientOffset, serverOffset)
}

func appendHTTPFromTCPStream(st TCPStream, wire [2]tcpWireDirection, isDecrypted bool, records *[]HTTPRecord, decodedBudget *httpDecodeBudget, clientOffset, serverOffset int) error {
	// Reassembly follows the first observed packet, which can be a response.
	if (hasHTTPRequestStart(st.Server.Data) || hasHTTPResponseStart(st.Client.Data) && !hasHTTPResponseStart(st.Server.Data)) &&
		!hasHTTPRequestStart(st.Client.Data) {
		st.reverse()
		clientOffset, serverOffset = serverOffset, clientOffset
		wire[0], wire[1] = wire[1], wire[0]
	}
	firstRequest := len(*records)
	haveWire := len(wire[0].spans) != 0 && len(wire[1].spans) != 0
	var requestOffsets []int
	for off := 0; off < len(st.Client.Data); {
		req, consumed, err := parseHTTPRequest(st.Client.Data[off:], decodedBudget)
		if errors.Is(err, errHTTPDecodeBudget) {
			return err
		}
		if err != nil || consumed <= 0 {
			break
		}
		if len(*records) >= MaxHTTPMessagesPerScan {
			return fmt.Errorf("%w: exceeds %d HTTP messages", ErrHTTPLimit, MaxHTTPMessagesPerScan)
		}
		if haveWire {
			requestOffsets = append(requestOffsets, off+clientOffset)
		}
		req.BodyOffset += off + clientOffset
		*records = append(*records, HTTPRecord{
			FlowIndex:   st.FlowIndex,
			SrcAddr:     st.SrcAddr,
			DstAddr:     st.DstAddr,
			SrcPort:     st.SrcPort,
			DstPort:     st.DstPort,
			IsResponse:  false,
			IsDecrypted: isDecrypted,
			Request:     req,
		})
		off += consumed
	}
	nextRequest, endRequests := firstRequest, len(*records)
	for off := 0; off < len(st.Server.Data); {
		data := st.Server.Data[off:]
		matched := nextRequest < endRequests &&
			(!haveWire || matchesHTTPResponse(wire, data, requestOffsets[nextRequest-firstRequest], off+serverOffset))
		var method string
		if matched {
			method = (*records)[nextRequest].Request.Method
		}
		resp, consumed, err := parseHTTPResponse(data, method, decodedBudget)
		if errors.Is(err, errHTTPDecodeBudget) {
			return err
		}
		if err != nil || consumed <= 0 {
			break
		}
		if len(*records) >= MaxHTTPMessagesPerScan {
			return fmt.Errorf("%w: exceeds %d HTTP messages", ErrHTTPLimit, MaxHTTPMessagesPerScan)
		}
		resp.BodyOffset += off + serverOffset
		*records = append(*records, HTTPRecord{
			FlowIndex:   st.FlowIndex,
			SrcAddr:     st.DstAddr,
			DstAddr:     st.SrcAddr,
			SrcPort:     st.DstPort,
			DstPort:     st.SrcPort,
			IsResponse:  true,
			IsDecrypted: isDecrypted,
			Response:    resp,
		})
		if resp.StatusCode == 101 || method == "CONNECT" && resp.StatusCode/100 == 2 {
			break
		}
		if resp.StatusCode >= 200 && matched {
			nextRequest++
		}
		off += consumed
	}
	return nil
}

func httpStartLineEnd(data []byte) int {
	return bytes.Index(data[:min(MaxHTTPHeaderLineBytes+2, len(data))], []byte("\r\n"))
}

// A complete HTTP start line gives stronger direction evidence than a method
// token that can also occur at the start of a captured body fragment.
func hasHTTPRequestStart(data []byte) bool {
	method, _, ok := bytes.Cut(data[:min(8, len(data))], []byte(" "))
	if !ok || !isStandardHTTPMethod(string(method)) {
		return false
	}
	_, _, err := parseHTTPRequestLine(data)
	return err == nil
}

func hasHTTPResponseStart(data []byte) bool {
	if len(data) < 14 || !bytes.HasPrefix(data, []byte("HTTP/1.")) || data[8] != ' ' ||
		data[9] < '1' || data[9] > '5' || data[10] < '0' || data[10] > '9' || data[11] < '0' || data[11] > '9' {
		return false
	}
	return httpStartLineEnd(data) >= 12
}

func (wire tcpWireDirection) packetAt(offset int) (tcpPacketEvidence, bool) {
	i := sort.Search(len(wire.spans), func(i int) bool { return wire.spans[i].end > uint32(offset) })
	if i == len(wire.spans) {
		return tcpPacketEvidence{}, false
	}
	return wire.spans[i].packet, true
}

// Reject a response whose TCP ACK has yet to reach the captured request. When
// the ACK is unavailable, require an earlier body with a valid Content-Length
// and a following response seen after the request.
func matchesHTTPResponse(wire [2]tcpWireDirection, data []byte, requestOffset, responseOffset int) bool {
	request, haveRequest := wire[0].packetAt(requestOffset)
	response, haveResponse := wire[1].packetAt(responseOffset)
	if !haveRequest || !haveResponse {
		return true
	}
	if response.ack != 0 {
		return int32(response.ack-(wire[0].seq+uint32(requestOffset))) > 0
	}
	if response.index >= request.index || !hasHTTPResponseStart(data) {
		return true
	}
	status := string(data[9:12])
	if status[0] == '1' || status == "204" || status == "304" {
		return true
	}
	_, start, framing, err := parseHTTPHeaders(data, httpStartLineEnd(data)+2, false)
	if err != nil || framing.hasTransfer || framing.invalidLength || framing.anomalies.MultipleContentLength ||
		framing.length <= 0 || framing.length > int64(len(data)-start) || hasHTTPResponseStart(data[start:]) {
		return true
	}
	end := start + int(framing.length)
	if !hasHTTPResponseStart(data[end:]) {
		return true
	}
	next, ok := wire[1].packetAt(responseOffset + end)
	return !ok || next.index <= request.index
}
