package pcap

import (
	"bytes"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// HTTPHeader represents a single name-value HTTP header line in wire order.
type HTTPHeader struct {
	Name  string
	Value string
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
	Headers     []HTTPHeader
	CookieCount int
	Body        []byte
	BodyOffset  int
	BodyLength  int
	JA4H        string
}

// HTTPResponse contains a parsed HTTP/1.x response and its carved body payload.
type HTTPResponse struct {
	Version     string
	StatusCode  int
	StatusText  string
	Server      string
	ContentType string
	Headers     []HTTPHeader
	Body        []byte
	BodyOffset  int
	BodyLength  int
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
// fingerprint, and extracts its body (via Content-Length or chunked encoding).
// It returns the parsed request, total bytes consumed from stream, and any error.
func ParseHTTPRequest(stream []byte) (HTTPRequest, int, error) {
	lineEnd := bytes.Index(stream, []byte("\r\n"))
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

	req := HTTPRequest{
		Method:  method,
		Path:    path,
		Version: protoVer[5:], // "1.1" or "1.0"
	}

	headers, bodyStart, contentLen, chunked, err := parseHTTPHeaders(stream, lineEnd+2)
	if err != nil {
		return HTTPRequest{}, 0, err
	}
	req.Headers = headers

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

	body, bodyOff, bodyLen, consumed := extractHTTPBody(stream, bodyStart, contentLen, chunked, true)
	req.Body = body
	req.BodyOffset = bodyOff
	req.BodyLength = bodyLen
	return req, consumed, nil
}

// ParseHTTPResponse parses one HTTP/1.x response from stream and extracts its
// body (via Content-Length or chunked encoding). It returns the parsed response,
// total bytes consumed from stream, and any error.
func ParseHTTPResponse(stream []byte) (HTTPResponse, int, error) {
	lineEnd := bytes.Index(stream, []byte("\r\n"))
	if lineEnd <= 0 || lineEnd > MaxHTTPHeaderLineBytes {
		return HTTPResponse{}, 0, fmt.Errorf("%w: missing or oversize HTTP status line", ErrInvalidHTTP)
	}
	statusLine := string(stream[:lineEnd])
	if !strings.HasPrefix(statusLine, "HTTP/1.") || len(statusLine) < 12 || statusLine[8] != ' ' {
		return HTTPResponse{}, 0, fmt.Errorf("%w: malformed HTTP status line", ErrInvalidHTTP)
	}
	ver := statusLine[5:8]
	codeStr := statusLine[9:12]
	code, err := strconv.Atoi(codeStr)
	if err != nil || code < 100 || code > 599 {
		return HTTPResponse{}, 0, fmt.Errorf("%w: invalid HTTP status code %q", ErrInvalidHTTP, codeStr)
	}
	var statusText string
	if len(statusLine) > 13 && statusLine[12] == ' ' {
		statusText = statusLine[13:]
	}

	headers, bodyStart, contentLen, chunked, err := parseHTTPHeaders(stream, lineEnd+2)
	if err != nil {
		return HTTPResponse{}, 0, err
	}
	resp := HTTPResponse{
		Version:    ver,
		StatusCode: code,
		StatusText: statusText,
		Headers:    headers,
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

	if (code >= 100 && code < 200) || code == 204 || code == 304 {
		resp.BodyOffset = bodyStart
		return resp, bodyStart, nil
	}

	body, bodyOff, bodyLen, consumed := extractHTTPBody(stream, bodyStart, contentLen, chunked, false)
	resp.Body = body
	resp.BodyOffset = bodyOff
	resp.BodyLength = bodyLen
	return resp, consumed, nil
}

func isStandardHTTPMethod(m string) bool {
	switch m {
	case "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE":
		return true
	default:
		return false
	}
}

func parseHTTPHeaders(stream []byte, start int) (headers []HTTPHeader, bodyStart int, contentLen int, chunked bool, err error) {
	offset := start
	contentLen = -1
	for offset < len(stream) {
		relEnd := bytes.Index(stream[offset:], []byte("\r\n"))
		if relEnd < 0 {
			return nil, 0, 0, false, fmt.Errorf("%w: unterminated HTTP headers", ErrInvalidHTTP)
		}
		if relEnd == 0 {
			// Empty line "\r\n" marks the end of headers.
			return headers, offset + 2, contentLen, chunked, nil
		}
		if relEnd > MaxHTTPHeaderLineBytes {
			return nil, 0, 0, false, fmt.Errorf("%w: header line exceeds %d bytes", ErrHTTPLimit, MaxHTTPHeaderLineBytes)
		}
		if len(headers) >= MaxHTTPHeaders {
			return nil, 0, 0, false, fmt.Errorf("%w: header count exceeds %d", ErrHTTPLimit, MaxHTTPHeaders)
		}
		line := stream[offset : offset+relEnd]
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			return nil, 0, 0, false, fmt.Errorf("%w: malformed HTTP header line", ErrInvalidHTTP)
		}
		name := strings.TrimSpace(string(line[:colon]))
		val := strings.TrimSpace(string(line[colon+1:]))
		headers = append(headers, HTTPHeader{Name: name, Value: val})

		if strings.EqualFold(name, "Content-Length") {
			if n, convErr := strconv.Atoi(val); convErr == nil && n >= 0 {
				contentLen = n
			}
		} else if strings.EqualFold(name, "Transfer-Encoding") && strings.Contains(strings.ToLower(val), "chunked") {
			chunked = true
		}
		offset += relEnd + 2
	}
	return nil, 0, 0, false, fmt.Errorf("%w: missing end of HTTP headers", ErrInvalidHTTP)
}

func extractHTTPBody(stream []byte, bodyStart int, contentLen int, chunked bool, bodylessIfUnspecified bool) (body []byte, bodyOffset int, bodyLength int, consumed int) {
	avail := len(stream) - bodyStart
	if avail <= 0 {
		return nil, bodyStart, 0, bodyStart
	}

	if chunked {
		decoded, rawConsumed := decodeChunkedBody(stream[bodyStart:])
		return decoded, bodyStart, len(decoded), bodyStart + rawConsumed
	}

	if contentLen == 0 || (contentLen < 0 && bodylessIfUnspecified) {
		return nil, bodyStart, 0, bodyStart
	}
	wireLen := avail
	if contentLen > 0 && contentLen < wireLen {
		wireLen = contentLen
	}
	take := min(wireLen, MaxHTTPBodyBytes)
	return bytes.Clone(stream[bodyStart : bodyStart+take]), bodyStart, take, bodyStart + wireLen
}

func decodeChunkedBody(raw []byte) ([]byte, int) {
	var out bytes.Buffer
	offset := 0
	for offset < len(raw) {
		lineEnd := bytes.Index(raw[offset:], []byte("\r\n"))
		if lineEnd <= 0 {
			break
		}
		sizeHex := strings.TrimSpace(string(raw[offset : offset+lineEnd]))
		if semi := strings.IndexByte(sizeHex, ';'); semi >= 0 {
			sizeHex = sizeHex[:semi]
		}
		chunkSize, err := strconv.ParseInt(sizeHex, 16, 32)
		if err != nil || chunkSize < 0 {
			break
		}
		offset += lineEnd + 2
		if chunkSize == 0 {
			// Consume optional HTTP trailers up to the terminating empty line "\r\n".
			for range MaxHTTPHeaders + 1 {
				trEnd := bytes.Index(raw[offset:], []byte("\r\n"))
				if trEnd < 0 {
					offset = len(raw)
					break
				}
				offset += trEnd + 2
				if trEnd == 0 {
					break
				}
			}
			break
		}
		rem := len(raw) - offset
		if chunkSize > int64(rem) {
			take := min(rem, MaxHTTPBodyBytes-out.Len())
			if take > 0 {
				out.Write(raw[offset : offset+take])
			}
			offset = len(raw)
			break
		}
		chunkLen := int(chunkSize)
		take := min(chunkLen, MaxHTTPBodyBytes-out.Len())
		if take > 0 {
			out.Write(raw[offset : offset+take])
		}
		offset += chunkLen
		if offset+2 <= len(raw) && raw[offset] == '\r' && raw[offset+1] == '\n' {
			offset += 2
		}
	}
	return out.Bytes(), offset
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
// payloads from both cleartext TCP streams and any TLS 1.3 streams decrypted via
// embedded PcapNG Decryption Secrets Blocks (DSB).
func (c *Capture) HTTP(data []byte) ([]HTTPRecord, error) {
	streams, err := c.Streams(data)
	if err != nil {
		return nil, err
	}
	var records []HTTPRecord
	for i := range streams {
		if err := appendHTTPFromTCPStream(&streams[i], false, &records); err != nil {
			return nil, err
		}
	}

	// Also inspect any DSB-decrypted TLS 1.3 streams automatically.
	if keys, err := c.TLSKeyLog(nil); err == nil && len(keys.Entries) > 0 {
		decStreams := decryptTLSStreams(streams, keys)
		for i := range decStreams {
			if err := appendHTTPFromTCPStream(&decStreams[i], true, &records); err != nil {
				return nil, err
			}
		}
	}
	return records, nil
}

func appendHTTPFromTCPStream(st *TCPStream, isDecrypted bool, records *[]HTTPRecord) error {
	for off := 0; off < len(st.Client.Data); {
		req, consumed, err := ParseHTTPRequest(st.Client.Data[off:])
		if err != nil || consumed <= 0 {
			break
		}
		if len(*records) >= MaxHTTPMessagesPerScan {
			return fmt.Errorf("%w: exceeds %d HTTP messages", ErrHTTPLimit, MaxHTTPMessagesPerScan)
		}
		req.BodyOffset += off
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
	for off := 0; off < len(st.Server.Data); {
		resp, consumed, err := ParseHTTPResponse(st.Server.Data[off:])
		if err != nil || consumed <= 0 {
			break
		}
		if len(*records) >= MaxHTTPMessagesPerScan {
			return fmt.Errorf("%w: exceeds %d HTTP messages", ErrHTTPLimit, MaxHTTPMessagesPerScan)
		}
		resp.BodyOffset += off
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
		off += consumed
	}
	return nil
}
