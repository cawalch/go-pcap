package pcap

import (
	"encoding/base64"
	"fmt"
	"math"
	"mime"
	"net/url"
	"strconv"
	"strings"
)

// DNSOverHTTPS extracts a wire-format DNS message from an HTTP/2 header block
// and the DATA bytes of its stream direction. For GET it reads the unpadded
// base64url dns query parameter. For POST and body-bearing 2xx responses,
// it reads the DATA bytes when the media type is application/dns-message and
// the content coding is absent or identity.
//
// The boolean reports whether the headers or URI identified a candidate.
// Invalid query parameters, mismatched DNS query/response flags, and DNS
// parser errors return a matching result with an error.
// [DNSMessage.Anomalies] describes any partial DNS sections. The parent
// [HTTP2Record.IsDecrypted] indicates whether the stream came from TLS.
func (b HTTP2HeaderBlock) DNSOverHTTPS(data []byte) (DNSMessage, bool, error) {
	data, match, err := dohPayload(b, data)
	if !match || err != nil {
		return DNSMessage{}, match, err
	}
	msg, err := parseDoHPayload(data, b.Method == "")
	return msg, true, err
}

func dohPayload(b HTTP2HeaderBlock, data []byte) ([]byte, bool, error) {
	switch b.Method {
	case "GET", "POST":
		if b.Status != "" {
			return nil, false, nil
		}
	case "":
		if len(b.Status) != 3 {
			return nil, false, nil
		}
		status, _ := strconv.Atoi(b.Status)
		if status < 200 || status >= 300 || status == 204 || status == 205 {
			return nil, false, nil
		}
	default:
		return nil, false, nil
	}
	if len(b.Headers) > MaxHTTPHeaders {
		return nil, false, ErrHTTPLimit
	}
	// These pseudo-headers identify the message and locate GET query bytes.
	pseudo := map[string]string{":method": b.Method, ":path": b.Path, ":status": b.Status}
	var typed bool
	for _, h := range b.Headers {
		if len(h.Name) > MaxHTTPHeaderLineBytes || len(h.Value) > MaxHTTPHeaderLineBytes {
			return nil, false, ErrHTTPLimit
		}
		switch h.Name {
		case ":method", ":path", ":status":
			if value, ok := pseudo[h.Name]; !ok || value != h.Value {
				return nil, false, nil
			}
			delete(pseudo, h.Name)
			continue
		}
		if b.Method == "GET" {
			continue
		}
		switch {
		case strings.EqualFold(h.Name, "content-type"):
			mt, _, err := mime.ParseMediaType(h.Value)
			if typed || err != nil || mt != "application/dns-message" {
				return nil, false, nil
			}
			typed = true
		case strings.EqualFold(h.Name, "content-encoding"):
			if !strings.EqualFold(strings.TrimSpace(h.Value), "identity") {
				return nil, false, nil
			}
		}
	}
	if b.Method == "GET" {
		var ok bool
		var err error
		data, ok, err = decodeDoHQuery(b.Path)
		if !ok || err != nil {
			return nil, ok, err
		}
	} else if !typed {
		return nil, false, nil
	}
	return data, true, nil
}

func parseDoHPayload(data []byte, response bool) (DNSMessage, error) {
	if len(data) > math.MaxUint16 {
		return DNSMessage{}, ErrDNSLimit
	}
	msg, err := ParseDNS(data)
	if err == nil && msg.IsResponse != response {
		return DNSMessage{}, fmt.Errorf("%w: DNS query/response flag does not match HTTP/2 headers", ErrInvalidDNS)
	}
	return msg, err
}

func decodeDoHQuery(path string) ([]byte, bool, error) {
	if len(path) > MaxHTTPHeaderLineBytes {
		return nil, false, ErrHTTPLimit
	}
	_, query, hasQuery := strings.Cut(path, "?")
	if !hasQuery || strings.Contains(path, "#") {
		return nil, false, nil
	}
	var value string
	var seen bool
	for arg := range strings.SplitSeq(query, "&") {
		key, raw, _ := strings.Cut(arg, "=")
		name, err := url.QueryUnescape(key)
		if err != nil || name != "dns" {
			continue
		}
		if seen {
			return nil, true, fmt.Errorf("%w: duplicate dns query parameter", ErrInvalidDNS)
		}
		seen = true
		value, err = url.QueryUnescape(raw)
		if err != nil || strings.ContainsAny(value, "\r\n") {
			return nil, true, fmt.Errorf("%w: invalid dns query parameter", ErrInvalidDNS)
		}
	}
	if !seen {
		return nil, false, nil
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil {
		return nil, true, fmt.Errorf("%w: invalid base64url dns parameter", ErrInvalidDNS)
	}
	return data, true, nil
}
