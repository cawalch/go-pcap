package pcap

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"unicode/utf8"
)

// WebSocketMessage holds one complete text (1), binary (2), close (8), ping
// (9), or pong (10) message. Payload owns its unmasked bytes.
type WebSocketMessage struct {
	Opcode  byte
	Payload []byte
}

// WebSocketRecord associates a message with its sender and receiving endpoint.
type WebSocketRecord struct {
	FlowIndex             int
	SrcAddr, DstAddr      netip.Addr
	SrcPort, DstPort      uint16
	IsServer, IsDecrypted bool
	Message               WebSocketMessage
}

// ParseWebSocketFrames reads one direction starting on a frame boundary.
// The first frame establishes the masking convention. Messages are returned
// in completion order, including control frames interleaved with fragments.
// On invalid or truncated input it returns preceding complete messages and
// [ErrInvalidWebSocket]. Resource limits return [ErrWebSocketLimit].
func ParseWebSocketFrames(stream []byte) ([]WebSocketMessage, error) {
	var messages []WebSocketMessage
	remaining := MaxTotalStreamBytes
	masked := len(stream) >= 2 && stream[1]&0x80 != 0
	err := walkWebSocketFrames(stream, masked, &remaining, func(m WebSocketMessage) error {
		messages = append(messages, m)
		return nil
	})
	return messages, err
}

func walkWebSocketFrames(data []byte, masked bool, remaining *int, emit func(WebSocketMessage) error) error {
	var pending WebSocketMessage
	for frames := 0; len(data) != 0; frames++ {
		if frames == MaxWebSocketFramesPerStream {
			return ErrWebSocketLimit
		}
		if len(data) < 2 || data[0]&0x70 != 0 || (data[1]&0x80 != 0) != masked {
			return ErrInvalidWebSocket
		}
		fin, opcode := data[0]&0x80 != 0, data[0]&15
		n := uint64(data[1] & 127)
		data = data[2:]
		switch opcode {
		case 0:
			if pending.Opcode == 0 {
				return ErrInvalidWebSocket
			}
		case 1, 2:
			if pending.Opcode != 0 {
				return ErrInvalidWebSocket
			}
			pending.Opcode = opcode
		case 8, 9, 10:
			if !fin || n > 125 {
				return ErrInvalidWebSocket
			}
		default:
			return ErrInvalidWebSocket
		}
		switch n {
		case 126:
			if len(data) < 2 {
				return ErrInvalidWebSocket
			}
			n = uint64(binary.BigEndian.Uint16(data))
			data = data[2:]
			if n < 126 {
				return ErrInvalidWebSocket
			}
		case 127:
			if len(data) < 8 || data[0]&128 != 0 {
				return ErrInvalidWebSocket
			}
			n = binary.BigEndian.Uint64(data)
			data = data[8:]
			if n <= 65535 {
				return ErrInvalidWebSocket
			}
		}
		var control WebSocketMessage
		m := &pending
		if opcode >= 8 {
			control.Opcode = opcode
			m = &control
		}
		if n > uint64(MaxHTTPBodyBytes-len(m.Payload)) || n > uint64(*remaining) {
			return ErrWebSocketLimit
		}
		var key []byte
		if masked {
			if len(data) < 4 {
				return ErrInvalidWebSocket
			}
			key, data = data[:4], data[4:]
		}
		if n > uint64(len(data)) {
			return ErrInvalidWebSocket
		}
		offset := len(m.Payload)
		if size := offset + int(n); size > cap(m.Payload) {
			buf := make([]byte, offset, min(MaxHTTPBodyBytes, max(size, 2*cap(m.Payload))))
			copy(buf, m.Payload)
			m.Payload = buf
		}
		m.Payload = append(m.Payload, data[:n]...)
		data = data[n:]
		*remaining -= int(n)
		if masked {
			payload := m.Payload[offset:]
			for i := range payload {
				payload[i] ^= key[i&3]
			}
		}
		if fin {
			if m.Opcode == 1 && !utf8.Valid(m.Payload) || opcode == 8 && (n == 1 || n >= 2 && !utf8.Valid(m.Payload[2:])) {
				return ErrInvalidWebSocket
			}
			if err := emit(*m); err != nil {
				return err
			}
			if opcode == 8 {
				return nil
			}
			if opcode < 8 {
				pending = WebSocketMessage{}
			}
		}
	}
	if pending.Opcode != 0 {
		return ErrInvalidWebSocket
	}
	return nil
}

// wsHTTP bounds the header before the standard library interprets HTTP body
// framing. Bytes buffered ahead by net/http still belong to the next message.
type wsHTTP struct {
	raw *bytes.Reader
	buf *bufio.Reader
}

func newWSHTTP(data []byte) *wsHTTP {
	const maxHead = (MaxHTTPHeaders+1)*(MaxHTTPHeaderLineBytes+2) + 2
	end := bytes.Index(data[:min(len(data), maxHead)], []byte("\r\n\r\n"))
	if end < 0 {
		return nil
	}
	head := data[:end]
	lines := 0
	for line := range bytes.SplitSeq(head, []byte("\r\n")) {
		lines++
		if lines > MaxHTTPHeaders+1 || len(line) > MaxHTTPHeaderLineBytes || bytes.IndexByte(line, '\n') >= 0 {
			return nil
		}
	}
	r := bytes.NewReader(data)
	return &wsHTTP{r, bufio.NewReader(r)}
}
func (r *wsHTTP) tail(data []byte) []byte { return data[len(data)-r.raw.Len()-r.buf.Buffered():] }

func wsUpgradeHeader(h http.Header) bool {
	for _, value := range h.Values("Upgrade") {
		for token := range strings.SplitSeq(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "websocket") {
				return true
			}
		}
	}
	return false
}

// Advance only across parsed HTTP exchanges. A body containing upgrade-like
// text cannot establish a WebSocket boundary.
func wsUpgraded(client, server []byte) ([]byte, []byte) {
	// A capture can start after one peer's handshake. Only that peer's
	// own HTTP boundary can establish a starting offset for its frames.
	if !bytes.HasPrefix(server, []byte("HTTP/1.")) {
		server = nil
	}
	if len(server) > 0 && !bytes.Contains(server, []byte("HTTP/1.1 101")) {
		return nil, nil
	}
	for count := 0; count < MaxHTTPMessagesPerScan && (len(client) > 0 || len(server) > 0); count++ {
		var req *http.Request
		var asked bool
		if len(client) > 0 {
			sp := bytes.IndexByte(client[:min(12, len(client))], ' ')
			if sp < 0 || !isStandardHTTPMethod(string(client[:sp])) {
				if count == 0 && len(server) > 0 {
					client = nil
					continue
				}
				return nil, nil
			}
			r := newWSHTTP(client)
			if r == nil {
				return nil, nil
			}
			var err error
			req, err = http.ReadRequest(r.buf)
			if err != nil {
				return nil, nil
			}
			asked = req.Method == "GET" && req.Proto == "HTTP/1.1" && wsUpgradeHeader(req.Header)
			if _, err = io.Copy(io.Discard, req.Body); err != nil {
				return nil, nil
			}
			client = r.tail(client)
		}
		if len(server) == 0 {
			if asked {
				return client, nil
			}
			continue
		}
		for {
			if !bytes.HasPrefix(server, []byte("HTTP/1.")) {
				return nil, nil
			}
			r := newWSHTTP(server)
			if r == nil {
				return nil, nil
			}
			resp, err := http.ReadResponse(r.buf, req)
			if err != nil {
				return nil, nil
			}
			if resp.StatusCode == 101 {
				if resp.Proto == "HTTP/1.1" && (asked || req == nil) && (wsUpgradeHeader(resp.Header) || asked && len(resp.Header.Values("Upgrade")) == 0) {
					return client, r.tail(server)
				}
				return nil, nil
			}
			if _, err = io.Copy(io.Discard, resp.Body); err != nil {
				return nil, nil
			}
			server = r.tail(server)
			if resp.StatusCode >= 200 {
				break
			}
			count++
			if count >= MaxHTTPMessagesPerScan {
				return nil, nil
			}
		}
	}
	return nil, nil
}

// WebSockets extracts complete messages after HTTP/1.1 WebSocket upgrades in
// cleartext and in TLS streams decrypted with embedded keys. Gapped directions
// are skipped. Malformed frames stop their direction. A resource limit aborts
// the scan with [ErrWebSocketLimit].
func (c *Capture) WebSockets(data []byte) ([]WebSocketRecord, error) {
	streams, err := c.proxyStreams(data)
	if err != nil {
		return nil, err
	}
	scan := webSocketScan{remaining: MaxTotalStreamBytes}
	for _, st := range streams {
		if err := scan.appendStream(st, false); err != nil {
			return nil, err
		}
	}
	keys, err := c.TLSKeyLog(nil)
	if err != nil {
		return nil, err
	}
	if len(keys.Entries) > 0 {
		for _, st := range decryptTLSStreams(streams, keys) {
			if err := scan.appendStream(st, true); err != nil {
				return nil, err
			}
		}
	}
	return scan.records, nil
}

type webSocketScan struct {
	records   []WebSocketRecord
	remaining int
}

func (scan *webSocketScan) appendStream(st TCPStream, decrypted bool) error {
	if bytes.HasPrefix(st.Client.Data, []byte("HTTP/1.")) || bytes.HasPrefix(st.Server.Data, []byte("GET ")) {
		st.reverse()
	}
	client, server := st.Client.Data, st.Server.Data
	if st.Client.Anomalies.SequenceGap {
		client = nil
	}
	if st.Server.Anomalies.SequenceGap {
		server = nil
	}
	client, server = wsUpgraded(client, server)
	for side, payload := range [2][]byte{client, server} {
		err := walkWebSocketFrames(payload, side == 0, &scan.remaining, func(m WebSocketMessage) error {
			if len(scan.records) >= MaxHTTPMessagesPerScan {
				return ErrWebSocketLimit
			}
			rec := WebSocketRecord{FlowIndex: st.FlowIndex, SrcAddr: st.SrcAddr, DstAddr: st.DstAddr, SrcPort: st.SrcPort, DstPort: st.DstPort, IsServer: side == 1, IsDecrypted: decrypted, Message: m}
			if rec.IsServer {
				rec.SrcAddr, rec.DstAddr = rec.DstAddr, rec.SrcAddr
				rec.SrcPort, rec.DstPort = rec.DstPort, rec.SrcPort
			}
			scan.records = append(scan.records, rec)
			return nil
		})
		if err != nil && !errors.Is(err, ErrInvalidWebSocket) {
			return err
		}
	}
	return nil
}
