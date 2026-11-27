package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"testing"
)

func TestHTTP2TransactionCapture(t *testing.T) {
	raw, err := os.ReadFile("testdata/deployments/http2-transactions.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	c, packets := readWrittenPackets(t, raw)
	rows, err := c.HTTP2Transactions(raw)
	if err != nil || len(rows) != 2 {
		t.Fatalf("slice = %+v, %v", rows, err)
	}
	reader := bytes.NewReader(raw)
	cr, err := NewFromReaderAt(reader, reader.Size())
	if err != nil {
		t.Fatal(err)
	}
	other, err := cr.HTTP2TransactionsFromReaderAt(reader)
	if err != nil || !reflect.DeepEqual(rows, other) {
		t.Fatalf("ReaderAt = %+v, %v", other, err)
	}
	if got, err := cr.HTTP2TransactionsFromReaderAt(bytes.NewReader(raw[:len(raw)/2])); err == nil || got != nil {
		t.Fatalf("short ReaderAt = %v, %v", got, err)
	}
	for i, tc := range []struct {
		id              HTTP2TransactionID
		path, req, resp string
		status          string
		code, final     int
		indices         []int
	}{
		{HTTP2TransactionID{6, 0, 1}, "/one", "alpha", "one", "200", 200, 12, []int{6, 7, 9, 11, 12, 13}},
		{HTTP2TransactionID{6, 50, 3}, "/two", "beta", "two", "201", 201, 10, []int{6, 7, 8, 10}},
	} {
		row := rows[i]
		req, resp := row.Request, row.Response
		fields := []HTTPHeader{{":method", "POST"}, {":scheme", "http"}, {":path", tc.path}, {":authority", "trace.example"}}
		if i == 0 {
			fields = append(fields, HTTPHeader{"x-tag", "a"}, HTTPHeader{"x-tag", "b"})
		}
		if row.ID() != tc.id || row.FlowIndex != 0 || row.Source != netip.MustParseAddrPort("192.0.2.14:50000") || row.Destination != netip.MustParseAddrPort("198.51.100.80:80") ||
			req.TimestampNs != packets[6].TimestampNs || req.Method != "POST" || req.Path != tc.path || !slices.Equal(req.Headers, fields) || req.Authority != "trace.example" ||
			string(req.Body) != tc.req || req.BodyState != HTTPBodyComplete || !req.EndStream || req.BodyLimitExceeded {
			t.Fatalf("request = %+v", row)
		}
		if row.Pairing != HTTP2ResponseConfirmed || row.StatusCode != tc.code || !row.SharedPackets || row.Reset || !slices.Equal(row.PacketIndices, tc.indices) ||
			resp == nil || !slices.Equal(resp.Headers, []HTTPHeader{{":status", tc.status}}) || resp.Status != tc.status || resp.PacketIndex != tc.final || resp.PacketPayloadOffset != 0 ||
			resp.TimestampNs != packets[tc.final].TimestampNs || string(resp.Body) != tc.resp || resp.BodyState != HTTPBodyComplete || !resp.EndStream || resp.BodyLimitExceeded {
			t.Fatalf("response = %+v, row = %+v", resp, row)
		}
		if i == 0 {
			if len(row.Informational) != 1 || !slices.Equal(row.Informational[0].Headers, []HTTPHeader{{":status", "103"}}) || !slices.Equal(resp.Trailers, []HTTPHeader{{"x-end", "ok"}}) {
				t.Fatalf("informational = %+v, trailers = %+v", row.Informational, resp.Trailers)
			}
		} else if len(row.Informational) != 0 || len(resp.Trailers) != 0 {
			t.Fatalf("stream 3 has unexpected headers: %+v", row)
		}
	}
}

// Build a prior-knowledge connection with valid directional sequence numbers
// and ACKs, including when a test later reorders packets in the capture.
type h2TestOpening struct {
	frames [][]byte
	seq    [2]uint32
}

func newH2TestOpening(base uint32) *h2TestOpening {
	c := &h2TestOpening{seq: [2]uint32{base, base + 1000}}
	c.packet(0, TCPFlagSYN, nil)
	c.packet(1, TCPFlagSYN|TCPFlagACK, nil)
	c.packet(0, TCPFlagACK, append(bytes.Clone(HTTP2ClientPreface), buildHTTP2Frame(HTTP2FrameSettings, 0, 0, nil)...))
	c.frame(1, HTTP2FrameSettings, 0, 0, nil)
	return c
}

func (c *h2TestOpening) packet(side int, flags uint8, data []byte) {
	c.frames = append(c.frames, txFrame(side == 1, c.seq[side], c.seq[1-side], flags, string(data)))
	c.seq[side] += uint32(len(data))
	if flags&TCPFlagSYN != 0 {
		c.seq[side]++
	}
}

func (c *h2TestOpening) frame(side int, kind, flags uint8, id uint32, data []byte) {
	c.packet(side, TCPFlagACK, buildHTTP2Frame(kind, flags, id, data))
}

func h2TestRows(t *testing.T, frames [][]byte) []HTTP2Transaction {
	t.Helper()
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	return checkReaderParity(t, raw, c.HTTP2Transactions, c.HTTP2TransactionsFromReaderAt)
}

func TestHTTP2TransactionOpeningsAndPacketOwnership(t *testing.T) {
	first := newH2TestOpening(100)
	h := buildHTTP2Frame(HTTP2FrameHeaders, 5, 1, []byte{0x82, 0x86, 0x84})
	first.packet(0, TCPFlagACK, h[:2])
	first.packet(0, TCPFlagACK, h[2:])
	first.frames[4], first.frames[5] = first.frames[5], first.frames[4]
	first.frames = append(first.frames, first.frames[5]) // Retransmission supplies no bytes.
	first.frame(1, HTTP2FrameHeaders, 5, 1, []byte{0x89})
	second := newH2TestOpening(5000)
	second.packet(0, TCPFlagACK, h)
	rows := h2TestRows(t, append(first.frames, second.frames...))
	if len(rows) != 2 || rows[0].ID() != (HTTP2TransactionID{5, 0, 1}) || rows[0].Pairing != HTTP2ResponseConfirmed || rows[0].SharedPackets ||
		!slices.Equal(rows[0].PacketIndices, []int{4, 5, 7}) || !rows[0].Request.TCPAnomalies.Retransmission ||
		rows[1].ID() != (HTTP2TransactionID{12, 0, 1}) || rows[1].Pairing != HTTP2ResponseUnseen || rows[1].Response != nil || rows[1].FlowIndex != rows[0].FlowIndex {
		t.Fatalf("rows = %+v", rows)
	}
}

func TestHTTP2TransactionResponseCoverage(t *testing.T) {
	req := []byte{0x82, 0x86, 0x84}
	rst := []byte{0, 0, 0, 8}
	for _, tc := range []struct {
		name    string
		build   func(*h2TestOpening)
		pair    HTTP2Pairing
		reset   bool
		indices []int
	}{
		{"server reset", func(c *h2TestOpening) {
			c.frame(1, HTTP2FrameRSTStream, 0, 1, rst)
			c.frame(1, HTTP2FrameHeaders, 5, 1, []byte{0x88})
		}, HTTP2ResponseUnseen, true, []int{4, 5}},
		{"client reset", func(c *h2TestOpening) {
			c.frame(0, HTTP2FrameRSTStream, 0, 1, rst)
			c.frame(1, HTTP2FrameHeaders, 5, 1, []byte{0x88})
		}, HTTP2ResponseUnseen, true, []int{4, 5}},
		{"gap", func(c *h2TestOpening) { c.seq[1]++; c.frame(1, HTTP2FrameHeaders, 5, 1, []byte{0x88}) }, HTTP2ResponseAmbiguous, false, []int{4}},
		{"conflict", func(c *h2TestOpening) {
			c.frame(1, HTTP2FrameHeaders, 5, 1, []byte{0x88})
			c.seq[1] -= 10
			c.frame(1, HTTP2FrameHeaders, 5, 1, []byte{0x89})
		}, HTTP2ResponseAmbiguous, false, []int{4}},
		{"TCP reset", func(c *h2TestOpening) {
			c.packet(1, TCPFlagRST|TCPFlagACK, nil)
			c.frame(1, HTTP2FrameHeaders, 5, 1, []byte{0x88})
		}, HTTP2ResponseAmbiguous, false, []int{4}},
		{"impossible ACK", func(c *h2TestOpening) { c.seq[0] -= 12; c.frame(1, HTTP2FrameHeaders, 5, 1, []byte{0x88}) }, HTTP2ResponseAmbiguous, false, []int{4}},
		{"only interim", func(c *h2TestOpening) { c.frame(1, HTTP2FrameHeaders, 4, 1, []byte{8, 3, '1', '0', '3'}) }, HTTP2ResponseUnseen, false, []int{4, 5}},
		{"invalid status", func(c *h2TestOpening) {
			c.frame(1, HTTP2FrameHeaders, 5, 1, []byte{8, 3, '2', 'x', '0'})
			c.frame(1, HTTP2FrameHeaders, 5, 1, []byte{0x88})
		}, HTTP2ResponseAmbiguous, false, []int{4}},
		{"unrelated reset", func(c *h2TestOpening) {
			c.frame(1, HTTP2FrameRSTStream, 0, 19, rst)
			c.frame(1, HTTP2FrameHeaders, 5, 1, []byte{0x88})
		}, HTTP2ResponseConfirmed, false, []int{4, 6}},
		{"push", func(c *h2TestOpening) {
			c.frame(1, HTTP2FramePushPromise, 4, 1, append([]byte{0, 0, 0, 2}, req...))
			c.frame(1, HTTP2FrameHeaders, 5, 2, []byte{0x88})
		}, HTTP2ResponseUnseen, false, []int{4}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newH2TestOpening(100)
			c.frame(0, HTTP2FrameHeaders, 5, 1, req)
			tc.build(c)
			rows := h2TestRows(t, c.frames)
			if len(rows) != 1 || rows[0].Pairing != tc.pair || rows[0].Reset != tc.reset || (rows[0].Response != nil) != (tc.pair == HTTP2ResponseConfirmed) || !slices.Equal(rows[0].PacketIndices, tc.indices) {
				t.Fatalf("rows = %+v", rows)
			}
		})
	}
}

func TestHTTP2TransactionBodies(t *testing.T) {
	get := []byte{0x82, 0x86, 0x84}
	head := []byte{2, 4, 'H', 'E', 'A', 'D', 0x86, 0x84}
	gzipHeaders := []byte{0x88, 0x0f, 11, 4, 'g', 'z', 'i', 'p'} // static name 26, content-encoding
	compressed := gzipTestBytes(t, bytes.Repeat([]byte("x"), 4096), 1025)
	for _, tc := range []struct {
		name               string
		req, headers, data []byte
		end                bool
		state              HTTPBodyState
		length             int
		capped             bool
	}{
		{"HEAD", head, []byte{0x88, 0x0f, 13, 1, '3'}, nil, true, HTTPBodyComplete, 0, false},
		{"204", get, []byte{0x89}, nil, true, HTTPBodyComplete, 0, false},
		{"304", get, []byte{0x8b}, nil, true, HTTPBodyComplete, 0, false},
		{"zero DATA", get, []byte{0x88}, []byte{}, true, HTTPBodyComplete, 0, false},
		{"prefix", get, []byte{0x88}, []byte("x"), false, HTTPBodyPartial, 1, false},
		{"unsupported", get, []byte{0x88, 0x0f, 11, 2, 'b', 'r'}, []byte("x"), true, HTTPBodyUnsupported, 0, false},
		{"encoding cap", get, gzipHeaders, compressed, true, HTTPBodyPartial, MaxHTTPBodyBytes, true},
		{"incorrect length", get, []byte{0x88, 0x0f, 13, 1, '3'}, []byte("x"), true, HTTPBodyUnknown, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newH2TestOpening(100)
			c.frame(0, HTTP2FrameHeaders, 5, 1, tc.req)
			flags := uint8(4)
			if tc.data == nil && tc.end {
				flags++
			}
			c.frame(1, HTTP2FrameHeaders, flags, 1, tc.headers)
			if tc.data != nil {
				flags = 0
				if tc.end {
					flags = 1
				}
				c.frame(1, HTTP2FrameData, flags, 1, tc.data)
			}
			rows := h2TestRows(t, c.frames)
			if len(rows) != 1 || rows[0].Response == nil {
				t.Fatalf("rows = %+v", rows)
			}
			r := rows[0].Response
			if r.BodyState != tc.state || len(r.Body) != tc.length || r.BodyLimitExceeded != tc.capped || r.EndStream != tc.end {
				t.Fatalf("state = %d, len = %d, capped = %v, ended = %v", r.BodyState, len(r.Body), r.BodyLimitExceeded, r.EndStream)
			}
		})
	}
}

func TestHTTP2TransactionBodyOwnership(t *testing.T) {
	opening := newH2TestOpening(100)
	bodies := []string{"plain", "first", "other"}
	for i, body := range bodies {
		id := uint32(2*i + 1)
		opening.frame(0, HTTP2FrameHeaders, 5, id, []byte{0x82, 0x86, 0x84})
		fields, data := []byte{0x88}, []byte(body)
		if i > 0 {
			fields = append(fields, 0x0f, 11, 4, 'g', 'z', 'i', 'p') // content-encoding
			data = gzipTestBytes(t, data, 1)
		}
		opening.frame(1, HTTP2FrameHeaders, 4, id, fields)
		opening.frame(1, HTTP2FrameData, 1, id, data)
	}
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, opening.frames)
	original := bytes.Clone(raw)
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	rows := checkReaderParity(t, raw, c.HTTP2Transactions, c.HTTP2TransactionsFromReaderAt)
	if len(rows) != len(bodies) {
		t.Fatalf("got %d transactions, want %d", len(rows), len(bodies))
	}
	for i, want := range bodies {
		r := rows[i].Response
		if r == nil || r.BodyState != HTTPBodyComplete || string(r.Body) != want {
			t.Fatalf("stream %d response = %+v, want body %q", rows[i].StreamID, r, want)
		}
		r.Body[0] = '!'
	}
	if !bytes.Equal(raw, original) {
		t.Fatal("editing the returned bodies changed the source capture")
	}
}

func TestHTTP2TransactionLimits(t *testing.T) {
	for _, tc := range []struct {
		name   string
		frames []byte
	}{
		{"header fields", buildHTTP2Frame(HTTP2FrameHeaders, 5, 1, bytes.Repeat([]byte{0x82}, MaxHTTPHeaders+1))},
		{"frame count", bytes.Repeat(buildHTTP2Frame(HTTP2FramePing, 0, 0, make([]byte, 8)), MaxHTTP2FramesPerStream)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newH2TestOpening(100)
			c.packet(0, TCPFlagACK, tc.frames)
			raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, c.frames)
			index, err := New(raw)
			if err != nil {
				t.Fatal(err)
			}
			if rows, err := index.HTTP2Transactions(raw); rows != nil || !errors.Is(err, ErrHTTPLimit) {
				t.Fatalf("slice = %v, %v", rows, err)
			}
			if rows, err := index.HTTP2TransactionsFromReaderAt(bytes.NewReader(raw)); rows != nil || !errors.Is(err, ErrHTTPLimit) {
				t.Fatalf("ReaderAt = %v, %v", rows, err)
			}
		})
	}
}

func TestHTTP2TransactionInterfaces(t *testing.T) {
	c := newH2TestOpening(100)
	c.frame(0, HTTP2FrameHeaders, 5, 1, []byte{0x82, 0x86, 0x84})
	c.frame(1, HTTP2FrameHeaders, 5, 1, []byte{0x88})
	var packets []tcpCapturePacket
	for i, frame := range c.frames {
		for iface := range 2 {
			packets = append(packets, tcpCapturePacket{uint32(iface), int64(2*i + iface), frame})
		}
	}
	raw, err := tcpInterfaceCapture(packets)
	if err != nil {
		t.Fatal(err)
	}
	capture, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	for mode := range 2 {
		capture.SeparateTCPInterfaces = mode == 1
		rows := checkReaderParity(t, raw, capture.HTTP2Transactions, capture.HTTP2TransactionsFromReaderAt)
		if len(rows) != mode+1 {
			t.Fatalf("mode %d = %+v", mode, rows)
		}
		for i, row := range rows {
			if row.ID() != (HTTP2TransactionID{8 + i, 0, 1}) || row.StatusCode != 200 || !slices.Equal(row.PacketIndices, []int{8 + i, 10 + i}) {
				t.Fatalf("row = %+v", row)
			}
		}
	}
}

func TestHTTP2TransactionRequiresPrefaceAndSettings(t *testing.T) {
	req := buildHTTP2Frame(HTTP2FrameHeaders, 5, 1, []byte{0x82, 0x86, 0x84})
	for _, start := range [][]byte{
		[]byte("GET / HTTP/1.1\r\nUpgrade: h2c\r\n\r\n"),
		HTTP2ClientPreface,
		append(bytes.Clone(HTTP2ClientPreface), buildHTTP2Frame(HTTP2FrameSettings, 1, 0, nil)...),
		append(bytes.Clone(HTTP2ClientPreface), buildHTTP2Frame(HTTP2FrameSettings, 0, 0, []byte{0})...),
	} {
		wire := append(bytes.Clone(start), req...)
		if rows := h2TestRows(t, [][]byte{txFrame(false, 1, 1, TCPFlagACK, string(wire))}); len(rows) != 0 {
			t.Fatalf("unexpected request = %+v", rows)
		}
	}
}

func TestHTTP2TransactionIncompleteCoverage(t *testing.T) {
	c := newH2TestOpening(100)
	c.frame(0, HTTP2FrameHeaders, 0, 1, []byte{0x82, 0x86})
	c.frame(0, HTTP2FrameContinuation, 4, 1, []byte{0x84})
	c.seq[0]-- // The response acknowledges all but the last header byte.
	c.frame(1, HTTP2FrameHeaders, 5, 1, []byte{0x88})
	rows := h2TestRows(t, c.frames)
	if len(rows) != 1 || rows[0].Response != nil || rows[0].Pairing != HTTP2ResponseAmbiguous {
		t.Fatalf("incomplete header ACK: %+v", rows)
	}
	c = newH2TestOpening(100)
	c.frame(0, HTTP2FrameHeaders, 4, 1, []byte{0x83, 0x86, 0x84})
	c.frame(0, HTTP2FrameData, 0, 1, []byte("a"))
	c.frame(1, HTTP2FrameRSTStream, 0, 1, []byte{0, 0, 0, 8})
	c.frame(0, HTTP2FrameData, 1, 1, []byte("b"))
	rows = h2TestRows(t, c.frames)
	if len(rows) != 1 || !rows[0].Reset || rows[0].Request.EndStream || rows[0].Request.BodyState != HTTPBodyPartial || string(rows[0].Request.Body) != "a" ||
		!slices.Equal(rows[0].PacketIndices, []int{4, 5, 6}) {
		t.Fatalf("data after reset: %+v", rows)
	}
	c = newH2TestOpening(100)
	c.frame(0, HTTP2FrameHeaders, 5, 1, []byte{0x82, 0x86, 0x84})
	c.frame(1, HTTP2FrameHeaders, 4, 1, []byte{0x88})
	c.frame(1, HTTP2FrameData, 0, 1, []byte("a"))
	c.seq[1]++
	c.frame(1, HTTP2FrameData, 1, 1, []byte("b"))
	rows = h2TestRows(t, c.frames)
	if len(rows) != 1 || rows[0].Response == nil || rows[0].Pairing != HTTP2ResponseConfirmed || rows[0].Response.BodyState != HTTPBodyPartial ||
		string(rows[0].Response.Body) != "a" || rows[0].Response.EndStream || !rows[0].Response.TCPAnomalies.SequenceGap || !slices.Equal(rows[0].PacketIndices, []int{4, 5, 6}) {
		t.Fatalf("gap after final status: %+v", rows)
	}
}

func TestHTTP2TransactionAggregateBudgets(t *testing.T) {
	raw, err := os.ReadFile("testdata/deployments/http2-transactions.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	dirs, err := collectHTTPTransactionDirections(ipFrameSource{capture: c, data: raw}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	headers := MaxHTTP2DecodedHeaderBytes
	client, err := readHTTP2TransactionFrames(&dirs[0], true, &headers)
	if err != nil {
		t.Fatal(err)
	}
	// The exact header allocation that admitted the request direction cannot
	// supply even the server's next HEADERS block.
	headers = MaxHTTP2DecodedHeaderBytes - headers
	if _, err = readHTTP2TransactionFrames(&dirs[0], true, &headers); err != nil || headers != 0 {
		t.Fatalf("exact header budget = %d, %v", headers, err)
	}
	if _, err = readHTTP2TransactionFrames(&dirs[1], false, &headers); !errors.Is(err, ErrHTTPLimit) {
		t.Fatalf("header budget = %v", err)
	}
	for _, tc := range []struct {
		transactions, refs int
		wantErr            bool
	}{
		{1, 6, true}, {2, 5, true}, {2, 6, false},
	} {
		budget := http2TransactionBudget{transactions: tc.transactions, packetRefs: tc.refs}
		streams := make(map[uint32]*http2Exchange)
		err := client.selectFrames(false, streams, nil, &budget)
		if tc.wantErr {
			if !errors.Is(err, ErrHTTPLimit) {
				t.Fatalf("limits %+v gave %v", tc, err)
			}
		} else if err != nil || budget.packetRefs != 0 || budget.transactions != 0 {
			t.Fatalf("exact limits: %+v, %v", budget, err)
		}
	}
	bodyBudget := http2TransactionBudget{bodyBytes: 3, decode: httpDecodeBudget{remaining: 3}}
	for i := range 2 {
		msg := HTTP2MessageEvidence{HTTP2HeaderBlock: HTTP2HeaderBlock{Headers: []HTTPHeader{{"content-encoding", "gzip"}}}, Body: gzipTestBytes(t, []byte("abc"), 1), EndStream: true}
		err := finishHTTP2Body(&msg, false, false, &bodyBudget)
		if i == 0 && (err != nil || string(msg.Body) != "abc") || i == 1 && !errors.Is(err, ErrHTTPLimit) {
			t.Fatalf("body %d = %v, %v", i, msg.Body, err)
		}
	}
}

func TestHTTP2TransactionMalformedHeaders(t *testing.T) {
	for _, h := range [][]byte{
		{2, 7, 'C', 'O', 'N', 'N', 'E', 'C', 'T'}, // CONNECT without :authority.
		append([]byte{0x82, 0x86, 0x84, 0, 9}, []byte(":protocol\x02ws")...),
		{0x82, 0x86, 0x84, 0x82},              // Duplicate :method.
		{0x82, 0x86, 0x84, 0, 1, 'X', 1, 'y'}, // Uppercase field name.
	} {
		c := newH2TestOpening(100)
		c.frame(0, HTTP2FrameHeaders, 5, 1, h)
		c.frame(1, HTTP2FrameHeaders, 5, 1, []byte{0x88})
		if rows := h2TestRows(t, c.frames); len(rows) != 0 {
			t.Fatalf("unexpected request = %+v", rows)
		}
	}
}
