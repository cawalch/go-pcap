package pcap

import (
	"bytes"
	"io"
	"os"
	"slices"
	"testing"
)

func TestKeyedHTTP3TransactionsAioquic(t *testing.T) {
	raw, err := os.ReadFile("testdata/http3-framing.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	rows := checkReaderParity(t, raw, func(b []byte) ([]KeyedHTTP3Transaction, error) { return c.KeyedHTTP3Transactions(b, nil) }, func(r io.ReaderAt) ([]KeyedHTTP3Transaction, error) {
		return c.KeyedHTTP3TransactionsFromReaderAt(r, nil)
	})
	if len(rows) != 1 {
		t.Fatalf("rows: %+v", rows)
	}
	row := rows[0]
	// TShark 4.6.10 and aioquic 1.3.0 independently report stream 0
	// POST /ingest and status 200 in frames 10 and 12, respectively.
	if row.StreamID != 0 || row.ConnectionIndex != 0 || row.StatusCode != 200 || !slices.Equal(row.ALPNPacketIndices, []int{1}) ||
		row.Request == nil || !slices.Equal(row.Request.PacketIndices, []int{9}) || string(row.Request.Body) != "request" || row.Request.BodyState != HTTPBodyComplete ||
		row.Response == nil || !slices.Equal(row.Response.PacketIndices, []int{11}) || string(row.Response.Body) != "response" || row.Response.BodyState != HTTPBodyComplete ||
		len(row.Request.Sections) != 1 || row.Request.Sections[0].Kind != HTTP3InitialSection || !slices.Equal(row.Request.Sections[0].Headers, []HTTPHeader{{":method", "POST"}, {":scheme", "https"}, {":authority", "fixture.test"}, {":path", "/ingest"}}) {
		t.Fatalf("row %+v, client %+v, server %+v", row, row.Request, row.Response)
	}
	keys := c.Secrets[0].Data
	// Select original ciphertext only. The ALPN and message packets omit
	// the client Initial needed to associate application keys and CIDs.
	for _, tc := range []struct {
		indices           []int
		external, replays bool
	}{
		{[]int{1, 9, 11}, true, false},
		{[]int{0, 1, 9, 11}, false, false},
		{[]int{0, 1, 9, 11}, true, true},
	} {
		var out bytes.Buffer
		source := flowExportSource{data: *NewSafeReader(raw), size: int64(len(raw))}
		if err := c.writeSelectedPackets(&source, &out, tc.indices, nil); err != nil {
			t.Fatal(err)
		}
		marked, err := New(out.Bytes())
		if err != nil || len(marked.Secrets) != 0 {
			t.Fatalf("selection: %v", err)
		}
		var external []byte
		if tc.external {
			external = keys
		}
		got, err := marked.KeyedHTTP3Transactions(out.Bytes(), external)
		if err != nil || (len(got) == 1) != tc.replays || len(got) == 1 && (got[0].StatusCode != 200 || string(got[0].Request.Body) != "request" || string(got[0].Response.Body) != "response") {
			t.Fatalf("selected %v external %v: %+v, %v", tc.indices, tc.external, got, err)
		}
	}
}

func h3TestStream(id, off byte, fin bool, data []byte) []byte {
	typ := byte(0x0e)
	if fin {
		typ++
	}
	return append([]byte{typ, id, off, byte(len(data))}, data...)
}

func TestKeyedHTTP3MultiplexingAndQPACKContext(t *testing.T) {
	// A client encoder insert arrives after both request sections. The same
	// datagram carries both streams; a later datagram repeats stream 0.
	req := []byte{1, 6, 2, 0, 0xd1, 0xd7, 0xc1, 0x80}
	settings := []byte{0, 4, 3, 1, 0x40, 0x40}     // Peer advertises a 64-byte table.
	encoder := []byte{2, 0x3f, 0x21, 0xc0, 1, 'x'} // :authority=x at absolute index 0.
	record := KeyedQUICRecord{ALPN: &QUICALPNSelection{Protocol: "h3", PacketIndices: []int{1}},
		Client: []QUIC1RTTPacket{
			{PacketIndex: 4, Payload: append(h3TestStream(0, 0, true, req), h3TestStream(4, 0, true, req)...)},
			{PacketIndex: 5, Payload: h3TestStream(6, 0, false, encoder[:3])},
			{PacketIndex: 6, Payload: h3TestStream(0, 0, true, req)},
			{PacketIndex: 7, Payload: h3TestStream(6, 3, false, encoder[3:])},
		},
		Server: []QUIC1RTTPacket{
			{PacketIndex: 3, Payload: h3TestStream(3, 0, false, settings)},
			{PacketIndex: 8, Payload: h3TestStream(0, 0, true, []byte{1, 3, 0, 0, 0xd8, 1, 3, 0, 0, 0xd9, 0, 1, 'x', 1, 3, 0, 0, 0xec})},
			{PacketIndex: 9, Payload: h3TestStream(8, 0, true, []byte{1, 3, 0, 0, 0xd9})},
		}}
	other := record
	other.ALPN = &QUICALPNSelection{Protocol: "doq"}
	rows, err := keyedHTTP3Transactions([]KeyedQUICRecord{other, record})
	if err != nil || len(rows) != 3 {
		t.Fatalf("rows %+v, %v", rows, err)
	}
	for i := range 2 {
		req := rows[i].Request
		if rows[i].ConnectionIndex != 1 || rows[i].StreamID != uint64(i*4) || !req.SharedPackets || req.Invalid || !req.EndStream ||
			req.BodyState != HTTPBodyComplete || !slices.Equal(req.QPACKPacketIndices, []int{3, 5, 7}) ||
			req.Sections[0].Headers[3] != (HTTPHeader{":authority", "x"}) || req.Sections[0].EncoderOffset != len(encoder) {
			t.Fatalf("request %d: %+v", i, req)
		}
	}
	if !slices.Equal(rows[0].Request.PacketIndices, []int{4, 6}) || !slices.Equal(rows[1].Request.PacketIndices, []int{4}) || rows[1].Response != nil || rows[2].Request != nil ||
		rows[2].Response == nil || rows[2].StatusCode != 200 {
		t.Fatalf("one-sided %+v", rows)
	}
	m := rows[0].Response
	if m.Invalid || rows[0].StatusCode != 200 || len(m.Sections) != 3 || m.Sections[0].Kind != HTTP3InformationalSection || m.Sections[1].Kind != HTTP3InitialSection ||
		m.Sections[2].Kind != HTTP3TrailerSection || string(m.Body) != "x" || !m.EndStream || m.SharedPackets {
		t.Fatalf("response %+v", m)
	}
	// Without peer SETTINGS the modulo range is unknown. Without encoder
	// history but with SETTINGS the count is known. Neither exposes fields.
	record.Server = nil
	for _, known := range []bool{false, true} {
		if known {
			record.Server = []QUIC1RTTPacket{{PacketIndex: 3, Payload: h3TestStream(3, 0, false, settings)}}
		}
		record.Client = record.Client[:1]
		rows, err := keyedHTTP3Transactions([]KeyedQUICRecord{record})
		if err != nil || rows[0].Request.Invalid || rows[0].Request.BodyState != HTTPBodyUnknown || rows[0].Request.Sections[0].State != QPACKBlocked ||
			len(rows[0].Request.Sections[0].Headers) != 0 || (rows[0].Request.Sections[0].RequiredInsertCount == 1) != known {
			t.Fatalf("known=%t: %+v %v", known, rows, err)
		}
	}
}

func TestKeyedHTTP3GapResetAndReordering(t *testing.T) {
	headers := []byte{1, 8, 0, 0, 0xd1, 0xd7, 0xc1, 0x50, 1, 'x'}
	start := append(slices.Clone(headers), 0, 4, 'a', 'b')
	record := KeyedQUICRecord{ALPN: &QUICALPNSelection{Protocol: "h3"},
		Client: []QUIC1RTTPacket{
			{PacketIndex: 0, Payload: h3TestStream(0, byte(len(start)+1), true, []byte{'d'})},
			{PacketIndex: 1, Payload: h3TestStream(0, 0, false, start)},
			{PacketIndex: 2, Payload: h3TestStream(4, 0, false, headers)},
			{PacketIndex: 3, Payload: []byte{4, 4, 0, byte(len(headers))}},
			{PacketIndex: 4, Payload: h3TestStream(8, 2, false, headers[2:])},
			{PacketIndex: 5, Payload: h3TestStream(8, 0, false, headers[:2])},
			{PacketIndex: 6, Payload: h3TestStream(12, 0, true, []byte{1, 3, 0, 0, 0xff})},
		}}
	rows, err := keyedHTTP3Transactions([]KeyedQUICRecord{record})
	if err != nil || len(rows) != 4 {
		t.Fatalf("%+v %v", rows, err)
	}
	m := rows[0].Request
	if !m.Gap || m.Reset || m.EndStream || m.BodyState != HTTPBodyPartial || string(m.Body) != "ab" || !slices.Equal(m.PacketIndices, []int{0, 1}) {
		t.Fatalf("gap %+v", m)
	}
	m = rows[1].Request
	if !m.Reset || m.Gap || m.EndStream || m.BodyState != HTTPBodyPartial || !slices.Equal(m.PacketIndices, []int{2, 3}) {
		t.Fatalf("reset %+v", m)
	}
	m = rows[2].Request
	if m.Reset || m.Gap || m.EndStream || m.BodyState != HTTPBodyPartial || m.Sections[0].Kind != HTTP3InitialSection {
		t.Fatalf("reorder %+v", m)
	}
	m = rows[3].Request
	if !m.Invalid || !m.EndStream || m.BodyState != HTTPBodyUnknown || m.Sections[0].State != QPACKMalformed {
		t.Fatalf("invalid %+v", m)
	}
}

func TestKeyedHTTP3ConnectData(t *testing.T) {
	// A regular or extended CONNECT request and the tunnel's DATA can share
	// a packet. The 2xx status applies to both directions of the same stream.
	for _, extended := range []bool{false, true} {
		header := []byte{0, 0, 0xcf, 0x50, 3, 'x', ':', '9'} // CONNECT, :authority=x:9.
		if extended {
			header = append(header, 0xd7, 0xc1, 0x27, 2)
			header = append(header, ":protocol"...)
			header = append(header, 9)
			header = append(header, "websocket"...)
		}
		request := append([]byte{1, byte(len(header))}, header...)
		request = append(request, 0, 3, 'a', 'b', 'c')
		for _, tc := range []struct {
			status   int
			field    byte
			response string
		}{
			{200, 0xd9, ""}, {404, 0xdb, "xyz"},
		} {
			record := KeyedQUICRecord{ALPN: &QUICALPNSelection{Protocol: "h3"},
				Client: []QUIC1RTTPacket{{PacketIndex: 2, Payload: h3TestStream(0, 0, false, request)}},
				Server: []QUIC1RTTPacket{{PacketIndex: 3, Payload: h3TestStream(0, 0, true, []byte{1, 3, 0, 0, tc.field, 0, 3, 'x', 'y', 'z'})}},
			}
			rows, err := keyedHTTP3Transactions([]KeyedQUICRecord{record})
			if err != nil || len(rows) != 1 {
				t.Fatalf("rows %+v, %v", rows, err)
			}
			cl, sv := rows[0].Request, rows[0].Response
			if cl.Body != nil || cl.BodyState != HTTPBodyComplete || cl.EndStream || cl.Invalid || !slices.Equal(cl.PacketIndices, []int{2}) ||
				rows[0].StatusCode != tc.status || string(sv.Body) != tc.response || sv.BodyState != HTTPBodyComplete || sv.Invalid || !slices.Equal(sv.PacketIndices, []int{3}) {
				t.Fatalf("extended=%t status=%d: request %+v response %+v", extended, tc.status, cl, sv)
			}
			if tc.status == 200 {
				record.Client = nil
				rows, err = keyedHTTP3Transactions([]KeyedQUICRecord{record})
				if err != nil || rows[0].Response.Body != nil || rows[0].Response.BodyState != HTTPBodyUnknown {
					t.Fatalf("response without method: %+v %v", rows, err)
				}
			}
		}
	}
}

func TestKeyedHTTP3RequestAuthority(t *testing.T) {
	for _, tc := range []struct {
		name, authority, host string
		valid                 bool
	}{
		{"absent", "-", "-", false}, {"empty authority", "", "-", false}, {"empty host", "-", "", false},
		{"empty authority with host", "", "x", false}, {"missing host value", "x", "", false},
		{"conflicting", "x", "y", false}, {"authority only", "x", "-", true}, {"host only", "-", "x", true},
		{"both equal", "x", "x", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fields := []byte{0, 0, 0xd1, 0xd7, 0xc1}
			if tc.authority != "-" {
				fields = append(fields, 0x50, byte(len(tc.authority)))
				fields = append(fields, tc.authority...)
			}
			if tc.host != "-" {
				fields = append(fields, 0x24, 'h', 'o', 's', 't', byte(len(tc.host)))
				fields = append(fields, tc.host...)
			}
			wire := append([]byte{1, byte(len(fields))}, fields...)
			record := KeyedQUICRecord{ALPN: &QUICALPNSelection{Protocol: "h3"}, Client: []QUIC1RTTPacket{{PacketIndex: 2, Payload: h3TestStream(0, 0, true, wire)}}}
			rows, err := keyedHTTP3Transactions([]KeyedQUICRecord{record})
			if err != nil || len(rows) != 1 {
				t.Fatalf("rows %+v %v", rows, err)
			}
			m := rows[0].Request
			if m.Invalid == tc.valid || (m.Sections[0].Kind == HTTP3InitialSection) != tc.valid || (m.BodyState == HTTPBodyComplete) != tc.valid {
				t.Fatalf("request %+v", m)
			}
		})
	}
}
