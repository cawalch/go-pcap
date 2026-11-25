package pcap

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"testing"
)

type keyedH2Fixture struct {
	*keyedFixture
	epoch [2]uint64
}

func (f *keyedH2Fixture) record(server bool, plain []byte) []byte {
	side := 0
	if server {
		side = 1
	}
	rec := f.seal(server, f.epoch[side], TLSRecordApplicationData, string(plain))
	f.epoch[side]++
	return rec
}

func newKeyedH2(t *testing.T, version uint16) *keyedH2Fixture {
	t.Helper()
	f := &keyedH2Fixture{keyedFixture: newKeyedProtocolFixture(t, version, "h2")}
	settings := buildHTTP2Frame(HTTP2FrameSettings, 0, 0, nil)
	f.send(false, TCPFlagACK, f.record(false, append(bytes.Clone(HTTP2ClientPreface), settings...)))
	f.send(true, TCPFlagACK, f.record(true, settings))
	return f
}

func (f *keyedH2Fixture) multiplex() {
	// Stream 1 inserts the authority into the directional HPACK table.
	one := append([]byte{0x83, 0x87, 4, 4}, []byte("/one")...)
	one = append(one, 0x41, 4, 't', 'e', 's', 't')
	two := append([]byte{0x82, 0x87, 4, 4}, []byte("/two")...)
	two = append(two, 0xbe)
	headers := buildHTTP2Frame(HTTP2FrameHeaders, 4, 1, one)
	headers = append(headers, buildHTTP2Frame(HTTP2FrameHeaders, 5, 3, two)...)
	f.send(false, TCPFlagACK, f.record(false, headers)) // packet 7
	upload := buildHTTP2Frame(HTTP2FrameData, 1, 1, []byte("upload"))
	f.send(false, TCPFlagACK, f.record(false, upload[:11]))
	f.send(false, TCPFlagACK, f.record(false, upload[11:]))
	response := buildHTTP2Frame(HTTP2FrameHeaders, 5, 3, []byte{0x89})
	response = append(response, buildHTTP2Frame(HTTP2FrameHeaders, 4, 1, []byte{8, 3, '1', '0', '3'})...)
	response = append(response, buildHTTP2Frame(HTTP2FrameHeaders, 4, 1, []byte{0x88})...)
	f.send(true, TCPFlagACK, f.record(true, response)) // packet 10
	f.send(true, TCPFlagACK, f.record(true, buildHTTP2Frame(HTTP2FrameData, 0, 1, []byte("download"))))
	trailer := f.record(true, buildHTTP2Frame(HTTP2FrameHeaders, 5, 1, []byte{0, 5, 'x', '-', 'e', 'n', 'd', 2, 'o', 'k'}))
	f.send(true, TCPFlagACK, trailer[:7])
	f.send(true, TCPFlagACK, trailer[7:])
}

func keyedH2Rows(t *testing.T, raw, extra []byte) []KeyedHTTP2Transaction {
	t.Helper()
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	a, err := c.KeyedHTTP2Transactions(raw, extra)
	if err != nil {
		t.Fatal(err)
	}
	r := bytes.NewReader(raw)
	c, err = NewFromReaderAt(r, int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.KeyedHTTP2TransactionsFromReaderAt(r, extra)
	if err != nil || !reflect.DeepEqual(a, b) {
		t.Fatalf("slice %+v, ReaderAt %+v, err %v", a, b, err)
	}
	return a
}

func TestKeyedHTTP2Transactions(t *testing.T) {
	for _, v := range []uint16{TLSVersion12, TLSVersion13} {
		f := newKeyedH2(t, v)
		f.multiplex()
		raw := keyedCapture(t, f.keys, f.packets)
		if v == TLSVersion13 {
			fixture, err := os.ReadFile("testdata/keyed-http2.pcapng")
			if err != nil || !bytes.Equal(raw, fixture) {
				t.Fatalf("fixture differs: %v", err)
			}
		}
		rows := keyedH2Rows(t, raw, nil)
		if len(rows) != 2 {
			t.Fatalf("rows %+v", rows)
		}
		one, two := rows[0], rows[1]
		recordStart := len(f.client) + len(f.packets[5]) - 54
		if one.ID != (KeyedHTTP2TransactionID{0, recordStart, 0, 1}) || two.ID != (KeyedHTTP2TransactionID{0, recordStart, 23, 3}) ||
			one.RequestPlaintextOffset != 33 || two.RequestPlaintextOffset != 56 || two.ResponsePlaintextOffset != 9 || one.ResponsePlaintextOffset != 33 {
			t.Fatalf("IDs/offsets: %+v, %+v", one, two)
		}
		if one.Request.Path != "/one" || two.Request.Path != "/two" || two.Request.Authority != "test" || one.Request.Method != "POST" || two.Request.Method != "GET" ||
			one.StatusCode != 200 || two.StatusCode != 204 || one.Response == nil || two.Response == nil || one.Pairing != HTTP2ResponseConfirmed || two.Pairing != HTTP2ResponseConfirmed ||
			one.Request.BodyState != HTTPBodyComplete || string(one.Request.Body) != "upload" || one.Response.BodyState != HTTPBodyComplete || string(one.Response.Body) != "download" ||
			two.Request.BodyState != HTTPBodyComplete || len(two.Request.Body) != 0 || two.Response.BodyState != HTTPBodyComplete || len(two.Response.Body) != 0 ||
			len(one.Informational) != 1 || one.Informational[0].Status != "103" || !reflect.DeepEqual(one.Response.Trailers, []HTTPHeader{{"x-end", "ok"}}) {
			t.Fatalf("transactions %+v, %+v", one, two)
		}
		for _, row := range rows {
			if !row.SharedRecords || !row.SharedPackets || row.Request.PacketIndex != -1 || row.Request.PacketPayloadOffset != -1 || row.Request.TimestampNs != 0 ||
				row.Response.PacketIndex != -1 || row.Response.PacketPayloadOffset != -1 || row.Response.TimestampNs != 0 || row.ServerCoverage.IncompleteTail || row.ClientCoverage.IncompleteTail {
				t.Fatalf("evidence %+v", row)
			}
		}
		if !slices.Equal(one.PacketIndices, []int{7, 8, 9, 10, 11, 12, 13}) || !slices.Equal(two.PacketIndices, []int{7, 10}) ||
			!slices.Equal(one.RequestRanges, []HTTP2PlaintextRange{{33, 56}, {74, 89}}) || !slices.Equal(two.RequestRanges, []HTTP2PlaintextRange{{56, 74}}) ||
			!slices.Equal(one.ResponseRanges, []HTTP2PlaintextRange{{19, 79}}) || !slices.Equal(two.ResponseRanges, []HTTP2PlaintextRange{{9, 19}}) {
			t.Fatalf("one ranges %v/%v packets %v; two %v/%v packets %v", one.RequestRanges, one.ResponseRanges, one.PacketIndices, two.RequestRanges, two.ResponseRanges, two.PacketIndices)
		}
		if len(one.RequestRecords) != 3 || len(two.RequestRecords) != 1 || len(one.ResponseRecords) != 3 || len(two.ResponseRecords) != 1 {
			t.Fatal("record counts", one, two)
		}
		check := func(records []TLSRecordEvidence, plain, wire int, ends []int, packets [][]int) {
			t.Helper()
			for i, end := range ends {
				n := 0
				for _, idx := range packets[i] {
					n += len(f.packets[idx]) - 54
				}
				want := TLSRecordEvidence{PlaintextStart: plain, PlaintextEnd: end, WireStart: wire, WireEnd: wire + n, PacketIndices: packets[i]}
				if !reflect.DeepEqual(records[i], want) {
					t.Fatalf("record %+v want %+v", records[i], want)
				}
				plain, wire = end, wire+n
			}
		}
		check(one.RequestRecords, 33, recordStart, []int{74, 85, 89}, [][]int{{7}, {8}, {9}})
		check(two.RequestRecords, 33, recordStart, []int{74}, [][]int{{7}})
		serverStart := len(f.server) + len(f.packets[6]) - 54
		check(one.ResponseRecords, 9, serverStart, []int{43, 60, 79}, [][]int{{10}, {11}, {12, 13}})
		check(two.ResponseRecords, 9, serverStart, []int{43}, [][]int{{10}})
		noKeys := keyedCapture(t, nil, f.packets)
		if got := keyedH2Rows(t, noKeys, nil); len(got) != 0 {
			t.Fatal("requests without keys", got)
		}
		if got := keyedH2Rows(t, noKeys, f.keys); !reflect.DeepEqual(rows, got) {
			t.Fatal("external keys differ")
		}
	}
}

func TestKeyedHTTP2FailureAndOpeningIsolation(t *testing.T) {
	f := newKeyedH2(t, TLSVersion13)
	f.multiplex()
	for _, tc := range []string{"truncation", "bad tag", "TCP gap", "missing handshake", "response key unavailable"} {
		t.Run(tc, func(t *testing.T) {
			frames := slices.Clone(f.packets)
			keys := f.keys
			switch tc {
			case "truncation":
				frames[13] = frames[13][:len(frames[13])-1]
			case "bad tag":
				frames[13] = bytes.Clone(frames[13])
				frames[13][len(frames[13])-1] ^= 1
			case "TCP gap":
				frames = slices.Delete(frames, 12, 13)
			case "missing handshake":
				frames = frames[2:]
			case "response key unavailable":
				keys, _, _ = bytes.Cut(keys, []byte("SERVER_TRAFFIC_SECRET_0"))
			}
			rows := keyedH2Rows(t, keyedCapture(t, keys, frames), nil)
			if len(rows) != 2 {
				t.Fatalf("rows %+v", rows)
			}
			if tc == "missing handshake" || tc == "response key unavailable" {
				for _, r := range rows {
					if r.Response != nil || r.Pairing != HTTP2ResponseAmbiguous || r.ResponsePlaintextOffset != -1 || len(r.ResponseRecords) != 0 || len(r.ResponseRanges) != 0 {
						t.Fatalf("ambiguous row %+v", r)
					}
				}
				return
			}
			one, two := rows[0], rows[1]
			if one.Response == nil || two.Response == nil || !one.ServerCoverage.IncompleteTail || one.Response.EndStream || one.StatusCode != 200 || one.Response.BodyState != HTTPBodyPartial ||
				string(one.Response.Body) != "download" || two.Response.BodyState != HTTPBodyComplete || two.StatusCode != 204 || len(one.ResponseRecords) != 2 ||
				!slices.Equal(one.PacketIndices, []int{7, 8, 9, 10, 11}) || !slices.Equal(one.ResponseRanges, []HTTP2PlaintextRange{{19, 60}}) {
				t.Fatalf("rows %+v", rows)
			}
			if tc != "bad tag" {
				return
			}
			// The next opening reuses the tuple and stream IDs with distinct TCP initial sequence numbers.
			offset := len(frames)
			for _, original := range f.packets {
				packet := bytes.Clone(original)
				for _, i := range []int{38, 42} {
					binary.BigEndian.PutUint32(packet[i:], binary.BigEndian.Uint32(packet[i:])+10000)
				}
				frames = append(frames, packet)
			}
			rows = keyedH2Rows(t, keyedCapture(t, keys, frames), nil)
			if len(rows) != 4 || rows[0].Response.BodyState != HTTPBodyPartial || rows[2].ID.OpeningPacket != offset || rows[2].ID.StreamID != 1 || rows[2].ID == rows[0].ID ||
				rows[2].Response == nil || rows[2].Response.BodyState != HTTPBodyComplete || rows[2].ServerCoverage.IncompleteTail || rows[2].FlowIndex != rows[0].FlowIndex {
				t.Fatalf("opening isolation %+v", rows)
			}
		})
	}
}

func TestKeyedHTTP2ResetBoundary(t *testing.T) {
	for _, split := range []bool{false, true} {
		f := newKeyedH2(t, TLSVersion13)
		send := func(server bool, data []byte) { f.send(server, TCPFlagACK, f.record(server, data)) }
		send(false, buildHTTP2Frame(HTTP2FrameHeaders, 5, 1, []byte{0x82, 0x87, 0x84}))
		rst := buildHTTP2Frame(HTTP2FrameRSTStream, 0, 1, []byte{0, 0, 0, 8})
		if split {
			send(true, buildHTTP2Frame(HTTP2FrameHeaders, 1, 1, nil))
			last := buildHTTP2Frame(HTTP2FrameContinuation, 4, 1, []byte{0x88})
			send(true, last[:5])
			send(false, rst)
			send(true, last[5:])
		} else {
			send(true, buildHTTP2Frame(HTTP2FrameHeaders, 4, 1, []byte{0x88}))
			send(true, buildHTTP2Frame(HTTP2FrameData, 0, 1, []byte("kept")))
			send(false, rst)
			send(true, buildHTTP2Frame(HTTP2FrameData, 1, 1, []byte("after reset")))
		}
		rows := keyedH2Rows(t, keyedCapture(t, f.keys, f.packets), nil)
		if len(rows) != 1 || !rows[0].Reset {
			t.Fatal("reset missing", rows)
		}
		row := rows[0]
		if split {
			if row.Response != nil || len(row.ResponseRecords) != 0 || row.ResponsePlaintextOffset != -1 || !slices.Equal(row.PacketIndices, []int{7, 10}) {
				t.Fatal("cross-reset final", row)
			}
		} else if row.Response == nil || row.Response.EndStream || string(row.Response.Body) != "kept" || row.Response.BodyState != HTTPBodyPartial ||
			!slices.Equal(row.PacketIndices, []int{7, 8, 9, 10}) {
			t.Fatal("reset body", row)
		}
	}
}

func TestKeyedHTTP2Sharing(t *testing.T) {
	for _, other := range []bool{false, true} {
		f := newKeyedH2(t, TLSVersion13)
		headers := []byte{0x82, 0x87, 0x84}
		a := f.record(false, buildHTTP2Frame(HTTP2FrameHeaders, 5, 1, headers))
		var b []byte
		if other {
			b = buildHTTP2Frame(HTTP2FrameHeaders, 5, 3, headers)
		} else {
			b = buildHTTP2Frame(HTTP2FramePing, 0, 0, make([]byte, 8))
		}
		f.send(false, TCPFlagACK, append(a, f.record(false, b)...))
		rows := keyedH2Rows(t, keyedCapture(t, f.keys, f.packets), nil)
		if len(rows) == 0 || other != (len(rows) == 2) {
			t.Fatal("selection", rows)
		}
		for _, r := range rows {
			if r.SharedRecords || r.SharedPackets != other || !slices.Equal(r.PacketIndices, []int{7}) || len(r.RequestRanges) != 1 || len(r.RequestRecords) != 1 {
				t.Fatalf("sharing %+v", r)
			}
		}
	}
}

func TestKeyedHTTP2LimitsAndRole(t *testing.T) {
	f := newKeyedH2(t, TLSVersion13)
	settingsOnly := keyedCapture(t, f.keys, f.packets)
	if got := keyedH2Rows(t, settingsOnly, nil); len(got) != 0 {
		t.Fatal("negotiation/SETTINGS created a request", got)
	}
	f.multiplex()
	raw := keyedCapture(t, f.keys, f.packets)
	c, err := NewFromReaderAt(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if rows, err := c.KeyedHTTP2TransactionsFromReaderAt(bytes.NewReader(raw[:len(raw)/2]), nil); err == nil || len(rows) != 0 {
		t.Fatal("short ReaderAt", rows, err)
	}
	streams, err := scanTLSProvenance(ipFrameSource{capture: c, data: raw}, nil)
	if err != nil || len(streams) != 1 {
		t.Fatal("provenance", err)
	}
	s := &streams[0]
	client := http2TransactionFrames{tls: s, data: s.Client.Data, anomalies: s.Client.Anomalies}
	budget := newHTTP2TransactionBudget()
	budget.packetRefs = 1
	if rows, err := appendKeyedHTTP2(nil, &client, true, &budget); rows != nil || !errors.Is(err, ErrHTTPLimit) {
		t.Fatal("retained references", rows, err)
	}
	f = &keyedH2Fixture{keyedFixture: newKeyedProtocolFixture(t, TLSVersion13, "h2")}
	headers := buildHTTP2Frame(HTTP2FrameHeaders, 5, 1, []byte{0x82, 0x87, 0x84})
	f.send(false, TCPFlagACK, f.record(false, headers))
	if rows := keyedH2Rows(t, keyedCapture(t, f.keys, f.packets), nil); len(rows) != 0 {
		t.Fatal("ALPN without preface", rows)
	}
}

func TestKeyedHTTP2EarlyDataBoundary(t *testing.T) {
	headers := buildHTTP2Frame(HTTP2FrameHeaders, 5, 1, []byte{0x82, 0x87, 0x84})
	settings := buildHTTP2Frame(HTTP2FrameSettings, 0, 0, nil)
	start := append(bytes.Clone(HTTP2ClientPreface), settings...)
	start = append(start, headers...)
	for _, split := range []bool{true, false} {
		f := newKeyedProtocolFixture(t, TLSVersion13, "h2")
		hello := bytes.Clone(f.client[:f.clientProtected])
		i := bytes.Index(hello, []byte{10, 10, 0, 0})
		if i < 0 {
			t.Fatal("missing fixture extension")
		}
		copy(hello[i:], []byte{0, 42})
		f.packets, f.seq = nil, [2]uint32{100, 200}
		f.send(false, TCPFlagSYN, nil)
		f.send(true, TCPFlagSYN|TCPFlagACK, nil)
		f.send(false, TCPFlagACK, hello)
		early, regular := start, start
		if split {
			early, regular = start[:7], start[7:]
		}
		secret := [32]byte{9}
		keys := fmt.Appendf(bytes.Clone(f.keys), "CLIENT_EARLY_TRAFFIC_SECRET %x %x\n", hello[11:43], secret)
		f.send(false, TCPFlagACK, encryptTLS13AppDataRecord(t, secret[:], TLS_AES_128_GCM_SHA256, 0, TLSRecordApplicationData, early))
		f.send(true, TCPFlagACK, f.server)
		f.send(false, TCPFlagACK, f.client[f.clientProtected:])
		f.send(false, TCPFlagACK, f.seal(false, 0, TLSRecordApplicationData, string(regular)))
		response := append(bytes.Clone(settings), buildHTTP2Frame(HTTP2FrameHeaders, 5, 1, []byte{0x88})...)
		f.send(true, TCPFlagACK, f.seal(true, 0, TLSRecordApplicationData, string(response)))
		rows := keyedH2Rows(t, keyedCapture(t, keys, f.packets), nil)
		if split {
			if len(rows) != 0 {
				t.Fatalf("joined preface from distinct epochs: %+v", rows)
			}
			continue
		}
		if len(rows) != 2 || rows[0].ID == rows[1].ID || rows[1].RequestPlaintextOffset != len(early)+33 {
			t.Fatal("epoch IDs and offsets", rows)
		}
		for i, r := range rows {
			if r.Response != nil || r.Pairing != HTTP2ResponseAmbiguous || r.RequestRecords[0].EarlyData != (i == 0) {
				t.Fatal("uncertain early-data acceptance", r)
			}
		}
	}
}

func TestKeyedHTTP2KeyUpdate(t *testing.T) {
	f := newKeyedH2(t, TLSVersion13)
	h := []byte{0x82, 0x87, 0x84, 0x41, 4, 't', 'e', 's', 't'}
	f.send(false, TCPFlagACK, f.record(false, buildHTTP2Frame(HTTP2FrameHeaders, 5, 1, h)))
	key := [32]byte{3}
	update := []byte{TLSHandshakeKeyUpdate, 0, 0, 1, 0}
	f.send(false, TCPFlagACK, encryptTLS13AppDataRecord(t, key[:], TLS_AES_128_GCM_SHA256, f.epoch[0], TLSRecordHandshake, update))
	next, err := tls13ExpandLabelHash(sha256.New, key[:], "traffic upd", nil, len(key))
	if err != nil {
		t.Fatal(err)
	}
	indexed := buildHTTP2Frame(HTTP2FrameHeaders, 5, 3, []byte{0x82, 0x87, 0x84, 0xbe})
	f.send(false, TCPFlagACK, encryptTLS13AppDataRecord(t, next, TLS_AES_128_GCM_SHA256, 0, TLSRecordApplicationData, indexed))
	rows := keyedH2Rows(t, keyedCapture(t, f.keys, f.packets), nil)
	if len(rows) != 2 || rows[1].Request.Authority != "test" || rows[1].ClientCoverage.IncompleteTail || !slices.Equal(rows[1].PacketIndices, []int{9}) {
		t.Fatalf("directional HPACK after KeyUpdate: %+v", rows)
	}
}
