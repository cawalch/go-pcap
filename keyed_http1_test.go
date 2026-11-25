package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"testing"
)

const (
	keyedFirst     = "GET /first HTTP/1.1\r\nHost: fixture.example\r\n\r\n"
	keyedSecond    = "GET /second HTTP/1.1\r\nHost: fixture.example\r\n\r\n"
	keyedInterim   = "HTTP/1.1 103 Early Hints\r\n\r\n"
	keyedNoContent = "HTTP/1.1 204 No Content\r\n\r\n"
	keyedCreated   = "HTTP/1.1 201 Created\r\nContent-Length: 5\r\n\r\n"
)

type keyedFixture struct {
	tlsProofFixture
	packets [][]byte
	seq     [2]uint32
}

func newKeyedFixture(t *testing.T, v uint16) *keyedFixture {
	t.Helper()
	return newKeyedProtocolFixture(t, v, "http/1.1")
}

func newKeyedProtocolFixture(t *testing.T, v uint16, alpn string) *keyedFixture {
	t.Helper()
	f := &keyedFixture{tlsProofFixture: makeTLSProofFixture(t, v), seq: [2]uint32{100, 200}}
	if v == TLSVersion13 {
		// Negotiate the fixture protocol in EncryptedExtensions, then send Finished
		// before switching to the sequence-zero application traffic keys.
		serverHello := wrapTLSHandshakeRecord(TLSHandshakeServerHello, bytes.Join([][]byte{
			{3, 3}, bytes.Repeat([]byte{0x24}, 32), {0, 0x13, 1, 0, 0, 6, 0, 43, 0, 2, 3, 4},
		}, nil))
		size := byte(len(alpn))
		extensions := append([]byte{8, 0, 0, size + 9, 0, size + 7, 0, 16, 0, size + 3, 0, size + 1, size}, alpn...)
		finished := append([]byte{20, 0, 0, 32}, make([]byte, 32)...)
		sh, ch := [32]byte{2}, [32]byte{1}
		f.server = append(serverHello, encryptTLS13AppDataRecord(t, sh[:], TLS_AES_128_GCM_SHA256, 0, TLSRecordHandshake, append(extensions, finished...))...)
		hello := buildTLS13ClientHelloRecord("provenance.example", alpn)
		f.clientProtected = len(hello)
		f.client = append(hello, encryptTLS13AppDataRecord(t, ch[:], TLS_AES_128_GCM_SHA256, 0, TLSRecordHandshake, finished)...)
	}
	f.send(false, TCPFlagSYN, nil)
	f.send(true, TCPFlagSYN|TCPFlagACK, nil)
	clientHello := 5 + int(binary.BigEndian.Uint16(f.client[3:5]))
	f.send(false, TCPFlagACK, f.client[:clientHello])
	f.send(true, TCPFlagACK, f.server)
	f.send(false, TCPFlagACK, f.client[clientHello:])
	return f
}

func (f *keyedFixture) send(server bool, flags uint8, data []byte) {
	a, b := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	sp, dp, dir := uint16(40000), uint16(443), 0
	if server {
		a, b, sp, dp, dir = b, a, dp, sp, 1
	}
	f.packets = append(f.packets, buildEthernetIPv4TCPFrame(a, b, sp, dp, f.seq[dir], f.seq[1-dir], flags, data))
	f.seq[dir] += uint32(len(data))
	if flags&(TCPFlagSYN|TCPFlagFIN) != 0 {
		f.seq[dir]++
	}
}

func (f *keyedFixture) pipeline() {
	f.send(false, TCPFlagACK, f.seal(false, 0, TLSRecordApplicationData, keyedFirst+keyedSecond))
	f.send(true, TCPFlagACK, f.seal(true, 0, TLSRecordApplicationData, keyedInterim+keyedNoContent))
	f.send(true, TCPFlagACK, f.seal(true, 1, TLSRecordApplicationData, keyedCreated+"re"))
	record := f.seal(true, 2, TLSRecordApplicationData, "pl")
	f.send(true, TCPFlagACK, record[:7])
	f.send(true, TCPFlagACK, record[7:])
	f.send(true, TCPFlagACK|TCPFlagFIN, f.seal(true, 3, TLSRecordApplicationData, "y"))
}

func keyedCapture(t *testing.T, keys []byte, frames [][]byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w, err := NewPCAPNGWriter(&out, PCAPNGWriterOptions{LinkType: LinkTypeEthernet})
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) > 0 {
		if err := w.WriteDecryptionSecrets(SecretsTypeTLSKeyLog, keys); err != nil {
			t.Fatal(err)
		}
	}
	for i, frame := range frames {
		if err := w.WritePacket(PacketRecord{TimestampNs: 1700000000000000000 + int64(i)*1000000}, frame); err != nil {
			t.Fatal(err)
		}
	}
	return out.Bytes()
}

func keyedScan(t *testing.T, frames [][]byte, embedded, extra []byte) []KeyedHTTP1Transaction {
	t.Helper()
	raw := keyedCapture(t, embedded, frames)
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := c.KeyedHTTP1Transactions(raw, extra)
	if err != nil {
		t.Fatal(err)
	}
	r := bytes.NewReader(raw)
	index, err := NewFromReaderAt(r, int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	other, err := index.KeyedHTTP1TransactionsFromReaderAt(r, extra)
	if err != nil || !reflect.DeepEqual(rows, other) {
		t.Fatalf("slice %+v; reader %+v, %v", rows, other, err)
	}
	return rows
}

func TestKeyedHTTP1Pipeline(t *testing.T) {
	for _, version := range []uint16{TLSVersion12, TLSVersion13} {
		t.Run(fmt.Sprintf("%04x", version), func(t *testing.T) {
			f := newKeyedFixture(t, version)
			f.pipeline()
			path := "testdata/keyed-http1.pcapng"
			if version == TLSVersion13 {
				path = "testdata/keyed-http1-tls13.pcapng"
			}
			fixture, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(keyedCapture(t, f.keys, f.packets), fixture) {
				t.Fatal("fixture differs", err)
			}
			for _, tail := range []string{"full", "tampered", "truncated", "gap", "external keys", "no keys", "wrong keys", "midstream"} {
				t.Run(tail, func(t *testing.T) {
					frames := slices.Clone(f.packets)
					embedded, extra := f.keys, []byte(nil)
					switch tail {
					case "tampered":
						frames[9] = bytes.Clone(frames[9])
						frames[9][len(frames[9])-1] ^= 1
					case "truncated":
						frames[9] = frames[9][:len(frames[9])-1]
					case "gap":
						frames = slices.Delete(frames, 8, 9)
					case "external keys":
						extra, embedded = embedded, nil
					case "no keys":
						embedded = nil
					case "wrong keys":
						embedded = bytes.ReplaceAll(embedded, []byte("0"), []byte("1"))
					case "midstream":
						frames = frames[2:]
					}
					rows := keyedScan(t, frames, embedded, extra)
					if tail == "no keys" || tail == "wrong keys" {
						if len(rows) != 0 {
							t.Fatalf("requests with unavailable key: %+v", rows)
						}
						return
					}
					if len(rows) != 2 {
						t.Fatalf("requests: %+v", rows)
					}
					if tail == "midstream" {
						for _, row := range rows {
							if row.Pairing != HTTP1ResponseAmbiguous || row.Response != nil {
								t.Fatalf("unanchored pairing: %+v", row)
							}
						}
						return
					}
					first, second := rows[0], rows[1]
					recStart := len(f.client)
					recEnd := recStart + len(frames[5]) - 54
					reqRecord := TLSRecordEvidence{WireStart: recStart, WireEnd: recEnd, PlaintextStart: 0, PlaintextEnd: len(keyedFirst + keyedSecond), PacketIndices: []int{5}}
					for i, row := range rows {
						off := []int{0, len(keyedFirst)}[i]
						wantID := KeyedHTTP1TransactionID{0, recStart, off}
						if row.ID != wantID || row.RequestPlaintextOffset != off || row.Request.Target != []string{"/first", "/second"}[i] ||
							row.Request.Authority != "fixture.example" || row.Request.PacketPayloadOffset != -1 || row.Response == nil ||
							row.Request.BodyState != HTTPBodyComplete || row.Pairing != HTTP1ResponseConfirmed ||
							!reflect.DeepEqual(row.RequestRecords, []TLSRecordEvidence{reqRecord}) {
							t.Fatalf("transaction %d: %+v", i, row)
						}
					}
					want := TLSRecordEvidence{WireStart: len(f.server), WireEnd: len(f.server) + len(frames[6]) - 54, PlaintextEnd: len(keyedInterim + keyedNoContent), PacketIndices: []int{6}}
					if first.ResponsePlaintextOffset != len(keyedInterim) || first.Response.StatusCode != 204 || first.Response.BodyState != HTTPBodyComplete ||
						!reflect.DeepEqual(first.ResponseRecords, []TLSRecordEvidence{want}) || !slices.Equal(first.PacketIndices, []int{5, 6}) {
						t.Fatalf("first: %+v", first)
					}
					next := TLSRecordEvidence{WireStart: want.WireEnd, WireEnd: want.WireEnd + len(frames[7]) - 54, PlaintextStart: want.PlaintextEnd, PlaintextEnd: want.PlaintextEnd + len(keyedCreated+"re"), PacketIndices: []int{7}}
					records := []TLSRecordEvidence{next}
					packets := []int{5, 7}
					state, body := HTTPBodyPartial, "re"
					if tail == "full" || tail == "external keys" {
						state, body = HTTPBodyComplete, "reply"
						packets = []int{5, 7, 8, 9, 10}
						for _, part := range []struct {
							packets          []int
							bodyLen, wireLen int
						}{{[]int{8, 9}, 2, len(frames[8]) + len(frames[9]) - 108}, {[]int{10}, 1, len(frames[10]) - 54}} {
							next = TLSRecordEvidence{WireStart: next.WireEnd, WireEnd: next.WireEnd + part.wireLen, PlaintextStart: next.PlaintextEnd, PlaintextEnd: next.PlaintextEnd + part.bodyLen, PacketIndices: part.packets}
							records = append(records, next)
						}
					}
					if second.ResponsePlaintextOffset != len(keyedInterim+keyedNoContent) || second.Response.StatusCode != 201 ||
						second.Response.BodyState != state || string(second.Response.Body) != body || second.ServerCoverage.IncompleteTail != (state == HTTPBodyPartial) ||
						!reflect.DeepEqual(second.ResponseRecords, records) || !slices.Equal(second.PacketIndices, packets) {
						t.Fatalf("second: %+v", second)
					}
				})
			}
		})
	}
}

func TestKeyedHTTP1Limits(t *testing.T) {
	f := newKeyedFixture(t, TLSVersion13)
	raw := keyedCapture(t, f.keys, f.packets)
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	if rows, err := c.KeyedHTTP1Transactions(raw, make([]byte, MaxDecryptionSecretBytes)); rows != nil || !errors.Is(err, ErrSecretLimit) {
		t.Fatalf("combined keys: %+v, %v", rows, err)
	}
}

func TestKeyedHTTP1Coverage(t *testing.T) {
	for _, v := range []uint16{TLSVersion12, TLSVersion13} {
		for _, tc := range []struct {
			name, request, reply string
			alert                string
			expected             HTTPBodyState
			pairing              HTTP1Pairing
		}{
			{"HEAD", "HEAD /first HTTP/1.1\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n", "", HTTPBodyComplete, HTTP1ResponseConfirmed},
			{"FIN without TLS close", keyedFirst, "HTTP/1.0 200 OK\r\n\r\nentity", "", HTTPBodyPartial, HTTP1ResponseConfirmed},
			{"authenticated close", keyedFirst, "HTTP/1.0 200 OK\r\n\r\nentity", "\x01\x00", HTTPBodyComplete, HTTP1ResponseConfirmed},
			{"fatal alert", keyedFirst, "HTTP/1.0 200 OK\r\n\r\nentity", "\x02\x28", HTTPBodyPartial, HTTP1ResponseConfirmed},
			{"partial request body", "POST /first HTTP/1.1\r\nContent-Length: 3\r\n\r\nx", "", "", HTTPBodyPartial, HTTP1ResponseUnseen},
			{"partial status headers", keyedFirst, "HTTP/1.1 200 OK\r\n", "", HTTPBodyUnknown, HTTP1ResponseAmbiguous},
			{"partial request headers", "GET /partial HTTP/1.1\r\n", "", "", HTTPBodyUnknown, HTTP1ResponseUnseen},
		} {
			t.Run(fmt.Sprintf("%04x/%s", v, tc.name), func(t *testing.T) {
				f := newKeyedFixture(t, v)
				f.send(false, TCPFlagACK, f.seal(false, 0, TLSRecordApplicationData, tc.request))
				if tc.reply != "" {
					f.send(true, TCPFlagACK, f.seal(true, 0, TLSRecordApplicationData, tc.reply))
				}
				if tc.alert != "" {
					f.send(true, TCPFlagACK, f.seal(true, 1, TLSRecordAlert, tc.alert))
					// A record captured after closure cannot extend the entity.
					f.send(true, TCPFlagACK, f.seal(true, 2, TLSRecordApplicationData, "tail"))
				}
				f.send(true, TCPFlagFIN|TCPFlagACK, nil)
				rows := keyedScan(t, f.packets, f.keys, nil)
				if tc.name == "partial request headers" {
					if len(rows) != 0 {
						t.Fatalf("partial headers returned %+v", rows)
					}
					return
				}
				if len(rows) != 1 || rows[0].Pairing != tc.pairing {
					t.Fatalf("rows %+v", rows)
				}
				row := rows[0]
				if tc.pairing != HTTP1ResponseConfirmed {
					if row.Response != nil || tc.name == "partial request body" && (row.Request.BodyState != tc.expected || string(row.Request.Body) != "x") {
						t.Fatalf("request-only row %+v", row)
					}
					return
				}
				if row.Response == nil || row.Response.BodyState != tc.expected {
					t.Fatalf("response %+v", row.Response)
				}
				wantBody := "entity"
				if tc.name == "HEAD" {
					wantBody = ""
				}
				if string(row.Response.Body) != wantBody {
					t.Fatalf("body %q", row.Response.Body)
				}
				wantPackets := []int{5, 6}
				if tc.name == "authenticated close" {
					wantPackets = append(wantPackets, 7)
					if len(row.ResponseRecords) != 2 || !row.ResponseRecords[1].CloseNotify ||
						row.ResponseRecords[1].PlaintextStart != len(tc.reply) || row.ResponseRecords[1].PlaintextEnd != len(tc.reply) {
						t.Fatalf("close evidence %+v", row.ResponseRecords)
					}
				}
				if !slices.Equal(row.PacketIndices, wantPackets) {
					t.Fatalf("packets %v, want %v", row.PacketIndices, wantPackets)
				}
			})
		}
	}
}

func TestKeyedHTTP1OpeningAndEpoch(t *testing.T) {
	for _, tc := range []string{"application keys only", "early data offered", "payload beyond FIN", "wrong SYN-ACK", "response before request", "tuple reuse"} {
		t.Run(tc, func(t *testing.T) {
			f := newKeyedFixture(t, TLSVersion13)
			keys := f.keys
			if tc == "application keys only" || tc == "early data offered" {
				_, keys, _ = bytes.Cut(keys, []byte{'\n'})
				_, keys, _ = bytes.Cut(keys, []byte{'\n'})
			}
			if tc == "early data offered" {
				// Replace the empty first (GREASE) extension in ClientHello.
				pos := bytes.Index(f.packets[2][54:], []byte{0x0a, 0x0a, 0, 0})
				if pos < 0 {
					t.Fatal("missing test extension")
				}
				copy(f.packets[2][54+pos:], []byte{0, 42})
			}
			if tc == "wrong SYN-ACK" {
				binary.BigEndian.PutUint32(f.packets[1][42:46], 404)
			}
			reply := f.seal(true, 0, TLSRecordApplicationData, keyedNoContent)
			if tc == "response before request" {
				f.send(true, TCPFlagACK, reply)
			}
			f.send(false, TCPFlagACK, f.seal(false, 0, TLSRecordApplicationData, keyedFirst))
			if tc == "payload beyond FIN" {
				f.send(true, TCPFlagFIN|TCPFlagACK, nil)
				f.seq[1]-- // Contradictory payload starts at the FIN's sequence.
			}
			if tc != "response before request" {
				f.send(true, TCPFlagACK, reply)
			}
			if tc == "tuple reuse" {
				next := newKeyedFixture(t, TLSVersion13)
				next.send(false, TCPFlagACK, next.seal(false, 0, TLSRecordApplicationData, keyedFirst))
				next.send(true, TCPFlagACK, reply)
				for _, frame := range next.packets {
					for _, off := range []int{38, 42} {
						binary.BigEndian.PutUint32(frame[off:], binary.BigEndian.Uint32(frame[off:])+1000)
					}
				}
				f.packets = append(f.packets, next.packets...)
			}
			rows := keyedScan(t, f.packets, nil, keys)
			if tc == "tuple reuse" {
				if len(rows) != 2 || rows[0].ID.OpeningPacket != 0 || rows[1].ID.OpeningPacket != 7 || rows[0].Request.FlowIndex != rows[1].Request.FlowIndex ||
					rows[0].Pairing != HTTP1ResponseConfirmed || rows[1].Pairing != HTTP1ResponseConfirmed {
					t.Fatalf("openings %+v", rows)
				}
				return
			}
			if len(rows) != 1 {
				t.Fatalf("rows %+v", rows)
			}
			row := rows[0]
			if tc == "application keys only" {
				if row.Pairing != HTTP1ResponseConfirmed || !row.ClientCoverage.OpaquePrefix || !row.ServerCoverage.OpaquePrefix {
					t.Fatalf("epoch coverage %+v", row)
				}
			} else if row.Pairing != HTTP1ResponseAmbiguous || row.Response != nil {
				t.Fatalf("unexpected pairing %+v", row)
			}
		})
	}
}

func TestKeyedHTTP1SharedRecordBudget(t *testing.T) {
	f := newKeyedFixture(t, TLSVersion13)
	// 510 requests share more than 520 ciphertext packets. The input TLS
	// mapping fits while the repeated output references exceed the scan cap.
	record := f.seal(false, 0, TLSRecordApplicationData, string(bytes.Repeat([]byte(txGET), 510)))
	for len(record) > 0 {
		n := min(16, len(record))
		f.send(false, TCPFlagACK, record[:n])
		record = record[n:]
	}
	raw := keyedCapture(t, f.keys, f.packets)
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	if rows, err := c.KeyedHTTP1Transactions(raw, nil); rows != nil || !errors.Is(err, ErrHTTPLimit) {
		t.Fatalf("expanded packet references: %d rows, %v", len(rows), err)
	}
	r := bytes.NewReader(raw)
	c, err = NewFromReaderAt(r, int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if rows, err := c.KeyedHTTP1TransactionsFromReaderAt(r, nil); rows != nil || !errors.Is(err, ErrHTTPLimit) {
		t.Fatalf("ReaderAt expanded references: %d rows, %v", len(rows), err)
	}
}

func TestKeyedHTTP1EarlyRequestBoundary(t *testing.T) {
	for _, tc := range []struct {
		early, regular string
		targets        []string
	}{
		{"GET /invented HTTP/1.1\r\n", "\r\n", nil},
		{keyedFirst, keyedSecond, []string{"/first", "/second"}},
	} {
		f := newKeyedFixture(t, TLSVersion13)
		secret := [32]byte{9}
		keys := fmt.Appendf(bytes.Clone(f.keys), "CLIENT_EARLY_TRAFFIC_SECRET %x %x\n", f.client[11:43], secret)
		f.packets, f.seq = nil, [2]uint32{100, 200}
		f.send(false, TCPFlagSYN, nil)
		f.send(true, TCPFlagSYN|TCPFlagACK, nil)
		hello := bytes.Clone(f.client[:f.clientProtected])
		pos := bytes.Index(hello, []byte{10, 10, 0, 0})
		copy(hello[pos:], []byte{0, 42})
		f.send(false, TCPFlagACK, hello)
		f.send(false, TCPFlagACK, encryptTLS13AppDataRecord(t, secret[:], TLS_AES_128_GCM_SHA256, 0, TLSRecordApplicationData, []byte(tc.early)))
		f.send(true, TCPFlagACK, f.server)
		f.send(false, TCPFlagACK, f.client[f.clientProtected:])
		f.send(false, TCPFlagACK, f.seal(false, 0, TLSRecordApplicationData, tc.regular))
		f.send(true, TCPFlagACK, f.seal(true, 0, TLSRecordApplicationData, keyedNoContent))
		rows := keyedScan(t, f.packets, keys, nil)
		if len(rows) != len(tc.targets) {
			t.Fatalf("cross-epoch request %+v", rows)
		}
		for i, row := range rows {
			if row.Request.Target != tc.targets[i] || row.Pairing != HTTP1ResponseAmbiguous || row.Response != nil || row.RequestRecords[0].EarlyData != (i == 0) {
				t.Fatalf("epoch %d: %+v", i, row)
			}
		}
	}
}
