package pcap

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"slices"
	"testing"
)

func keyedEpochExportFixture(t *testing.T) *keyedFixture {
	t.Helper()
	f := newKeyedFixture(t, TLSVersion13)
	f.send(false, TCPFlagACK, f.seal(false, 0, TLSRecordApplicationData, keyedFirst+keyedSecond))
	f.send(true, TCPFlagACK, f.seal(true, 0, TLSRecordApplicationData, keyedInterim+keyedNoContent))
	f.send(true, TCPFlagACK, f.seal(true, 1, TLSRecordHandshake, string([]byte{TLSHandshakeKeyUpdate, 0, 0, 1, 0})))
	serverSecret := [32]byte{4}
	next, err := tls13ExpandLabelHash(sha256.New, serverSecret[:], "traffic upd", nil, 32)
	if err != nil {
		t.Fatal(err)
	}
	f.send(true, TCPFlagACK, encryptTLS13AppDataRecord(t, next, TLS_AES_128_GCM_SHA256, 0, TLSRecordApplicationData, []byte(keyedCreated+"re")))
	end := encryptTLS13AppDataRecord(t, next, TLS_AES_128_GCM_SHA256, 1, TLSRecordApplicationData, []byte("ply"))
	f.send(true, TCPFlagACK, end[:7])
	f.send(true, TCPFlagACK, end[7:])
	f.send(false, TCPFlagACK, f.seal(false, 1, TLSRecordApplicationData, "GET /later HTTP/1.1\r\n\r\n"))
	other := buildEthernetIPv4TCPFrame([4]byte{192, 0, 2, 8}, [4]byte{192, 0, 2, 9}, 32000, 8443, 99, 0, TCPFlagSYN, nil)
	f.packets = slices.Insert(f.packets, 10, other)
	f.packets = slices.Insert(f.packets, 0, buildEthernetIPv4UDPFrame([4]byte{192, 0, 2, 8}, [4]byte{192, 0, 2, 9}, 31000, 31001, []byte("unrelated")))
	return f
}

func keyedExportSource(t *testing.T, f *keyedFixture) []byte {
	t.Helper()
	var out bytes.Buffer
	w, err := NewPCAPNGWriter(&out, PCAPNGWriterOptions{InterfaceName: "unused-interface", UserApplication: "source-metadata-marker"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.AddInterface(PCAPNGWriterOptions{LinkType: LinkTypeEthernet, InterfaceName: "source-interface-marker"}); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteDecryptionSecrets(SecretsTypeTLSKeyLog, f.keys); err != nil {
		t.Fatal(err)
	}
	for i, frame := range f.packets {
		pkt := PacketRecord{InterfaceID: 1, OriginalLen: uint32(len(frame)), TimestampNs: 1700000000000000000 + int64(i)*1000000}
		if i == 0 || i == 11 {
			pkt.InterfaceID = 0
		}
		if i == 6 {
			// Exercise EPB FCS flags and the original-length field. The
			// four FCS bytes are outside the IP datagram.
			frame = append(bytes.Clone(frame), 1, 2, 3, 4)
			pkt.OriginalLen = uint32(len(frame) + 3)
			pkt.Flags = 4<<5 | 1
			pkt.ContainerID = "packet-comment-marker"
		}
		if err := w.WritePacket(pkt, frame); err != nil {
			t.Fatal(err)
		}
	}
	return out.Bytes()
}

func keyedExportBoth(t *testing.T, raw, keys []byte, id KeyedHTTP1TransactionID) []byte {
	t.Helper()
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	var a, b bytes.Buffer
	if err := c.ExtractKeyedHTTP1TransactionPCAPNG(raw, keys, &a, id); err != nil {
		t.Fatal(err)
	}
	r := bytes.NewReader(raw)
	index, err := NewFromReaderAt(r, r.Size())
	if err != nil {
		t.Fatal(err)
	}
	if err := index.ExtractKeyedHTTP1TransactionPCAPNGFromReaderAt(r, keys, &b, id); err != nil || !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatalf("ReaderAt output differs: %v", err)
	}
	return a.Bytes()
}

func TestExtractKeyedHTTP1Epoch(t *testing.T) {
	f := keyedEpochExportFixture(t)
	raw := keyedExportSource(t, f)
	fixture, err := os.ReadFile("testdata/keyed-http1-export.pcapng")
	if err != nil || !bytes.Equal(raw, fixture) {
		t.Fatalf("key-update fixture differs: %v", err)
	}
	for _, classic := range []bool{false, true} {
		var keys []byte
		if classic {
			raw = buildClassicPCAP(binary.BigEndian, true, LinkTypeEthernet, 65535, f.packets)
			keys = f.keys
		}
		c, original := readWrittenPackets(t, raw)
		rows, err := c.KeyedHTTP1Transactions(raw, keys)
		if err != nil || len(rows) != 3 || rows[1].Request.Target != "/second" || rows[1].Response == nil || string(rows[1].Response.Body) != "reply" {
			t.Fatalf("source rows %+v, %v", rows, err)
		}
		out := keyedExportBoth(t, raw, keys, rows[1].ID)
		check, packets := readWrittenPackets(t, out)
		want := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12}
		if len(packets) != len(want) || len(check.Interfaces) != 1 || len(check.Secrets) != 0 {
			t.Fatalf("export packets %d, interfaces %d, secrets %d", len(packets), len(check.Interfaces), len(check.Secrets))
		}
		for i, at := range want {
			p, q := original[at], packets[i]
			a, err := c.PacketPayload(raw, p)
			if err != nil {
				t.Fatal(err)
			}
			b, err := check.PacketPayload(out, q)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(a, b) || p.TimestampNs != q.TimestampNs || p.OriginalLen != q.OriginalLen || p.CaptureLen != q.CaptureLen || p.LinkType != q.LinkType || q.InterfaceID != 0 || q.Flags != p.Flags&(0xf<<5) {
				t.Fatalf("selected packet %d = %+v; source %d = %+v", i, q, at, p)
			}
		}
		for _, marker := range [][]byte{[]byte("source-metadata-marker"), []byte("source-interface-marker"), []byte("packet-comment-marker"), f.keys, []byte(keyedSecond), []byte("unrelated")} {
			if bytes.Contains(out, marker) {
				t.Fatalf("export contains %q", marker)
			}
		}
		checkKeyedExportBlocks(t, out)
		noKeys, err := check.KeyedHTTP1Transactions(out, nil)
		if err != nil || len(noKeys) != 0 {
			t.Fatalf("export decrypted without keys: %+v, %v", noKeys, err)
		}
		decoded, err := check.KeyedHTTP1Transactions(out, f.keys)
		if err != nil || len(decoded) != 2 {
			t.Fatalf("reopened rows %+v, %v", decoded, err)
		}
		tx := decoded[1]
		if tx.ID.OpeningPacket != 0 || tx.ID == rows[1].ID || tx.Request.Method != "GET" || tx.Request.Target != "/second" || tx.Pairing != HTTP1ResponseConfirmed ||
			tx.Response == nil || tx.Response.StatusCode != 201 || tx.Response.BodyState != HTTPBodyComplete || string(tx.Response.Body) != "reply" {
			t.Fatalf("reopened second %+v", tx)
		}
	}
}

// Check the block and option allowlist independently of the parsed summaries.
func checkKeyedExportBlocks(t *testing.T, data []byte) {
	t.Helper()
	var order binary.ByteOrder = binary.LittleEndian
	if order.Uint32(data[8:]) != PCAPNGByteOrderMagic {
		order = binary.BigEndian
	}
	for len(data) > 0 {
		kind, length := order.Uint32(data), int(order.Uint32(data[4:]))
		body := data[8 : length-4]
		var optStart int
		switch kind {
		case BlockTypeSectionHeader:
			optStart = 16
		case BlockTypeInterfaceDesc:
			optStart = 8
		case BlockTypeEnhancedPacket:
			optStart = 20 + (int(order.Uint32(body[12:]))+3)&^3
		default:
			t.Fatalf("unexpected block %#x", kind)
		}
		r := NewSafeReader(body)
		err := walkPCAPNGOptions(r, int64(optStart), r.Size(), order, func(code uint16, _ []byte) error {
			interfaceOption := kind == BlockTypeInterfaceDesc && (code == optIDBTsResol || code == optIDBFCSLen || code == optIDBTsOffset)
			packetOption := kind == BlockTypeEnhancedPacket && code == optEPBFlags
			if !interfaceOption && !packetOption {
				t.Fatalf("unexpected option %d on block %#x", code, kind)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		data = data[length:]
	}
}

func TestExtractKeyedHTTP1Errors(t *testing.T) {
	f := newKeyedFixture(t, TLSVersion13)
	f.pipeline()
	raw := keyedCapture(t, nil, f.packets)
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := c.KeyedHTTP1Transactions(raw, f.keys)
	if err != nil || len(rows) != 2 {
		t.Fatal(err)
	}
	r := &measuredReaderAt{Reader: bytes.NewReader(raw)}
	for _, id := range []KeyedHTTP1TransactionID{{-1, 0, 0}, {c.PacketCount, 0, 0}, {0, -1, 0}, {0, MaxFlowStreamBytes, 0}, {0, 0, -1}, {0, 0, MaxTLSRecordBytes}} {
		w := &incompleteCaptureWrite{}
		if err := c.ExtractKeyedHTTP1TransactionPCAPNGFromReaderAt(r, f.keys, w, id); !errors.Is(err, ErrOutOfBounds) || r.calls != 0 || w.writes != 0 {
			t.Fatalf("invalid ID %+v: %v, reads %d, writes %d", id, err, r.calls, w.writes)
		}
	}
	for _, export := range []func([]byte, io.Writer, KeyedHTTP1TransactionID) error{
		func(keys []byte, w io.Writer, id KeyedHTTP1TransactionID) error {
			return c.ExtractKeyedHTTP1TransactionPCAPNG(raw, keys, w, id)
		},
		func(keys []byte, w io.Writer, id KeyedHTTP1TransactionID) error {
			return c.ExtractKeyedHTTP1TransactionPCAPNGFromReaderAt(r, keys, w, id)
		},
	} {
		w := &incompleteCaptureWrite{failAt: 2}
		missing := rows[1].ID
		missing.OffsetInRecord++
		if err := export(f.keys, w, missing); !errors.Is(err, ErrOutOfBounds) || w.writes != 0 {
			t.Fatalf("missing id: %v, writes %d", err, w.writes)
		}
		if err := export(nil, w, rows[1].ID); !errors.Is(err, ErrOutOfBounds) || w.writes != 0 {
			t.Fatalf("missing keys: %v, writes %d", err, w.writes)
		}
		if err := export(f.keys, w, rows[1].ID); !errors.Is(err, io.ErrShortWrite) || w.writes != 2 {
			t.Fatalf("writer failure: %v, writes %d", err, w.writes)
		}
	}
}

func TestExtractKeyedHTTP1OutOfOrderAndReuse(t *testing.T) {
	f := keyedEpochExportFixture(t)
	// Delay the KeyUpdate until after the selected final response and the
	// next request. Its original capture position is still needed.
	update := f.packets[8]
	f.packets = slices.Delete(f.packets, 8, 9)
	f.packets = append(f.packets, update)
	// An earlier opening uses the same endpoints, paths and traffic keys.
	prior := newKeyedFixture(t, TLSVersion13)
	prior.pipeline()
	for _, frame := range prior.packets {
		for _, off := range []int{38, 42} {
			binary.BigEndian.PutUint32(frame[off:], binary.BigEndian.Uint32(frame[off:])+10000)
		}
	}
	raw := keyedCapture(t, f.keys, slices.Concat(prior.packets, f.packets))
	c, src := readWrittenPackets(t, raw)
	rows, err := c.KeyedHTTP1Transactions(raw, nil)
	if err != nil || len(rows) != 5 {
		t.Fatalf("source rows %+v, %v", rows, err)
	}
	id := rows[3].ID
	if rows[3].Request.Target != "/second" || id.OpeningPacket != len(prior.packets)+1 {
		t.Fatalf("selected opening %+v", rows[3])
	}
	out := keyedExportBoth(t, raw, nil, id)
	opened, pkts := readWrittenPackets(t, out)
	want := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 13}
	if len(pkts) != len(want) {
		t.Fatalf("got %d packets", len(pkts))
	}
	for i, n := range want {
		original := src[len(prior.packets)+n]
		if pkts[i].TimestampNs != original.TimestampNs {
			t.Fatalf("packet %d time %d, want %d", i, pkts[i].TimestampNs, original.TimestampNs)
		}
	}
	got, err := opened.KeyedHTTP1Transactions(out, f.keys)
	if err != nil || len(got) != 2 || got[1].Response == nil || string(got[1].Response.Body) != "reply" {
		t.Fatalf("reopened %+v, %v", got, err)
	}
}

func TestExtractKeyedHTTP1PartialCoverage(t *testing.T) {
	for _, damage := range []string{"authentication", "overlap conflict", "missing reverse key"} {
		t.Run(damage, func(t *testing.T) {
			f := newKeyedFixture(t, TLSVersion13)
			f.pipeline()
			keys := f.keys
			switch damage {
			case "authentication":
				f.packets[9][len(f.packets[9])-1] ^= 1
			case "overlap conflict":
				conflict := bytes.Clone(f.packets[9])
				conflict[len(conflict)-1] ^= 1
				f.packets = append(f.packets, conflict)
			case "missing reverse key":
				lines := bytes.Split(keys, []byte{'\n'})
				keys = bytes.Join(lines[:3], []byte{'\n'})
			}
			raw := keyedCapture(t, keys, f.packets)
			c, _ := readWrittenPackets(t, raw)
			rows, err := c.KeyedHTTP1Transactions(raw, nil)
			if err != nil || len(rows) != 2 {
				t.Fatalf("source %+v, %v", rows, err)
			}
			before := rows[1]
			if damage == "authentication" {
				if before.Response == nil || before.Response.BodyState != HTTPBodyPartial || string(before.Response.Body) != "re" {
					t.Fatalf("source response %+v", before)
				}
			} else if before.Pairing != HTTP1ResponseAmbiguous || before.Response != nil {
				t.Fatalf("source pairing %+v", before)
			}
			out := keyedExportBoth(t, raw, nil, before.ID)
			opened, _ := readWrittenPackets(t, out)
			got, err := opened.KeyedHTTP1Transactions(out, keys)
			if err != nil || len(got) != 2 || got[1].Pairing != before.Pairing {
				t.Fatalf("reopened %+v, %v", got, err)
			}
			if before.Response != nil && (got[1].Response == nil || got[1].Response.BodyState != HTTPBodyPartial || string(got[1].Response.Body) != "re" || !got[1].ServerCoverage.IncompleteTail) {
				t.Fatalf("partial export %+v", got[1])
			}
		})
	}
}

func consumeTLSRecordBudget(t *testing.T, remaining int) *keyedFixture {
	t.Helper()
	other := newKeyedFixture(t, TLSVersion13)
	ccs := []byte{TLSRecordChangeCipherSpec, 3, 3, 0, 1, 1}
	for left := maxTLSProvenanceRecords - remaining - 4; left > 0; {
		n := min(left, 9000)
		other.send(false, TCPFlagACK, bytes.Repeat(ccs, n))
		left -= n
	}
	for _, frame := range other.packets {
		if binary.BigEndian.Uint16(frame[34:]) == 40000 {
			binary.BigEndian.PutUint16(frame[34:], 40001)
		} else {
			binary.BigEndian.PutUint16(frame[36:], 40001)
		}
	}
	return other
}

func TestExtractKeyedHTTP1RecordBudget(t *testing.T) {
	// Earlier traffic leaves seven records in the shared decryption budget:
	// both client handshake records, the request record, both server handshake
	// records, the 204 and a partial 201. A fresh budget could decode "ply".
	other := consumeTLSRecordBudget(t, 7)
	for _, shared := range []bool{false, true} {
		f := newKeyedFixture(t, TLSVersion13)
		f.pipeline()
		if shared {
			frame := slices.Concat(f.packets[7], f.packets[8][54:], f.packets[9][54:])
			binary.BigEndian.PutUint16(frame[16:], uint16(len(frame)-14))
			f.packets[7] = frame
			f.packets = slices.Delete(f.packets, 8, 10)
		}
		raw := keyedCapture(t, f.keys, slices.Concat(other.packets, f.packets))
		c, _ := readWrittenPackets(t, raw)
		rows, err := c.KeyedHTTP1Transactions(raw, nil)
		if err != nil || len(rows) != 2 || rows[1].Response == nil || rows[1].Response.BodyState != HTTPBodyPartial || string(rows[1].Response.Body) != "re" {
			t.Fatalf("shared=%v: original %+v, %v", shared, rows, err)
		}
		if shared {
			var w bytes.Buffer
			err := c.ExtractKeyedHTTP1TransactionPCAPNG(raw, nil, &w, rows[1].ID)
			if !errors.Is(err, ErrReassemblyLimit) || w.Len() != 0 {
				t.Fatalf("inseparable records: %v, wrote %d", err, w.Len())
			}
			err = c.ExtractKeyedHTTP1TransactionPCAPNGFromReaderAt(bytes.NewReader(raw), nil, &w, rows[1].ID)
			if !errors.Is(err, ErrReassemblyLimit) || w.Len() != 0 {
				t.Fatalf("ReaderAt inseparable records: %v, wrote %d", err, w.Len())
			}
			continue
		}
		out := keyedExportBoth(t, raw, nil, rows[1].ID)
		opened, _ := readWrittenPackets(t, out)
		got, err := opened.KeyedHTTP1Transactions(out, f.keys)
		if err != nil || len(got) != 2 || got[1].Response == nil || got[1].Response.BodyState != HTTPBodyPartial || string(got[1].Response.Body) != "re" || !got[1].ServerCoverage.IncompleteTail {
			t.Fatalf("limit disappeared: %+v, %v", got, err)
		}
	}
}

func TestExtractKeyedHTTP1ReadBudget(t *testing.T) {
	f := newKeyedFixture(t, TLSVersion13)
	f.pipeline()
	c, r := transactionExportBudgetCapture(t, f.packets, MaxSnapLen-128)
	w := &incompleteCaptureWrite{}
	err := c.ExtractKeyedHTTP1TransactionPCAPNGFromReaderAt(r, f.keys, w, KeyedHTTP1TransactionID{0, len(f.client), len(keyedFirst)})
	if !errors.Is(err, ErrPacketLimit) || w.writes == 0 || r.bytesRead > MaxReaderAtScanBytes || r.bytesRead < MaxReaderAtScanBytes-32<<10 {
		t.Fatalf("shared budget: %v; reads %d, writes %d", err, r.bytesRead, w.writes)
	}
}

func TestExtractKeyedHTTP1SeparateInterfaces(t *testing.T) {
	f := newKeyedFixture(t, TLSVersion13)
	f.pipeline()
	var raw bytes.Buffer
	w, err := NewPCAPNGWriter(&raw, PCAPNGWriterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.AddInterface(PCAPNGWriterOptions{LinkType: LinkTypeEthernet}); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteDecryptionSecrets(SecretsTypeTLSKeyLog, f.keys); err != nil {
		t.Fatal(err)
	}
	for i, frame := range f.packets {
		for iface := range 2 {
			if err := w.WritePacket(PacketRecord{InterfaceID: uint32(iface), TimestampNs: int64(2*i + iface)}, frame); err != nil {
				t.Fatal(err)
			}
		}
	}
	c, _ := readWrittenPackets(t, raw.Bytes())
	c.SeparateTCPInterfaces = true
	rows, err := c.KeyedHTTP1Transactions(raw.Bytes(), nil)
	if err != nil || len(rows) != 4 || rows[3].ID.OpeningPacket != 1 {
		t.Fatalf("interface openings %+v, %v", rows, err)
	}
	var a, b bytes.Buffer
	if err := c.ExtractKeyedHTTP1TransactionPCAPNG(raw.Bytes(), nil, &a, rows[3].ID); err != nil {
		t.Fatal(err)
	}
	reader := bytes.NewReader(raw.Bytes())
	index, err := NewFromReaderAt(reader, reader.Size())
	if err != nil {
		t.Fatal(err)
	}
	index.SeparateTCPInterfaces = true
	if err := index.ExtractKeyedHTTP1TransactionPCAPNGFromReaderAt(reader, nil, &b, rows[3].ID); err != nil || !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatalf("interface ReaderAt parity: %v", err)
	}
	opened, packets := readWrittenPackets(t, a.Bytes())
	if len(packets) != len(f.packets) || len(opened.Interfaces) != 1 {
		t.Fatalf("selected %d packets, %d interfaces", len(packets), len(opened.Interfaces))
	}
	for i, pkt := range packets {
		if pkt.TimestampNs != int64(2*i+1) || pkt.InterfaceID != 0 {
			t.Fatalf("unexpected interface packet %d: %+v", i, pkt)
		}
	}
}

func TestExtractKeyedHTTP1InseparableLimits(t *testing.T) {
	for _, tc := range []string{"record limit before second response", "TCP limit with snaplen cut"} {
		t.Run(tc, func(t *testing.T) {
			f := newKeyedFixture(t, TLSVersion13)
			f.pipeline()
			var other *keyedFixture
			if tc == "record limit before second response" {
				// The next record, in a single packet, contains a final response
				// whose headers were unavailable at the original scan limit.
				other = consumeTLSRecordBudget(t, 6)
			} else {
				// Reuse the tuple after most of its TCP byte budget was consumed.
				// The final server packet contains enough ciphertext for the
				// entire entity, but also declares one extra (uncaptured) byte.
				keep := len(f.server) + len(f.packets[6]) - 54 + len(f.packets[7]) - 54
				combined := slices.Concat(f.packets[7], f.packets[8][54:], f.packets[9][54:], f.packets[10][54:])
				binary.BigEndian.PutUint16(combined[16:], uint16(len(combined)-14+1))
				f.packets = append(f.packets[:7], combined)
				other = newKeyedFixture(t, TLSVersion13)
				fill := bytes.Repeat([]byte{'x'}, 60000)
				for n := MaxFlowStreamBytes - keep - len(other.server); n > 0; {
					size := min(n, len(fill))
					other.send(true, TCPFlagACK, fill[:size])
					n -= size
				}
				for _, p := range other.packets {
					for _, off := range []int{38, 42} {
						binary.BigEndian.PutUint32(p[off:], binary.BigEndian.Uint32(p[off:])+10000)
					}
				}
			}
			raw := keyedCapture(t, f.keys, slices.Concat(other.packets, f.packets))
			c, _ := readWrittenPackets(t, raw)
			rows, err := c.KeyedHTTP1Transactions(raw, nil)
			if err != nil || len(rows) != 2 || !rows[1].ServerCoverage.IncompleteTail {
				t.Fatalf("source %+v, %v", rows, err)
			}
			if tc == "record limit before second response" {
				if rows[1].Pairing != HTTP1ResponseAmbiguous || rows[1].Response != nil {
					t.Fatalf("ambiguous source %+v", rows[1])
				}
			} else if rows[1].Response == nil || string(rows[1].Response.Body) != "re" || rows[1].Response.BodyState != HTTPBodyPartial {
				t.Fatalf("partial source %+v", rows[1])
			}
			var out bytes.Buffer
			if err := c.ExtractKeyedHTTP1TransactionPCAPNG(raw, nil, &out, rows[1].ID); !errors.Is(err, ErrReassemblyLimit) || out.Len() != 0 {
				t.Fatalf("error %v, wrote %d", err, out.Len())
			}
		})
	}
}

func TestExtractKeyedHTTP1OpeningLocalLimits(t *testing.T) {
	for _, limit := range []string{"TCP bytes", "TLS records"} {
		t.Run(limit, func(t *testing.T) {
			f := newKeyedFixture(t, TLSVersion13)
			if limit == "TCP bytes" {
				f.send(false, TCPFlagACK, f.seal(false, 0, TLSRecordApplicationData, "POST /large HTTP/1.1\r\nContent-Length: 4500000\r\n\r\n"))
				f.send(true, TCPFlagACK, f.seal(true, 0, TLSRecordApplicationData, keyedNoContent))
				body := string(bytes.Repeat([]byte{'x'}, 16000))
				for n := 1; n < 280; n++ {
					f.send(false, TCPFlagACK, f.seal(false, uint64(n), TLSRecordApplicationData, body))
				}
			} else {
				ccs := []byte{TLSRecordChangeCipherSpec, 3, 3, 0, 1, 1}
				for left := maxTLSProvenanceRecords - 6; left > 0; {
					count := min(left, 9000)
					f.send(false, TCPFlagACK, bytes.Repeat(ccs, count))
					left -= count
				}
				f.send(false, TCPFlagACK, f.seal(false, 0, TLSRecordApplicationData, keyedFirst+keyedSecond))
				f.send(true, TCPFlagACK, f.seal(true, 0, TLSRecordApplicationData, keyedNoContent))
				f.send(true, TCPFlagACK, f.seal(true, 1, TLSRecordApplicationData, keyedCreated+"reply"))
			}
			raw := keyedCapture(t, f.keys, f.packets)
			c, _ := readWrittenPackets(t, raw)
			rows, err := c.KeyedHTTP1Transactions(raw, nil)
			if err != nil || len(rows) == 0 {
				t.Fatalf("missing request: %v", err)
			}
			row := rows[len(rows)-1]
			if limit == "TCP bytes" {
				if row.Request.BodyState != HTTPBodyPartial || row.Response == nil || row.Response.StatusCode != 204 {
					t.Fatalf("unexpected TCP-limited row: body=%v, pairing=%v", row.Request.BodyState, row.Pairing)
				}
			} else if row.Pairing != HTTP1ResponseAmbiguous || !row.ServerCoverage.IncompleteTail {
				t.Fatalf("unexpected TLS-limited row %+v", row)
			}
			out := keyedExportBoth(t, raw, nil, row.ID)
			opened, packets := readWrittenPackets(t, out)
			got, err := opened.KeyedHTTP1Transactions(out, f.keys)
			if err != nil || len(got) != len(rows) || len(packets) != len(f.packets) {
				t.Fatalf("reopened %d rows, %d packets: %v", len(got), len(packets), err)
			}
			selected := got[len(got)-1]
			if selected.Pairing != row.Pairing || selected.ClientCoverage != row.ClientCoverage || selected.ServerCoverage != row.ServerCoverage ||
				selected.Request.BodyState != row.Request.BodyState || !bytes.Equal(selected.Request.Body, row.Request.Body) {
				t.Fatal("reopened opening changed coverage")
			}
		})
	}
}
