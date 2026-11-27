package pcap

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"reflect"
	"slices"
	"testing"
)

const (
	tlsProofFirst   = "first "
	tlsProofSecond  = "request"
	tlsProofReverse = "reply"
)

type tlsProofFixture struct {
	client, server, first, control, second, reverse, keys []byte
	clientProtected, serverProtected                      int
	seal                                                  func(server bool, seq uint64, kind uint8, payload string) []byte
}

func makeTLSProofFixture(t *testing.T, version uint16) tlsProofFixture {
	t.Helper()
	if version == TLSVersion13 {
		const suite = TLS_AES_128_GCM_SHA256
		client := buildTLS13ClientHelloRecord("provenance.example", "http/1.1")
		server := buildTLSServerHelloRecord()
		clientProtected, serverProtected := len(client), len(server)
		clientHS, serverHS, clientApp, serverApp := [32]byte{1}, [32]byte{2}, [32]byte{3}, [32]byte{4}
		finished := []byte{20, 0, 0, 0}
		client = append(client, encryptTLS13AppDataRecord(t, clientHS[:], suite, 0, TLSRecordHandshake, finished)...)
		server = append(server, encryptTLS13AppDataRecord(t, serverHS[:], suite, 0, TLSRecordHandshake, finished)...)
		updated, err := tls13ExpandLabelHash(sha256.New, clientApp[:], "traffic upd", nil, len(clientApp))
		if err != nil {
			t.Fatal(err)
		}
		random := client[11:43]
		return tlsProofFixture{
			seal: func(server bool, seq uint64, kind uint8, payload string) []byte {
				secret := clientApp
				if server {
					secret = serverApp
				}
				return encryptTLS13AppDataRecord(t, secret[:], suite, seq, kind, []byte(payload))
			},
			client: client, server: server,
			clientProtected: clientProtected, serverProtected: serverProtected,
			first:   encryptTLS13AppDataRecord(t, clientApp[:], suite, 0, TLSRecordApplicationData, []byte(tlsProofFirst)),
			control: encryptTLS13AppDataRecord(t, clientApp[:], suite, 1, TLSRecordHandshake, []byte{TLSHandshakeKeyUpdate, 0, 0, 1, 0}),
			second:  encryptTLS13AppDataRecord(t, updated, suite, 0, TLSRecordApplicationData, []byte(tlsProofSecond)),
			reverse: encryptTLS13AppDataRecord(t, serverApp[:], suite, 0, TLSRecordApplicationData, []byte(tlsProofReverse)),
			keys: fmt.Appendf(nil, "CLIENT_HANDSHAKE_TRAFFIC_SECRET %x %x\nSERVER_HANDSHAKE_TRAFFIC_SECRET %x %x\nCLIENT_TRAFFIC_SECRET_0 %x %x\nSERVER_TRAFFIC_SECRET_0 %x %x\n",
				random, clientHS, random, serverHS, random, clientApp, random, serverApp),
		}
	}

	const suite = TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	clientRandom, serverRandom, master := [32]byte{5}, [32]byte{6}, [48]byte{7}
	client := wrapTLSHandshakeRecord(TLSHandshakeClientHello, bytes.Join([][]byte{
		{3, 3}, clientRandom[:], {0, 0, 2, 0xc0, 0x2f, 1, 0},
	}, nil))
	server := wrapTLSHandshakeRecord(TLSHandshakeServerHello, bytes.Join([][]byte{
		{3, 3}, serverRandom[:], {0, 0xc0, 0x2f, 0},
	}, nil))
	keyLen, hashFn, _ := tls12CipherSuiteParams(suite)
	seed := append(bytes.Clone(serverRandom[:]), clientRandom[:]...)
	block := tls12PRF(hashFn, master[:], "key expansion", seed, 2*keyLen+8)
	ck, sk := block[:keyLen], block[keyLen:2*keyLen]
	ci, si := block[2*keyLen:2*keyLen+4], block[2*keyLen+4:]
	ccs := []byte{TLSRecordChangeCipherSpec, 3, 3, 0, 1, 1}
	finished := []byte{20, 0, 0, 12, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	return tlsProofFixture{
		seal: func(server bool, seq uint64, kind uint8, payload string) []byte {
			key, salt := ck, ci
			if server {
				key, salt = sk, si
			}
			return encryptTLS12Record(t, kind, key, salt, seq+1, []byte(payload))
		},
		clientProtected: len(client) + len(ccs), serverProtected: len(server) + len(ccs),
		client:  append(append(client, ccs...), encryptTLS12Record(t, TLSRecordHandshake, ck, ci, 0, finished)...),
		server:  append(append(server, ccs...), encryptTLS12Record(t, TLSRecordHandshake, sk, si, 0, finished)...),
		first:   encryptTLS12Record(t, TLSRecordApplicationData, ck, ci, 1, []byte(tlsProofFirst)),
		control: encryptTLS12Record(t, TLSRecordAlert, ck, ci, 2, []byte{1, 100}),
		second:  encryptTLS12Record(t, TLSRecordApplicationData, ck, ci, 3, []byte(tlsProofSecond)),
		reverse: encryptTLS12Record(t, TLSRecordApplicationData, sk, si, 1, []byte(tlsProofReverse)),
		keys:    fmt.Appendf(nil, "CLIENT_RANDOM %x %x\n", clientRandom, master),
	}
}

// The opening packet can come from the TLS server. A retransmission repeats
// packet 4 after both its original bytes and later bytes have been observed.
func (f tlsProofFixture) packets(start uint32, tail string, retransmit, reverseOpening bool) [][]byte {
	client, server := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	seq, ack := start+1, start+1001
	c := func(off uint32, data []byte) []byte {
		return buildEthernetIPv4TCPFrame(client, server, 40000, 443, seq+off, ack, TCPFlagPSH|TCPFlagACK, data)
	}
	s := func(off uint32, data []byte) []byte {
		return buildEthernetIPv4TCPFrame(server, client, 443, 40000, ack+off, seq, TCPFlagPSH|TCPFlagACK, data)
	}
	packets := [][]byte{
		buildEthernetIPv4TCPFrame(client, server, 40000, 443, start, 0, TCPFlagSYN, nil),
		buildEthernetIPv4TCPFrame(server, client, 443, 40000, ack-1, seq, TCPFlagSYN|TCPFlagACK, nil),
		c(0, f.client), s(0, f.server),
	}
	if reverseOpening {
		packets[0], packets[1] = packets[1], packets[0]
	}
	firstLen := uint32(len(f.client))
	second := bytes.Clone(f.second)
	var gap uint32
	switch tail {
	case "truncated":
		second = second[:len(second)-1]
	case "tampered":
		second[len(second)-1] ^= 1
	case "gap":
		gap = 1
		second = append(second[:3], second[4:]...)
	}
	tailStart := firstLen + uint32(len(f.first)+len(f.control))
	packets = append(packets,
		c(firstLen, f.first[:7]),
		c(firstLen+7, bytes.Join([][]byte{f.first[7:], f.control, second[:3]}, nil)),
		c(tailStart+3+gap, second[3:]),
		s(uint32(len(f.server)), f.reverse),
	)
	if tail == "FIN gap" {
		packets[5] = c(firstLen+7, bytes.Join([][]byte{f.first[7:], f.control}, nil))
		packets[6] = buildEthernetIPv4TCPFrame(client, server, 40000, 443, seq+tailStart+uint32(len(second)), ack, TCPFlagFIN|TCPFlagACK, nil)
	}
	if tail == "capture cut" {
		packets[5] = c(firstLen+7, bytes.Join([][]byte{f.first[7:], f.control}, nil))
		packets[6] = c(tailStart, second)
		packets[6] = packets[6][:54] // Keep the TCP header while cutting the payload from the capture.
	}
	if retransmit {
		packets = append(packets, packets[4])
	}
	return packets
}

func tlsProofScan(t *testing.T, raw, keys []byte) []tlsProvenanceStream {
	t.Helper()
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	a, err := scanTLSProvenance(ipFrameSource{capture: c, data: raw}, keys)
	if err != nil {
		t.Fatal(err)
	}
	r := bytes.NewReader(raw)
	index, err := NewFromReaderAt(r, int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	b, err := scanTLSProvenance(index.tcpReaderAt(r), keys)
	if err != nil || !reflect.DeepEqual(a, b) {
		t.Fatalf("ReaderAt = %+v, %v, want %+v", b, err, a)
	}
	return a
}

func TestTLSRecordProvenance(t *testing.T) {
	for _, version := range []uint16{TLSVersion12, TLSVersion13} {
		t.Run(fmt.Sprintf("%04x", version), func(t *testing.T) {
			f := makeTLSProofFixture(t, version)
			firstStart := len(f.client)
			secondStart := firstStart + len(f.first) + len(f.control)
			wantClient := []tlsApplicationRecord{
				{0, len(tlsProofFirst), firstStart, firstStart + len(f.first), []int{4, 5}, false},
				{len(tlsProofFirst), len(tlsProofFirst) + len(tlsProofSecond), secondStart, secondStart + len(f.second), []int{5, 6}, false},
			}
			wantServer := []tlsApplicationRecord{{0, len(tlsProofReverse), len(f.server), len(f.server) + len(f.reverse), []int{7}, false}}
			for _, tc := range []struct {
				name        string
				packets     [][]byte
				keys        []byte
				extra       []byte
				wantRecords int
				stop        tlsStopReason
				stopOffset  int
			}{
				{"complete", f.packets(100, "", false, false), f.keys, nil, 2, tlsStopEnd, secondStart + len(f.second)},
				{"retransmission", f.packets(100, "", true, false), f.keys, nil, 2, tlsStopEnd, secondStart + len(f.second)},
				{"server first, external keys", f.packets(100, "", false, true), nil, f.keys, 2, tlsStopEnd, secondStart + len(f.second)},
				{"truncated", f.packets(100, "truncated", false, false), f.keys, nil, 1, tlsStopTruncated, secondStart},
				{"tampered", f.packets(100, "tampered", false, false), f.keys, nil, 1, tlsStopAuthentication, secondStart},
				{"gap", f.packets(100, "gap", false, false), f.keys, nil, 1, tlsStopGap, secondStart},
				{"FIN gap", f.packets(100, "FIN gap", false, false), f.keys, nil, 1, tlsStopGap, secondStart},
				{"capture cut", f.packets(100, "capture cut", false, false), f.keys, nil, 1, tlsStopTruncated, secondStart},
				{"no keys", f.packets(100, "", false, false), nil, nil, 0, tlsStopMissingKey, f.clientProtected},
			} {
				t.Run(tc.name, func(t *testing.T) {
					rows := tlsProofScan(t, buildPCAPNGFixture(binary.LittleEndian, tc.keys, tc.packets), tc.extra)
					if len(rows) != 1 {
						t.Fatalf("got %d TLS openings, want 1", len(rows))
					}
					row := rows[0]
					stopOffset := tc.stopOffset
					if row.openingPacket != 0 || row.SrcPort != 40000 || row.DstPort != 443 ||
						row.client.stop != (tlsProvenanceBoundary{stopOffset, tc.stop}) || row.client.before.reason != tlsStopEnd {
						t.Fatalf("opening %d, endpoints %d → %d, before %+v, stop %+v", row.openingPacket, row.SrcPort, row.DstPort, row.client.before, row.client.stop)
					}
					if tc.wantRecords == 0 {
						if len(row.client.records)+len(row.server.records)+len(row.Client.Data)+len(row.Server.Data) != 0 ||
							row.server.stop != (tlsProvenanceBoundary{f.serverProtected, tlsStopMissingKey}) {
							t.Fatalf("unexpected decrypted records without keys: %+v", row)
						}
						return
					}
					if !reflect.DeepEqual(row.client.records, wantClient[:tc.wantRecords]) || !reflect.DeepEqual(row.server.records, wantServer) {
						t.Fatalf("client records %+v, server records %+v", row.client.records, row.server.records)
					}
					n := wantClient[tc.wantRecords-1].plainEnd
					if string(row.Client.Data) != (tlsProofFirst + tlsProofSecond)[:n] || string(row.Server.Data) != tlsProofReverse {
						t.Fatalf("client plaintext %q, server plaintext %q", row.Client.Data, row.Server.Data)
					}
				})
			}

			t.Run("tuple reuse", func(t *testing.T) {
				packets := append(f.packets(100, "", true, false), f.packets(10_000, "", false, false)...)
				rows := tlsProofScan(t, buildPCAPNGFixture(binary.LittleEndian, f.keys, packets), nil)
				if len(rows) != 2 || rows[0].FlowIndex != rows[1].FlowIndex || rows[0].openingPacket != 0 || rows[1].openingPacket != 9 {
					t.Fatalf("openings %+v", rows)
				}
				for i, row := range rows {
					if len(row.client.records) != 2 || !slices.Equal(row.client.records[0].packets, []int{4 + 9*i, 5 + 9*i}) ||
						!slices.Equal(row.client.records[1].packets, []int{5 + 9*i, 6 + 9*i}) || row.client.records[0].plainStart != 0 {
						t.Fatalf("opening %d records %+v", row.openingPacket, row.client.records)
					}
				}
			})
		})
	}
}

func TestTLSRecordProvenanceProxy(t *testing.T) {
	f := makeTLSProofFixture(t, TLSVersion13)
	clientProxy := []byte("CONNECT provenance.example:443 HTTP/1.1\r\n\r\n")
	serverProxy := []byte("HTTP/1.1 200 Connection Established\r\n\r\n")
	f.client = append(clientProxy, f.client...)
	f.server = append(serverProxy, f.server...)
	rows := tlsProofScan(t, buildPCAPNGFixture(binary.LittleEndian, f.keys, f.packets(100, "", false, true)), nil)
	if len(rows) != 1 || rows[0].SrcPort != 40000 || len(rows[0].client.records) != 2 || len(rows[0].server.records) != 1 {
		t.Fatalf("got %+v", rows)
	}
	c, s := rows[0].client.records[0], rows[0].server.records[0]
	if c.wireStart != len(f.client) || s.wireStart != len(f.server) || !slices.Equal(c.packets, []int{4, 5}) || !slices.Equal(s.packets, []int{7}) {
		t.Fatalf("client record %+v, server record %+v", c, s)
	}
}

func TestTLSRecordProvenanceSnaplenRecovery(t *testing.T) {
	f := makeTLSProofFixture(t, TLSVersion13)
	for _, tc := range []struct {
		name    string
		missing uint16
		reason  tlsStopReason
		gre     bool
		ipv6    bool
	}{
		{"partial", 100, tlsStopTruncated, false, false},
		{"complete", 0, tlsStopEnd, false, false},
		{"GRE partial", 100, tlsStopTruncated, true, false},
		{"GRE complete", 0, tlsStopEnd, true, false},
		{"IPv6 partial", 100, tlsStopTruncated, false, true},
		{"GRE IPv6 complete", 0, tlsStopEnd, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packets := f.packets(100, "", false, false)
			clipped := bytes.Clone(packets[6][:54])
			const ipv4LengthOffset = 16
			length := binary.BigEndian.Uint16(clipped[ipv4LengthOffset:])
			binary.BigEndian.PutUint16(clipped[ipv4LengthOffset:], length+tc.missing)
			packets = slices.Insert(packets, 6, clipped)
			for i, packet := range packets {
				if tc.ipv6 {
					header := make([]byte, 54)
					copy(header[:12], packet[:12])
					binary.BigEndian.PutUint16(header[12:14], EtherTypeIPv6)
					header[14], header[20], header[21] = 0x60, IPProtoTCP, 64
					binary.BigEndian.PutUint16(header[18:20], binary.BigEndian.Uint16(packet[16:18])-20)
					copy(header[34:38], packet[26:30])
					copy(header[50:54], packet[30:34])
					packet = append(header, packet[34:]...)
				}
				if tc.gre {
					// The outer packet declares extra bytes after the inner IP
					// datagram. Those bytes do not extend the inner TCP stream.
					outer := make([]byte, 38)
					copy(outer[:12], packet[:12])
					binary.BigEndian.PutUint16(outer[12:14], EtherTypeIPv4)
					outer[14], outer[22], outer[23] = 0x45, 64, IPProtoGRE
					binary.BigEndian.PutUint16(outer[16:18], uint16(len(packet)-14+24+100))
					copy(outer[36:38], packet[12:14])
					packet = append(outer, packet[14:]...)
				}
				packets[i] = packet
			}
			rows := tlsProofScan(t, buildPCAPNGFixture(binary.LittleEndian, f.keys, packets), nil)
			end := len(f.client) + len(f.first) + len(f.control) + len(f.second)
			if len(rows) != 1 || rows[0].client.stop != (tlsProvenanceBoundary{end, tc.reason}) ||
				len(rows[0].client.records) != 2 || !slices.Equal(rows[0].client.records[1].packets, []int{5, 7}) {
				t.Fatalf("got %+v", rows)
			}
		})
	}
}

func TestTLSRecordProvenanceWithApplicationKeysOnly(t *testing.T) {
	f := makeTLSProofFixture(t, TLSVersion13)
	_, keys, _ := bytes.Cut(f.keys, []byte("\n"))
	rows := tlsProofScan(t, buildPCAPNGFixture(binary.LittleEndian, keys, f.packets(100, "", false, false)), nil)
	if len(rows) != 1 || rows[0].client.before != (tlsProvenanceBoundary{f.clientProtected, tlsStopMissingKey}) ||
		rows[0].client.stop.reason != tlsStopEnd || string(rows[0].Client.Data) != tlsProofFirst+tlsProofSecond ||
		len(rows[0].client.records) != 2 || rows[0].client.records[0].plainStart != 0 {
		t.Fatalf("got %+v", rows)
	}
}

func TestTLSRecordProvenanceBudget(t *testing.T) {
	f := makeTLSProofFixture(t, TLSVersion13)
	wire := bytes.Join([][]byte{f.client, f.first, f.control, f.second}, nil)
	keyLog, err := ParseTLSKeyLog(f.keys)
	if err != nil {
		t.Fatal(err)
	}
	entry := keyLog.Entries[[32]byte(wire[11:43])]
	firstEnd := len(f.client) + len(f.first)
	secondStart := firstEnd + len(f.control)
	for _, tc := range []struct {
		name         string
		budget       tlsProvenanceBudget
		wantBoundary int
	}{
		{"records including control", tlsProvenanceBudget{records: 3, ranges: 5}, firstEnd},
		{"packet ranges", tlsProvenanceBudget{records: 5, ranges: 2}, secondStart},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mapper := tlsRecordMapper{budget: &tc.budget, spans: []tcpWireSpan{
				{end: uint32(len(f.client) + 7), packet: tcpPacketEvidence{index: 4}},
				{end: uint32(secondStart + 3), packet: tcpPacketEvidence{index: 5}},
				{end: uint32(len(wire)), packet: tcpPacketEvidence{index: 6}},
			}}
			_, app, err := decryptTLS13Records(wire, TLS_AES_128_GCM_SHA256, entry.ClientHandshakeSecret, entry.ClientTrafficSecret0, nil, &mapper, nil, nil)
			if err != nil || string(app) != tlsProofFirst || mapper.stop != (tlsProvenanceBoundary{tc.wantBoundary, tlsStopLimit}) ||
				len(mapper.records) != 1 || !slices.Equal(mapper.records[0].packets, []int{4, 5}) {
				t.Fatalf("plaintext %q, err %v, provenance %+v", app, err, mapper.tlsDirectionProvenance)
			}
		})
	}
}

func TestTLSRecordProvenancePhysicalReadBudget(t *testing.T) {
	const (
		recordBytes   = (64 << 10) - 3
		records       = MaxReaderAtScanBytes / (64 << 10)
		tcpHeaderSize = 14 + 20 + 20
	)
	order := binary.LittleEndian
	tcp := buildEthernetIPv4TCPFrame([4]byte{1}, [4]byte{2}, 1234, 443, 1, 0, TCPFlagACK, make([]byte, recordBytes-pcapPacketHeaderSize-tcpHeaderSize))
	binary.BigEndian.PutUint16(tcp[16:18], 65535)
	raw := buildClassicPCAP(order, false, LinkTypeEthernet, 65535, [][]byte{tcp})
	recordHeader := raw[pcapGlobalHeaderSize : pcapGlobalHeaderSize+pcapPacketHeaderSize+tcpHeaderSize]

	// The scan skips the UDP tails and reads every shortened TCP record,
	// including a second read of the two-byte IP length.
	udp := buildEthernetIPv4UDPFrame([4]byte{3}, [4]byte{4}, 1234, 4321, make([]byte, 442))
	prefix := buildClassicPCAP(order, false, LinkTypeEthernet, 65535, [][]byte{udp, udp, udp})
	file := tempCaptureFile(t, prefix)
	for i := range records {
		if _, err := file.WriteAt(recordHeader, int64(len(prefix)+i*recordBytes)); err != nil {
			t.Fatal(err)
		}
	}
	size := int64(len(prefix) + records*recordBytes)
	if err := file.Truncate(size); err != nil {
		t.Fatal(err)
	}
	reader := &measuredFile{File: file}
	c, err := NewFromReaderAt(reader, size)
	if err != nil {
		t.Fatal(err)
	}
	reader.bytesRead = 0
	rows, err := scanTLSProvenance(c.tcpReaderAt(reader), nil)
	if err != nil || len(rows) != 0 || reader.bytesRead > MaxReaderAtScanBytes {
		t.Fatalf("got %d TLS rows, err %v, read %d bytes with a limit of %d", len(rows), err, reader.bytesRead, MaxReaderAtScanBytes)
	}
}

func TestTLSRecordProvenanceEarlyData(t *testing.T) {
	raw, err := os.ReadFile("testdata/rfc8448-0rtt.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	rows := tlsProofScan(t, raw, nil)
	wantC := []tlsApplicationRecord{{0, 6, 517, 545, []int{1}, true}, {6, 56, 629, 701, []int{6}, false}}
	wantS := []tlsApplicationRecord{{0, 50, 203, 275, []int{7}, false}}
	if len(rows) != 1 || !reflect.DeepEqual(rows[0].client.records, wantC) || !reflect.DeepEqual(rows[0].server.records, wantS) {
		t.Fatalf("early-data provenance %+v", rows)
	}
	want := make([]byte, 50)
	for i := range want {
		want[i] = byte(i)
	}
	if !bytes.Equal(rows[0].Client.Data, append([]byte("ABCDEF"), want...)) || !bytes.Equal(rows[0].Server.Data, want) {
		t.Fatalf("client plaintext %x, server plaintext %x", rows[0].Client.Data, rows[0].Server.Data)
	}
}
