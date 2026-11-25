package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

func appendQUICVarint2(buf *bytes.Buffer, v uint16) {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], 0x4000|(v&0x3fff))
	buf.Write(b[:])
}

func buildEncryptedQUICInitialDatagram(
	t testing.TB,
	version uint32,
	dcid, scid, token []byte,
	packetNumber uint16,
	cryptoOffset uint16,
	cryptoChunk []byte,
) []byte {
	t.Helper()
	return buildQUICInitialWithKeys(t, version, dcid, scid, token, packetNumber, cryptoOffset, cryptoChunk, dcid, true)
}

func buildQUICInitialWithKeys(t testing.TB, version uint32, dcid, scid, token []byte, packetNumber, cryptoOffset uint16, cryptoChunk, keyID []byte, client bool) []byte {
	t.Helper()
	keys, err := deriveQUICInitialKeys(keyID, version, client)
	if err != nil {
		t.Fatalf("deriveQUICInitialKeys: %v", err)
	}

	var plain bytes.Buffer
	plain.WriteByte(0x06)
	appendQUICVarint2(&plain, cryptoOffset)
	appendQUICVarint2(&plain, uint16(len(cryptoChunk)))
	plain.Write(cryptoChunk)
	for plain.Len() < 24 {
		plain.WriteByte(0x00)
	}

	firstByte := uint8(0xc1)
	if version == QUICVersion2 {
		firstByte = 0xd1
	}

	var hdr bytes.Buffer
	hdr.WriteByte(firstByte)
	var verBytes [4]byte
	binary.BigEndian.PutUint32(verBytes[:], version)
	hdr.Write(verBytes[:])
	hdr.WriteByte(byte(len(dcid)))
	hdr.Write(dcid)
	hdr.WriteByte(byte(len(scid)))
	hdr.Write(scid)
	appendQUICVarint2(&hdr, uint16(len(token)))
	hdr.Write(token)

	remLen := uint16(2 + plain.Len() + 16)
	appendQUICVarint2(&hdr, remLen)
	pnOffset := hdr.Len()

	var pnBytes [2]byte
	binary.BigEndian.PutUint16(pnBytes[:], packetNumber)
	hdr.Write(pnBytes[:])

	aad := bytes.Clone(hdr.Bytes())
	nonce := keys.iv
	nonce[10] ^= pnBytes[0]
	nonce[11] ^= pnBytes[1]

	ciphertext := keys.aead.Seal(nil, nonce[:], plain.Bytes(), aad)
	packet := append(aad, ciphertext...)

	sampleOffset := pnOffset + 4
	var mask [16]byte
	keys.hp.Encrypt(mask[:], packet[sampleOffset:sampleOffset+16])
	packet[0] ^= mask[0] & 0x0f
	packet[pnOffset] ^= mask[1]
	packet[pnOffset+1] ^= mask[2]
	return packet
}

func TestQUICInitialDecryptionMultiPacketAndJA4(t *testing.T) {
	tlsRecord := buildTLS13ClientHelloRecord("quic.c2.example.com", "h3")
	hsMsg := tlsRecord[5:]

	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	scid := []byte{0x11, 0x22, 0x33, 0x44}

	for _, version := range []uint32{QUICVersion1, QUICVersion2} {
		mid := len(hsMsg) / 2
		dgram2 := buildEncryptedQUICInitialDatagram(t, version, dcid, scid, nil, 2, uint16(mid), hsMsg[mid:])
		dgram1 := buildEncryptedQUICInitialDatagram(t, version, dcid, scid, nil, 1, 0, hsMsg[:mid])

		hs, err := DecryptQUICInitial([][]byte{dgram2, dgram1})
		if err != nil {
			t.Fatalf("DecryptQUICInitial(v=%#x) error = %v", version, err)
		}
		if !hs.HasClientHello || hs.ClientHello.SNI != "quic.c2.example.com" {
			t.Fatalf("QUICHandshake = %+v", hs)
		}
		if !strings.HasPrefix(hs.ClientHello.JA4, "q13d0205h3_") {
			t.Fatalf("QUIC JA4 = %q, want prefix \"q13d0205h3_\"", hs.ClientHello.JA4)
		}

		u1 := buildEthernetIPv4UDPFrame([4]byte{10, 0, 0, 20}, [4]byte{198, 51, 100, 99}, 55443, 443, dgram2)
		u2 := buildEthernetIPv4UDPFrame([4]byte{10, 0, 0, 20}, [4]byte{198, 51, 100, 99}, 55443, 443, dgram1)
		rawPCAP := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{u1, u2})
		cap, err := New(rawPCAP)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		checkReaderParity(t, rawPCAP, cap.QUIC, cap.QUICFromReaderAt)
		qRecords, err := cap.QUIC(rawPCAP)
		if err != nil || len(qRecords) != 1 {
			t.Fatalf("cap.QUIC() = (%d, %v), want 1", len(qRecords), err)
		}
		if ok, err := cap.HasQUICJA4(rawPCAP, hs.ClientHello.JA4); err != nil || !ok {
			t.Fatalf("HasQUICJA4() = (%v, %v), want (true, nil)", ok, err)
		}
		if ok, err := cap.HasQUICSNI(rawPCAP, "QUIC.C2.EXAMPLE.COM"); err != nil || !ok {
			t.Fatalf("HasQUICSNI() = (%v, %v), want (true, nil)", ok, err)
		}
	}
}

func TestQUICBoundsAndMalformedPackets(t *testing.T) {
	if _, _, ok := ReadQUICVarint(nil); ok {
		t.Fatal("ReadQUICVarint(nil) = true, want false")
	}
	if _, _, ok := ReadQUICVarint([]byte{0x40}); ok {
		t.Fatal("ReadQUICVarint(truncated 2B) = true, want false")
	}
	if _, err := ParseQUICInitialPacket([]byte{1, 2, 3}); !errors.Is(err, ErrInvalidQUIC) {
		t.Fatalf("ParseQUICInitialPacket(short) err = %v, want ErrInvalidQUIC", err)
	}
	if _, err := ParseQUICInitialPacket([]byte{0x40, 0, 0, 0, 1, 0, 0}); !errors.Is(err, ErrInvalidQUIC) {
		t.Fatalf("ParseQUICInitialPacket(short header) err = %v, want ErrInvalidQUIC", err)
	}
	if _, err := ParseQUICInitialPacket([]byte{0xc0, 0xde, 0xad, 0xbe, 0xef, 0, 0}); !errors.Is(err, ErrInvalidQUIC) {
		t.Fatalf("ParseQUICInitialPacket(bad version) err = %v, want ErrInvalidQUIC", err)
	}
	tooMany := make([][]byte, MaxQUICPacketsPerFlow+1)
	if _, err := DecryptQUICInitial(tooMany); !errors.Is(err, ErrQUICLimit) {
		t.Fatalf("DecryptQUICInitial(tooMany) err = %v, want ErrQUICLimit", err)
	}
}

func TestDecryptQUICInitialDatagramLimit(t *testing.T) {
	const maxPayload = 65_527
	const name = "datagram-limit.example"
	hello := buildTLS13ClientHelloRecord(name, "h3")
	initial := buildEncryptedQUICInitialDatagram(t, QUICVersion1, []byte{1, 2, 3, 4}, nil, nil, 1, 0, hello[5:])
	payload := make([]byte, maxPayload+1)
	maxDatagrams := make([][]byte, MaxQUICPacketsPerFlow)
	for i := range maxDatagrams {
		maxDatagrams[i] = payload[:maxPayload]
	}

	for _, tc := range []struct {
		name      string
		datagrams [][]byte
		wantErr   error
	}{
		{name: "empty input", wantErr: ErrInvalidQUIC},
		{name: "nil payload", datagrams: [][]byte{nil}, wantErr: ErrInvalidQUIC},
		{name: "below byte limit", datagrams: [][]byte{payload[:maxPayload-1], initial}},
		{name: "at byte limit", datagrams: [][]byte{nil, payload[:maxPayload], initial}},
		{name: "over byte limit", datagrams: [][]byte{initial, payload}, wantErr: ErrQUICLimit},
		{name: "at both limits", datagrams: maxDatagrams, wantErr: ErrInvalidQUIC},
		{name: "over both limits", datagrams: append(maxDatagrams, payload), wantErr: ErrQUICLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hs, err := DecryptQUICInitial(tc.datagrams)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("DecryptQUICInitial error = %v, want %v", err, tc.wantErr)
			}
			if err == nil && (!hs.HasClientHello || hs.ClientHello.SNI != name) {
				t.Fatalf("DecryptQUICInitial handshake = %+v, want ClientHello for %s", hs, name)
			}
			if err != nil && hs.HasClientHello {
				t.Fatalf("DecryptQUICInitial returned a ClientHello with error %v", err)
			}
		})
	}
}

func TestQUICAckFrameBounds(t *testing.T) {
	ack := []byte{
		0x02,       // ACK
		0x40, 0x07, // Largest Acknowledged
		0x01,       // ACK Delay
		0x40, 0x01, // ACK Range Count
		0x01,       // First ACK Range
		0x00,       // Gap
		0x40, 0x01, // ACK Range Length
	}
	ackECN := append(bytes.Clone(ack), 0x01, 0x40, 0x01, 0x01)
	ackECN[0] = 0x03
	ackWithRanges := func(count uint16) []byte {
		frame := bytes.NewBuffer([]byte{0x02, 0x44, 0x00, 0x00}) // Largest Acknowledged is 1024.
		appendQUICVarint2(frame, count)
		frame.Write(make([]byte, 1+2*int(count))) // First ACK Range and zero-valued range pairs.
		return frame.Bytes()
	}
	crypto := []byte{0x06, 0x05, 0x01, 'x'} // One CRYPTO byte at offset 5.
	for _, tc := range []struct {
		name  string
		frame []byte
	}{
		{"ACK", ack},
		{"ACK_ECN", ackECN},
		{"256 ranges", ackWithRanges(256)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var chunks []quicCryptoChunk
			err := extractQUICCryptoFrames(append(bytes.Clone(tc.frame), crypto...), &chunks)
			if err != nil || len(chunks) != 1 || chunks[0].offset != 5 || !bytes.Equal(chunks[0].data, crypto[3:]) {
				t.Fatalf("extract after ACK: chunks = %+v, err = %v", chunks, err)
			}
			for end := 1; end < len(tc.frame); end++ {
				chunks = nil
				if err := extractQUICCryptoFrames(tc.frame[:end], &chunks); !errors.Is(err, ErrInvalidQUIC) {
					t.Fatalf("extract at byte %d: err = %v, want ErrInvalidQUIC", end, err)
				}
			}
		})
	}

	var chunks []quicCryptoChunk
	if err := extractQUICCryptoFrames(append(ackWithRanges(257), crypto...), &chunks); !errors.Is(err, ErrInvalidQUIC) {
		t.Fatalf("extract with 257 ACK ranges: err = %v, want ErrInvalidQUIC", err)
	}
}

func TestQUICInitialHeaderOwnership(t *testing.T) {
	dcid, scid := []byte{1, 2, 3, 4}, []byte{5, 6, 7, 8}
	token := bytes.Repeat([]byte{9}, MaxQUICTokenBytes)
	hello := buildTLS13ClientHelloRecord("ownership.example", "h3")
	wire := buildEncryptedQUICInitialDatagram(t, QUICVersion2, dcid, scid, token, 1, 0, hello[5:])
	original := bytes.Clone(wire)
	h, err := ParseQUICInitialPacket(wire)
	if err != nil {
		t.Fatal(err)
	}
	hs, err := DecryptQUICInitial([][]byte{wire})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, wire) {
		t.Fatal("parsing modified the input datagram")
	}
	clear(wire)
	for _, fields := range [][]byte{h.DCID, hs.DCID} {
		if !bytes.Equal(fields, dcid) {
			t.Fatal("DCID differs after input mutation")
		}
	}
	for _, fields := range [][]byte{h.SCID, hs.SCID} {
		if !bytes.Equal(fields, scid) {
			t.Fatal("SCID differs after input mutation")
		}
	}
	for _, fields := range [][]byte{h.Token, hs.Token} {
		if !bytes.Equal(fields, token) {
			t.Fatal("token differs after input mutation")
		}
	}
}

func TestQUICRetryDCIDAndServerFirstOrdering(t *testing.T) {
	hello := buildTLS13ClientHelloRecord("retry-quic.example", "h3")
	oldDCID := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	retryDCID := []byte{9, 10, 11, 12, 13, 14, 15, 16}
	scid := []byte{0xaa, 0xbb, 0xcc, 0xdd}

	// 1. Retry-updated DCID: first packet uses oldDCID (undecryptable/unanswered), second uses retryDCID.
	pkt1 := make([]byte, 1200)
	pkt1[0] = 0xc0
	binary.BigEndian.PutUint32(pkt1[1:5], QUICVersion1)
	pkt1[5] = byte(len(oldDCID))
	copy(pkt1[6:], oldDCID)
	pkt2 := buildEncryptedQUICInitialDatagram(t, QUICVersion1, retryDCID, scid, []byte("retry"), 2, 0, hello[5:])
	hs, err := DecryptQUICInitial([][]byte{pkt1, pkt2})
	if err != nil {
		t.Fatalf("DecryptQUICInitial(Retry DCID) error = %v", err)
	}
	if !bytes.Equal(hs.DCID, retryDCID) || hs.ClientHello.SNI != "retry-quic.example" {
		t.Fatalf("DecryptQUICInitial(Retry DCID) = (%x, %q)", hs.DCID, hs.ClientHello.SNI)
	}

	// 2. Server-first UDP packet ordering in Capture.QUIC.
	srvInitial := make([]byte, 1200)
	srvInitial[0] = 0xc0
	binary.BigEndian.PutUint32(srvInitial[1:5], QUICVersion1)
	srvInitial[5] = byte(len(retryDCID))
	copy(srvInitial[6:], retryDCID)
	fSrv := buildEthernetIPv4UDPFrame([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1}, 443, 55555, srvInitial)
	fCli := buildEthernetIPv4UDPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 55555, 443, pkt2)
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{fSrv, fCli})
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	recs, err := c.QUIC(raw)
	if err != nil || len(recs) != 1 || recs[0].Handshake.ClientHello.SNI != "retry-quic.example" {
		t.Fatalf("Capture.QUIC(server-first) = (%+v, %v)", recs, err)
	}
}

func quicTestRecords(t *testing.T, frames ...[]byte) []QUICRecord {
	t.Helper()
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	checkReaderParity(t, raw, c.QUIC, c.QUICFromReaderAt)
	records, err := c.QUIC(raw)
	if err != nil {
		t.Fatal(err)
	}
	return records
}

func quicControlPacket(first byte, version uint32, dcid, scid, tail []byte) []byte {
	p := binary.BigEndian.AppendUint32([]byte{first}, version)
	p = append(p, byte(len(dcid)))
	p = append(p, dcid...)
	p = append(p, byte(len(scid)))
	p = append(p, scid...)
	return append(p, tail...)
}

func TestQUICRebindingAndObservations(t *testing.T) {
	client, server := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	fromClient := func(port uint16, payload []byte) []byte {
		return buildEthernetIPv4UDPFrame(client, server, port, 443, payload)
	}
	fromServer := func(port uint16, payload []byte) []byte {
		return buildEthernetIPv4UDPFrame(server, client, 443, port, payload)
	}
	hello := buildTLS13ClientHelloRecord("rebound.example", "h3")[5:]
	dcid, scid, retryID := []byte("original"), []byte("client"), []byte("retry")
	for _, v := range []uint32{QUICVersion1, QUICVersion2} {
		first := byte(0xf0)
		if v == QUICVersion2 {
			first = 0xc0
		}
		half := len(hello) / 2
		start := fromClient(10001, buildEncryptedQUICInitialDatagram(t, v, dcid, scid, nil, 1, 0, hello[:half]))
		vn := quicControlPacket(0x81, 0, scid, dcid, []byte{0, 0, 0, 42})
		retry := quicControlPacket(first, v, scid, retryID, make([]byte, 17))
		for _, useRetry := range []bool{false, true} {
			frames := [][]byte{start, fromServer(10002, vn)}
			activeID := dcid
			if useRetry {
				frames = append(frames, fromServer(10002, retry))
				activeID = retryID
			}
			last := buildEncryptedQUICInitialDatagram(t, v, activeID, scid, nil, 2, uint16(half), hello[half:])
			records := quicTestRecords(t, append(frames, fromClient(10003, last))...)
			if len(records) != 1 {
				t.Fatalf("v=%x retry=%v got %d records", v, useRetry, len(records))
			}
			r := records[0]
			if r.FlowIndex != 0 || r.SrcPort != 10001 || !r.Handshake.HasVersionNegotiation || r.Handshake.HasRetry != useRetry || r.Handshake.ClientHello.SNI != "rebound.example" || !bytes.Equal(r.Handshake.DCID, activeID) {
				t.Fatalf("rebound record = %+v", r)
			}
		}
		complete := fromClient(10001, buildEncryptedQUICInitialDatagram(t, v, dcid, scid, nil, 1, 0, hello))
		serverInitial := buildQUICInitialWithKeys(t, v, scid, []byte("server"), nil, 1, 0, buildTLSServerHelloRecord()[5:], dcid, false)
		rebound := quicTestRecords(t, complete, fromServer(10004, serverInitial))
		if len(rebound) != 1 || !rebound[0].Handshake.HasServerHello {
			t.Fatalf("server Initial after rebinding: %+v", rebound)
		}
		records := quicTestRecords(t, complete, fromServer(10001, retry[:len(retry)-1]), fromClient(10001, retry), fromServer(10001, vn[:len(vn)-1]), fromServer(10001, quicControlPacket(0x80, 0, scid, retryID, []byte{0, 0, 0, 42})))
		if len(records) != 1 || records[0].Handshake.HasRetry || records[0].Handshake.HasVersionNegotiation {
			t.Fatalf("unexpected observation: %+v", records)
		}
		frames := make([][]byte, MaxQUICPacketsPerFlow)
		for i := range frames {
			frames[i] = complete
		}
		records = quicTestRecords(t, append(frames, fromServer(10002, retry))...)
		if len(records) != 1 || records[0].Handshake.HasRetry {
			t.Fatalf("packet limit: %+v", records)
		}
	}
}

func TestQUICRebindingDistinctAndAmbiguousIDs(t *testing.T) {
	client, server := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	hello := buildTLS13ClientHelloRecord("distinct.example", "h3")[5:]
	var frames [][]byte
	add := func(port uint16, dcid, scid string) {
		wire := buildEncryptedQUICInitialDatagram(t, QUICVersion1, []byte(dcid), []byte(scid), nil, 1, 0, hello)
		frames = append(frames, buildEthernetIPv4UDPFrame(client, server, port, 443, wire))
	}
	add(10001, "one", "shared")
	add(10002, "two", "shared")
	// Either flow could have received this Retry on a new port.
	retry := quicControlPacket(0xf0, QUICVersion1, []byte("shared"), []byte("new"), make([]byte, 17))
	frames = append(frames, buildEthernetIPv4UDPFrame(server, client, 443, 10003, retry))
	add(10004, "one", "different")
	add(10005, "one", "shared") // The forward DCID now has two owners.
	add(10006, "", "empty")
	add(10007, "", "empty")
	// These IDs have the same zero-padded bytes but different wire lengths.
	add(10008, "id", "source")
	add(10009, "id\x00", "source")
	records := quicTestRecords(t, frames...)
	if len(records) != 8 {
		t.Fatalf("got %d records, want 8", len(records))
	}
	for _, r := range records {
		if r.Handshake.HasRetry {
			t.Fatalf("ambiguous Retry attached to %+v", r)
		}
	}
}

func TestQUICRebindOntoOccupiedTuple(t *testing.T) {
	client, server := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	var frames [][]byte
	add := func(port uint16, dcid, scid string, off int, fragment []byte) {
		payload := buildEncryptedQUICInitialDatagram(t, QUICVersion1, []byte(dcid), []byte(scid), nil, uint16(off+1), uint16(off), fragment)
		frames = append(frames, buildEthernetIPv4UDPFrame(client, server, port, 443, payload))
	}
	a := buildTLS13ClientHelloRecord("original.example", "h3")[5:]
	b := buildTLS13ClientHelloRecord("rebound.example", "h3")[5:]
	add(10001, "dest-a", "src-a", 0, a[:40])
	add(10002, "dest-b", "src-b", 0, b[:40])
	add(10001, "dest-b", "src-b", 40, b[40:])
	add(10001, "dest-a", "src-a", 40, a[40:])
	serverInitial := buildQUICInitialWithKeys(t, QUICVersion1, []byte("src-b"), []byte("server"), nil, 1, 0, buildTLSServerHelloRecord()[5:], []byte("dest-b"), false)
	frames = append(frames, buildEthernetIPv4UDPFrame(server, client, 443, 10001, serverInitial))
	records := quicTestRecords(t, frames...)
	if len(records) != 2 || records[0].Handshake.ClientHello.SNI != "original.example" || records[0].Handshake.HasServerHello ||
		records[1].SrcPort != 10002 || records[1].Handshake.ClientHello.SNI != "rebound.example" || !records[1].Handshake.HasServerHello {
		t.Fatalf("occupied tuple: %+v", records)
	}
}

func TestQUICRebindToEarlierUDPFlow(t *testing.T) {
	client, server := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	dcid := []byte("original")
	hello := buildTLS13ClientHelloRecord("earlier.example", "h3")[5:]
	half := len(hello) / 2
	start := buildEncryptedQUICInitialDatagram(t, QUICVersion1, dcid, nil, nil, 1, 0, hello[:half])
	end := buildEncryptedQUICInitialDatagram(t, QUICVersion1, dcid, nil, nil, 2, uint16(half), hello[half:])
	reply := buildQUICInitialWithKeys(t, QUICVersion1, nil, []byte("server"), nil, 1, 0, buildTLSServerHelloRecord()[5:], dcid, false)

	// Tuple 0 predates the first QUIC exchange, which starts on tuple 1.
	// Its empty SCID forces the server reply to use the remembered alias.
	records := quicTestRecords(t,
		buildEthernetIPv4UDPFrame(client, server, 10000, 443, []byte{1}),
		buildEthernetIPv4UDPFrame(client, server, 10001, 443, start),
		buildEthernetIPv4UDPFrame(client, server, 10000, 443, end),
		buildEthernetIPv4UDPFrame(server, client, 443, 10000, reply),
	)
	if len(records) != 1 || records[0].FlowIndex != 1 || records[0].SrcPort != 10001 ||
		records[0].Handshake.ClientHello.SNI != "earlier.example" || !records[0].Handshake.HasServerHello {
		t.Fatalf("rebound exchange: %+v", records)
	}
}

func TestQUICDistinctInitialExchangesOnOneTuple(t *testing.T) {
	client, server := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	frame := func(wire []byte) []byte {
		return buildEthernetIPv4UDPFrame(client, server, 55555, 443, wire)
	}
	for _, tc := range []struct {
		name       string
		dcid, scid string
		v          uint32
	}{
		{"distinct IDs", "dest-b", "src-b", QUICVersion1},
		{"shared DCID", "dest-a", "src-b", QUICVersion1},
		{"shared SCID", "dest-b", "src-a", QUICVersion1},
		{"different version", "dest-a", "src-a", QUICVersion2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := buildTLS13ClientHelloRecord("first.example", "h3")[5:]
			b := buildTLS13ClientHelloRecord("later.example", "h3")[5:]
			a1 := buildEncryptedQUICInitialDatagram(t, QUICVersion1, []byte("dest-a"), []byte("src-a"), nil, 1, 0, a[:40])
			a2 := buildEncryptedQUICInitialDatagram(t, QUICVersion1, []byte("dest-a"), []byte("src-a"), nil, 2, 40, a[40:])
			b1 := buildEncryptedQUICInitialDatagram(t, tc.v, []byte(tc.dcid), []byte(tc.scid), nil, 1, 0, b)
			// A mixed datagram must not use a second exchange's CRYPTO bytes.
			mixed := append(bytes.Clone(a1), b1...)
			for _, frames := range [][][]byte{{frame(mixed), frame(b1), frame(a2)}, {frame(a1), frame(a2), frame(b1)}} {
				records := quicTestRecords(t, frames...)
				if len(records) != 2 {
					t.Fatalf("got %d records, want 2", len(records))
				}
				for i, want := range []struct {
					name, dcid, scid string
					v                uint32
				}{{"first.example", "dest-a", "src-a", QUICVersion1}, {"later.example", tc.dcid, tc.scid, tc.v}} {
					r := records[i]
					if r.FlowIndex != 0 || r.SrcPort != 55555 || r.DstPort != 443 || r.Handshake.ClientHello.SNI != want.name ||
						string(r.Handshake.DCID) != want.dcid || string(r.Handshake.SCID) != want.scid || r.Handshake.Version != want.v {
						t.Fatalf("record %d = %+v", i, r)
					}
				}
			}
		})
	}
}

func TestQUICOverlappingRetryAndPacketLimits(t *testing.T) {
	client, server := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	frame := func(wire []byte) []byte {
		return buildEthernetIPv4UDPFrame(client, server, 55555, 443, wire)
	}
	dcid, scid, retryID := []byte("initial"), []byte("source"), []byte("retry")
	hello := buildTLS13ClientHelloRecord("retried.example", "h3")[5:]
	a := buildEncryptedQUICInitialDatagram(t, QUICVersion1, dcid, scid, nil, 1, 0, hello[:40])
	b := buildEncryptedQUICInitialDatagram(t, QUICVersion1, []byte("other"), []byte("other-src"), nil, 1, 0, buildTLS13ClientHelloRecord("other.example", "h3")[5:])
	retry := quicControlPacket(0xf0, QUICVersion1, scid, retryID, make([]byte, 17))
	last := buildEncryptedQUICInitialDatagram(t, QUICVersion1, retryID, scid, []byte{0}, 2, 40, hello[40:])
	frames := [][]byte{frame(a)}
	for range MaxQUICPacketsPerFlow {
		frames = append(frames, frame(b))
	}
	frames = append(frames, buildEthernetIPv4UDPFrame(server, client, 443, 55555, retry), frame(last), frame(a))
	records := quicTestRecords(t, frames...)
	if len(records) != 2 || !records[0].Handshake.HasRetry || !bytes.Equal(records[0].Handshake.DCID, retryID) ||
		records[0].Handshake.ClientHello.SNI != "retried.example" || records[1].Handshake.HasRetry || records[1].Handshake.ClientHello.SNI != "other.example" {
		t.Fatalf("overlapping Retry = %+v", records)
	}

	// The cap independently blocks a continuation of the saturated exchange.
	frames = frames[:0]
	for range MaxQUICPacketsPerFlow {
		frames = append(frames, frame(a))
	}
	frames = append(frames, frame(b), frame(buildEncryptedQUICInitialDatagram(t, QUICVersion1, dcid, scid, nil, 3, 40, hello[40:])))
	records = quicTestRecords(t, frames...)
	if len(records) != 1 || records[0].Handshake.ClientHello.SNI != "other.example" {
		t.Fatalf("overlapping cap = %+v", records)
	}
}

func TestQUICServerFirstWithOverlappingExchange(t *testing.T) {
	client, server := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	ch := func(dcid, scid, sni string) []byte {
		wire := buildEncryptedQUICInitialDatagram(t, QUICVersion1, []byte(dcid), []byte(scid), nil, 1, 0, buildTLS13ClientHelloRecord(sni, "h3")[5:])
		return buildEthernetIPv4UDPFrame(client, server, 55555, 443, wire)
	}
	sh := buildQUICInitialWithKeys(t, QUICVersion1, []byte("client-first"), []byte("server-id"), nil, 1, 0,
		buildTLSServerHelloRecord()[5:], []byte("first"), false)
	records := quicTestRecords(t, buildEthernetIPv4UDPFrame(server, client, 443, 55555, sh),
		ch("other", "client-other", "other.example"), ch("first", "client-first", "server-first.example"))
	if len(records) != 2 || records[0].FlowIndex != 0 || records[0].SrcPort != 55555 || records[0].DstPort != 443 ||
		!records[0].Handshake.HasServerHello || records[0].Handshake.ClientHello.SNI != "server-first.example" ||
		records[1].Handshake.HasServerHello || records[1].Handshake.ClientHello.SNI != "other.example" {
		t.Fatalf("server-first records = %+v", records)
	}
}

func TestQUICServerConnectionIDChange(t *testing.T) {
	client, server := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	dcid, scid, serverID := []byte("initial"), []byte("source"), []byte("server")
	hello := buildTLS13ClientHelloRecord("original.example", "h3")[5:]
	start := buildEncryptedQUICInitialDatagram(t, QUICVersion1, dcid, scid, nil, 1, 0, hello[:40])
	reply := buildQUICInitialWithKeys(t, QUICVersion1, scid, serverID, nil, 1, 0, buildTLSServerHelloRecord()[5:], dcid, false)
	end := buildQUICInitialWithKeys(t, QUICVersion1, serverID, scid, nil, 2, 40, hello[40:], dcid, true)
	independent := buildEncryptedQUICInitialDatagram(t, QUICVersion1, serverID, scid, nil, 1, 0, buildTLS13ClientHelloRecord("independent.example", "h3")[5:])
	frames := [][]byte{
		buildEthernetIPv4UDPFrame(client, server, 55555, 443, start),
		buildEthernetIPv4UDPFrame(server, client, 443, 55555, reply),
		buildEthernetIPv4UDPFrame(client, server, 55555, 443, end),
	}
	other := buildEthernetIPv4UDPFrame(client, server, 55555, 443, independent)
	for _, saturated := range []bool{false, true} {
		if saturated {
			for len(frames) < MaxQUICPacketsPerFlow {
				frames = append(frames, frames[0])
			}
		}
		records := quicTestRecords(t, append(frames, other)...)
		if len(records) != 2 || !records[0].Handshake.HasServerHello || !bytes.Equal(records[0].Handshake.DCID, dcid) ||
			records[0].Handshake.ClientHello.SNI != "original.example" || records[1].Handshake.HasServerHello ||
			!bytes.Equal(records[1].Handshake.DCID, serverID) || records[1].Handshake.ClientHello.SNI != "independent.example" {
			t.Fatalf("server connection ID change (saturated = %t) = %+v", saturated, records)
		}
	}
}

func TestQUICExchangeLimitOnOneTuple(t *testing.T) {
	client, server := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	wire := buildEncryptedQUICInitialDatagram(t, QUICVersion1, []byte{1, 2, 3, 4}, []byte("source"), nil, 1, 0,
		buildTLS13ClientHelloRecord("exchange.example", "h3")[5:])
	frames := make([][]byte, 0, MaxQUICFlowsPerScan+1)
	for i := range MaxQUICFlowsPerScan + 1 {
		// Only the headers are needed to hit the limit. Each wire DCID
		// differs, and the scan reaches the limit before decryption.
		binary.BigEndian.PutUint32(wire[6:10], uint32(i))
		frames = append(frames, buildEthernetIPv4UDPFrame(client, server, 55555, 443, wire))
	}
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
	r := bytes.NewReader(raw)
	c, err := NewFromReaderAt(r, int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if records, err := c.QUIC(raw); records != nil || !errors.Is(err, ErrQUICLimit) {
		t.Fatalf("slice has %d records and error %v", len(records), err)
	}
	if records, err := c.QUICFromReaderAt(r); records != nil || !errors.Is(err, ErrQUICLimit) {
		t.Fatalf("ReaderAt has %d records and error %v", len(records), err)
	}
}
