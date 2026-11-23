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
	keys, err := deriveQUICInitialKeys(dcid, version, true)
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
