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
