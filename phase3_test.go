package pcap

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func appendQUICVarint2(buf *bytes.Buffer, v uint16) {
	// 2-byte QUIC varint (prefix 0b01, 14-bit value up to 16383).
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], 0x4000|(v&0x3fff))
	buf.Write(b[:])
}

func buildEncryptedQUICInitialDatagram(
	t *testing.T,
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

	// Build plaintext CRYPTO frame (type 0x06) + PADDING so payload >= 20 bytes.
	var plain bytes.Buffer
	plain.WriteByte(0x06) // CRYPTO frame
	appendQUICVarint2(&plain, cryptoOffset)
	appendQUICVarint2(&plain, uint16(len(cryptoChunk)))
	plain.Write(cryptoChunk)
	for plain.Len() < 24 {
		plain.WriteByte(0x00) // PADDING frame
	}

	// Build unmasked header with 2-byte packet number (pnLen = 2 -> low 2 bits = 0x01).
	firstByte := uint8(0xc1) // Long header (0x80) | Fixed (0x40) | Type 0 (Initial v1) | PN len 2 (0x01)
	if version == QUICVersion2 {
		firstByte = 0xd1 // Type 1 (Initial v2 = 0x10) | PN len 2 (0x01)
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

	// Remaining Length = 2 (PN) + len(plain) + 16 (GCM tag).
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

	// Apply QUIC header protection using 16-byte sample at pnOffset + 4.
	sampleOffset := pnOffset + 4
	var mask [16]byte
	keys.hp.Encrypt(mask[:], packet[sampleOffset:sampleOffset+16])
	packet[0] ^= mask[0] & 0x0f
	packet[pnOffset] ^= mask[1]
	packet[pnOffset+1] ^= mask[2]
	return packet
}

func TestQUICInitialDecryptionMultiPacketAndJA4(t *testing.T) {
	// Extract the raw TLS 1.3 ClientHello handshake message (without the 5-byte TLS record header).
	tlsRecord := buildTLS13ClientHelloRecord("quic.c2.example.com", "h3")
	hsMsg := tlsRecord[5:] // starts with msgType=1 + 3-byte length + ClientHello body

	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	scid := []byte{0x11, 0x22, 0x33, 0x44}

	for _, version := range []uint32{QUICVersion1, QUICVersion2} {
		// Split CRYPTO stream across 2 UDP datagrams and deliver out-of-order.
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

		// Wrap in UDP frames inside a PCAP and verify Capture.QUIC, HasQUICJA4, HasQUICSNI.
		u1 := buildEthernetIPv4UDPFrame([4]byte{10, 0, 0, 20}, [4]byte{198, 51, 100, 99}, 55443, 443, dgram2)
		u2 := buildEthernetIPv4UDPFrame([4]byte{10, 0, 0, 20}, [4]byte{198, 51, 100, 99}, 55443, 443, dgram1)
		rawPCAP := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{u1, u2})
		cap, err := New(rawPCAP)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
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

func TestHTTPRequestJA4HAndChunkedResponseCarving(t *testing.T) {
	rawReq := []byte("POST /gate.php HTTP/1.1\r\n" +
		"Host: c2.example.com\r\n" +
		"User-Agent: Mozilla/5.0\r\n" +
		"Accept-Language: en-US,en;q=0.9\r\n" +
		"Referer: https://c2.example.com/index.html\r\n" +
		"Cookie: z_token=999; a_sid=123\r\n" +
		"Content-Type: application/octet-stream\r\n" +
		"Content-Length: 10\r\n" +
		"\r\n" +
		"MZ_PAYLOAD")

	req, consumed, err := ParseHTTPRequest(rawReq)
	if err != nil {
		t.Fatalf("ParseHTTPRequest() error = %v", err)
	}
	if consumed != len(rawReq) || req.Method != "POST" || req.Path != "/gate.php" || req.Host != "c2.example.com" {
		t.Fatalf("HTTPRequest = %+v (consumed=%d)", req, consumed)
	}
	if string(req.Body) != "MZ_PAYLOAD" || req.CookieCount != 2 {
		t.Fatalf("Body=%q, CookieCount=%d", req.Body, req.CookieCount)
	}
	// Verify JA4H: po (POST) + 11 (HTTP/1.1) + c (Cookie) + r (Referer) + 05 (5 non-Cookie/non-Referer headers) + enus
	wantJA4H := "po11cr05enus_" +
		truncSHA256Hex12([]byte("Host,User-Agent,Accept-Language,Content-Type,Content-Length")) + "_" +
		truncSHA256Hex12([]byte("a_sid,z_token")) + "_" +
		truncSHA256Hex12([]byte("a_sid=123,z_token=999"))
	if req.JA4H != wantJA4H {
		t.Fatalf("HTTPRequest.JA4H = %q, want %q", req.JA4H, wantJA4H)
	}

	rawResp := []byte("HTTP/1.1 200 OK\r\n" +
		"Server: nginx\r\n" +
		"Content-Type: application/x-msdownload\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"\r\n" +
		"4\r\nMZ\x90\x00\r\n" +
		"6\r\nPE\x00\x00\x64\x86\r\n" +
		"0\r\n\r\n")

	resp, _, err := ParseHTTPResponse(rawResp)
	if err != nil {
		t.Fatalf("ParseHTTPResponse() error = %v", err)
	}
	if resp.StatusCode != 200 || resp.Server != "nginx" || !bytes.Equal(resp.Body, []byte("MZ\x90\x00PE\x00\x00\x64\x86")) {
		t.Fatalf("HTTPResponse = %+v, body=%x", resp, resp.Body)
	}
}

func encryptTLS13AppDataRecord(t *testing.T, secret []byte, cipherSuite uint16, seq uint64, innerType uint8, payload []byte) []byte {
	t.Helper()
	aead, iv, err := deriveTLS13TrafficAEAD(secret, cipherSuite)
	if err != nil {
		t.Fatalf("deriveTLS13TrafficAEAD: %v", err)
	}
	inner := make([]byte, len(payload)+1)
	copy(inner, payload)
	inner[len(payload)] = innerType

	recLen := uint16(len(inner) + aead.Overhead())
	hdr := []byte{TLSRecordApplicationData, 0x03, 0x03, byte(recLen >> 8), byte(recLen)}
	nonce := xorTLS13Nonce(iv, seq)
	ciphertext := aead.Seal(nil, nonce[:], inner, hdr)
	return append(hdr, ciphertext...)
}

func TestPCAPNGDSBTLS13DecryptionToHTTP(t *testing.T) {
	// 1. Build TLS 1.3 ClientHello (with Random = 32 bytes of 0x42) and ServerHello (cipher 0x1301).
	chRec := buildTLS13ClientHelloRecord("secure.c2.example.com", "http/1.1")
	shRec := buildTLSServerHelloAndCertRecords(t)

	clientAppSecret := bytes.Repeat([]byte{0xaa}, 32)
	serverAppSecret := bytes.Repeat([]byte{0xbb}, 32)
	clientRandomHex := hex.EncodeToString(bytes.Repeat([]byte{0x42}, 32))

	keylog := fmt.Sprintf(
		"CLIENT_TRAFFIC_SECRET_0 %s %s\nSERVER_TRAFFIC_SECRET_0 %s %s\n",
		clientRandomHex, hex.EncodeToString(clientAppSecret),
		clientRandomHex, hex.EncodeToString(serverAppSecret),
	)

	// 2. Encrypt an HTTP GET request and HTTP 200 response inside TLS 1.3 ApplicationData records.
	httpReqPlain := []byte("GET /beacon HTTP/1.1\r\nHost: secure.c2.example.com\r\nUser-Agent: Go-http-client/1.1\r\n\r\n")
	httpRespPlain := []byte("HTTP/1.1 200 OK\r\nServer: c2\r\nContent-Length: 7\r\n\r\nCOMMAND")

	encReqRec := encryptTLS13AppDataRecord(t, clientAppSecret, TLS_AES_128_GCM_SHA256, 0, TLSRecordApplicationData, httpReqPlain)
	encRespRec := encryptTLS13AppDataRecord(t, serverAppSecret, TLS_AES_128_GCM_SHA256, 0, TLSRecordApplicationData, httpRespPlain)

	clientStream := append(bytes.Clone(chRec), encReqRec...)
	serverStream := append(bytes.Clone(shRec), encRespRec...)

	p1 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 54000, 443, 1, 0, TCPFlagSYN, nil)
	p2 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1}, 443, 54000, 100, 2, TCPFlagSYN|TCPFlagACK, nil)
	p3 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 54000, 443, 2, 101, TCPFlagPSH|TCPFlagACK, clientStream)
	p4 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1}, 443, 54000, 101, 2+uint32(len(clientStream)), TCPFlagPSH|TCPFlagACK, serverStream)

	// 3. Build a PcapNG capture embedding the DSB keylog block + the encrypted TLS packets.
	rawPCAPNG := buildPCAPNGFixture(binary.LittleEndian, []byte(keylog), [][]byte{p1, p2, p3, p4})
	cap, err := New(rawPCAPNG)
	if err != nil {
		t.Fatalf("New(PCAPNG) error = %v", err)
	}

	// 4. Call cap.HTTP(rawPCAPNG) and verify it automatically decrypts the TLS 1.3 flow via DSB!
	httpRecords, err := cap.HTTP(rawPCAPNG)
	if err != nil || len(httpRecords) != 2 {
		t.Fatalf("cap.HTTP(DSB-decrypted) = (%d, %v), want 2 records", len(httpRecords), err)
	}
	if !httpRecords[0].IsDecrypted || httpRecords[0].Request.Path != "/beacon" || httpRecords[0].Request.Host != "secure.c2.example.com" {
		t.Fatalf("Decrypted HTTPRequest = %+v", httpRecords[0])
	}
	if !httpRecords[1].IsDecrypted || httpRecords[1].Response.StatusCode != 200 || string(httpRecords[1].Response.Body) != "COMMAND" {
		t.Fatalf("Decrypted HTTPResponse = %+v (body=%q)", httpRecords[1], httpRecords[1].Response.Body)
	}
}

func buildSSHKexStream(banner string, kex, hostKey, enc, mac, comp string) []byte {
	var payload bytes.Buffer
	payload.WriteByte(sshMsgKexInit)
	payload.Write(bytes.Repeat([]byte{0x11}, 16)) // 16-byte cookie
	lists := [10]string{kex, hostKey, enc, enc, mac, mac, comp, comp, "", ""}
	for _, s := range lists {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(s)))
		payload.Write(l[:])
		payload.WriteString(s)
	}
	payload.WriteByte(0)              // first_kex_packet_follows = false
	payload.Write([]byte{0, 0, 0, 0}) // reserved uint32

	padLen := 8 - ((5 + payload.Len()) % 8)
	if padLen < 4 {
		padLen += 8
	}
	pktLen := 1 + payload.Len() + padLen

	var stream bytes.Buffer
	stream.WriteString(banner + "\r\n")
	var hdr [5]byte
	binary.BigEndian.PutUint32(hdr[0:4], uint32(pktLen))
	hdr[4] = byte(padLen)
	stream.Write(hdr[:])
	stream.Write(payload.Bytes())
	stream.Write(make([]byte, padLen))
	return stream.Bytes()
}

func TestSSHHandshakeAndHASSH(t *testing.T) {
	cStream := buildSSHKexStream(
		"SSH-2.0-OpenSSH_9.6",
		"curve25519-sha256",
		"ssh-ed25519",
		"chacha20-poly1305@openssh.com",
		"umac-128-etm@openssh.com",
		"none",
	)
	sStream := buildSSHKexStream(
		"SSH-2.0-OpenSSH_9.6p1",
		"curve25519-sha256",
		"ssh-ed25519",
		"aes128-gcm@openssh.com",
		"umac-128-etm@openssh.com",
		"none",
	)

	hs, err := ParseSSHHandshake(cStream, sStream)
	if err != nil {
		t.Fatalf("ParseSSHHandshake() error = %v", err)
	}
	if hs.ClientBanner != "SSH-2.0-OpenSSH_9.6" || hs.ServerBanner != "SSH-2.0-OpenSSH_9.6p1" {
		t.Fatalf("Banners = (%q, %q)", hs.ClientBanner, hs.ServerBanner)
	}
	wantHASSH := computeHASSH("curve25519-sha256", "chacha20-poly1305@openssh.com", "umac-128-etm@openssh.com", "none")
	wantHASSHServer := computeHASSH("curve25519-sha256", "aes128-gcm@openssh.com", "umac-128-etm@openssh.com", "none")
	if hs.HASSH != wantHASSH || hs.HASSHServer != wantHASSHServer {
		t.Fatalf("HASSH = (%q, %q), want (%q, %q)", hs.HASSH, hs.HASSHServer, wantHASSH, wantHASSHServer)
	}

	p1 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 52222, 22, 1, 1, TCPFlagPSH|TCPFlagACK, cStream)
	p2 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1}, 22, 52222, 1, 1+uint32(len(cStream)), TCPFlagPSH|TCPFlagACK, sStream)
	rawPCAP := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{p1, p2})
	cap, err := New(rawPCAP)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	sshRecords, err := cap.SSH(rawPCAP)
	if err != nil || len(sshRecords) != 1 || sshRecords[0].Handshake.HASSH != wantHASSH {
		t.Fatalf("cap.SSH() = (%+v, %v)", sshRecords, err)
	}
}
