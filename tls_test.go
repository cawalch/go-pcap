package pcap

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"
)

func sealAESGCMTest(t *testing.T, key, nonce, plain, aad []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return gcm.Seal(nil, nonce, plain, aad)
}

func buildTLS13ClientHelloRecord(sni string, alpn string) []byte {
	var ext bytes.Buffer
	ext.Write([]byte{0x0a, 0x0a, 0x00, 0x00})

	if sni != "" {
		sniBytes := []byte(sni)
		var sniExt bytes.Buffer
		var hdr [9]byte
		binary.BigEndian.PutUint16(hdr[0:2], TLSExtServerName)
		binary.BigEndian.PutUint16(hdr[2:4], uint16(5+len(sniBytes)))
		binary.BigEndian.PutUint16(hdr[4:6], uint16(3+len(sniBytes)))
		hdr[6] = 0
		binary.BigEndian.PutUint16(hdr[7:9], uint16(len(sniBytes)))
		sniExt.Write(hdr[:])
		sniExt.Write(sniBytes)
		ext.Write(sniExt.Bytes())
	}

	ext.Write([]byte{0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x1d, 0x00, 0x17})
	ext.Write([]byte{0x00, 0x0d, 0x00, 0x06, 0x00, 0x04, 0x04, 0x03, 0x08, 0x04})

	if alpn != "" {
		ab := []byte(alpn)
		var alpnHdr [7]byte
		binary.BigEndian.PutUint16(alpnHdr[0:2], TLSExtALPN)
		binary.BigEndian.PutUint16(alpnHdr[2:4], uint16(3+len(ab)))
		binary.BigEndian.PutUint16(alpnHdr[4:6], uint16(1+len(ab)))
		alpnHdr[6] = uint8(len(ab))
		ext.Write(alpnHdr[:])
		ext.Write(ab)
	}

	ext.Write([]byte{0x00, 0x2b, 0x00, 0x07, 0x06, 0x1a, 0x1a, 0x03, 0x04, 0x03, 0x03})

	var body bytes.Buffer
	body.Write([]byte{0x03, 0x03})
	body.Write(bytes.Repeat([]byte{0x42}, 32))
	body.WriteByte(0)
	body.Write([]byte{0x00, 0x06, 0x2a, 0x2a, 0x13, 0x02, 0x13, 0x01})
	body.Write([]byte{0x01, 0x00})
	var extLen [2]byte
	binary.BigEndian.PutUint16(extLen[:], uint16(ext.Len()))
	body.Write(extLen[:])
	body.Write(ext.Bytes())

	return wrapTLSHandshakeRecord(TLSHandshakeClientHello, body.Bytes())
}

func buildTLSServerHelloAndCertRecords(t *testing.T) []byte {
	t.Helper()
	var shBody bytes.Buffer
	shBody.Write([]byte{0x03, 0x03})
	shBody.Write(bytes.Repeat([]byte{0x24}, 32))
	shBody.WriteByte(0)
	shBody.Write([]byte{0x13, 0x01})
	shBody.WriteByte(0)

	var shExt bytes.Buffer
	shExt.Write([]byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04})
	shExt.Write([]byte{0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 'h', '2'})

	var shExtLen [2]byte
	binary.BigEndian.PutUint16(shExtLen[:], uint16(shExt.Len()))
	shBody.Write(shExtLen[:])
	shBody.Write(shExt.Bytes())

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x123456),
		Subject: pkix.Name{
			CommonName:   "c2.example.com",
			Organization: []string{"TestOrg"},
		},
		NotBefore:   time.Unix(1700000000, 0),
		NotAfter:    time.Unix(1800000000, 0),
		DNSNames:    []string{"c2.example.com"},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}

	var certBody bytes.Buffer
	listLen := 3 + len(der)
	certBody.Write([]byte{byte(listLen >> 16), byte(listLen >> 8), byte(listLen)})
	certBody.Write([]byte{byte(len(der) >> 16), byte(len(der) >> 8), byte(len(der))})
	certBody.Write(der)

	var out bytes.Buffer
	out.Write(wrapTLSHandshakeRecord(TLSHandshakeServerHello, shBody.Bytes()))
	out.Write(wrapTLSHandshakeRecord(TLSHandshakeCertificate, certBody.Bytes()))
	return out.Bytes()
}

func wrapTLSHandshakeRecord(msgType uint8, msgBody []byte) []byte {
	hsLen := len(msgBody)
	recLen := 4 + hsLen
	out := make([]byte, 5+recLen)
	out[0] = TLSRecordHandshake
	binary.BigEndian.PutUint16(out[1:3], TLSVersion12)
	binary.BigEndian.PutUint16(out[3:5], uint16(recLen))
	out[5] = msgType
	out[6] = byte(hsLen >> 16)
	out[7] = byte(hsLen >> 8)
	out[8] = byte(hsLen)
	copy(out[9:], msgBody)
	return out
}

func TestTLSHandshakeJA4SuiteAndCaptureTLS(t *testing.T) {
	chRec := buildTLS13ClientHelloRecord("c2.example.com", "h2")
	shRec := buildTLSServerHelloAndCertRecords(t)

	hsClient, err := ParseTLSRecords(chRec)
	if err != nil {
		t.Fatalf("ParseTLSRecords(client) error = %v", err)
	}
	if !hsClient.HasClientHello {
		t.Fatal("HasClientHello = false, want true")
	}
	ch := hsClient.ClientHello
	if ch.SNI != "c2.example.com" || len(ch.ALPNs) != 1 || ch.ALPNs[0] != "h2" {
		t.Fatalf("ClientHello SNI/ALPN = (%q, %v)", ch.SNI, ch.ALPNs)
	}
	wantJA4 := "t13d0205h2_" + truncSHA256Hex12([]byte("1301,1302")) + "_" + truncSHA256Hex12([]byte("000a,000d,002b_0403,0804"))
	if ch.JA4 != wantJA4 {
		t.Fatalf("ClientHello.JA4 = %q, want %q", ch.JA4, wantJA4)
	}

	hsServer, err := ParseTLSRecords(shRec)
	if err != nil {
		t.Fatalf("ParseTLSRecords(server) error = %v", err)
	}
	if !hsServer.HasServerHello || len(hsServer.Certificates) != 1 {
		t.Fatalf("ServerHello/Certs = (hasSH=%v, certs=%d)", hsServer.HasServerHello, len(hsServer.Certificates))
	}
	wantJA4S := "t1302h2_1301_" + truncSHA256Hex12([]byte("002b,0010"))
	if hsServer.ServerHello.JA4S != wantJA4S {
		t.Fatalf("ServerHello.JA4S = %q, want %q", hsServer.ServerHello.JA4S, wantJA4S)
	}
	cert := hsServer.Certificates[0]
	if !cert.SelfSigned || !hsServer.Anomalies.SelfSignedCertificate || len(cert.JA4X) != 38 {
		t.Fatalf("Certificate = %+v, anomalies=%+v", cert, hsServer.Anomalies)
	}

	mid := len(chRec) / 2
	p1 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 10}, [4]byte{198, 51, 100, 44}, 50000, 443, 1000, 0, TCPFlagSYN, nil)
	p2 := buildEthernetIPv4TCPFrame([4]byte{198, 51, 100, 44}, [4]byte{10, 0, 0, 10}, 443, 50000, 5000, 1001, TCPFlagSYN|TCPFlagACK, nil)
	p3 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 10}, [4]byte{198, 51, 100, 44}, 50000, 443, 1001+uint32(mid), 5001, TCPFlagPSH|TCPFlagACK, chRec[mid:])
	p4 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 10}, [4]byte{198, 51, 100, 44}, 50000, 443, 1001, 5001, TCPFlagACK, chRec[:mid])
	p5 := buildEthernetIPv4TCPFrame([4]byte{198, 51, 100, 44}, [4]byte{10, 0, 0, 10}, 443, 50000, 5001, 1001+uint32(len(chRec)), TCPFlagPSH|TCPFlagACK, shRec)

	rawPCAP := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{p1, p2, p3, p4, p5})
	cap, err := New(rawPCAP)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	flows, err := cap.Flows(rawPCAP)
	if err != nil || len(flows) != 1 {
		t.Fatalf("Flows() = (%d, %v)", len(flows), err)
	}
	if flows[0].ClientJA4T != "65535_00_00_00" || flows[0].ServerJA4TS != "65535_00_00_00" {
		t.Fatalf("Flow JA4T/JA4TS = (%q, %q)", flows[0].ClientJA4T, flows[0].ServerJA4TS)
	}

	tlsRecords, err := cap.TLS(rawPCAP)
	if err != nil || len(tlsRecords) != 1 {
		t.Fatalf("cap.TLS() = (%d, %v), want 1", len(tlsRecords), err)
	}
	rec := tlsRecords[0]
	if !rec.Handshake.HasClientHello || !rec.Handshake.HasServerHello || len(rec.Handshake.Certificates) != 1 {
		t.Fatalf("TLSRecord = %+v", rec)
	}
	if rec.Handshake.ClientHello.JA4 != wantJA4 || rec.Handshake.ServerHello.JA4S != wantJA4S {
		t.Fatalf("JA4/JA4S mismatch: got (%q, %q)", rec.Handshake.ClientHello.JA4, rec.Handshake.ServerHello.JA4S)
	}

	if ok, err := cap.HasTLSJA4(rawPCAP, wantJA4); err != nil || !ok {
		t.Fatalf("HasTLSJA4() = (%v, %v), want (true, nil)", ok, err)
	}
	if ok, err := cap.HasTLSSNI(rawPCAP, "C2.EXAMPLE.COM"); err != nil || !ok {
		t.Fatalf("HasTLSSNI() = (%v, %v), want (true, nil)", ok, err)
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

	rawPCAPNG := buildPCAPNGFixture(binary.LittleEndian, []byte(keylog), [][]byte{p1, p2, p3, p4})
	cap, err := New(rawPCAPNG)
	if err != nil {
		t.Fatalf("New(PCAPNG) error = %v", err)
	}

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

func TestTLSBoundsAnomaliesAndMalformedInputs(t *testing.T) {
	if _, err := ParseTLSRecords([]byte{TLSRecordApplicationData, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5}); !errors.Is(err, ErrInvalidTLS) {
		t.Fatalf("ParseTLSRecords(AppData) err = %v, want ErrInvalidTLS", err)
	}

	var oversizeRec [5]byte
	oversizeRec[0] = TLSRecordHandshake
	binary.BigEndian.PutUint16(oversizeRec[1:3], TLSVersion12)
	binary.BigEndian.PutUint16(oversizeRec[3:5], MaxTLSRecordBytes+1)
	if _, err := ParseTLSRecords(oversizeRec[:]); !errors.Is(err, ErrTLSLimit) {
		t.Fatalf("ParseTLSRecords(oversize record) err = %v, want ErrTLSLimit", err)
	}

	chIPRec := buildTLS13ClientHelloRecord("192.0.2.99", "h3")
	hs, err := ParseTLSRecords(chIPRec)
	if err != nil {
		t.Fatalf("ParseTLSRecords(SNI IP literal) err = %v", err)
	}
	if !hs.ClientHello.Anomalies.SNIIPLiteral || !hs.ClientHello.Anomalies.ALPNTransportMismatch {
		t.Fatalf("ClientHello.Anomalies = %+v, want SNIIPLiteral and ALPNTransportMismatch", hs.ClientHello.Anomalies)
	}
	if !strings.HasPrefix(hs.ClientHello.JA4, "t13i") {
		t.Fatalf("ClientHello.JA4 = %q, want 't13i' prefix for IP-literal SNI", hs.ClientHello.JA4)
	}
}

func TestTLS12OfflineStreamDecryptionViaClientRandom(t *testing.T) {
	// Issue #4: Verify TLS 1.2 CLIENT_RANDOM master secret PRF key expansion and
	// AES-128-GCM decryption in DecryptTLS12Records and Capture.HTTP.
	var clientRandom, serverRandom [32]byte
	for i := range 32 {
		clientRandom[i] = byte(0x10 + i)
		serverRandom[i] = byte(0x50 + i)
	}
	masterSecret := bytes.Repeat([]byte{0x99}, 48)

	// Build a TLS 1.2 ClientHello and ServerHello choosing TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f).
	var chBody bytes.Buffer
	chBody.Write([]byte{0x03, 0x03})
	chBody.Write(clientRandom[:])
	chBody.WriteByte(0)
	chBody.Write([]byte{0x00, 0x02, 0xc0, 0x2f})
	chBody.Write([]byte{0x01, 0x00})
	chRec := wrapTLSHandshakeRecord(TLSHandshakeClientHello, chBody.Bytes())

	var shBody bytes.Buffer
	shBody.Write([]byte{0x03, 0x03})
	shBody.Write(serverRandom[:])
	shBody.WriteByte(0)
	shBody.Write([]byte{0xc0, 0x2f})
	shBody.WriteByte(0)
	shRec := wrapTLSHandshakeRecord(TLSHandshakeServerHello, shBody.Bytes())

	// Derive TLS 1.2 key block to encrypt a client HTTP GET record (seqNum = 0).
	keyLen, hashFn, _ := tls12CipherSuiteParams(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
	var seed [64]byte
	copy(seed[0:32], serverRandom[:])
	copy(seed[32:64], clientRandom[:])
	keyBlock := tls12PRF(hashFn, masterSecret, "key expansion", seed[:], 2*keyLen+8)
	clientWriteKey := keyBlock[:keyLen]
	clientSalt := keyBlock[2*keyLen : 2*keyLen+4]

	aead, _, err := deriveTLS13TrafficAEAD(bytes.Repeat([]byte{1}, 32), TLS_AES_128_GCM_SHA256)
	_ = aead
	_ = err
	// Encrypt using DecryptTLS12Records' exact inverse.
	plainHTTP := []byte("GET /tls12 HTTP/1.1\r\nHost: legacy.example.com\r\n\r\n")
	encRec := encryptTLS12AppDataRecord(t, clientWriteKey, clientSalt, 0, plainHTTP)

	clientStream := append(bytes.Clone(chRec), encRec...)
	dec, err := DecryptTLS12Records(clientStream, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, masterSecret, clientRandom, serverRandom, true)
	if err != nil || !bytes.Equal(dec, plainHTTP) {
		t.Fatalf("DecryptTLS12Records() = (%q, %v), want %q", dec, err, plainHTTP)
	}

	keylog := fmt.Sprintf("CLIENT_RANDOM %s %s\n", hex.EncodeToString(clientRandom[:]), hex.EncodeToString(masterSecret))
	p1 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 56000, 443, 1, 0, TCPFlagSYN, nil)
	p2 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1}, 443, 56000, 100, 2, TCPFlagSYN|TCPFlagACK, nil)
	p3 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 56000, 443, 2, 101, TCPFlagPSH|TCPFlagACK, clientStream)
	p4 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1}, 443, 56000, 101, 2+uint32(len(clientStream)), TCPFlagPSH|TCPFlagACK, shRec)

	rawPCAPNG := buildPCAPNGFixture(binary.LittleEndian, []byte(keylog), [][]byte{p1, p2, p3, p4})
	cap, err := New(rawPCAPNG)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	httpRecords, err := cap.HTTP(rawPCAPNG)
	if err != nil || len(httpRecords) != 1 || !httpRecords[0].IsDecrypted || httpRecords[0].Request.Path != "/tls12" {
		t.Fatalf("cap.HTTP(TLS 1.2 DSB) = (%+v, %v)", httpRecords, err)
	}
}

func encryptTLS12AppDataRecord(t *testing.T, writeKey []byte, salt []byte, seqNum uint64, plaintext []byte) []byte {
	t.Helper()
	// Derive AES-GCM directly via stdlib helper in tls_decrypt.go.
	explicitNonce := []byte{0, 0, 0, 0, 0, 0, 0, 1}
	var nonce [12]byte
	copy(nonce[0:4], salt)
	copy(nonce[4:12], explicitNonce)

	var aad [13]byte
	binary.BigEndian.PutUint64(aad[0:8], seqNum)
	aad[8] = TLSRecordApplicationData
	binary.BigEndian.PutUint16(aad[9:11], TLSVersion12)
	binary.BigEndian.PutUint16(aad[11:13], uint16(len(plaintext)))

	// Re-use aes.NewCipher + cipher.NewGCM through a tiny local wrapper.
	ciphertext := sealAESGCMTest(t, writeKey, nonce[:], plaintext, aad[:])
	recLen := uint16(len(explicitNonce) + len(ciphertext))
	hdr := []byte{TLSRecordApplicationData, 0x03, 0x03, byte(recLen >> 8), byte(recLen)}
	out := append(hdr, explicitNonce...)
	return append(out, ciphertext...)
}
