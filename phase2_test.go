package pcap

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"net/netip"
	"testing"
	"time"
)

func TestJA4TFingerprint(t *testing.T) {
	// Options: MSS(2)=1460, SACKPerm(4), TS(8), NOP(1), WS(3)=8
	opts := []byte{
		2, 4, 0x05, 0xb4, // MSS = 1460
		4, 2, // SACK Permitted
		8, 10, 0, 0, 0, 1, 0, 0, 0, 0, // Timestamps
		1,       // NOP
		3, 3, 8, // Window scale = 8
	}
	fp, ok := JA4T(64240, opts)
	if !ok {
		t.Fatal("JA4T() ok = false, want true")
	}
	const want = "64240_2-4-8-1-3_1460_8"
	if fp != want {
		t.Fatalf("JA4T() = %q, want %q", fp, want)
	}

	// Empty options -> "window_00_00_00"
	emptyFP, ok := JA4T(8192, nil)
	if !ok || emptyFP != "8192_00_00_00" {
		t.Fatalf("JA4T(nil) = (%q, %v), want (\"8192_00_00_00\", true)", emptyFP, ok)
	}
}

func TestReassembleTCPOutOfOrderGapAndOverlapConflict(t *testing.T) {
	// 1. Out-of-order segments with SYN.
	segs := []TCPSegmentInput{
		{Seq: 1000, Flags: TCPFlagSYN, Payload: nil},
		{Seq: 1006, Flags: TCPFlagACK, Payload: []byte("world")},
		{Seq: 1001, Flags: TCPFlagACK, Payload: []byte("hello")},
	}
	res, err := ReassembleTCP(segs)
	if err != nil {
		t.Fatalf("ReassembleTCP() err = %v", err)
	}
	if string(res.Data) != "helloworld" || res.Anomalies.Any() {
		t.Fatalf("ReassembleTCP() = (%q, %+v), want (\"helloworld\", no anomalies)", res.Data, res.Anomalies)
	}

	// 2. Identical retransmission sets Retransmission but NOT OverlapConflict.
	retransSegs := []TCPSegmentInput{
		{Seq: 10, Flags: TCPFlagSYN},
		{Seq: 11, Flags: TCPFlagACK, Payload: []byte("abcdef")},
		{Seq: 11, Flags: TCPFlagACK, Payload: []byte("abcdef")},
	}
	resRetrans, err := ReassembleTCP(retransSegs)
	if err != nil {
		t.Fatalf("ReassembleTCP(retrans) err = %v", err)
	}
	if string(resRetrans.Data) != "abcdef" || !resRetrans.Anomalies.Retransmission || resRetrans.Anomalies.OverlapConflict {
		t.Fatalf("ReassembleTCP(retrans) = (%q, %+v)", resRetrans.Data, resRetrans.Anomalies)
	}

	// 3. Conflicting overlapping segment retains first-seen bytes and sets OverlapConflict.
	conflictSegs := []TCPSegmentInput{
		{Seq: 10, Flags: TCPFlagSYN},
		{Seq: 11, Flags: TCPFlagACK, Payload: []byte("SAFE_COMMAND")},
		{Seq: 11, Flags: TCPFlagACK, Payload: []byte("EVIL_PAYLOAD_TAIL")},
	}
	resConflict, err := ReassembleTCP(conflictSegs)
	if err != nil {
		t.Fatalf("ReassembleTCP(conflict) err = %v", err)
	}
	if string(resConflict.Data) != "SAFE_COMMAND_TAIL" || !resConflict.Anomalies.OverlapConflict {
		t.Fatalf("ReassembleTCP(conflict) = (%q, %+v), want first-seen prefix + OverlapConflict", resConflict.Data, resConflict.Anomalies)
	}

	// 4. Sequence gap + midstream pickup.
	gapSegs := []TCPSegmentInput{
		{Seq: 500, Flags: TCPFlagACK, Payload: []byte("part1")},
		{Seq: 510, Flags: TCPFlagACK, Payload: []byte("part2")},
	}
	resGap, err := ReassembleTCP(gapSegs)
	if err != nil {
		t.Fatalf("ReassembleTCP(gap) err = %v", err)
	}
	if string(resGap.Data) != "part1part2" || !resGap.Anomalies.MidstreamPickup || !resGap.Anomalies.SequenceGap || resGap.GapBytes != 5 {
		t.Fatalf("ReassembleTCP(gap) = (%q, gapBytes=%d, %+v)", resGap.Data, resGap.GapBytes, resGap.Anomalies)
	}
}

func buildDNSQueryResponsePacket() []byte {
	var buf bytes.Buffer
	// Header: ID=0x1337, Flags=0x8180 (Response, RD, RA), QD=1, AN=2, NS=0, AR=0
	var hdr [12]byte
	binary.BigEndian.PutUint16(hdr[0:2], 0x1337)
	binary.BigEndian.PutUint16(hdr[2:4], 0x8180)
	binary.BigEndian.PutUint16(hdr[4:6], 1)
	binary.BigEndian.PutUint16(hdr[6:8], 2)
	buf.Write(hdr[:])

	// Question at offset 12: "\x02c2\x07example\x03com\x00", Type A (1), Class IN (1)
	buf.Write([]byte("\x02c2\x07example\x03com\x00"))
	var qTail [4]byte
	binary.BigEndian.PutUint16(qTail[0:2], DNSTypeA)
	binary.BigEndian.PutUint16(qTail[2:4], 1)
	buf.Write(qTail[:])

	// Answer 1: pointer to offset 12 (0xc00c), Type CNAME (5), Class IN (1), TTL 60, RData "\x04edge\xc0\x0f" (edge.example.com)
	buf.Write([]byte{0xc0, 0x0c})
	var rr1 [10]byte
	binary.BigEndian.PutUint16(rr1[0:2], DNSTypeCNAME)
	binary.BigEndian.PutUint16(rr1[2:4], 1)
	binary.BigEndian.PutUint32(rr1[4:8], 60)
	binary.BigEndian.PutUint16(rr1[8:10], 7)
	buf.Write(rr1[:])
	buf.Write([]byte{'\x04', 'e', 'd', 'g', 'e', 0xc0, 0x0f})

	// Answer 2: pointer to offset 12 (0xc00c), Type A (1), Class IN (1), TTL 300, RData 203.0.113.42
	buf.Write([]byte{0xc0, 0x0c})
	var rr2 [10]byte
	binary.BigEndian.PutUint16(rr2[0:2], DNSTypeA)
	binary.BigEndian.PutUint16(rr2[2:4], 1)
	binary.BigEndian.PutUint32(rr2[4:8], 300)
	binary.BigEndian.PutUint16(rr2[8:10], 4)
	buf.Write(rr2[:])
	buf.Write([]byte{203, 0, 113, 42})

	return buf.Bytes()
}

func buildEthernetIPv4UDPFrame(srcIP, dstIP [4]byte, srcPort, dstPort uint16, payload []byte) []byte {
	udpLen := 8 + len(payload)
	ipTotalLen := 20 + udpLen
	frame := make([]byte, 14+ipTotalLen)
	binary.BigEndian.PutUint16(frame[12:14], EtherTypeIPv4)
	ip := frame[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipTotalLen))
	ip[8] = 64
	ip[9] = IPProtoUDP
	copy(ip[12:16], srcIP[:])
	copy(ip[16:20], dstIP[:])

	udp := frame[34:42]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(frame[42:], payload)
	return frame
}

func TestParseDNSAndCaptureDNSQueries(t *testing.T) {
	dnsBytes := buildDNSQueryResponsePacket()
	msg, err := ParseDNS(dnsBytes)
	if err != nil {
		t.Fatalf("ParseDNS() error = %v", err)
	}
	if !msg.IsResponse || msg.TransactionID != 0x1337 || len(msg.Questions) != 1 || len(msg.Answers) != 2 {
		t.Fatalf("DNSMessage = %+v", msg)
	}
	if msg.Questions[0].Name != "c2.example.com" {
		t.Fatalf("Question[0].Name = %q, want \"c2.example.com\"", msg.Questions[0].Name)
	}
	if msg.Answers[0].Target != "edge.example.com" {
		t.Fatalf("Answers[0].Target = %q, want \"edge.example.com\"", msg.Answers[0].Target)
	}
	if msg.Answers[1].Address != netip.MustParseAddr("203.0.113.42") {
		t.Fatalf("Answers[1].Address = %s, want 203.0.113.42", msg.Answers[1].Address)
	}

	udpFrame := buildEthernetIPv4UDPFrame([4]byte{8, 8, 8, 8}, [4]byte{10, 0, 0, 5}, 53, 55111, dnsBytes)
	rawPCAP := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{udpFrame})
	cap, err := New(rawPCAP)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	records, err := cap.DNS(rawPCAP)
	if err != nil || len(records) != 1 {
		t.Fatalf("cap.DNS() = (%d, %v), want 1", len(records), err)
	}
	found, err := cap.HasDNSQuery(rawPCAP, "C2.EXAMPLE.COM.")
	if err != nil || !found {
		t.Fatalf("HasDNSQuery(C2.EXAMPLE.COM.) = (%v, %v), want (true, nil)", found, err)
	}
	notFound, err := cap.HasDNSQuery(rawPCAP, "other.example.com")
	if err != nil || notFound {
		t.Fatalf("HasDNSQuery(other.example.com) = (%v, %v), want (false, nil)", notFound, err)
	}
}

func buildTLS13ClientHelloRecord(sni string, alpn string) []byte {
	var ext bytes.Buffer

	// 1. GREASE extension 0x0a0a (ignored by JA4).
	ext.Write([]byte{0x0a, 0x0a, 0x00, 0x00})

	// 2. SNI extension (0x0000).
	if sni != "" {
		sniBytes := []byte(sni)
		var sniExt bytes.Buffer
		var hdr [9]byte
		binary.BigEndian.PutUint16(hdr[0:2], TLSExtServerName)
		binary.BigEndian.PutUint16(hdr[2:4], uint16(5+len(sniBytes)))
		binary.BigEndian.PutUint16(hdr[4:6], uint16(3+len(sniBytes)))
		hdr[6] = 0 // host_name
		binary.BigEndian.PutUint16(hdr[7:9], uint16(len(sniBytes)))
		sniExt.Write(hdr[:])
		sniExt.Write(sniBytes)
		ext.Write(sniExt.Bytes())
	}

	// 3. Supported Groups (0x000a): x25519 (0x001d), secp256r1 (0x0017).
	ext.Write([]byte{0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x1d, 0x00, 0x17})

	// 4. Signature Algorithms (0x000d): ecdsa_secp256r1_sha256 (0x0403), rsa_pss_rsae_sha256 (0x0804).
	ext.Write([]byte{0x00, 0x0d, 0x00, 0x06, 0x00, 0x04, 0x04, 0x03, 0x08, 0x04})

	// 5. ALPN (0x0010).
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

	// 6. Supported Versions (0x002b): GREASE (0x1a1a), TLS 1.3 (0x0304), TLS 1.2 (0x0303).
	ext.Write([]byte{0x00, 0x2b, 0x00, 0x07, 0x06, 0x1a, 0x1a, 0x03, 0x04, 0x03, 0x03})

	var body bytes.Buffer
	// Legacy version TLS 1.2 (0x0303) + 32-byte random.
	body.Write([]byte{0x03, 0x03})
	body.Write(bytes.Repeat([]byte{0x42}, 32))
	// Session ID length 0.
	body.WriteByte(0)
	// Cipher suites: GREASE (0x2a2a), TLS_AES_128_GCM_SHA256 (0x1301), TLS_AES_256_GCM_SHA384 (0x1302).
	body.Write([]byte{0x00, 0x06, 0x2a, 0x2a, 0x13, 0x02, 0x13, 0x01})
	// Compression methods: null (0x00).
	body.Write([]byte{0x01, 0x00})
	// Extensions block.
	var extLen [2]byte
	binary.BigEndian.PutUint16(extLen[:], uint16(ext.Len()))
	body.Write(extLen[:])
	body.Write(ext.Bytes())

	return wrapTLSHandshakeRecord(TLSHandshakeClientHello, body.Bytes())
}

func buildTLSServerHelloAndCertRecords(t *testing.T) []byte {
	t.Helper()
	// ServerHello: TLS 1.2 legacy version, cipher 0x1301, extensions: supported_versions (0x0304), ALPN ("h2").
	var shBody bytes.Buffer
	shBody.Write([]byte{0x03, 0x03})
	shBody.Write(bytes.Repeat([]byte{0x24}, 32))
	shBody.WriteByte(0)              // Session ID len 0
	shBody.Write([]byte{0x13, 0x01}) // Cipher suite 0x1301
	shBody.WriteByte(0)              // Compression 0

	var shExt bytes.Buffer
	// Supported versions: TLS 1.3 (0x0304).
	shExt.Write([]byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04})
	// ALPN: "h2".
	shExt.Write([]byte{0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 'h', '2'})

	var shExtLen [2]byte
	binary.BigEndian.PutUint16(shExtLen[:], uint16(shExt.Len()))
	shBody.Write(shExtLen[:])
	shBody.Write(shExt.Bytes())

	// Generate a self-signed X.509 certificate in memory using stdlib crypto/x509.
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

	// 1. Standalone ParseTLSRecords on ClientHello.
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
	// Verify JA4 part 'a': t + 13 (TLS 1.3) + d (domain SNI) + 02 (2 non-GREASE ciphers) + 05 (5 non-GREASE extensions) + h2 (ALPN)
	// Part 'b': sha256("1301,1302")[:12] = truncSHA256Hex12([]byte("1301,1302"))
	// Part 'c': sha256("000a,000d,002b_0403,0804")[:12]
	wantJA4 := "t13d0205h2_" + truncSHA256Hex12([]byte("1301,1302")) + "_" + truncSHA256Hex12([]byte("000a,000d,002b_0403,0804"))
	if ch.JA4 != wantJA4 {
		t.Fatalf("ClientHello.JA4 = %q, want %q", ch.JA4, wantJA4)
	}

	// 2. Standalone ParseTLSRecords on ServerHello + Certificate.
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

	// 3. Full PCAP end-to-end flow: SYN, SYN-ACK, split ClientHello across 2 TCP segments, ServerHello+Cert.
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
