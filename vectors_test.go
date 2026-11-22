package pcap

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"
)

// TestRFC9001AppendixAClientInitialVector verifies QUIC v1 Initial key derivation,
// header-protection unmasking, AES-128-GCM decryption, CRYPTO frame extraction,
// and TLS 1.3 ClientHello + JA4 fingerprinting against the official RFC 9001
// Appendix A.1 and A.2 test vectors, as well as FoxIO JA4+ edge cases.
func TestRFC9001AppendixAClientInitialVector(t *testing.T) {
	dcid, _ := hex.DecodeString("8394c8f03e515708")
	keys, err := deriveQUICInitialKeys(dcid, QUICVersion1, true)
	if err != nil {
		t.Fatalf("deriveQUICInitialKeys(RFC 9001 A.1) error = %v", err)
	}
	wantIV, _ := hex.DecodeString("fa044b2f42a3fd3b46fb255c")
	if !bytes.Equal(keys.iv[:], wantIV) {
		t.Fatalf("RFC 9001 A.1 client IV = %x, want %x", keys.iv, wantIV)
	}

	// RFC 9001 Appendix A.2 plaintext CRYPTO frame containing the 237-byte TLS 1.3 ClientHello
	// (0x01 0x00 0x00 0xed ... with SNI "example.org" and ALPN "hq-interop").
	const rfc9001ClientHelloHandshakeHex = "" +
		"010000ea0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47" +
		"f06a2b69484c00000413011302010000bd00000010000e00000b6578616d706c" +
		"652e6f7267ff01000100000a00080006001d001700180010000d000b0a68712d" +
		"696e7465726f70003300260024001d00209370b2c9caa47fbaaf4559fedba753" +
		"de171fa71f50f1ce15d43e994ec74d7480002b0003020304000d0010000e0403" +
		"050306030203080408050806002d00020101001c00024001003900320408ffff" +
		"ffffffffffff05048000ffff07048000ffff0801100104800075300901100f08" +
		"8394c8f03e51570806048000ffff"

	chHandshake, err := hex.DecodeString(rfc9001ClientHelloHandshakeHex)
	if err != nil {
		t.Fatalf("hex.DecodeString(rfc9001ClientHelloHandshakeHex): %v", err)
	}
	dgram := buildEncryptedQUICInitialDatagram(t, QUICVersion1, dcid, nil, nil, 2, 0, chHandshake)
	hs, err := DecryptQUICInitial([][]byte{dgram})
	if err != nil {
		t.Fatalf("DecryptQUICInitial(RFC 9001 A.2) error = %v", err)
	}
	if hs.ClientHello.SNI != "example.org" || len(hs.ClientHello.ALPNs) != 1 || hs.ClientHello.ALPNs[0] != "hq-interop" {
		t.Fatalf("RFC 9001 ClientHello SNI=%q ALPNs=%v", hs.ClientHello.SNI, hs.ClientHello.ALPNs)
	}
	// Verify JA4 part 'a' for "hq-interop" (first='h', last='p') and 9 extensions (0000, ff01, 000a, 0010, 0033, 002b, 000d, 002d, 001c, 0039 -> 10 extensions):
	wantJA4 := "q13d0210hp_" +
		truncSHA256Hex12([]byte("1301,1302")) + "_" +
		truncSHA256Hex12([]byte("000a,000d,001c,002b,002d,0033,0039,ff01_0403,0503,0603,0203,0804,0805,0806"))
	if hs.ClientHello.JA4 != wantJA4 {
		t.Fatalf("RFC 9001 ClientHello JA4 = %q, want %q", hs.ClientHello.JA4, wantJA4)
	}
}

func TestPacketSeqIteratorAndFlowTableOverflow(t *testing.T) {
	// Create 16 distinct 5-tuple flows (> 12 inline capacity) to exercise flowIndexTable spill to overflow map.
	var frames [][]byte
	for i := range 16 {
		src := [4]byte{10, 0, 0, byte(i + 1)}
		dst := [4]byte{198, 51, 100, 1}
		frames = append(frames, buildEthernetIPv4TCPFrame(src, dst, uint16(40000+i), 443, 1, 0, TCPFlagSYN, []byte("ping")))
	}
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
	cap, err := New(raw)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Verify PacketSeq iterates all 16 packets and supports early break.
	count := 0
	for pkt, err := range cap.PacketSeq(raw) {
		if err != nil {
			t.Fatalf("PacketSeq() error = %v", err)
		}
		if pkt.Index != count {
			t.Fatalf("PacketSeq() index = %d, want %d", pkt.Index, count)
		}
		count++
	}
	if count != 16 {
		t.Fatalf("PacketSeq() count = %d, want 16", count)
	}

	// Early break after 3 packets.
	early := 0
	for _, err := range cap.PacketSeq(raw) {
		if err != nil {
			t.Fatalf("PacketSeq(early) error = %v", err)
		}
		early++
		if early == 3 {
			break
		}
	}
	if early != 3 {
		t.Fatalf("early break count = %d, want 3", early)
	}

	flows, err := cap.Flows(raw)
	if err != nil || len(flows) != 16 {
		t.Fatalf("Flows(16 distinct) = (%d, %v), want 16", len(flows), err)
	}
	for i, f := range flows {
		wantSrc := netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)})
		if f.SrcAddr != wantSrc || f.PacketCount != 1 {
			t.Fatalf("flows[%d] = %+v, want SrcAddr=%s", i, f, wantSrc)
		}
	}
}

func TestTLS13EncryptedServerCertificateDecryptionViaDSB(t *testing.T) {
	// Issue #3: In TLS 1.3, the server Certificate handshake message is encrypted
	// inside an outer ApplicationData (23) record using SERVER_HANDSHAKE_TRAFFIC_SECRET.
	chRec := buildTLS13ClientHelloRecord("tls13-cert.example.com", "h2")

	// Build a TLS 1.3 ServerHello (without an unencrypted Certificate record).
	var shBody bytes.Buffer
	shBody.Write([]byte{0x03, 0x03})
	shBody.Write(bytes.Repeat([]byte{0x24}, 32))
	shBody.WriteByte(0)
	shBody.Write([]byte{0x13, 0x01}) // TLS_AES_128_GCM_SHA256
	shBody.WriteByte(0)
	var shExt bytes.Buffer
	shExt.Write([]byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04})
	shExt.Write([]byte{0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 'h', '2'})
	var shExtLen [2]byte
	binary.BigEndian.PutUint16(shExtLen[:], uint16(shExt.Len()))
	shBody.Write(shExtLen[:])
	shBody.Write(shExt.Bytes())
	shRec := wrapTLSHandshakeRecord(TLSHandshakeServerHello, shBody.Bytes())

	// Build a self-signed X.509 certificate and format a RFC 8446 §4.4.2 TLS 1.3 Certificate handshake message:
	// msgType (11) + 3-byte msgLen + 1-byte contextLen (0) + 3-byte certListLen + (3-byte certLen + DER + 2-byte extLen (0)).
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0xabcdef),
		Subject: pkix.Name{
			CommonName:   "tls13-cert.example.com",
			Organization: []string{"EncryptedCertOrg"},
		},
		NotBefore: time.Unix(1700000000, 0),
		NotAfter:  time.Unix(1800000000, 0),
		DNSNames:  []string{"tls13-cert.example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}

	entryLen := 3 + len(der) + 2
	bodyLen := 1 + 3 + entryLen
	var hsCertMsg bytes.Buffer
	hsCertMsg.WriteByte(TLSHandshakeCertificate)
	hsCertMsg.Write([]byte{byte(bodyLen >> 16), byte(bodyLen >> 8), byte(bodyLen)})
	hsCertMsg.WriteByte(0) // certificate_request_context length = 0
	hsCertMsg.Write([]byte{byte(entryLen >> 16), byte(entryLen >> 8), byte(entryLen)})
	hsCertMsg.Write([]byte{byte(len(der) >> 16), byte(len(der) >> 8), byte(len(der))})
	hsCertMsg.Write(der)
	hsCertMsg.Write([]byte{0, 0}) // CertificateEntry extensions length = 0

	serverHsSecret := bytes.Repeat([]byte{0x77}, 32)
	encCertRecord := encryptTLS13AppDataRecord(t, serverHsSecret, TLS_AES_128_GCM_SHA256, 0, TLSRecordHandshake, hsCertMsg.Bytes())
	serverStream := append(bytes.Clone(shRec), encCertRecord...)

	clientRandomHex := hex.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	keylog := fmt.Sprintf("SERVER_HANDSHAKE_TRAFFIC_SECRET %s %s\n", clientRandomHex, hex.EncodeToString(serverHsSecret))

	p1 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 55000, 443, 1, 0, TCPFlagSYN, nil)
	p2 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1}, 443, 55000, 100, 2, TCPFlagSYN|TCPFlagACK, nil)
	p3 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 55000, 443, 2, 101, TCPFlagPSH|TCPFlagACK, chRec)
	p4 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1}, 443, 55000, 101, 2+uint32(len(chRec)), TCPFlagPSH|TCPFlagACK, serverStream)

	rawPCAPNG := buildPCAPNGFixture(binary.LittleEndian, []byte(keylog), [][]byte{p1, p2, p3, p4})
	cap, err := New(rawPCAPNG)
	if err != nil {
		t.Fatalf("New(PCAPNG) error = %v", err)
	}

	tlsRecords, err := cap.TLS(rawPCAPNG)
	if err != nil || len(tlsRecords) != 1 {
		t.Fatalf("cap.TLS() = (%d, %v), want 1", len(tlsRecords), err)
	}
	certs := tlsRecords[0].Handshake.Certificates
	if len(certs) != 1 {
		t.Fatalf("len(Certificates) = %d, want 1 decrypted TLS 1.3 certificate", len(certs))
	}
	if !certs[0].SelfSigned || !tlsRecords[0].Handshake.Anomalies.SelfSignedCertificate || len(certs[0].JA4X) != 38 {
		t.Fatalf("Decrypted TLS 1.3 cert = %+v, anomalies=%+v", certs[0], tlsRecords[0].Handshake.Anomalies)
	}
}

func TestPCAPNGBinaryTimestampResolutionAndOffset(t *testing.T) {
	// Issue #7: Binary power-of-two if_tsresol (0x80 | 32 -> 2^-32 seconds per tick)
	// and if_tsoffset (option 14, int64 seconds).
	var buf bytes.Buffer

	var shb bytes.Buffer
	var shbFixed [16]byte
	binary.LittleEndian.PutUint32(shbFixed[0:4], PCAPNGByteOrderMagic)
	binary.LittleEndian.PutUint16(shbFixed[4:6], 1)
	binary.LittleEndian.PutUint16(shbFixed[6:8], 0)
	binary.LittleEndian.PutUint64(shbFixed[8:16], 0xffffffffffffffff)
	shb.Write(shbFixed[:])
	appendPCAPNGBlock(&buf, binary.LittleEndian, BlockTypeSectionHeader, shb.Bytes())

	var idb bytes.Buffer
	var idbFixed [8]byte
	binary.LittleEndian.PutUint16(idbFixed[0:2], uint16(LinkTypeEthernet))
	binary.LittleEndian.PutUint32(idbFixed[4:8], 65535)
	idb.Write(idbFixed[:])
	// if_tsresol = 0x80 | 32 (2^-32 seconds per tick, so 1 << 32 ticks == 1 second == 1,000,000,000 ns)
	appendPCAPNGOption(&idb, binary.LittleEndian, optIDBTsResol, []byte{0x80 | 32})
	// if_tsoffset = 1700000000 seconds
	var tsOffBytes [8]byte
	binary.LittleEndian.PutUint64(tsOffBytes[:], 1700000000)
	appendPCAPNGOption(&idb, binary.LittleEndian, optIDBTsOffset, tsOffBytes[:])
	appendPCAPNGOption(&idb, binary.LittleEndian, optEndOfOpt, nil)
	appendPCAPNGBlock(&buf, binary.LittleEndian, BlockTypeInterfaceDesc, idb.Bytes())

	// EPB with rawTicks = (2 << 32) | (1 << 31) = 2.5 seconds in 2^-32 resolution.
	frame := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 1234, 80, 1, 0, TCPFlagSYN, nil)
	var epb bytes.Buffer
	var epbFixed [20]byte
	binary.LittleEndian.PutUint32(epbFixed[0:4], 0)
	binary.LittleEndian.PutUint32(epbFixed[4:8], 2)      // tsHigh = 2 seconds
	binary.LittleEndian.PutUint32(epbFixed[8:12], 1<<31) // tsLow = 0.5 seconds
	binary.LittleEndian.PutUint32(epbFixed[12:16], uint32(len(frame)))
	binary.LittleEndian.PutUint32(epbFixed[16:20], uint32(len(frame)))
	epb.Write(epbFixed[:])
	epb.Write(frame)
	if rem := len(frame) % 4; rem != 0 {
		epb.Write(make([]byte, 4-rem))
	}
	appendPCAPNGBlock(&buf, binary.LittleEndian, BlockTypeEnhancedPacket, epb.Bytes())

	raw := buf.Bytes()
	cap, err := New(raw)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if !cap.Interfaces[0].TimestampBinary || cap.Interfaces[0].TimestampExponent != 32 || cap.Interfaces[0].TimestampOffsetSec != 1700000000 {
		t.Fatalf("InterfaceDescriptor = %+v", cap.Interfaces[0])
	}
	pkts, err := cap.Packets(raw)
	if err != nil || len(pkts) != 1 {
		t.Fatalf("Packets() = (%d, %v)", len(pkts), err)
	}
	wantNs := int64(1700000002)*1_000_000_000 + 500_000_000
	if pkts[0].TimestampNs != wantNs {
		t.Fatalf("PacketRecord.TimestampNs = %d, want %d", pkts[0].TimestampNs, wantNs)
	}
}

// The datagrams are the protected packets in RFC 9001 and RFC 9369,
// Appendix A.2 (client) and A.3 (server), including the original padding.
func TestPublishedQUICInitialDatagrams(t *testing.T) {
	for _, tc := range []struct {
		rfc     string
		version uint32
	}{{"9001", QUICVersion1}, {"9369", QUICVersion2}} {
		t.Run(tc.rfc, func(t *testing.T) {
			var frames [][]byte
			src, dst := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
			client, server := uint16(54321), uint16(443)
			for _, side := range []string{"client", "server"} {
				wire, err := os.ReadFile("testdata/rfc" + tc.rfc + "-" + side + ".bin")
				if err != nil {
					t.Fatal(err)
				}
				frames = append(frames, buildEthernetIPv4UDPFrame(src, dst, client, server, wire))
				src, dst = dst, src
				client, server = server, client
			}
			raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
			c, err := New(raw)
			if err != nil {
				t.Fatal(err)
			}
			records, err := c.QUIC(raw)
			if err != nil || len(records) != 1 {
				t.Fatalf("QUIC records: %+v, %v", records, err)
			}
			hs := records[0].Handshake
			if hs.Version != tc.version || !hs.HasClientHello || hs.ClientHello.SNI != "example.com" || !slices.Equal(hs.ClientHello.ALPNs, []string{"alpn"}) {
				t.Fatalf("client: %+v", hs.ClientHello)
			}
			if !hs.HasServerHello || hs.ServerHello.CipherSuite != TLS_AES_128_GCM_SHA256 || hs.ServerHello.NegotiatedVersion != TLSVersion13 {
				t.Fatalf("server: %+v", hs.ServerHello)
			}
		})
	}
}
