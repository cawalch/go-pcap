package pcap

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"testing"
	"time"
)

// Build a signed leaf and issuer with independently selectable SANs.
func sanTestChain(t testing.TB, names []string, ips []net.IP, issuerSANs bool) [][]byte {
	t.Helper()
	caKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	leafKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Issuer"},
		NotBefore: time.Unix(1700000000, 0), NotAfter: time.Unix(1800000000, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	if issuerSANs {
		ca.DNSNames = []string{"issuer.example"}
		ca.IPAddresses = []net.IP{net.ParseIP("2001:db8::ca")}
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "leaf.example"},
		NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, DNSNames: names, IPAddresses: ips,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, leafKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	return [][]byte{leafDER, caDER}
}

func sanTestCapture(t testing.TB, chain [][]byte, encrypted bool) []byte {
	t.Helper()
	var entries []byte
	for _, der := range chain {
		entries = append(entries, byte(len(der)>>16), byte(len(der)>>8), byte(len(der)))
		entries = append(entries, der...)
		if encrypted {
			entries = append(entries, 0, 0) // TLS 1.3 CertificateEntry extensions
		}
	}
	body := []byte{byte(len(entries) >> 16), byte(len(entries) >> 8), byte(len(entries))}
	if encrypted {
		body = append([]byte{0}, body...) // Empty certificate request context.
	}
	rec := wrapTLSHandshakeRecord(TLSHandshakeCertificate, append(body, entries...))
	var keylog []byte
	if encrypted {
		secret := bytes.Repeat([]byte{0x77}, 32)
		rec = encryptTLS13AppDataRecord(t, secret, TLS_AES_128_GCM_SHA256, 0, TLSRecordHandshake, rec[5:])
		keylog = fmt.Appendf(nil, "SERVER_HANDSHAKE_TRAFFIC_SECRET %x %x\n", bytes.Repeat([]byte{0x42}, 32), secret)
	}
	client, server := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	hello := buildTLSServerHelloRecord()
	if !encrypted {
		// Use the reference TLS 1.2 ServerHello for the cleartext certificate.
		var err error
		hello, err = os.ReadFile("testdata/foxio/h2-server.tls")
		if err != nil {
			t.Fatal(err)
		}
	}
	return buildPCAPNGFixture(binary.LittleEndian, keylog, [][]byte{
		buildEthernetIPv4TCPFrame(client, server, 51234, 443, 1, 0, TCPFlagACK, buildTLS13ClientHelloRecord("leaf.example", "h2")),
		buildEthernetIPv4TCPFrame(server, client, 443, 51234, 1, 0, TCPFlagACK, append(hello, rec...)),
	})
}

func TestTLSCertificateSANs(t *testing.T) {
	manyNames := make([]string, MaxTLSCertSANsPerKind+1)
	manyIPs := make([]net.IP, len(manyNames))
	for i := range manyNames {
		manyNames[i] = fmt.Sprintf("n%d.example", i)
		manyIPs[i] = net.IPv4(192, 0, 2, byte(i))
	}
	mixed := []net.IP{net.ParseIP("192.0.2.17"), net.ParseIP("2001:db8::17")}
	for _, tc := range []struct {
		name  string
		names []string
		ips   []net.IP
	}{
		{"Absent", nil, nil},
		{"Mixed", []string{"a.example", "b.example"}, mixed},
		{"AtLimit", manyNames[:MaxTLSCertSANsPerKind], manyIPs[:MaxTLSCertSANsPerKind]},
		{"ExcessDNS", manyNames, nil},
		{"ExcessIP", nil, manyIPs},
	} {
		chain := sanTestChain(t, tc.names, tc.ips, true)
		for _, encrypted := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/encrypted=%t", tc.name, encrypted), func(t *testing.T) {
				raw := sanTestCapture(t, chain, encrypted)
				c, err := New(raw)
				if err != nil {
					t.Fatal(err)
				}
				slice, err := c.TLS(raw)
				if err != nil {
					t.Fatal(err)
				}
				r := bytes.NewReader(raw)
				cr, err := NewFromReaderAt(r, r.Size())
				if err != nil {
					t.Fatal(err)
				}
				reader, err := cr.TLSFromReaderAt(r)
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(slice, reader) {
					t.Fatal("slice and ReaderAt TLS records differ")
				}
				if len(slice) != 1 || len(slice[0].Handshake.Certificates) != 2 {
					t.Fatal("expected one handshake with leaf and issuer")
				}
				certs := slice[0].Handshake.Certificates
				leaf := certs[0]
				wantNames := tc.names[:min(len(tc.names), MaxTLSCertSANsPerKind)]
				var wantIPs []netip.Addr
				for _, ip := range tc.ips[:min(len(tc.ips), MaxTLSCertSANsPerKind)] {
					wantIPs = append(wantIPs, netip.MustParseAddr(ip.String()))
				}
				if !reflect.DeepEqual(leaf.DNSNames, wantNames) || !reflect.DeepEqual(leaf.IPAddresses, wantIPs) {
					t.Fatalf("leaf DNS=%v IP=%v, want %v %v", leaf.DNSNames, leaf.IPAddresses, wantNames, wantIPs)
				}
				wantTruncated := len(wantNames) < len(tc.names) || len(wantIPs) < len(tc.ips)
				if leaf.SANsTruncated != wantTruncated || certs[1].SANsTruncated {
					t.Fatalf("unexpected truncation flags: leaf=%t issuer=%t", leaf.SANsTruncated, certs[1].SANsTruncated)
				}
				if !slices.Equal(certs[1].DNSNames, []string{"issuer.example"}) || !slices.Equal(certs[1].IPAddresses, []netip.Addr{netip.MustParseAddr("2001:db8::ca")}) {
					t.Fatalf("issuer DNS=%v IP=%v", certs[1].DNSNames, certs[1].IPAddresses)
				}
				if !bytes.Equal(leaf.RawDER, chain[0]) || !bytes.Equal(certs[1].RawDER, chain[1]) {
					t.Fatal("chain order or DER differs")
				}
			})
		}
	}
}

// BenchmarkTLSCertificateSANs scans a two-certificate server chain in a pre-opened PcapNG capture.
func BenchmarkTLSCertificateSANs(b *testing.B) {
	for _, tc := range []struct {
		name  string
		names []string
		ips   []net.IP
	}{
		{"Absent", nil, nil},
		{"IPOnly", nil, []net.IP{net.ParseIP("192.0.2.17"), net.ParseIP("2001:db8::17")}},
		{"Mixed", []string{"a.example", "b.example"}, []net.IP{net.ParseIP("192.0.2.17"), net.ParseIP("2001:db8::17")}},
	} {
		chain := sanTestChain(b, tc.names, tc.ips, false)
		for _, mode := range []string{"Clear", "Decrypted"} {
			raw := sanTestCapture(b, chain, mode == "Decrypted")
			r := bytes.NewReader(raw)
			c, err := New(raw)
			if err != nil {
				b.Fatal(err)
			}
			cr, err := NewFromReaderAt(r, r.Size())
			if err != nil {
				b.Fatal(err)
			}
			for _, reader := range []string{"Slice", "ReaderAt"} {
				b.Run(tc.name+"/"+mode+"/"+reader, func(b *testing.B) {
					b.ReportAllocs()
					for b.Loop() {
						var rows []TLSRecord
						var err error
						if reader == "Slice" {
							rows, err = c.TLS(raw)
						} else {
							rows, err = cr.TLSFromReaderAt(r)
						}
						if err != nil || len(rows) != 1 || len(rows[0].Handshake.Certificates) != 2 {
							b.Fatal("missing chain", err)
						}
					}
				})
			}
		}
	}
}
