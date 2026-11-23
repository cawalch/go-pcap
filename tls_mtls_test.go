package pcap

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"reflect"
	"testing"
)

// Construct each direction independently, with the server captured first.
func mtlsTestCapture(t testing.TB, encrypted bool, clientChain, serverChain [][]byte, clientKey, serverKey bool) []byte {
	t.Helper()
	ch := buildTLS13ClientHelloRecord("mtls.example", "h2")
	sh := buildTLSServerHelloRecord()
	request := wrapTLSHandshakeRecord(TLSHandshakeCertificateRequest, []byte{0, 0, 8, 0, 13, 0, 4, 0, 2, 4, 3})
	if !encrypted {
		var err error
		sh, err = os.ReadFile("testdata/foxio/h2-server.tls")
		if err != nil {
			t.Fatal(err)
		}
		request = wrapTLSHandshakeRecord(TLSHandshakeCertificateRequest, []byte{1, 1, 0, 2, 4, 1, 0, 0})
	}
	clientCert := certificateTestRecord(clientChain, encrypted)
	serverCert := certificateTestRecord(serverChain, encrypted)
	var keylog []byte
	if encrypted {
		clientSecret := bytes.Repeat([]byte{0x55}, 32)
		serverSecret := bytes.Repeat([]byte{0x77}, 32)
		random := bytes.Repeat([]byte{0x42}, 32)
		if clientKey {
			keylog = fmt.Appendf(keylog, "CLIENT_HANDSHAKE_TRAFFIC_SECRET %x %x\n", random, clientSecret)
		}
		if serverKey {
			keylog = fmt.Appendf(keylog, "SERVER_HANDSHAKE_TRAFFIC_SECRET %x %x\n", random, serverSecret)
		}
		ch = append(ch, encryptTLS13AppDataRecord(t, clientSecret, TLS_AES_128_GCM_SHA256, 0, TLSRecordHandshake, clientCert[5:])...)
		sh = append(sh, encryptTLS13AppDataRecord(t, serverSecret, TLS_AES_128_GCM_SHA256, 0, TLSRecordHandshake, append(request[5:], serverCert[5:]...))...)
	} else {
		ch = append(ch, clientCert...)
		sh = append(sh, serverCert...)
		sh = append(sh, request...)
	}
	client, server := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	return buildPCAPNGFixture(binary.LittleEndian, keylog, [][]byte{
		buildEthernetIPv4TCPFrame(server, client, 443, 51234, 1, 0, TCPFlagACK, sh),
		buildEthernetIPv4TCPFrame(client, server, 51234, 443, 1, 0, TCPFlagACK, ch),
	})
}

func TestMutualTLSCertificates(t *testing.T) {
	client := sanTestChain(t, []string{"client.example"}, nil, false)
	server := sanTestChain(t, []string{"server.example"}, nil, false)
	many := make([][]byte, MaxTLSCertificates+1)
	for i := range many {
		many[i] = client[0]
	}
	for _, tc := range []struct {
		name                            string
		encrypted, clientKey, serverKey bool
		chain                           [][]byte
		want                            int
	}{
		{"Clear", false, false, false, client, 2}, {"Encrypted", true, true, true, client, 2}, {"ServerSecretOnly", true, false, true, client, 0}, {"ClientSecretOnly", true, true, false, client, 2}, {"Empty", true, true, true, nil, 0}, {"AtCap", true, true, true, many, MaxTLSCertificates},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := mtlsTestCapture(t, tc.encrypted, tc.chain, server, tc.clientKey, tc.serverKey)
			c, err := New(raw)
			if err != nil {
				t.Fatal(err)
			}
			r := bytes.NewReader(raw)
			cr, err := NewFromReaderAt(r, r.Size())
			if err != nil {
				t.Fatal(err)
			}
			rows, err := c.TLS(raw)
			if err != nil || len(rows) != 1 {
				t.Fatalf("TLS: %d, %v", len(rows), err)
			}
			got, err := cr.TLSFromReaderAt(r)
			if err != nil || !reflect.DeepEqual(rows, got) {
				t.Fatalf("ReaderAt differs: %v", err)
			}
			hs := rows[0].Handshake
			visible := !tc.encrypted || tc.serverKey
			if hs.HasCertificateRequest != visible || len(hs.ClientCertificates) != tc.want {
				t.Fatalf("request=%t client chain=%d", hs.HasCertificateRequest, len(hs.ClientCertificates))
			}
			if visible {
				if len(hs.Certificates) != 2 || !bytes.Equal(hs.Certificates[0].RawDER, server[0]) {
					t.Fatal("wrong server chain")
				}
			} else if len(hs.Certificates) != 0 {
				t.Fatal("unexpected server certificate")
			}
			for i, cert := range hs.ClientCertificates {
				wantFP, err := JA4XFromDER(tc.chain[i])
				if err != nil || cert.JA4X != wantFP || !bytes.Equal(cert.RawDER, tc.chain[i]) {
					t.Fatalf("wrong client certificate %d", i)
				}
			}
		})
	}
}

func BenchmarkMutualTLSCertificates(b *testing.B) {
	client := sanTestChain(b, []string{"client.example"}, nil, false)
	server := sanTestChain(b, []string{"server.example"}, nil, false)
	for _, mode := range []string{"Clear", "Encrypted"} {
		raw := mtlsTestCapture(b, mode == "Encrypted", client, server, true, true)
		c, err := New(raw)
		if err != nil {
			b.Fatal(err)
		}
		r := bytes.NewReader(raw)
		for _, input := range []string{"Slice", "ReaderAt"} {
			b.Run(mode+"/"+input, func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					var rows []TLSRecord
					var err error
					if input == "Slice" {
						rows, err = c.TLS(raw)
					} else {
						rows, err = c.TLSFromReaderAt(r)
					}
					if err != nil || len(rows) != 1 {
						b.Fatal("TLS scan", err)
					}
				}
			})
		}
	}
}

func TestMutualTLSMidstreamClientChain(t *testing.T) {
	chain := sanTestChain(t, []string{"client.example"}, nil, false)
	cert := certificateTestRecord(chain, false)
	sh, err := os.ReadFile("testdata/foxio/h2-server.tls")
	if err != nil {
		t.Fatal(err)
	}
	for _, clientFirst := range []bool{true, false} {
		c, s := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
		frames := [][]byte{buildEthernetIPv4TCPFrame(c, s, 51234, 443, 1, 0, TCPFlagACK, cert), buildEthernetIPv4TCPFrame(s, c, 443, 51234, 1, 0, TCPFlagACK, sh)}
		if !clientFirst {
			frames[0], frames[1] = frames[1], frames[0]
		}
		raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
		cap, err := New(raw)
		if err != nil {
			t.Fatal(err)
		}
		checkReaderParity(t, raw, cap.TLS, cap.TLSFromReaderAt)
		rows, err := cap.TLS(raw)
		if err != nil || len(rows) != 1 {
			t.Fatal(len(rows), err)
		}
		hs := rows[0].Handshake
		if hs.HasCertificateRequest || len(hs.Certificates) != 0 || len(hs.ClientCertificates) != 2 || !bytes.Equal(hs.ClientCertificates[0].RawDER, chain[0]) {
			t.Fatalf("incorrect attribution, clientFirst=%t", clientFirst)
		}
	}
}
