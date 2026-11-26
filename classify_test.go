package pcap

import (
	"encoding/binary"
	"testing"
)

func TestClassifyL7(t *testing.T) {
	dns := "\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
	krb := buildKRB5ASReqFixture("EXAMPLE.COM", "user", []string{"krbtgt", "EXAMPLE.COM"}, []int{18})
	krbTCP := binary.BigEndian.AppendUint32(nil, uint32(len(krb)))
	krbTCP = append(krbTCP, krb...)

	for _, tc := range []struct {
		name, payload string
		transport     uint8
		src, dst      uint16
		want          L7Protocol
	}{
		{"empty", "", IPProtoTCP, 53, 88, L7Unknown},
		{"other transport", "GET ", IPProtoICMP, 0, 0, L7Unknown},
		{"HTTP request off port", "OPTIONS ", IPProtoTCP, 2345, 3456, L7HTTP1},
		{"HTTP response", "HTTP/1.", IPProtoTCP, 2345, 53, L7HTTP1},
		{"HTTP partial method", "OPTIONS", IPProtoTCP, 2345, 3456, L7Unknown},
		{"HTTP nonstandard method", "GETTER ", IPProtoTCP, 2345, 3456, L7Unknown},
		{"HTTP over UDP", "GET ", IPProtoUDP, 2345, 3456, L7Unknown},
		{"HTTP2 client preface", http2ClientPreface, IPProtoTCP, 2345, 3456, L7HTTP2},
		{"HTTP2 partial preface", http2ClientPreface[:23], IPProtoTCP, 2345, 3456, L7Unknown},
		{"SSH", "SSH-2.0-example", IPProtoTCP, 2345, 3456, L7SSH},
		{"SMB2 session frame", "\x00\x00\x00\x40\xfeSMB", IPProtoTCP, 2345, 3456, L7SMB2},
		{"SMB3 transform", "\x00\x00\x00\x34\xfdSMB", IPProtoTCP, 2345, 3456, L7SMB3Encrypted},
		{"SMB3 incomplete signature", "\x00\x00\x00\x34\xfdSM", IPProtoTCP, 2345, 3456, L7Unknown},
		{"SMB3 without session marker", "\x01\x00\x00\x34\xfdSMB", IPProtoTCP, 2345, 3456, L7Unknown},
		{"TLS ClientHello", "\x16\x03\x01\x00\x64\x01", IPProtoTCP, 2345, 3456, L7TLS},
		{"TLS ServerHello", "\x16\x03\x03\x00\x60\x02", IPProtoTCP, 2345, 3456, L7TLS},
		{"TLS other handshake", "\x16\x03\x03\x00\x60\x0b", IPProtoTCP, 2345, 443, L7Unknown},
		{"TLS unsupported version", "\x16\x03\x05\x00\x64\x01", IPProtoTCP, 2345, 443, L7Unknown},
		{"RDP connection request", "\x03\x00\x00\x0b\x06\xe0\x00\x00\x00\x00\x00", IPProtoTCP, 2345, 3456, L7RDP},
		{"RDP connection confirm", "\x03\x00\x00\x0b\x06\xd0\x00\x00\x00\x00\x00", IPProtoTCP, 2345, 3456, L7RDP},
		{"X.224 data TPDU", "\x03\x00\x00\x0b\x06\xf0\x00\x00\x00\x00\x00", IPProtoTCP, 2345, 3389, L7Unknown},
		{"QUIC v1", "\xc0\x00\x00\x00\x01\x00\x00", IPProtoUDP, 2345, 3456, L7QUIC},
		{"QUIC v2", "\xd0\x6b\x33\x43\xcf\x00\x00", IPProtoUDP, 2345, 3456, L7QUIC},
		{"QUIC short header", "\x40\x00\x00\x00\x01\x00\x00", IPProtoUDP, 2345, 443, L7Unknown},
		{"QUIC unknown version", "\xc0\x00\x00\x00\x03\x00\x00", IPProtoUDP, 2345, 443, L7Unknown},
		{"QUIC over TCP", "\xc0\x00\x00\x00\x01\x00\x00", IPProtoTCP, 2345, 443, L7Unknown},
		{"DNS UDP", dns, IPProtoUDP, 2345, 53, L7DNS},
		{"mDNS UDP", dns, IPProtoUDP, 2345, 5353, L7DNS},
		{"LLMNR UDP", dns, IPProtoUDP, 5355, 2345, L7DNS},
		{"DNS TCP prefix", "\x00\x50" + dns, IPProtoTCP, 53, 2345, L7DNS},
		{"DNS TCP short length", "\x00\x09" + dns, IPProtoTCP, 53, 2345, L7Unknown},
		{"DNS UDP short header", dns[:11], IPProtoUDP, 2345, 53, L7Unknown},
		{"DNS off port", dns, IPProtoUDP, 2345, 3456, L7Unknown},
		{"Kerberos UDP", string(krb), IPProtoUDP, 88, 2345, L7KRB5},
		{"Kerberos TCP prefix", string(krbTCP[:12]), IPProtoTCP, 2345, 88, L7KRB5},
		{"Kerberos TCP short length", "\x00\x00\x00\x07" + string(krb), IPProtoTCP, 88, 2345, L7Unknown},
		{"Kerberos TCP reserved length bit", "\x80" + string(krbTCP[1:]), IPProtoTCP, 88, 2345, L7Unknown},
		{"Kerberos unsupported tag", "\x69" + string(krb[1:]), IPProtoUDP, 2345, 88, L7Unknown},
		{"Kerberos off port", string(krb), IPProtoUDP, 2345, 3456, L7Unknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyL7([]byte(tc.payload), tc.transport, tc.src, tc.dst); got != tc.want {
				t.Fatalf("ClassifyL7 = %d, want %d", got, tc.want)
			}
		})
	}
}

func BenchmarkClassifyL7(b *testing.B) {
	for _, tc := range []struct {
		name, payload string
		transport     uint8
		port          uint16
		want          L7Protocol
	}{
		{"unknown-tcp", "\xa6\x2b\x23\x19\x10\xfb\x8a\x22", IPProtoTCP, 443, L7Unknown},
		{"unknown-http-prefix", "CONNECTX\x00", IPProtoTCP, 443, L7Unknown},
		{"unknown-udp", "\xc0\x00\x00\x00\x03\x00\x00", IPProtoUDP, 443, L7Unknown},
		{"http1-request", "POST /status HTTP/1.1\r\n", IPProtoTCP, 8080, L7HTTP1},
		{"http1-response", "HTTP/1.1 200 OK\r\n", IPProtoTCP, 8080, L7HTTP1},
		{"http2", http2ClientPreface, IPProtoTCP, 8080, L7HTTP2},
		{"ssh", "SSH-2.0-example", IPProtoTCP, 2222, L7SSH},
		{"tls", "\x16\x03\x01\x00\x64\x01", IPProtoTCP, 8443, L7TLS},
		{"smb2", "\x00\x00\x00\x40\xfeSMB", IPProtoTCP, 1445, L7SMB2},
		{"smb3", "\x00\x00\x00\x34\xfdSMB", IPProtoTCP, 1445, L7SMB3Encrypted},
		{"rdp", "\x03\x00\x00\x0b\x06\xe0\x00\x00\x00\x00\x00", IPProtoTCP, 3390, L7RDP},
		{"quic", "\xc0\x00\x00\x00\x01\x00\x00", IPProtoUDP, 8443, L7QUIC},
		{"dns-tcp", "\x00\x50\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00", IPProtoTCP, 53, L7DNS},
		{"dns-udp", "\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00", IPProtoUDP, 53, L7DNS},
		{"kerberos-tcp", "\x00\x00\x00\x30\x6a\x2e\x30\x2c\xa1\x03\x02\x01\x05", IPProtoTCP, 88, L7KRB5},
		{"kerberos-udp", "\x6a\x2e\x30\x2c\xa1\x03\x02\x01\x05", IPProtoUDP, 88, L7KRB5},
	} {
		b.Run(tc.name, func(b *testing.B) {
			data := []byte(tc.payload)
			b.ReportAllocs()
			for b.Loop() {
				if p := ClassifyL7(data, tc.transport, 50321, tc.port); p != tc.want {
					b.Fatalf("ClassifyL7 = %d, want %d", p, tc.want)
				}
			}
		})
	}
}
