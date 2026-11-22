package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"
)

func testServiceDNS(kind uint16, binding []byte) []byte {
	msg := []byte{0x12, 0x34, 0x81, 0x80, 0, 0, 0, 1, 0, 0, 0, 1, 3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0}
	msg = binary.BigEndian.AppendUint16(msg, kind)
	msg = append(msg, 0, 1, 0, 0, 0, 60)
	msg = binary.BigEndian.AppendUint16(msg, uint16(len(binding)))
	msg = append(msg, binding...)
	return append(msg, 0, 0, 41, 0x04, 0xd0, 0, 0, 0x80, 0, 0, 0)
}

func testServiceParams() []byte {
	return []byte{0, 1, 0, 0, 1, 0, 6, 2, 'h', '3', 2, 'h', '2', 0, 3, 0, 2, 0x20, 0xfb, 0, 5, 0, 3, 0, 1, 0}
}

func serviceDNSCapture(payload []byte) []byte {
	frames := make([][]byte, 32)
	for i := range frames {
		frames[i] = buildEthernetIPv4UDPFrame([4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}, 53, uint16(50000+i), payload)
	}
	return buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
}

func BenchmarkCaptureServiceDNS(b *testing.B) {
	for _, tc := range []struct {
		name string
		msg  []byte
	}{
		{"Address", buildDNSQueryResponsePacket()},
		{"HTTPS", testServiceDNS(65, testServiceParams())},
	} {
		raw := serviceDNSCapture(tc.msg)
		r := bytes.NewReader(raw)
		c, err := New(raw)
		if err != nil {
			b.Fatal(err)
		}
		cr, err := NewFromReaderAt(r, r.Size())
		if err != nil {
			b.Fatal(err)
		}
		for _, input := range []string{"Slice", "ReaderAt"} {
			b.Run(tc.name+"/"+input, func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					var rows []DNSRecord
					var err error
					if input == "Slice" {
						rows, err = c.DNS(raw)
					} else {
						rows, err = cr.DNSFromReaderAt(r)
					}
					if err != nil || len(rows) != 32 {
						b.Fatal(len(rows), err)
					}
				}
			})
		}
	}
}

func TestDNSServiceBindings(t *testing.T) {
	for _, tc := range []struct {
		kind   uint16
		wire   []byte
		target string
		want   DNSServiceBinding
	}{
		// RFC 9460 Appendix D, Figures 2 and 4.
		{DNSTypeHTTPS, []byte("\x00\x00\x03foo\x07example\x03com\x00"), "foo.example.com", DNSServiceBinding{}},
		{DNSTypeSVCB, []byte("\x00\x10\x03foo\x07example\x03com\x00\x00\x03\x00\x02\x00\x35"), "foo.example.com", DNSServiceBinding{Priority: 16, Port: 53, HasPort: true}},
		{DNSTypeHTTPS, testServiceParams(), "", DNSServiceBinding{Priority: 1, ALPN: []string{"h3", "h2"}, Port: 8443, HasPort: true, HasECHConfig: true}},
		{DNSTypeSVCB, []byte{0, 0, 0, 0, 3, 0, 2, 0, 1}, "", DNSServiceBinding{}},
		{DNSTypeSVCB, []byte{0, 1, 0, 0, 3, 0, 2, 0, 0, 0, 5, 0, 0, 0xff, 0x01, 0, 1, 7}, "", DNSServiceBinding{Priority: 1, HasPort: true}},
	} {
		wire := testServiceDNS(tc.kind, tc.wire)
		msg, err := ParseDNS(wire)
		if err != nil || msg.Anomalies.Any() || len(msg.Answers) != 1 || len(msg.Additionals) != 1 {
			t.Fatal(msg, err)
		}
		ans, opt := msg.Answers[0], msg.Additionals[0]
		if ans.Target != tc.target || !reflect.DeepEqual(ans.ServiceBinding, &tc.want) {
			t.Fatalf("target=%q binding=%+v, want %q %+v", ans.Target, ans.ServiceBinding, tc.target, tc.want)
		}
		if opt.EDNSUDPPayloadSize() != 1232 || !opt.EDNSDOBit() || ans.EDNSUDPPayloadSize() != 0 || ans.EDNSDOBit() {
			t.Fatal(ans, opt)
		}
		raw := serviceDNSCapture(wire)
		c, err := New(raw)
		if err != nil {
			t.Fatal(err)
		}
		r := bytes.NewReader(raw)
		cr, err := NewFromReaderAt(r, r.Size())
		if err != nil {
			t.Fatal(err)
		}
		checkReaderParity(t, raw, c.DNS, cr.DNSFromReaderAt)
		rows, err := c.DNS(raw)
		if err != nil || len(rows) != 32 || !reflect.DeepEqual(rows[0].Message, msg) {
			t.Fatal("capture differs from direct DNS parse", err)
		}
		clear(wire)
		if !reflect.DeepEqual(ans.ServiceBinding, &tc.want) {
			t.Fatal("metadata aliases input")
		}
	}
}

func TestDNSServiceBindingBounds(t *testing.T) {
	for _, data := range [][]byte{nil, {0, 1, 2, 'x'}, {0, 1, 0, 0}, {0, 1, 0, 0, 1, 0, 0}, {0, 1, 0, 0, 1, 0, 1, 0}, {0, 1, 0, 0, 1, 0, 2, 2, 'h'}, {0, 1, 0, 0, 3, 0, 1, 42}, {0, 1, 0, 0, 3, 0, 3, 0, 53}, append(testServiceParams(), 0, 5, 0, 0), append(testServiceParams(), 0, 3, 0, 2, 0, 53)} {
		m, err := ParseDNS(testServiceDNS(DNSTypeHTTPS, data))
		if err != nil || !m.Anomalies.InvalidRDataLength || len(m.Answers) != 1 || m.Answers[0].ServiceBinding != nil || len(m.Additionals) != 1 {
			t.Fatalf("malformed %x: %+v, %v", data, m, err)
		}
	}
	if _, err := ParseDNS(testServiceDNS(DNSTypeHTTPS, []byte{0, 1, 0xc0, 0x0c})); !errors.Is(err, ErrInvalidDNS) {
		t.Fatal("compressed target", err)
	}
	for _, n := range []int{MaxDNSALPNProtocols, MaxDNSALPNProtocols + 1} {
		data := append([]byte{0, 1, 0, 0, 1, 0, byte(2 * n)}, bytes.Repeat([]byte{1, 'x'}, n)...)
		msg, err := ParseDNS(testServiceDNS(DNSTypeHTTPS, data))
		if n == MaxDNSALPNProtocols {
			if err != nil || len(msg.Answers[0].ServiceBinding.ALPN) != n {
				t.Fatal(n, err)
			}
		} else if !errors.Is(err, ErrDNSLimit) {
			t.Fatal(n, err)
		}
	}
}
