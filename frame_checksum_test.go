package pcap

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

const checksumFixtureIPv4TCP = "460000350000400040064b8bc0000201c633640201010100" +
	"303901bb1122334499aabbcc6010200081ef00000101010068656c6c6f"

func TestDecodeFrameWithChecksumsIPv4(t *testing.T) {
	frame := append([]byte{12: 0x08, 13: 0x00}, checksumTestBytes(t, checksumFixtureIPv4TCP)...)
	frame = append(frame, 0xaa, 0xff) // Ethernet padding.
	const ip, tcp = 14, 14 + 24
	for _, tc := range []struct {
		name         string
		edit         func([]byte) []byte
		badIP, badL4 bool
	}{
		{"valid", nil, false, false},
		{"IPv4 mismatch", func(b []byte) []byte { b[ip+8]--; return b }, true, false},
		{"TCP mismatch", func(b []byte) []byte { b[len(b)-3]++; return b }, false, true},
		{"pseudo-header sum", func(b []byte) []byte { copy(b[tcp+16:], []byte{0xec, 0x5a}); return b }, false, false},
		{"zero checksum", func(b []byte) []byte { clear(b[tcp+16 : tcp+18]); return b }, false, false},
		{"short capture", func(b []byte) []byte { b[ip+8]--; return b[:len(b)-3] }, false, false},
		{"bad data offset", func(b []byte) []byte { b[tcp+12] = 0; return b }, false, false},
		{"IPv4 fragment", func(b []byte) []byte {
			b[ip+6] = 0x20
			binary.BigEndian.PutUint16(b[ip+10:], 0x6b8b)
			return b
		}, false, false},
		{"source route", func(b []byte) []byte {
			copy(b[ip+20:], []byte{131, 3, 4, 0})
			binary.BigEndian.PutUint16(b[ip+10:], 0xc688)
			b[tcp+16]++
			return b
		}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := bytes.Clone(frame)
			if tc.edit != nil {
				data = tc.edit(data)
			}
			assertChecksumFrame(t, data, LinkTypeEthernet, tc.badIP, tc.badL4)
		})
	}
}

func TestDecodeFrameWithChecksumsIPv6(t *testing.T) {
	const base = "600000000015004020010db800000000000000000000000120010db8000000000000000000000002"
	const udp = "3039270f000d094568656c6c6f"
	for _, tc := range []struct {
		name  string
		next  byte
		ext   string
		badL4 bool
	}{
		{"hop-by-hop", IPProtoHopByHop, "1100000000000000", true},
		{"destination padding", IPProtoIPv6Opts, "1100000000000000", true},
		{"atomic fragment", IPProtoIPv6Frag, "1100000000000000", true},
		{"fragment", IPProtoIPv6Frag, "1100000100000000", false},
		{"active routing", IPProtoIPv6Route, "1100020100000000", false},
		{"completed routing", IPProtoIPv6Route, "1100020000000000", true},
		{"home address", IPProtoIPv6Opts, "1102" + "01020000" + "c91020010db8000000000000000000000003", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := checksumTestBytes(t, base+tc.ext+udp)
			binary.BigEndian.PutUint16(data[4:], uint16(len(data)-40))
			data[6] = tc.next
			assertChecksumFrame(t, data, LinkTypeIPv6, false, false)
			data[len(data)-1]++
			assertChecksumFrame(t, data, LinkTypeIPv6, false, tc.badL4)
		})
	}
}

func TestDecodeFrameWithChecksumsIPIP(t *testing.T) {
	// The outer header has no checksum and the inner packet has a valid one.
	data := checksumTestBytes(t, "450000490000000040040000cb007101cb007102"+checksumFixtureIPv4TCP)
	assertChecksumFrame(t, data, LinkTypeRaw, false, false)
	data[len(data)-1]++
	assertChecksumFrame(t, data, LinkTypeRaw, false, true)
}

func assertChecksumFrame(t *testing.T, data []byte, linkType LinkType, badIP, badL4 bool) {
	t.Helper()
	got, err := DecodeFrameWithChecksums(data, linkType)
	ordinary, ordinaryErr := DecodeFrame(data, linkType)
	if err != nil || ordinaryErr != nil {
		t.Fatalf("decode errors = %v, %v", err, ordinaryErr)
	}
	if got.Anomalies.InvalidIPChecksum != badIP || got.Anomalies.InvalidL4Checksum != badL4 ||
		(got.Anomalies.Any() != (ordinary.Anomalies.Any() || badIP || badL4)) {
		t.Fatalf("anomalies = %+v, want IP mismatch %t, transport mismatch %t", got.Anomalies, badIP, badL4)
	}
	got.Anomalies.InvalidIPChecksum = false
	got.Anomalies.InvalidL4Checksum = false
	if got != ordinary {
		t.Fatal("checksum verification altered decoded fields")
	}
}

func BenchmarkDecodeFrameWithChecksumsIPv4TCP(b *testing.B) {
	data := checksumTestBytes(b, checksumFixtureIPv4TCP)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		f, err := DecodeFrameWithChecksums(data, LinkTypeRaw)
		if err != nil || f.Anomalies.Any() {
			b.Fatalf("decode failed: %v, %+v", err, f.Anomalies)
		}
	}
}

func ExampleDecodeFrameWithChecksums() {
	// IPv4 header, UDP header, and a single data byte from an offline packet.
	data := []byte{
		0x45, 0, 0, 29, 0, 0, 0, 0, 64, IPProtoUDP, 0x8e, 0x99, 192, 0, 2, 1, 198, 51, 100, 2,
		0x30, 0x39, 0x23, 0xab, 0, 9, 0x12, 0x34, 'a',
	}
	f, err := DecodeFrameWithChecksums(data, LinkTypeRaw)
	if err != nil {
		panic(err)
	}
	fmt.Println(f.Anomalies.InvalidIPChecksum, f.Anomalies.InvalidL4Checksum)
	// Output:
	// false true
}
