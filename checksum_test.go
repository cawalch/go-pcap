package pcap

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"testing"
)

func TestVerifyIPv4HeaderChecksum(t *testing.T) {
	header := checksumTestBytes(t, "460000350000400040064b8bc0000201c633640201010100")
	if !VerifyIPv4HeaderChecksum(header) || !VerifyIPv4HeaderChecksum(append(bytes.Clone(header), 0xff)) {
		t.Fatal("valid IPv4 header with options was rejected")
	}
	for _, input := range [][]byte{
		nil,
		header[:23],
		append([]byte{0x66}, header[1:]...),
		append([]byte{0x44}, header[1:]...),
		append([]byte{0x46, 0, 0, 20}, header[4:]...),
		append(bytes.Clone(header[:23]), 0x01),
	} {
		if VerifyIPv4HeaderChecksum(input) {
			t.Fatalf("accepted IPv4 header %x", input)
		}
	}
}

func TestVerifyTransportChecksums(t *testing.T) {
	for _, tc := range []struct {
		name, src, dst, wire string
		verify               func(netip.Addr, netip.Addr, []byte) (bool, bool)
		checksumOffset       int
		offload              [2]byte
	}{
		{"TCPv4", "192.0.2.1", "198.51.100.2", "303901bb1122334499aabbcc6010200081ef00000101010068656c6c6f", VerifyTCPChecksum, 16, [2]byte{0xec, 0x5a}},
		{"TCPv6", "2001:db8::1", "2001:db8::2", "303901bb1122334499aabbcc6010200012b200000101010068656c6c6f", VerifyTCPChecksum, 16, [2]byte{0x5b, 0x98}},
		{"UDPv4", "192.0.2.1", "198.51.100.2", "3039270f000d788268656c6c6f", VerifyUDPChecksum, 6, [2]byte{0xec, 0x55}},
		{"UDPv6", "2001:db8::1", "2001:db8::2", "3039270f000d094568656c6c6f", VerifyUDPChecksum, 6, [2]byte{0x5b, 0x93}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src, dst := netip.MustParseAddr(tc.src), netip.MustParseAddr(tc.dst)
			data := checksumTestBytes(t, tc.wire)
			check := func(label string, data []byte, wantValid, wantOffload bool) {
				t.Helper()
				valid, offload := tc.verify(src, dst, data)
				if valid != wantValid || offload != wantOffload {
					t.Errorf("%s: got (%t, %t), want (%t, %t)", label, valid, offload, wantValid, wantOffload)
				}
			}
			check("wire", data, true, false)
			check("short header", data[:7], false, false)
			check("partial payload", data[:len(data)-1], false, false)
			bad := bytes.Clone(data)
			bad[len(bad)-1]++
			check("mismatch", bad, false, false)
			copy(bad[tc.checksumOffset:], tc.offload[:])
			check("pseudo-header sum", bad, false, true)
			clear(bad[tc.checksumOffset : tc.checksumOffset+2])
			check("zero field", bad, false, true)
			if valid, offload := tc.verify(src, netip.Addr{}, data); valid || offload {
				t.Error("accepted a missing destination address")
			}
			other := netip.MustParseAddr("2001:db8::10")
			if dst.Is6() {
				other = netip.MustParseAddr("192.0.2.10")
			}
			if valid, offload := tc.verify(src, other, data); valid || offload {
				t.Error("accepted mixed address families")
			}
		})
	}
}

func TestVerifyTransportChecksumLengthAndZero(t *testing.T) {
	src, dst := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.2")
	tcp := checksumTestBytes(t, "b22801bb1122334499aabbcc60102000000000000101010068656c6c6f")
	if valid, offload := VerifyTCPChecksum(src, dst, tcp); !valid || offload {
		t.Fatal("a valid zero TCP checksum must verify before the offload check")
	}
	shortOffset := bytes.Clone(tcp)
	shortOffset[12] = 4 << 4
	oversized := make([]byte, 65536)
	copy(oversized, tcp)
	for _, data := range [][]byte{tcp[:23], shortOffset, oversized} {
		if valid, offload := VerifyTCPChecksum(src, dst, data); valid || offload {
			t.Fatal("accepted an invalid TCP header or oversized segment")
		}
	}
	udp := checksumTestBytes(t, "a8bb270f000dffff68656c6c6f")
	if valid, offload := VerifyUDPChecksum(src, dst, append(bytes.Clone(udp), 0xff)); !valid || offload {
		t.Fatal("UDP checksum of all ones or trailing padding was rejected")
	}
	for _, length := range []byte{0, 7, 14} {
		udp[5] = length
		if valid, offload := VerifyUDPChecksum(src, dst, udp); valid || offload {
			t.Fatalf("accepted UDP length %d", length)
		}
	}
}

func checksumTestBytes(t testing.TB, data string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(data)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func BenchmarkVerifyTCPChecksum(b *testing.B) {
	src, dst := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.2")
	segment := checksumTestBytes(b, "303901bb1122334499aabbcc6010200081ef00000101010068656c6c6f")
	b.SetBytes(int64(len(segment)))
	b.ReportAllocs()
	for b.Loop() {
		if valid, offload := VerifyTCPChecksum(src, dst, segment); !valid || offload {
			b.Fatal("checksum failed")
		}
	}
}
