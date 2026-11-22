package pcap

import (
	"bytes"
	"encoding/binary"
	"slices"
	"testing"
)

func testTLSExtension(id uint16, data []byte) []byte {
	out := binary.BigEndian.AppendUint16(nil, id)
	out = binary.BigEndian.AppendUint16(out, uint16(len(data)))
	return append(out, data...)
}

func testKeyShareHello(server bool, random [32]byte, extensions []byte) []byte {
	body := []byte{3, 3}
	body = append(body, random[:]...)
	body = append(body, 0) // Empty session ID.
	msg := uint8(TLSHandshakeClientHello)
	if server {
		msg = TLSHandshakeServerHello
		body = append(body, 0x13, 1, 0)
	} else {
		body = append(body, 0, 2, 0x13, 1, 1, 0)
	}
	body = binary.BigEndian.AppendUint16(body, uint16(len(extensions)))
	return wrapTLSHandshakeRecord(msg, append(body, extensions...))
}

func testKeyShareRecords(withShares bool) ([]byte, []byte) {
	client := testTLSExtension(TLSExtSupportedVersions, []byte{2, 3, 4})
	client = append(client, testTLSExtension(TLSExtSupportedGroups, []byte{0, 8, 0x2a, 0x2a, 0x11, 0xec, 0, 29, 0, 23})...)
	server := testTLSExtension(TLSExtSupportedVersions, []byte{3, 4})
	if withShares {
		shares := testTLSExtension(0x2a2a, []byte{0})
		shares = append(shares, testTLSExtension(0x11ec, make([]byte, 1216))...)
		shares = append(shares, testTLSExtension(29, make([]byte, 32))...)
		list := binary.BigEndian.AppendUint16(nil, uint16(len(shares)))
		client = append(client, testTLSExtension(51, append(list, shares...))...)
		client = append(client, testTLSExtension(0xfe0d, []byte{0, 0, 1})...)
		server = append(server, testTLSExtension(51, testTLSExtension(29, make([]byte, 32)))...)
	}
	return testKeyShareHello(false, [32]byte{}, client), testKeyShareHello(true, [32]byte{1}, server)
}

func keyShareCapture(client, server []byte, flows int) []byte {
	var frames [][]byte
	a, b := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	for i := range flows {
		port := uint16(50000 + i)
		frames = append(frames, buildEthernetIPv4TCPFrame(a, b, port, 443, 1, 0, TCPFlagACK, client),
			buildEthernetIPv4TCPFrame(b, a, 443, port, 1, 0, TCPFlagACK, server))
	}
	return buildPCAPNGFixture(binary.LittleEndian, nil, frames)
}

func BenchmarkTLSKeyShare(b *testing.B) {
	for _, profile := range []string{"Absent", "Hybrid"} {
		ch, sh := testKeyShareRecords(profile == "Hybrid")
		raw := keyShareCapture(ch, sh, 16)
		c, err := New(raw)
		if err != nil {
			b.Fatal(err)
		}
		r := bytes.NewReader(raw)
		cr, err := NewFromReaderAt(r, r.Size())
		if err != nil {
			b.Fatal(err)
		}
		for _, input := range []string{"Slice", "ReaderAt"} {
			b.Run(profile+"/"+input, func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					var records []TLSRecord
					var err error
					if input == "Slice" {
						records, err = c.TLS(raw)
					} else {
						records, err = cr.TLSFromReaderAt(r)
					}
					if err != nil || len(records) != 16 {
						b.Fatal(len(records), err)
					}
				}
			})
		}
	}
}

func TestTLSKeyShareCapture(t *testing.T) {
	for _, tc := range []struct {
		shares    bool
		ja4, ja4s string // Captured from main at 6c7bca7 using the same bytes.
	}{
		{false, "t13i010200_0f2cb44170f4_b0ac53b37fa7", "t130100_1301_b9a491fefe05"},
		{true, "t13i010400_0f2cb44170f4_dc622e6146a7", "t130200_1301_a56c5b993250"},
	} {
		client, server := testKeyShareRecords(tc.shares)
		raw := keyShareCapture(client, server, 1)
		c, err := New(raw)
		if err != nil {
			t.Fatal(err)
		}
		r := bytes.NewReader(raw)
		cr, err := NewFromReaderAt(r, r.Size())
		if err != nil {
			t.Fatal(err)
		}
		checkReaderParity(t, raw, c.TLS, cr.TLSFromReaderAt)
		rows, err := c.TLS(raw)
		if err != nil || len(rows) != 1 {
			t.Fatal(len(rows), err)
		}
		ch, sh := rows[0].Handshake.ClientHello, rows[0].Handshake.ServerHello
		var offered []uint16
		var selected uint16
		if tc.shares {
			offered = []uint16{TLSGroupX25519MLKEM768, TLSGroupX25519}
			selected = TLSGroupX25519
		}
		if !slices.Equal(ch.SupportedGroups, []uint16{TLSGroupX25519MLKEM768, TLSGroupX25519, TLSGroupSecp256r1}) ||
			!slices.Equal(ch.KeyShareGroups, offered) || ch.HasECH != tc.shares || sh.SelectedGroup != selected || sh.IsHelloRetryRequest {
			t.Fatalf("supported=%x offered=%x ECH=%t selected=%x retry=%t", ch.SupportedGroups, ch.KeyShareGroups, ch.HasECH, sh.SelectedGroup, sh.IsHelloRetryRequest)
		}
		if ch.JA4 != tc.ja4 || sh.JA4S != tc.ja4s {
			t.Fatalf("fingerprints changed: %s %s", ch.JA4, sh.JA4S)
		}
		qc, err := parseTLSClientHelloWithRecordVersion(client[9:], TLSVersion12, true)
		if err != nil {
			t.Fatal(err)
		}
		qs, err := parseTLSServerHelloWithRecordVersion(server[9:], TLSVersion12, true)
		if err != nil {
			t.Fatal(err)
		}
		if qc.JA4 != "q"+tc.ja4[1:] || qs.JA4S != "q"+tc.ja4s[1:] {
			t.Fatalf("QUIC hello fingerprints changed: %s %s", qc.JA4, qs.JA4S)
		}
	}
}

func TestTLSKeyShareBounds(t *testing.T) {
	for _, vector := range [][]byte{nil, {0}, {0, 0}, {0, 1}, {0, 0, 0}, {0, 3, 0, 29, 0}, {0, 4, 0, 29, 0, 0}, {0, 5, 0, 29, 0, 2, 0}, {0, 6, 0, 29, 0, 1, 1, 0}} {
		ext := append(testTLSExtension(TLSExtKeyShare, vector), testTLSExtension(TLSExtECH, nil)...)
		ch, err := ParseTLSClientHello(testKeyShareHello(false, [32]byte{}, ext)[9:])
		if err != nil || ch.KeyShareGroups != nil || ch.HasECH || !slices.Contains(ch.Extensions, TLSExtECH) {
			t.Fatalf("vector %x: %+v, %v", vector, ch, err)
		}
	}
	var shares, groups []byte
	for i := range MaxTLSExtensions + 2 {
		g := uint16(0x7000 + i)
		shares = append(shares, testTLSExtension(g, []byte{0})...)
		groups = binary.BigEndian.AppendUint16(groups, g)
	}
	ext := testTLSExtension(TLSExtKeyShare, append(binary.BigEndian.AppendUint16(nil, uint16(len(shares))), shares...))
	ext = append(ext, testTLSExtension(TLSExtSupportedGroups, append(binary.BigEndian.AppendUint16(nil, uint16(len(groups))), groups...))...)
	ch, err := ParseTLSClientHello(testKeyShareHello(false, [32]byte{}, bytes.Repeat(ext, 2))[9:])
	if err != nil || len(ch.KeyShareGroups) != MaxTLSExtensions || !slices.Equal(ch.KeyShareGroups, ch.SupportedGroups) || ch.KeyShareGroups[MaxTLSExtensions-1] != 0x7000+MaxTLSExtensions-1 {
		t.Fatalf("capped duplicate extensions: %x, %v", ch.KeyShareGroups, err)
	}
}

func TestTLSServerKeyShareForms(t *testing.T) {
	// RFC 8446 section 4.1.3.
	retry := [32]byte{0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c}
	for _, tc := range []struct {
		random [32]byte
		data   []byte
		want   uint16
	}{
		{retry, []byte{0x11, 0xeb}, TLSGroupSecP256r1MLKEM768},
		{retry, []byte{0, 29, 0, 1, 1}, 0},
		{[32]byte{}, []byte{0, 29}, 0},
		{[32]byte{}, []byte{0, 29, 0, 0}, 0},
		{[32]byte{}, []byte{0, 29, 0, 2, 1}, 0},
		{[32]byte{}, []byte{0, 29, 0, 1, 1, 2}, 0},
	} {
		sh, err := ParseTLSServerHello(testKeyShareHello(true, tc.random, testTLSExtension(TLSExtKeyShare, tc.data))[9:])
		if err != nil || sh.SelectedGroup != tc.want || sh.IsHelloRetryRequest != (tc.random == retry) {
			t.Fatalf("share %x: group=%x retry=%t err=%v", tc.data, sh.SelectedGroup, sh.IsHelloRetryRequest, err)
		}
	}
}
