package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"reflect"
	"slices"
	"testing"
)

func quicALPNRows(t *testing.T, raw, keys []byte) []KeyedQUICRecord {
	t.Helper()
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	want, err := c.KeyedQUICWithALPN(raw, keys)
	if err != nil {
		t.Fatal(err)
	}
	r := &measuredReaderAt{Reader: bytes.NewReader(raw)}
	got, err := c.KeyedQUICWithALPNFromReaderAt(r, keys)
	if err != nil || !reflect.DeepEqual(got, want) || r.bytesRead > MaxReaderAtScanBytes {
		t.Fatalf("ReaderAt parity error %v after %d bytes", err, r.bytesRead)
	}
	return got
}

// aioquic 1.3.0 endpoints produced these captures, and TShark independently
// locates each selected ALPN in the second frame's EncryptedExtensions.
func TestQUICALPNEndpoints(t *testing.T) {
	for _, tc := range []struct {
		file, key, selected string
		offers              []string
	}{
		{"http3-framing.pcapng", "", "h3", []string{"h3"}},
		{"quic-alpn-doq.pcapng", "", "doq", []string{"h3", "doq", "fixture"}},
		{"quic-1rtt-v2.pcap", "quic-1rtt-v2-handshake.keys", "fixture", []string{"fixture"}},
	} {
		t.Run(tc.selected, func(t *testing.T) {
			raw, err := os.ReadFile("testdata/" + tc.file)
			if err != nil {
				t.Fatal(err)
			}
			var keys []byte
			if tc.key != "" {
				keys, err = os.ReadFile("testdata/" + tc.key)
				if err != nil {
					t.Fatal(err)
				}
			}
			rows := quicALPNRows(t, raw, keys)
			if len(rows) != 1 || rows[0].ALPN == nil || rows[0].ALPN.Protocol != tc.selected || !slices.Equal(rows[0].ALPN.PacketIndices, []int{1}) ||
				!slices.Equal(rows[0].Handshake.ClientHello.ALPNs, tc.offers) {
				t.Fatalf("unexpected selection or offer: %+v", rows)
			}
			if tc.selected == "doq" && len(rows[0].Client)+len(rows[0].Server) != 0 {
				t.Fatal("expected handshake-only row")
			}
			if tc.key != "" {
				appRaw, appKeys := keyedQUICFixture(t, 2)
				legacy := keyedQUICBoth(t, appRaw, appKeys)
				app := quicALPNRows(t, appRaw, appKeys)
				if !reflect.DeepEqual(app, legacy) || len(app) != 1 || app[0].ALPN != nil {
					t.Fatal("app-only key changed ordinary output")
				}
				wrong := bytes.Fields(keys)
				wrong[2] = bytes.Repeat([]byte{'0'}, len(wrong[2]))
				if r := quicALPNRows(t, raw, bytes.Join(wrong, []byte{' '})); len(r) != 0 {
					t.Fatal("wrong handshake key yielded a row")
				}
				if r := quicALPNRows(t, raw, nil); len(r) != 0 {
					t.Fatal("absent keys yielded a row")
				}
				if r := keyedQUICBoth(t, raw, keys); len(r) != 0 {
					t.Fatal("legacy scan emitted a handshake-only row")
				}
			}
		})
	}
}

// Re-packetize the endpoint's original EncryptedExtensions under its real
// handshake secret. The packet numbers and CRYPTO offsets vary independently.
func TestQUICALPNReorderedAndGapped(t *testing.T) {
	raw, err := os.ReadFile("testdata/quic-alpn-doq.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := c.TLSKeyLog(nil)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := c.QUIC(raw)
	if err != nil || len(initial) != 1 {
		t.Fatal("no fixture Initial", err)
	}
	hs := initial[0].Handshake
	decoder, err := NewQUIC1RTTDecoder(hs.Version, hs.ServerHello.CipherSuite, keys.Entries[hs.ClientHello.Random].ServerHandshakeSecret)
	if err != nil {
		t.Fatal(err)
	}
	frames := keyedQUICFrames(t, raw)
	server, err := DecodeFrame(frames[1], LinkTypeRaw)
	if err != nil {
		t.Fatal(err)
	}
	wire := frames[1][server.PayloadOffset : server.PayloadOffset+server.PayloadLength]
	var packet, crypto []byte
	var offset int
	_, err = walkQUICLongHeaders(wire, func(_ uint32, _ []byte, pn int, p []byte) error {
		packet, offset = p, pn
		_, plain, err := decoder.openPacket(p, pn, 0, 0x0f, 0x0c)
		if err != nil {
			return err
		}
		return visitQUICCryptoFrames(plain, func(ch quicCryptoChunk) error {
			if ch.offset == 0 {
				crypto = ch.data
			}
			return nil
		})
	})
	if err != nil || len(crypto) < 8 {
		t.Fatal("missing server CRYPTO", err)
	}
	// Retain just the server Initial from its coalesced datagram.
	h, err := ParseQUICInitialPacket(wire)
	if err != nil {
		t.Fatal(err)
	}
	initialWire := wire[:h.PacketLength]
	n := 4 + (int(crypto[1])<<16 | int(crypto[2])<<8 | int(crypto[3]))
	seal := func(num uint16, start int, b []byte) []byte {
		var plain bytes.Buffer
		plain.WriteByte(6)
		appendQUICVarint2(&plain, uint16(start))
		appendQUICVarint2(&plain, uint16(len(b)))
		plain.Write(b)
		for plain.Len() < 24 {
			plain.WriteByte(0)
		}
		_, _, cidEnd, _ := quicConnectionIDs(packet)
		header := bytes.NewBuffer(bytes.Clone(packet[:cidEnd]))
		header.Bytes()[0] = packet[0]&0xf0 | 1
		appendQUICVarint2(header, uint16(2+plain.Len()+16))
		pn := header.Len()
		header.Write([]byte{byte(num >> 8), byte(num)})
		aad := header.Bytes()
		nonce := xorTLS13Nonce(decoder.keys.iv, uint64(num))
		sealed := decoder.keys.aead.Seal(bytes.Clone(aad), nonce[:], plain.Bytes(), aad)
		var mask [16]byte
		decoder.keys.hp.Encrypt(mask[:], sealed[pn+4:pn+20])
		sealed[0] ^= mask[0] & 0x0f
		sealed[pn] ^= mask[1]
		sealed[pn+1] ^= mask[2]
		return sealed
	}
	frame := func(b []byte) []byte {
		return buildEthernetIPv4UDPFrame(server.SrcAddr.As4(), server.DstAddr.As4(), server.SrcPort, server.DstPort, b)[14:]
	}
	tail := seal(12, 7, crypto[7:n])
	prefix := seal(11, 0, crypto[:7])
	equal := seal(13, 0, crypto[:7])
	bad := bytes.Clone(crypto[:7])
	bad[6] ^= 1
	for _, tc := range []struct {
		name      string
		datagrams [][]byte
		owners    []int
	}{
		{"reordered retransmission", [][]byte{tail, prefix, equal}, []int{1, 2}},
		{"gap", [][]byte{seal(12, 8, crypto[8:n]), prefix}, nil},
		{"conflict", [][]byte{tail, prefix, seal(13, 0, bad)}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			capture := [][]byte{frames[0], frame(append(bytes.Clone(initialWire), tc.datagrams[0]...))}
			for _, p := range tc.datagrams[1:] {
				capture = append(capture, frame(p))
			}
			changed := buildClassicPCAP(binary.LittleEndian, false, LinkTypeRaw, 65535, capture)
			rows := quicALPNRows(t, changed, c.Secrets[0].Data)
			if tc.owners == nil {
				if len(rows) != 0 {
					t.Fatal("ambiguous selection")
				}
				return
			}
			if len(rows) != 1 || rows[0].ALPN == nil || rows[0].ALPN.Protocol != "doq" || !slices.Equal(rows[0].ALPN.PacketIndices, tc.owners) {
				t.Fatalf("rows: %+v", rows)
			}
		})
	}
	s := quicKeyedScan{probes: MaxKeyedQUICProbes - 1, handshakes: make(map[quicKeyedCID][]*quicALPNDirection)}
	cid, _, _, _ := quicConnectionIDs(packet)
	k := quicKeyedCID{path: keyedQUICPaths(server)[1], cid: makeQUICCID(cid)}
	if len(cid) == 0 {
		k.clientPort = server.DstPort
	}
	d := &quicALPNDirection{decoder: decoder, version: hs.Version}
	s.handshakes[k] = []*quicALPNDirection{d, d}
	if err := s.observeHandshake(0, server, hs.Version, cid, offset, packet); !errors.Is(err, ErrQUICLimit) || len(d.chunks) != 0 {
		t.Fatal("probe ceiling or ambiguous commit", err)
	}
	s.probes = 0
	if err := s.observeHandshake(0, server, hs.Version, cid, offset, packet); err != nil || len(d.chunks) != 0 || d.expected != 0 {
		t.Fatal("ambiguous packet attributed", err)
	}
}

func TestQUICALPNSingleProtocol(t *testing.T) {
	for _, body := range [][]byte{
		{0, 10, 0, 16, 0, 6, 0, 4, 1, 'a', 1, 'b'},                    // A server cannot supply a list of alternatives.
		{0, 7, 0, 16, 0, 3, 0, 1, 0},                                  // Empty name.
		{0, 8, 0, 16, 0, 4, 0, 2, 1, 'a', 0},                          // Trailing bytes outside the extensions vector.
		{0, 16, 0, 16, 0, 4, 0, 2, 1, 'a', 0, 16, 0, 4, 0, 2, 1, 'b'}, // Two ALPN extensions.
	} {
		if got := encryptedExtensionsALPN(body); got != "" {
			t.Fatalf("unexpected ALPN %q", got)
		}
	}
}
