package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"slices"
	"testing"
)

// A quic-go v0.63.0 server and an aioquic 1.3.0 client each saw these
// request/reply pairs. TShark 4.6.10 identifies both issuers and retirements.
// Frame numbers in this test are one-based to match TShark's display.
func TestKeyedQUICCIDInterop(t *testing.T) {
	raw, err := os.ReadFile("testdata/quic-cid-interop.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	rows := keyedQUICBoth(t, raw, nil)
	if len(rows) != 1 {
		t.Fatalf("got %d connections", len(rows))
	}
	for _, side := range []struct {
		pkts   []QUIC1RTTPacket
		frames []int
		prefix string
	}{
		{rows[0].Client, []int{3, 5, 7}, ""}, {rows[0].Server, []int{2, 4, 6, 8, 9}, "echo "},
	} {
		var idx []int
		for _, p := range side.pkts {
			idx = append(idx, p.PacketIndex+1)
		}
		streams, err := keyedQUICStreamData(side.pkts)
		if !slices.Equal(idx, side.frames) || err != nil || len(streams) != 2 ||
			streams[0].ID != 0 || !streams[0].Complete || string(streams[0].Data) != side.prefix+"before rotation" ||
			streams[1].ID != 4 || !streams[1].Complete || string(streams[1].Data) != side.prefix+"after rotation" {
			t.Fatalf("frames %v, streams %+v, %v", idx, streams, err)
		}
	}
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	frames := keyedQUICFrames(t, raw)
	// Move frame 5 after frame 7. Its packet number 4 proves it preceded
	// the client's packet-number-5 retirement of the original server CID.
	reordered := slices.Concat(frames[:4], frames[5:7], frames[4:5], frames[7:])
	for _, tc := range []struct {
		name   string
		frames [][]byte
		wantPN []uint64
		client bool
	}{
		{"late old CID", reordered, []uint64{3, 5, 4}, true},
		// Removing client frame 3 removes the NEW_CONNECTION_ID for the
		// server's rotated destination. Its initial packet remains usable.
		{"missing issuance", slices.Concat(frames[:2], frames[3:]), []uint64{0}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			classic := buildClassicPCAP(binary.LittleEndian, false, LinkTypeRaw, 65535, tc.frames)
			result := keyedQUICBoth(t, classic, c.Secrets[0].Data)
			if len(result) != 1 {
				t.Fatalf("got %d connections", len(result))
			}
			pkts := result[0].Server
			if tc.client {
				pkts = result[0].Client
			}
			var numbers []uint64
			for _, p := range pkts {
				numbers = append(numbers, p.PacketNumber)
			}
			if !slices.Equal(numbers, tc.wantPN) {
				t.Fatalf("packet numbers %v; want %v", numbers, tc.wantPN)
			}
		})
	}
}

func TestKeyedQUICCIDLifecycle(t *testing.T) {
	newScan := func() (*quicKeyedScan, *quicKeyedDirection) {
		s := &quicKeyedScan{lengths: make(map[quicKeyedPath]uint32), candidates: make(map[quicKeyedCID][]*quicKeyedDirection)}
		initial := makeQUICCID([]byte{0xa0})
		dir := &quicKeyedDirection{initial: quicKeyedCID{cid: initial}, decoder: &QUIC1RTTDecoder{}, packetCID: initial}
		return s, dir
	}
	add := func(seq, prior uint64, id byte) quicCIDChange {
		return quicCIDChange{sequence: seq, prior: prior, id: makeQUICCID([]byte{id})}
	}
	s, d := newScan()
	issue := add(1, 0, 0xa1)
	if err := s.applyCID(d, issue, 3); err != nil {
		t.Fatal(err)
	}
	if err := s.applyCID(d, issue, 4); err != nil || len(s.candidates[quicKeyedCID{cid: issue.id}]) != 1 {
		t.Fatalf("duplicate issuance: %v", err)
	}
	if err := s.applyCID(d, add(2, 1, 0xa2), 5); err != nil || d.ids.accepts(d.initial.cid, 2) {
		t.Fatal("retire prior to did not deactivate sequence zero", err)
	}
	d.packetCID = issue.id
	if err := s.applyCID(d, quicCIDChange{sequence: 0}, 8); err != nil || !d.ids.accepts(d.initial.cid, 7) || d.ids.accepts(d.initial.cid, 8) {
		t.Fatal("retirement packet-number boundary", err)
	}
	// A RETIRE may be observed earlier than its issuance in capture order.
	if err := s.applyCID(d, quicCIDChange{sequence: 3}, 11); err != nil {
		t.Fatal(err)
	}
	if err := s.applyCID(d, add(3, 0, 0xa3), 6); err != nil || !d.ids.accepts(makeQUICCID([]byte{0xa3}), 10) || d.ids.accepts(makeQUICCID([]byte{0xa3}), 12) {
		t.Fatal("out-of-order issuance lost retirement", err)
	}
	issue.token[0] = 1
	if err := s.applyCID(d, issue, 7); err != nil || d.ids.accepts(issue.id, 9) {
		t.Fatal("incompatible reset token was accepted", err)
	}
	for _, tc := range []struct {
		name  string
		count int
		floor bool
		seed  int
	}{
		{"active", MaxKeyedQUICActiveIDs, false, 0},
		{"history", MaxKeyedQUICHistoricalIDs, true, 0},
		{"scan", 1, false, MaxKeyedQUICLearnedIDs},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, d := newScan()
			s.learnedIDs = tc.seed
			for i := 1; i <= tc.count; i++ {
				var floor uint64
				if tc.floor {
					floor = uint64(i)
				}
				err := s.applyCID(d, add(uint64(i), floor, byte(i)), uint64(i))
				if i == tc.count {
					if !errors.Is(err, ErrQUICLimit) {
						t.Fatalf("limit error %v", err)
					}
				} else if err != nil {
					t.Fatalf("early limit: %d: %v", i, err)
				}
			}
		})
	}
	s, d = newScan()
	d.peer = &quicKeyedDirection{decoder: &QUIC1RTTDecoder{}}
	// A peer that originally issued an empty CID cannot issue a replacement.
	newFrame := append([]byte{0x18, 1, 0, 1, 0xab}, bytes.Repeat([]byte{5}, 16)...)
	if err := s.observeCIDs(d, 1, newFrame); err != nil || d.peer.ids != nil {
		t.Fatal("zero-CID issuer created an alternate association", err)
	}
}

func TestKeyedQUICLearnedCIDRequiresUniqueAuthentication(t *testing.T) {
	vectors, err := readQUIC1RTTVectors()
	if err != nil {
		t.Fatal(err)
	}
	v := vectors[0]
	decoder, err := v.decoder()
	if err != nil {
		t.Fatal(err)
	}
	f := Frame{SrcAddr: netip.MustParseAddr("192.0.2.1"), DstAddr: netip.MustParseAddr("192.0.2.2"), SrcPort: 45678, DstPort: 4433}
	path := keyedQUICPaths(f)[0]
	s := quicKeyedScan{lengths: make(map[quicKeyedPath]uint32), candidates: make(map[quicKeyedCID][]*quicKeyedDirection)}
	issue := quicCIDChange{sequence: 1, id: makeQUICCID(v.DestinationCID)}
	for _, id := range []byte{1, 2} {
		dir := &quicKeyedDirection{initial: quicKeyedCID{path: path, cid: makeQUICCID([]byte{id})}, decoder: decoder, expected: v.ExpectedNumber}
		if err := s.applyCID(dir, issue, 1); err != nil {
			t.Fatal(err)
		}
	}
	if dir, _, _, err := s.authenticate(f, v.Packet); err != nil || dir != nil || s.probes != 2 {
		t.Fatalf("authenticated twice: dir=%v probes=%d err=%v", dir, s.probes, err)
	}
	s.probes = MaxKeyedQUICProbes - 1
	if _, _, _, err := s.authenticate(f, v.Packet); !errors.Is(err, ErrQUICLimit) {
		t.Fatalf("shared probe limit: %v", err)
	}
}
