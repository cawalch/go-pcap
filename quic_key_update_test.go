package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"testing"
)

func TestKeyedQUICKeyUpdates(t *testing.T) {
	raw, err := os.ReadFile("testdata/quic-key-updates.pcap")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := os.ReadFile("testdata/quic-key-updates.keys")
	if err != nil {
		t.Fatal(err)
	}
	rows := keyedQUICBoth(t, raw, keys)
	if len(rows) != 1 {
		t.Fatalf("got %d keyed connections", len(rows))
	}
	want := map[int]struct {
		pn         uint64
		generation uint8
		body       string
	}{
		7:  {6, 1, "generation-one"},
		9:  {5, 0, "generation-zero"},
		10: {7, 2, "generation-two"},
	}
	for _, packet := range rows[0].Client {
		if packet.PacketIndex == 6 {
			t.Fatal("damaged update authenticated")
		}
		if w, ok := want[packet.PacketIndex]; ok {
			if packet.KeyGeneration != w.generation || packet.PacketNumber != w.pn || !bytes.Contains(packet.Payload, []byte(w.body)) {
				t.Fatalf("packet %d: generation=%d, number=%d", packet.PacketIndex, packet.KeyGeneration, packet.PacketNumber)
			}
			delete(want, packet.PacketIndex)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing updated or delayed packets: %v", want)
	}

	// Erase the two observations of the first client update. The opposite
	// sender's authenticated update cannot advance this sender's keys.
	frames := keyedQUICFrames(t, raw)
	gapped := buildClassicPCAP(binary.LittleEndian, false, LinkTypeRaw, 65535, append(frames[:6], frames[8:]...))
	rows = keyedQUICBoth(t, gapped, keys)
	if len(rows) != 1 {
		t.Fatalf("loss obscured the original connection: %d rows", len(rows))
	}
	for _, packet := range rows[0].Client {
		if packet.KeyGeneration != 0 || bytes.Contains(packet.Payload, []byte("generation-two")) {
			t.Fatal("inferred missing key generation")
		}
	}
}

func TestQUIC1RTTKeyTrackerUpdateLimit(t *testing.T) {
	dcid := []byte{1, 2, 3, 4}
	for _, version := range []uint32{QUICVersion1, QUICVersion2} {
		tracker, err := NewQUIC1RTTKeyTracker(version, TLS_AES_128_GCM_SHA256, make([]byte, 32))
		if err != nil {
			t.Fatal(err)
		}
		for generation := uint8(0); generation <= MaxQUICKeyUpdates+1; generation++ {
			keys := tracker.next
			if generation == 0 {
				keys = tracker.current
			}
			header := append([]byte{0x40 | (generation&1)<<2}, dcid...)
			header = append(header, generation)
			nonce := xorTLS13Nonce(keys.iv, uint64(generation))
			packet := keys.aead.Seal(bytes.Clone(header), nonce[:], []byte{1, 0, 0, 0}, header)
			pnAt := 1 + len(dcid)
			var mask [16]byte
			keys.hp.Encrypt(mask[:], packet[pnAt+4:pnAt+20])
			packet[0] ^= mask[0] & 0x1f
			packet[pnAt] ^= mask[1]
			pn, gotGen, payload, err := tracker.Open(packet, dcid, uint64(generation))
			if generation > MaxQUICKeyUpdates {
				if !errors.Is(err, ErrQUICLimit) || tracker.generation != MaxQUICKeyUpdates {
					t.Fatalf("generation ceiling: %v", err)
				}
				break
			}
			if err != nil || pn != uint64(generation) || gotGen != generation || len(payload) != 4 {
				t.Fatalf("version %#x update %d: PN %d, generation %d, %v", version, generation, pn, gotGen, err)
			}
		}
	}
}

func BenchmarkKeyedQUICKeyUpdates(b *testing.B) {
	raw, err := os.ReadFile("testdata/quic-key-updates.pcap")
	if err != nil {
		b.Fatal(err)
	}
	keys, err := os.ReadFile("testdata/quic-key-updates.keys")
	if err != nil {
		b.Fatal(err)
	}
	r := bytes.NewReader(raw)
	c, err := NewFromReaderAt(r, r.Size())
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := c.KeyedQUICFromReaderAt(r, keys); err != nil {
			b.Fatal(err)
		}
	}
}
