package pcap

import (
	"encoding/binary"
	"io"
	"net/netip"
	"os"
	"slices"
	"testing"
)

func keyedQUICMigrationFixture(t *testing.T, alpn string) ([]byte, []byte) {
	t.Helper()
	raw, err := os.ReadFile("testdata/quic-migration-" + alpn + ".pcap")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := os.ReadFile("testdata/quic-migration-" + alpn + ".keys")
	if err != nil {
		t.Fatal(err)
	}
	return raw, keys
}

func TestKeyedQUICMigrationDoQ(t *testing.T) {
	raw, keys := keyedQUICMigrationFixture(t, "doq")
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	rows := checkReaderParity(t, raw,
		func(data []byte) ([]DoQTransaction, error) { return c.DoQTransactions(data, keys) },
		func(r io.ReaderAt) ([]DoQTransaction, error) { return c.DoQTransactionsFromReaderAt(r, keys) })
	if len(rows) != 3 {
		t.Fatalf("got %d complete or partial DoQ exchanges, want 3", len(rows))
	}
	for i, label := range []string{"original", "rebound", "migrated"} {
		row := rows[i]
		queryIndex := []int{6, 9, 13}[i]
		replyIndex := queryIndex + 1
		address := []string{"192.0.2.10", "192.0.2.11", "192.0.2.12"}[i]
		if row.StreamID != uint64(i)*4 || row.Query.State != DoQComplete || row.Reply.State != DoQComplete ||
			row.Query.DNS.Questions[0].Name != label+".example" || row.Reply.DNS.Answers[0].Address.String() != address ||
			!slices.Equal(row.Query.PacketIndices, []int{queryIndex}) || !slices.Equal(row.Reply.PacketIndices, []int{replyIndex}) {
			t.Fatalf("%s exchange: %+v", label, row)
		}
	}
}

func TestKeyedQUICMigrationHTTP3(t *testing.T) {
	raw, keys := keyedQUICMigrationFixture(t, "h3")
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	rows := checkReaderParity(t, raw,
		func(data []byte) ([]KeyedHTTP3Transaction, error) { return c.KeyedHTTP3Transactions(data, keys) },
		func(r io.ReaderAt) ([]KeyedHTTP3Transaction, error) {
			return c.KeyedHTTP3TransactionsFromReaderAt(r, keys)
		})
	if len(rows) != 2 {
		t.Fatalf("got %d HTTP/3 transactions, want 2", len(rows))
	}
	for i, label := range []string{"original", "migrated"} {
		row := rows[i]
		queryIndex := []int{9, 13}[i]
		if row.StreamID != uint64(i)*4 || row.StatusCode != 200 || row.Request == nil || row.Response == nil ||
			!row.Request.EndStream || !row.Response.EndStream || string(row.Response.Body) != label ||
			!slices.Equal(row.Request.PacketIndices, []int{queryIndex}) || !slices.Equal(row.Response.PacketIndices, []int{queryIndex + 1}) {
			t.Fatalf("%s transaction: %+v", label, row)
		}
	}
}

func TestKeyedQUICMigrationObservations(t *testing.T) {
	raw, keys := keyedQUICMigrationFixture(t, "doq")
	frames := keyedQUICFrames(t, raw)
	// Copy an already observed migrated datagram onto a third client IP.
	// The IP header is outside the authenticated QUIC packet.
	replay := slices.Clone(frames[13])
	copy(replay[12:16], netip.MustParseAddr("203.0.113.1").AsSlice())
	for _, tc := range []struct {
		name     string
		frames   [][]byte
		clientPN []uint64
		serverPN []uint64
	}{
		{"observed", frames, []uint64{3, 4, 5, 6, 7, 8, 9, 10}, []uint64{3, 4, 5, 6, 7, 8}},
		{"missing issuance", slices.Concat(frames[:3], frames[5:]), []uint64{4, 5, 6, 7, 8}, []uint64{4, 5, 6}},
		{"missing first migrated packets", slices.Concat(frames[:13], frames[15:]), []uint64{3, 4, 5, 6, 7, 8, 10}, []uint64{3, 4, 5, 6, 8}},
		{"reordered", slices.Concat(frames[:9], frames[10:15], frames[9:10], frames[16:], frames[15:16]), []uint64{3, 4, 5, 6, 8, 9, 7, 10}, []uint64{3, 4, 5, 6, 7, 8}},
		{"replay on a different IP", slices.Concat(frames[:14], [][]byte{replay}, frames[14:]), []uint64{3, 4, 5, 6, 7, 8, 9, 10}, []uint64{3, 4, 5, 6, 7, 8}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeRaw, 65535, tc.frames)
			rows := keyedQUICBoth(t, raw, keys)
			if len(rows) != 1 {
				t.Fatalf("got %d QUIC connections, want 1", len(rows))
			}
			for i, packets := range [][]QUIC1RTTPacket{rows[0].Client, rows[0].Server} {
				want := [][]uint64{tc.clientPN, tc.serverPN}[i]
				got := make([]uint64, 0, len(packets))
				for _, packet := range packets {
					got = append(got, packet.PacketNumber)
				}
				if !slices.Equal(got, want) {
					t.Fatalf("direction %d packet numbers = %v, want %v", i, got, want)
				}
			}
		})
	}
}

func TestKeyedQUICMigrationPayloadScope(t *testing.T) {
	raw, _ := keyedQUICMigrationFixture(t, "doq")
	frames := keyedQUICFrames(t, raw)
	frame, err := DecodeFrame(frames[13], LinkTypeRaw)
	if err != nil {
		t.Fatal(err)
	}
	packet := frames[13][frame.PayloadOffset:]
	prefix := packet[:9] // Short header and the fixture's eight-byte DCID.
	path := keyedQUICPaths(frame)[0]
	cid := makeQUICCID(prefix[1:])
	lookups := quicKeyedScan{
		lengths:    map[quicKeyedPath]uint32{path.anyClient(): 1 << cid.length},
		candidates: map[quicKeyedCID][]*quicKeyedDirection{{path: path.anyClient(), cid: cid}: {{}}},
	}
	if !lookups.needsPayload(frame, prefix) || !lookups.needsPayload(frame, prefix[:1]) {
		t.Fatal("migration candidate was excluded by its prefix")
	}
	unissuedID := slices.Clone(prefix)
	unissuedID[1] ^= 1
	longHeader := slices.Clone(prefix)
	longHeader[0] |= 0x80
	if lookups.needsPayload(frame, unissuedID) || lookups.needsPayload(frame, longHeader) {
		t.Fatal("unrelated traffic entered the migration lookup")
	}
	frame.DstPort++
	if lookups.needsPayload(frame, prefix) {
		t.Fatal("migration candidate widened to a different server port")
	}
}
