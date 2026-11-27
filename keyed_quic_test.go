package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// The captures are the complete synthetic aioquic 1.3.0 sessions used to
// generate quic-1rtt-vectors.json. TShark 4.6.10 independently decoded the
// packet numbers and STREAM data using the sessions' TLS key logs.
func readKeyedQUICFixture(version int) ([]byte, []byte, error) {
	raw, err := os.ReadFile(fmt.Sprintf("testdata/quic-1rtt-v%d.pcap", version))
	if err != nil {
		return nil, nil, err
	}
	vectors, err := readQUIC1RTTVectors()
	if err != nil {
		return nil, nil, err
	}
	prefix := fmt.Sprintf("version_%d-", version)
	var keys []byte
	for _, v := range vectors {
		if strings.HasPrefix(v.Name, prefix) {
			keys = append(append(keys, v.KeyLog...), '\n')
		}
	}
	if len(keys) == 0 {
		return nil, nil, errors.New("missing QUIC fixture keys")
	}
	return raw, keys, nil
}

func keyedQUICFixture(t testing.TB, version int) ([]byte, []byte) {
	t.Helper()
	raw, keys, err := readKeyedQUICFixture(version)
	if err != nil {
		t.Fatal(err)
	}
	return raw, keys
}

func keyedQUICFrames(t testing.TB, raw []byte) [][]byte {
	t.Helper()
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	var frames [][]byte
	for pkt, err := range c.PacketSeq(raw) {
		if err != nil {
			t.Fatal(err)
		}
		data, err := c.PacketPayload(raw, pkt)
		if err != nil {
			t.Fatal(err)
		}
		frames = append(frames, data)
	}
	return frames
}

func keyedQUICBoth(t *testing.T, raw, keys []byte) []KeyedQUICRecord {
	t.Helper()
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	return checkReaderParity(t, raw,
		func(data []byte) ([]KeyedQUICRecord, error) { return c.KeyedQUIC(data, keys) },
		func(r io.ReaderAt) ([]KeyedQUICRecord, error) { return c.KeyedQUICFromReaderAt(r, keys) })
}

func keyedQUICStreamData(packets []QUIC1RTTPacket) ([]QUICStream, error) {
	var frames [][]byte
	for _, packet := range packets {
		frames = append(frames, packet.Payload)
	}
	return ReassembleQUIC1RTTStreams(frames)
}

func TestKeyedQUICCaptureAssociation(t *testing.T) {
	for _, version := range []int{1, 2} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			raw, keys := keyedQUICFixture(t, version)
			rows := keyedQUICBoth(t, raw, keys)
			if len(rows) != 1 {
				t.Fatalf("got %d connections", len(rows))
			}
			c, err := New(raw)
			if err != nil {
				t.Fatal(err)
			}
			initial, err := c.QUIC(raw)
			if err != nil || len(initial) != 1 || !reflect.DeepEqual(rows[0].QUICRecord, initial[0]) {
				t.Fatalf("Initial metadata = %+v, %v", initial, err)
			}
			r := rows[0]
			if len(r.Client) != 3 || len(r.Server) != 2 {
				t.Fatalf("client=%+v, server=%+v", r.Client, r.Server)
			}
			identity := func(p []QUIC1RTTPacket) [][2]uint64 {
				out := make([][2]uint64, len(p))
				for i, packet := range p {
					out[i] = [2]uint64{uint64(packet.PacketIndex), packet.PacketNumber}
				}
				return out
			}
			if !reflect.DeepEqual(identity(r.Client), [][2]uint64{{2, 3}, {4, 4}, {5, 5}}) ||
				!reflect.DeepEqual(identity(r.Server), [][2]uint64{{3, 2}, {6, 3}}) ||
				r.Client[0].UDPOffset == 0 || r.Client[1].UDPOffset != 0 {
				t.Fatalf("packet provenance client=%+v, server=%+v", r.Client, r.Server)
			}
			for sender, packets := range map[string][]QUIC1RTTPacket{"client": r.Client, "server": r.Server} {
				streams, err := keyedQUICStreamData(packets)
				want := fmt.Sprintf("fixture-version_%d-%s", version, sender)
				if err != nil || len(streams) != 1 || !streams[0].Complete || string(streams[0].Data) != want {
					t.Fatalf("%s streams = %+v, %v", sender, streams, err)
				}
			}
		})
	}
}

func TestKeyedQUICFragmentInterfaceScope(t *testing.T) {
	fixture, keys := keyedQUICFixture(t, 1)
	frames := keyedQUICFrames(t, fixture)
	// The fixture starts with a client Initial in a raw IPv4 packet.
	first := frames[0]
	src, dst := [4]byte(first[12:16]), [4]byte(first[16:20])
	udp := first[20:]
	fragments := [][]byte{
		buildEthernetIPv4FragmentFrame(src, dst, IPProtoUDP, 1, 0, true, udp[:16])[14:],
		buildEthernetIPv4FragmentFrame(src, dst, IPProtoUDP, 1, 16, false, udp[16:])[14:],
	}

	var buf bytes.Buffer
	opts := PCAPNGWriterOptions{LinkType: LinkTypeRaw}
	w, err := NewPCAPNGWriter(&buf, opts)
	if err != nil {
		t.Fatal(err)
	}
	second, err := w.AddInterface(opts)
	if err != nil {
		t.Fatal(err)
	}
	for i, frame := range slices.Concat(fragments, frames[1:]) {
		var pkt PacketRecord
		if i == 1 {
			pkt.InterfaceID = second
		}
		if err := w.WritePacket(pkt, frame); err != nil {
			t.Fatal(err)
		}
	}

	raw := buf.Bytes()
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, separate := range []bool{false, true} {
		c.SeparateIPFragmentInterfaces = separate
		rows := checkReaderParity(t, raw,
			func(data []byte) ([]KeyedQUICRecord, error) { return c.KeyedQUIC(data, keys) },
			func(r io.ReaderAt) ([]KeyedQUICRecord, error) { return c.KeyedQUICFromReaderAt(r, keys) })
		if separate {
			if len(rows) != 0 {
				t.Fatalf("separate interfaces: got %d keyed connections, want none", len(rows))
			}
		} else if len(rows) != 1 || len(rows[0].Client) != 3 || len(rows[0].Server) != 2 {
			t.Fatalf("combined interfaces: keyed connections = %+v, want one complete connection", rows)
		}
	}
}

func TestKeyedQUICRebindingAndTupleReuse(t *testing.T) {
	raw1, keys1 := keyedQUICFixture(t, 1)
	raw2, keys2 := keyedQUICFixture(t, 2)
	v1, v2 := keyedQUICFrames(t, raw1), keyedQUICFrames(t, raw2)
	v1[5] = bytes.Clone(v1[5])
	v1[6] = bytes.Clone(v1[6])
	// Change the client port in both directions while retaining the protected
	// QUIC packets. The fixtures use raw IPv4 without options.
	binary.BigEndian.PutUint16(v1[5][20:22], 45679)
	binary.BigEndian.PutUint16(v1[6][22:24], 45679)
	corrupt := bytes.Clone(v1[5])
	corrupt[len(corrupt)-1] ^= 1

	var buf bytes.Buffer
	writer, err := NewPCAPNGWriter(&buf, PCAPNGWriterOptions{LinkType: LinkTypeRaw})
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteDecryptionSecrets(SecretsTypeTLSKeyLog, keys1); err != nil {
		t.Fatal(err)
	}
	frames := slices.Concat(v1[:5], [][]byte{corrupt}, v1[5:], v2)
	for i, frame := range frames {
		if err := writer.WritePacket(PacketRecord{TimestampNs: int64(i + 1), OriginalLen: uint32(len(frame))}, frame); err != nil {
			t.Fatal(err)
		}
	}
	rows := keyedQUICBoth(t, buf.Bytes(), keys2)
	if len(rows) != 2 || rows[0].Handshake.Version != QUICVersion1 || rows[1].Handshake.Version != QUICVersion2 {
		t.Fatalf("connections = %+v", rows)
	}
	if rows[0].FlowIndex != 0 || rows[1].FlowIndex != 0 ||
		len(rows[0].Client) != 3 || len(rows[0].Server) != 2 ||
		rows[0].Client[2].PacketIndex != 6 || rows[0].Server[1].PacketIndex != 7 ||
		len(rows[1].Client) != 3 || len(rows[1].Server) != 2 ||
		rows[1].Client[2].PacketIndex != 13 || rows[1].Server[1].PacketIndex != 14 {
		t.Fatalf("misassociated packets: %+v", rows)
	}
}

func TestKeyedQUICMissingKeysAndLimits(t *testing.T) {
	raw, keys := keyedQUICFixture(t, 1)
	if rows := keyedQUICBoth(t, raw, nil); len(rows) != 0 {
		t.Fatalf("unkeyed results: %+v", rows)
	}
	clientKey, _, _ := bytes.Cut(keys, []byte{'\n'})
	rows := keyedQUICBoth(t, raw, clientKey)
	if len(rows) != 1 || len(rows[0].Client) != 3 || len(rows[0].Server) != 0 {
		t.Fatalf("single-direction results: %+v", rows)
	}
	frames := keyedQUICFrames(t, raw)
	for range MaxQUICStreamPackets {
		frames = append(frames, frames[5])
	}
	raw = buildClassicPCAP(binary.LittleEndian, true, LinkTypeRaw, 65535, frames)
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	if rows, err := c.KeyedQUIC(raw, keys); rows != nil || !errors.Is(err, ErrQUICLimit) {
		t.Fatalf("slice limit = %+v, %v", rows, err)
	}
	if rows, err := c.KeyedQUICFromReaderAt(bytes.NewReader(raw), keys); rows != nil || !errors.Is(err, ErrQUICLimit) {
		t.Fatalf("reader limit = %+v, %v", rows, err)
	}
}

func TestKeyedQUICRequiresUniqueAuthentication(t *testing.T) {
	vectors, err := readQUIC1RTTVectors()
	if err != nil {
		t.Fatal(err)
	}
	v := vectors[0]
	decoder, err := v.tracker()
	if err != nil {
		t.Fatal(err)
	}
	f := Frame{SrcAddr: netip.MustParseAddr("192.0.2.1"), DstAddr: netip.MustParseAddr("192.0.2.2"), SrcPort: 45678, DstPort: 4433}
	path := keyedQUICPaths(f)[0]
	a := quicKeyedDirection{decoder: decoder}
	b := quicKeyedDirection{decoder: decoder}
	key := quicKeyedCID{path: path, cid: makeQUICCID(v.DestinationCID)}
	s := quicKeyedScan{
		lengths:    map[quicKeyedPath]uint32{path: 1 << len(v.DestinationCID)},
		candidates: map[quicKeyedCID][]*quicKeyedDirection{key: {&a, &b}},
	}
	if match, _, _, payload, err := s.authenticate(f, v.Packet, false); match != nil || payload != nil || err != nil {
		t.Fatalf("ambiguous packet: %v, %x, %v", match, payload, err)
	}
	b.decoder, err = NewQUIC1RTTKeyTracker(v.Version, v.CipherSuite, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if match, number, _, payload, err := s.authenticate(f, v.Packet, false); match != &a || number != v.PacketNumber ||
		!bytes.Equal(payload, v.Plaintext) || err != nil {
		t.Fatalf("unique authentication: %v, %d, %x, %v", match, number, payload, err)
	}
	s.probes = MaxKeyedQUICProbes
	if _, _, _, _, err := s.authenticate(f, v.Packet, false); !errors.Is(err, ErrQUICLimit) {
		t.Fatalf("probe limit: %v", err)
	}
}

func TestKeyedQUICZeroCIDRequiresTuple(t *testing.T) {
	vectors, err := readQUIC1RTTVectors()
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(vectors, func(v quic1RTTVector) bool { return v.Name == "zero-cid-wrap" })
	if i < 0 {
		t.Fatal("missing zero-CID vector")
	}
	v := vectors[i]
	decoder, err := v.tracker()
	if err != nil {
		t.Fatal(err)
	}
	f := Frame{SrcAddr: netip.MustParseAddr("192.0.2.1"), DstAddr: netip.MustParseAddr("192.0.2.2"), SrcPort: 45678, DstPort: 4433}
	path := keyedQUICPaths(f)[0]
	dir := quicKeyedDirection{decoder: decoder, expected: v.ExpectedNumber}
	s := quicKeyedScan{
		lengths:    map[quicKeyedPath]uint32{path: 1},
		candidates: map[quicKeyedCID][]*quicKeyedDirection{{path: path, clientPort: f.SrcPort}: {&dir}},
	}
	match, number, _, _, err := s.authenticate(f, v.Packet, false)
	if err != nil || match != &dir || number != v.PacketNumber {
		t.Fatalf("exact tuple: %v, %d, %v", match, number, err)
	}
	f.SrcPort++
	if match, _, _, _, err := s.authenticate(f, v.Packet, false); match != nil || err != nil || s.probes != 1 {
		t.Fatalf("changed tuple: %v, %v, %d probes", match, err, s.probes)
	}
}

func TestKeyedQUICReaderAtSharedBudget(t *testing.T) {
	raw, keys := keyedQUICFixture(t, 1)
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	m := measuredReaderAt{Reader: bytes.NewReader(raw)}
	if _, err := c.QUICFromReaderAt(&m); err != nil {
		t.Fatal(err)
	}
	budget := scanReadBudget{r: bytes.NewReader(raw), remaining: m.bytesRead}
	source := ipFrameSource{capture: c, reader: &budget, needsPayload: quicInitialPayload}
	rows, err := scanKeyedQUIC(source, keys, false)
	if rows != nil || !errors.Is(err, ErrPacketLimit) || budget.remaining != 0 {
		t.Fatalf("shared budget = %+v, %v, %d bytes left", rows, err, budget.remaining)
	}

	direct := measuredReaderAt{Reader: bytes.NewReader(raw)}
	descriptor := measuredReaderAt{Reader: bytes.NewReader(raw)}
	want, err := c.KeyedQUICFromReaderAt(&direct, keys)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.KeyedQUICFromReaderAt(descriptorReader{&descriptor}, keys)
	if err != nil || !reflect.DeepEqual(got, want) || descriptor.bytesRead != direct.bytesRead {
		t.Fatalf("file-backed reads = %d, direct reads = %d, error %v", descriptor.bytesRead, direct.bytesRead, err)
	}
}

func FuzzQUICShortTail(f *testing.F) {
	for _, version := range []int{1, 2} {
		raw, _ := keyedQUICFixture(f, version)
		for _, frame := range keyedQUICFrames(f, raw) {
			f.Add(frame[28:]) // Raw IPv4 and UDP headers occupy 28 bytes.
		}
	}
	f.Fuzz(func(t *testing.T, datagram []byte) {
		tail, _ := walkQUICLongHeaders(datagram, nil)
		if len(tail) > 0 && (tail[0]&0x80 != 0 || !bytes.HasSuffix(datagram, tail)) {
			t.Fatal("invalid short-header suffix")
		}
	})
}

func BenchmarkKeyedQUIC(b *testing.B) {
	raw, keys := keyedQUICFixture(b, 1)
	c, err := New(raw)
	if err != nil {
		b.Fatal(err)
	}
	for _, mode := range []string{"Slice", "ReaderAt"} {
		b.Run(mode, func(b *testing.B) {
			r := bytes.NewReader(raw)
			b.ReportAllocs()
			for b.Loop() {
				var rows []KeyedQUICRecord
				var err error
				if mode == "Slice" {
					rows, err = c.KeyedQUIC(raw, keys)
				} else {
					rows, err = c.KeyedQUICFromReaderAt(r, keys)
				}
				if err != nil || len(rows) != 1 {
					b.Fatalf("got %d connections, %v", len(rows), err)
				}
			}
		})
	}
}

func ExampleCapture_KeyedQUIC() {
	raw, keys, err := readKeyedQUICFixture(1)
	if err != nil {
		panic(err)
	}
	capture, err := New(raw)
	if err != nil {
		panic(err)
	}
	connections, err := capture.KeyedQUIC(raw, keys)
	if err != nil {
		panic(err)
	}
	for _, conn := range connections {
		fmt.Printf("flow %d, client packets %d, server packets %d\n", conn.FlowIndex, len(conn.Client), len(conn.Server))
	}
	// Output:
	// flow 0, client packets 3, server packets 2
}
