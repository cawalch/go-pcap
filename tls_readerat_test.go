package pcap

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
)

// A single unrelated TCP direction crosses the read budget, with fewer than
// MaxSegmentsPerFlow segments. A different flow then carries a ClientHello.
func tlsNoiseFile(t testing.TB, format string) (*Capture, *os.File) {
	t.Helper()
	f := tempCaptureFile(t, nil)
	var write func([]byte) error
	switch format {
	case "PCAP":
		w, err := NewPCAPWriter(f, LinkTypeEthernet, 65535)
		if err != nil {
			t.Fatal(err)
		}
		write = func(frame []byte) error { return w.WritePacket(0, frame) }
	case "PcapNG":
		w, err := NewPCAPNGWriter(f, PCAPNGWriterOptions{LinkType: LinkTypeEthernet, SnapLen: 65535})
		if err != nil {
			t.Fatal(err)
		}
		write = func(frame []byte) error { return w.WritePacket(PacketRecord{}, frame) }
	default:
		t.Fatal(format)
	}
	src, dst := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	const payload = 60 << 10
	frame := buildEthernetIPv4TCPFrame(src, dst, 5000, 443, 1, 0, TCPFlagACK, make([]byte, payload))
	for off := 0; off <= MaxReaderAtScanBytes; off += payload {
		binary.BigEndian.PutUint32(frame[14+20+4:], uint32(1+off))
		if err := write(frame); err != nil {
			t.Fatal(err)
		}
	}
	hello := buildTLS13ClientHelloRecord("late.example", "h2")
	if err := write(buildEthernetIPv4TCPFrame(src, dst, 5000, 12345, 1, 0, TCPFlagACK, hello)); err != nil {
		t.Fatal(err)
	}
	size, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewFromReaderAt(f, size)
	if err != nil {
		t.Fatal(err)
	}
	return c, f
}

func TestTLSFromReaderAtHandshakeBudget(t *testing.T) {
	for _, format := range []string{"PCAP", "PcapNG"} {
		t.Run(format, func(t *testing.T) {
			c, f := tlsNoiseFile(t, format)
			r := &measuredFile{File: f}
			rows, err := c.TLSFromReaderAt(r)
			t.Logf("ReaderAt read %d bytes in %d calls", r.bytesRead, r.calls)
			if err != nil || len(rows) != 1 || rows[0].FlowIndex != 1 || rows[0].Handshake.ClientHello.SNI != "late.example" || r.bytesRead > 1<<20 {
				t.Fatalf("got %d rows, %v after %d bytes in %d reads", len(rows), err, r.bytesRead, r.calls)
			}
			raw := make([]byte, c.fileSize)
			if _, err := f.ReadAt(raw, 0); err != nil {
				t.Fatal(err)
			}
			want, err := c.TLS(raw)
			if err != nil || !reflect.DeepEqual(rows, want) {
				t.Fatalf("file and byte TLS records differ: %v", err)
			}
		})
	}
}

func BenchmarkTLSFromReaderAtMixedTCP(b *testing.B) {
	for _, format := range []string{"PCAP", "PcapNG"} {
		b.Run(format, func(b *testing.B) {
			c, f := tlsNoiseFile(b, format)
			r := &measuredFile{File: f}
			b.ReportAllocs()
			for b.Loop() {
				if _, err := c.TLSFromReaderAt(r); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(r.bytesRead)/float64(b.N), "read-B/op")
			b.ReportMetric(float64(r.calls)/float64(b.N), "reads/op")
		})
	}
}

// Put the client tail before the prefix and capture the server first. Large
// packets force ReaderAt to classify and then recover the deferred tails.
func TestTLSFromReaderAtDeferredProxy(t *testing.T) {
	client, server := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	for _, tc := range []struct {
		name      string
		req, resp []byte
	}{
		{"direct", nil, nil},
		{"CONNECT", []byte(proxyRequest), []byte(proxyResponse)},
		{"SOCKS5", []byte{5, 1, 0, 5, 1, 0, 1, 192, 0, 2, 2, 0, 80}, []byte{5, 0, 5, 0, 0, 1, 192, 0, 2, 2, 0, 80}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cl := append(bytes.Clone(tc.req), buildTLS13ClientHelloRecord("deferred.example", "h2")...)
			sv := append(bytes.Clone(tc.resp), buildTLSServerHelloRecord()...)
			cl = append(cl, make([]byte, 1024)...)
			sv = append(sv, make([]byte, 1024)...)
			for _, gap := range []uint32{0, 8} {
				raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{
					buildEthernetIPv4TCPFrame(server, client, 53212, 5000, 200, 0, TCPFlagACK, sv),
					buildEthernetIPv4TCPFrame(client, server, 5000, 53212, 101+gap, 0, TCPFlagACK, cl[1:]),
					buildEthernetIPv4TCPFrame(client, server, 5000, 53212, 100, 0, TCPFlagACK, cl[:1]),
				})
				c, err := New(raw)
				if err != nil {
					t.Fatal(err)
				}
				rows := checkReaderParity(t, raw, c.TLS, c.TLSFromReaderAt)
				if gap == 0 && (len(rows) != 1 || !rows[0].Handshake.HasClientHello || !rows[0].Handshake.HasServerHello) {
					t.Fatalf("incomplete recovered handshake: %+v", rows)
				}
			}
		})
	}
}

func TestTLSFromReaderAtReusedTupleByteLimit(t *testing.T) {
	src, dst := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	frame := func(port uint16, seq uint32, flags byte, payload []byte) []byte {
		return buildEthernetIPv4TCPFrame(src, dst, 12000, port, seq, 0, flags, payload)
	}
	frames := [][]byte{frame(443, 0, TCPFlagSYN, nil)}
	noise := make([]byte, 60<<10)
	for n := 0; n < MaxFlowStreamBytes; n += len(noise) {
		frames = append(frames, frame(443, 1+uint32(n), TCPFlagACK, noise))
	}
	hello := buildTLS13ClientHelloRecord("reuse.example", "h2")
	// The exhausted side of the reused 5-tuple cannot expose a new hello.
	// A different tuple still has its own byte allowance.
	frames = append(frames, frame(443, 99, TCPFlagSYN, nil), frame(443, 100, TCPFlagACK, hello), frame(8443, 1, TCPFlagACK, hello))
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	rows := checkReaderParity(t, raw, c.TLS, c.TLSFromReaderAt)
	if len(rows) != 1 || rows[0].FlowIndex != 1 {
		t.Fatalf("got %+v", rows)
	}
}

func TestTLSFromReaderAtCandidateApplicationData(t *testing.T) {
	src, dst := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	hello := buildTLS13ClientHelloRecord("opaque.example", "h2")
	wire := bytes.Clone(hello)
	for range 65 {
		wire = append(wire, TLSRecordApplicationData, 3, 3, 0x40, 0)
		wire = append(wire, make([]byte, 16384)...)
	}
	// An incomplete last record is observable even when its body is opaque.
	wire = append(wire, TLSRecordApplicationData, 3, 3, 0x40, 0, 1, 2)
	var frames [][]byte
	for i := 0; i < len(wire); i += 32 << 10 {
		frames = append(frames, buildEthernetIPv4TCPFrame(src, dst, 12345, 45678, 1+uint32(i), 0, TCPFlagACK, wire[i:min(len(wire), i+32<<10)]))
	}
	for _, raw := range [][]byte{
		buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames),
		buildPCAPNGFixture(binary.LittleEndian, []byte("SERVER_HANDSHAKE_TRAFFIC_SECRET "+strings.Repeat("bb", 32)+" "+strings.Repeat("ee", 32)+"\n"), frames),
	} {
		c, err := New(raw)
		if err != nil {
			t.Fatal(err)
		}
		r := &measuredReaderAt{Reader: bytes.NewReader(raw)}
		want, err := c.TLS(raw)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := c.TLSFromReaderAt(r)
		if err != nil || !reflect.DeepEqual(rows, want) {
			t.Fatalf("selective TLS records differ: %v", err)
		}
		if len(rows) != 1 || !rows[0].Handshake.Anomalies.TruncatedRecord || r.bytesRead > 32<<10 {
			t.Fatalf("got %d records after %d bytes", len(rows), r.bytesRead)
		}
	}
}

func TestTLSReaderAtPlanOverlapAndGap(t *testing.T) {
	// The first captured payload owns a conflicting overlap. The bytes after
	// the gap still consume the shared budget and cannot enter the TLS prefix.
	segments := []TCPSegmentInput{{Seq: 100, Flags: TCPFlagSYN}, {Seq: 104, Payload: []byte("D")}, {Seq: 101, Payload: []byte("A")}, {Seq: 112, Payload: []byte("L")}}
	src := []byte("DEFGHabcdefghLMN")
	reader := tlsStreamReader{size: int64(len(src)), budget: scanReadBudget{r: bytes.NewReader(src), remaining: 64}}
	refs := []tlsSegmentRead{{0, 1, 0, 5}, {0, 2, 5, 8}, {0, 3, 13, 3}}
	d, used, err := reader.plan(segments, refs, 0, 10)
	if err != nil || used != 10 || d.size() != 8 {
		t.Fatalf("planned %d contiguous, %d charged: %v", d.size(), used, err)
	}
	got := make([]byte, d.size())
	if err := d.read(&reader, got, 0); err != nil || string(got) != "AbcDEFGH" {
		t.Fatalf("%q, %v", got, err)
	}
}

func TestTLSFromReaderAtSkipsKeyedApplicationTail(t *testing.T) {
	f := newKeyedFixture(t, TLSVersion13)
	body := strings.Repeat("x", 16<<10)
	for i := range 70 {
		f.send(true, TCPFlagACK, f.seal(true, uint64(i), TLSRecordApplicationData, body))
	}
	raw := keyedCapture(t, f.keys, f.packets)
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	want, err := c.TLS(raw)
	if err != nil {
		t.Fatal(err)
	}
	r := &measuredReaderAt{Reader: bytes.NewReader(raw)}
	got, err := c.TLSFromReaderAt(r)
	if err != nil || len(got) != 1 || !reflect.DeepEqual(got, want) {
		t.Fatalf("TLS rows differ after protected Finished: %v", err)
	}
	if r.bytesRead > 48<<10 {
		t.Fatalf("read %d bytes from %d-byte capture after the handshake", r.bytesRead, len(raw))
	}
}

func TestTLSFromReaderAtFinishedBoundary(t *testing.T) {
	chain := sanTestChain(t, []string{"trace.example"}, nil, false)
	cert := certificateTestRecord(chain, true)[5:]
	client, server := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	hello, sh := buildTLS13ClientHelloRecord("trace.example", "h2"), buildTLSServerHelloRecord()
	secret := bytes.Repeat([]byte{0x77}, 32)
	keys := []byte("SERVER_HANDSHAKE_TRAFFIC_SECRET " + strings.Repeat("42", 32) + " " + strings.Repeat("77", 32))
	for _, size := range []int{0, 32} {
		finished := append([]byte{20, 0, 0, byte(size)}, make([]byte, size)...)
		for _, shared := range []bool{false, true} {
			wire := bytes.Clone(sh)
			if shared {
				finished = append(finished, cert...)
			}
			wire = append(wire, encryptTLS13AppDataRecord(t, secret, TLS_AES_128_GCM_SHA256, 0, TLSRecordHandshake, finished)...)
			if !shared {
				wire = append(wire, encryptTLS13AppDataRecord(t, secret, TLS_AES_128_GCM_SHA256, 1, TLSRecordHandshake, cert)...)
			}
			raw := keyedCapture(t, keys, [][]byte{
				buildEthernetIPv4TCPFrame(client, server, 40000, 443, 1, 0, TCPFlagACK, hello),
				buildEthernetIPv4TCPFrame(server, client, 443, 40000, 1, 0, TCPFlagACK, wire),
			})
			c, err := New(raw)
			if err != nil {
				t.Fatal(err)
			}
			rows := checkReaderParity(t, raw, c.TLS, c.TLSFromReaderAt)
			if len(rows) != 1 || (len(rows[0].Handshake.Certificates) != 0) != (size == 0) {
				t.Fatalf("size=%d shared=%t: unexpected certificates", size, shared)
			}
		}
	}
}
