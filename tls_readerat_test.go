package pcap

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
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
