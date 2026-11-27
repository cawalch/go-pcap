package pcap_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/metrics"
	"sync"
	"testing"
	"time"

	pcap "github.com/cawalch/go-pcap"
)

type workloadReader struct {
	io.ReaderAt
	calls, readBytes int64
	ctx              context.Context
	cancel           context.CancelFunc
	canceledAt       time.Time
}

func (r *workloadReader) ReadAt(p []byte, off int64) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := r.ReaderAt.ReadAt(p, off)
	r.calls++
	r.readBytes += int64(n)
	if r.cancel != nil {
		r.canceledAt = time.Now()
		r.cancel()
		r.cancel = nil
	}
	return n, err
}

// Mirror a file-backed consumer that preserves the Fd capability across its
// cancellation wrapper. The library uses that capability to enable prefetch.
type workloadFile struct {
	*workloadReader
	file *os.File
}

func (r workloadFile) Fd() uintptr { return r.file.Fd() }

type workloadScan func(*pcap.Capture, io.ReaderAt) (int, error)

var workloadScans = [...]workloadScan{
	func(c *pcap.Capture, r io.ReaderAt) (int, error) {
		rows, err := c.DNSFromReaderAt(r)
		return len(rows), err
	},
	func(c *pcap.Capture, r io.ReaderAt) (int, error) {
		rows, err := c.TLSFromReaderAt(r)
		return len(rows), err
	},
	func(c *pcap.Capture, r io.ReaderAt) (int, error) {
		rows, err := c.HTTP1TransactionsFromReaderAt(r)
		return len(rows), err
	},
	func(c *pcap.Capture, r io.ReaderAt) (int, error) {
		rows, err := c.HTTP2TransactionsFromReaderAt(r)
		return len(rows), err
	},
}

func workloadCapture(b testing.TB, mixed bool) []byte {
	b.Helper()
	if !mixed {
		data, err := os.ReadFile("testdata/deployments/client.pcapng")
		if err != nil {
			b.Fatal(err)
		}
		return data
	}
	var raw bytes.Buffer
	w, err := pcap.NewPCAPNGWriter(&raw, pcap.PCAPNGWriterOptions{LinkType: pcap.LinkTypeEthernet})
	if err != nil {
		b.Fatal(err)
	}
	for i := range 8192 {
		// Independent, unrelated TCP and UDP flows with one KiB captured each.
		frame := make([]byte, 1024)
		frame[12], frame[14], frame[22], frame[23] = 8, 0x45, 64, pcap.IPProtoTCP
		binary.BigEndian.PutUint16(frame[16:], uint16(len(frame)-14))
		copy(frame[26:34], []byte{192, 0, 2, 100, 198, 51, 100, 100})
		binary.BigEndian.PutUint16(frame[34:], uint16(20000+i))
		binary.BigEndian.PutUint16(frame[36:], 15000)
		frame[46], frame[47] = 0x50, 0x10
		if i%2 == 0 {
			frame[23] = pcap.IPProtoUDP
			binary.BigEndian.PutUint16(frame[38:], uint16(len(frame)-34))
		}
		if err := w.WritePacket(pcap.PacketRecord{TimestampNs: int64(i + 1)}, frame); err != nil {
			b.Fatal(err)
		}
	}
	for _, name := range []string{"client", "http1-transactions", "http2-transactions"} {
		data, err := os.ReadFile("testdata/deployments/" + name + ".pcapng")
		if err != nil {
			b.Fatal(err)
		}
		c, err := pcap.New(data)
		if err != nil {
			b.Fatal(err)
		}
		for pkt, err := range c.PacketSeq(data) {
			if err != nil {
				b.Fatal(err)
			}
			payload, err := c.PacketPayload(data, pkt)
			if err != nil {
				b.Fatal(err)
			}
			pkt.InterfaceID = 0
			if err := w.WritePacket(pkt, payload); err != nil {
				b.Fatal(err)
			}
		}
	}
	return raw.Bytes()
}

func BenchmarkEmbeddedCaptureWorkload(b *testing.B) {
	for _, input := range []string{"tiny", "mixed"} {
		raw := workloadCapture(b, input == "mixed")
		path := filepath.Join(b.TempDir(), input+".pcapng")
		if err := os.WriteFile(path, raw, 0600); err != nil {
			b.Fatal(err)
		}
		disk, err := os.Open(path)
		if err != nil {
			b.Fatal(err)
		}
		b.Cleanup(func() {
			if err := disk.Close(); err != nil {
				b.Error(err)
			}
		})
		for _, source := range []string{"bytes", "file"} {
			b.Run(input+"/"+source, func(b *testing.B) {
				var base io.ReaderAt = bytes.NewReader(raw)
				if source == "file" {
					base = disk
				}
				for _, mode := range []string{"dns", "tls", "all", "parallel"} {
					b.Run(mode, func(b *testing.B) {
						benchmarkWorkload(b, base, int64(len(raw)), mode)
					})
				}
			})
		}
	}
}

func benchmarkWorkload(b *testing.B, base io.ReaderAt, size int64, mode string) {
	var operations []workloadScan
	switch mode {
	case "dns":
		operations = workloadScans[:1]
	case "tls":
		operations = workloadScans[1:2]
	default:
		operations = workloadScans[:]
	}
	var calls, bytesRead, rows int64
	// Sample heap separately from timed comparisons. Report the largest
	// observed heap-object total above the fixture's initial heap.
	if os.Getenv("GO_PCAP_MEASURE_WORKLOAD_HEAP") == "1" {
		stop := make(chan struct{})
		peak := make(chan uint64, 1)
		started := make(chan struct{})
		go sampleWorkloadHeap(stop, peak, started)
		<-started
		defer func() {
			close(stop)
			b.ReportMetric(float64(<-peak), "peak-heap-B")
		}()
	}
	b.ReportAllocs()
	for b.Loop() {
		opened := &workloadReader{ReaderAt: base, ctx: context.Background()}
		inputFor := func(r *workloadReader) io.ReaderAt {
			if f, ok := base.(*os.File); ok {
				return workloadFile{workloadReader: r, file: f}
			}
			return r
		}
		c, err := pcap.NewFromReaderAt(inputFor(opened), size)
		if err != nil {
			b.Fatal(err)
		}
		calls += opened.calls
		bytesRead += opened.readBytes
		var results [len(workloadScans)]struct {
			n, calls, readBytes int64
			err                 error
		}
		run := func(i int, scan workloadScan) {
			reader := &workloadReader{ReaderAt: base, ctx: context.Background()}
			n, err := scan(c, inputFor(reader))
			result := &results[i]
			result.n, result.calls, result.readBytes, result.err = int64(n), reader.calls, reader.readBytes, err
		}
		if mode == "parallel" {
			var wg sync.WaitGroup
			for i, scan := range operations {
				wg.Go(func() { run(i, scan) })
			}
			wg.Wait()
		} else {
			for i, scan := range operations {
				run(i, scan)
			}
		}
		for _, result := range results[:len(operations)] {
			if result.err != nil {
				b.Fatal(result.err)
			}
			calls += result.calls
			bytesRead += result.readBytes
			rows += result.n
		}
	}
	b.ReportMetric(float64(calls)/float64(b.N), "reads/op")
	b.ReportMetric(float64(bytesRead)/float64(b.N), "read-B/op")
	b.ReportMetric(float64(rows)/float64(b.N), "rows/op")
}

func TestEmbeddedCaptureWorkloadCancellation(t *testing.T) {
	if testing.Short() {
		t.Skip("mixed capture")
	}
	raw := workloadCapture(t, true)
	base := bytes.NewReader(raw)
	c, err := pcap.NewFromReaderAt(base, int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	for i, scan := range workloadScans {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			reader := &workloadReader{ReaderAt: base, ctx: ctx, cancel: cancel}
			n, err := scan(c, reader)
			if !errors.Is(err, context.Canceled) || n != 0 || reader.calls != 1 {
				t.Fatalf("got %d rows after %d reads, err=%v", n, reader.calls, err)
			}
			t.Logf("read %d bytes; return after cancellation %s", reader.readBytes, time.Since(reader.canceledAt))
		})
	}
}

func sampleWorkloadHeap(stop <-chan struct{}, peak chan<- uint64, started chan<- struct{}) {
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	sample := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	metrics.Read(sample)
	initial := sample[0].Value.Uint64()
	var high uint64
	close(started)
	for {
		select {
		case <-stop:
			peak <- high
			return
		case <-ticker.C:
			metrics.Read(sample)
			if n := sample[0].Value.Uint64(); n > initial {
				high = max(high, n-initial)
			}
		}
	}
}
