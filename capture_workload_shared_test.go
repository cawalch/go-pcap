package pcap_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"sync"
	"testing"

	pcap "github.com/cawalch/go-pcap"
)

const (
	workloadCacheBytes   = 8 << 20
	workloadCacheEntries = 32768
	workloadWindowBytes  = 16 << 10
)

type workloadReadRange struct {
	off  int64
	size int
}

type workloadReadWindow struct {
	off  int64
	data []byte
}

// workloadReadCache is a sequential, one-capture experiment. It keeps only
// complete reads requested by existing consumers, including their prefetches.
type workloadReadCache struct {
	base          *workloadReader
	physicalLimit int64
	retained      int
	exact         map[workloadReadRange][]byte
	windows       []workloadReadWindow
}

func newWorkloadReadCache(base *workloadReader, physicalLimit int64) *workloadReadCache {
	return &workloadReadCache{base: base, physicalLimit: physicalLimit, exact: make(map[workloadReadRange][]byte)}
}

func (r *workloadReadCache) ReadAt(p []byte, off int64) (int, error) {
	if err := r.base.ctx.Err(); err != nil {
		return 0, err
	}
	if len(p) == 0 {
		return r.base.ReadAt(p, off)
	}
	key := workloadReadRange{off, len(p)}
	if data, ok := r.exact[key]; ok {
		return copy(p, data), nil
	}
	if off >= 0 && len(r.windows) > 0 {
		i := sort.Search(len(r.windows), func(i int) bool { return r.windows[i].off > off })
		if i > 0 {
			window := r.windows[i-1]
			start := off - window.off
			if start <= int64(len(window.data))-int64(len(p)) {
				return copy(p, window.data[int(start):]), nil
			}
		}
	}
	if int64(len(p)) > r.physicalLimit-r.base.readBytes {
		return 0, pcap.ErrPacketLimit
	}
	n, err := r.base.ReadAt(p, off)
	if err == nil && n == len(p) && off >= 0 && len(r.exact) < workloadCacheEntries && len(p) <= workloadCacheBytes-r.retained {
		data := bytes.Clone(p)
		r.exact[key] = data
		r.retained += len(data)
		if len(p) >= workloadWindowBytes {
			i := sort.Search(len(r.windows), func(i int) bool { return r.windows[i].off >= off })
			window := workloadReadWindow{off, data}
			if i == len(r.windows) || r.windows[i].off != off {
				r.windows = slices.Insert(r.windows, i, window)
			} else if len(data) > len(r.windows[i].data) {
				r.windows[i] = window
			}
		}
	}
	return n, err
}

func denseWorkloadCapture(t testing.TB) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/deployments/http1-transactions.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	capture, err := pcap.New(data)
	if err != nil {
		t.Fatal(err)
	}
	// One five-packet exchange from SYN to response, with a different
	// ephemeral port on each copy to produce independent connections.
	var exchange [][]byte
	for pkt, err := range capture.PacketSeq(data) {
		if err != nil {
			t.Fatal(err)
		}
		if pkt.Index < 12 || pkt.Index > 16 {
			continue
		}
		frame, err := capture.PacketPayload(data, pkt)
		if err != nil {
			t.Fatal(err)
		}
		exchange = append(exchange, bytes.Clone(frame))
	}
	if len(exchange) != 5 {
		t.Fatalf("dense workload needs five packets, got %d", len(exchange))
	}
	var raw bytes.Buffer
	writer, err := pcap.NewPCAPNGWriter(&raw, pcap.PCAPNGWriterOptions{LinkType: pcap.LinkTypeEthernet})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 1024 {
		for j, frame := range exchange {
			port := 34
			if j == 1 || j == 4 {
				port = 36
			}
			binary.BigEndian.PutUint16(frame[port:], uint16(20000+i))
			if err := writer.WritePacket(pcap.PacketRecord{TimestampNs: int64(i*len(exchange) + j + 1)}, frame); err != nil {
				t.Fatal(err)
			}
		}
	}
	return raw.Bytes()
}

func TestEmbeddedCaptureWorkloadSharedParity(t *testing.T) {
	if testing.Short() {
		t.Skip("mixed and dense captures")
	}
	type scan func(io.ReaderAt) (any, error)
	for _, name := range []string{"mixed", "dense", "tenant"} {
		t.Run(name, func(t *testing.T) {
			var raw []byte
			switch name {
			case "mixed":
				raw = workloadCapture(t, true)
			case "dense":
				raw = denseWorkloadCapture(t)
			case "tenant":
				var err error
				raw, err = os.ReadFile("testdata/framing/tenant-scope.pcapng")
				if err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(t.TempDir(), name+".pcapng")
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			disk, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := disk.Close(); err != nil {
					t.Error(err)
				}
			})
			for _, base := range []io.ReaderAt{bytes.NewReader(raw), disk} {
				capture, err := pcap.NewFromReaderAt(base, int64(len(raw)))
				if err != nil {
					t.Fatal(err)
				}
				var scans []scan
				if name == "tenant" {
					for _, vni := range []uint32{201, 202} {
						view, err := capture.SelectTenant(pcap.TenantScope{VXLAN: &pcap.VXLANScope{
							VNI: vni, EndpointA: netip.MustParseAddr("203.0.113.1"), EndpointB: netip.MustParseAddr("203.0.113.2"),
						}})
						if err != nil {
							t.Fatal(err)
						}
						scans = append(scans,
							func(r io.ReaderAt) (any, error) { return view.DNSTransactionsFromReaderAt(r) },
							func(r io.ReaderAt) (any, error) { return view.TLSHandshakeEvidenceFromReaderAt(r, nil) },
							func(r io.ReaderAt) (any, error) { return view.HTTP1TransactionsFromReaderAt(r) })
					}
				} else {
					scans = []scan{
						func(r io.ReaderAt) (any, error) { return capture.DNSFromReaderAt(r) },
						func(r io.ReaderAt) (any, error) { return capture.TLSFromReaderAt(r) },
						func(r io.ReaderAt) (any, error) { return capture.HTTP1TransactionsFromReaderAt(r) },
						func(r io.ReaderAt) (any, error) { return capture.HTTP2TransactionsFromReaderAt(r) },
					}
				}
				physical := &workloadReader{ReaderAt: base, ctx: t.Context()}
				shared := workloadWithFD(base, newWorkloadReadCache(physical, pcap.MaxReaderAtScanBytes))
				type outcome struct {
					rows any
					err  error
				}
				parallel := make([]outcome, len(scans))
				var wg sync.WaitGroup
				for i, scan := range scans {
					wg.Go(func() { parallel[i].rows, parallel[i].err = scan(base) })
				}
				wg.Wait()
				var targets []string
				for i, scan := range scans {
					want, err := scan(base)
					if err != nil {
						t.Fatal(err)
					}
					got, err := scan(shared)
					if err != nil || !reflect.DeepEqual(got, want) || parallel[i].err != nil || !reflect.DeepEqual(parallel[i].rows, want) {
						t.Fatalf("%T scan %d parity failed, shared error %v, parallel error %v", base, i, err, parallel[i].err)
					}
					if tx, ok := got.([]pcap.HTTP1Transaction); ok {
						if name == "dense" && len(tx) != 1024 {
							t.Fatalf("dense workload has %d HTTP rows", len(tx))
						}
						if name == "tenant" {
							if len(tx) != 1 {
								t.Fatalf("expected one HTTP transaction in tenant, got %d", len(tx))
							}
							targets = append(targets, tx[0].Request.Target)
						}
					}
				}
				if name == "tenant" && targets[0] == targets[1] {
					t.Fatalf("expected distinct tenant targets, got %v", targets)
				}
			}
		})
	}
}

func TestEmbeddedCaptureWorkloadSharedLimits(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	raw := make([]byte, workloadWindowBytes+2)
	raw[1] = 42
	physical := &workloadReader{ReaderAt: bytes.NewReader(raw), ctx: ctx}
	shared := newWorkloadReadCache(physical, workloadWindowBytes)
	if _, err := shared.ReadAt(make([]byte, workloadWindowBytes), 0); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if n, err := shared.ReadAt(b[:], 1); err != nil || n != 1 || b[0] != 42 || physical.calls != 1 {
		t.Fatalf("cached read returned %v, %d, %v after %d calls", b, n, err, physical.calls)
	}
	if n, err := shared.ReadAt(b[:], workloadWindowBytes); !errors.Is(err, pcap.ErrPacketLimit) || n != 0 || physical.calls != 1 {
		t.Fatalf("exhausted read returned %d, %v after %d calls", n, err, physical.calls)
	}
	cancel()
	if n, err := shared.ReadAt(b[:], 1); !errors.Is(err, context.Canceled) || n != 0 || physical.calls != 1 {
		t.Fatalf("canceled read returned %d, %v after %d calls", n, err, physical.calls)
	}

	fixture := workloadCapture(t, false)
	source := bytes.NewReader(fixture)
	capture, err := pcap.NewFromReaderAt(source, int64(len(fixture)))
	if err != nil {
		t.Fatal(err)
	}
	blocked := &workloadReader{ReaderAt: source, ctx: t.Context()}
	if rows, err := capture.DNSFromReaderAt(newWorkloadReadCache(blocked, 0)); !errors.Is(err, pcap.ErrPacketLimit) || len(rows) != 0 || blocked.calls != 0 {
		t.Fatalf("exhausted DNS scan returned %d rows, %v after %d calls", len(rows), err, blocked.calls)
	}
}
