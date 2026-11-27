# Embedded capture workload measurements

Keep independent, lazy protocol scans and a caller-owned cancellation
wrapper. The measured combined workload still repeats reads, but the current
go-yara adapter requests TLS only. The results below give a baseline for an
external caller with a proven need to share a capture index across protocol
families.

The benchmark has a 1,668-byte client capture and an 8.65 MB PcapNG capture
with 8,192 unrelated TCP and UDP packets followed by known DNS, TLS, HTTP/1
and HTTP/2 observations. Each run opens a capture once. The mixed capture
returns three DNS records, one TLS record and seven HTTP transactions.
The four-scan modes return the same 11 rows and count the same bytes,
including when the application submits scans concurrently.

Compare v0.2.0 with the selective TLS candidate. Both used Go 1.27.4, ten
interleaved samples and an unchanged-source control on Apple M3 Max and AMD
Ryzen 9950X. The benchmark counts bytes the source actually received and
includes any file prefetch.

| Mixed workload | Source | Baseline read | Selective read | Baseline calls | Selective calls |
| --- | --- | ---: | ---: | ---: | ---: |
| TLS alone | Counting ReaderAt | 5.507 MiB | 2.507 MiB | 61,787 | 57,691 |
| All four scans | Counting ReaderAt | 18.27 MiB | 15.27 MiB | 168,874 | 164,778 |
| TLS alone | File with prefetch | 16.34 MiB | 16.30 MiB | 458 | 394 |
| All four scans | File with prefetch | 40.93 MiB | 40.89 MiB | 1,369 | 1,305 |

The mixed TLS scan used about 40% fewer allocated bytes and about 8,240 more
allocations per iteration, primarily in per-opening planning. The four-scan
file mode used about 45.4 MiB of allocated bytes per iteration after the
change, compared with 51.6 MiB at baseline. Timings for the mixed file TLS
case improved from 4.48 to 4.02 ms on ARM64 and from 4.29 to 3.79 ms on
AMD64. Concurrent mixed file scans took about 7 ms on both hosts and the
sequential scans took about 15 ms. A sampled peak-heap run on the Mac saw
23.6 to 26.0 MB above the fixture's initial heap for sequential file scans
and 31.8 to 34.1 MB for concurrent file scans. Heap samples include objects
that have not yet been collected and can miss brief peaks.

When the reader cancels immediately after the first successful eight-byte
read, each scanner returns the context error without another underlying
read or any result rows. A separate run against go-yara's own file
adapter at `3f53206` opened the small client file in three reads (1,672 bytes)
and found its single TLS handshake in two reads (1,668 bytes). A pre-canceled
scan performed zero additional underlying reads. The same test run verified
go-yara's lazy, cached TLS access. The file case in the benchmark mirrors
the adapter's preservation of the file descriptor for prefetch.
[go-yara file adapter](https://github.com/cawalch/go-yara/blob/3f53206e468b68a5d74b1ac211072f75157eaae0/compiler/scanner_stream.go#L970)

```sh
go test -run '^TestEmbeddedCaptureWorkloadCancellation$' -count=1 -v .
go test -run '^$' -bench '^BenchmarkEmbeddedCaptureWorkload/mixed/(bytes|file)' \
  -benchmem -benchtime=5x -count=10 .
GO_PCAP_MEASURE_WORKLOAD_HEAP=1 go test -run '^$' \
  -bench '^BenchmarkEmbeddedCaptureWorkload/mixed/file/(all|parallel)$' \
  -benchmem -benchtime=1x -count=3 .
```
