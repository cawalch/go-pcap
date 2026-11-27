# Embedded capture workload measurements

Use independent lazy scans. The measured workload repeats reads, but
go-yara's adapter requests TLS only. The mixed 8.65 MB PcapNG contains
8,192 unrelated packets before 11 known DNS, TLS, and HTTP observations.
Sequential and concurrent scans return the same rows and read counts.

Compare v0.2.0 and selective TLS reads using Go 1.27.4, ten interleaved
samples, and an unchanged-source control on Apple M3 Max and AMD Ryzen
9950X. Counts include file prefetch.

| Mixed workload | Source | Baseline read | Selective read | Baseline calls | Selective calls |
| --- | --- | ---: | ---: | ---: | ---: |
| TLS alone | Counting ReaderAt | 5.507 MiB | 2.507 MiB | 61,787 | 57,691 |
| All four scans | Counting ReaderAt | 18.27 MiB | 15.27 MiB | 168,874 | 164,778 |
| TLS alone | File with prefetch | 16.34 MiB | 16.30 MiB | 458 | 394 |
| All four scans | File with prefetch | 40.93 MiB | 40.89 MiB | 1,369 | 1,305 |

The mixed file TLS scan improved from 4.48 to 4.02 ms on ARM64 and from
4.29 to 3.79 ms on AMD64. It allocated about 40% fewer bytes and made
about 8,240 more allocations. Four file scans took about 7 ms concurrently
and 15 ms sequentially. The Mac sampled 23.6–26.0 MB above baseline
heap sequentially and 31.8–34.1 MB concurrently.

Cancellation after the first successful eight-byte read returns the context
error and no rows or further reads. A 1,668-byte client file opened through
[go-yara's pinned adapter](https://github.com/cawalch/go-yara/blob/3f53206e468b68a5d74b1ac211072f75157eaae0/compiler/scanner_stream.go#L970)
in three reads (1,672 bytes). TLS used two reads (1,668 bytes). A
pre-canceled scan made no additional reads.

```sh
go test -run '^TestEmbeddedCaptureWorkloadCancellation$' -count=1 -v .
go test -run '^$' -bench '^BenchmarkEmbeddedCaptureWorkload/mixed/(bytes|file)' \
  -benchmem -benchtime=5x -count=10 .
GO_PCAP_MEASURE_WORKLOAD_HEAP=1 go test -run '^$' \
  -bench '^BenchmarkEmbeddedCaptureWorkload/mixed/file/(all|parallel)$' \
  -benchmem -benchtime=1x -count=3 .
```

## Shared-read trial after selective HTTP

The trial cleared the 25% read-volume threshold in [#310](https://github.com/cawalch/go-pcap/issues/310).
Keep independent lazy scans in the library. The trial saved file reads,
but its added allocations and inconsistent latency gains make it a poor
default. Revisit sharing for a caller whose seekable source has costly
reads and that requests multiple protocol families together.

The late-HTTP fixture is the 8.65 MB mixed capture above. The dense control
has 1,024 separate HTTP/1 exchanges. The DNS-only control runs one scan of
the same captures. The test-only cache keeps complete reads already
requested by the scanners, including file prefetch windows. It allows up
to 64 MiB of underlying reads and retains up to 8 MiB of data in 32,768
entries. At the retention limits, misses still use the source. DNS-only
uses the existing reader path and creates no shared cache.

The control was commit `6a8b66d`. Each host ran ten rotated five-operation
samples comparing control, unchanged-source repeat, independent scans
from the trial build, and shared scans. Reads count underlying ReaderAt
calls and their returned bytes including prefetch. Parallel and sequential
scans issued the same reads. Both ordered output sets and the shared run
matched, including reference indices and two VXLAN tenant views. Tests
also covered cancellation on a cache hit and physical read exhaustion.

| Workload and source | Independent MiB / calls | Shared MiB / calls | Reduction in bytes |
| --- | ---: | ---: | ---: |
| Late HTTP, counting ReaderAt | 12.27 / 160,682 | 5.38 / 37,656 | 56% |
| Late HTTP, file | 34.93 / 33,945 | 8.83 / 1,294 | 75% |
| Dense HTTP, counting ReaderAt | 2.18 / 97,306 | 0.51 / 20,486 | 77% |
| Dense HTTP, file | 2.57 / 20,547 | 0.53 / 632 | 79% |

Wall times are medians in ms, shown as sequential / parallel / shared.
The Mac used Go 1.27.4 on ARM64. The .110 host used Go 1.26.8 on AMD64.

| Workload and source | Mac | .110 |
| --- | ---: | ---: |
| Late HTTP, counting ReaderAt | 11.86 / 5.95 / 18.24 | 13.16 / 5.91 / 22.53 |
| Late HTTP, file | 24.48 / 16.98 / 14.41 | 18.48 / 9.06 / 14.53 |
| Dense HTTP, counting ReaderAt | 6.35 / 3.77 / 9.64 | 6.08 / 3.05 / 9.76 |
| Dense HTTP, file | 13.33 / 10.66 / 7.02 | 8.61 / 5.70 / 6.31 |

The mixed DNS-only control fetched 2.51 MiB in 57,691 reads for the
counting ReaderAt and 16.30 MiB in 394 reads for the file. The dense
DNS-only control fetched 0.66 MiB in 35,851 reads and 1.03 MiB in 28 reads,
respectively. DNS-only timing, reads, and allocation volume tracked the
unchanged control. The repeated control's mixed timings were within 6%
of the first run's medians.

Allocation and peak figures below are decimal MB. Allocations are counts
per operation. Parallel allocation totals were within 0.12 MB and 20
allocations of sequential. Peak is the median of five separate
one-operation runs sampled at 1 ms, shown as sequential / parallel /
shared. Short operations can finish between samples.

| Workload and source | Sequential allocated MB / count | Shared allocated MB / count | Mac peak MB | .110 peak MB |
| --- | ---: | ---: | ---: | ---: |
| Late HTTP, counting ReaderAt | 40.87 / 70,775 | 49.56 / 103,819 | 15.95 / 24.60 / 21.10 | 16.49 / 25.09 / 21.68 |
| Late HTTP, file | 40.94 / 70,789 | 49.42 / 71,406 | 17.74 / 27.03 / 31.35 | 17.62 / 25.61 / 30.00 |
| Dense HTTP, counting ReaderAt | 10.08 / 61,694 | 13.86 / 82,323 | 2.77 / 4.61 / 7.26 | 4.47 / 5.08 / 7.36 |
| Dense HTTP, file | 10.18 / 61,710 | 10.83 / 62,358 | 3.50 / 5.27 / 3.77 | 3.82 / 5.08 / 4.58 |

On the Mac, TShark 4.6.10 and independent embedded scans of the same
warm file returned matching packet numbers and values for three
observations: a DNS name and address, a ClientHello SNI, and an HTTP GET
target. The ten alternating runs took a median of 140 ms with TShark
and 33 ms embedded. TShark launched once per run and emitted 73 bytes
of stdout. Embedded scans used zero external launches. Both read the
same 8,656,148-byte input and wrote zero per-run temporary file bytes.
This compares the selected rule output on this fixture.

```sh
go test -run '^TestEmbeddedCaptureWorkload' -count=1 .
go test -run '^$' -bench '^BenchmarkEmbeddedCaptureWorkload/(mixed|dense)/(bytes|file)/(dns|all|parallel|shared)$' \
  -benchmem -benchtime=5x -count=10 .
GO_PCAP_MEASURE_WORKLOAD_HEAP=1 go test -run '^$' \
  -bench '^BenchmarkEmbeddedCaptureWorkload/(mixed|dense)/(bytes|file)/(all|parallel|shared)$' \
  -benchmem -benchtime=1x -count=5 .
GO_PCAP_COMPARE_TSHARK=1 go test -run '^TestEmbeddedCaptureWorkloadTShark$' -count=1 -v .
```
