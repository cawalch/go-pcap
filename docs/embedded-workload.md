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
