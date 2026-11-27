# Verify published capture workflows

These offline modules resolve go-pcap v0.2.0 (`7ffa353`). The nested
module also pins go-yara at `3f53206`. Tests compare byte-slice and
seekable results on the checked-in fixtures. Run from the repository root
with Go 1.27.4. The standalone Go module also supports Go 1.26.

```sh
(cd testdata/consumer/qualified &&
  GOWORK=off go test -mod=readonly -count=1 -v ./...)
(cd testdata/consumer/qualified/goyara &&
  GOWORK=off go list -mod=readonly -m github.com/cawalch/go-pcap github.com/cawalch/go-yara &&
  GOWORK=off go test -mod=readonly -count=1 -v ./...)
GOWORK=off go run github.com/cawalch/go-pcap/examples/dns-transactions@v0.2.0 \
  testdata/deployments/dns-transactions.pcap
```

| Workflow | Positive | Negative | Unavailable or ambiguous |
| --- | --- | --- | --- |
| TLS configuration | `match.example` agrees with the observed leaf DNS SAN. | `different.example` disagrees with that leaf DNS SAN. | The `opaque.example` TLS 1.3 certificate is encrypted and no secrets are present. The comparison is undefined. |
| Resolver | Frames 1 and 2 pair with status 0 and 8 ms elapsed. | Frames 3 and 4 pair with NXDOMAIN. | Frames 9–11 contain an ambiguous retry. Frame 13 lacks a reply. |
| HTTP content | `/upload` uploads `data` and the confirmed 200 response decodes to `upload accepted\n`. | `/pipelined` has a confirmed 204 and a complete empty body. | The gap after `/after-gap` makes response pairing ambiguous. |

The tests also check a clipped capture with an earlier complete HTTP
exchange and a DNS message whose question count hits a parser limit.
[Independent decoder reference and packet numbers](../../deployments/qualified.md)

## Observed input and allocation cost

Three 150 ms samples on Go 1.27.4 and Apple M3 Max. Reads include open,
scan, and repeated ranges. The standalone file wrapper disables prefetch.
The go-yara scanner also reads the input sequentially once.

| Workflow | Input bytes | Sequential bytes/op | ReaderAt bytes/op and calls | Allocations/op | Allocated bytes/op |
| --- | ---: | ---: | ---: | ---: | ---: |
| TLS | 9,284 | 0 | 10,050 in 159 | 293 | 47,928 |
| DNS | 1,298 | 0 | 1,510 in 41 | 97 | 11,296 |
| HTTP | 2,512 | 0 | 3,333 in 155 | 164 | 55,664 |
| go-yara TLS | 9,284 | 9,284 | 10,050 in 159 | 331 | 53,787–53,807 |

```sh
(cd testdata/consumer/qualified &&
  GOWORK=off go test -mod=readonly -run '^$' -bench '^BenchmarkTaggedWorkflows$' \
    -benchmem -benchtime=150ms -count=3 .)
(cd testdata/consumer/qualified/goyara &&
  GOWORK=off go test -mod=readonly -run '^$' -bench '^BenchmarkGoYARATaggedPCAP$' \
    -benchmem -benchtime=150ms -count=3 .)
```
