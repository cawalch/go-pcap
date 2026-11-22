# gopacket differential parity and benchmark comparison

This standalone comparison submodule (`github.com/cawalch/go-pcap/benchmarks/gopacket`)
isolates the third-party `github.com/gopacket/gopacket` (`v1.8.0`) dependency
from the root `go-pcap` module (which has zero external dependencies).

It verifies differential packet and header parity against `gopacket/pcapgo` and
`gopacket/layers`, and benchmarks `go-pcap` head-to-head against:

- `gopacket.NewPacket(..., gopacket.NoCopy)`
- `gopacket.NewDecodingLayerParser`
- `pcapgo.NewNgReader`
- `gopacket/tcpassembly`

## Run tests and benchmarks

```sh
cd benchmarks/gopacket
go test -race ./...
go test -run '^$' -bench . -benchmem -count=5
```

## Head-to-head results against `gopacket v1.8.0` (Apple M3 Max, `darwin/arm64`, Go 1.27.4)

| Workload | `go-pcap` | `gopacket v1.8.0` | Relative comparison |
| --- | --- | --- | --- |
| L2–L4 Ethernet + IPv4 + TCP decode (`DecodeFrame` vs `gopacket.NewPacket`) | `31.7 ns/op`, `0 B/op`, `0 allocs/op` (`2,239 MB/s`) | `269.6 ns/op`, `1,354 B/op`, `6 allocs/op` (`263 MB/s`) | **8.5x faster**, **0 allocs** vs 6 allocs |
| L2–L4 Ethernet + IPv4 + TCP decode (`DecodeFrame` vs `DecodingLayerParser`) | `31.7 ns/op`, `0 B/op`, `0 allocs/op` (`2,239 MB/s`) | `36.9 ns/op`, `0 B/op`, `0 allocs/op` (`1,922 MB/s`) | **1.16x faster**, zero caller layer setup |
| PcapNG 64-packet parse + walk (`New` + `PacketSeq` vs `pcapgo.NewNgReader`) | `3,983 ns/op`, `416 B/op`, `3 allocs/op` (`2,329 MB/s`) | `4,771 ns/op`, `13,088 B/op`, `70 allocs/op` (`1,944 MB/s`) | **1.20x faster**, **31.5x less memory**, **23.3x fewer allocs** |
| 64-packet 8-flow TCP stream reassembly (`Capture.Streams` vs `tcpassembly`) | `8,600 ns/op`, `18,192 B/op`, `77 allocs/op` (`940 MB/s`) | `88,845 ns/op`, `2,351,867 B/op`, `101 allocs/op` (`91 MB/s`) | **10.3x faster**, **129.3x less memory** (`18.2 KiB` vs `2.35 MiB`) |
