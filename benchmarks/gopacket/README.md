# gopacket differential parity and benchmark comparison

This standalone comparison submodule (`github.com/cawalch/go-pcap/benchmarks/gopacket`)
isolates the third-party `github.com/gopacket/gopacket` dependency from the root
`go-pcap` module (which has zero external dependencies).

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

## Head-to-head results (Apple M3 Max, `darwin/arm64`, Go 1.27.4)

| Workload | `go-pcap` | `gopacket` | Relative comparison |
| --- | --- | --- | --- |
| L2–L4 Ethernet + IPv4 + TCP decode (`DecodeFrame` vs `gopacket.NewPacket`) | `31.5 ns/op`, `0 B/op`, `0 allocs/op` (`2,251 MB/s`) | `258.5 ns/op`, `1,354 B/op`, `6 allocs/op` (`275 MB/s`) | **8.2x faster**, **0 allocs** vs 6 allocs |
| L2–L4 Ethernet + IPv4 + TCP decode (`DecodeFrame` vs `DecodingLayerParser`) | `31.5 ns/op`, `0 B/op`, `0 allocs/op` (`2,251 MB/s`) | `35.0 ns/op`, `0 B/op`, `0 allocs/op` (`2,027 MB/s`) | **1.11x faster**, zero caller layer setup |
| PcapNG 64-packet parse + walk (`New` + `PacketSeq` vs `pcapgo.NewNgReader`) | `3,992 ns/op`, `416 B/op`, `3 allocs/op` | `3,383 ns/op`, `13,088 B/op`, `70 allocs/op` | **31.5x less memory**, **23.3x fewer allocs** (includes 2-pass container validation in `New`) |
| 64-packet 8-flow TCP stream reassembly (`Capture.Streams` vs `tcpassembly`) | `8,165 ns/op`, `18,192 B/op`, `77 allocs/op` (`991 MB/s`) | `83,283 ns/op`, `2,343,675 B/op`, `101 allocs/op` (`97 MB/s`) | **10.2x faster**, **128.8x less memory** (`18 KiB` vs `2.34 MiB`) |
