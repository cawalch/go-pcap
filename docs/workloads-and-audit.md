# Workload comparisons and parser audit

This document records the parser limit audit, algorithmic complexity bounds,
adversarial input threat model, and reproducible benchmark measurements for
`go-pcap` (`go-pcap#18`). For buffer ownership and general usage, see the
[parsing guide](parsing.md).

## Reproducibility metadata

- **CPU and OS:** Apple M3 Max, `darwin/arm64` (`GOMAXPROCS=14`)
- **Go toolchain:** `go1.27.4 darwin/arm64` (module `go.mod` targets `go 1.26.0`+)
- **Root module dependencies:** zero external dependencies (`go 1.26.0` standard library only)

To reproduce the test, fuzz, and benchmark suite from the repository root:

```sh
go test -race -cover ./...
go test -run '^$' -bench . -benchmem -count=5
```

## Parser limit, complexity, and memory audit

`go-pcap` executes synchronously without background goroutines or unbounded
caches. Every entry point enforces explicit count and byte limits:

| Entry point | Hard limits | Complexity & memory audit |
| --- | --- | --- |
| `New` / `NewWithLength` / `NewFromReaderAt` | `MaxInterfaces = 256`, `MaxPackets = 1,048,576`, `MaxDecryptionSecrets = 256`, `MaxDecryptionSecretBytes = 4 MiB`, `MaxOptionsPerBlock = 64`, `MaxOptionStringBytes = 4,096`, `MaxSnapLen = 16 MiB` | Non-capture inputs fail the 4-byte magic gate in `~1.97 ns` with `0 B / 0 allocs` using pre-allocated static error wrappers. Classic PCAP and PcapNG block framing scans advance strictly forward in $O(N_{\text{blocks}})$ time without copying packet payloads. `Capture` retains no reference to `data`. |
| `Capture.PacketSeq` / `Capture.Packets` | `MaxPackets = 1,048,576`, `MaxSnapLen = 16 MiB` | `PacketSeq` streams `PacketRecord` values in a single pass with `0` slice allocations. `Packets` pre-sizes its slice to `min(c.PacketCount, MaxPackets)`, performing a single slice allocation. |
| `DecodeFrame` / `Frame.JA4T` / `JA4T` | `MaxFrameLayers = 8`, `MaxVLANTags = 4`, `MaxIPv6ExtHeaders = 8`, `MaxTCPOptions = 32` | Uses a fixed-capacity stack layer array (`[8]LayerSpan`) and `netip.Addr` value types. `DecodeFrame` performs `0 B / 0 allocs` in `~16.6 ns`. `JA4T` formats option kinds on a 96-byte stack scratch buffer (`1 alloc` for the returned `string`). |
| `Capture.Flows` | `MaxFlows = 65,536`, `MaxPackets = 1,048,576` | Streams packets via `walkPackets` without allocating a `[]PacketRecord` slice. Uses an inline 12-slot stack `flowIndexTable` before spilling to a heap map for captures with `> 12` distinct flows. |
| `ReassembleTCP` / `Capture.Streams` | `MaxSegmentsPerFlow = 4,096`, `MaxFlowStreamBytes = 4 MiB`, `MaxTotalStreamBytes = 64 MiB` | Sorts at most `4,096` segment descriptors per flow direction ($O(S \log S)$) and coalesces contiguous ranges into a bounded buffer capped at `4 MiB` per direction and `64 MiB` across all flows. Detects overlapping segment byte conflicts (`StreamAnomalies.OverlapConflict`) without overwriting first-seen bytes. |
| `ParseDNS` / `Capture.DNS` / `Capture.HasDNSQuery` | `MaxDNSQuestions = 64`, `MaxDNSResourceRecords = 256`, `MaxDNSCompressionJumps = 16`, `MaxDNSNameBytes = 255`, `MaxDNSTXTStrings = 32`, `MaxDNSMessagesPerScan = 65,536` | Decodes domain names into a 255-byte stack buffer. RFC 1035 compression pointers (`0xc0`) must point strictly backward (`ptr < cur`) and may jump at most `16` times, preventing pointer loops in $O(1)$ space. `HasDNSQuery` short-circuits on the first matching question without allocating `DNSRecord` slices. |
| `ParseTLSRecords` / `Capture.TLS` / `Capture.TLSWithKeyLog` | `MaxTLSRecordBytes = 18,432`, `MaxTLSHandshakeBytes = 256 KiB`, `MaxTLSCipherSuites = 256`, `MaxTLSExtensions = 128`, `MaxTLSSignatureSchemes = 128`, `MaxTLSALPNProtocols = 32`, `MaxTLSCertificates = 16`, `MaxTLSHandshakesPerScan = 16,384` | Coalesces multi-record TLS handshakes up to `256 KiB`. Computes FoxIO `JA4` and `JA4S` using stack backing arrays for cipher/extension sorting and hex formatting. When PcapNG `DSB` or keylog material provides `SERVER_HANDSHAKE_TRAFFIC_SECRET`, decrypts TLS 1.3 encrypted server `Certificate` records and computes `JA4X`. |
| `DecryptQUICInitial` / `Capture.QUIC` | `MaxQUICConnIDBytes = 20`, `MaxQUICTokenBytes = 4,096`, `MaxQUICCryptoBytes = 64 KiB`, `MaxQUICPacketsPerFlow = 64`, `MaxQUICFlowsPerScan = 16,384` | Derives RFC 9001 (QUIC v1) and RFC 9369 (QUIC v2) Initial AEAD (`AES-128-GCM`) and Header Protection (`AES-128-ECB`) keys via stdlib `crypto/hkdf`, reassembles out-of-order `CRYPTO` frames up to `64 KiB`, and parses the inner TLS 1.3 `ClientHello` and `q13...` `JA4`. |
| `ParseTLSKeyLog` / `DecryptTLS13Records` / `Capture.DecryptedTLSStreams` | `MaxTLSKeyLogEntries = 4,096`, `MaxTLSRecordBytes = 18,432`, `MaxFlowStreamBytes = 4 MiB` | Indexes up to `4,096` NSS `SSLKEYLOGFILE` entries by 32-byte `ClientHello.Random` and decrypts TLS 1.3 `TLS_AES_128_GCM_SHA256` and `TLS_AES_256_GCM_SHA384` records under flow byte budgets. |
| `ParseHTTPRequest` / `ParseHTTPResponse` / `Capture.HTTP` | `MaxHTTPHeaders = 128`, `MaxHTTPHeaderLineBytes = 8,192`, `MaxHTTPCookies = 64`, `MaxHTTPBodyBytes = 4 MiB`, `MaxHTTPMessagesPerScan = 16,384` | Bounds individual header lines to `8 KiB`, header count to `128`, and carved `Content-Length` or `chunked` bodies to `4 MiB`. Computes FoxIO `JA4H` across wire-order header names and sorted cookies. |
| `ParseSSHHandshake` / `Capture.SSH` | `MaxSSHBannerBytes = 255`, `MaxSSHKexPacketBytes = 32 KiB`, `MaxSSHNameListBytes = 16 KiB`, `MaxSSHHandshakesPerScan = 16,384` | Bounds SSH version banners and `SSH_MSG_KEXINIT` name-lists before computing `HASSH` and `HASSHServer` MD5 digests. |
| `ParseSMB2Message` / `ParseNTLMSSP` / `Capture.SMB` | `MaxSMB2PacketBytes = 64 KiB`, `MaxNTLMTokenBytes = 16 KiB`, `MaxNTLMAvPairs = 32`, `MaxSMBRecordsPerScan = 16,384` | Validates NetBIOS framing, 64-byte SMB2 headers, NTLMSSP security buffer offsets, and UTF-16LE `TargetInfo` attribute-value pairs. |
| `DefragmentIP` (and fragmented UDP in `Capture.DNS` / `Capture.QUIC`) | `MaxFragmentGroups = 1,024`, `MaxFragmentsPerGroup = 16`, `MaxReassembledIPPacketBytes = 65,535` | Reassembles out-of-order IPv4 and IPv6 fragments using a first-seen-wins policy and sets `FrameAnomalies.IPFragmentOverlapConflict` on conflicting overlapping bytes. |
| `ParseHTTP2Frames` / `Capture.HTTP2` | `MaxHTTP2FramesPerStream = 1,024`, `MaxHTTP2Settings = 64`, `MaxHTTP2FramePayload = 1 MiB`, `MaxHTTPBodyBytes = 4 MiB` | Validates the 24-byte HTTP/2 client preface or initial `SETTINGS` frame, formats `SettingsFingerprint` on a 128-byte stack buffer, and reassembles `DATA` frames under `MaxHTTPBodyBytes`. |
| `ParseKRB5` / `Capture.Kerberos` / `ParseRDPNegotiation` / `Capture.RDP` | `MaxKRB5PacketBytes = 64 KiB`, `MaxKRB5PrincipalParts = 16`, `MaxKRB5ETypes = 32`, `MaxRDPPacketBytes = 16 KiB`, `MaxRDPCookieBytes = 512` | Bounds ASN.1 DER Kerberos v5 `AS-REQ`/`TGS-REQ`/`KRB-ERROR` structures and TPKT/X.224 RDP negotiation PDUs. |
| `EvalBPF` / `BPFFilter*` | `MaxBPFFilterInstructions = 4,096` | Executes classic BPF instructions in a strictly forward program counter loop (rejecting backward jumps, out-of-bounds frame loads, and division by zero). |
| `Capture.*FromReaderAt` | `MaxReaderAtScanBytes = 64 MiB`, `MaxPackets = 1,048,576`, `MaxFlows = 65,536` | Enforces a cumulative `64 MiB` payload I/O read budget per `FlowsFromReaderAt`, `DNSFromReaderAt`, `TLSFromReaderAt`, or `QUICFromReaderAt` call. |
| `ComputeBeaconStats` / `Capture.Beacons` | `MaxFlows = 65,536`, `MaxPackets = 1,048,576` | Computes median inter-arrival interval, Median Absolute Deviation (MAD), Bowley quartile skewness periodicity, payload uniformity, and Producer-Consumer Ratio (PCR) in $O(P \log P)$ per flow. |

## Adversarial input threat model

1. **DNS label compression loops and forward pointers:** `decodeDNSNameBounded`
   rejects any pointer target `ptr >= cur` (defeating self-referential `0xc00c`
   and forward pointer cycles in a single check) and caps backward pointer chains
   at `MaxDNSCompressionJumps` (`16`).
2. **Nested encapsulation and extension bombs:** `DecodeFrame` caps nested
   `802.1Q` / `802.1ad` VLAN tags at `MaxVLANTags` (`4`), IPv6 extension headers
   at `MaxIPv6ExtHeaders` (`8`), and total layer spans at `MaxFrameLayers` (`8`),
   setting anomaly flags rather than recursing or allocating.
3. **TCP overlapping segment insertion attacks:** `ReassembleTCP` sorts segments
   by relative sequence offset and arrival order, retains first-seen payload
   bytes across any overlap, and sets `StreamAnomalies.OverlapConflict` whenever
   an overlapping segment's bytes differ from already-reassembled data.
4. **Chunked HTTP and stream memory exhaustion:** Both `ReassembleTCP` and
   `decodeChunkedBody` clamp output buffers to `MaxFlowStreamBytes` /
   `MaxHTTPBodyBytes` (`4 MiB`) and total capture reassembly to
   `MaxTotalStreamBytes` (`64 MiB`).
5. **Truncated captures and PcapNG blocks:** When a trailing packet or PcapNG
   block declares a length past `len(data)`, `New` records the declared end in
   `Capture.DeclaredExtent`, sets `CaptureAnomalies.TruncatedPacketBlock`, and
   reports `Capture.InputTruncated() == true` while allowing inspection of all
   preceding complete blocks.

## Representative benchmark measurements

Measured on Apple M3 Max (`darwin/arm64`, Go 1.27.4):

| Benchmark | Throughput | Latency | Bytes / Op | Allocs / Op |
| --- | ---: | ---: | ---: | ---: |
| `BenchmarkNewRejectNonPCAP-14` | `14,728 MB/s` | `1.97 ns/op` | `0 B/op` | `0 allocs/op` |
| `BenchmarkDecodeFrameEthernetIPv4TCP-14` | `4,398 MB/s` | `16.60 ns/op` | `0 B/op` | `0 allocs/op` |
| `BenchmarkJA4T-14` | — | `56.14 ns/op` | `24 B/op` | `1 allocs/op` |
| `BenchmarkComputeBeaconStats-14` | — | `112.0 ns/op` | `320 B/op` | `5 allocs/op` |
| `BenchmarkParseDNS-14` | `465.95 MB/s` | `143.8 ns/op` | `280 B/op` | `6 allocs/op` |
| `BenchmarkParseSMB2NTLM-14` | `833.91 MB/s` | `299.8 ns/op` | `136 B/op` | `7 allocs/op` |
| `BenchmarkNewPCAPNG-14` | `1,182 MB/s` | `358.7 ns/op` | `352 B/op` | `9 allocs/op` |
| `BenchmarkParseTLSClientHelloJA4-14` | `282.74 MB/s` | `435.0 ns/op` | `328 B/op` | `13 allocs/op` |
| `BenchmarkParseSSHHandshakeHASSH-14` | `647.85 MB/s` | `710.0 ns/op` | `730 B/op` | `24 allocs/op` |
| `BenchmarkParseHTTPRequestJA4H-14` | `192.13 MB/s` | `879.6 ns/op` | `952 B/op` | `28 allocs/op` |
| `BenchmarkDecryptQUICInitial-14` | `67.07 MB/s` | `2,520 ns/op` | `5,624 B/op` | `69 allocs/op` |
| `BenchmarkFlows-14` (64 packets, single flow) | `1,509 MB/s` | `3,494 ns/op` | `208 B/op` | `3 allocs/op` |

## Head-to-head comparison against `gopacket`

Measured via the isolated `benchmarks/gopacket` submodule (`go-pcap` vs
`github.com/gopacket/gopacket v1.3.1` on Apple M3 Max, `darwin/arm64`, Go
1.27.4):

| Workload | `go-pcap` | `gopacket` | Result |
| --- | --- | --- | --- |
| Ethernet + IPv4 + TCP frame decode (`DecodeFrame` vs `gopacket.NewPacket`) | `31.5 ns/op`, `0 B/op`, `0 allocs/op` (`2,251 MB/s`) | `258.5 ns/op`, `1,354 B/op`, `6 allocs/op` (`275 MB/s`) | **8.2x faster**, **0 allocs** vs 6 allocs |
| Ethernet + IPv4 + TCP frame decode (`DecodeFrame` vs `DecodingLayerParser`) | `31.5 ns/op`, `0 B/op`, `0 allocs/op` (`2,251 MB/s`) | `35.0 ns/op`, `0 B/op`, `0 allocs/op` (`2,027 MB/s`) | **1.11x faster**, zero caller layer setup |
| PcapNG 64-packet parse + walk (`New` + `PacketSeq` vs `pcapgo.NewNgReader`) | `3,992 ns/op`, `416 B/op`, `3 allocs/op` | `3,383 ns/op`, `13,088 B/op`, `70 allocs/op` | **31.5x less memory**, **23.3x fewer allocs** |
| 64-packet 8-flow TCP stream reassembly (`Capture.Streams` vs `tcpassembly`) | `8,165 ns/op`, `18,192 B/op`, `77 allocs/op` (`991 MB/s`) | `83,283 ns/op`, `2,343,675 B/op`, `101 allocs/op` (`97 MB/s`) | **10.2x faster**, **128.8x less memory** (`18 KiB` vs `2.34 MiB`) |
