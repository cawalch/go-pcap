# Architecture and release roadmap

This guide describes the library design, release criteria, and scope of protocol additions.

## Design pillars

1. **Zero third-party dependencies (`CGO_ENABLED=0`).** All container parsing,
   protocol dissection, live socket capture (`syscall`), cryptographic key
   derivation (`crypto/hkdf`), cipher decryption (`crypto/aes`, `crypto/cipher`),
   and certificate parsing (`crypto/x509`) use only the Go standard library.
2. **Synchronous, caller-owned memory.** `New(data)` parses container headers,
   interface descriptors, Decryption Secrets Blocks (`DSB`), and block extents
   without retaining `data` or spawning background goroutines.
3. **Zero-allocation hot paths and low GC pressure.**
   - Non-capture inputs fail the 4-byte magic gate in under 5 ns with 0 heap
     allocations.
   - `DecodeFrame` uses a fixed-capacity stack array (`[MaxFrameLayers]LayerSpan`)
     and `netip.Addr` value types so L2–L4 decoding performs 0 heap allocations.
   - Payload bodies are referenced via `(Offset, Length)` byte ranges into the
     caller's slice rather than cloned upfront.
4. **Explicit work limits and anomaly flags.** Every parser enforces strict count
   and byte limits (`MaxInterfaces`, `MaxPackets`, `MaxFlows`,
   `MaxDecryptionSecrets`, `MaxFrameLayers`) and reports structural anomalies
   (such as truncated blocks, snaplen mismatches, IP header length conflicts, or
   overlapping TCP segments) without panicking.

## Release roadmap

### v0.1.0 — capture correctness and compatibility

The [v0.1.0 milestone](https://github.com/cawalch/go-pcap/milestone/1) tracks the
work required before the first experimental tag.

| Area | Release evidence |
| --- | --- |
| PcapNG sections | Resolve interface IDs within their section on both reader paths. Verify two sections that reuse interface 0 with different link types and timestamp settings. [#26](https://github.com/cawalch/go-pcap/issues/26) |
| Flow summaries | Compare complete slice and ReaderAt results for padded, truncated and long packets. [#58](https://github.com/cawalch/go-pcap/issues/58) |
| Reassembly | Verify exact TCP bytes for reordered midstream pickup and sequence wrap. Verify IPv6 overlap rejection and atomic-fragment handling through the consuming dissectors. [#44](https://github.com/cawalch/go-pcap/issues/44), [#52](https://github.com/cawalch/go-pcap/issues/52) |
| Compatibility fixtures | Check QUIC v1 and v2 ciphertext and fingerprint outputs against independent references. Exercise Server Initial decryption, Simple Packet Blocks and DNS TXT records. [#17](https://github.com/cawalch/go-pcap/issues/17), [#59](https://github.com/cawalch/go-pcap/issues/59), [#60](https://github.com/cawalch/go-pcap/issues/60) |

Before tagging, verify the documented [ReaderAt limits](parsing.md#parse-capture-containers)
and describe the extent of live capture testing for each supported platform.
Linux, macOS and Windows CI run unit tests. The live tests cover argument
validation and buffer handling. Successful device reads and kernel filter
behavior require separate verification on a host with capture permissions.

### After v0.1.0 — large captures and repeated analysis

ReaderAt packet iteration uses bounded read-ahead on files. Use
`BenchmarkReaderAtScan` to compare read counts, bytes read and allocations
for metadata scans, packet collection and flows. `BenchmarkReaderAtProtocols`
and `BenchmarkReaderAtFileProtocols` compare mixed-traffic scans in memory
and on a warm file. Measure the benefit of [reusing TCP streams in HTTP and HTTP/2](https://github.com/cawalch/go-pcap/issues/41)
on captures with and without decryption keys before changing segment storage.
Use `BenchmarkCaptureFingerprints` and `BenchmarkCaptureQUICInitials` to
measure formatting and decryption costs across complete capture scans.
Schedule compiler bounds-check work when those measurements justify it.

### Protocol and integration proposals

Add protocol fields when a caller can use the observation and the parser can
bound the work. Flow summaries expose on-demand Community ID v1 for TCP and UDP correlation.
HTTP/3 depends on a separate decision about QUIC 1-RTT decryption and stream
reconstruction. Consumers interpret observations such as TCP timestamps, ICMP
statistics and advertised address bindings in their deployment context.
The [go-yara adapter](https://github.com/cawalch/go-yara/issues/646) belongs to
the consuming repository. Its schema and release schedule are owned there.
The [original design discussion](https://github.com/cawalch/go-pcap/issues/19) records the proposed adapter contract.

## Protocol expansion model

To add a new L2/L3 encapsulation protocol:

1. Add the `LinkType`, `EtherType`, or `IPProto` constant in `types.go`.
2. Extend `DecodeFrame` in `frame.go` to append a `LayerSpan` to `Frame.Layers`
   and advance the cursor offset with explicit bounds checks.
3. Add unit tests (`frame_test.go`), bounds tests (`frame_bounds_test.go`), and
   seed corpora (`fuzz_test.go`).

To add a new L7 protocol dissector (`<proto>`):

1. Create `proto_<proto>.go` exposing both a standalone `Parse<Proto>(payload []byte)`
   function and a capture-level `(c *Capture) <Proto>(data []byte)` method.
2. Pair it with `proto_<proto>_test.go`, `proto_<proto>_bounds_test.go`,
   `proto_<proto>_fuzz_test.go`, and `proto_<proto>_benchmark_test.go`.
