# Architecture and release roadmap

This guide describes the library design, release criteria, and scope of protocol additions.

## From a file to a protocol record

1. **Read the container.** PCAP records use a file-wide link type. PcapNG
   packets refer to an interface in their own section, so the same local
   interface number can refer to different link types or timestamp resolutions.
   Opening the capture resolves those descriptions and records any embedded
   name mappings, process information, and decryption secrets.
2. **Locate and decode packets.** A packet record gives the frame's byte range,
   link type, and timestamp. `DecodeFrame` walks a bounded stack of link,
   tunnel, network, and transport headers. A caller interested only in
   packet counts or timestamps can stop before decoding frame payloads.
3. **Group related packets.** Flow aggregation uses the transport protocol and
   both address/port pairs. It assigns each bidirectional conversation a
   capture-local index. A flow's source is the first endpoint observed, which
   can be the server in a capture started mid-connection.
4. **Recover messages.** A protocol determines what needs reassembly. DNS can
   occupy a fragmented UDP datagram or span several TCP segments. TLS handshake
   records travel in TCP streams, while QUIC Initials carry TLS handshake
   bytes in CRYPTO frames. The selected dissector determines which packet
   payloads a ReaderAt scan needs to read.

Parsing is synchronous and uses only the Go standard library. The caller owns
the input. A `Capture` retains metadata and packet counts, and subsequent calls
read the source again as needed. Byte and count limits apply at different
stages, including input reads, TCP reassembly, and decoded output.
[Buffer ownership and limits](parsing.md#parse-capture-containers)

## Release roadmap

### v0.1.0 — capture correctness and compatibility

The first experimental release shipped on November 23, 2026. All seven
milestone issues closed. The tests cover section-local PcapNG interface IDs,
slice and ReaderAt flow parity, TCP reordering, IPv6 fragment handling, DNS TXT
and Simple Packet Blocks, and independent QUIC and fingerprint fixtures.
[Completed milestone](https://github.com/cawalch/go-pcap/milestone/1) ·
[Release notes and platform verification](../CHANGELOG.md#platform-verification)

### Toward v1.0

The consumer module exercises ordering, payload ownership, limits and errors
against v0.1.0 and the checkout. Remaining platform work includes native
Windows tests and privileged live-capture verification on macOS and Windows.
[Compatibility contract](compatibility.md) · [Consumer tests](../testdata/consumer/contract_test.go)

### Large captures and repeated analysis

ReaderAt packet iteration uses bounded read-ahead on files. Use
`BenchmarkReaderAtScan` to compare read counts, bytes read and allocations
for metadata scans, packet collection and flows. `BenchmarkReaderAtProtocols`
and `BenchmarkReaderAtFileProtocols` compare mixed-traffic scans in memory
and on a warm file. For keyed HTTP analysis, compare captures with and without
decryption keys. [TCP stream reuse in HTTP and HTTP/2](https://github.com/cawalch/go-pcap/issues/41)
Use `BenchmarkCaptureFingerprints` and `BenchmarkCaptureQUICInitials` to
measure formatting and decryption costs across complete capture scans.
Schedule compiler bounds-check work when those measurements justify it.

Single-flow PcapNG export accepts slice and file-backed inputs. Use
`BenchmarkFileFlowExport` to compare reading the full file with selecting
one flow through bounded reads. [Flow export guide](parsing.md#write-captures)

### Protocol and integration proposals

Add protocol fields when a caller can use the observation and the parser can
bound the work. Flow summaries expose on-demand Community ID v1 for TCP and UDP correlation.
HTTP/3 depends on a separate decision about QUIC 1-RTT decryption and stream
reconstruction. Consumers interpret observations such as TCP timestamps, ICMP
statistics and advertised address bindings in their deployment context.
The [go-yara adapter](https://github.com/cawalch/go-yara/issues/646) belongs to
the consuming repository. Its schema and release schedule are owned there.
The [original design discussion](https://github.com/cawalch/go-pcap/issues/19) records the proposed adapter contract.

## Where to make a change

The module exposes one import path. Its public entry points are package
functions for individual buffers and methods on `Capture` for whole-capture
analysis. Protocol files can use the same private packet walkers, bounds
checks, and reassembly code. The external-package examples exercise the API
as a caller sees it. [Go module layout](https://go.dev/doc/modules/layout) ·
[Public API examples](../example_test.go)

| Change | Start here | Check the boundary |
| --- | --- | --- |
| Container framing, timestamps, or PcapNG options | [pcap.go](../pcap.go) for slice walks and shared block decoders, [readerat.go](../readerat.go) for file reads | Exercise both open and packet iteration. Include multiple sections for interface changes. |
| Frame or tunnel decoding | [frame.go](../frame.go) | Exercise truncated headers and nested layers. A new header can also change how many bytes ReaderAt needs to identify a flow. |
| Flow counters, direction, or handshake fields | [flow.go](../flow.go) for aggregation on both inputs | Check complete summaries with `TestReaderAtFlowParity`. Benchmark `BenchmarkFlows` and the flow cases in `BenchmarkReaderAtScan`. |
| Reassembly or protocol metadata | Start in the protocol file, such as [dns.go](../dns.go). Shared TCP ordering lives in [reassembly.go](../reassembly.go). [tcp_messages.go](../tcp_messages.go) adds length framing and packet attribution for DNS and Kerberos. | Test the direct parser and the capture method. For DNS, TLS, or QUIC, include the ReaderAt path. Fingerprint changes also have [reference fixtures](../testdata/foxio/README.md). |
| Capture output or live I/O | [writer.go](../writer.go), [extract.go](../extract.go), or the `live_*.go` file for the target OS | Reopen written bytes and compare packet metadata. Exercise live reads, filters, and counters on the target OS. |

Use `types.go` for shared constants, limits, and sentinel errors. Put a
protocol-specific result type beside the parser that produces it. Most
changes fit in the owning file and its existing tests. For a new public
observation, document the zero value, how callers recognize missing data,
and which input paths produce it. [Contributor verification guide](../CONTRIBUTING.md#validate-a-change)
