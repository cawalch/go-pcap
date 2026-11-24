# Architecture and release roadmap

## From a file to a protocol record

1. **Open the capture.** `Capture` owns a metadata snapshot. Classic PCAP has
   one link type. PcapNG resolves each section’s local interface IDs to capture-wide
   descriptors with their own link types and timestamp encodings.
2. **Read packets.** Each record gives the frame’s byte range and timestamp.
   Callers can iterate metadata alone or pass the payload to `DecodeFrame`.
3. **Group flows.** The transport protocol and two address/port pairs identify
   a bidirectional flow. The first observed endpoint supplies its source.
4. **Reassemble protocol data.** DNS may need IP fragments or TCP segments.
   TLS uses TCP streams. QUIC Initials carry handshake bytes in CRYPTO frames.
   ReaderAt scans read payloads according to the protocol and its work budget.

## Release roadmap

### v0.1.0 — capture correctness and compatibility

The first release covered container framing, flow parity, reassembly, and
reference fixtures. [Completed milestone](https://github.com/cawalch/go-pcap/milestone/1) · [Release verification](../CHANGELOG.md#platform-verification)

### Toward v1.0

CI tests the consumer contract against v0.1.0 and the checkout. It runs the
native Windows and macOS test suites and privileged loopback capture on Linux.
Privileged live capture on Windows and macOS requires separate verification.
[Compatibility contract](compatibility.md) · [CI jobs](../.github/workflows/checks.yml)

### Large captures and repeated analysis

Measure metadata scans and flow indexing with `BenchmarkReaderAtScan`, protocol
scans with `BenchmarkReaderAtProtocols` and `BenchmarkReaderAtFileProtocols`,
and bounded export with `BenchmarkFileFlowExport`. Compare read counts, bytes,
allocations and elapsed time on the same inputs. [Benchmark guide](../CONTRIBUTING.md#measure-performance)

### Protocol and integration proposals

New protocol fields need a caller and bounded parsing costs. HTTP/3 depends on
QUIC 1-RTT stream reconstruction. Scanner schemas and rule evaluation belong in
the consuming repository. [HTTP/3 proposal](https://github.com/cawalch/go-pcap/issues/31) · [go-yara integration](https://github.com/cawalch/go-yara/issues/646)

## Where to make a change

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
