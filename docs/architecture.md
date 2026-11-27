# Architecture and release roadmap

## From a file to a protocol record

`Capture` owns container metadata. Packet iterators resolve each PcapNG
packet's interface and expose the byte range and timestamp. `DecodeFrame`
locates headers in that range. Flow aggregation groups bidirectional
five-tuples in observation order. Protocol scans can reassemble narrower
inputs, such as TCP openings or directional QUIC streams, as needed.

The byte-slice and ReaderAt paths share protocol decoding. ReaderAt paths
read selected ranges under a separate per-scan budget. Field evidence
locates original packets. An authenticated TLS record can reference every
packet carrying its header or ciphertext.
[Input and result contracts](compatibility.md) · [TLS fixture](../testdata/tls-provenance.md)

## Release roadmap

The v0.x API remains experimental. Use the
[coverage matrix](capabilities.md) to check supported questions and
the [tagged consumer tests](../testdata/consumer/qualified/README.md)
to verify external workflows. The
[embedded evidence roadmap](https://github.com/cawalch/go-pcap/issues/266)
records the scope decisions and completed work.

A protocol addition needs a concrete caller, bounded work, and a way to
distinguish observed data from data missing at the capture point. Capture
evidence belongs in this package. Consumers own rules and scoring.

## Where to make a change

| Area | Source | Verification |
| --- | --- | --- |
| Capture framing and metadata | [pcap.go](../pcap.go), [readerat.go](../readerat.go) | Open and iterate both inputs. Exercise multiple sections for interface changes. |
| Frames and tunnels | [frame.go](../frame.go) | Test clipped headers and nested layers. Check ReaderAt header read costs. |
| Flow summaries | [flow.go](../flow.go) | Run `TestReaderAtFlowParity` and `BenchmarkFlows`. |
| Reassembly and protocol fields | [reassembly.go](../reassembly.go), [tcp_messages.go](../tcp_messages.go), protocol source | Test direct and capture entry points, gaps, and seekable parity. |
| Writers, exports, and live I/O | [writer.go](../writer.go), [extract.go](../extract.go), `live_*.go` | Reopen exports to check original packets and context. Exercise live behavior on the target OS. |

Put protocol-specific types beside their parser. Use
[types.go](../types.go) for shared types and errors.
[Verification and performance](../CONTRIBUTING.md#validate-a-change)
