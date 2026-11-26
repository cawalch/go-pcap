# Consumer API compatibility

The v0.1.0 tag is the baseline for these behaviors. Consumers can rely on
them when upgrading to a compatible version. The module is experimental
during v0.x. A deliberate breaking change requires a minor release and a
changelog entry. Use keyed literals for exported structs so new fields can
be added compatibly.

## Record order

- `PacketSeq`, `Packets`, and their ReaderAt counterparts enumerate complete
  packets in file order. `PacketRecord.Index` starts at zero. Timestamps may
  repeat or move backward.
- `Flows` and `FlowsFromReaderAt` return bidirectional flows in first-observed
  order. The first observed direction defines the source and destination.
  `Streams` returns TCP connections in order of their first observed packet.
  Connections that reuse a five-tuple share a `FlowIndex`. This index refers
  to the flow list, which can also contain UDP flows. When
  `Capture.SeparateTCPInterfaces` tracks connections by PcapNG interface,
  their flow indices still refer to this same capture-wide list.
  Reassembled bytes within a direction follow TCP sequence order. A gap sets
  `SequenceGap` and concatenates the available ranges.
- DNS capture records follow packet-index order. DHCPv4 and neighbor records
  follow observation order. Neighbor binding changes follow the packet-index
  order of the current observation. For combined web analysis, each slice returned
  by `Web` or `WebWithWebSockets` follows the corresponding standalone
  method. WebSocket capture records group cleartext before decrypted streams
  and client before server messages within a stream. Within a direction
  messages appear on completion, so a ping can precede an interrupted text
  message. Use packet indexes when correlating different record families.
- Cleartext HTTP/1 request evidence follows packet-index and then TCP
  payload-offset order. These two fields identify a request start within a
  capture, including when multiple requests start in one packet.

## Inputs and payloads

| API | Lifetime a caller can rely on |
| --- | --- |
| `New`, `NewWithLength`, `NewFromReaderAt`, `Open` | The capture owns its metadata snapshot, including copied decryption secrets. Supply the same underlying capture contents to later scans. Keep a ReaderAt available and its size and bytes stable throughout use. Concurrent reads of a capture require its exported fields to remain unmodified. |
| `PacketPayload`, `SafeReader.Slice`, `UnwrapProxyStream` | The returned views borrow the input bytes. Copy before reusing or modifying the backing buffer if you need to retain the original content. |
| `PacketPayloadFromReaderAt`, `ReassembleTCP`, `ParseWebSocketFrames` | The returned frame, stream data, and message payloads respectively survive reuse of the supplied input. |
| `HTTP1RequestEvidence`, `HTTP1RequestEvidenceFromReaderAt` | The returned headers and body survive reuse of the supplied input. |
| `HTTP1Transactions`, `HTTP1TransactionsFromReaderAt` | Returned headers, bodies and packet indices survive reuse of the input. Transaction IDs apply to the original capture. |
| `KeyedHTTP1Transactions`, `KeyedHTTP1TransactionsFromReaderAt` | Caller-owned HTTP and TLS record evidence survives input reuse. IDs apply to the original capture. See [key inputs and coverage](parsing.md#select-http1-transactions-inside-tls). |
| `ExtractKeyedHTTP1TransactionPCAPNG`, `ExtractKeyedHTTP1TransactionPCAPNGFromReaderAt` | The source ID and matching keys select original ciphertext packets. Reopening the packet-only output requires separate secrets. [Export coverage](parsing.md#export-an-http1-exchange-as-ciphertext) |
| `ExtractKeyedHTTP2TransactionPCAPNG`, `ExtractKeyedHTTP2TransactionPCAPNGFromReaderAt` | The source ID and matching keys select original ciphertext packets and directional HPACK history. Reopening requires separate secrets. [Export coverage](parsing.md#export-a-keyed-http2-exchange-as-ciphertext) |
| `DecompressCapture` | Non-gzip input passes through by reference. A successful gzip decode returns decompressed bytes. |
| `LiveCapture.ReadPacket` | For portable code, copy a packet that must survive the next read. The macOS backend reuses its buffer. |

For other low-level parsers, consult the individual API before modifying an
input while its result is still in use. An offset in a result refers to the
input identified by that API.

## Limits and errors

Use the exported sentinel with `errors.Is` to classify a failure. Diagnostic
strings may change. Check the operation’s result policy before using output
from a failed call.

| Operation | What the caller receives |
| --- | --- |
| Container open | A valid header followed by an incomplete trailing record can produce a usable snapshot. Check `InputTruncated()` and `DeclaredExtent()` to distinguish this from a complete capture. |
| Compressed signatures | A leading Zstandard data frame or XZ stream signature returns `ErrUnsupportedZstd` or `ErrUnsupportedXZ` with a nil capture. Both errors also match `ErrNotPCAP` and `ErrInvalidMagic`. |
| Link-type coverage | `UnsupportedLinkTypePackets` and `UnsupportedLinkTypePacketsFromReaderAt` report complete records on unsupported interfaces. The ReaderAt metadata pass is bounded by `MaxReaderAtScanBytes`. Packet iteration still exposes those records, and frame-based scans can return empty or partial results. |
| Packet iteration and collection | Iterators can yield complete packets followed by one terminal error. Breaking stops iteration. On a walk error the collecting methods discard the accumulated records. |
| ReaderAt flow, DNS, TLS and QUIC scans | The per-call read budget covers selected payload and metadata. Exceeding `MaxReaderAtScanBytes` returns `ErrPacketLimit`. A larger file can fit within the budget. |
| QUIC 1-RTT packet decryption | `QUIC1RTTDecoder.Open` returns owned, authenticated frame bytes on success. Oversized input returns `ErrQUICLimit`. Invalid context, headers or authentication return `ErrInvalidQUIC`. |
| TCP reassembly | A directional byte cap produces a bounded stream with `Anomalies.Truncated`. Exceeding `MaxSegmentsPerFlow` in `ReassembleTCP` returns `ErrReassemblyLimit`. |
| Direct protocol parsing | A short DNS header returns `ErrInvalidDNS`. Excessive advertised question counts return `ErrDNSLimit`. `ParseWebSocketFrames` returns preceding complete messages plus `ErrInvalidWebSocket` for malformed or truncated input. Frame-count exhaustion returns `ErrWebSocketLimit`. |
| Combined web scan | `WebWithWebSockets` discards both results if an analysis fails. Capture-level dissectors may skip malformed or incomplete protocol observations as documented. |
| HTTP/1 request evidence | The scan discards its result on a read or limit error. A parsed request with an incomplete, malformed, or unsupported body reports its state in `BodyState`. |
| HTTP/1 transaction export | An invalid or absent request ID returns `ErrOutOfBounds` before writing. Once output starts, a read or write error can leave a partial PcapNG. ReaderAt selection and output share one `MaxReaderAtScanBytes` budget. |

Use the named limits for the selected parser. A change that makes a
previously accepted input exceed a limit warrants a compatibility review.
The parsing guide lists the individual ceilings and their units. [Work and output limits](parsing.md#work-and-output-limits)
