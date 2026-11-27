# Consumer API compatibility

The v0.1.0 tag is the compatibility baseline. Before v1.0, deliberate
breaking changes require a minor release and a changelog entry. Use keyed
literals for exported structs so added fields remain compatible.
[External contract tests](../testdata/consumer/contract_test.go)

## Record order

- Packet iterators and collectors use file order and zero-based indices.
  Timestamps can repeat or move backward.
- Flows start in first-observed order. That direction defines their
  source. Multiple TCP openings can share a capture-wide flow index,
  including with interface-scoped reassembly.
- TCP stream data is ordered by sequence. `SequenceGap` warns that
  available ranges can be concatenated across missing bytes.
- DNS records use packet-index order. DHCPv4 and neighbors use observation
  order. Pairing and transaction APIs document their own ordering.
  Cleartext HTTP/1 request evidence sorts by packet index and then payload
  offset. The combined web scan preserves standalone result order.
- WebSocket capture results group cleartext before decrypted streams and
  client before server within a stream. Messages in a direction are
  ordered by completion, so a ping can precede an interrupted message.

## Inputs and payloads

| Input or result | Contract |
| --- | --- |
| Capture snapshot | Opening copies metadata, including secrets. Supply the same capture contents to later scans. Keep ReaderAt data and exported capture fields immutable during concurrent use. |
| Borrowed bytes | `PacketPayload`, `SafeReader.Slice`, `UnwrapProxyStream`, and plain input passed through `DecompressCapture` borrow their input. |
| Owned bytes | `PacketPayloadFromReaderAt`, `ReassembleTCP`, and decoded WebSocket messages own their bytes. HTTP and SMB evidence APIs own retained bodies or fields and packet references. |
| Live packet bytes | Copy bytes that must survive a later read. The macOS backend reuses its buffer. |
| Evidence IDs | Indices and transaction IDs identify the original capture. Reopening a keyed packet-only export requires the matching keys separately. |

For other low-level APIs, check the Go doc before modifying input that
may back a result.

## Limits and errors

Use `errors.Is` with the documented sentinel. Diagnostic strings can change.
An iterator can yield complete packets followed by one terminal error.
A collector can discard its results on the same error. Check each API's
partial-result contract.

- A valid prefix with an incomplete last record can still open. Inspect
  `InputTruncated` and `DeclaredExtent`.
- Unsupported Zstandard and XZ signatures have specific errors that also
  match `ErrNotPCAP` and `ErrInvalidMagic`.
- Unsupported datalinks can yield no protocol rows. Count them with
  `UnsupportedLinkTypePackets` or its ReaderAt variant.
- Bounded ReaderAt scans charge selected metadata and packet bytes against
  `MaxReaderAtScanBytes`. Exceeding it returns `ErrPacketLimit`.
- An invalid transaction ID fails before writing. A later read or write
  error can leave partial output. Discard that output before retrying.
- A change that makes a previously accepted input exceed a limit warrants
  compatibility review. [Parsing limits and protocol outcomes](parsing.md#work-and-output-limits)
