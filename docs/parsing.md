# Parse packet captures, frames, and protocols

This guide describes buffer ownership, parser limits, error handling, container
metadata, Layer 2 through Layer 4 (L2–L4) frame decoding, TCP stream reassembly,
and Layer 7 (L7) protocol dissectors. For installation and a complete example,
see the [README](../README.md).

## Parse capture containers

`New` parses classic Portable Packet Capture (PCAP) headers or PCAP Next
Generation (PcapNG) section blocks (`SHB`, `IDB`, `DSB`, `NRB`, `ISB`, `DPEB`,
`EPB`, and `SPB`) and validates block framing across the buffer. It copies
header values, interface descriptors, Name Resolution Block (`NRB`) records,
Interface Statistics Block (`ISB`) counters, Darwin Process Event Block (`DPEB`)
entries, and Decryption Secrets Block (`DSB`) payloads without retaining the
input buffer. It records `int64(len(data))` as `Capture.FileSize`.

For a `.pcap.gz` or `.pcapng.gz` buffer, call `DecompressCapture(input)`
before `New`. Pass the returned bytes to `Packets`, `PacketPayload`, and
other slice methods. Plain input is returned by reference. For gzip, the
helper checks member trailers and enforces a combined 64 MiB output limit.
An oversized stream returns `ErrPacketLimit`. Decompression errors return no
partial buffer. Use `New` to validate the resulting capture format.

A truncated capture succeeds as long as its initial container header (the
24-byte classic PCAP header or the first PcapNG Section Header Block) is valid.
When a trailing packet record or PcapNG block extends past `data`, `New` stops
at the last complete record, sets `Capture.DeclaredExtent` to include the
declared trailing record end, and marks `Capture.InputTruncated() == true`.
If only a leading stream prefix is buffered while the total stream length is
known, call `NewWithLength(data, streamLength)`. For large files on disk, call
`NewFromReaderAt(r, size)` to parse container metadata without reading the
entire capture into a single byte slice. On a file (including a wrapper exposing `Fd() uintptr`), a scan can
prefetch up to 64 KiB of adjacent bytes, including frame data. Each scan owns
its window. Other readers receive exact range requests. Opening a PcapNG capture
validates its metadata blocks. Later packet walks reuse that validation and skip
name resolution, interface statistics, and decryption secrets block bodies.
They still read interface descriptions, process events, packet headers,
options and block trailers. Each buffered PcapNG metadata read is limited to
`MaxSnapLen + 4096` bytes. Use `PacketSeqFromReaderAt` to process records
in order and break when you have enough. `PacketsFromReaderAt` collects a
packet record slice. `FlowsFromReaderAt` starts with a 256-byte prefix or the
whole frame when shorter. It reads additional bytes into a reusable buffer
when needed to resolve flow headers and lengths. All frame reads count toward
the 64 MiB flow budget. Flow metadata incurs additional I/O.

`DNSFromReaderAt`, `TLSFromReaderAt`, and `QUICFromReaderAt` each allow
64 MiB of total reads, including container metadata, frame prefixes, and
selected payloads. A call can finish on a larger file. A read that would
exceed the remaining allowance returns `ErrPacketLimit` without partial results.
File prefetch uses only the allowance left after reserving for exact reads,
including overlapping PcapNG block headers. Large sparse captures keep exact
reads when that reservation leaves no room. Cache hits still count toward
the limit on selected input. Opening the capture has a separate scan cost.

DNS selects DNS ports and UDP fragments. TLS reassembles TCP on any port.
QUIC selects candidate UDP long headers and UDP fragments. Incomplete headers
and tunnels can require a full frame read. Each selected transport byte comes
from the read allowance, bounding retained input payloads to 64 MiB per call.
TCP reassembly separately allows 4 MiB per direction and 64 MiB total output.
Fragment and QUIC reassembly also apply the limits below. Decoded records,
flow tables and scratch buffers use additional memory.

If you don't modify its exported fields, you can read a `Capture` concurrently
from multiple goroutines. Unlike `Capture`, `SafeReader` retains a reference to
its input buffer; don't modify that buffer concurrently with reads.

## Work and output limits

The following limits bound parsing work and memory allocation on each call:

| Limit | Maximum | Purpose |
| --- | --- | --- |
| `MaxDecompressedCaptureBytes` | 64 MiB | Bounds decompressed output across gzip members in `DecompressCapture` |
| `MaxInterfaces` | 256 interfaces | Bounds PcapNG `IDB` descriptors per capture |
| `MaxPackets` | 1,048,576 packets | Bounds packets indexed or returned by `New`, `PacketSeq`, `Packets`, and `Flows` |
| `MaxFlows` | 65,536 flows | Bounds distinct 5-tuple flows aggregated by `Flows` and L7 dissectors |
| `MaxDecryptionSecrets` | 256 blocks | Bounds PcapNG `DSB` blocks per capture |
| `MaxDecryptionSecretBytes` | 4 MiB | Bounds cumulative secret payload bytes copied across all `DSB` blocks |
| `MaxNameResolutionRecords` | 16,384 records | Bounds IPv4 and IPv6 hostname mappings across PcapNG `NRB` blocks |
| `MaxInterfaceStats` | 1,024 blocks | Bounds PcapNG `ISB` statistics blocks per capture |
| `MaxProcessEvents` | 16,384 entries | Bounds Darwin Process Event Blocks (`DPEB`) per capture |
| `MaxOptionsPerBlock` | 64 options | Bounds PcapNG TLV options per block |
| `MaxOptionStringBytes` | 4,096 bytes | Bounds individual PcapNG option or `NRB` record payloads |
| `MaxSnapLen` | 16 MiB | Bounds maximum packet capture length accepted in headers |
| `MaxFrameLayers` | 8 layers | Bounds stack-allocated layer spans per decoded frame |
| `MaxVLANTags` | 4 tags | Bounds nested 802.1Q / 802.1ad VLAN tags per Ethernet header |
| `MaxMPLSLabels` | 8 labels | Bounds MPLS label stack depth per frame |
| `MaxIPv6ExtHeaders` | 8 headers | Bounds IPv6 extension headers traversed per packet |
| `MaxSegmentsPerFlow` | 4,096 segments | Bounds TCP segments buffered per flow direction |
| `MaxFlowStreamBytes` | 4 MiB | Bounds reassembled TCP stream bytes per flow direction |
| `MaxTotalStreamBytes` | 64 MiB | Bounds total reassembled TCP stream bytes per `Streams` call |
| `MaxDNSQuestions` | 64 questions | Bounds questions per DNS message |
| `MaxDNSResourceRecords` | 256 records | Bounds total answer, authority, and additional records per DNS message |
| `MaxDNSCompressionJumps` | 16 jumps | Bounds RFC 1035 label pointer hops per domain name |
| `MaxDNSALPNProtocols` | 32 identifiers | Bounds ALPN identifiers per DNS `SVCB` or `HTTPS` record |
| `MaxDNSMessagesPerScan` | 65,536 messages | Bounds DNS messages returned per capture scan |
| `MaxTLSHandshakeBytes` | 256 KiB | Bounds coalesced TLS handshake payload size |
| `MaxTLSExtensions` | 128 extensions | Bounds TLS extensions parsed per handshake message |
| `MaxTLSCertSANsPerKind` | 64 per kind | Bounds retained DNS names and IP addresses independently for each certificate |
| `MaxTLSCertificates` | 16 certificates | Bounds X.509 certificates parsed per TLS Certificate message |
| `MaxTLSHandshakesPerScan` | 16,384 handshakes | Bounds TLS handshakes returned per capture scan |
| `MaxTLSKeyLogEntries` | 4,096 entries | Bounds NSS keylog entries parsed per `ParseTLSKeyLog` / `TLSKeyLog` call |
| `MaxQUICCryptoBytes` | 64 KiB | Bounds reassembled QUIC Initial `CRYPTO` stream size |
| `MaxQUICPacketsPerFlow` | 64 packets | Bounds Initial UDP datagrams inspected per QUIC flow |
| `MaxQUICFlowsPerScan` | 16,384 flows | Bounds QUIC Initial flows returned per capture scan |
| `MaxHTTPHeaders` | 128 headers | Bounds HTTP header lines per request or response |
| `MaxHTTPBodyBytes` | 4 MiB | Bounds each carved HTTP body before and after content decoding |
| `MaxHTTPDecodedBodyBytesPerScan` | 64 MiB | Bounds cumulative HTTP/1.x content decoding per `Capture.HTTP` call, including failed attempts |
| `MaxHTTPMessagesPerScan` | 16,384 messages | Bounds HTTP/1.x and HTTP/2 records returned per capture scan |
| `MaxSSHKexPacketBytes` | 32 KiB | Bounds SSH `SSH_MSG_KEXINIT` packet length |
| `MaxSSHHandshakesPerScan` | 16,384 handshakes | Bounds SSH handshakes returned per capture scan |
| `MaxSMB2PacketBytes` | 64 KiB | Bounds NetBIOS-framed SMB2/3 message length |
| `MaxNTLMTokenBytes` | 16 KiB | Bounds NTLMSSP token length |
| `MaxSMBRecordsPerScan` | 16,384 records | Bounds SMB2/3 records returned per capture scan |
| `MaxBPFFilterInstructions` | 4,096 instructions | Bounds classic BPF filter program length in `OpenLive` and `EvalBPF` |
| `MaxReaderAtScanBytes` | 64 MiB | Bounds flow frame reads, or all reads per DNS, TLS or QUIC ReaderAt scan |
| `MaxFragmentGroups` | 1,024 groups | Bounds concurrent IPv4/IPv6 fragment groups tracked per scan |
| `MaxFragmentsPerGroup` | 16 fragments | Bounds IP fragments reassembled per fragmented packet |
| `MaxReassembledIPPacketBytes` | 65,535 bytes | Bounds reassembled IPv4/IPv6 packet payload size |
| `MaxHTTP2FramesPerStream` | 1,024 frames | Bounds HTTP/2 frames parsed per directional stream |
| `MaxHTTP2FramePayload` | 1 MiB | Bounds individual HTTP/2 frame payload size |
| `MaxKRB5PacketBytes` | 64 KiB | Bounds Kerberos v5 message length |
| `MaxKRB5RecordsPerScan` | 16,384 records | Bounds Kerberos v5 records returned per capture scan |
| `MaxRDPPacketBytes` | 16 KiB | Bounds RDP TPKT/X.224 negotiation PDU length |
| `MaxRDPRecordsPerScan` | 16,384 records | Bounds RDP negotiation records returned per capture scan |

Use `errors.Is` with `ErrNotPCAP`, `ErrInvalidMagic`, `ErrInvalidHeader`,
`ErrInvalidBlock`, `ErrInvalidPacket`, `ErrInvalidFrame`, `ErrInvalidDNS`,
`ErrInvalidTLS`, `ErrInvalidQUIC`, `ErrInvalidHTTP`, `ErrInvalidSSH`,
`ErrInvalidSMB`, `ErrInvalidKRB5`, `ErrInvalidRDP`,
`ErrLiveCaptureUnsupported`, `ErrInterfaceLimit`, `ErrPacketLimit`,
`ErrFlowLimit`, `ErrSecretLimit`, `ErrOptionLimit`, `ErrReassemblyLimit`,
`ErrFragmentLimit`, `ErrDNSLimit`, `ErrTLSLimit`, `ErrQUICLimit`,
`ErrHTTPLimit`, `ErrSSHLimit`, `ErrSMBLimit`, `ErrKRB5Limit`, `ErrRDPLimit`,
`ErrOutOfBounds`, or `ErrIntegerOverflow` to classify failures.

## Inspect truncation and anomalies

Call `Capture.DeclaredExtent` or `Capture.InputTruncated` to check whether the
input ends before a declared packet record or PcapNG block finishes. Call
`Capture.Anomalies` to inspect non-fatal container anomalies:

- `TruncatedPacketBlock`: A packet header or PcapNG block declared a length
  extending past the end of `data`.
- `CaptureLenExceedsOriginal`: A packet record declared `CaptureLen > OriginalLen`.
- `CaptureLenExceedsSnapLen`: A packet record declared `CaptureLen` larger than
  its interface's `SnapLen` (when `SnapLen > 0`).
- `UnknownLinkType`: An interface declared an unrecognized link-layer type.
- `TrailingBytes`: Trailing bytes after the last block were too short to form a
  complete record header.
- `UnalignedBlockLength`: A PcapNG block declared a total length that was not a
  multiple of 4 bytes.
- `InvalidTimestampResolution`: An interface declared an invalid `if_tsresol`
  option (such as a decimal exponent greater than 9).

In PcapNG, each section defines its own interface table and byte order. Packet
and statistics records expose the resolved index into `Capture.Interfaces`.

## Read packet records

To stream packet records in file order without allocating a slice, use
`capture.PacketSeq(data)` with a `for ... range` loop:

```go
for pkt, err := range capture.PacketSeq(data) {
	if err != nil {
		return err
	}
	payload, err := capture.PacketPayload(data, pkt)
	if err != nil {
		return err
	}
	frame, err := pcap.DecodeFrame(payload, pkt.LinkType)
	// ...
}
```

If you need a slice of all packet records, call `capture.Packets(data)` (or
`capture.PacketsFromReaderAt(r)`). Each `PacketRecord` contains:

- `Index`: Zero-based packet index in file order.
- `InterfaceID` and `LinkType`: Link-layer encapsulation type for decoding.
- `TimestampNs`: Packet timestamp normalized to nanoseconds since the Unix
  epoch, applying any PcapNG decimal ($10^{-N}$) or binary ($2^{-N}$)
  `if_tsresol` scaling and `if_tsoffset` seconds offset.
- `CaptureLen` and `OriginalLen`: Captured and on-wire byte counts.
- `PayloadOffset` and `PayloadLength`: Byte range of the captured frame inside
  `data`. Pass `pkt` to `capture.PacketPayload(data, pkt)` to obtain a
  bounds-checked zero-copy slice into `data`.
- `ProcessID`, `ThreadID`, `UserID`, `ProcessName`, `ProcessArgs`,
  `ContainerID`, `Flags`, and `DropCount`: Process attribution and packet
  metadata decoded from PcapNG Enhanced Packet Block options and Darwin Process
  Event Blocks (`DPEB`).

## Decode L2–L4 frames and tunnels

Call `DecodeFrame(payload, linkType)` on a packet payload slice. `DecodeFrame`
parses link, tunnel, network, and transport headers into a value `Frame` struct
without heap allocations:

- Supported link types: `LinkTypeEthernet` (with up to 4 nested 802.1Q / 802.1ad
  VLAN tags), `LinkTypeLinuxSLL`, `LinkTypeLinuxSLL2`, `LinkTypeNull` (BSD
  loopback), `LinkTypeRaw`, `LinkTypeIPv4`, and `LinkTypeIPv6`.
- Supported tunnel encapsulations: `MPLS` (`0x8847` / `0x8848`, up to 8 labels),
  `PPPoE` Session (`0x8864` over IPv4 or IPv6), `GRE` (`IPProto 47` over IPv4,
  IPv6, or Transparent Ethernet Bridging), `VXLAN` (`UDP 4789`), and `Geneve`
  (`UDP 6081`).
- Supported network headers: `IPv4` (with fragment detection), `IPv6` (with
  bounded extension-header traversal for Hop-by-Hop, Routing, Fragment,
  Destination Options, and Authentication headers), and `ARP`.
- Supported transport headers: `TCP` (extracting ports, sequence/acknowledgment
  numbers, flags, window size, and raw TCP option range for `JA4T`), `UDP`,
  `ICMPv4`, and `ICMPv6`.
- `Frame.PayloadOffset` and `Frame.PayloadLength` identify the innermost
  transport payload slice (`payload[frame.PayloadOffset : frame.PayloadOffset+frame.PayloadLength]`).

IPv6 reassembly discards a datagram if fragments overlap, including identical
bytes. A first UDP or TCP fragment must contain its complete transport header.
Atomic IPv6 packets are decoded independently of pending fragment groups.

The [fingerprint reference fixtures](../testdata/foxio/README.md) identify the
FoxIO revisions and inputs used for compatibility tests.

## Aggregate 5-tuple flows

Call `capture.Flows(data)` to aggregate IPv4 and IPv6 packets into deterministic
bidirectional flows ordered by their first appearance in the capture. The first
packet observed for a 5-tuple defines the client (`SrcAddr`, `SrcPort`) to
server (`DstAddr`, `DstPort`) direction; replies in the reverse direction
increment `ServerPackets` and `ServerBytes`. For TCP flows, `Flows` records:

- `ClientJA4T` and `ServerJA4TS` from the first client `SYN` and server `SYN-ACK`.
- `SYNTimestamp` and `SYNACKTimestamp` hold the first observed timestamp option
  for each handshake flag combination, in capture order. This also works when
  the capture starts with a SYN-ACK. Check `Present` before reading the raw
  `TSval` and `TSecr` values. Either value can be zero. A missing option, a
  duplicate timestamp, or a malformed TLV boundary leaves that packet out of
  consideration, so a retransmission can supply the first valid observation.
  Both flow readers use the same selection. For example:

  ```go
  if ts := flow.SYNACKTimestamp; ts.Present {
      fmt.Printf("server TSval=%d TSecr=%d\n", ts.TSval, ts.TSecr)
  }
  ```

- `ServerJA4L` (`<half_syn_synack_rtt_us>_<server_ttl>`) and `ClientJA4L`
  (`<half_synack_ack_rtt_us>_<client_ttl>`) from the 3-way handshake timestamps
  and IP `TTL` / `HopLimit`.
- First-seen process attribution (`ProcessID`, `UserID`, `ProcessName`,
  `ProcessArgs`, and `ContainerID`).

Call `flow.CommunityID(seed)` on a summary from `Flows` or `FlowsFromReaderAt`
to correlate IPv4 or IPv6 TCP and UDP traffic with other tools. Both directions
produce the same ID. Match the seed across tools (the default is zero).
The method computes the ID only when called and returns an empty string for
unsupported protocols, invalid or mixed-family addresses, or a summary with
`PortsUnavailable` set. A decoded port value of zero is valid.

## Reassemble TCP streams

Call `capture.Streams(data)` to reassemble ordered directional TCP byte streams
(`Client` and `Server`) for every TCP flow in the capture, or call
`ReassembleTCP(segments)` directly on a slice of `TCPSegmentInput`. Reassembly
resolves overlapping segments using a first-seen-wins policy and sets
`StreamAnomalies.OverlapConflict` when a later overlapping segment contains
differing bytes at the same sequence offset.

## Parse DNS messages and tunneling metrics

Call `ParseDNS(payload)` on a single DNS message or `capture.DNS(data)` to
extract DNS queries and responses over UDP (ports 53, 5353, 5355) and TCP (port
53 length-prefixed). Compression pointers must point strictly backward and may
jump at most `MaxDNSCompressionJumps` times. Use `capture.HasDNSQuery(data, qname)`
to test whether a capture queries a domain without allocating `DNSRecord` slices.

A TCP segment can end halfway through a DNS message or contain multiple
messages. The scanner orders each direction by TCP sequence number and reads
each message using its two-byte length prefix. If a gap breaks framing, it
stops decoding that direction. For a split message, `PacketIndex` and
`TimestampNs` identify the packet supplying the first prefix byte. This lets
you locate the message in the original capture even when the final bytes
arrived later. Slice and ReaderAt scans return records in packet-index order.
[DNS over TCP (RFC 7766)](https://www.rfc-editor.org/rfc/rfc7766)

For SVCB and HTTPS records, inspect `rr.ServiceBinding` for the priority,
ordered ALPN identifiers, optional port, and presence of a nonempty ECH
configuration. `rr.Target` is the advertised name (empty for the DNS root).
Priority zero denotes an alias and its parameters are ignored. The parser
accepts uncompressed targets and strictly increasing parameter keys. Unknown
keys are skipped. A malformed parameter length or ordering sets
`InvalidRDataLength` and leaves the binding nil. More than 32 ALPN identifiers
returns `ErrDNSLimit`. The original RDATA remains available via `DataOffset`
and `DataLength`. For an OPT record, read `rr.EDNSUDPPayloadSize()` and
`rr.EDNSDOBit()` for the advertised payload size and DNSSEC OK flag.

To evaluate DNS tunneling or high-entropy subdomain indicators, call
`DNSLabelEntropy(qname)` on a domain name or `capture.DNSDomainStats(data)` to
aggregate query counts, unique subdomain fan-out, `NXDOMAIN` counts, maximum
label length, subdomain Shannon entropy, TXT answer payload volume, and a
composite `TunnelScore` ($[0.0, 1.0]$) per group. Grouping uses the last two
labels, so both
`a.example.co.uk` and `b.other.co.uk` contribute to `co.uk`.

## Parse TLS handshakes and JA4+ fingerprints

Call `ParseTLSRecords(stream)` on a TCP payload or reassembled stream, or call
`capture.TLS(data)` (or `capture.TLSWithKeyLog(data, extraKeyLog)`) to
reassemble TCP flows and decode TLS 1.2 and TLS 1.3 `ClientHello`, `ServerHello`,
and `Certificate` handshake messages:

- `TLSClientHello.JA4` reports the 36-character FoxIO JA4 fingerprint (filtering
  RFC 8701 GREASE values, sorting cipher suites and non-SNI/non-ALPN extensions,
  and preserving signature scheme wire order).
- `TLSServerHello.JA4S` reports the FoxIO JA4S fingerprint over the server's
  selected version, cipher suite, ALPN, and wire-order extension list.
- `ClientHello.SupportedGroups` lists advertised groups. `KeyShareGroups`
  lists groups with an offered key share. Both retain up to `MaxTLSExtensions`
  non-GREASE IDs in wire order. A malformed key-share vector contributes no
  IDs. The parser skips the public-key bytes.
- `ClientHello.HasECH` reports a nonempty encrypted_client_hello extension.
  This observation includes GREASE ECH offers. The extension ID also appears
  in `Extensions` when its payload is empty. A passive observer can read the
  outer ClientHello. The inner server name remains encrypted.
  [Encrypted Client Hello (RFC 9849)](https://www.rfc-editor.org/rfc/rfc9849)
- `ServerHello.SelectedGroup` gives the group from a structurally valid
  server key share (zero when unavailable). If `IsHelloRetryRequest` is true,
  the group is the one requested for the next ClientHello. For example,
  `!sh.IsHelloRetryRequest && sh.SelectedGroup == pcap.TLSGroupX25519MLKEM768`
  identifies an observed ServerHello selecting that hybrid group.
- Both hellos expose the bounded, copied `SessionID`, `HasSessionTicket`,
  and `HasPSK`. For TLS 1.2, `hs.IsResumed` indicates a nonempty session ID
  echoed by the server with no certificate in the parsed handshake. Missing
  capture data can affect this inference. For TLS 1.3 it indicates a server
  PSK selection, which can also use an externally provisioned key. A client
  offer alone is insufficient. After a HelloRetryRequest the parser checks
  the next ServerHello for selection and retains the first hello for JA4S.
  For example, `hs.ClientHello.HasPSK && !hs.IsResumed` identifies a captured
  offer without observed acceptance.
- To inspect mutual TLS, read `HasCertificateRequest` for the server's request
  and `ClientCertificates` for the chain the client presented. Each side has
  its own `MaxTLSCertificates` limit. For TLS 1.3, the client and server
  handshake secrets unlock their respective directions independently. A
  missing client chain can reflect an empty reply, missing packets, or a
  missing secret. A presented certificate alone does not establish that the
  server accepted it. For example:

  ```go
  for _, cert := range record.Handshake.ClientCertificates {
      fmt.Println(record.FlowIndex, cert.JA4X, cert.DNSNames)
  }
  ```

- Each certificate in the chain exposes DNS SANs in `DNSNames` and IPv4/IPv6
  SANs in `IPAddresses` as `netip.Addr` values. For example,
  `record.Handshake.Certificates[0].IPAddresses` gives the leaf's addresses
  when the chain is present. Each list is nil when absent and preserves the
  first 64 entries in certificate order, including duplicates. If either
  list exceeds the limit, `SANsTruncated` is true for that certificate.
  `RawDER` retains the complete certificate. Cleartext and decrypted client and server
  certificates follow the same rules for slice and ReaderAt scans.
- `TLSCertificate.JA4X` (and standalone `JA4XFromDER` / `JA4XFromCert`) reports
  the FoxIO JA4X fingerprint over the certificate's raw ASN.1 issuer RDNs,
  subject RDNs, and X.509 extension OIDs. When a PcapNG `DSB` block or
  `extraKeyLog` contains `SERVER_HANDSHAKE_TRAFFIC_SECRET`, `TLS` and
  `TLSWithKeyLog` automatically decrypt the TLS 1.3 encrypted server
  `Certificate` handshake message and populate `Certificates` and `JA4X`.
- `TLSAnomalies` reports `SNIIPLiteral`, `EmptySNI`, `DuplicateExtension`,
  `ALPNTransportMismatch`, `SelfSignedCertificate`, `InvalidCertificateDER`, and
  `TruncatedRecord`.

## Decrypt QUIC Initial packets

Call `DecryptQUICInitial(datagrams)` on a slice of UDP payloads or call
`capture.QUIC(data)` to decrypt QUIC v1 (RFC 9001) and QUIC v2 (RFC 9369)
Initial packets using `crypto/hkdf` and `crypto/aes`, remove header protection,
reassemble `CRYPTO` frames across UDP packets, and parse the inner TLS 1.3
`ClientHello` (`q13...` JA4 fingerprint). Use `capture.HasQUICJA4(data, ja4)`
and `capture.HasQUICSNI(data, sni)` for direct matching. Initial keys can be
derived from the version-specific salt and the client’s destination connection
ID. Application traffic uses separate keys. The Initial parser exposes the
handshake metadata even when application payloads remain opaque.
[QUIC v1 Initial secrets](https://www.rfc-editor.org/rfc/rfc9001#section-5.2) ·
[QUIC v2 changes](https://www.rfc-editor.org/rfc/rfc9369#section-3.3)

## Decrypt TLS 1.2 and TLS 1.3 streams offline

Call `capture.DecryptedTLSStreams(data, extraKeyLog)` to decrypt TLS 1.2
(`CLIENT_RANDOM` master secrets with AES-128-GCM and AES-256-GCM cipher suites)
and TLS 1.3 (`CLIENT_TRAFFIC_SECRET_0` / `SERVER_TRAFFIC_SECRET_0` with
`TLS_AES_128_GCM_SHA256` and `TLS_AES_256_GCM_SHA384`) application streams using
secrets embedded in PcapNG Decryption Secrets Blocks (`DSB`) or supplied in
`extraKeyLog` (`SSLKEYLOGFILE` format).

## Parse HTTP messages and carve payloads

Call `ParseHTTPRequest(stream)` or `ParseHTTPResponse(stream)` on a TCP stream,
or call `capture.HTTP(data)` to extract HTTP/1.x requests, responses, FoxIO
`JA4H` fingerprints, and carved `Body` payloads (`Content-Length` and
`Transfer-Encoding: chunked`) from both cleartext TCP streams and DSB-decrypted
TLS 1.2 and TLS 1.3 flows.

For a single `gzip`, `x-gzip`, or `deflate` content coding, the parser removes
chunk framing before decoding the content. Deflate supports zlib streams and raw
DEFLATE streams without a zlib header. `ContentEncoding` carries the header
value, and `IsDecompressed` reports whether `Body` contains decoded bytes.
Unsupported or stacked codings leave the carved body as-is. A decoding failure
keeps the carved body and sets `Anomalies.InvalidContentEncoding`. If decoded
output exceeds 4 MiB, `Body` contains the first 4 MiB and
`Anomalies.DecompressionLimitExceeded` is true.

`BodyLength` is the length of the returned body. `BodyOffset` and the parser's
consumed byte count refer to the original stream, so use the consumed count
to locate the next pipelined message.

A call to `capture.HTTP(data)` shares a 64 MiB decoding budget across all
cleartext and decrypted directions. The budget counts bytes produced before a
decoding failure and charges up to 4 MiB per message. On budget exhaustion,
the call returns an error wrapping `ErrHTTPLimit` and no records.

For HTTP/2 (`h2c` cleartext or decrypted TLS `h2`), call
`ParseHTTP2Frames(stream)` or `capture.HTTP2(data)` to parse the 24-byte HTTP/2
client preface, `SETTINGS` parameter pairs and `SettingsFingerprint`
(`id:val;id:val`), `WINDOW_UPDATE` increments, and reassembled per-stream `DATA`
frame payloads (handling padded `DATA` frames under `MaxHTTPBodyBytes`).

## Parse SSH handshakes and HASSH

Call `ParseSSHHandshake(clientStream, serverStream)` or `capture.SSH(data)` to
extract SSH version banners, `SSH_MSG_KEXINIT` algorithm lists, `HASSH` /
`HASSHServer` MD5 fingerprints, and FoxIO `JA4SSH` session fingerprints.

## Parse SMB2, NTLMSSP, Kerberos v5, and RDP messages

Call `ParseSMB2Message(buf)`, `ParseNTLMSSP(token)`, or `capture.SMB(data)` to
extract SMB2/3 `NEGOTIATE` and `SESSION_SETUP` metadata (dialect revision,
signing flags, message/session IDs) and embedded NTLMSSP Type 1, Type 2, and
Type 3 tokens (server challenge, target/domain/user/workstation strings, and
NetBIOS/DNS computer and domain names from target info attribute-value pairs).
NTLM extraction examines the declared security buffer. Capture walks can skip
NetBIOS keep-alives, SMB1 negotiation, and complete oversized data frames to
reach later SMB2 commands on the same connection.

For a `TREE_CONNECT` request, `Message.ShareName` gives the full UNC path.
For a `CREATE` request, `Message.FileName` gives the wire name, including a
named pipe such as `srvsvc` on an IPC share. An empty CREATE name opens the
share root. Synchronous headers expose `TreeID`. To associate a CREATE with
a share, match the TREE_CONNECT request to its response by message ID, then
use the response tree ID within the same session and connection.

Both names are length-delimited UTF-16LE. The direct parser returns
`ErrInvalidSMB` for incomplete frames or invalid name spans and `ErrSMBLimit`
for names exceeding 4,096 input bytes. It returns the first command from a
compound packet. Capture scans emit each readable compound command and skip
malformed commands. When `Message.IsEncrypted` is true, `SessionID` and
`OriginalMessageSize` are observations from the 52-byte SMB3 transform
header. The ciphertext stays opaque.

Call `ParseKRB5(buf)` or `capture.Kerberos(data)` to decode ASN.1 DER Kerberos
v5 `AS-REQ`, `AS-REP`, `TGS-REQ`, `TGS-REP`, and `KRB-ERROR` messages over UDP
and TCP port 88, including client/service principal names, realm, requested
encryption types, and the encryption types on replies. Use `HasRC4HMAC` to
find messages mentioning encryption type 23 when auditing legacy crypto.
On TCP, the scanner reassembles each port-88 direction and attributes the
message to the packet containing the first byte of its four-byte record mark.
[Kerberos over TCP (RFC 4120)](https://www.rfc-editor.org/rfc/rfc4120#section-7.2.2)

Call `ParseRDPNegotiation(buf)` or `capture.RDP(data)` to decode TPKT / X.224
Connection Request and Connection Confirm PDUs, `Cookie: mstshash=...` tokens,
and `RDP_NEG_REQ` / `RDP_NEG_RSP` security protocol flags (`RDPProtoTLS`,
`RDPProtoCredSSP`, `RDPProtoHybridEx`).

## Compute C2 beacon and flow statistics

Call `ComputeBeaconStats(timestampsNs, payloadBytes, clientBytes, serverBytes)`
or `capture.Beacons(data)` to calculate median inter-arrival intervals, median
absolute deviation (MAD), jitter ratios, Bowley quartile skewness periodicity
scores, payload size uniformity, Producer-Consumer Ratio (PCR), and composite
`BeaconScore` values in $[0.0, 1.0]$.

## Write captures

Use `NewPCAPWriter(w, linkType, snapLen)` for single-interface classic PCAP.
Pass Unix nanoseconds and the complete packet to `WritePacket`. The writer
stores up to `snapLen` bytes and preserves the original length. Timestamps must
fit unsigned 32-bit Unix seconds; zero snaplen selects `DefaultLiveSnapLen`.

Use `NewPCAPNGWriter(w, opts)` to stream PcapNG `SHB`, `IDB` (nanosecond
resolution), `NRB` (`WriteNameResolution`), `ISB` (`WriteInterfaceStats`),
`DSB` (`WriteDecryptionSecrets`), and process-attributed `EPB` (`WritePacket`)
blocks to any `io.Writer`. Interface 0 is ready immediately; set `LinkTypeSet: true`
to select `LinkTypeNull` explicitly on interface 0 for any interface name. Call
`AddInterface` for each additional interface and use its returned ID in
`PacketRecord` and `InterfaceStatistics`. Each interface has its own link type
and snaplen. After an output error, start a new capture stream.

Call `capture.ExtractFlowPCAPNG(data, w, flowIndex)` to write one bidirectional
flow. Pass the original capture bytes and the zero-based index from `Flows`.
For PcapNG input, the export retains the source sections, registers only the
interfaces used by selected packets, and preserves their timestamp encoding
and packet options. Name records, process definitions and decryption secrets
are capture-wide and can describe other flows. Classic PCAP input becomes a
single-interface PcapNG capture. An absent flow returns `ErrOutOfBounds`
before writing output.

## Capture live interface traffic

Use `OpenLive(ifaceName, opts)` to capture live packets from an OS network
interface using standard-library `syscall` descriptors (`/dev/bpf*` on macOS,
`AF_PACKET` on Linux, `SIO_RCVALL` raw sockets on Windows) without `cgo` or
`libpcap`. Use `BPFFilterTCPPort`, `BPFFilterUDPPort`, `BPFFilterIPProtocol`,
and `BPFFilterIPv4Host` to construct classic BPF filter programs, or `EvalBPF`
to evaluate a classic BPF program in memory.

Call `live.Stats()` before closing the handle to check kernel packet loss:

```go
stats, err := live.Stats()
if err != nil {
    return err
}
fmt.Printf("received=%d dropped=%d\n", stats.PacketsReceived, stats.PacketsDropped)
```

Linux and macOS report per-handle totals since opening. You can poll while
reading packets. Each kernel counter is 32 bits, so poll before it advances by
2³² packets. The received count follows the backend's filter accounting. The
drop count measures capture-buffer loss. Windows and other backends without
counters return `ErrLiveCaptureUnsupported`.
