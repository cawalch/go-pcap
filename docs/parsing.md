# Parse packet captures and frames

This guide describes buffer ownership, parser limits, error handling, container
metadata, and L2–L4 frame decoding. For installation and a complete example,
see the [README](../README.md).

## Parse capture containers

`New` parses classic PCAP headers or PcapNG section blocks (`SHB`, `IDB`, `DSB`,
`EPB`, and `SPB`) and validates block framing across the buffer. It copies
header values, interface descriptors, and Decryption Secrets Block (`DSB`)
payloads without retaining the input buffer. It records `int64(len(data))` as
`Capture.FileSize`.

A truncated capture succeeds as long as its initial container header (the
24-byte classic PCAP header or the first PcapNG Section Header Block) is valid.
When a trailing packet record or PcapNG block extends past `data`, `New` stops
at the last complete record, sets `Capture.DeclaredExtent` to include the
declared trailing record end, and marks `Capture.InputTruncated() == true`.
Use `NewWithLength(data, streamLength)` when only a leading stream prefix is
buffered while the total stream length is known.

If you don't modify its exported fields, you can read a `Capture` concurrently
from multiple goroutines. Unlike `Capture`, `SafeReader` retains a reference to
its input buffer; don't modify that buffer concurrently with reads.

## Work and output limits

The following limits apply to each parse call:

| Limit | Maximum | Purpose |
| --- | --- | --- |
| `MaxInterfaces` | 256 interfaces | Bounds PcapNG `IDB` descriptors per capture |
| `MaxPackets` | 1,048,576 packets | Bounds packets indexed or returned by `New`, `Packets`, and `Flows` |
| `MaxFlows` | 65,536 flows | Bounds distinct 5-tuple flows aggregated by `Flows` |
| `MaxDecryptionSecrets` | 256 blocks | Bounds PcapNG `DSB` blocks per capture |
| `MaxDecryptionSecretBytes` | 4 MiB | Bounds cumulative secret payload bytes copied across all `DSB` blocks |
| `MaxOptionsPerBlock` | 64 options | Bounds PcapNG TLV options per block |
| `MaxOptionStringBytes` | 4,096 bytes | Bounds individual PcapNG string options (`if_name`, `if_description`, `shb_os`) |
| `MaxSnapLen` | 16 MiB | Bounds maximum packet capture length accepted in headers |
| `MaxFrameLayers` | 8 layers | Bounds stack-allocated layer spans per decoded frame |
| `MaxVLANTags` | 4 tags | Bounds nested 802.1Q / 802.1ad VLAN tags per Ethernet frame |
| `MaxIPv6ExtHeaders` | 8 headers | Bounds IPv6 extension headers traversed per packet |
| `MaxSegmentsPerFlow` | 4,096 segments | Bounds TCP segments buffered per flow direction |
| `MaxFlowStreamBytes` | 4 MiB | Bounds reassembled bytes per flow direction |
| `MaxTotalStreamBytes` | 64 MiB | Bounds total reassembled TCP stream bytes per `Streams` call |
| `MaxDNSQuestions` | 64 questions | Bounds questions per DNS message |
| `MaxDNSResourceRecords` | 256 records | Bounds total answer, authority, and additional records per DNS message |
| `MaxDNSCompressionJumps` | 16 jumps | Bounds RFC 1035 label pointer hops per domain name |
| `MaxTLSHandshakeBytes` | 256 KiB | Bounds coalesced TLS handshake payload size |
| `MaxTLSCertificates` | 16 certificates | Bounds X.509 certificates parsed per TLS Certificate message |
| `MaxQUICCryptoBytes` | 64 KiB | Bounds reassembled QUIC Initial `CRYPTO` stream size |
| `MaxQUICPacketsPerFlow` | 64 packets | Bounds Initial UDP datagrams inspected per QUIC flow |
| `MaxHTTPHeaders` | 128 headers | Bounds HTTP header lines per request or response |
| `MaxHTTPBodyBytes` | 4 MiB | Bounds carved HTTP request or response body size |
| `MaxSSHKexPacketBytes` | 32 KiB | Bounds SSH `SSH_MSG_KEXINIT` packet length |

Use `errors.Is` with `ErrNotPCAP`, `ErrInvalidMagic`, `ErrInvalidHeader`,
`ErrInvalidBlock`, `ErrInvalidPacket`, `ErrInvalidFrame`, `ErrInterfaceLimit`,
`ErrPacketLimit`, `ErrFlowLimit`, `ErrSecretLimit`, `ErrOptionLimit`,
`ErrOutOfBounds`, or `ErrIntegerOverflow` to classify failures. See
[Workload comparisons and parser audit](workloads-and-audit.md) for worst-case
complexity bounds, adversarial input handling, and benchmark measurements.

## Inspect truncation and anomalies

Call `Capture.DeclaredExtent` or `Capture.InputTruncated` to check whether the
input ends before a declared packet record or PcapNG block finishes. Call
`Capture.Anomalies` to inspect non-fatal container anomalies:

- `TruncatedPacketBlock`: A packet header or PcapNG block declared a length
  extending past the end of `data`.
- `CaptureLenExceedsOriginalLen`: A packet record declared `CaptureLen > OriginalLen`.
- `CaptureLenExceedsSnapLen`: A packet record declared `CaptureLen` larger than
  its interface's `SnapLen` (when `SnapLen > 0`).
- `UnknownLinkType`: An interface declared an unrecognized link-layer type.
- `TrailingBytes`: Trailing bytes after the last block were too short to form a
  complete record header.

## Read packet records

Call `capture.Packets(data)` with the original bytes passed to `New`. Each
returned `PacketRecord` contains:

- `Index`: Zero-based packet index in file order.
- `InterfaceID` and `LinkType`: Link-layer encapsulation type for decoding.
- `TimestampNs`: Packet timestamp normalized to nanoseconds since the Unix epoch.
- `CaptureLen` and `OriginalLen`: Captured and on-wire byte counts.
- `PayloadOffset` and `PayloadLength`: Byte range of the captured frame inside
  `data`. Pass the `PacketRecord` to `capture.PacketPayload(data, pkt)` to obtain
  a bounds-checked zero-copy slice into `data`.
- `ProcessID`, `HasProcessID`, `ThreadID`, `HasThreadID`, `Flags`, and
  `DropCount`: Process attribution and packet metadata decoded from PcapNG
  Enhanced Packet Block options.

## Decode L2–L4 frames

Call `DecodeFrame(payload, linkType)` on a packet payload slice. `DecodeFrame`
parses link, network, and transport headers into a value `Frame` struct without
heap allocations:

- Supported link types: `LinkTypeEthernet` (with 802.1Q and 802.1ad VLAN tags),
  `LinkTypeLinuxSLL`, `LinkTypeLinuxSLL2`, `LinkTypeNull` (BSD loopback),
  `LinkTypeRaw`, `LinkTypeIPv4`, and `LinkTypeIPv6`.
- Supported network headers: `IPv4` (with fragment detection) and `IPv6` (with
  bounded extension-header traversal for Hop-by-Hop, Routing, Fragment,
  Destination Options, and Authentication headers), plus `ARP`.
- Supported transport headers: `TCP` (extracting ports, sequence/acknowledgment
  numbers, flags, window size, and raw TCP option range for `JA4T`), `UDP`,
  `ICMPv4`, and `ICMPv6`.
- `Frame.PayloadOffset` and `Frame.PayloadLength` identify the inner transport
  payload slice (`payload[frame.PayloadOffset : frame.PayloadOffset+frame.PayloadLength]`).

## Aggregate 5-tuple flows

Call `capture.Flows(data)` to aggregate IPv4 and IPv6 packets into deterministic
bidirectional flows ordered by their first appearance in the capture. The first
packet observed for a 5-tuple defines the client (`SrcAddr`, `SrcPort`) to
server (`DstAddr`, `DstPort`) direction; replies in the reverse direction increment
`ServerPackets` and `ServerBytes`. For TCP flows, `Flows` records the first
client `SYN` fingerprint in `ClientJA4T` and the first server `SYN-ACK`
fingerprint in `ServerJA4TS`.

## Reassemble TCP streams

Call `capture.Streams(data)` to reassemble ordered directional TCP byte streams
(`Client` and `Server`) for every TCP flow in the capture, or call
`ReassembleTCP(segments)` directly on a slice of `TCPSegmentInput`. Reassembly
resolves overlapping segments using a first-seen-wins policy and sets
`StreamAnomalies.OverlapConflict` when a later overlapping segment contains
differing bytes at the same sequence offset.

## Parse DNS messages

Call `ParseDNS(payload)` on a single DNS message or `capture.DNS(data)` to
extract DNS queries and responses over UDP (ports 53, 5353, 5355) and TCP (port
53 length-prefixed). Compression pointers must point strictly backward and may
jump at most `MaxDNSCompressionJumps` times. Use `capture.HasDNSQuery(data, qname)`
to test whether a capture queries a domain without allocating `DNSRecord` slices.

## Parse TLS handshakes and JA4+ fingerprints

Call `ParseTLSRecords(stream)` on a TCP payload or reassembled stream, or call
`capture.TLS(data)` to reassemble TCP flows and decode TLS 1.2 and TLS 1.3
`ClientHello`, `ServerHello`, and `Certificate` handshake messages:

- `TLSClientHello.JA4` reports the 36-character FoxIO JA4 fingerprint (filtering
  RFC 8701 GREASE values, sorting cipher suites and non-SNI/non-ALPN extensions,
  and preserving signature scheme wire order).
- `TLSServerHello.JA4S` reports the FoxIO JA4S fingerprint over the server's
  selected version, cipher suite, ALPN, and wire-order extension list.
- `TLSCertificate.JA4X` (and standalone `JA4XFromDER` / `JA4XFromCert`) reports
  the FoxIO JA4X fingerprint over the certificate's raw ASN.1 issuer RDNs,
  subject RDNs, and X.509 extension OIDs.
- `TLSAnomalies` reports `SNIIPLiteral`, `EmptySNI`, `DuplicateExtension`,
  `ALPNTransportMismatch`, `SelfSignedCertificate`, `InvalidCertificateDER`, and
  `TruncatedRecord`.

## Decrypt QUIC Initial packets

Call `DecryptQUICInitial(datagrams)` on a slice of UDP payloads or call
`capture.QUIC(data)` to decrypt QUIC v1 (RFC 9001) and QUIC v2 (RFC 9369)
Initial packets using `crypto/hkdf` and `crypto/aes`, remove header protection,
reassemble `CRYPTO` frames across UDP packets, and parse the inner TLS 1.3
`ClientHello` (`q13...` JA4 fingerprint). Use `capture.HasQUICJA4(data, ja4)`
and `capture.HasQUICSNI(data, sni)` for direct matching.

## Decrypt TLS 1.3 streams offline

Call `capture.DecryptedTLSStreams(data, extraKeyLog)` to decrypt TLS 1.3
application streams (`TLS_AES_128_GCM_SHA256` and `TLS_AES_256_GCM_SHA384`)
using secrets embedded in PcapNG Decryption Secrets Blocks (`DSB`) or supplied
in `extraKeyLog` (`SSLKEYLOGFILE` format).

## Parse HTTP messages and carve payloads

Call `ParseHTTPRequest(stream)` or `ParseHTTPResponse(stream)` on a TCP stream,
or call `capture.HTTP(data)` to extract HTTP/1.x requests, responses, FoxIO
`JA4H` fingerprints, and carved `Body` payloads (`Content-Length` and
`Transfer-Encoding: chunked`) from both cleartext TCP streams and DSB-decrypted
TLS 1.3 flows.

## Parse SSH handshakes and HASSH

Call `ParseSSHHandshake(clientStream, serverStream)` or `capture.SSH(data)` to
extract SSH version banners, `SSH_MSG_KEXINIT` algorithm lists, and `HASSH` /
`HASSHServer` MD5 fingerprints.

## Parse SMB2 and NTLMSSP messages

Call `ParseSMB2Message(buf)`, `ParseNTLMSSP(token)`, or `capture.SMB(data)` to
extract SMB2/3 `NEGOTIATE` and `SESSION_SETUP` metadata (dialect revision,
signing flags, message/session IDs) and embedded NTLMSSP Type 1, Type 2, and
Type 3 tokens (server challenge, target/domain/user/workstation strings, and
NetBIOS/DNS computer and domain names from target info attribute-value pairs).

## Compute C2 beacon and flow statistics

Call `ComputeBeaconStats(timestampsNs, payloadBytes, clientBytes, serverBytes)`
or `capture.Beacons(data)` to calculate median inter-arrival intervals, median
absolute deviation (MAD), jitter ratios, Bowley quartile skewness periodicity
scores, payload size uniformity, Producer-Consumer Ratio (PCR), and composite
`BeaconScore` values in $[0.0, 1.0]$.

## Write PcapNG captures

Use `NewPCAPNGWriter(w, opts)` to stream PcapNG `SHB`, `IDB` (nanosecond
resolution), `DSB` (`WriteDecryptionSecrets`), and process-attributed `EPB`
(`WritePacket`) blocks to any `io.Writer`.

## Capture live interface traffic

Use `OpenLive(ifaceName, opts)` to capture live packets from an OS network
interface using standard-library `syscall` descriptors (`/dev/bpf*` on macOS,
`AF_PACKET` on Linux) without `cgo` or `libpcap`.



