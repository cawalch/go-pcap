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

A truncated capture succeeds as long as its initial container header (the
24-byte classic PCAP header or the first PcapNG Section Header Block) is valid.
When a trailing packet record or PcapNG block extends past `data`, `New` stops
at the last complete record, sets `Capture.DeclaredExtent` to include the
declared trailing record end, and marks `Capture.InputTruncated() == true`.
If only a leading stream prefix is buffered while the total stream length is
known, call `NewWithLength(data, streamLength)`. For large files on disk, call
`NewFromReaderAt(r, size)` to parse container metadata without reading the
entire capture into a single byte slice. Both formats skip frame bytes. The PcapNG scanner reads packet headers,
options and block trailers. Use `PacketSeqFromReaderAt` to process records
in order and break when you have enough. `PacketsFromReaderAt` collects a
packet record slice. `FlowsFromReaderAt` starts with a 256-byte prefix or the
whole frame when shorter. It reads additional bytes into a reusable buffer
when needed to resolve flow headers and lengths. All frame reads count toward
the 64 MiB flow budget. The metadata scan incurs additional I/O. `DNSFromReaderAt`, `TLSFromReaderAt`, and `QUICFromReaderAt`
allocate a file-sized buffer and read the full capture. They return an error
wrapping `ErrPacketLimit` when the file exceeds 64 MiB.

If you don't modify its exported fields, you can read a `Capture` concurrently
from multiple goroutines. Unlike `Capture`, `SafeReader` retains a reference to
its input buffer; don't modify that buffer concurrently with reads.

## Work and output limits

The following limits bound parsing work and memory allocation on each call:

| Limit | Maximum | Purpose |
| --- | --- | --- |
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
| `MaxTLSHandshakeBytes` | 256 KiB | Bounds coalesced TLS handshake payload size |
| `MaxTLSCertificates` | 16 certificates | Bounds X.509 certificates parsed per TLS Certificate message |
| `MaxQUICCryptoBytes` | 64 KiB | Bounds reassembled QUIC Initial `CRYPTO` stream size |
| `MaxQUICPacketsPerFlow` | 64 packets | Bounds Initial UDP datagrams inspected per QUIC flow |
| `MaxHTTPHeaders` | 128 headers | Bounds HTTP header lines per request or response |
| `MaxHTTPBodyBytes` | 4 MiB | Bounds carved HTTP request or response body size |
| `MaxSSHKexPacketBytes` | 32 KiB | Bounds SSH `SSH_MSG_KEXINIT` packet length |
| `MaxSMB2PacketBytes` | 64 KiB | Bounds NetBIOS-framed SMB2/3 message length |
| `MaxNTLMTokenBytes` | 16 KiB | Bounds NTLMSSP token length |
| `MaxReaderAtScanBytes` | 64 MiB | Bounds cumulative flow frame reads or total file size for DNS, TLS and QUIC ReaderAt calls |
| `MaxFragmentGroups` | 1,024 groups | Bounds concurrent IPv4/IPv6 fragment groups tracked per scan |
| `MaxFragmentsPerGroup` | 16 fragments | Bounds IP fragments reassembled per fragmented packet |
| `MaxReassembledIPPacketBytes` | 65,535 bytes | Bounds reassembled IPv4/IPv6 packet payload size |
| `MaxHTTP2FramesPerStream` | 1,024 frames | Bounds HTTP/2 frames parsed per directional stream |
| `MaxKRB5PacketBytes` | 64 KiB | Bounds Kerberos v5 message length |
| `MaxRDPPacketBytes` | 16 KiB | Bounds RDP TPKT/X.224 negotiation PDU length |

Use `errors.Is` with `ErrNotPCAP`, `ErrInvalidMagic`, `ErrInvalidHeader`,
`ErrInvalidBlock`, `ErrInvalidPacket`, `ErrInvalidFrame`, `ErrInvalidDNS`,
`ErrInvalidTLS`, `ErrInvalidQUIC`, `ErrInvalidHTTP`, `ErrInvalidSSH`,
`ErrInvalidSMB`, `ErrInterfaceLimit`, `ErrPacketLimit`, `ErrFlowLimit`,
`ErrSecretLimit`, `ErrOptionLimit`, `ErrReassemblyLimit`, `ErrDNSLimit`,
`ErrTLSLimit`, `ErrQUICLimit`, `ErrHTTPLimit`, `ErrSSHLimit`, `ErrSMBLimit`,
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
- `ServerJA4L` (`<half_syn_synack_rtt_us>_<server_ttl>`) and `ClientJA4L`
  (`<half_synack_ack_rtt_us>_<client_ttl>`) from the 3-way handshake timestamps
  and IP `TTL` / `HopLimit`.
- First-seen process attribution (`ProcessID`, `UserID`, `ProcessName`,
  `ProcessArgs`, and `ContainerID`).

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

To evaluate DNS tunneling or high-entropy subdomain indicators, call
`DNSLabelEntropy(qname)` on a domain name or `capture.DNSDomainStats(data)` to
aggregate query counts, unique subdomain fan-out, `NXDOMAIN` counts, maximum
label length, subdomain Shannon entropy, TXT answer payload volume, and a
composite `TunnelScore` ($[0.0, 1.0]$) per registrable apex domain.

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
and `capture.HasQUICSNI(data, sni)` for direct matching.

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

Call `ParseKRB5(buf)` or `capture.Kerberos(data)` to decode ASN.1 DER Kerberos
v5 `AS-REQ`, `AS-REP`, `TGS-REQ`, `TGS-REP`, and `KRB-ERROR` messages over UDP
and TCP port 88, including client/service principal names, realm, requested
encryption types, and weak `RC4-HMAC` (`etype 23`, Kerberoasting) indicators.

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

## Write PcapNG captures

Use `NewPCAPNGWriter(w, opts)` to stream PcapNG `SHB`, `IDB` (nanosecond
resolution), `NRB` (`WriteNameResolution`), `ISB` (`WriteInterfaceStats`),
`DSB` (`WriteDecryptionSecrets`), and process-attributed `EPB` (`WritePacket`)
blocks to any `io.Writer`.

## Capture live interface traffic

Use `OpenLive(ifaceName, opts)` to capture live packets from an OS network
interface using standard-library `syscall` descriptors (`/dev/bpf*` on macOS,
`AF_PACKET` on Linux, `SIO_RCVALL` raw sockets on Windows) without `cgo` or
`libpcap`. Use `BPFFilterTCPPort`, `BPFFilterUDPPort`, `BPFFilterIPProtocol`,
and `BPFFilterIPv4Host` to construct classic BPF filter programs, or `EvalBPF`
to evaluate a classic BPF program in memory.
