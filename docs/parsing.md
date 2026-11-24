# Parse packet captures, frames, and protocols

For a runnable first scan, follow the [packet capture quick start](../README.md#quick-start-with-a-packet-capture).

| Task | Sections |
| --- | --- |
| Read a file | [Container metadata](#parse-capture-containers) · [Packet records](#read-packet-records) · [Limits](#work-and-output-limits) |
| Identify devices and connections | [ARP and IPv6 neighbors](#observe-arp-and-ipv6-neighbors) · [DHCPv4 leases](#dhcpv4-address-assignments) · [Flows](#aggregate-5-tuple-flows) |
| Investigate a web connection | [DNS](#parse-dns-messages-and-tunneling-metrics) · [TLS](#parse-tls-handshakes-and-ja4-fingerprints) · [QUIC](#decrypt-quic-initial-packets) · [HTTP](#parse-http-messages-and-carve-payloads) |
| Collect or share traffic | [Live capture](#capture-live-interface-traffic) · [Write or export a capture](#write-captures) |

## Parse capture containers

`New` parses classic Portable Packet Capture (PCAP) headers or PCAP Next
Generation (PcapNG) section blocks (`SHB`, `IDB`, `DSB`, `NRB`, `ISB`, `DPEB`,
`EPB`, `SPB`, and obsolete Packet Blocks) and validates block framing across
the buffer. It copies header values, interface descriptors, Name Resolution
Block (`NRB`) records, Interface Statistics Block (`ISB`) counters, Darwin
Process Event Block (`DPEB`) entries, and Decryption Secrets Block (`DSB`)
payloads without retaining the input buffer. It records `int64(len(data))` as `Capture.FileSize`.

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
options and block trailers. Large metadata blocks use a bounded read window
for name records and options, including name resolution blocks larger than
16 MiB. The block and record totals below apply when scanning a capture.
Streaming writers check individual calls and can continue across those totals. Use `PacketSeqFromReaderAt` to process records
in order and break when you have enough. `PacketsFromReaderAt` collects a
packet record slice. `FlowsFromReaderAt` starts with a 256-byte prefix or the
whole frame when shorter. It reads additional bytes into a reusable buffer
when needed to resolve flow headers and lengths. Both container metadata and frame reads
count toward the 64 MiB flow budget.

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
| `MaxFlows` | 65,536 flows | Bounds distinct five-tuples and the number of reassembled TCP connections |
| `MaxDecryptionSecrets` | 256 blocks | Bounds PcapNG `DSB` blocks per capture |
| `MaxDecryptionSecretBytes` | 4 MiB | Bounds cumulative secret payload bytes copied across all `DSB` blocks |
| `MaxPCAPNGBlocks` | 2,097,152 blocks | Bounds all PcapNG block types across sections |
| `MaxNamesPerRecord` | 64 names | Bounds nonempty names retained from a single name resolution record |
| `MaxNameResolutionRecords` | 16,384 records | Counts all non-terminator records across PcapNG name resolution blocks |
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
| `MaxTLSHandshakeRecords` | 128 records | Bounds the record scan for a directional plaintext handshake, including empty records and warning alerts |
| `MaxTLSHandshakeBytes` | 256 KiB | Bounds coalesced TLS handshake payload size |
| `MaxTLSExtensions` | 128 extensions | Bounds TLS extensions parsed per handshake message |
| `MaxTLSCertSANsPerKind` | 64 per kind | Bounds retained DNS names and IP addresses independently for each certificate |
| `MaxTLSCertificates` | 16 certificates | Bounds X.509 certificates parsed per TLS Certificate message |
| `MaxTLSHandshakesPerScan` | 16,384 handshakes | Bounds TLS handshakes returned per capture scan |
| `MaxTLSKeyLogEntries` | 4,096 entries | Bounds NSS keylog entries parsed per `ParseTLSKeyLog` / `TLSKeyLog` call |
| `MaxQUICCryptoBytes` | 64 KiB | Bounds reassembled QUIC Initial `CRYPTO` stream size |
| `MaxQUICPacketsPerFlow` | 64 packets | Bounds UDP datagrams inspected per QUIC Initial exchange |
| `MaxQUICFlowsPerScan` | 16,384 exchanges | Bounds QUIC Initial exchanges tracked per capture scan |
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
| `MaxReaderAtScanBytes` | 64 MiB | Bounds total reads per flow, DNS, TLS or QUIC ReaderAt scan |
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
- `InvalidTimestampResolution`: An interface declared an `if_tsresol` option
  whose value is longer or shorter than one byte.

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
  epoch. PcapNG decimal ($10^{-N}$) and binary ($2^{-N}$) resolutions
  round down to a whole nanosecond. The reader applies the signed
  `if_tsoffset` in seconds before clamping the result to the signed
  64-bit nanosecond range. Interface statistics use the same conversion.
- `CaptureLen` and `OriginalLen`: Captured and on-wire byte counts.
- `PayloadOffset` and `PayloadLength`: Byte range of the captured frame inside
  `data`. Pass `pkt` to `capture.PacketPayload(data, pkt)` to obtain a
  bounds-checked zero-copy slice into `data`.
- `ProcessID`, `ThreadID`, `UserID`, `ProcessName`, `ProcessArgs`,
  `ContainerID`, `Flags`, and `DropCount`: Process attribution and packet
  metadata decoded from PcapNG Enhanced Packet Block (EPB) options.
  Obsolete Packet Blocks supply `Flags` from their flags option and `DropCount`
  from their fixed header. A drop count of `0xffff` in that header means the
  count was unavailable and leaves `DropCount` at zero.

Apple PcapNG captures store process IDs and names in Process Information Blocks,
also called Darwin Process Event Blocks (DPEB). An EPB's Apple primary process
option (`0x8001`) indexes the preceding process blocks in its own section,
starting at zero. `PacketRecord` exposes the primary process when the index
resolves. Apple uses process ID `0xffffffff` for a name without a PID. The
reader sets `ProcessName` for these entries and leaves `HasProcessID` false.
Effective process references, service classes, packet metadata
flags, flow IDs, and trace tags use their own Apple options. The reader leaves
the process fields unset when only the effective process is available.
[Apple PcapNG definitions](https://github.com/apple-oss-distributions/libpcap/blob/aa560f1fd969af63ebfb182fa33373d1d2549de5/libpcap/pcap/pcap-ng.h#L315-L350)

The reader also accepts a resolvable legacy go-pcap process reference
(`0x8000`) when the native reference is absent. Earlier go-pcap writers put
inline attribution in the Apple option range. The reader decodes those inline
fields only for a section whose application is explicitly `go-pcap` and which
has yet to declare a process block. An earlier file without that application
marker may lose inline attribution on read.

## Decode L2–L4 frames and tunnels

Call `DecodeFrame(payload, linkType)` on a packet payload slice. `DecodeFrame`
parses link, tunnel, network, and transport headers into a value `Frame` struct
without heap allocations:

- Supported link types: `LinkTypeEthernet` (with up to 4 nested 802.1Q / 802.1ad
  VLAN tags), `LinkTypeLinuxSLL`, `LinkTypeLinuxSLL2`, `LinkTypeNull` (BSD
  loopback), `LinkTypeRaw`, `LinkTypeIPv4`, `LinkTypeIPv6`,
  `LinkTypeIEEE80211` (105), and `LinkTypeIEEE80211RadioTap` (127).
- Supported tunnel encapsulations: `MPLS` (`0x8847` / `0x8848`, up to 8 labels),
  `PPPoE` Session (`0x8864` over IPv4 or IPv6), `GRE` (`IPProto 47` over IPv4,
  IPv6, or Transparent Ethernet Bridging), `VXLAN` (`UDP 4789`), and `Geneve`
  (`UDP 6081`).
- Supported network headers: `IPv4` (with fragment detection), `IPv6` (with
  bounded extension-header traversal for Hop-by-Hop, Routing, Fragment,
  Destination Options, and Authentication headers), and `ARP`.
- Supported transport headers: `TCP` (extracting ports, sequence/acknowledgment
  numbers, flags, window size, and raw TCP option range for `JA4T`), `UDP`,
  `ICMPv4`, `ICMPv6`, Encapsulating Security Payload (ESP, IP protocol 50),
  and Internet Key Exchange version 2 (IKEv2) over UDP 500 or 4500.
- `Frame.PayloadOffset` and `Frame.PayloadLength` identify the innermost
  transport payload slice (`payload[frame.PayloadOffset : frame.PayloadOffset+frame.PayloadLength]`).

On a monitor-mode capture, `LayerRadiotap` gives the Radiotap header span.
`LayerIEEE80211` gives the MAC header span for Data frames and the Frame
Control span for other frames. For an unprotected, unfragmented Data frame
with a standard LLC/SNAP header, the decoder continues at the embedded
EtherType. This supports four-address frames, QoS, HT Control on QoS frames,
and the Radiotap data-padding flag. Protected frames, fragments, and
aggregated MAC service data units (A-MSDUs) stay opaque. For IP
and neighbor observations on an access point or controller mirror, capture
after decapsulation and use the Ethernet link type.

`LayerESP` spans the 8-byte SPI and sequence number header in IPv4 or IPv6.
The payload span starts at the protected body. ESP flows have no transport
ports. IKEv2 uses the existing UDP endpoints. On port 4500,
`LayerIKEv2` requires the four-byte Non-ESP Marker. It spans the 28-byte
IKEv2 header and the payload span starts after it. UDP-encapsulated ESP and
NAT keepalives retain their UDP payload spans. The decoder does not
authenticate or decrypt IPsec traffic.

The [reference frames](../testdata/framing/README.md) include a Radiotap
header longer than the default ReaderAt prefix. See the
[Radiotap flags](https://www.radiotap.org/fields/Flags.html),
[ESP framing](https://www.rfc-editor.org/rfc/rfc4303#section-2), and
[IKEv2 message format](https://www.rfc-editor.org/rfc/rfc7296#section-3.1).

IPv6 reassembly discards a datagram if fragments overlap, including identical
bytes. A first fragment must contain the complete UDP or TCP header, including
any preceding Authentication or Destination Options headers. DNS and QUIC
resolve those headers using fragment zero's Next Header field. The completion
packet supplies the flow index even when another fragment has a different
Next Header value.
Atomic IPv6 packets are decoded independently of pending fragment groups.

The [fingerprint reference fixtures](../testdata/foxio/README.md) identify the
FoxIO revisions and inputs used for compatibility tests.

## Observe ARP and IPv6 neighbors

Use `Capture.Neighbors` or `Capture.NeighborsFromReaderAt` to read local-link
messages as observed on the wire, in packet order. Match each observation to
controller logs by capture interface and timestamp. Repeated observations on
different interfaces retain their own packet indices.

For Ethernet/IPv4 ARP, inspect `Operation` for a request or reply. A probe
carries an unspecified sender IP address. The record preserves both protocol
addresses and both six-byte hardware fields, including all-zero fields.
For IPv6 Neighbor Discovery, a Solicitation can supply a source link-layer
address, and an Advertisement can supply a target link-layer address.
Missing options yield nil hardware addresses. An Advertisement also reports
the Router, Solicited and Override flags.

Both scanners accept up to four VLAN tags and inspect the outer network
protocol. They use a 96-byte frame prefix and extend it only for candidate
IPv6 datagrams with at most 4096 bytes of IPv6 payload. They share the 64 MiB
read budget and a 4096-record limit. ARP requires Ethernet hardware, IPv4
protocol and the corresponding address lengths. IPv6 checks include hop
limit 255, ICMPv6 code zero, a valid captured checksum, a unicast target,
duplicate-address-detection rules and bounded eight-byte-unit options.
Packets with a Fragment header or missing bytes are skipped. The scanner
uses the first applicable Ethernet link-layer option and checks all option
lengths. Captures taken before transmit checksum offload can omit a valid
checksum and therefore omit that observation.

### Find changes in observed neighbor bindings

Use `Capture.NeighborBindingChanges` or
`Capture.NeighborBindingChangesFromReaderAt` to find where successive
observations associate the same IP address with different hardware addresses.
ARP requests and replies contribute the sender address pair. An IPv6 Neighbor
Solicitation contributes its source IP and source link-layer option. A
Neighbor Advertisement contributes its target IP and target link-layer option,
including when its packet source differs from its target. The scan requires a
unicast IP address and a nonzero unicast media access control (MAC) address.
It skips duplicate address detection probes and packets without the relevant
link-layer option.

The scanners track Ethernet and Linux cooked v2 packets by capture interface,
link type, ordered VLAN IDs, and the interface index in the cooked v2 header.
They skip cooked v2 packets with an unknown interface index. Untagged packets
and packets with VLAN ID 0 use separate scopes. Each accepted observation
becomes the baseline, including repeated hardware addresses. A change reports
both packet indices and timestamps, and results follow file order even when
timestamps go backward. Use `Previous` and `Current` to inspect the operations
and the Solicited and Override flags. Use deployment information to assess
ownership and compare changes with events such as failover or reassignment.

The existing neighbor scan limits apply. The scan retains at most one prior
observation per scoped address and returns no partial changes if the scan
exceeds the read budget or the 4096-observation limit.

## DHCPv4 address assignments

Use `Capture.DHCPv4` or `Capture.DHCPv4FromReaderAt` to read Discover,
Offer, Request, ACK and NAK messages in capture order. Each observation
includes its packet index, timestamp and capture interface. To find an
acknowledged allocation, select ACK records with a valid `YourAddr`. A Request
can carry option 50 (`RequestedAddr`) or the client's existing address
(`ClientAddr`) during renewal. `NextServerAddr` identifies the BOOTP next
server. DHCP option 54 supplies `ServerIdentifier`. A later observation can
associate the same address with another client.

The scan accepts complete, unfragmented IPv4 UDP messages on client/server
ports 68/67, including relay-to-server and server-to-relay datagrams on 67/67.
It verifies the BOOTP request/reply operation, hardware address bounds, magic
cookie and option boundaries. Missing hardware addresses and client identifiers
are nil. Client identifiers are opaque bytes. `HasLease` and `HasHostname`
distinguish absent options from an advertised zero duration or empty hostname.

Each datagram can contain up to 4096 bytes and 128 non-padding options across
all fields. The parser skips padding, requires an End marker in every option
field and ignores bytes after End. Option 52 can select the file field, the
server-name field, or both, in that order. For repeated options the first
value wins. The parser validates subsequent lengths and does not concatenate
split values. Hostnames and client identifiers each retain at most 255 bytes.
Malformed and oversized messages are skipped.

The scan returns `ErrDHCPv4Limit` above 4096 observations or 64 MiB of candidate
datagrams. ReaderAt also applies the shared 64 MiB read budget to framing,
prefixes and candidate payloads. Ordinary UDP traffic only requires header
inspection. The default flow scan runs independently of DHCP.

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
  and IP `TTL` / `HopLimit`. Both values come from the first matching 3-way
  handshake completed in capture order. The SYN sender defines the client
  for these samples. If no handshake completes, `ServerJA4L` uses the first
  matching SYN and SYN-ACK pair. Matching retransmissions keep the first
  timestamp, and a matching reset clears the pending opening. Both flow readers
  use the same selection. With `SeparateTCPInterfaces` enabled, packets must
  match on the same interface. The scan limits pending interface-specific
  handshakes to `MaxFlows`.
- First-seen process attribution (`ProcessID`, `UserID`, `ProcessName`,
  `ProcessArgs`, and `ContainerID`). The first packet with attribution supplies
  these fields. Later packets can fill missing fields when they carry the same
  known PID. A name-only observation keeps its PID unknown.

Call `flow.CommunityID(seed)` on a summary from `Flows` or `FlowsFromReaderAt`
to correlate IPv4 or IPv6 TCP and UDP traffic with other tools. Both directions
produce the same ID. Match the seed across tools (the default is zero).
The method computes the ID only when called and returns an empty string for
unsupported protocols, invalid or mixed-family addresses, or a summary with
`PortsUnavailable` set. A decoded port value of zero is valid.

## Trace a client connection and a TLS proxy

If DNS succeeds but a connection fails, capture both directions at the
client-facing interface before NAT.
When the service uses a TLS-terminating proxy, also
capture the proxy's client-facing and origin-facing interfaces. Preserve the
interface names and use synchronized capture clocks.

1. In the [client fixture](../testdata/deployments/client.pcapng), call `DNS` to
   find the answer `trace.example → 198.51.100.80`. Follow the response's
   `PacketIndex` to check its capture timestamp. `Flows` shows the TCP tuple
   `192.0.2.14:50000 → 198.51.100.80:443`. The first connection has visible
   ClientHello and ServerHello messages, followed by a TCP reset. A later SYN
   and distinct initial sequence numbers show the tuple being reused.
   `ExtractFlowPCAPNG` for flow 1 exports both attempts because the flow key is
   the bidirectional 5-tuple. The export preserves the later packet's captured
   length of 58 bytes and original length of 76 bytes.
2. In the [proxy fixture](../testdata/deployments/proxy.pcapng), call `TLS`
   and match each `FlowIndex` with its `Flows` entry. The client-facing
   ClientHello offers `app.example` and `h2`. The origin-facing ClientHello
   offers `origin.example` and `http/1.1`. The second ClientHello comes from
   the proxy's upstream socket. Each leg has its own ServerHello and TLS
   session. The visible ALPN values are client offers. The certificate
   chains, server-selected ALPN, and application bytes in TLS 1.3 require the
   corresponding TLS secrets when those encrypted records are available.
   Use the proxy request log to associate a front-end request with an
   upstream TCP session, especially when the proxy pools connections.
3. To associate a pre-NAT IP with a device at the time of the capture, check
   a contemporaneous Dynamic Host Configuration Protocol (DHCP) ACK or lease
   log. In the [IoT fixture](../testdata/deployments/iot.pcapng), `DHCPv4`
   reports a Discover and an Offer with `YourAddr` set to `203.0.113.42`.
   The Offer gives a candidate assignment. Use timestamped interface and lease
   records to identify the client. After NAT, use the gateway's translation
   log to associate the translated tuple with the original client.

The [reference decoder commands and packet numbers](../testdata/deployments/README.md)
let you repeat these checks on the synthetic fixtures.

## Reassemble TCP streams

Call `capture.Streams(data)` to reassemble ordered directional TCP byte streams
(`Client` and `Server`) for every TCP flow in the capture, or call
`ReassembleTCP(segments)` directly on a slice of `TCPSegmentInput`. Reassembly
resolves overlapping segments using a first-seen-wins policy and sets
`StreamAnomalies.OverlapConflict` when a later overlapping segment contains
differing bytes at the same sequence offset.

`Streams` starts a new connection when an opening SYN follows a midstream
capture or changes the opening sequence number or sending endpoint. A matching
SYN retransmission stays in its connection. Each connection uses its first
observed packet to define the client direction. Connections that reuse a
five-tuple share the same `FlowIndex` and directional segment and byte limits.
Without a new opening SYN, tuple reuse can be indistinguishable from a gap.

By default, TCP reassembly combines observations across capture interfaces.
This lets you recover a connection when its packets were captured on different
interfaces. When the PcapNG interfaces observe independent networks, set
`capture.SeparateTCPInterfaces` before calling a stream-based analyzer. It
tracks connections by the capture-wide `PacketRecord.InterfaceID` as well as
by the five-tuple. The flow index and packet totals still cover the entire
capture. All connections on that tuple share the directional segment and byte
limits.

For example, if `capture` was parsed from `data`, recover HTTP/1 requests and
responses separately for each interface.

```go
capture.SeparateTCPInterfaces = true
records, err := capture.HTTP(data)
```

Set the same field on a capture from `NewFromReaderAt` before calling
`HTTPRequestsFromReaderAt` to get packet-attributed requests. Look up each
observation's `PacketIndex` in the packet records to identify its interface.

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

DNS record flow indices use the order returned by `capture.Flows(data)`. For
fragmented UDP messages, the record uses the fragment flow index and the
reassembled UDP ports. The packet index and timestamp identify the fragment
that completed the message.

[DNS over TCP (RFC 7766)](https://www.rfc-editor.org/rfc/rfc7766)

### Diagnose DNS transactions

Run the [DNS transaction example](../examples/dns-transactions/main.go) from
the repository root. It scans a seekable capture using `DNSFromReaderAt`.
Frame numbers start at one so you can jump to them in Wireshark.

```sh
go run ./examples/dns-transactions testdata/deployments/dns-transactions.pcap
```

| Frames in the synthetic capture | Observation |
| --- | --- |
| 1 → 2 | A successful lookup took 8 ms at the capture point. |
| 3 → 4 | The resolver replied NXDOMAIN (header RCODE 3) after 5 ms. |
| 5 → 8 and 6 → 7 | Two TCP queries were outstanding. The first took 1.2 s, the second 6 ms. The replies arrived in reverse order. |
| 9, 10 and 11 | Two identical UDP questions preceded one reply. Both queries and the reply are marked ambiguous, without elapsed time. |
| 12 | A SERVFAIL reply (header RCODE 2) was observed without its query. |
| 13 | The capture ended with an outstanding query. Packet loss, a one-sided capture, and ending the capture too early can all leave a query unanswered in the report. |

The example pairs single-question, standard DNS queries on port 53 by flow,
directional endpoints, transaction ID, and decoded question name, type and
class. Names compare case-insensitively for ASCII letters. After identical
outstanding questions collide, that key stays ambiguous for the remainder of
the capture. Unsupported question shapes and structural anomalies produce an
`unsupported` observation when the DNS parser returns a record.

Use a capture from one observation point. A flow index groups a five-tuple
and can span reused connections. For TCP, frame numbers identify the packet
containing the first length-prefix byte. Elapsed time includes everything
between the two observations, including network transit. Missing, zero or
backward timestamps leave it unknown. Inspect the original packets for the
TC flag, EDNS extended response codes, and any evidence outside this pairing.

### Read DNS over TLS

For DNS-over-TLS on TCP/853, use `capture.DNSOverTLS(data, extraKeyLog)` or
`capture.DNSOverTLSFromReaderAt(r, extraKeyLog)`. Both use the existing TLS
1.2 and TLS 1.3 decryptors with embedded or caller-supplied NSS key logs.
Only complete length-prefixed messages from authenticated plaintext are
passed to `ParseDNS`. Inspect `Message.Anomalies` for DNS section truncation.
A known TCP gap excludes that direction. Missing or incorrect keys can yield
an empty result. Each record identifies the flow and directional endpoints.
[DNS over TLS (RFC 7858)](https://www.rfc-editor.org/rfc/rfc7858#section-3.3)

For example, given a capture opened with `NewFromReaderAt` and its original
reader `r`, print the DNS questions recovered with embedded keys:

```go
records, err := capture.DNSOverTLSFromReaderAt(r, nil)
if err != nil {
	return err
}
for _, record := range records {
	for _, question := range record.Message.Questions {
		fmt.Println(record.FlowIndex, record.SrcAddr, record.DstAddr, question.Name)
	}
}
```

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
composite `TunnelScore` ($[0.0, 1.0]$) per group. The apex heuristic uses the final two
labels by default. For selected two-label suffixes, it includes one more
label. For example, `a.example.co.uk` groups under
`example.co.uk` and `b.other.co.uk` under `other.co.uk`. The built-in table
covers a subset of public suffixes and has no wildcard or exception rules.

`Capture.DNSSourceStats` groups observations by client address. Queries use
their source and unicast responses use their destination. Multicast responses
are skipped. The capture-wide DGA score combines NXDOMAIN ratio, distinct
NXDOMAIN apex count and maximum query entropy once a client has at least five
NXDOMAIN responses across three apexes. The ratio divides NXDOMAIN responses
by the larger of the observed query and response counts. The score is
independent of capture duration.

## Parse TLS handshakes and JA4+ fingerprints

Call `ParseTLSRecords(stream)` on a TCP payload or reassembled stream, or call
`capture.TLS(data)` (or `capture.TLSWithKeyLog(data, extraKeyLog)`) to
reassemble TCP flows and decode TLS 1.2 and TLS 1.3 `ClientHello`, `ServerHello`,
and `Certificate` handshake messages:

- A hello may span one-byte records. The parser joins the fragments across
  complete, non-closing plaintext warning alerts. Fatal alerts and
  `close_notify` end collection. If a handshake needs a 129th record,
  `ParseTLSRecords` returns an error matching `ErrTLSLimit`. Capture scans
  omit that direction and can still return a hello from the opposite direction.
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
- Supply a known capture packet timestamp to
  `cert.ValidityAt(time.Unix(0, pkt.TimestampNs))` to check that certificate's
  inclusive validity window. If the timestamp is unavailable (for example,
  in a PcapNG Simple Packet Block), pass `time.Time{}` for `TLSValidityUnknown`.
  You can check each server or client certificate independently.
- Use `match, known := record.Handshake.ServerNameMatch()` to compare the observed
  ClientHello DNS name with the server leaf's DNS SANs. Matching follows Go's
  X.509 case and wildcard rules. With Encrypted Client Hello, the observed
  name can be the outer public name. A missing or invalid DNS name, an IP
  literal, missing leaf or DNS SANs, or invalid certificate DER gives an unknown
  result. A match in the retained DNS names is conclusive. A miss is unknown
  if further DNS names might have been omitted. Both helpers describe the
  captured evidence independently of chain trust and revocation policy.
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

`QUIC` and `QUICFromReaderAt` return distinct Initial exchanges on the same
UDP tuple in first-observed order. They group Initials across a client port
change when the same endpoint IPs and server port have a unique matching
nonempty connection ID. Each record uses the flow index of its first observed
Initial packet in `capture.Flows(data)`. The record retains the original ports,
including UDP ports recovered from fragments. A matching Retry can supply a new
destination ID for a subsequent client Initial. Read `record.Handshake.HasRetry`
or `record.Handshake.HasVersionNegotiation` on each record to check which server
responses appeared in the capture. These flags describe packet observations.
Retry integrity tags are not verified.
When authentication is needed to resolve a server-first packet or a changed
server connection ID, unsuccessful checks count toward the exchange's budget
for resolving ambiguous packets.

## Decrypt TLS 1.2 and TLS 1.3 streams offline

Call `capture.DecryptedTLSStreams(data, extraKeyLog)` to decrypt TLS 1.2
(`CLIENT_RANDOM` master secrets with AES-128-GCM and AES-256-GCM cipher suites)
and TLS 1.3 (`CLIENT_TRAFFIC_SECRET_0` / `SERVER_TRAFFIC_SECRET_0` with
`TLS_AES_128_GCM_SHA256` and `TLS_AES_256_GCM_SHA384`) application streams using
secrets embedded in PcapNG Decryption Secrets Blocks (`DSB`) or supplied in
`extraKeyLog` (`SSLKEYLOGFILE` format).

When the key log includes `CLIENT_EARLY_TRAFFIC_SECRET`, the client stream
includes authenticated 0-RTT application bytes followed by recovered 1-RTT
bytes in wire order. Both epochs share the directional output limit. These
bytes show what the client sent. Determining whether the server accepted early
data requires inspecting the handshake. The keyed example capture uses the
published records and secrets from [RFC 8448 section 4](https://www.rfc-editor.org/rfc/rfc8448#section-4).

For example, if the client sends a TLS 1.3 `KeyUpdate` during an HTTP request,
the client traffic secret for generation zero lets the parser recover request
bytes both before and after the update. The server keeps its current traffic
secret until it sends its own authenticated update. After 32 updates in one
direction, the next update ends decryption for that direction and the parser
returns the plaintext recovered so far. [TLS 1.3 traffic key updates](https://www.rfc-editor.org/rfc/rfc8446#section-7.2)

### Read DNS messages from decrypted HTTP/2

Call `capture.HTTP2(data)` and select records with `IsDecrypted`. For each
stream in `record.Summary.Streams`, call `block.DNSOverHTTPS(stream.Data)`
for each header block. The method reads the `dns` URI parameter on GET
requests and the `application/dns-message` body of POST requests and 2xx
responses that allow a body. It accepts an uncoded body of up to 65,535 bytes
and limits GET request targets to `MaxHTTPHeaderLineBytes`.

Check the match flag and error before using the DNS message. Inspect
`DNSMessage.Anomalies` for partial DNS sections. Use the flow index and
HTTP/2 stream ID to pair requests with responses. [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484#section-4)

## Inspect explicit proxy tunnels

TLS, HTTP, HTTP/2, SSH, SMB, and RDP capture methods inspect the payload after
one successful HTTP CONNECT or no-authentication SOCKS5 CONNECT exchange.
`DecryptedTLSStreams` uses the inner TLS records with the supplied key log.
The flow index and addresses identify the captured client and proxy. `HTTP`
returns the outer CONNECT request, interim responses, and successful 2xx response as header-only records
before any inner HTTP messages. Body offsets refer to the original stream.

Use `UnwrapProxyStream(stream.Client.Data, stream.Server.Data)` on a reassembled
request and response to get the inner byte slices, proxy type, requested host,
and port. The host comes from the proxy request and can differ from the inner
TLS server name. Both slices borrow the original stream buffers. HTTP headers
must end within 4,096 bytes per direction, including any interim responses. SOCKS5 accepts up to 16 offered methods and
IPv4, IPv6, or domain targets. On an incomplete or rejected exchange the helper
returns both input slices and `false`.

## Parse HTTP messages and carve payloads

Call `ParseHTTPRequest(stream)` or `ParseHTTPResponse(stream)` on a TCP stream,
or call `capture.HTTP(data)` to extract HTTP/1.x requests, responses, FoxIO
`JA4H` fingerprints, and carved `Body` payloads (`Content-Length` and
`Transfer-Encoding: chunked`) from both cleartext TCP streams and DSB-decrypted
TLS 1.2 and TLS 1.3 flows.

Inspect `Anomalies` for conflicting numeric lengths, simultaneous transfer
encoding and content length, folded headers, and incomplete bodies. Folded
lines count toward the header limit and are unfolded into their preceding
field. A final `chunked` transfer coding determines the wire boundary even
when a length is present. Without transfer coding, equal lengths are accepted.
For conflicting or invalid lengths on a body-bearing message, the parser
returns the headers, omits the body, and consumes the remaining input in that
direction. An incomplete chunk stream also consumes the remaining input and
retains the bounded body prefix. Bodyless response statuses end at the headers.

On cleartext connections, `HTTP` stops each direction at its first known TCP
gap and retains any complete headers and available body prefix before it. It
identifies request and response directions from complete start lines. When
both sides are available, it pairs requests and final responses in order.
On partial captures, a TCP acknowledgement can identify a response to a
request that preceded the captured requests. When acknowledgements are
unavailable, an earlier response with a complete `Content-Length` body and a
later response packet can establish that boundary. Otherwise the parser uses the observed HTTP
message order. A response to HEAD ends at the headers even if it advertises
a content length. Interim responses leave the request pending. The
standalone `ParseHTTPResponse` function has no request-method context.

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

When you need TLS, HTTP/1 and HTTP/2 together, call `capture.Web(data)`.
It reassembles the capture's TCP streams once and shares the decrypted
application bytes between the HTTP parsers. The returned `TLS`, `HTTP` and
`HTTP2` slices follow the same ordering and limits as the individual methods,
including outer CONNECT records and cleartext records before decrypted ones.
An analysis error returns an empty result.

For HTTP/2 (`h2c` cleartext or decrypted TLS `h2`), call
`ParseHTTP2Frames(stream)` or `capture.HTTP2(data)` to parse the 24-byte HTTP/2
client preface, `SETTINGS` parameter pairs and `SettingsFingerprint`
(`id:val;id:val`), `WINDOW_UPDATE` increments, and reassembled per-stream `DATA`
frame payloads (handling padded `DATA` frames under `MaxHTTPBodyBytes`).

For each stream ID, `HeaderBlocks` retains complete header blocks in order,
including interim responses and trailers. Inspect `Method`, `Authority`,
`Path`, and `Status` in their respective direction. HPACK context is shared by
concurrent stream IDs within a direction. A partial or invalid block sets
`HeadersIncomplete` and suppresses subsequent header decoding in that
direction. DATA and already completed blocks remain available. When TCP
reassembly reports a sequence gap, the scanner suppresses all header blocks
and the client fingerprint for that direction. A missing frame may have changed
the HPACK table even when later frame boundaries appear intact.

The decoder accepts up to 4 KiB of dynamic table state and 64 KiB per compressed
block. Each block costs 128 bytes, plus 32 bytes per field and the length of its
name and value. These charges count against a 4 MiB
budget shared across a capture scan. Exceeding these limits returns
`ErrHTTPLimit`. A client preface and decoded request produce the four-part
`AkamaiFingerprint` from SETTINGS, connection window increment, initial
PRIORITY frames and pseudo-header order. Use cleartext or decrypted bytes for
the observed proxy leg. [HPACK format and examples](https://www.rfc-editor.org/rfc/rfc7541)

### Locate individual HTTP requests in a capture

Use `capture.HTTPRequests(data)` or `capture.HTTPRequestsFromReaderAt(r)` to
build a request timeline from a cleartext capture, including the plaintext leg
of a TLS-terminating proxy. Each observation contains the request method,
authority, path, source and destination, flow index, zero-based packet index,
and that packet’s timestamp in nanoseconds. For Wireshark, add one to the
packet index.

For HTTP/1, the packet supplies the first byte of the request line. For HTTP/2
with a client preface, it supplies the first byte of the initial HEADERS frame,
even when a later CONTINUATION frame completes the header block. Multiple
requests in one packet share its index and time. Retransmitted bytes produce
one observation. Results follow packet-index order even when timestamps go
backward. HTTP/2 requests carry a stream ID; HTTP/1 uses zero.

```go
requests, err := capture.HTTPRequestsFromReaderAt(file)
if err != nil {
    return err
}
for _, r := range requests {
    fmt.Printf("frame=%d time_ns=%d flow=%d stream=%d %s %s\n",
        r.PacketIndex+1, r.TimestampNs, r.FlowIndex, r.StreamID, r.Method, r.Authority)
}
```

The scan stops parsing each direction at its first known TCP gap. A capture
beginning midstream needs a recognizable request at the start of the observed
prefix. It reports an HTTP/1 CONNECT request and stops at the tunnel boundary.
Use `Web` for keyed TLS inspection. This timeline has no mapping from decrypted
bytes back to packets in an encrypted capture. Zero timestamp values can occur
on packets recorded without a timestamp.

The scan accepts up to `MaxTotalStreamBytes` of candidate TCP payload (including
retransmissions), applies the existing stream and HTTP decoding limits, and
returns at most `MaxHTTPMessagesPerScan` observations. Errors discard the result.
ReaderAt also limits capture reads to `MaxReaderAtScanBytes`.

For cleartext HTTP/2, `HTTP2` and `Web` use the client connection preface
to identify the sender of each directional record. If neither direction has
a preface, the first observed direction retains the client role. Decrypted
streams use the roles established by TLS.

### Extract WebSocket messages

Call `capture.WebSockets(data)` for HTTP/1.1 upgrades in cleartext or in
supported TLS streams with an embedded key log. Each record identifies the
flow, sending endpoint, direction, and whether TLS decryption supplied the
bytes. Results contain cleartext streams first, then decrypted streams. For
each stream, client messages precede server messages. Within each direction,
messages appear when their final frame arrives. A ping can therefore precede
the fragmented text message it interrupted.

Call `capture.WebWithWebSockets(data)` when you need both the web records
and WebSocket messages. It shares TCP reassembly and TLS application-data
decryption, preserves each protocol’s record order and limits, and discards
both results if a scan fails.

The scanner follows HTTP message boundaries through preceding exchanges
and informational responses. With a one-sided capture it can use a WebSocket
upgrade request or a 101 response naming WebSocket. Each direction needs its
own visible HTTP boundary. A captured rejection produces no messages for
that exchange. Negotiation detection does not authenticate the handshake.

For bytes already positioned at a frame boundary, use
`ParseWebSocketFrames(stream)`. Payloads are owned copies. Client frames are
unmasked, continuations are joined, and close, ping and pong keep their
opcodes. A gap suppresses the affected capture direction. Invalid frames,
including extension frames with reserved bits (such as compressed messages),
stop decoding that direction. Earlier complete messages remain available.
The standalone parser reports an error for malformed or truncated input.

The limits are 1,024 frames per direction, 4 MiB per message, 16,384 output
records per capture, and 64 MiB of processed frame payload per call. A frame
that declares an oversized payload is rejected before allocation. A capture
scan that exceeds a WebSocket limit returns `ErrWebSocketLimit` and no records.
HTTP/2 extended CONNECT and WebSocket extension decoding are outside this API.
[RFC 6455 framing and examples](https://www.rfc-editor.org/rfc/rfc6455#section-5)

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
For a `KRB-ERROR` message, `ErrorCode` contains the protocol error code.
`ClientRealm` and `ClientNames` contain the optional client identity fields.
For example, an error for `alice@CLIENT.EXAMPLE` from `SERVICE.EXAMPLE` can
report `ClientNames` as `["alice"]`, `ClientRealm` as `CLIENT.EXAMPLE`, and
`Realm` as `SERVICE.EXAMPLE`.
On TCP, the scanner reassembles each port-88 direction and attributes the
message to the packet containing the first byte of its four-byte record mark.
[Kerberos over TCP (RFC 4120)](https://www.rfc-editor.org/rfc/rfc4120#section-7.2.2)

Call `ParseRDPNegotiation(buf)` or `capture.RDP(data)` to decode TPKT / X.224
Connection Request and Connection Confirm PDUs, `Cookie: mstshash=...` tokens,
and `RDP_NEG_REQ` / `RDP_NEG_RSP` security protocol flags (`RDPProtoTLS`,
`RDPProtoCredSSP`, `RDPProtoHybridEx`).

## Compute C2 beacon and flow statistics

Use `Capture.BeaconsWithOptions` with `GroupBy3Tuple` to group flow starts
by protocol, source address, destination address and destination port. Each
distinct five-tuple supplies one sample, so a change of source port can
contribute to the same group. Port 53 on either endpoint is excluded unless
`IncludeDNSPort` is set. Median intervals below one second suppress the
periodicity and beacon scores by default. Set `MinIntervalNs` to adjust this
threshold or use a negative value to disable it.

Call `ComputeBeaconStats(timestampsNs, payloadBytes, clientBytes, serverBytes)`
or `capture.Beacons(data)` to calculate median inter-arrival intervals, median
absolute deviation (MAD), jitter ratios, Bowley quartile skewness periodicity
scores, payload size uniformity, Producer-Consumer Ratio (PCR), and composite
`BeaconScore` values in $[0.0, 1.0]$.

## Write captures

Use `NewPCAPWriter(w, linkType, snapLen)` for single-interface classic PCAP.
Pass Unix nanoseconds and the complete packet to `WritePacket`. The writer
stores up to `snapLen` bytes and preserves the original length. Timestamps must
fit unsigned 32-bit Unix seconds. A zero snaplen selects `DefaultLiveSnapLen`.
When copying an already-truncated packet, call
`WritePacketWithOriginalLen(pkt.TimestampNs, payload, pkt.OriginalLen)` to
retain its wire length even if the destination snaplen truncates it further.

Use `NewPCAPNGWriter(w, opts)` to stream PcapNG `SHB`, `IDB` (nanosecond
resolution), `NRB` (`WriteNameResolution`), `ISB` (`WriteInterfaceStats`),
`DSB` (`WriteDecryptionSecrets`), and `EPB` (`WritePacket`) blocks to any
`io.Writer`. Interface 0 is ready immediately. Set `LinkTypeSet: true`
to select `LinkTypeNull` explicitly on interface 0 for any interface name. Call
`AddInterface` for each additional interface and use its returned ID in
`PacketRecord` and `InterfaceStatistics`. Each interface has its own link type
and snaplen. After an output error, start a new capture stream.

When a process ID or name is present, `WritePacket` emits the Apple process
index and shares a process block across packets with the same attribution.
Process ID `0xffffffff` is reserved for a name-only entry. Passing that ID
with `HasProcessID` set returns `ErrInvalidPacket`. A new entry that would
exceed `MaxProcessEvents` returns `ErrOptionLimit`. The writer stores the
thread ID, user ID, command line, and container ID in go-pcap packet comments.

Call `capture.ExtractFlowPCAPNG(data, w, flowIndex)` to write one bidirectional
flow. Pass the original capture bytes and the zero-based index from `Flows`.
For PcapNG input, the export retains the source sections, registers only the
interfaces used by selected packets, and preserves their block type, timestamp
encoding, and packet options. Name records, process definitions and decryption secrets
are capture-wide and can describe other flows. Classic PCAP input becomes a
single-interface PcapNG capture. An absent flow returns `ErrOutOfBounds`
before writing output.

For a file opened with `NewFromReaderAt`, pass the same unchanged file to
`ExtractFlowPCAPNGFromReaderAt(r, w, flowIndex)`. The method reads frame
prefixes to identify flows. For PcapNG it then copies selected blocks in
chunks of up to 32 KiB and skips unrelated packet bodies. Classic PCAP
conversion buffers one selected packet at a time. All source reads during the
export share the 64 MiB `MaxReaderAtScanBytes` budget, including copied metadata
and repeated reads. Budget exhaustion returns `ErrPacketLimit`. Discard partial
output after a read, write, or budget error.

## Capture live interface traffic

Use `OpenLive(ifaceName, opts)` to capture live packets from an OS network
interface using standard-library `syscall` descriptors (`/dev/bpf*` on macOS,
`AF_PACKET` on Linux, `SIO_RCVALL` raw sockets on Windows) without `cgo` or
`libpcap`. Use `BPFFilterTCPPort`, `BPFFilterUDPPort`, `BPFFilterIPProtocol`,
and `BPFFilterIPv4Host` to construct classic BPF filter programs, or `EvalBPF`
to evaluate a classic BPF program in memory.

On Linux, `Promiscuous` requests membership for the capture socket until it
closes. `OriginalLen` retains the wire length when the socket filter or
`SnapLen` shortens a packet. `TimestampNs` uses the kernel software receive
timestamp. Linux requests 64-bit seconds and tries the legacy timestamp option
on older kernels. The kernel can supply a read-time timestamp if the packet
arrived before software timestamping took effect. When the socket has no usable
kernel timestamp for the packet, `TimestampNs` uses the userspace wall clock at
read time.

On macOS, `TimestampNs` comes from the kernel BPF packet header and has
microsecond resolution. `OpenLive` translates the interface's native BPF
datalink type to the corresponding capture-file `LinkType`, including native
`DLT_RAW` (12) to `LinkTypeRaw` (101). It returns an error if the kernel cannot
report a datalink type or the library has no mapping for it.

On Windows, `TimestampNs` uses the userspace wall clock when `ReadPacket`
accepts the packet. A positive `Timeout` applies to each `ReadPacket` call,
including time spent waiting for a filter match.

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
