# Parse packet captures, frames, and protocols

Start with the [quick start](../README.md#quick-start-with-a-packet-capture).
Run `go doc -all .` from the repository root for signatures, fields, and
limits. See the [runnable examples](../example_test.go) for code. This guide
describes how to choose an API and interpret its results.

| Task | Start here |
| --- | --- |
| Open or scan a capture | [Containers](#parse-capture-containers), [packets](#read-packet-records), [limits](#work-and-output-limits) |
| Inspect traffic | [Frames](#decode-l2l4-frames-and-tunnels), [flows](#aggregate-5-tuple-flows), [TCP streams](#reassemble-tcp-streams) |
| Analyze protocols | [DNS](#parse-dns-messages-and-tunneling-metrics), [TLS](#parse-tls-handshakes-and-ja4-fingerprints), [QUIC](#decrypt-quic-initial-packets), [HTTP](#parse-http-messages-and-carve-payloads) |
| Collect or share traffic | [Live capture](#capture-live-interface-traffic), [writers and exports](#write-captures) |

## Parse capture containers

Use `New` for bytes, `NewWithLength` for a buffered prefix of known total
length, and `NewFromReaderAt` for a seekable source. The capture stores its own
metadata, including PcapNG interfaces, names, process events, statistics, and
secrets. Supply the same input contents on later calls. For concurrent
analysis, keep the input and the capture's exported fields unchanged.
[Input lifetimes](compatibility.md#inputs-and-payloads)

### Read compressed or non-seekable input

`DecompressCapture` accepts gzip with up to 64 MiB of total output. It returns
plain input by reference. To handle a pipe or a larger gzip file, stage the
uncompressed bytes in a temporary file with a size limit. Finish copying and
check errors before opening the file with `NewFromReaderAt`.
[Runnable gzip staging example](../example_test.go)

`ErrUnsupportedZstd` and `ErrUnsupportedXZ` identify compressed input that
needs an external decoder. Use the same bounded staging workflow with its
output.

## Work and output limits

| Work | Representative limits |
| --- | --- |
| Open a capture | `MaxPackets`, `MaxInterfaces`, `MaxPCAPNGBlocks`, `MaxSnapLen` |
| Scan seekable input | `MaxReaderAtScanBytes` (64 MiB per bounded scan) |
| Reassemble traffic | `MaxSegmentsPerFlow`, `MaxFlowStreamBytes`, `MaxTotalStreamBytes` |
| Retain protocol evidence | The protocol's exported size, record, and work limits |

Opening and scanning charge separate budgets. A bounded scan can finish on
a file larger than its read budget by reading selected ranges. For seekable
exports, selection and copying share a budget. Check each operation's
result and use `errors.Is` with its documented error.
[Limits and error contracts](compatibility.md#limits-and-errors)

## Inspect truncation and anomalies

After a valid header, an incomplete final record can leave a usable prefix.
Check `InputTruncated`, `DeclaredExtent`, and `Anomalies` before interpreting
absence. To distinguish unsupported link framing from missing traffic, use
`UnsupportedLinkTypePackets` or its ReaderAt variant.

## Read packet records

Use `PacketSeq` or `PacketSeqFromReaderAt` to iterate in file order and stop
early. The iterator can yield complete records before a terminal error.
`PacketPayload` borrows the frame bytes. `PacketPayloadFromReaderAt` returns
owned bytes. Packet indices start at zero. In PcapNG, use each packet's
resolved interface and link type.

## Decode L2–L4 frames and tunnels

Pass the frame bytes and their link type to `DecodeFrame`. Use its layer
spans and offsets to locate fields in the original frame. The decoder can
trace supported VLAN, MPLS, GRE, VXLAN, Geneve, and IP-in-IP encapsulation.
An inner packet visible in a frame may be outside a capture scan's flow
scope. Protected wireless and encrypted ESP payloads remain opaque.
[Framing fixtures](../testdata/framing/README.md)

Use `ICMPFlowErrors` to count errors quoting known flows and `TCPZeroWindows`
to count observed zero-window advertisements. Their packet indices locate
the observation, which may cover an entire flow.

### Verify packet checksums

Use `DecodeFrameWithChecksums` for checksum observations on a decoded frame.
Validate only complete headers or transport data with the required context.
Capture truncation and checksum offload can affect the result.

## Observe ARP and IPv6 neighbors

Use `Neighbors` or `NeighborsFromReaderAt` for ARP and IPv6 Neighbor
Discovery records. Each row identifies a packet and its observation scope.
ARP probes and IPv6 duplicate address detection can occur before an address
is assigned.

### Find changes in observed neighbor bindings

Use `NeighborBindingChanges` to compare successive address-to-link-layer
assertions within an observation scope. A change records two observations.
Use the interface and packet indices to investigate why the binding changed.

## DHCPv4 address assignments

Use `DHCPv4` or `DHCPv4FromReaderAt` for lease negotiation on the standard
DHCPv4 ports. A Discover initiates discovery, an Offer proposes an address,
and an ACK records the server's response. Use the transaction ID and packet
indices to correlate messages.

## Aggregate 5-tuple flows

Use `Flows` or `FlowsFromReaderAt` for bidirectional IPv4 and IPv6 summaries.
The first observed direction sets the source. For TCP or UDP, `CommunityID`
joins the tuple to compatible sensor records. Use the same seed and check
whether the ports were observable.

## Trace a client connection and a TLS proxy

Correlate DNS records, flows, and TLS hellos across the client and proxy
captures. A proxy can create a separate upstream connection with different
endpoints and handshake settings. Compare each leg's original packets.
[Deployment fixtures and decoder results](../testdata/deployments/README.md#independent-decoder)

## Reassemble TCP streams

Use `Streams` for capture-level TCP connections or `ReassembleTCP` for
segments you already collected. Read gap, overlap, and truncation flags
before interpreting the bytes. Batch reassembly can concatenate available
ranges across a gap. Protocol scanners that require a contiguous prefix stop at
the gap. A new opening SYN can separate connections that share a flow index.

### Select an observation scope on one interface

Set `Capture.SeparateTCPInterfaces` or `Capture.SeparateIPFragmentInterfaces`
before analysis when interface IDs distinguish observations you need to keep
apart. These options affect TCP opening and supported UDP fragment grouping.
Without a scope, flow indices remain capture-wide.

Use `Capture.SelectTenant` to limit flow, DNS message, and cleartext HTTP/1
transaction scans to one Ethernet observation point. Specify its capture interface
and outer VLAN stack. To select VXLAN, also specify the VNI, outer IP endpoint pair,
and inner VLAN stack. Empty VLAN lists select untagged traffic at their respective
layers. The endpoint pair matches either tunnel direction. A VXLAN scope can
specify up to two VLAN tags across both layers. The selector skips identities
that are incomplete or exceed the frame layer limit.

Both slice and ReaderAt methods use the original input. Packet indices remain
capture-wide and flow indices refer to the view's `Flows` order. Each scan uses
its existing read and reassembly limits.
[Tenant fixture and example](../testdata/framing/tenant-scope.md)

### Identify an application protocol from a prefix

Use `ClassifyL7` to choose a parser. Treat a match as a hint. The parser
validates the message.

### Identify fragmented TCP coverage

Batch TCP stream collection skips IP-fragmented TCP. Inspect the fragment
fields with `DecodeFrame`. If you manage fragment sets yourself,
`DefragmentIP` can reconstruct IP datagrams before transport parsing.
[IPv4 and IPv6 fixture](../testdata/framing/README.md#fragmented-tcp)

## Parse DNS messages and tunneling metrics

Use `ParseDNS` on one DNS message. `DNS` and `DNSFromReaderAt` scan UDP
DNS, mDNS and LLMNR, and length-framed TCP DNS. For TCP, the packet
index identifies the first length-prefix byte. For fragmented UDP, it
identifies the packet that completed the datagram. Use `DNSSourceStats`
for bounded query and label statistics. Check message anomalies before
interpreting partial answers.

### Diagnose DNS transactions

Use `DNSTransactions` or its ReaderAt variant for ordinary unicast DNS.
Pairing uses the observed transport scope and message fields. Rows distinguish
paired exchanges, one-sided traffic, and ambiguous retries. A paired row
can provide latency when the timestamps support it. Try the diagnostic from
the repository root.

```sh
go run ./examples/dns-transactions testdata/deployments/dns-transactions.pcap
```

### Read DNS over TLS

Use `DNSOverTLS` or `DNSOverTLSFromReaderAt` for TCP/853 when traffic keys
authenticate TLS records carrying complete length-framed messages. Rows
identify the flow and sending direction.

## Parse TLS handshakes and JA4+ fingerprints

Use `ParseTLSRecords` for a directional stream or `TLS` for a capture.
Use `TLSWithKeyLog` for protected handshake fields when you have keys.
The observed records can include hellos, certificates, and fingerprints.
[Automatic fingerprint computation](fingerprints.md)

### Interpret server names with ECH

With Encrypted ClientHello (ECH), the visible name can be the public outer
name. The private name is unavailable. `ServerNameMatch` distinguishes a
known comparison from unavailable evidence. Check its second return value
before using a mismatch.

### Locate a hello or certificate chain in the original packets

Use `TLSHandshakeEvidence` or `TLSHandshakeEvidenceFromReaderAt`. Each
record identifies the TCP opening and retains field-specific packet indices.
Protected fields refer to whole authenticated TLS records. Inspect directional
coverage for incomplete or unavailable observations.
[Runnable examples](../example_test.go)

## Decrypt QUIC Initial packets

Use `DecryptQUICInitial` on UDP datagrams or `QUIC` on a capture. QUIC v1
and v2 Initial keys are derived from public inputs. Initials expose client
offers and JA4 when enough bytes are present. Authenticated Handshake or
application data requires its own traffic keys.

### Authenticate QUIC 1-RTT packets with capture keys

Use `NewQUIC1RTTDecoder` for generation zero or `NewQUIC1RTTKeyTracker` to
follow updates. Create one decoder or tracker per sending direction. Use
the version, cipher suite, directional application secret, and packet number
context from the same connection. [Cipher coverage](offline-crypto.md)

### Reassemble authenticated QUIC streams

Call `ReassembleQUIC1RTTStreams` for one connection and direction.
Results contain the contiguous prefix and report clean FIN, gap, or reset.
Conflicting bytes and inconsistent final sizes invalidate the reconstruction.

### Associate keyed QUIC packets with capture connections

Use `KeyedQUIC` or `KeyedQUICFromReaderAt` when Initials and application keys
are available. Each authenticated packet retains its capture packet index,
UDP offset, and key generation. Only uniquely authenticated associations
contribute evidence. The scan tracks bounded connection-ID rotation within
the observed path scope and up to 32 key updates per direction. It can
decode reordered packets from the immediately preceding generation. Missing
issuance or generation history can keep later packets opaque.
[Rotation and key-update fixture](../testdata/quic-key-updates.md)

### Observe the server-selected QUIC ALPN

Use `KeyedQUICWithALPN` or its ReaderAt variant. Server Handshake keys can
authenticate EncryptedExtensions and identify the selected Application-Layer
Protocol Negotiation (ALPN) value and its packet indices. An application row
can have nil `ALPN`. Client offers establish no server selection.

### Delimit HTTP/3 frames

Use `ParseHTTP3Stream` on a directional stream from a confirmed HTTP/3
connection. It reports frame ranges in the original stream and can retain
complete frames preceding a truncated suffix.

### Decode HTTP/3 QPACK field sections

Use `DecodeQPACKSections` once per sender. Supply its QPACK encoder stream,
negotiated table limit, and compressed field sections. Results distinguish
decoded, blocked, malformed, and limited sections. A decoded section retains
field order and the encoder range it depends on.

### Recover keyed HTTP/3 request streams

Use `KeyedHTTP3Transactions` or its ReaderAt variant. Authenticated `h3`
ALPN gates decoding. Each row identifies a connection and a request stream
with directional headers, body state, completion, and original packet
indices. Packets can also support other streams or shared QPACK context.
After successful CONNECT, DATA belongs to the tunnel. For independent
replay, keep the source capture and keys. A transaction's packet selection
can omit handshake and packet-number history required to reopen it.

### Read DNS over QUIC

Use `DoQTransactions` or its ReaderAt variant. Authenticated `doq` ALPN
gates pairing by client-initiated bidirectional stream. Each complete
direction carries one DNS message with ID zero and clean FIN. Partial or
reset streams and unsupported transfers retain directional evidence and
an explicit state. [Resolver example](../doq_example_test.go) ·
[Reference trace](../testdata/doq-exchanges.md)

## Decrypt TLS 1.2 and TLS 1.3 streams offline

Use `DecryptedTLSStreams` with the capture and an NSS key log or embedded
secrets. Recovery depends on supported suites, handshake context, and
a contiguous, authenticated record history for each direction.
[Cipher and generation coverage](offline-crypto.md)

### Select HTTP/1 transactions inside TLS

Use `KeyedHTTP1Transactions` or its ReaderAt variant. Rows identify the TCP
opening, paired messages, authenticated TLS record ranges, and original
ciphertext packets. Check pairing, body state, and directional coverage.

### Explain keyed HTTP/1 coverage

Use `AnalyzeKeyedHTTP1` or its ReaderAt variant for an explanation when
transaction coverage is incomplete. Consult the reported TLS stopping point
and HTTP state before interpreting a missing request or body.

### Export an HTTP/1 exchange as ciphertext

Pass the transaction ID, original input, and matching keys to
`ExtractKeyedHTTP1TransactionPCAPNG` or its ReaderAt variant. Reopening the
packet-only output requires separate secrets. Write to a temporary destination
if you need to discard partial output on error.
[Runnable export tool](../examples/keyed-http1-export/main.go) ·
[Replay fixture](../testdata/tls-provenance.md)

### Read DNS messages from decrypted HTTP/2

Use `HTTP2` to recover decrypted headers and DATA for the stream. Apply
`HTTP2HeaderBlock.DNSOverHTTPS` to the corresponding headers and body.
Check DNS anomalies after decoding. For DoQ, use the separate
[QUIC stream binding](#read-dns-over-quic).

### Recover DNS-over-HTTPS transactions

Use `DoHTransactions` or `DoHTransactionsFromReaderAt` with the original
capture and its key material. Both APIs run the keyed HTTP/2 and HTTP/3
scans. A row requires authenticated HTTPS request headers that identify a
`dns` GET parameter or an identity-coded `application/dns-message` POST.
Missing keys or undecodable request headers can prevent a row from appearing.

Check the query and reply states independently. A GET query resides in the
headers. POST queries and DNS replies require complete, supported bodies.
The final HTTP status is reported separately, so HTTP errors, missing
replies, and incomplete bodies remain distinguishable. Both directions
are associated through the HTTP stream in its TCP opening or QUIC
connection. DNS IDs can repeat across exchanges.

Use the directional packet indices to locate the observations in the
original capture. HTTP/2 also reports the contributing TLS records. HTTP/3
reports the authenticated ALPN and supporting QPACK packets. The same
packet can contribute to multiple streams or contain transport context.
The ReaderAt method applies one read budget across both scans.

[Runnable example](../example_test.go) ·
[Independent fixture](../testdata/doh-exchanges.md)

### Choose TLS and QUIC key sources

Pass explicit NSS key log bytes to keyed scans or supply an input with a
supported PcapNG Decryption Secrets Block. For an external-only scan, make
a value copy of the capture and set its `Secrets` to nil. For an embedded-only
scan, pass nil for the extra key log. With both sources enabled, the last
accepted line for a client random and label wins, and the external log is
processed last. Keep key material private. Packet-only exports omit secrets.
[Input and ownership rules](compatibility.md#inputs-and-payloads)

## Inspect explicit proxy tunnels

Use `UnwrapProxyStream` on known client and server directions to locate
inner bytes after a supported CONNECT or SOCKS exchange. The returned views
borrow the supplied streams. Attribute TLS on each observed proxy leg to
its own endpoints and keys.

### Select HTTP/2 transactions inside TLS

Use `KeyedHTTP2Transactions` or its ReaderAt variant with NSS key log
material. Rows distinguish HTTP/2 stream IDs and identify frame ranges,
authenticated TLS records, and original packets. Check directional coverage
and shared HPACK context.

### Export a keyed HTTP/2 exchange as ciphertext

Pass the transaction ID, original input, and matching keys to
`ExtractKeyedHTTP2TransactionPCAPNG` or its ReaderAt variant. The selected
packets can include TLS and HPACK history shared with other requests.
Reopen the packet-only capture with separate keys.
[Replay example](../testdata/tls-provenance.md#export-a-keyed-http2-exchange)

## Parse HTTP messages and carve payloads

Use `ParseHTTPRequest` and `ParseHTTPResponse` for individual HTTP/1
messages. Use `HTTP` for capture records or `Web` to share work with TLS
and HTTP/2 analysis. Inspect framing anomalies and body completeness before
interpreting a body. The HTTP/1 parser can remove chunk framing and decode
a single supported gzip or deflate coding within its output limits.
Offsets and consumed byte counts refer to the original stream.

Use `ParseHTTP2Frames` or `HTTP2` for HTTP/2 settings, frames, headers,
and bounded DATA. HPACK state is directional and shared across streams.
A gap can prevent header decoding. Already framed DATA and observable
headers have separate coverage.

### Locate individual HTTP requests in a capture

Use `HTTPRequests` or its ReaderAt variant for a cleartext HTTP/1 or HTTP/2
timeline. Use request evidence or transaction APIs when you also need
headers, body state, or full packet membership.

### Select a prior-knowledge cleartext HTTP/2 transaction

Use `HTTP2Transactions` or its ReaderAt variant for prior-knowledge HTTP/2.
The client preface establishes direction. Each row preserves stream
identity, directional headers and DATA, packet indices, and shared context.

### Export a cleartext HTTP/2 transaction

Pass the transaction ID and the original input to
`ExtractHTTP2TransactionPCAPNG` or its ReaderAt variant. The subset can
include the client preface, frame boundaries, and HPACK history required
to reopen it. [Replay fixture](../testdata/deployments/README.md#reopen-the-stream-3-export)

### Select and export a cleartext HTTP/1 transaction

Use `HTTP1Transactions` or its ReaderAt variant and check `Pairing`.
Responses to HEAD and bodyless statuses end at the headers. Pass the row's
ID and original input to `ExtractHTTP1TransactionPCAPNG` or its ReaderAt
variant. Shared packets can carry adjacent messages.

### Inspect cleartext HTTP/1 request evidence

Use `HTTP1RequestEvidence` or its ReaderAt variant for the raw target,
ordered headers, and bounded entity bytes. Check `BodyState` before treating
bytes as the full entity. Packet index and TCP payload offset locate the
request start. The result owns its headers and body.

### Extract WebSocket messages

Use `WebSockets` for supported HTTP/1.1 upgrades or `WebWithWebSockets`
for combined web observations. For already framed bytes, use
`ParseWebSocketFrames`. It can return complete messages before a framing
error. Capture gaps and unsupported extensions can prevent later decoding.

## Parse SSH handshakes and HASSH

Use `ParseSSHHandshake` or `SSH` for observed identification strings and
KEXINIT fields. HASSH, HASSHServer, and JA4SSH depend on which fields are
available. The capture record identifies the flow.
[Fingerprint inventory](fingerprints.md)

## Parse SMB2, NTLMSSP, Kerberos v5, and RDP messages

Use `SMB` or `ParseSMB2Message` for visible SMB2 and SMB3 fields, and
`ParseNTLMSSP` for a located token. A transform header exposes its visible
metadata. Encrypted SMB command bodies remain opaque.

### Find the original packets for an SMB command

Use `SMB2Evidence` or its ReaderAt variant for the TCP opening, direction,
stream range, and contributing original packets. The stream range refers to
the command within that opening. [SMB reference](../testdata/framing/smb-evidence.md)

### Read Kerberos and RDP negotiation fields

Use `Kerberos` or `ParseKRB5` for visible Kerberos messages and error fields.
The capture record identifies the UDP packet or TCP length-prefix packet.
Use `RDP` for negotiation observations such as requested or selected
protocols. The RDP record identifies a flow.

## Parse LDAP requests

Use `LDAP` or its ReaderAt variant for supported cleartext Bind and Search
messages. `KeyedLDAP` and its ReaderAt variant inspect LDAPS on TCP/636 with
traffic keys. Cleartext packet locators identify the message start. Keyed
locators cover authenticated TLS records.

## Parse DCE/RPC fragments

Use `ParseDCERPC` for a located connection-oriented fragment or `DCERPC`
for capture evidence, including supported cleartext SMB pipe buffers.
The record locates the fragment start in the original packet or pipe context.
Inspect bind and transfer syntax information before interpreting a request.

## Compute C2 beacon and flow statistics

Use `BeaconsWithOptions` for periodic flow-start summaries or
`ComputeBeaconStats` for observations you already collected. Choose the
grouping and thresholds in the caller. Periodicity describes the capture
and needs deployment context to support a detection.

## Write captures

Use `NewPCAPWriter` for one link type or `NewPCAPNGWriter` for
multiple interfaces. To keep the wire length when copying a clipped packet,
use `WritePacketWithOriginalLen`.

| Export | Output |
| --- | --- |
| `ExtractFlowPCAPNG` | Selected packets and source metadata, which can include names, process information, and secrets |
| `ExtractFlowPacketsPCAPNG` | Selected original packets and the metadata needed to interpret them |

Packet-only output still contains original endpoints and payloads. Both
exports have ReaderAt variants. Discard partial output after an error.
[Packet-only example](../README.md#share-packets-from-one-flow)

## Capture live interface traffic

Use `LiveDevices` to locate an interface and `OpenLive` to capture.
The available backends use AF_PACKET on Linux, BPF on macOS, and raw IPv4
sockets on Windows. Capture privileges depend on the backend. Copy packet
bytes that must survive a later read.

### Compile a live capture filter

Use `CompileBPFFilter` with the device's link type. Numeric expressions
`ip and port N`, `ip and tcp port N`, and `ip and udp port N` apply to
untagged IPv4 Ethernet. An empty expression accepts all link types.
[Live capture example](../examples/live-capture/main.go)

### Discover interfaces

Use `LiveDevices` and check `HasLinkType` before relying on a device's link
type. macOS can list devices without BPF access. Linux reports supported
Ethernet framing, including synthetic Ethernet for loopback.

### Framing, direction, and interface mode

Use `LiveCapture.LinkType` for decoding and writing packets. The backend
uses the interface's current mode and default packet direction. The kernel
supplies timestamps on Linux and macOS. The Windows backend timestamps in
userspace.

### Live packet counters

Use `LiveCapture.Stats` before closing the handle. Linux and macOS
return per-handle counters. Poll before a kernel counter can wrap at 2³².
Windows returns `ErrLiveCaptureUnsupported` for counters.
