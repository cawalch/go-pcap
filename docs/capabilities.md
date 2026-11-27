# Capture analysis capability matrix

This baseline compares the [v0.1.1 release](https://github.com/cawalch/go-pcap/tree/v0.1.1)
with the current main branch. The [original inventory at 1420853](https://github.com/cawalch/go-pcap/tree/14208534efbb0ba81b6bd98731a4bc6337689e3d)
records the roadmap starting point. The main column includes release capabilities and calls out differences that
matter to an external Go caller. The external checks below use the published
[v0.2.0 release](https://github.com/cawalch/go-pcap/tree/v0.2.0), which
includes the baseline and adds unicast DNS transaction pairing. A parser
reads an already located byte range.
A capture scan finds records and associates them with the input. A transaction
export writes selected original packets that can be opened again. Unless a row
names a narrower exporter, the five-tuple export is the available selection.

Library packet indices start at zero. The reference captures list one-based
TShark frame numbers. Interface IDs, flow indices and transaction identifiers
apply to the original input. Observed fields and empty results are subject to
the observation point, capture length, keys and scan limits.
[Consumer compatibility](compatibility.md) · [Work and output limits](parsing.md#work-and-output-limits)

## Capture, frames and transport

| Caller question | v0.1.1 | Main additions and boundaries | Reproduction |
| --- | --- | --- | --- |
| Which interfaces, packets and metadata did the writer record? | Classic PCAP and PcapNG open from bytes or `ReaderAt`. Packet iteration exposes timestamps, capture lengths and original lengths. Both writers and metadata-preserving PcapNG flow export are available. | PcapNG also exposes obsolete Packet Blocks and improves Darwin process attribution. A complete prefix can survive an incomplete trailing record. Gzip can be staged with a bounded copy. Zstandard and XZ have specific unsupported-format errors. Packet-only flow export omits names, comments, process data and secrets. A seekable flow export shares a 64 MiB source-read budget across selection and copying. | [Container and export guide](parsing.md#write-captures) · [Client and Darwin PKTAP fixtures](../testdata/deployments/README.md#apple-pktap-process-fixture) |
| What sits inside this frame or tunnel? | `DecodeFrame` exposes bounded L2–L4 offsets for Ethernet, Linux cooked, loopback, raw IP and supported wireless headers. It handles MPLS, PPPoE, GRE, VXLAN and Geneve. | Added PKTAP, PPP variants, standalone PPPoE, PFLOG, NFLOG, IP-in-IP and ICMP error quotes. IP-in-IP frame decode can show inner ports while capture scans keep the outer flow. Protected wireless bodies and encrypted ESP content remain opaque. Unsupported link types are countable even when a protocol scan gives no rows. | [Frame and tunnel guide](parsing.md#decode-l2l4-frames-and-tunnels) · [Framing reference](../testdata/framing/README.md) |
| Which endpoint talked to another, and which bytes form a stream? | `Flows` and its seekable counterpart group bidirectional five-tuples. `ReassembleTCP` and `Streams` expose gap and overlap observations. Community ID v1 joins TCP and UDP tuples with other tools. | A later opening SYN can separate tuple reuse, and callers may separate TCP openings by PcapNG interface. The exported flow index remains a five-tuple index. Batch stream bytes can join ranges across a reported gap. TCP stream collection skips IP-fragmented TCP. UDP defragmentation for DNS and QUIC Initials can use interface scope. | [TCP reassembly](parsing.md#reassemble-tcp-streams) · [Deployment reference](../testdata/deployments/README.md#independent-decoder) · [Fragment coverage tests](../defrag_test.go) |
| Which device or transport behavior did the capture show? | Byte-slice and seekable DHCPv4 and ARP/IPv6 neighbor observations report addresses, packet indices and timestamps. Basic flow and beacon measurements are available. | Added scoped neighbor binding changes and counters for ICMP errors quoting an observed flow and zero-window TCP advertisements. An ICMP quote can identify the flow without identifying a particular application request. A DHCP offer records a proposed assignment. | [Neighbor observations](parsing.md#observe-arp-and-ipv6-neighbors) · [ICMP and TCP diagnostics](parsing.md#decode-l2l4-frames-and-tunnels) · [IoT fixture](../testdata/deployments/README.md#independent-decoder) |

## Application observations

| Caller question | v0.1.1 | Main additions and boundaries | Reproduction |
| --- | --- | --- | --- |
| Which DNS question or reply passed this capture point? | `ParseDNS` reads one message. `DNS` and `DNSFromReaderAt` cover UDP on ports 53, 5353 and 5355 and framed TCP on port 53. | For TCP, the locator identifies the packet that supplied the first length-prefix byte. For fragmented UDP, it identifies the fragment that completed the message. The library and example CLI pair ordinary unicast questions and replies and leave ambiguous retries unresolved. Keyed DoT feeds complete messages from authenticated records to the DNS parser. The HTTP/2 DoH helper reads an already identified header block and DATA. Keyed DoQ pairs ordinary lookups by stream after authenticated `doq` selection and returns directional packet indices and observation state. | [DNS transports and bounds](parsing.md#parse-dns-messages-and-tunneling-metrics) · [DNS reference](../testdata/deployments/README.md#dns-transaction-fixture) · [DoQ reference](../testdata/doq-exchanges.md) |
| What TLS name, version or certificate did this peer present? | Byte-slice and seekable TLS scans expose observed hellos and available certificates. TLS 1.3 handshake secrets can unlock encrypted certificates. TLS 1.2 AES-GCM and TLS 1.3 AES-GCM application decryption are available with supported keys. | TLS capture scans stop at the first known TCP gap per direction. Added observed-name comparison and TLS 1.2 AES-CBC support for the documented suites. `TLSRecord.FlowIndex` identifies a flow, which can contain several openings. The evidence methods retain opening packets, per-field packet indices and explicit reasons for incomplete keyed results. A visible ClientHello name can be the ECH public name. Application bytes and parts of a certificate exchange can remain opaque. | [TLS handshake and decryption guide](parsing.md#parse-tls-handshakes-and-ja4-fingerprints) · [Proxy capture](../testdata/deployments/README.md#independent-decoder) · [OpenSSL CBC reference](../testdata/tls/README.md#tls-12-aes-cbc) |
| Which QUIC Initials or application packets did the capture record? | Direct and capture-level QUIC v1/v2 Initial decoding derive Initial keys from public information. Byte-slice and seekable scans expose observable TLS offers. | Keyed capture scans associate supported AES-GCM 1-RTT packets with an Initial exchange. The optional handshake scan reports the server-selected ALPN and contributing packets when server Handshake keys authenticate EncryptedExtensions. Each authenticated packet carries its source packet index and UDP offset. The scan tracks authenticated connection-ID changes and up to 32 successive key updates per direction, keeping the immediately preceding generation for bounded reordering. Directional stream reconstruction reports a contiguous prefix and clean FIN, gap or reset. Read, authentication and output budgets are separate. | [QUIC Initial and 1-RTT guide](parsing.md#decrypt-quic-initial-packets) · [RFC Initial vectors](../testdata/foxio/README.md) · [aioquic 1.3.0 reference tests](../keyed_quic_test.go) |
| Can I locate and reopen an HTTP/1 or HTTP/2 exchange? | Direct HTTP/1 parsers and the HTTP/2 frame parser accept already located bytes. Byte-slice `HTTP`, `HTTP2` and `Web` handle cleartext and supported TLS streams. | Byte-slice and seekable transaction scans give request/response evidence for supported cleartext and keyed exchanges. Pairing and body coverage have explicit limits. HTTP/2 retains directional HPACK dependencies. Exports can include packets shared with other exchanges or needed to decode the selection. Keyed exports retain ciphertext and require separate keys on reopening. | [HTTP/1 cleartext capture](../testdata/deployments/README.md#http1-transaction-fixture) · [HTTP/2 cleartext export](../testdata/deployments/README.md#reopen-the-stream-3-export) · [Keyed export reference](../testdata/tls-provenance.md) |
| Which HTTP/3 fields and entity bytes are visible? | HTTP/3 framing is unavailable. | `ParseHTTP3Stream` identifies frame ranges and stream kinds after the caller establishes HTTP/3. It reports incomplete and truncated streams and can retain preceding complete frames. A separate QPACK decoder recovers static or dynamic fields from a known encoder timeline and identifies blocked, malformed and limited sections. With authenticated h3 and traffic keys, keyed transaction scans return per-stream requests and responses, bounded bodies, QPACK states and directional capture packet selections. | [Framing and QPACK](parsing.md#delimit-http3-frames) · [Keyed transactions](parsing.md#recover-keyed-http3-request-streams) · [HTTP/3 fixture evidence](#encrypted-transport-fixtures) |
| What WebSocket messages followed an HTTP/1.1 upgrade? | `ParseWebSocketFrames`, `WebSockets` and `WebWithWebSockets` return bounded messages from located frames or supported cleartext and keyed HTTP/1.1 upgrades. | The capture-level locator is the flow and sending direction. One-sided recordings need a visible HTTP boundary for the direction being decoded. Missing bytes or unsupported extension framing can suppress later messages. The external test checks message completion and bounds. | [WebSocket capture guide](parsing.md#extract-websocket-messages) · [External consumer contract](../testdata/consumer/contract_test.go) |
| Which handshake or enterprise metadata was visible? | Direct parsers and byte-slice scans cover SSH banners/KEXINIT, SMB2/3 and NTLMSSP metadata, Kerberos v5 on port 88, and RDP negotiation. | SSH, SMB and RDP records identify a flow. A Kerberos record identifies its starting packet. SMB transform headers expose only their visible metadata. LDAP Bind/Search and connection-oriented DCE/RPC have direct, byte-slice and seekable paths. LDAP includes keyed LDAPS on port 636. RPC includes attributed cleartext SMB2 pipe buffers. | [SSH and enterprise protocols](parsing.md#parse-ssh-handshakes-and-hassh) · [LDAP tests](../ldap_capture_test.go) · [Keyed LDAP tests](../keyed_ldap_test.go) · [RPC tests](../dcerpc_capture_test.go) |
| Can I compare a captured fingerprint with another tool? | JA4 and supported JA4+ methods, HASSH/HASSHServer and the HTTP/2 settings fingerprint are available from their protocol inputs. | The fingerprint describes captured inputs and can be absent when required bytes were missed. The reference checks specify the algorithm, source packet or packet window and expected result. Applicable terms vary by method. | [FoxIO baseline and frame references](../testdata/foxio/README.md) · [Third-party notices](../NOTICE) |

### Enterprise packet locators

This table describes packet attribution in the current checkout.

| Protocol | Original capture locator |
| --- | --- |
| SMB | An evidence scan retains opening packet, directional stream range and contributing packets. A transform exposes its visible header. [SMB evidence](parsing.md#find-the-original-packets-for-an-smb-command) |
| SSH and RDP | The capture records identify the observed flow and endpoints. [SSH record](../ssh.go) · [RDP record](../rdp.go) |
| Kerberos | The UDP message packet or the TCP packet supplying the first record-mark byte. [Kerberos record](../krb5.go) |
| LDAP and LDAPS | The first cleartext message byte for TCP or the UDP packet. Keyed LDAPS retains the TCP opening and packet sets for whole authenticated TLS records. [Cleartext record](../ldap_capture.go) · [Keyed record](../keyed_ldap.go) |
| DCE/RPC | The packet supplying the first fragment byte in TCP or an observed SMB2 pipe buffer. [DCE/RPC record](../dcerpc_capture.go) |

## Platform observations

| Environment | v0.1.1 evidence | Main evidence |
| --- | --- | --- |
| Linux | Native and 386 tests and privileged loopback counters passed. | The Go 1.26.11 AMD64 and 386 loopback suite exercised live reads, wire lengths and counters with `CAP_NET_RAW`. Linux resolves supported datalinks during interface discovery. [Hosted Linux job](https://github.com/cawalch/go-pcap/actions/runs/45913998511/job/140228753586) |
| macOS | Native ARM64 tests passed. Live verification reported missing BPF access. | Hosted Go 1.27.4 ARM64 tests passed. With BPF access, `TestLiveDevicesDarwinLoopback` verified `lo0` discovery and agreement with the opened capture's datalink. [Hosted macOS job](https://github.com/cawalch/go-pcap/actions/runs/45913998511/job/140228753574) |
| Windows | The AMD64 test binary cross-compiled. | Hosted Go 1.27.4 AMD64 tests passed, including read, filter and timeout tests using ordinary UDP sockets. Privileged `SIO_RCVALL` capture requires its own verification. [Hosted Windows job](https://github.com/cawalch/go-pcap/actions/runs/45913998511/job/140228753513) |

See [release platform verification](../CHANGELOG.md#platform-verification)
and the [live capture guide](parsing.md#capture-live-interface-traffic) for
backend options and privilege requirements.

## Encrypted transport fixtures

| Fixture | Origin and keys | Pinned reference and expected frames |
| --- | --- | --- |
| `quic-1rtt-v1.pcap` and `quic-1rtt-v2.pcap` | Synthetic traffic between two aioquic 1.3.0 endpoints. Associated test-only key entries are in `quic-1rtt-vectors.json`. | TShark 4.6.10 confirms packet numbers and stream data. The capture tests locate application packet numbers 3, 4 and 5 in client frames 3, 5 and 6, and packet numbers 2 and 3 in server frames 4 and 7. [QUIC association test](../keyed_quic_test.go) |
| `quic-cid-interop.pcapng` | A quic-go v0.63.0 server and aioquic 1.3.0 client exchanged `before rotation` and `after rotation` on streams 0 and 4. This synthetic nine-datagram loopback capture uses documentation addresses and embeds only the two test application traffic secrets. | TShark 4.6.10 identified client application packets in frames 3, 5 and 7 and server packets in 2, 4, 6, 8 and 9. CID tracking recovers all eight, up from three with the Initial IDs alone. It includes both endpoint-confirmed requests and replies. [Interop test](../quic_cid_test.go) |
| `quic-key-updates-rotated.pcap` | aioquic 1.3.0 endpoint capture with a CID change, two key updates and a reordered packet from the first generation. | TShark 4.6.10 confirms the first rotation and phase change in frame 8, the delayed first-generation packet in frame 10 and the second phase change in frame 14. [Generator and decoder evidence](../testdata/quic-key-updates.md) |
| `doq-exchanges.pcap` | aioquic 1.3.0 client and resolver with two overlapping A queries whose replies finish in reverse order. | TShark 4.6.10 identifies both query and reply pairs with keys. A separate dnspython resolver diagnostic returns both expected addresses. [Endpoint and decoder evidence](../testdata/doq-exchanges.md) |
| `quic-alpn-doq.pcapng` | Client and server aioquic 1.3.0 endpoints reported `doq`. The two-datagram v1 capture embeds the synthetic server handshake secret. | TShark 4.6.10 reports offers `h3,doq,fixture` in frame 1 and selected `doq` in frame 2. It finds server-selected `h3` in the existing HTTP/3 fixture and `fixture` in the v2 capture with `quic-1rtt-v2-handshake.keys`, also in frame 2. [ALPN endpoint tests](../quic_alpn_test.go) |
| `http3-framing.pcapng` | Synthetic aioquic 1.3.0 v1 session. TLS secrets are embedded in the fixture. | TShark 4.6.10 reports request stream 0 HEADERS/DATA lengths 22/7 in client frame 10 and 3/8 in server frame 12. Their DATA bytes are `request` and `response`. [HTTP/3 test](../http3_test.go) |
| `tls12-cbc.pcapng` | TLS bytes from eight OpenSSL 4.1.0 loopback connections, carried in synthetic Ethernet/IP/TCP packets. The test master secrets are embedded. | TShark 4.6.10 confirms the `/response` request and status 200 in eight streams. [Endpoint commands and cipher table](../testdata/tls/README.md#tls-12-aes-cbc) |

Run this command with TShark 4.6.10 (commit `eac916f07299`) from the
repository root to check the HTTP/3 frame observations.

```sh
tshark -n -o tls.keylog_file: -r testdata/http3-framing.pcapng -Y http3 \
  -T fields -e frame.number -e quic.stream.stream_id \
  -e http3.frame_type -e http3.frame_length -e http3.data
```

## External caller verification

The deployment corpus includes full exchanges, a clipped Ethernet frame,
one-sided observations, opaque TLS 1.3 records and an ambiguous HTTP response
after a TCP gap. The external Go suite exercises packet ownership, record
order, unsupported links, and hard DNS, reassembly and WebSocket limits.
These checks use checked-in inputs. Reference decoders are used independently
of the test suite. [Deployment corpus](../testdata/deployments/README.md) · [External Go tests](../testdata/consumer/contract_test.go)

The [tagged acceptance workflows](../testdata/consumer/qualified/README.md)
exercise TLS configuration, resolver diagnosis and HTTP content with positive,
negative and unavailable controls. The separate Go modules bind v0.2.0
without a workspace override. The go-yara integration confirms defined
agreement, defined disagreement and undefined certificate evidence on a
byte slice and a seekable input. The checks record input size, read counts
and allocations.

The [independent reference captures](../testdata/deployments/qualified.md)
cover a Kerberos UDP error, RDP connection request, cleartext and keyed
LDAP Bind, and a DCE/RPC Bind. Each covers the observed messages in the
fixture. SSH algorithm variants, encrypted SMB commands, RDP session data,
Kerberos TCP exchanges and DCE/RPC over authenticated SMB stay outside that
reference set. The original aioquic fixtures have reproducible decoding
commands. Their original endpoint generator is unavailable.
[Coverage qualification issue](https://github.com/cawalch/go-pcap/issues/267)
