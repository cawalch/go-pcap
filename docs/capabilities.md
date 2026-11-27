# Capture analysis capability matrix

The baseline is [v0.1.1](https://github.com/cawalch/go-pcap/tree/v0.1.1).
The last column describes the current tree and points to independent
verification where available. The
[tagged consumer suite](../testdata/consumer/qualified/README.md)
uses [v0.2.0](https://github.com/cawalch/go-pcap/tree/v0.2.0).

Packet indices start at zero. TShark frame numbers start at one.
Interpret absent results using the capture point, keys, completeness, and
[work limits](parsing.md#work-and-output-limits).

## Capture, frames and transport

| Question | v0.1.1 | Current coverage and evidence |
| --- | --- | --- |
| What packets and metadata did the writer record? | PCAP and PcapNG from bytes or ReaderAt, writers, and flow export. | Adds obsolete Packet Blocks, Darwin attribution, and bounded gzip staging. A clipped tail can leave a readable prefix. Packet-only export omits capture-wide metadata. [Container and export contracts](parsing.md#parse-capture-containers) |
| What is inside a frame or tunnel? | L2–L4 offsets for Ethernet, cooked, loopback, raw IP, wireless, and supported tunnels. | Adds PKTAP, PPP variants, PFLOG, NFLOG, IP-in-IP, and ICMP quotes. Inner frame visibility can exceed capture scan scope. Encrypted payloads can remain opaque. [Framing fixtures](../testdata/framing/README.md) |
| Which flows, streams, or neighbors did I observe? | Bidirectional five-tuples, TCP reassembly, Community ID, DHCPv4, ARP, and IPv6 neighbor records. | Supports interface-scoped TCP openings and selected UDP fragment grouping. IP-fragmented TCP remains outside batch stream decoding. Also reports scoped neighbor changes, ICMP flow errors, and TCP zero windows. [Scope fixture](../testdata/framing/tenant-scope.md) |

## Application observations

| Question | v0.1.1 | Current coverage and evidence |
| --- | --- | --- |
| Did DNS receive a reply? | DNS messages over supported UDP and TCP bindings. | Pairs ordinary unicast requests and replies, preserving ambiguous and one-sided cases. Also covers keyed DoT and DoQ, and a helper for HTTP/2 DoH. [Resolver guide](parsing.md#diagnose-dns-transactions) · [DoQ trace](../testdata/doq-exchanges.md) |
| Which TLS name or certificate was visible? | TLS hellos, available certificates, and supported AES-GCM decryption. | Attributes hellos and certificates to TCP openings and original packets. Reports incomplete keyed results, covers supported TLS 1.2 CBC, and distinguishes visible ECH names from private data. [TLS evidence](parsing.md#locate-a-hello-or-certificate-chain-in-the-original-packets) · [Cipher fixture](../testdata/tls/README.md) |
| Which QUIC packets and streams can I inspect? | v1 and v2 Initials and client offers. | Authenticates supported AES-GCM application packets, ALPN, ID rotation, and key updates. Retains packet index and UDP offset. A stream can end in a gap or reset. [QUIC association](parsing.md#associate-keyed-quic-packets-with-capture-connections) |
| Which HTTP exchanges can I recover? | HTTP/1 parsing and bodies, HTTP/2 frames, TLS-aware capture scans. | HTTP/1 and HTTP/2 expose bounded packet evidence and replayable selections. HTTP/3 exposes QPACK states, body coverage, and original packets. Keep source files for HTTP/3 replay. [HTTP guide](parsing.md#parse-http-messages-and-carve-payloads) · [HTTP/3 guide](parsing.md#recover-keyed-http3-request-streams) |
| What crossed a WebSocket upgrade? | Bounded messages from located frames or supported cleartext and keyed HTTP/1.1 upgrades. | Directional flow evidence. Missing framing or unsupported extensions can stop decoding. [Consumer contract](../testdata/consumer/contract_test.go) |
| Which fingerprints are available? | JA4+, HASSH, and HTTP/2 fingerprints from observed fields. | Availability depends on captured inputs. [Automatic calculations and terms](fingerprints.md) |

### Enterprise packet locators

SSH, SMB, RDP, and Kerberos have baseline parsers. The current tree adds
bounded LDAP and DCE/RPC capture coverage and SMB command attribution.

| Protocol | Locator |
| --- | --- |
| SMB | TCP opening, direction, stream range, and contributing packets. Encrypted commands remain opaque. [SMB fixture](../testdata/framing/smb-evidence.md) |
| SSH and RDP | Flow and endpoints. |
| Kerberos | UDP packet or TCP record-mark packet. |
| LDAP and LDAPS | Message-start packet or the packets for whole authenticated TLS records. |
| DCE/RPC | Fragment-start packet in TCP or a supported SMB pipe. |

[Independent enterprise captures](../testdata/deployments/qualified.md#enterprise-metadata)

## Platform observations

| Platform | v0.1.1 | v0.2.0 verification |
| --- | --- | --- |
| Linux | Native and 386 tests, privileged loopback. | Hosted AMD64 and 386, including privileged loopback. [Linux job](https://github.com/cawalch/go-pcap/actions/runs/45913998511/job/140228753586) |
| macOS | Native ARM64, live tests skipped without BPF access. | Hosted native tests and loopback datalink discovery with BPF access. [macOS job](https://github.com/cawalch/go-pcap/actions/runs/45913998511/job/140228753574) |
| Windows | AMD64 test binary cross-compiled. | Hosted native tests with ordinary UDP sockets. Privileged raw capture lacks verification. [Windows job](https://github.com/cawalch/go-pcap/actions/runs/45913998511/job/140228753513) |

## Encrypted transport fixtures

- [QUIC Initial and ALPN fixtures](../testdata/deployments/qualified.md#recheck-the-existing-keyed-quic-captures)
  cover v1 and v2 and h3 selection. The ALPN test adds DoQ and a third
  negotiated value. [ALPN test](../quic_alpn_test.go)
- [CID interop](../quic_cid_test.go) recovers eight authenticated packets
  from quic-go and aioquic, up from three using the Initial IDs.
  [Key updates](../testdata/quic-key-updates.md) exercise rotation together
  with two updates and reordering.
- [TLS and HTTP replay fixtures](../testdata/tls-provenance.md) and the
  [cipher reference](../testdata/tls/README.md) record original packets,
  decoder versions, and key inputs.

## External caller verification

The [tagged Go and go-yara suites](../testdata/consumer/qualified/README.md)
check positive, negative, and unavailable TLS, DNS, and HTTP results.
The [deployment corpus](../testdata/deployments/README.md) also covers
clipped and one-sided inputs. [Qualification issue](https://github.com/cawalch/go-pcap/issues/267)
