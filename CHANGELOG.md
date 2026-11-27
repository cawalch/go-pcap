# Changelog

All notable changes to `go-pcap` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
for pre-v1 releases (`0.y.z` minor bumps may include API additions or changes).

## Unreleased

## [v0.2.0](https://github.com/cawalch/go-pcap/releases/tag/v0.2.0) - 2026-11-26

This experimental release adds capture-local protocol observations and
packet-only evidence export. The module remains pure Go and requires Go 1.26.

### Added

- Separate TCP openings after a new SYN and optionally isolate TCP openings
  and UDP fragments by PcapNG interface. The ordinary flow index still
  identifies the capture-wide bidirectional five-tuple.
- Report bounded unicast DNS transactions with query and reply packet
  references and ambiguous retry outcomes. Add keyed DNS over TLS and a
  helper for wire-format DNS inside HTTP/2.
- Recover supported TLS 1.2 AES-CBC records, including both MAC orders.
  Handle TLS 1.3 client early data and directional application key updates.
  Expose observed TLS name comparison and certificate validity.
- Authenticate supported QUIC v1 and v2 application packets from supplied
  secrets, associate them with an Initial exchange, and reconstruct
  directional streams. Delimit HTTP/3 frames on streams already identified
  by the caller. QPACK field sections remain compressed.
- Select bounded cleartext and keyed HTTP/1 and HTTP/2 transactions on
  either input path. Retain the original packet evidence and export
  packet-only PcapNG with needed decoding context. Keyed exports contain
  original ciphertext and require keys separately when reopened.
- Report bounded LDAP and LDAPS requests, DCE/RPC fragment metadata over
  direct TCP and supported SMB2 pipes, and additional Kerberos metadata.
- Decode additional datalinks and IP-in-IP. Report unsupported link-layer
  packet counts, ICMP errors along quoted flows, TCP zero windows, checksum
  evidence and scoped neighbor binding observations.
- Enumerate native live devices and provide a small numeric IPv4 BPF filter
  compiler. Stage gzip captures and pipes in the two offline example
  commands. Detect unsupported Zstandard and XZ wrappers at capture open.

### Fixed

- Stop TLS, SMB, RDP and SSH capture parsing at a known TCP sequence gap.
  HTTP transaction evidence distinguishes complete, incomplete and ambiguous
  observations.
- Improve PcapNG timestamps, obsolete Packet Blocks, Darwin attribution,
  selected packet export and Linux capture length and buffer handling.
- Bound TLS record coalescing, QUIC and HTTP decoding, and protocol scan
  work. See the [limits and partial results](docs/compatibility.md#limits-and-errors)
  and [coverage baseline](docs/capabilities.md).

### Platform verification

| Platform | Release candidate check |
| --- | --- |
| Linux | Hosted Go 1.26 and stable race tests, 386 tests, and privileged loopback on AMD64 and 386. |
| macOS | Hosted native tests and datalink discovery with BPF access. |
| Windows | Hosted native tests. Privileged Windows live capture remains unverified. |

## [v0.1.1](https://github.com/cawalch/go-pcap/releases/tag/v0.1.1) - 2026-11-23

This patch packages the [third-party notices](NOTICE) with the module,
including the terms for JA4 and JA4+, the Community ID test vectors and
the QUIC reference packets. The library API and implementation match v0.1.0.

Pull request checks now target GitHub-hosted Linux, macOS and Windows
runners. The [consumer compatibility guide](docs/compatibility.md) and its
external test module document and exercise the v0.1.0 baseline.

## [v0.1.0](https://github.com/cawalch/go-pcap/releases/tag/v0.1.0) - 2026-11-23

First experimental release of the Go 1.26+ module. It reads, analyzes and
writes packet captures with standard-library dependencies. The public API
may change in subsequent minor releases before v1.0.

### Fixed

- Resolve PcapNG interface IDs within each section and preserve ReaderAt flow
  byte counts and truncation flags across padded frames and deep headers.
- Retain earlier TCP segments on reordered midstream pickup and sequence wrap.
  Reject overlapping IPv6 fragments and handle atomic packets independently.
- Match reference TCP fingerprint padding and round half-RTT measurements to
  the nearest microsecond, with ties rounded to even.

### Added

- Bounded packet iteration and file-backed flow, DNS, TLS, QUIC, DHCPv4 and
  neighbor analysis. Single-flow PcapNG export carries interface metadata
  and can include capture-wide names and decryption secrets.
- Community ID v1 for TCP and UDP, DHCPv4 lease observations, local-link
  neighbors, and DNS service binding records.
- Shared TLS, HTTP/1 and HTTP/2 analysis with `Capture.Web`. Use
  `Capture.WebWithWebSockets` to also recover bounded messages after cleartext
  or decrypted HTTP/1.1 upgrades with one TCP reassembly.
- Classic PCAP (little/big-endian, microsecond/nanosecond) and PcapNG (`SHB`,
  `IDB`, `EPB`, `SPB`, `DSB`) container parsing (`New`, `NewWithLength`,
  `NewFromReaderAt`, `Open`) and PcapNG streaming output (`NewPCAPNGWriter`).
- PcapNG Decryption Secrets Block (`DSB`) extraction and Enhanced Packet Block
  (`EPB`) process/thread attribution.
- Zero-allocation stack-cursor L2–L4 frame decoder (`DecodeFrame`) for Ethernet,
  802.1Q/802.1ad VLANs, Linux SLL/SLL2, BSD Loopback/Null, Raw IP, IPv4, IPv6
  with extension headers, TCP, UDP, and ICMPv4/ICMPv6.
- FoxIO **JA4T / JA4TS** TCP SYN fingerprinting (`JA4T`, `Frame.JA4T`) and
  deterministic 5-tuple flow aggregation (`Capture.Flows`).
- Synchronous, bounded TCP stream reassembler (`ReassembleTCP`,
  `Capture.Streams`) with sequence-gap and overlap-conflict anomaly detection.
- Hardened DNS message dissector (`ParseDNS`, `Capture.DNS`,
  `Capture.HasDNSQuery`) with bounded RFC 1035 compression pointer resolution.
- TLS 1.2/1.3 handshake and X.509 certificate chain dissector
  (`ParseTLSRecords`, `ParseTLSClientHello`, `ParseTLSServerHello`,
  `JA4XFromDER`, `JA4XFromCert`, `Capture.TLS`, `Capture.HasTLSJA4`,
  `Capture.HasTLSSNI`) with FoxIO **JA4, JA4S, and JA4X** fingerprinting.
- QUIC v1 (RFC 9001) and QUIC v2 (RFC 9369) Initial packet decryption, `CRYPTO`
  frame reassembly, and inner TLS 1.3 `q13...` **JA4** extraction
  (`ParseQUICInitialPacket`, `DecryptQUICInitial`, `Capture.QUIC`,
  `Capture.HasQUICJA4`, `Capture.HasQUICSNI`).
- Offline decryption of supported TLS 1.2 and TLS 1.3 streams via PcapNG `DSB` or `SSLKEYLOGFILE` secrets
  (`ParseTLSKeyLog`, `Capture.TLSKeyLog`, `DecryptTLS13Records`,
  `Capture.DecryptedTLSStreams`).
- HTTP/1.x request/response dissector across cleartext and DSB-decrypted TLS 1.3
  streams (`ParseHTTPRequest`, `ParseHTTPResponse`, `Capture.HTTP`) with FoxIO
  **JA4H** fingerprinting and body payload carving.
- SSH handshake dissector (`ParseSSHHandshake`, `Capture.SSH`) with **HASSH**
  and **HASSHServer** fingerprinting.
- SMB2 share paths and filenames, SMB3 transform headers, and NTLMSSP negotiation/challenge dissection (`ParseSMB2Message`,
  `ParseNTLMSSP`, `Capture.SMB`).
- Statistical C2 beacon timing periodicity and Producer-Consumer Ratio (PCR)
  analyzer (`ComputeBeaconStats`, `Capture.Beacons`).
- Pure-Go stdlib `syscall` live interface capture (`OpenLive`, `ParseBPFBuffer`)
  for macOS (`/dev/bpf*`), Linux (`AF_PACKET`), and Windows (`SIO_RCVALL`).

### Platform verification

| Platform | Evidence for this release |
| --- | --- |
| Linux | Native amd64 CI passed on Go 1.26 and 1.27, including vet, race tests, 386 tests, lint and vulnerability checks. All 22 fuzz targets ran for bounded intervals. Live loopback counters passed on amd64 and 386. The full benchmark suite also completed a one-iteration smoke run. |
| macOS | Native arm64, Go 1.27.4. Vet, lint, examples and the race suite passed with 84.1% statement coverage. The live loopback test skipped because the account lacked BPF device access. |
| Windows | The complete amd64 test binary cross-compiled. Native tests and live capture remain unverified for this release. |

The hosted macOS and Windows jobs were enabled. GitHub billing prevented
execution. [Linux CI and hosted job status](https://github.com/cawalch/go-pcap/actions/runs/45246663064)

### Before v1.0

Set the compatibility contract for exported types, record ordering, input and
payload ownership, and parser limits and errors. Exercise those guarantees
from a consuming Go module across upgrades. Complete native Windows testing
and privileged macOS and Windows live-capture checks before promising those
platform behaviors. Protocol proposals can be evaluated separately from
that compatibility decision.
