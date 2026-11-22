# Changelog

All notable changes to `go-pcap` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
for pre-v1 releases (`0.y.z` minor bumps may include API additions or changes).

## [v0.1.0] - 2026-11-21

### Fixed

- Resolve PcapNG interface IDs within each section and preserve ReaderAt flow
  byte counts and truncation flags across padded frames and deep headers.
- Retain earlier TCP segments on reordered midstream pickup and sequence wrap.
  Reject overlapping IPv6 fragments and handle atomic packets independently.
- Match reference TCP fingerprint padding and round half-RTT measurements to
  the nearest microsecond, with ties rounded to even.

### Added
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
- Offline TLS 1.3 stream decryption via PcapNG `DSB` or `SSLKEYLOGFILE` secrets
  (`ParseTLSKeyLog`, `Capture.TLSKeyLog`, `DecryptTLS13Records`,
  `Capture.DecryptedTLSStreams`).
- HTTP/1.x request/response dissector across cleartext and DSB-decrypted TLS 1.3
  streams (`ParseHTTPRequest`, `ParseHTTPResponse`, `Capture.HTTP`) with FoxIO
  **JA4H** fingerprinting and body payload carving.
- SSH handshake dissector (`ParseSSHHandshake`, `Capture.SSH`) with **HASSH**
  and **HASSHServer** fingerprinting.
- SMB2/3 and NTLMSSP negotiation/challenge dissector (`ParseSMB2Message`,
  `ParseNTLMSSP`, `Capture.SMB`).
- Statistical C2 beacon timing periodicity and Producer-Consumer Ratio (PCR)
  analyzer (`ComputeBeaconStats`, `Capture.Beacons`).
- Pure-Go stdlib `syscall` live interface capture (`OpenLive`, `ParseBPFBuffer`)
  for macOS (`/dev/bpf*`), Linux (`AF_PACKET`), and Windows (`SIO_RCVALL`).
