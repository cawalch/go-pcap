# Changelog

## Unreleased

- Add authenticated QUIC ALPN, connection-ID rotation, key updates, HTTP/3
  transaction evidence, ordinary DNS-over-QUIC exchanges, and QUIC protection
  coverage for observed Initial exchanges.
- Attribute TLS hellos, certificate chains, and SMB commands to original
  packets. Report incomplete keyed TLS observations and reduce unrelated
  reads in seekable TLS scans.
- Qualify the coverage matrix with independent traces and tagged Go and
  go-yara consumer tests.

## [v0.2.0](https://github.com/cawalch/go-pcap/releases/tag/v0.2.0) - 2026-11-26

### Added

- Bounded unicast DNS pairing, keyed DoT, and an HTTP/2 DoH helper.
- Interface-scoped TCP openings and UDP fragment grouping.
- TLS 1.2 AES-CBC, TLS 1.3 early data and key updates, and observed-name
  comparison. QUIC v1 and v2 1-RTT decryption and directional stream framing.
- Cleartext and keyed HTTP/1 and HTTP/2 evidence and packet-only exports.
  Keyed exports retain ciphertext and require separate keys.
- LDAP, LDAPS, DCE/RPC, and additional Kerberos metadata. Additional link
  types, checksum observations, and flow and neighbor diagnostics.
- Live interface discovery, numeric IPv4 BPF filters, and bounded gzip
  staging.

### Fixed

- Stop TLS, SMB, RDP, and SSH parsing at known TCP sequence gaps.
- Improve PcapNG timestamp and process attribution, legacy Packet Blocks,
  selected captures, and Linux capture buffer handling.
- Bound TLS, QUIC, and HTTP scan work.
  [Limits and partial results](docs/compatibility.md#limits-and-errors)

### Platform verification

| Platform | v0.2.0 evidence |
| --- | --- |
| Linux | Go 1.26 and stable race tests. Privileged loopback on AMD64 and 386. |
| macOS | Native tests and datalink discovery with BPF access. |
| Windows | Native tests. Privileged raw capture remains unverified. |

## [v0.1.1](https://github.com/cawalch/go-pcap/releases/tag/v0.1.1) - 2026-11-23

Packages [third-party notices](NOTICE) and uses GitHub-hosted PR checks.
The library API and implementation match v0.1.0.

## [v0.1.0](https://github.com/cawalch/go-pcap/releases/tag/v0.1.0) - 2026-11-23

### Fixed

- Resolve PcapNG interfaces per section and preserve byte counts across
  ReaderAt flow scans.
- Reassemble reordered TCP segments and reject overlapping IPv6 fragments.
- Match TCP fingerprint padding and half-RTT reference rounding.

### Added

- Pure-Go PCAP and PcapNG reading, writing, iteration, and flow export.
- Frame decoding, TCP stream reassembly, and protocol capture scans.
- TLS and QUIC Initial analysis, supported offline TLS decryption, and
  HTTP and WebSocket parsing. JA4+ and HASSH fingerprints.
- Live capture backends for Linux, macOS, and Windows.

### Platform verification

Linux passed native, 386, and privileged loopback tests. macOS passed
native tests without BPF access. Windows AMD64 cross-compiled.
[Release CI](https://github.com/cawalch/go-pcap/actions/runs/45246663064)
