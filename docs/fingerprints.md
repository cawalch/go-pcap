# Fingerprints computed by parsing APIs

A fingerprint describes the observed input. It can be empty when required
bytes are missing. The automatic calculations affect callers that need only
another field from the same parser.

| Method | Automatic calculation | Explicit helper or input |
| --- | --- | --- |
| JA4 and JA4S | TLS hello parsers, TLS scans, and QUIC Initial decoding | Client or server hello fields |
| JA4X | TLS certificate decoding, including supported keyed handshakes | `JA4XFromDER`, `JA4XFromCert` |
| JA4H | HTTP/1 request parsing, `HTTP`, and `HTTPRequests`. `HTTPRequests` returns request observations without the fingerprint field. | HTTP/1 request fields |
| JA4L and JA4LS | `Flows` and its ReaderAt variant, when handshake packets are available | `JA4L` with timing and TTL |
| JA4T and JA4TS | `Flows` and its ReaderAt variant, when SYN options are available | `JA4T`, `Frame.JA4T` |
| JA4SSH | `SSH` across a recognized session | `JA4SSH` with a packet window |

Combined web scans retain the TLS and HTTP/1 calculations. TLS and QUIC
name-only lookup reuses the hello parsers. Keyed TLS scans also parse hellos
to associate secrets. `ParseSSHHandshake` computes HASSH and HASSHServer.
HTTP/2 parsing provides SETTINGS and, with sufficient client context, an
Akamai fingerprint. [Pinned reference fixtures](../testdata/foxio/README.md)

## Entry points for primitive fields

- Use packet iteration and `DecodeFrame` for raw TCP timing and options,
  and `ClassifyL7` for a prefix-based protocol hint.
- Use `HTTP1RequestEvidence` or `HTTP1Transactions` for cleartext HTTP/1
  fields without calculating JA4H.
- Use `crypto/x509.ParseCertificate` for certificate DER,
  `ParseQUICInitialPacket` for visible QUIC header fields, or the directional
  TLS and QUIC decryption APIs for caller-supplied cryptographic context.

## Upstream terms

JA4 is BSD-3-Clause. Other FoxIO methods in this inventory use FoxIO
License 1.1. Review which calculations your distributed application uses.
[Third-party notices](../NOTICE) ·
[FoxIO licensing FAQ](https://github.com/FoxIO-LLC/ja4/blob/aaf2113031b76e98642355b69bf83799c3e6b9af/License%20FAQ.md)
