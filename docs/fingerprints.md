# Fingerprints computed by parsing APIs

Use this inventory when choosing entry points for an embedded application.
The fingerprint fields describe the observed protocol inputs. They can be
empty when required bytes are unavailable. The tables distinguish computed
outputs from the underlying packet fields and helpers you call explicitly.

| Method | Inputs | Calls that compute it automatically | Explicit helper and reference |
| --- | --- | --- | --- |
| JA4 | TLS client hello version, SNI presence, ALPN, cipher suites, extensions and signature algorithms. | `ParseTLSClientHello`, `ParseTLSRecords`, `TLS`, `TLSWithKeyLog` and `TLSFromReaderAt` compute `TLSClientHello.JA4` when the hello is parsed. `DecryptQUICInitial`, `QUIC`, `QUICFromReaderAt` and the keyed QUIC scans compute the QUIC form from the Initial ClientHello. | The hello parsers expose the computed value. [GREASE and RFC Initial vectors](../testdata/foxio/README.md) |
| JA4S | TLS server hello version, cipher suite, extensions and visible ALPN. | The TLS server hello parser and TLS capture scans compute `TLSServerHello.JA4S`. QUIC Initial capture scans compute the QUIC form when they recover the server hello. | `ParseTLSServerHello` computes the TLS form. [Server hello reference frame 6](../testdata/foxio/README.md) |
| JA4X | ASN.1 issuer and subject RDN types and X.509 extension identifiers. | `ParseTLSRecords` and TLS capture scans compute `TLSCertificate.JA4X` for each certificate they decode, including certificates decrypted with supported TLS 1.3 handshake keys. | `JA4XFromDER`, `JA4XFromCert`. [Certificate reference frame 7](../testdata/foxio/README.md) |
| JA4H | HTTP/1 request method, version, header names, cookie information, referer presence and language. | `ParseHTTPRequest` and `HTTP` compute `HTTPRequest.JA4H`. `HTTPRequests` and `HTTPRequestsFromReaderAt` also compute it through the HTTP/1 parser, then return only request observations. | The request parser exposes the computed value. [HTTP frame and cookie references](../testdata/foxio/README.md) |
| JA4L and JA4LS | Captured TCP handshake timing and the packet TTL or hop limit used in the calculation. | `Flows` and `FlowsFromReaderAt` compute per-flow values in `ClientJA4L` and `ServerJA4L` from observed handshake packets when available. | `JA4L` takes a timing delta and TTL. [Handshake reference frames 109, 111 and 112](../testdata/foxio/README.md) |
| JA4T and JA4TS | SYN or SYN-ACK window and TCP option bytes. | `Flows` and `FlowsFromReaderAt` populate `ClientJA4T` and `ServerJA4TS` when the relevant packet and options are available. | `JA4T` accepts a window and options. `Frame.JA4T` locates the options in the supplied frame. [SYN and SYN-ACK reference frames 1 and 2](../testdata/foxio/README.md) |
| JA4SSH | Packet direction, TCP payload length and flags. | `SSH` computes `SSHRecord.JA4SSH` by collecting packets for a recognized SSH session. | `JA4SSH` summarizes the caller's packet window. [Packet window reference frames 1–200](../testdata/foxio/README.md) |

`Web` and `WebWithWebSockets` include the TLS and HTTP/1 calculations.
`HasTLSSNI` and `HasQUICSNI` reuse their capture scans, so name-only lookups
also compute the applicable hello fingerprints. High-level keyed TLS
analysis goes through the hello parsers to associate traffic keys. This
applies even when those hello records are absent from the returned result.
[Combined web scan](../web.go) · [TLS record decryption](../tls_decrypt.go) ·
[Keyed record provenance](../tls_provenance.go)

`ParseSSHHandshake` computes HASSH and HASSHServer from available directional
KEXINIT algorithm lists. `SSH` retains those fields alongside JA4SSH.
`ParseHTTP2Frames` and `HTTP2` expose the SETTINGS fingerprint and calculate
the Akamai fingerprint when a complete client request follows the preface.
These fields are distinct from the JA4+ methods in the table.
[SSH parser](../ssh.go) · [HTTP/2 parser](../http2.go)

## Entry points for primitive fields

| Needed evidence | Entry point |
| --- | --- |
| Packet timestamps, IP and transport headers, TCP window and the option byte range | Use `PacketSeq` or `PacketSeqFromReaderAt` with `DecodeFrame`. These entry points expose the inputs for JA4T and JA4L without invoking the flow summary calculations. [Frame decoding](parsing.md#decode-l2l4-frames-and-tunnels) |
| Bounded classification from a prefix | Use `ClassifyL7` on located payload bytes. It returns a protocol candidate. [Prefix classification](parsing.md#identify-an-application-protocol-from-a-prefix) |
| Cleartext HTTP/1 method, raw target, ordered headers, body or response association | Use `HTTP1RequestEvidence` or `HTTP1Transactions` and their ReaderAt variants. These paths parse the request line and headers without invoking JA4H. `ParseHTTPResponse` provides direct response parsing. [HTTP/1 evidence parser](../http_evidence.go) |
| Cipher suites or names from typed TLS hellos | The public hello parsers couple field extraction with fingerprint computation. If you already have DER bytes, `crypto/x509.ParseCertificate` gives certificate fields without invoking JA4X. [TLS handshake parser](../tls.go) |
| QUIC Initial header fields or already located protected records | `ParseQUICInitialPacket` parses the visible packet header. `NewQUIC1RTTDecoder` and the directional TLS decryption functions accept caller-supplied cryptographic context. The directional functions and the QUIC header parser do not invoke the TLS hello fingerprints. [QUIC Initial header parser](../quic.go) · [Directional TLS decryptors](../tls_decrypt.go) |

To check the default TLS and HTTP/1 parser outputs against the pinned FoxIO
baselines, run the fixture tests from the repository root.

```sh
go test -count=1 -run 'JA4|Fingerprint|TLS|HTTP' .
```

A standalone Go 1.26.0 caller also observed JA4 and JA4S through
`Capture.TLS` on `client.pcapng`, and JA4H through `Capture.HTTP` on the
`/upload` request in `http1-transactions.pcapng`.
[Deployment captures and source frames](../testdata/deployments/README.md)

## Upstream terms

The repository notice identifies JA4 TLS client fingerprinting as
BSD-3-Clause and the other FoxIO methods listed here as FoxIO License 1.1.
FoxIO's FAQ describes an OEM license for vendors that sell JA4+ as part
of their product offering. The inventory identifies which methods run in
each API. Review the notices and upstream terms for your distribution.
[Repository notices](../NOTICE) ·
[FoxIO licensing FAQ](https://github.com/FoxIO-LLC/ja4/blob/aaf2113031b76e98642355b69bf83799c3e6b9af/License%20FAQ.md)
