# Offline TLS and QUIC cipher coverage

Use the observed ServerHello suite to determine whether a protected
record can be decoded. TLS and QUIC scans can report an observed hello
even when a key or cipher is unavailable.
[TLS and QUIC key sources](parsing.md#choose-tls-and-quic-key-sources)

## Supported protection

| Traffic | Protection | Key input |
| --- | --- | --- |
| TLS 1.2 application | AES-GCM suites `0x009c`, `0x009d`, `0xc02b`, `0xc02c`, `0xc02f`, `0xc030` | `CLIENT_RANDOM` master secret, hello randoms, and direction |
| TLS 1.2 application | [Eight AES-CBC suites](../testdata/tls/README.md#tls-12-aes-cbc), both MAC orders | `CLIENT_RANDOM` master secret |
| TLS 1.3 handshake and application | AES-GCM suites `0x1301` and `0x1302` | Traffic secret for the direction and epoch. Application keys can follow bounded updates. Early data needs a client early traffic secret. |
| QUIC v1 and v2 Initial | AES-128-GCM and AES header protection | Public destination connection ID and version salt |
| QUIC v1 and v2 server ALPN and 1-RTT | AES-GCM suites `0x1301` and `0x1302` with AES header protection | Directional traffic secret and packet context. The capture scan can follow bounded application key updates. |

Missing records, ECH's private ClientHello random, or authentication
failure can prevent recovery with a supported suite.
[OpenSSL and TShark cipher fixture](../testdata/tls/README.md#tls-aes-gcm-and-chacha20-poly1305)

## ChaCha20-Poly1305 decision

Offline coverage omits ChaCha20-Poly1305. Go 1.26 supports it in live
`crypto/tls` and HPKE, but supplies neither a public record AEAD with
arbitrary traffic keys and nonces nor the QUIC header protection primitive.
The library keeps its Go 1.26 floor and zero runtime dependencies.
[Go 1.26 HPKE](https://pkg.go.dev/crypto/hpke@go1.26.0) ·
[QUIC header protection](https://www.rfc-editor.org/rfc/rfc9001.html#section-5.4.4)

## Measured coverage gap

| Keyed endpoint fixture | Reference decoder | go-pcap |
| --- | --- | --- |
| TLS 1.2 and 1.3 [OpenSSL HTTP/1](../testdata/tls/README.md#tls-aes-gcm-and-chacha20-poly1305) | Four exchanges, two AES-GCM and two ChaCha20-Poly1305 | Two AES-GCM exchanges. All four selected suites are visible. |
| QUIC v1 [aioquic DNS-over-QUIC](../testdata/doq-exchanges.md) | Two exchanges for each of AES-GCM and ChaCha20-Poly1305 | Two AES-GCM exchanges. Both selected suites are visible in Initial packets. |

For TCP, `Capture.TLS` shows the selected suite when the ServerHello is visible.
`Capture.AnalyzeKeyedHTTP1` reports `TLSCoverageUnsupported` in both directions
of the keyed ChaCha20 exchanges above. Removing the keys from the AES controls
reports `TLSCoverageMissingKey`. Failed record authentication has a separate
`TLSCoverageAuthenticationFailed` boundary. A missing hello can leave no
opening to diagnose.

For QUIC, `Capture.AnalyzeKeyedQUIC` reports `QUICProtectionUnsupported`
for the selected ChaCha20 suite. Removing keys from the AES control reports
`QUICProtectionMissingKey` for each missing directional secret. The wrong-key
control reports `QUICProtectionAuthenticationFailed` for a uniquely attempted
AEAD failure. The cause of a failed attempt can remain unknown. If the scan
recovers the ClientHello and has no final ServerHello, it reports
`QUICProtectionHandshakeUnavailable`. An ambiguous association or an opaque
packet without an authentication attempt can leave the state unknown.
Authenticated protection confirms some packets and can still yield zero
recognizable transactions.

TShark 4.6.10 found seven ServerHellos across the 11 checked-in
[deployment fixtures](../testdata/deployments/README.md). All seven selected
AES. Only the enterprise LDAPS exchange supplies a negotiated suite and
verified keys for application traffic. These are synthetic fixtures, so
the frequency of key-backed ChaCha20 traffic in deployments is unknown.

Keep the existing cipher boundary until a representative, key-backed capture
shows an affected consumer workload. TLS record recovery would require a
public ChaCha20-Poly1305 AEAD that accepts the traffic key and record nonce.
QUIC would additionally require ChaCha20 header protection. On Go 1.26,
support would require revisiting the runtime dependency decision for those
primitives.

```sh
go test -count=1 -run 'CipherCoverage|QUIC1RTT|KeyedQUICProtectionCoverage|TestKeyedHTTP1Analysis$' .
```
