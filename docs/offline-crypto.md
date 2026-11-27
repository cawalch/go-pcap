# Offline TLS and QUIC cipher coverage

Start with the cipher-suite ID from the observed ServerHello.
`Capture.TLS` and `Capture.TLSFromReaderAt` can report a visible TLS hello
with a cipher that the record decryptor cannot use. `Capture.QUIC` and
`Capture.QUICFromReaderAt` can do the same for a ServerHello recovered from
QUIC Initial packets. QUIC Initial protection uses version-specific public
secrets and AES-128-GCM independently of the cipher negotiated for later
packets. [TLS handshake guide](parsing.md#parse-tls-handshakes-and-ja4-fingerprints) ·
[QUIC Initial secrets](https://www.rfc-editor.org/rfc/rfc9001.html#section-5.2) ·
[QUIC v2 changes](https://www.rfc-editor.org/rfc/rfc9369.html#section-3.3)

## Supported protection

| Traffic | Protection | Key input and capture scope |
| --- | --- | --- |
| TLS 1.2 application records | AES-128-GCM with SHA-256 and AES-256-GCM with SHA-384. Each key size supports RSA, ECDHE_RSA and ECDHE_ECDSA. Suite IDs are `0x009c`, `0x009d`, `0xc02b`, `0xc02c`, `0xc02f` and `0xc030`. | `CLIENT_RANDOM` master secret. `DecryptTLS12Records` takes both hello randoms and a wire direction. Capture scans can use embedded or supplied secrets. [TLS 1.2 GCM suite selection](../tls_decrypt.go) |
| TLS 1.2 application records | The eight AES-CBC suites in the fixture. MAC-then-encrypt and encrypt-then-MAC are supported. | `CLIENT_RANDOM` master secret. The direct parser establishes the layout on the first authenticated record. The capture path uses the ServerHello extension. [CBC suite IDs and OpenSSL fixture](../testdata/tls/README.md#tls-12-aes-cbc) |
| TLS 1.3 protected handshake and application records | `TLS_AES_128_GCM_SHA256` (`0x1301`) and `TLS_AES_256_GCM_SHA384` (`0x1302`). | Handshake traffic secrets recover available handshake records. Application traffic secrets recover authenticated application bytes and permit bounded KeyUpdate tracking. Early data uses the client early traffic secret. [TLS key inputs](parsing.md#decrypt-tls-12-and-tls-13-streams-offline) |
| QUIC v1 and v2 Initial packets | AES-128-GCM with SHA-256 and AES header protection. | The initial destination connection ID and the public version salt derive the keys. The caller supplies no secret. [QUIC Initial scans](parsing.md#decrypt-quic-initial-packets) |
| QUIC v1 and v2 1-RTT short headers | `TLS_AES_128_GCM_SHA256` and `TLS_AES_256_GCM_SHA384`, with AES header protection. | `NewQUIC1RTTDecoder` takes one direction's initial traffic secret. The capture scan uses both key-log directions and uniquely authenticates associated packets. Available coverage depends on connection IDs, the packet number window and the initial key generation. [Keyed QUIC capture scans](parsing.md#associate-keyed-quic-packets-with-capture-connections) |

Check the observed suite against the table before interpreting an empty
result. For a supported suite, inspect whether `Capture.TLSKeyLog` contains
the secret for the observed ClientHello random and the epoch you need. For
TLS 1.3 ECH, a key log can instead index secrets by the inner ClientHello
random. Available secrets can still yield no plaintext when required
records are missing or authentication fails.
[ECH and key lookup](parsing.md#interpret-server-names-with-ech)

The low-level TLS decryptors reject the unsupported ChaCha20 suites with an
error matching `ErrInvalidTLS` when given the corresponding record secret.
`NewQUIC1RTTDecoder` rejects unsupported suites with `ErrInvalidQUIC`.
Capture scans can omit application output for either an unsupported cipher
or an unavailable key. The OpenSSL fixture exercises both cases alongside
successful AES-GCM decryption. [Independent cipher fixture](../testdata/tls/README.md#tls-aes-gcm-and-chacha20-poly1305) ·
[QUIC decoder tests](../quic_1rtt_test.go)

## ChaCha20-Poly1305 decision

Keep ChaCha20-Poly1305 outside the offline decryptors under the Go 1.26 and
zero third-party runtime dependency contract. Go's public `crypto/tls`
handles the cipher for live TLS connections. The `crypto/hpke` AEAD
descriptor exposes a cipher-suite identity, and HPKE senders and recipients
derive and manage their own keys and nonces. These interfaces provide no
record AEAD accepting an arbitrary traffic key and nonce. QUIC additionally
needs a header mask generated from a separate ChaCha20 key and sample.
The Go 1.26 standard library implements both primitives internally and
provides no supported public constructors for these uses.
[Go 1.26 crypto/hpke](https://pkg.go.dev/crypto/hpke@go1.26.0) ·
[QUIC ChaCha20 header protection](https://www.rfc-editor.org/rfc/rfc9001.html#section-5.4.4)

Adding coverage would require a supported primitive outside the current
module dependency boundary or a new in-module cryptographic implementation.
Revisit when the supported Go floor supplies the needed primitives or the
module's dependency policy changes.
