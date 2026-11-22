# Agent guidelines

Follow [CONTRIBUTING.md](CONTRIBUTING.md) and apply a strict YAGNI ("you aren't
gonna need it") bar to every change in `go-pcap`.

## Decision ladder

Before writing new code, evaluate options in order and stop at the first match:

1. **Skip unnecessary work.** Do not add speculative abstractions, pass-through
   wrappers, or unrequested features.
2. **Reuse existing repo code.** Check existing helpers in the package before
   adding a new one.
3. **Use the Go standard library.** `go-pcap` has zero third-party runtime
   dependencies (`go.mod`). Prefer standard-library primitives (`slices`,
   `maps`, `bytes`, `encoding/binary`, `net/netip`, `crypto/x509`, `crypto/hkdf`,
   `crypto/aes`, `crypto/cipher`) over hand-rolled code.
4. **Keep new code minimal and bounded.** Every parser or reader path must
   enforce explicit size, count, and bounds checks without cutting corners on
   input validation or error handling.

## Scope boundaries

- Keep PCAP/PcapNG parsing, live OS capture (`syscall`), L2–L7 frame/flow
  dissection, fingerprinting (JA4+), and offline TLS/QUIC decryption in the
  root module; keep third-party comparisons in `benchmarks/`.
- Keep scanner-specific schemas, YARA adapters, and rule semantics in consuming
  projects (such as `go-yara`).
- Do not change exported APIs without updating docstrings, examples, and
  `docs/`.

## Verification

Run before finishing any Go code change:

```sh
gofmt -w *.go
golangci-lint run ./...
go vet ./...
go test -race ./...
```
