# Contributing to go-pcap

Keep changes focused on the standalone packet capture and protocol parser.
Include regression tests for behavior changes and benchmarks for changes to
capture indexing, frame decoding, or flow aggregation.

## Scope a change

Before adding a protocol dissector or analysis feature, assess existing Go
libraries for suitable implementations. Consider their APIs, dependencies,
licenses, input validation, resource use, and performance on comparable
workloads. Use standard-library primitives where they meet the requirements.

Keep scanner schemas, rule semantics, and scan lifecycle management in consuming
projects. If a feature adds expensive parsing or stream reassembly, define its
work limits and error behavior for general library callers.

## Write documentation

Follow the [Google developer documentation style guide](https://developers.google.com/style/)
for the README, repository documentation, and prose in code comments. Follow
[Go doc comment conventions](https://go.dev/doc/comment) for API comments and
`gofmt` for Go code, including code samples.

- Write direct sentences in active voice. Address the reader as "you" in instructions.
- Use familiar words, sentence-case headings, and consistent technical terms.
- Define abbreviations on first use when readers might not know them.
- Put conditions before instructions. Use numbered lists for ordered steps.
- Introduce code samples and commands. Provide runnable examples or identify
  omitted context, and verify the examples you change.
- Describe implemented behavior and relevant limits. Avoid promotional claims,
  unsupported guarantees, and promises about future features.
- Start exported API comments with the identifier's name. Link related symbols
  with Go doc links, such as `[New]`.

## Validate a change

From the repository root, format the Go files and run the tests and static checks:

```sh
gofmt -w *.go
golangci-lint run ./...
go vet ./...
go test -race -cover ./...
```

For parser or reader changes, run the applicable fuzz target:

```sh
go test -run '^$' -fuzz '^FuzzNew$' -fuzztime=30s -parallel=2
go test -run '^$' -fuzz '^FuzzSafeReader$' -fuzztime=30s -parallel=2
go test -run '^$' -fuzz '^FuzzPackets$' -fuzztime=30s -parallel=2
go test -run '^$' -fuzz '^FuzzDecodeFrame$' -fuzztime=30s -parallel=2
```

The tests use synthetic PCAP and PcapNG fixtures built in memory and offline
[reference inputs](testdata/foxio/README.md) for fingerprint compatibility.
Separate tests cover byte-order variants, nanosecond timestamps, PcapNG
Decryption Secrets Blocks (`DSB`), Enhanced Packet Block process metadata,
VLAN nesting, IPv4/IPv6 headers, TCP/UDP framing, truncation, arithmetic
overflow, resource limits, and concurrent reads. These tests and bounded fuzz
runs don't establish full format compatibility or prove that all inputs are
safe.

## Measure performance

To collect timing and allocation samples, run the benchmarks:

```sh
go test -run '^$' -bench . -benchmem -count=5
```

Record the Go version, CPU, workload, and raw results. Benchmarks cover
rejecting non-capture input, parsing classic PCAP and PcapNG containers,
enumerating packets, decoding L2–L4 frames without heap allocations, and
aggregating 5-tuple flows.

## Report vulnerabilities

Report suspected vulnerabilities through the [security policy](SECURITY.md).
