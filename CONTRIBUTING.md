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

## Merge a change

Open a pull request against `main` and resolve its review conversations.
After reviewing the current changes, the owner applies the `run-ci` label
to start the six required GitHub-hosted checks on the PR merge candidate:

```sh
gh pr edit NUMBER --add-label run-ci
```

Keep the branch up to date with `main`. After updating it, remove and
reapply the label to test the new revision. Squash-merge after both Go
test jobs, macOS and Windows tests, lint, and the vulnerability check pass.
The sole maintainer can merge their own PR after these checks.

## Validate a change

From the repository root, format the Go files and run the tests and static checks:

```sh
gofmt -w *.go
golangci-lint run ./...
go vet ./...
go test -race -cover ./...
```

For a focused edit, start with the [source and test map](docs/architecture.md#where-to-make-a-change).
For example, after changing a flow field, exercise both reader paths and an
external caller:

```sh
go test -run 'TestReaderAtFlowParity|TestFlowHandshakeTimestamp|ExampleFlowSummary' .
```

The [consumer compatibility suite](testdata/consumer/contract_test.go) is a
separate Go module. From `testdata/consumer`, run the same tests against
the published module and your checkout. For a private clone, configure Go
to access the repository directly with your GitHub credentials
(`GOPRIVATE=github.com/cawalch/go-pcap`).

```sh
GOWORK=off go test -mod=readonly -count=1 ./...
workdir=$(mktemp -d)
(cd "$workdir" && go work init)
export GOWORK="$workdir/go.work"
go work use . ../..
go test -count=1 ./...
```

From `testdata/consumer`, run the DNS consumer benchmark against your
checkout with the workspace created above.

```sh
GOWORK="$workdir/go.work" go test -run '^$' -bench '^BenchmarkClientDNS$' -benchmem -count=10 .
```

The fixtures contain 32 synthetic DNS responses each. One has A and CNAME
records, and the other has HTTPS (type 65) records with placeholder ECH bytes.

When comparing capture-reader changes, use separate Go workspaces for the
baseline and candidate and run the same benchmark and fixtures on native AMD64
and ARM64. Alternate which revision runs first in each pair and check an
unchanged-source control before interpreting the results. On Linux, build with
`go test -c` and overwrite the same executable file between runs to keep the
path and inode fixed. Separate executable files produced different timings in
an unchanged-source control.

CI tests the Go 1.26 compatibility floor and the current stable toolchain.
Use the patched release for each line when reproducing a result. To preview
standard-library and language simplifications, run `go fix -diff ./...` with
the stable toolchain. Review its suggestions against the module’s Go version.
The Linux
jobs cover race detection and 32-bit arithmetic. The stable job discovers
fuzz targets with `go test -list '^Fuzz' .` and runs each for a bounded time.
To exercise the ReaderAt parity target locally:

```sh
go test -run '^$' -fuzz '^FuzzReaderAt$' -fuzztime=30s -parallel=2 .
```

The tests use synthetic PCAP and PcapNG fixtures built in memory and offline
[reference inputs](testdata/foxio/README.md) for fingerprint compatibility.
The [deployment corpus](testdata/deployments/README.md) compares mixed
whole-capture cases against TShark. Separate tests cover byte-order variants,
nanosecond timestamps, PcapNG Decryption Secrets Blocks (`DSB`), Enhanced
Packet Block process metadata,
VLAN nesting, IPv4/IPv6 headers, TCP/UDP framing, truncation, arithmetic
overflow, resource limits, and concurrent reads. These tests and bounded fuzz
runs don't establish full format compatibility or prove that all inputs are
safe.

## Measure performance

To collect timing and allocation samples, run the benchmarks:

```sh
go test -run '^$' -bench . -benchmem -count=5
```

For a flow-accounting change, run the same fixtures on both revisions:

```sh
go test -run '^$' -bench '^BenchmarkFlows$|^BenchmarkReaderAtScan$/./^flows$' -benchmem -count=10 .
```

Record the Go patch version, OS, CPU, and inputs with the samples. The
ReaderAt benchmarks report calls and bytes read alongside time and heap
allocations. Compare repeated samples with `benchstat`. Use a CPU or heap
profile when an end-to-end result changes enough to investigate. Go 1.27
changed how the compiler allocates small objects, so use the same toolchain
on both sides of a source comparison.
[Go 1.27 runtime changes](https://go.dev/doc/go1.27#runtime) ·
[Go diagnostics](https://go.dev/doc/diagnostics) ·
[benchstat](https://pkg.go.dev/golang.org/x/perf/cmd/benchstat)

## Report vulnerabilities

Report suspected vulnerabilities through the [security policy](SECURITY.md).
