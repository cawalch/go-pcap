# Contributing to go-pcap

## Scope a change

Keep changes focused on capture I/O and bounded protocol evidence. Before
adding a dissector or analyzer, check existing Go implementations for
coverage, bounded work, performance, dependencies, and licensing.
[Architecture and source map](docs/architecture.md)

## Write documentation

Use [Go doc conventions](https://go.dev/doc/comment) for API contracts and
[Google's documentation style](https://developers.google.com/style/) for
guides. Start exported comments with the identifier. Document ownership,
units, limits, and partial results where they affect callers. Prefer runnable
Go examples. Use sentence-case headings, direct instructions, and descriptive
links. Keep signatures and field definitions in the API reference. Follow the
[Google Go style guide](https://google.github.io/styleguide/go/guide) for code
readability and use `gofmt` for formatting.

## Write the change description

Start with the verified change direction and affected files or symbols. Give
the verification commands, observed results, scope, and one line requesting
specific feedback. Verify each evidence link and quote a short excerpt beside
it. Pin source links to a commit and check that their lines support the claim.
For assisted changes, disclose the tool, model, settings, and extent.

## Merge a change

Open a pull request against `main` and resolve review conversations. After
reviewing the merge candidate, the owner applies the `run-ci` label. When the
candidate changes, remove and reapply the label. Squash-merge after all six
required checks pass. [CI policy](SECURITY.md#starting-ci)

## Validate a batch of reviewed changes

Review focused commits before combining them on the current `main`. Run
the same committed candidate on the local stable Go toolchain and a Linux
AMD64 host at the compatibility floor.

```sh
bash scripts/preflight.sh HEAD linux-test-host
```

Use reviewed refs on personal or shared machines. Preflight covers format,
vet, race tests, local lint, the external consumer, and Linux 386. GitHub CI
also covers native platform tests, privileged Linux loopback, vulnerability
analysis, and timed fuzzing.

## Validate a change

Run the following commands from the repository root.

```sh
gofmt -w *.go
golangci-lint run ./...
go vet ./...
go test -race ./...
```

Exercise both byte-slice and ReaderAt paths for capture changes. Run the
[consumer contract](testdata/consumer/contract_test.go) against the tagged
dependency and the checkout. Run the following commands from `testdata/consumer`.

```sh
GOWORK=off go test -mod=readonly -count=1 ./...
workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT
(cd "$workdir" && go work init)
export GOWORK="$workdir/go.work"
go work use . ../..
go test -count=1 ./...
```

CI tests the Go 1.26 floor and stable Go. Use patched toolchains and
review `go fix -diff ./...` suggestions against the module's minimum version.
Run all timed targets with `bash scripts/test-fuzz.sh`.

## Measure performance

Run the relevant benchmarks on both revisions with the same Go patch
version, CPU, and inputs. Record time, allocations, and ReaderAt calls
and bytes where applicable. Use repeated, alternating samples and an
unchanged-source control for small changes. For Linux controls sensitive
to executable layout, rebuild at the same path and preserve the inode.

```sh
go test -run '^$' -bench '^BenchmarkFlows$|^BenchmarkReaderAtScan$/./^flows$' -benchmem -count=10 .
```

Use [benchstat](https://pkg.go.dev/golang.org/x/perf/cmd/benchstat) to compare
samples. For changes to DNS scan cost, run `BenchmarkClientDNS` in the
external consumer on native ARM64 and AMD64.

## Report vulnerabilities

Follow the [security policy](SECURITY.md).
