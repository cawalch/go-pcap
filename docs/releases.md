# Release an experimental version

This guide describes maintainer actions for `go-pcap`. Subsequent releases are
tracked in the [changelog](../CHANGELOG.md).

## Choose a version

Use semantic versions. The experimental MVP starts at `v0.1.0`. Before `v1.0.0`,
document breaking changes in release notes and increase the minor version for
them. Use patch versions for compatible fixes.

The module path remains `github.com/cawalch/go-pcap` for v0 and v1. Keep
`go 1.26.0` as the minimum Go version until an intentional compatibility change
requires otherwise.

## Prepare and validate a release

1. Review the API, [README](../README.md) example,
   [architecture guide](architecture.md), [parsing guide](parsing.md),
   [security policy](../SECURITY.md), and [MIT license](../LICENSE).
2. Run the full verification, benchmark, and fuzz suite from
   [Contributing](../CONTRIBUTING.md#validate-a-change):
   ```sh
   gofmt -w *.go
   golangci-lint run ./...
   go vet ./...
   go test -race -cover ./...
   ```
3. From a clean checkout of the reviewed commit, create and push an annotated
   tag once ready to publish:
   ```sh
   git tag -a v0.1.0 -m 'Experimental MVP v0.1.0'
   git push origin v0.1.0
   ```
