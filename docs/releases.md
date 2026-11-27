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

1. Confirm that the release issue's blockers have landed. For v0.2.0,
   the release blockers are #260 and #262. Review the release changes
   against v0.1.1.
2. Review the API, [README](../README.md) example,
   [architecture guide](architecture.md), [parsing guide](parsing.md),
   [security policy](../SECURITY.md), and [MIT license](../LICENSE).
3. Run the full verification, benchmark, and fuzz suite from
   [Contributing](../CONTRIBUTING.md#validate-a-change):
   ```sh
   gofmt -w *.go
   golangci-lint run ./...
   go vet ./...
   go test -race -cover ./...
   ```
4. Run the external consumer tests in separate workspaces with v0.1.1 and
   the candidate. Run go-yara's `go test ./compiler -run '^TestPCAP' -count=1`
   with the candidate in its workspace. Confirm the six required hosted checks
   and platform claims against the reviewed merge candidate.
5. From a clean checkout of the reviewed commit, create and push an annotated
   tag. For v0.2.0, run these commands.
   ```sh
   git tag -a v0.2.0 -m 'Experimental go-pcap v0.2.0'
   git push origin refs/tags/v0.2.0
   ```
6. Verify the annotated tag resolves to the reviewed commit. Publish the
   GitHub release using the existing tag and the matching changelog entry.
   Close the release issue once the published tag and release agree.
