# Release an experimental version

## Choose a version

Use a minor release for breaking changes during v0.x and a patch release
for compatible fixes. Record user-visible changes in the
[changelog](../CHANGELOG.md). Keep the current module path and Go floor
unless the release intentionally changes compatibility.

## Prepare and validate a release

1. Confirm the release blockers landed. Review compatibility and examples.
2. Run [preflight and consumer verification](../CONTRIBUTING.md#validate-a-batch-of-reviewed-changes)
   against the prior release and candidate. Verify the go-yara integration
   with `go test ./compiler -run '^TestPCAP' -count=1` in its candidate
   workspace. Check hosted results and platform claims for the reviewed tree.
3. Create and push an annotated tag from the reviewed, clean commit.
   Confirm the remote tag resolves to that commit.
4. Publish the GitHub release from the existing tag and matching changelog
   entry. Close the release issue after verifying the published release.
