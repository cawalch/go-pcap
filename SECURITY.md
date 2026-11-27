# Security policy

## Report a vulnerability

Email [Caleb Walch](mailto:cawalch@pm.me) privately. Include the affected
revision, Go version, and a small synthetic reproduction. Keep credentials,
malware, and confidential captures out of reports. Coordinate disclosure
before posting details in a public issue or pull request.

## Supported versions and limits

Fixes target the latest development revision and subsequent releases.
Use a patched Go toolchain. Treat captures as untrusted input and bound
application resources. `Open` reads the whole file.
[Parser limits](docs/parsing.md#work-and-output-limits)

## Starting CI

The owner reviews a PR candidate and applies `run-ci` to start GitHub-hosted
checks. For the default branch, run `gh workflow run ci.yml --ref main`.
The workflow verifies the owner and the actor starting or rerunning the job.
Fork workflows require approval. Keep private-network runners unregistered.
