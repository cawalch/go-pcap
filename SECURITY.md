# Security policy

## Report a vulnerability

Email [Caleb Walch](mailto:cawalch@pm.me) privately with suspected security
issues. Include the affected commit or version, Go version, reproduction steps,
and expected and actual behavior. Prefer a small synthetic reproducer; do not
send malware samples, credentials, or confidential packet captures.

Do not disclose exploit details in public issues or pull requests before
coordinating a fix. There is no guaranteed response time.

## Supported versions and limits

The project is experimental; fixes target the latest development revision and
are published in subsequent releases. Older versions have no maintained security
branch. Use a supported Go toolchain with current security patches, including
for this standard-library-only module.

Treat packet captures and network frames as untrusted input. Bound file sizes
and application resource use; `Open` reads the entire file. Parser limits and
tests do not guarantee that every input is safe. See the
[parsing guide](docs/parsing.md) for work and output limits.

## Starting CI

The repository owner starts CI explicitly on GitHub-hosted runners. To test
the default branch, run `gh workflow run ci.yml --ref main`. To test a
reviewed branch in this repository, substitute its branch name. Each job
checks the owner's numeric account ID and the account requesting the run or
rerun before GitHub allocates a runner. For required PR checks, review the
changes (including the workflow) and apply the `run-ci` label. Opening a PR
or pushing commits does not start runners. Dependency update jobs are
unscheduled. The manual CI run includes the vulnerability check.

GitHub also requires approval for workflows from all external fork
contributors. Keep private-network runners unregistered from this repository.
