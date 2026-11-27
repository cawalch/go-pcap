#!/usr/bin/env bash
set -euo pipefail

jobs=${1:-2}
if [[ ! "$jobs" =~ ^[1-9][0-9]*$ ]]; then
  echo "Usage: $0 [concurrent targets]" >&2
  exit 2
fi

# Use the same target discovery and per-target limits on every runner.
targets=$(go test -list '^Fuzz' . | sed -n '/^Fuzz[[:alnum:]_]*$/p')
test -n "$targets"
logs=$(mktemp -d)
trap 'rm -rf "$logs"' EXIT

# Keep each target's output together while the tests run independently.
status=0
# The positional parameters expand in each child Bash process.
# shellcheck disable=SC2016
printf '%s\n' "$targets" | xargs -P "$jobs" -I '{}' bash -c '
  go test -run "^$" -fuzz "^${2}$" -fuzztime=10s -parallel=2 . > "$1/$2.log" 2>&1
' _ "$logs" '{}' || status=$?

for target in $targets; do
  printf '\n%s\n' "$target"
  cat "$logs/$target.log"
done
exit "$status"
