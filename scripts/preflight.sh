#!/usr/bin/env bash
set -euo pipefail

# Preflight runs only maintainer-reviewed code on these hosts.
if [[ ${1:-} == --check && $# == 2 ]]; then
  platform=$2
  export GOWORK=off
  go version
  test -z "$(gofmt -l .)"
  go vet ./...
  go test -race -cover ./...
  if [[ "$platform" == linux ]]; then
    GOARCH=386 go test ./...
  elif [[ "$platform" == local ]]; then
    golangci-lint run ./...
  else
    exit 2
  fi

  workspace=$(mktemp -d)
  trap 'rm -rf "$workspace"' EXIT
  root=$PWD
  (cd "$workspace" && go work init)
  cd testdata/consumer
  export GOWORK="$workspace/go.work"
  go work use . "$root"
  go test -count=1 ./...
  exit
fi

if [[ $# != 2 || ! "$2" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.@-]*$ ]]; then
  echo "Usage: $0 <reviewed Git ref> <Linux SSH host>" >&2
  exit 2
fi

commit=$(git rev-parse --verify --end-of-options "$1^{commit}")
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
git archive "$commit" > "$scratch/source.tar"
tar -xf "$scratch/source.tar" -C "$scratch"
printf 'Testing %s on %s and %s\n' "$commit" "$(uname -sm)" "$2"

ssh -o BatchMode=yes -o ConnectTimeout=10 "$2" 'bash -c '\''
  set -euo pipefail
  scratch=$(mktemp -d)
  trap "rm -rf \"\$scratch\"" EXIT
  tar -xf - -C "$scratch"
  cd "$scratch"
  bash scripts/preflight.sh --check linux
'\''' < "$scratch/source.tar" > "$scratch/linux.log" 2>&1 &
remote_pid=$!

local_status=0
(cd "$scratch" && bash scripts/preflight.sh --check local) > "$scratch/local.log" 2>&1 || local_status=$?
remote_status=0
wait "$remote_pid" || remote_status=$?
printf '\nLocal tests (exit %s)\n' "$local_status"
cat "$scratch/local.log"
printf '\nLinux tests (exit %s)\n' "$remote_status"
cat "$scratch/linux.log"
(( local_status == 0 && remote_status == 0 ))
