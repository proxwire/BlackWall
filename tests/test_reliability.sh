#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=../blackwall
source "$repo_root/blackwall"

fail() {
  echo "reliability test failed: $*" >&2
  exit 1
}

fixture_root=$(mktemp -d)
trap 'rm -rf "$fixture_root"' EXIT
CASES="$fixture_root/cases"
# Consumed by the sourced BlackWall functions.
# shellcheck disable=SC2034
IMAGE=blackwall:test
sha=$(printf 'b%.0s' {1..64})
container=$(cname "$sha")
volume=$(vname "$sha")
mkdir -p "$CASES/$sha" "$fixture_root/retained/state/evidence"
touch "$CASES/$sha/sample.zip"
printf 'retained\n' > "$fixture_root/retained/state/evidence/sentinel"

fake_exists="$fixture_root/container-exists"
fake_log="$fixture_root/docker.log"
touch "$fake_exists" "$fake_log"

docker() {
  printf '%q ' "$@" >> "$fake_log"
  printf '\n' >> "$fake_log"
  case "${1:-} ${2:-}" in
    "image inspect")
      if [ "${3:-}" = "-f" ]; then
        echo "sha256:new"
      fi
      return 0
      ;;
    "inspect -f")
      [ -f "$fake_exists" ] || return 1
      case "${3:-}" in
        *State.Running*) echo true ;;
        *".Image"*) echo "sha256:old" ;;
        *blackwall.case*) echo "$sha" ;;
        *blackwall.volume*) echo "$volume" ;;
        *blackwall.sandbox-spec*) echo "$SANDBOX_SPEC" ;;
        *Mounts*) echo "$volume" ;;
        *) echo "" ;;
      esac
      return 0
      ;;
    "inspect $container")
      [ -f "$fake_exists" ]
      ;;
    "rm -f")
      [ "${3:-}" = "$container" ] || fail "removed the wrong container"
      rm -f "$fake_exists"
      ;;
    "run -d")
      touch "$fake_exists"
      ;;
    "exec $container")
      return 0
      ;;
    "volume inspect")
      [ "${3:-}" = "$volume" ] || fail "inspected the wrong volume"
      return 0
      ;;
    *)
      fail "unexpected docker invocation: $*"
      ;;
  esac
}

start_sandbox "$sha" 0

grep -q "rm -f $container" "$fake_log" \
  || fail "stale container was not recreated"
grep -q -- "-v $volume:/work" "$fake_log" \
  || fail "recreated container did not reuse retained volume"
grep -q -- "--label blackwall.sandbox-spec=$SANDBOX_SPEC" "$fake_log" \
  || fail "recreated container lacks the sandbox spec label"
if grep -q "volume rm" "$fake_log"; then
  fail "stale recreation attempted to delete the evidence volume"
fi
grep -q '^retained$' "$fixture_root/retained/state/evidence/sentinel" \
  || fail "retained evidence sentinel changed"

: > "$fake_log"
cmd_diagnose "$sha" >/dev/null
if grep -Eq '(^| )rm( |$)|volume rm|run -d' "$fake_log"; then
  fail "diagnostic performed a destructive lifecycle operation"
fi

echo "reliability shell tests passed"
