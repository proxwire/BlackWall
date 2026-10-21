#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
export BLACKWALL_SKIP_ENV=1
# shellcheck source=../blackwall
source "$repo_root/blackwall"

fail() {
  echo "case-management test failed: $*" >&2
  exit 1
}

test_root=$(mktemp -d)
trap 'rm -rf "$test_root"' EXIT
CASES="$test_root/cases"
mkdir -p "$CASES"
sha=$(printf 'c%.0s' {1..64})
mkdir -p "$CASES/$sha"/{notes,detections,exports}
write_case_json "$sha" local fixture.exe
docker_log="$test_root/docker.log"
mock_running=true

docker() {
  printf '%q ' "$@" >> "$docker_log"
  printf '\n' >> "$docker_log"
  if [ "${1:-}" = inspect ] && [ "${2:-}" = -f ]; then
    printf '%s\n' "$mock_running"
    return 0
  fi
  if [ "${1:-}" = inspect ]; then
    return 1
  fi
  if [ "${1:-}" = image ] || [ "${1:-} ${2:-}" = "volume inspect" ]; then
    return 0
  fi
  if [ "${1:-}" = stats ]; then
    printf '%s\n' '{"CPUPerc":"1.0%","MemUsage":"2MiB / 8GiB","PIDs":"3"}'
    return 0
  fi
  if [ "${1:-}" = run ]; then
    printf '%s\n' '{"schema":"blackwall.case-status.v1","counts":{"evidence_records":1,"derived_artifacts":2,"claims":3},"progress":{"finished_steps":4,"total_steps":5,"percent":80.0},"checkpoints":[]}'
    return 0
  fi
  return 0
}

cmd_cancel "$sha"
jq -e '.last_lifecycle_event.event == "cancelled"' "$CASES/$sha/case.json" >/dev/null \
  || fail "cancel did not record lifecycle metadata"
grep -q "stop bw-${sha:0:12}" "$docker_log" \
  || fail "cancel did not stop the expected case container"

captured=()
cmd_analyze() { captured=("$@"); }
cmd_resume "${sha:0:12}" --profile strict
[ "${captured[*]}" = "${sha:0:12} --auto --profile strict" ] \
  || fail "resume did not preserve options and force automatic checkpoint use"

mock_running=false
status=$(cmd_status "${sha:0:12}")
grep -q 'progress: 4/5 steps (80.0%)' <<<"$status" \
  || fail "status did not render checkpoint progress"

cmd_clean "${sha:0:12}" --scratch >/dev/null
grep -q 'cleanup /work --scratch' "$docker_log" \
  || fail "safe cleanup did not use the scratch-only worker operation"
if (cmd_clean "${sha:0:12}" >/dev/null 2>&1); then
  fail "cleanup did not require the explicit --scratch scope"
fi

echo "case-management shell tests passed"
