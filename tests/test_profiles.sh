#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=../blackwall
source "$repo_root/blackwall"

fail() {
  echo "profile test failed: $*" >&2
  exit 1
}

[ "$DEFAULT_ANALYSIS_PROFILE" = strict ] || fail "strict is not the CLI default"

strict=$(make_mcp_config "$(printf '0%.0s' {1..64})" 0 strict)
jq -e '
  (.mcpServers | keys) == ["ghidra", "intel", "lab"]
  and .mcpServers.lab.args[-2:] == ["--profile", "strict"]
  and (.mcpServers | has("radare2") | not)
' <<<"$strict" >/dev/null || fail "strict MCP config exposes an expert server"

expert=$(make_mcp_config "$(printf '1%.0s' {1..64})" 1 expert)
jq -e '
  (.mcpServers | keys) == ["ghidra", "intel", "lab", "radare2"]
  and .mcpServers.lab.args[-2:] == ["--profile", "expert"]
  and .mcpServers.ghidra.args[-1] == "--gui"
' <<<"$expert" >/dev/null || fail "expert MCP config is incomplete"

if (validate_profile_name permissive >/dev/null 2>&1); then
  fail "an unknown profile did not fail closed"
fi
analyst_policy_valid || fail "host process and web tools are not denied"

test_root=$(mktemp -d)
trap 'rm -rf "$test_root"' EXIT
CASES="$test_root/cases"
sha=$(printf 'a%.0s' {1..64})
mkdir -p "$CASES/$sha"
write_case_json "$sha" local fixture.exe
jq -e '.analysis_profile == {name:"strict", selected_at:null}' \
  "$CASES/$sha/case.json" >/dev/null || fail "new case is not strict by default"

record_case_profile "$sha" expert
jq -e '
  .analysis_profile.name == "expert"
  and (.analysis_profile.selected_at | type) == "string"
  and .analysis_profile_history[-1].name == "expert"
' "$CASES/$sha/case.json" >/dev/null || fail "expert profile was not recorded"

printf '# Fixture report\n' > "$CASES/$sha/report.md"
stamp_report_profile "$sha" expert
record_case_profile "$sha" strict
stamp_report_profile "$sha" strict
[ "$(grep -c '^<!-- blackwall-analysis-profile -->$' "$CASES/$sha/report.md")" -eq 1 ] \
  || fail "report profile marker is not idempotent"
grep -q "BlackWall analysis profile: \`strict\`" "$CASES/$sha/report.md" \
  || fail "report does not record the selected profile"

echo "profile tests passed"
