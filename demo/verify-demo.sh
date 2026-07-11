#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo build --release -p etherfence-cli --bin etherfence >/dev/null
etherfence="$repo_root/target/release/etherfence"

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

fake_bin="$tmp_dir/bin"
mkdir -p "$fake_bin"
for runner in npx uvx pipx; do
  cat > "$fake_bin/$runner" <<'SH'
#!/usr/bin/env bash
echo "$0 $*" >> "${ETHERFENCE_DEMO_EXEC_LOG:?}"
exit 99
SH
  chmod +x "$fake_bin/$runner"
done
export ETHERFENCE_DEMO_EXEC_LOG="$tmp_dir/executed.log"
: > "$ETHERFENCE_DEMO_EXEC_LOG"

assert_contains() {
  local haystack="$1"
  local needle="$2"
  if [[ "$haystack" != *"$needle"* ]]; then
    echo "missing expected text: $needle" >&2
    exit 1
  fi
}

assert_not_contains() {
  local haystack="$1"
  local needle="$2"
  if [[ "$haystack" == *"$needle"* ]]; then
    echo "unexpected text present: $needle" >&2
    exit 1
  fi
}

setup_output="$(PATH="$fake_bin:$PATH" "$etherfence" setup detect --root demo/workspace)"
assert_contains "$setup_output" "EtherFence setup detect"
assert_contains "$setup_output" "Root: demo/workspace"
assert_contains "$setup_output" "Claude Code [write-supported]"
assert_contains "$setup_output" "filesystem-server transport=stdio wrapped=false"
assert_contains "$setup_output" "capabilities: filesystem"
assert_contains "$setup_output" "recommendation: deny (needs-review=false)"
assert_contains "$setup_output" "trust: artifact-identity=known-source configuration-risk=needs-review aggregate=needs-review needs-review=true"
assert_contains "$setup_output" "EF-TRUST-PIN-001 [medium] package-pinning: Package version is omitted"
assert_contains "$setup_output" "EF-TRUST-ENV-005 [medium] environment-variable: Environment variable name looks secret-like"
assert_not_contains "$setup_output" "fixture-only"
assert_not_contains "$setup_output" "DEMO_TOKEN"

if [[ -s "$ETHERFENCE_DEMO_EXEC_LOG" ]]; then
  echo "configured package runner was executed unexpectedly:" >&2
  cat "$ETHERFENCE_DEMO_EXEC_LOG" >&2
  exit 1
fi

validate_output="$($etherfence mcp-policy validate demo/workspace/project-readonly.toml)"
assert_contains "$validate_output" "OK:"
assert_contains "$validate_output" "name=\"project-readonly\""
assert_contains "$validate_output" "schema_version=\"ef-mcp-policy/v0.1\""

set +e
policy_output="$($etherfence mcp-policy check --policy demo/workspace/project-readonly.toml --request demo/workspace/request.json)"
policy_status=$?
set -e
if [[ "$policy_status" -ne 0 ]]; then
  echo "mcp-policy check returned unexpected exit code $policy_status" >&2
  echo "$policy_output" >&2
  exit 1
fi
assert_contains "$policy_output" "Decision: DENY"
assert_contains "$policy_output" "Would be forwarded: no"
assert_contains "$policy_output" "Inspected by policy: yes"
assert_contains "$policy_output" "Category: tool_call_decision"
assert_contains "$policy_output" "Method: tools/call"
assert_contains "$policy_output" "Tool: filesystem.write"
assert_contains "$policy_output" "Reason: tool name is in the global policy deny list"
assert_contains "$policy_output" "No MCP server was started or contacted and no tool was executed."

if [[ -s "$ETHERFENCE_DEMO_EXEC_LOG" ]]; then
  echo "configured package runner was executed unexpectedly after policy check:" >&2
  cat "$ETHERFENCE_DEMO_EXEC_LOG" >&2
  exit 1
fi

printf '%s\n' "demo verification passed"
