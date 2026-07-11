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

# ── scan ──────────────────────────────────────────────────────────────
scan_output="$(PATH="$fake_bin:$PATH" "$etherfence" scan --root demo/workspace)"
assert_contains "$scan_output" "EtherFence scan report"
assert_contains "$scan_output" "Scanned root: demo/workspace"
assert_contains "$scan_output" "Claude Code"
assert_contains "$scan_output" "filesystem-server"
assert_contains "$scan_output" "EF-MCP-001 Broad filesystem access hint"
assert_contains "$scan_output" "EF-MCP-000 MCP server configured"
assert_not_contains "$scan_output" "DEMO_TOKEN"

if [[ -s "$ETHERFENCE_DEMO_EXEC_LOG" ]]; then
  echo "configured package runner was executed unexpectedly during scan:" >&2
  cat "$ETHERFENCE_DEMO_EXEC_LOG" >&2
  exit 1
fi

# ── setup detect ──────────────────────────────────────────────────────
setup_output="$(PATH="$fake_bin:$PATH" "$etherfence" setup detect --root demo/workspace)"
assert_contains "$setup_output" "EtherFence setup detect"
assert_contains "$setup_output" "Root: demo/workspace"
assert_contains "$setup_output" "Claude Code [write-supported]"
assert_contains "$setup_output" "filesystem-server transport=stdio wrapped=false"
assert_contains "$setup_output" "capabilities: filesystem"
assert_contains "$setup_output" "recommendation: deny (needs-review=false)"
assert_contains "$setup_output" "trust: artifact-identity=known-source configuration-risk=needs-review aggregate=needs-review needs-review=true"
assert_contains "$setup_output" "EF-TRUST-PIN-001 [medium] package-pinning: Package version is omitted"
assert_not_contains "$setup_output" "DEMO_TOKEN"
# No synthetic secret-looking env var in fixture
assert_not_contains "$setup_output" "secret-like"

if [[ -s "$ETHERFENCE_DEMO_EXEC_LOG" ]]; then
  echo "configured package runner was executed unexpectedly:" >&2
  cat "$ETHERFENCE_DEMO_EXEC_LOG" >&2
  exit 1
fi

# ── policy validate ───────────────────────────────────────────────────
validate_output="$($etherfence mcp-policy validate demo/workspace/project-readonly.toml)"
assert_contains "$validate_output" "OK:"
assert_contains "$validate_output" 'name="project-readonly"'
assert_contains "$validate_output" 'schema_version="ef-mcp-policy/v0.1"'

# ── policy check ──────────────────────────────────────────────────────
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

# ── splash check: tagline is present in --help output ─────────────────
splash_output="$("$etherfence" --help 2>&1)"
assert_contains "$splash_output" "AI Agent Security Posture"
assert_contains "$splash_output" "Runtime Control"

printf '%s\n' "demo verification passed"
