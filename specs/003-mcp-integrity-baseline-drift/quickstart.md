# Quickstart: MCP Server Integrity Baseline and Drift Detection

Validates the feature end-to-end against a local debug build. Uses a
throwaway fixture-style home directory; substitute any real root you have
read access to.

## Prerequisites

```bash
cargo build -p etherfence-cli
BIN=./target/debug/etherfence
ROOT=/tmp/ef-quickstart-home   # any generic placeholder root
mkdir -p "$ROOT/.claude"
cat > "$ROOT/.claude.json" <<'EOF'
{"mcpServers":{"filesystem":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/tmp"]}}}
EOF
```

## 1. Write a baseline

```bash
$BIN setup baseline write --root "$ROOT" --output /tmp/ef-baseline.json
cat /tmp/ef-baseline.json | jq '.schemaVersion, (.servers | length)'
```

Expected: `"ef-setup-baseline/v0.1"`, `1`.

## 2. Refuse overwrite without `--overwrite`

```bash
$BIN setup baseline write --root "$ROOT" --output /tmp/ef-baseline.json; echo "exit=$?"
```

Expected: non-zero exit, file unchanged (confirm via `sha256sum
/tmp/ef-baseline.json` before/after).

## 3. Check with no changes

```bash
$BIN setup baseline check --root "$ROOT" --baseline /tmp/ef-baseline.json --format json | jq '.entries[0].status'
```

Expected: `"unchanged"`.

## 4. Introduce drift and re-check

```bash
sed -i 's#/tmp#/var/tmp#' "$ROOT/.claude.json"
$BIN setup baseline check --root "$ROOT" --baseline /tmp/ef-baseline.json --format json \
  | jq '.entries[0].status, .entries[0].reasons'
```

Expected: `"changed"`, `["arguments-changed"]`.

## 5. Gate behavior

```bash
$BIN setup baseline check --root "$ROOT" --baseline /tmp/ef-baseline.json --fail-on-drift; echo "exit=$?"
$BIN setup baseline check --root "$ROOT" --baseline /tmp/ef-baseline.json --fail-on-new; echo "exit=$?"
```

Expected: first exits non-zero (drift present) while still printing the
full report above the exit line; second exits zero (no `new` servers).

## 6. Confirm the baseline file itself never changed

```bash
sha256sum /tmp/ef-baseline.json   # unchanged across every command above
```

## 7. Confirm no secret-bearing content leaks

```bash
EF_SECRET_TOKEN=super-secret-value $BIN setup detect --root "$ROOT" --format json | grep -c super-secret-value
```

Expected: `0` (no baseline/check output path ever emits an environment
variable value).

## Cross-references

- CLI surface and schemas: [contracts/setup-baseline.md](./contracts/setup-baseline.md)
- Field-level model: [data-model.md](./data-model.md)
- Design rationale: [research.md](./research.md)
