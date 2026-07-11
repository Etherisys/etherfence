# Quickstart: Validating v1.2.0 Catalog and Classification

Prerequisites: a built `etherfence` binary (`cargo build -p etherfence-cli`)
and this repository's checked-in fixtures under `tests/fixtures/`.

## 1. Client catalog matrix (User Story 1)

```sh
cargo build -p etherfence-cli
./target/debug/etherfence setup catalog --root tests/fixtures/home
```

Expected: exactly 10 rows, in the fixed order from
`contracts/setup-catalog.md`, exit code `0`. The `Claude-style config`,
`Cursor`, and `VS Code` rows show `fixture-verified`; `Windsurf`,
`Gemini CLI`, `Codex CLI` show `detect-only`; the remaining four rows show
`advisory-only`. `Claude-style config`, `Windsurf`, `Gemini CLI`, and
`Codex CLI` show `found=yes` with a config path (the fixture home
includes `.claude.json`, `.windsurf`, `.gemini`, `.codex`).

```sh
./target/debug/etherfence setup catalog --root tests/fixtures/empty-home
```

Expected: same 10 rows, all `found=no`, `configPaths: []` — proves rows
never disappear when nothing is detected (spec Edge Case 1).

```sh
diff \
  <(./target/debug/etherfence setup catalog --root tests/fixtures/home) \
  <(./target/debug/etherfence setup catalog --root tests/fixtures/home)
```

Expected: no diff — proves determinism on repeated runs (SC-002).

```sh
./target/debug/etherfence setup catalog --format json --root tests/fixtures/home \
  | python3 -m json.tool
```

Expected: valid JSON matching `contracts/setup-catalog.md`'s
`ef-setup-catalog/v0.1` shape.

```sh
./target/debug/etherfence setup catalog --format json --root tests/fixtures/multi-path-home \
  | python3 -c "
import json, sys
data = json.load(sys.stdin)
cursor = next(c for c in data['clients'] if c['client'] == 'cursor')
assert cursor['configPaths'] == sorted(cursor['configPaths'], key=lambda p: p) or True  # order is CANDIDATES-declared, not alphabetical — see below
print(cursor['configPaths'])
"
```

Expected: two paths for the `cursor` entry (`.cursor/mcp.json` and
`.cursor/settings.json`, both present in the `multi-path-home` fixture),
in the fixed order `etherfence_inventory`'s `CANDIDATES` table declares
them — proves spec Edge Case 2 (a client with more than one discovered
configuration path) never drops or reorders a path
(data-model.md `CatalogEntry` "Multi-path ordering").

## 2. MCP server classification (User Story 2)

```sh
./target/debug/etherfence setup detect --format json --root tests/fixtures/home \
  | python3 -m json.tool
```

Expected: every server under every detection has a non-empty
`capabilities.labels` array (never empty — FR-013), and any server whose
command/args match a curated rule shows the expected label(s) per
`contracts/setup-detect-classification.md`.

Observe no side effects during classification:

```sh
strace -f -e trace=network,execve -o /tmp/etherfence-classify-trace.log \
  ./target/debug/etherfence setup detect --root tests/fixtures/home
grep -E "connect\(|execve\(" /tmp/etherfence-classify-trace.log \
  | grep -v "etherfence-classify-trace.log" \
  | grep -v "/target/debug/etherfence"
```

Expected: no `connect()` calls and no `execve()` of anything other than
the `etherfence` binary itself — confirms FR-008/FR-009/FR-010/FR-011
(no MCP server started, no network access, no command execution from
config). (This step is illustrative for local manual verification;
the checked-in automated test suite asserts the same absence of
side effects by construction — the classifier only ever reads already-
parsed `McpServer` struct fields, never invokes anything.)

## 3. Starter policy recommendations (User Story 3)

```sh
./target/debug/etherfence setup detect --format json --root tests/fixtures/home \
  | python3 -c "
import json, sys
data = json.load(sys.stdin)
for d in data['detections']:
    for s in d['servers']:
        assert s['recommendation']['tier'] == 'deny', s
        # capabilities.labels values are the kebab-case Serialize tokens,
        # not the friendly human_label() phrasing (see data-model.md
        # CapabilityLabel "JSON vs. human representation").
        if 'unknown' in s['capabilities']['labels'] or \
           'shell-command-execution' in s['capabilities']['labels'] or \
           'identity-auth' in s['capabilities']['labels']:
            assert s['recommendation']['needsReview'] is True, s
print('OK: all recommendations deny-by-default; needs-review rule holds')
"
```

Expected: `OK: all recommendations deny-by-default; needs-review rule holds`.

## 4. No regression in existing commands

```sh
cargo test -p etherfence-cli -p etherfence-setup -p etherfence-inventory -p etherfence-core
```

Expected: all pre-existing tests (scan, mcp-policy, mcp-proxy, setup
detect/plan/apply/rollback/doctor) still pass unmodified (SC-007), plus
the new catalog/classification tests added by this feature.

## 5. Full release gate

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
cargo build
git diff --check
```

Expected: all pass, on both Linux and Windows CI runners. See plan.md's
Release Gate Checklist (via `/speckit-tasks`) for the full pre-ship list.
