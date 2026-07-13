# Quickstart: Validating Posture Score Risk Separation

## Prerequisites

- Rust toolchain matching the workspace (`cargo build` succeeds on `main` before starting).
- Repository checked out on `feature/v1.7.4-posture-risk-separation`.

## 1. Build

```sh
cargo build
```

## 2. Zero-risk inventory does not lower the score

Run against the existing zero-findings/minimal fixture (or a fixture with only clean MCP servers plus ordinary env vars):

```sh
cargo run -- scan --root tests/fixtures/<clean-fixture> --format json | jq '.posture.score, .posture.grade'
```

Expected: `100` and `"a"`, regardless of how many MCP servers are configured, as long as none match a risk heuristic and no environment variable name looks secret-shaped.

## 3. Secret-specific finding still scores

```sh
cargo run -- scan --root tests/fixtures/home --format json | jq '.findings[] | select(.id=="EF-SEC-001") | {id, severity, category}'
```

Expected: `severity: "medium"`, `category: "risk"`, and the overall `posture.score` reduced by 10 relative to a variant fixture with that finding removed.

## 4. Inventory findings no longer score

```sh
cargo run -- scan --root tests/fixtures/home --format json | jq '.findings[] | select(.id=="EF-MCP-000" or .id=="EF-MCP-004") | {id, severity, category}'
```

Expected: `severity: "info"`, `category: "inventory"` for both IDs.

## 5. Evidence names the matched field

```sh
cargo run -- scan --root tests/fixtures/home --format json | jq '.findings[] | select(.id=="EF-MCP-001") | .evidence'
```

Expected: entries of the form `"server=..."`, `"command=..."`, `"args[N]=..."`, or `"url=..."` — never a bare unlabeled value.

## 6. No secret values in any output format

Run against whatever literal secret placeholder value the fixture's existing redaction tests already assert is absent (e.g. the fixture's raw env var value before redaction):

```sh
for fmt in human markdown sarif json; do
  cargo run -- scan --root tests/fixtures/home --format "$fmt" > /tmp/out.$fmt
done
cargo run -- scan --root tests/fixtures/home --verbose > /tmp/out.verbose
grep -R "secret-value-marker-from-fixture" /tmp/out.* # expect no matches
```

## 7. Human output shows four distinct sections

```sh
cargo run -- scan --root tests/fixtures/home
cargo run -- scan --root tests/fixtures/home --verbose
```

Expected (default): "Inventory observations" and "Informational findings" headings appear between "Clients" and "Protection coverage"/"Priority findings".
Expected (verbose): per-finding badges include `OBS` for inventory findings alongside the existing `HIGH`/`MEDIUM`/`LOW`/`INFO` badges; "Consolidated recommended actions" contains no `EF-MCP-000`/`EF-MCP-004`/`EF-TIRITH-*` entries.

## 8. Baseline schema fails closed on old files

```sh
cargo run -- scan --root tests/fixtures/home --baseline docs/examples/ci/baseline.json
```

Expected (before `docs/examples/ci/baseline.json` is regenerated in this feature): a hard error naming the unsupported `schema_version` and instructing `--write-baseline` regeneration. After regeneration (task-phase work), the same command succeeds and reports `resolved`/`existing`/`new` counts normally.

## 9. Full gate

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo build
git diff --check
```

All must pass with zero regressions in unrelated fixtures/tests.
