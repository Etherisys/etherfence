# Quickstart: Validate Scan Posture Experience

## Prerequisites

- Run from the repository root on `feat/v1.7.0-scan-posture-experience`.
- Use checked-in fixtures only; do not scan a real home directory for feature validation.

## Focused validation

```sh
cargo test -p etherfence-core posture
cargo test -p etherfence-report posture
cargo test -p etherfence-cli --test cli_scan posture
```

Expected: score/grade boundaries, priority ordering, resolved exclusion, renderer content, JSON compatibility, and exit behavior tests pass.

## Human executive scan

```sh
cargo run -- scan --root tests/fixtures/home
```

Expected: the first `Security posture` section includes a score/grade and advisory assessment; `Priority findings` contains no more than three deterministic risk entries with `Why this matters`; `Next steps` has linked recommendation text and the existing verbose/setup guidance. It must state that scan is read-only posture discovery and does not prove security.

## Full evidence and Markdown

```sh
cargo run -- scan --root tests/fixtures/home --verbose
cargo run -- scan --root tests/fixtures/home --format markdown
```

Expected: both contain posture/priority/action content before complete severity-grouped finding evidence. Markdown preserves the existing scope note.

## JSON and SARIF compatibility

```sh
cargo run -- scan --root tests/fixtures/home --format json
cargo run -- scan --root tests/fixtures/home --format sarif
```

Expected JSON: `schema_version` remains `ef-scan-report/v0.1.1`; existing report/finding fields remain present; optional `posture` contains deterministic score, grade, counts, risks, and actions.

Expected SARIF: no posture field is added; existing SARIF rule/result mapping remains unchanged.

## Baseline and exit semantics

```sh
baseline=$(mktemp)
cargo run -- scan --root tests/fixtures/home --write-baseline "$baseline"
cargo run -- scan --root tests/fixtures/safe-home --baseline "$baseline" --format json
cargo run -- scan --root tests/fixtures/home --fail-on high; test $? -eq 2
rm -f "$baseline"
```

Expected: resolved baseline evidence does not affect posture; `--fail-on high` remains exit code 2 with high findings. These commands do not modify policy/proxy behavior.

## Full release gate

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo build --workspace
git diff --check
```

Expected: all commands succeed before the branch is committed and proposed for review.
