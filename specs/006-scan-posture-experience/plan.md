# Implementation Plan: Scan Posture Experience

**Branch**: `feat/v1.7.0-scan-posture-experience` | **Date**: 2026-07-12 | **Spec**: [spec.md](./spec.md)

## Summary

Deliver a deterministic executive posture layer for `etherfence scan`. It derives a score, grade, assessment, three priority risks, and three linked next actions from the report's already displayed active findings. The feature reuses the existing terminal theme and report structure, improves verbose and Markdown presentation, and adds an optional JSON `posture` object while preserving the `ef-scan-report/v0.1.1` identifier, all existing fields, detector behavior, baseline semantics, and exit decisions.

## Technical Context

**Language/Version**: Rust 2021 workspace, current stable toolchain

**Primary Dependencies**: Existing `serde`/`serde_json`, `console` styles through `dialoguer`, and internal EtherFence crates only; no new dependencies

**Storage**: No new storage; posture is derived in memory from the displayed report findings

**Testing**: Core unit tests, report-rendering unit tests, fixture-backed CLI integration tests, existing documentation/example validation, full workspace gate

**Target Platform**: Linux and Windows CLI; human output must retain current color and plain-text fallback behavior

**Project Type**: Local-first Rust CLI workspace

**Performance Goals**: Single linear scan of displayed findings plus bounded selection/sort of priority candidates; no filesystem reads, process launches, network calls, or detector work added

**Constraints**: No new detector, finding ID, severity variant, policy/proxy behavior, exit-code change, schema-version change, or breaking report field change. Score derives after existing baseline comparison and severity filtering; resolved findings are excluded from posture even though they remain report evidence.

**Scale/Scope**: One additive report-model subtree, existing renderer/CLI surfaces, focused tests, documentation, examples, changelog, and version bump to 1.7.0.

## Constitution Check

| Principle | Evidence / decision | Status |
|---|---|---|
| I. Security-First, Deny-by-Default | No enforcement path, policy decision, or default access behavior changes; executive text stays advisory. | PASS |
| II. Local-First Operation | Posture derives locally from an in-memory report; no service, network, hook, or daemon. | PASS |
| III. Truth in Claims | Human/Markdown/docs retain read-only, advisory, non-remediation, non-proof language; score is a prioritization aid, not a certification. | PASS |
| IV. Deterministic Output | Fixed deduction schedule, fixed grade ranges, explicit stable priority tuple, no timestamps/randomness. | PASS |
| V. Fixture-Backed Findings and Classifications | No detector/classification additions; new derived posture behavior has unit and fixture-backed CLI tests. | PASS |
| VI. Schema Compatibility and Explicit Versioning | `posture` is optional and additive on the existing scan report; existing schema identifier and fields remain unchanged; docs describe compatibility. | PASS |
| VII. Fail-Closed Runtime Proxy Behavior | `mcp-proxy` and policy evaluators are untouched. | PASS |
| VIII. Audit Log Safety | No audit fields or persisted sensitive data; posture copies only existing safe finding metadata. | PASS |
| IX. Complete Release Packaging | Version, CHANGELOG, README, install docs, JSON schema docs, example baseline, Spec Kit artifacts, and full gate are tracked. | PASS |
| X. Scope Discipline | Spec excludes detector, policy, proxy, remediation, remote posture, exit-code, and unrelated work. | PASS |
| XI. Catalog Classification Discipline | No catalog additions or changed support claims. | PASS |

## Research Decisions

See [research.md](./research.md). All technical unknowns are resolved with existing project patterns; no new dependency or schema-version decision is required.

## Design

### Derived posture model

Add shared report-model types in `crates/etherfence-core/src/lib.rs`:

- `PostureSummary`: `score`, `grade`, `assessment`, active severity counts, `priority_risks`, and `recommended_actions`.
- `PostureRisk`: finding ID, severity, title, agent, target, fingerprint, and `why_this_matters` (copied from `Finding.impact`).
- `RecommendedAction`: the linked finding ID and the existing recommendation text.
- `PostureGrade`: fixed `a`/`b`/`c`/`d`/`f` serialized token with a human label helper.

Expose `PostureSummary::from_findings(&[Finding])`. Its input is the report's `display_findings` after existing baseline comparison and severity filtering. It selects active findings where `baseline_status != Resolved` and calculates:

```text
score = clamp(100 - 25*high - 10*medium - 2*low, 0, 100)
A = 90..=100; B = 75..=89; C = 55..=74; D = 30..=54; F = 0..=29
```

Informational findings are counted for context but do not reduce score. Priority candidates are active findings sorted by `(severity descending, id ascending, target ascending, agent key ascending, fingerprint ascending)` and truncated to three. The score and chosen priorities must be deterministic for identical displayed findings. Resolved historical findings remain in the existing report evidence but do not affect the score or executive action list.

Add `posture: Option<PostureSummary>` to `ScanReport` with `skip_serializing_if`. v1.7 scan construction always supplies `Some`, while the option keeps report-model construction and external consumers backward-compatible. No existing field or schema identifier changes.

### Rendering

- `main.rs`: construct posture only after the existing `display_findings` filter, so `--severity-threshold` remains the sole selector for what the executive layer reflects. Keep `should_fail` and `should_fail_new` exactly where they are, calculated from the existing current-finding flow.
- Default human summary: evolve the existing `Security posture`, `Priority findings`, and `Next steps` sections rather than replace them. Show score/grade and assessment in the first section, show exactly up to three priority risks with `Why this matters`, and show corresponding actions in `Next steps`; preserve current theme helpers and `--verbose` cue.
- Verbose renderer: add posture summary and priority/action sections before full inventory/evidence; preserve severity-grouped complete evidence and existing advisory note.
- Markdown renderer: place a posture table, priority risks, and next actions before inventory/full findings; retain the existing severity organization and scope note.
- JSON renderer: relies on serde for the additive `posture` subtree. SARIF remains unchanged.

### Compatibility and release updates

- Keep `ef-scan-report/v0.1.1`; document `posture` as optional/additive in `docs/json-schema.md`.
- Preserve `Summary` counts and `findings` values/ordering, baseline file shape, policy metadata, `--fail-on`, `--fail-on-new`, and `--write-baseline` behavior.
- Bump workspace version and existing version assertions/examples from 1.6.2 to 1.7.0 per release convention.

## Project Structure

### Documentation (this feature)

```text
specs/006-scan-posture-experience/
├── spec.md
├── plan.md
├── research.md
├── data-model.md
├── contracts/scan-report-posture.md
├── quickstart.md
└── tasks.md
```

### Source Code

```text
crates/
├── etherfence-core/src/lib.rs              # additive derived posture model + deterministic calculation
├── etherfence-report/src/lib.rs            # human/Markdown posture rendering; report tests
└── etherfence-cli/
    ├── src/main.rs                         # create posture after existing display selection; themed summary
    └── tests/cli_scan.rs                   # fixture-backed behavior/compatibility/exit tests

docs/
├── json-schema.md                          # additive optional posture contract
└── install.md                              # 1.7.0 version references
README.md                                   # current scan experience/examples
CHANGELOG.md                                # v1.7.0 release notes
Cargo.toml                                  # workspace version
Cargo.lock                                  # regenerated workspace metadata
```

**Structure Decision**: Keep posture derivation in the shared core model so all report renderers consume exactly one result. Rendering remains in existing report/CLI modules; no new crate, frontend, or runtime surface is introduced.

## Test Strategy

1. Core unit tests: score clamp, every grade boundary, info-only/no-active behavior, resolved exclusion, fixed tie ordering, and three-item cap.
2. Report unit tests: verbose human and Markdown posture blocks preserve existing scope note and full evidence organization; no posture leaks into SARIF.
3. CLI integration tests: additive JSON fields and unmodified legacy fields/schema; default executive view has posture/why/actions; Markdown matches posture values; severity threshold changes only displayed posture input; baseline-resolved state is excluded; `--fail-on`/`--fail-on-new` exit status stays unchanged.
4. Documentation/example checks: versioned docs, schema descriptions, example baseline regeneration, and existing examples tests.

## Documentation Updates

- Refresh `README.md` scan example so the first screen illustrates score/grade, risk context, and next actions without claiming remediation or enforcement.
- Update `docs/json-schema.md` with the optional v1.7 posture subtree, scoring rules, ordering, threshold/baseline treatment, and compatibility promise.
- Update `docs/install.md`, `CHANGELOG.md`, `docs/examples/ci/baseline.json`, version assertions, and any user-facing version evidence to 1.7.0.

## Release Gate Checklist

- `cargo fmt --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test --workspace`
- `cargo build --workspace`
- focused CLI fixture scans in human, Markdown, JSON, and SARIF formats
- `git diff --check`
- pushed branch + GitHub PR; do not merge

## Complexity Tracking

No constitution violation or justified exception.

## Post-Design Re-Check

All principles remain PASS. The model is advisory, local, deterministic, fixture-tested, schema-additive, and deliberately isolated from enforcement and scan semantics.
