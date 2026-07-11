# Implementation Plan: MCP Server Integrity Baseline and Drift Detection

**Branch**: `spec/v1.4.0-mcp-integrity-baseline-drift` | **Date**: 2026-07-11 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/003-mcp-integrity-baseline-drift/spec.md`

## Summary

Add `etherfence setup baseline write` and `etherfence setup baseline check`
so operators can capture a deterministic, safety-redacted snapshot of
discovered MCP servers (identity, command/argument fingerprints, package
identity/version, executable path/hash, env-var names, capability labels,
trust-indicator IDs, and the v1.3.0 trust/risk vocabulary) and later
compare live state against it. Comparison classifies every server as
`unchanged`/`new`/`changed`/`missing`/`unverifiable` using a closed,
15-value drift-reason enum and a collision-safe 3-field identity
fingerprint (a stable agent-kind key, normalized config source, server
name — hashed via a canonical JSON encoding, never a stable machine key
alone or a delimiter-joined string) — never display name alone, and
transport is tracked as a comparable field rather than folded into the
fingerprint. Three independent CI gate flags
(`--fail-on-drift`/`--fail-on-new`/`--fail-on-risk-increase`) always render
the full report before exiting. All new logic is a pure extension living
entirely in one new `etherfence-setup` module (`baseline.rs`) plus CLI
wiring in `etherfence-cli`; `trust.rs`/`classification.rs` and the existing
`ef-setup-detect/v0.2` schema are untouched.

## Technical Context

**Language/Version**: Rust (2021 edition), `stable` toolchain — unchanged.

**Primary Dependencies**: `sha2` (already a workspace dependency of
`etherfence-setup`, reused for the identity/command/argument fingerprint
hashes), `serde`/`serde_json`, `anyhow` — no new dependency is added.

**Storage**: None beyond local filesystem reads (existing discovery) and
one new local file write (the baseline JSON file itself, an explicit
`--output` CLI argument) plus one new local file read (`--baseline`,
bounded via the existing `MAX_BASELINE_FILE_BYTES`).

**Testing**: `cargo test --workspace`; `cargo test -p etherfence-setup` for
the new pure comparison logic; `cargo test -p etherfence-cli` for CLI
integration tests against checked-in fixtures.

**Target Platform**: Linux and Windows (existing CI matrix, unchanged).

**Project Type**: Single Rust Cargo workspace, CLI tool backed by library
crates — unchanged.

**Performance Goals**: Not a distinguishing constraint — same small local
config set as v1.2.0/v1.3.0, plus reuse of v1.3.0's already-bounded local
artifact hashing (no new hashing algorithm or larger bound introduced).

**Constraints**: Fully local, read-only over the scanned root, offline;
`check` never writes to `--baseline` under any circumstance (FR-032);
`write` refuses to overwrite without `--overwrite` (FR-002); deterministic
output (FR-004/FR-040); no new schema touches `ef-setup-detect/v0.2`
(FR-037).

**Scale/Scope**: Scales with the number of locally configured MCP servers
(single digits to low tens, same as v1.2.0/v1.3.0).

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-checked after Phase 1 design (see "Post-Design Re-Check" below).*

| Principle | Compliance approach |
|---|---|
| I. Security-First, Deny-by-Default | A hashing/verification failure always degrades toward `unverifiable`/`changed`, never a silently favorable `unchanged` (FR-012, FR-036). No new allow-by-default path is introduced; this feature adds no enforcement, only reporting. |
| II. Local-First Operation | No daemon, network call, shell hook, or subprocess. `write`/`check` are single invoker-initiated processes, exactly like every other `setup` subcommand. |
| III. Truth in Claims | Docs will state plainly that `check` reports drift only — it never blocks, enforces, or auto-remediates anything; `unverifiable` is documented as "we could not re-verify," never "this is unsafe." |
| IV. Deterministic Output | Fixed sort order for baseline/comparison entries (research.md Decision 9), fixed `DriftReason` declaration order, byte-identical `write` output for identical input (FR-004). |
| V. Fixture-Backed Findings and Classifications / XI. Catalog Classification Discipline | Every status/drift-reason combination ships with a checked-in fixture pair (baseline + mutated current state) and an exact-output test — see Fixture Strategy below. No new catalog/classification tables are introduced by this feature (it consumes v1.2.0/v1.3.0's existing ones as-is). |
| VI. Schema Compatibility and Explicit Versioning | New, additive schema families `ef-setup-baseline/v0.1` and `ef-setup-baseline-comparison/v0.1` (contracts/setup-baseline.md); `ef-setup-detect/v0.2` is untouched. |
| VII. Fail-Closed Runtime Proxy Behavior | Not touched — `mcp-proxy` code is untouched. |
| VIII. Audit Log Safety | Not applicable (no audit log here); this feature's own analogous redaction rule (FR-024/FR-025 — command/argument fingerprints only, env names only, never values/secrets/file contents) is enforced by `baseline.rs`'s field selection and covered by a dedicated redaction test (SC-005). |
| IX. Complete Release Packaging | Fixtures and CLI tests run on both Linux and Windows via the existing CI matrix; docs/CHANGELOG updated in the same change (Documentation Updates below). |
| X. Scope Discipline | Fixed 5-status/14-reason closed enums, no new discovery/classification/hashing engine, explicit Non-Goals in spec.md re-affirmed here (no malware classification, no network/registry lookup, no download/install, no signature verification, no sandboxing/subprocess execution, no daemon/watcher, no control plane, no automatic baseline acceptance, no `mcp-proxy` change). |
| XI. Catalog Classification Discipline | No new curated tables are introduced; this feature is a pure comparison layer over already-fixture-verified v1.2.0/v1.3.0 classification output. |

No violations requiring justification were identified. Complexity Tracking is intentionally empty.

## Project Structure

### Documentation (this feature)

```text
specs/003-mcp-integrity-baseline-drift/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md         # Phase 1 output
├── contracts/
│   └── setup-baseline.md
└── quickstart.md         # Phase 1 output
```
(`tasks.md` is Phase 2 output — not created here.)

### Source Code (repository root)

```text
crates/etherfence-setup/src/
├── lib.rs                 # `mod baseline;` + `pub use baseline::{...}`. No changes to
│                           # SetupDetection/SetupServer/detect()/plan()/doctor()/apply()/
│                           # rollback() — baseline.rs consumes their existing pub output.
├── catalog.rs              # unchanged
├── classification.rs       # unchanged
├── trust.rs                 # unchanged
└── baseline.rs               # NEW: BaselineDocument/BaselineServerEntry/IndicatorSummary/
                            # ReviewState/ComparisonReport/ComparisonEntry/ComparisonStatus/
                            # DriftReason/RiskDirection + build_baseline()/compare()/
                            # risk_rank()/drift_gate_triggered()/new_gate_triggered()/
                            # risk_increase_gate_triggered(). Pure functions only, no I/O.

crates/etherfence-cli/src/main.rs        # New `SetupCommand::Baseline { command:
                                          # SetupBaselineCommand }` with `Write`/`Check`
                                          # variants; `run_setup_baseline_command()`; file
                                          # read (bounded, via MAX_BASELINE_FILE_BYTES) /
                                          # write (overwrite-guarded) helpers; human/JSON
                                          # renderers for both subcommands; gate-flag exit
                                          # code wiring.

crates/etherfence-cli/tests/
├── cli_setup_baseline.rs    # NEW: integration tests against fixtures below.

tests/fixtures/
└── baseline-home/            # NEW, isolated fixture directory (mirrors v1.3.0's
                              # `trust-home/` precedent of using an isolated fixture root
                              # rather than risking `home`/`windows-home`'s existing
                              # exact-count assertions) — baseline-vs-mutated-current pairs
                              # for every status/drift-reason combination.
```

**Structure Decision**: Everything new lives in one new file per existing
crate (`etherfence-setup/src/baseline.rs`, `etherfence-cli/tests/
cli_setup_baseline.rs`) plus one new isolated fixture directory. No
existing production file changes except `etherfence-setup/src/lib.rs`
(module declaration + re-exports, additive) and `etherfence-cli/src/
main.rs` (new subcommand variants + match arms + renderers, additive). This
is a strictly smaller footprint than v1.3.0's (which also needed a
one-line visibility change in a third crate) because this feature needs no
change to `etherfence-mcp` at all.

## Fixture Strategy

A brand-new, isolated `tests/fixtures/baseline-home/` avoids any risk of
perturbing `home`/`windows-home`/`malformed-home`/`trust-home`'s existing
exact-count/exact-baseline assertions (the same deliberate choice v1.3.0
made for `trust-home/`, spec FR-034's compatibility concern).

| Area | Fixture approach | Proves |
|---|---|---|
| Byte-identical `write` | Same fixture root scanned twice via `write --output` to two paths, diffed. | FR-004. |
| `unchanged` | Baseline written, `check` run against same fixture with no mutation. | FR-011, SC-001. |
| `new`/`missing` | Baseline written against a 2-server fixture; test adds/removes one server's config block before `check`. | FR-010, FR-015. |
| `command-changed`/`arguments-changed` | Mutate the fixture's `command`/`args` field between `write` and `check`. | FR-013, FR-014, FR-016. |
| `package-identity-changed`/`package-version-changed` | Mutate an npx package name / version tag between runs. | FR-014. |
| `environment-variable-names-changed` (order-independent) | Reorder existing env names (no drift expected) vs. add/remove a name (drift expected) — two sub-cases in one test. | FR-014, FR-016, Edge Cases. |
| `transport-changed` | Fixture server switches from a `command` to a `url` (or vice versa) between runs. | FR-014. |
| `capability-set-changed`/`trust-indicator-set-changed` | Mutate a fixture command from a curated known-source package to an arbitrary one (changes both capability classification and trust indicators). | FR-014, FR-017, FR-018. |
| `artifact-identity-changed`/`executable-hash-changed` | A real small fixture binary is hashed at baseline time, then its bytes are modified by exactly one byte before `check`. | FR-014, FR-019, FR-036, SC-002. |
| `unverifiable` | A fixture binary that is hash-verified at baseline time is replaced with a symlink (or has its permissions changed, platform-appropriate) before `check`, with no other field changed. | FR-012, Decision 8. |
| `risk-increased`/decrease-no-gate | One fixture pair whose aggregate rank increases between baseline/current; one whose rank decreases. Both assert `changed` status; only the increase case asserts `risk-increased` in reasons. | FR-020, FR-021–FR-023. |
| Fingerprint collision-safety | Two servers with the identical `serverName` across two different agents/config files/transports in the same fixture root. | FR-006, FR-007, SC-003. |
| Malformed/unsupported baseline | A hand-written baseline file with a wrong `schemaVersion` and one with invalid JSON. | Edge Cases (fail closed). |
| Overwrite refusal | `write` run twice to the same `--output` without `--overwrite`, then with it. | FR-002. |
| `check` never mutates baseline | Hash the baseline file before/after every `check` invocation in the test suite. | FR-032, SC-004. |
| Key reorder causes no drift | Reorder JSON keys in the fixture config file (no semantic change) between `write` and `check`. | Edge Cases. |
| No secret leakage | A fixture env var with a realistic secret-looking value; assert the value string never appears in baseline file or `check` stdout/stderr. | FR-025, SC-005. |
| Gate combinations | Table-driven test over all 2^3 gate-flag combinations against a fixture with one `new`, one `changed`-with-risk-increase, and one `unchanged` server. | FR-027–FR-030, SC-006. |
| Gate never suppresses report | Assert full report is present in stdout even when a gate causes non-zero exit. | FR-031. |

**Gate**: a status or drift reason may be described as implemented only
once its fixture has an accompanying test asserting the exact
`ComparisonEntry` output it produces.

## Test Strategy

1. **Unit tests, `crates/etherfence-setup/src/baseline.rs`**: fingerprint
   determinism/collision-avoidance table test (varying exactly one of the
   four identity inputs at a time); `risk_rank` total-order test over all
   5 `AggregateAssessmentStatus` values; a full status-classification
   table test covering every FR-009–FR-013 case with synthetic
   hand-built `SetupDetection`/baseline-entry inputs (no filesystem
   needed); gate-predicate unit tests for all three
   `*_gate_triggered` functions.
2. **CLI integration tests, `crates/etherfence-cli/tests/
   cli_setup_baseline.rs`**: fixture-backed tests per the Fixture Strategy
   table above, following the existing `fixture_root`/`run`/`temp_home`
   helper pattern already used by `cli_setup.rs`.
3. **Workspace regression gate**: `cargo test --workspace` must remain
   fully green, including unmodified `cli_setup.rs`/`cli_setup_catalog.rs`
   assertions (proves `setup detect`/`setup catalog` byte-for-byte
   unaffected).
4. **CI platforms**: existing `rust (ubuntu-latest)`/`rust
   (windows-latest)` matrix; the symlink-based `unverifiable` fixture case
   uses a Unix-only test variant (mirroring the existing `/dev/zero`/
   symlink Unix-only precedent in `etherfence-core`/`trust.rs`), with a
   platform-appropriate equivalent (e.g. permission removal or path
   deletion) exercised on both platforms for the general "becomes
   unhashable" case.

## Documentation Updates

Per Constitution Principle IX, updated in the same change as the code:

- **`README.md`**: new `setup baseline write`/`check` example section,
  Command overview row additions.
- **`docs/setup-onboarding.md`**: new subsection documenting the baseline
  workflow, its safety boundary (what is/isn't persisted), and gate flags.
- **`docs/json-schema.md`**: new `ef-setup-baseline/v0.1` and
  `ef-setup-baseline-comparison/v0.1` sections.
- **`docs/architecture.md`**: note that baseline/comparison adds no new
  trust boundary — same local config reads plus reuse of v1.3.0's already-
  documented bounded local-file-read surface, no new one.
- **`docs/threat-model.md`**: addendum noting `--baseline`/`--output` are
  trusted-operator CLI inputs (same model as every other config path),
  read/written through the existing bounded-file-read/write helpers.
- **`docs/roadmap.md`**: new v1.4.0 entry.
- **`CHANGELOG.md`**: new `## [1.4.0]` section.
- **No changes required**: `docs/mcp-proxy.md`, `docs/mcp-proxy-operator-
  guide.md`, `docs/mcp-policy-ux.md`, `docs/sarif.md`, `docs/ci.md`,
  `docs/mcp-compatibility-matrix.md` — none touched by this feature.

## Release Gate Checklist

- [ ] `cargo fmt --check` passes.
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passes.
- [ ] `cargo test --workspace` passes on both Linux and Windows CI runners.
- [ ] `cargo build` succeeds.
- [ ] `git diff --check` passes.
- [ ] Every status/drift-reason combination has a passing fixture test
      asserting its exact output (SC-002, SC-006).
- [ ] No test observes an environment-variable value, file content,
      credential, token, or complete sensitive command string anywhere in
      baseline or `check` output (SC-005).
- [ ] `check` never modifies the `--baseline` file, verified by hash
      comparison before/after every test invocation (SC-004).
- [ ] `write` refuses to overwrite without `--overwrite` (FR-002).
- [ ] `setup detect`'s `ef-setup-detect/v0.2` output is byte-for-byte
      unaffected (FR-037).
- [ ] The pre-existing `scan --write-baseline`/`--baseline`
      (`ef-baseline/v0.1.3`) feature is unaffected (FR-038).
- [ ] All documentation files listed above are updated.
- [ ] No documentation or command output claims baseline/check performs
      enforcement, blocking, or automatic remediation (Truth in Claims).
- [ ] Spec's Out of Scope / Explicit Non-Goals items re-confirmed absent
      from the diff.

## Complexity Tracking

*No Constitution Check violations were identified; this table is intentionally empty.*

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| — | — | — |

## Post-Design Re-Check

Re-evaluated after Phase 1 (data-model.md, contracts/, quickstart.md):

- **Zero changes to `trust.rs`/`classification.rs`** confirmed still
  achievable: every field `baseline.rs` needs (`invocation.package_identity`,
  `invocation.version_expression`, `executable_path`, `sha256`,
  `artifact_identity`, `configuration_risk`, `aggregate`, `capabilities.labels`,
  `indicators[].{id,category,severity}`) is already `pub` on
  `TrustAssessment`/`ClassifiedCapabilities`/`TrustIndicator`. No new
  visibility or signature change is needed anywhere outside the new module.
- **`sha256` omission semantics** double-checked against the v1.3.0
  precedent: both `data-model.md` and `contracts/setup-baseline.md` agree
  it is omitted-not-null, consistent with `TrustAssessment.sha256`'s
  existing behavior — no divergence introduced.
- **No new violation** was introduced by the data model or contract;
  Constitution Check table above still holds.
