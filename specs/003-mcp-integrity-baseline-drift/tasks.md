# Tasks: MCP Server Integrity Baseline and Drift Detection

**Input**: Design documents from `/specs/003-mcp-integrity-baseline-drift/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/setup-baseline.md, quickstart.md

**Tests**: Explicitly requested by the spec (Acceptance Scenarios, Success Criteria, and the goal's own Tests list) — test tasks are included throughout.

**Organization**: Tasks are grouped by user story (US1 = baseline write, US2 = drift detection, US3 = gate automation), all Priority P1 per spec.md.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no unresolved dependency)
- **[Story]**: US1/US2/US3, omitted for Setup/Foundational/Polish tasks
- File paths are exact and relative to the repository root.

## Phase 1: Setup

- [X] T001 Create isolated fixture directory `tests/fixtures/baseline-home/` with a minimal `.claude.json` (one `npx -y @modelcontextprotocol/server-filesystem` stdio server, one `url`-only remote server) and a second agent config (e.g. `.cursor/mcp.json`) containing a server with the **same `serverName`** as the Claude Code one, to exercise fingerprint collision-safety later. Mirrors v1.3.0's `trust-home/` precedent of using a brand-new isolated fixture root rather than touching `home`/`windows-home`/`malformed-home`/`trust-home`'s existing exact-count assertions.

## Phase 2: Foundational (blocking prerequisites)

**Purpose**: Shared vocabulary types, the identity fingerprint, and the pure baseline-building function every user story depends on. No user story can be implemented before this phase completes.

- [X] T002 [P] Add `ReviewState`, `DriftReason` (closed 14-variant enum per spec FR-014), `ComparisonStatus`, `RiskDirection`, and `IndicatorSummary` types with `Serialize` derives (kebab-case enums, camelCase structs) to new file `crates/etherfence-setup/src/baseline.rs`, per data-model.md.
- [X] T003 Implement `fingerprint(agent: &str, config_source: &str, server_name: &str, transport: ServerTransport) -> String` in `crates/etherfence-setup/src/baseline.rs` per research.md Decision 3 (SHA-256 hex of the four inputs joined with `\u{1}`). Add unit tests: varying each of the 4 inputs alone changes the fingerprint; identical inputs always reproduce the identical fingerprint.
- [X] T004 Implement `BaselineServerEntry`, `BaselineDocument`, and `build_baseline(root: &Path, detections: &[SetupDetection]) -> BaselineDocument` in `crates/etherfence-setup/src/baseline.rs`, copying fields verbatim from `SetupServer`/`TrustAssessment`/`ClassifiedCapabilities` (research.md Decisions 4-6), sorted per research.md Decision 9. Add a unit test asserting two calls against identical input produce equal (`==`) `BaselineDocument` values.
- [X] T005 Add `mod baseline;` and `pub use baseline::{BaselineDocument, BaselineServerEntry, IndicatorSummary, ReviewState, ComparisonReport, ComparisonEntry, ComparisonStatus, DriftReason, RiskDirection, build_baseline, compare, risk_rank, drift_gate_triggered, new_gate_triggered, risk_increase_gate_triggered}` to `crates/etherfence-setup/src/lib.rs` (some names forward-declared here will be implemented in later tasks — add them as the module grows, keeping this file's re-export list in sync each time).
- [X] T006 Add `SetupCommand::Baseline { command: SetupBaselineCommand }` and a new `SetupBaselineCommand` enum (`Write { root: Option<PathBuf>, output: PathBuf, overwrite: bool }`, `Check { root: Option<PathBuf>, baseline: PathBuf, format: SetupOutputFormat, fail_on_drift: bool, fail_on_new: bool, fail_on_risk_increase: bool }`) to `crates/etherfence-cli/src/main.rs`, wired into `run_setup_command`'s match via a new `run_setup_baseline_command` function containing a `todo!()` body for each arm so the workspace compiles — replaced by US1/US2 respectively.

**Checkpoint**: `cargo build --workspace` succeeds (the `todo!()` stubs compile; they are never exercised by any test yet).

## Phase 3: User Story 1 - Capture a point-in-time integrity baseline (Priority: P1)

**Goal**: `etherfence setup baseline write --root <path> --output <file> [--overwrite]` produces a deterministic `ef-setup-baseline/v0.1` file and refuses to clobber an existing one without `--overwrite`.

**Independent Test**: Run `write` against `tests/fixtures/baseline-home/` twice to two output paths and diff them; run a third time to the same path without `--overwrite` and confirm refusal.

- [X] T007 [US1] Replace the `Write` arm's `todo!()` in `crates/etherfence-cli/src/main.rs` with `run_setup_baseline_write`: calls `etherfence_setup::detect(&root)` → `etherfence_setup::build_baseline(&root, &detections)` → refuses (non-zero exit, no file touched) if `--output` exists and `--overwrite` absent → serializes via `serde_json::to_string_pretty` → writes the file. Add `render_setup_baseline_write_human` per contracts/setup-baseline.md.
- [X] T008 [P] [US1] Add `crates/etherfence-cli/tests/cli_setup_baseline.rs` with tests: byte-identical output across two `write` runs against the T001 fixture with no changes in between; `write` without `--overwrite` against an existing file refuses and leaves it byte-unchanged; `write --overwrite` replaces it; output JSON declares `schemaVersion == "ef-setup-baseline/v0.1"`.

**Checkpoint**: User Story 1 is independently functional and testable.

## Phase 4: User Story 2 - Detect drift against a saved baseline (Priority: P1)

**Goal**: `etherfence setup baseline check --root <path> --baseline <file> [--format human|json]` classifies every server as `unchanged`/`new`/`changed`/`missing`/`unverifiable` with the correct closed drift reason(s), and never modifies the baseline file.

**Independent Test**: Write a baseline, mutate the fixture's command, run `check`, and confirm `changed` + `command-changed` while the baseline file's hash is unchanged before/after.

- [X] T009 [US2] Implement `risk_rank(status: AggregateAssessmentStatus) -> u8` in `crates/etherfence-setup/src/baseline.rs` per research.md Decision 7 (`VerifiedLocal=0 < KnownSource=1 < Unknown=2 < NeedsReview=3 < HighRisk=4`). Add a unit test asserting the total order over all 5 values.
- [X] T010 [US2] Implement `compare(baseline: &BaselineDocument, current: &[SetupDetection], root: &Path) -> ComparisonReport` in `crates/etherfence-setup/src/baseline.rs`: match by fingerprint; classify per spec FR-009–FR-020 (including the `unverifiable`-vs-`changed` precedence rule from research.md Decision 8 and the order-independent set comparisons from FR-016/FR-017/FR-018); sort reasons by `DriftReason` declaration order and entries per research.md Decision 9. Add unit tests covering every one of the 5 statuses and all 14 `DriftReason` variants using synthetic hand-built `SetupDetection`/`BaselineDocument` values (no filesystem needed) — include the `unverifiable`-only-when-nothing-else-differs precedence case explicitly.
- [X] T011 [US2] Replace the `Check` arm's `todo!()` in `crates/etherfence-cli/src/main.rs` with `run_setup_baseline_check`: reads `--baseline` via `read_bounded_text_file(path, MAX_BASELINE_FILE_BYTES)`, parses JSON, fails closed on parse error or `schemaVersion != "ef-setup-baseline/v0.1"`; calls `etherfence_setup::detect(&root)`; calls `compare()`; renders via `--format` (`render_setup_baseline_check_human` / `render_setup_baseline_check_json`, the latter declaring `ef-setup-baseline-comparison/v0.1`) per contracts/setup-baseline.md. No gate handling yet (added in US3) — command always exits 0 in this task.
- [X] T012 [P] [US2] Extend `crates/etherfence-cli/tests/cli_setup_baseline.rs`: `unchanged` (no mutation), `new` (add a server), `missing` (remove a server), `changed` for each of `command-changed`/`arguments-changed`/`package-identity-changed`/`package-version-changed`/`transport-changed`/`capability-set-changed`/`trust-indicator-set-changed`/`artifact-identity-changed`/`executable-hash-changed` (one small real fixture binary, one byte flipped between `write` and `check`), and `unverifiable` (fixture binary replaced with a symlink or made unreadable, no other field changed).
- [X] T013 [P] [US2] Extend `crates/etherfence-cli/tests/cli_setup_baseline.rs`: environment-variable-name-set reordering causes no drift but addition/removal does; JSON key reordering in the fixture config file causes no drift; the two same-`serverName`-different-agent fixture entries from T001 are never conflated (distinct fingerprints, distinct statuses); a hand-written baseline file with a wrong `schemaVersion` and one with invalid JSON both fail closed (non-zero exit, no partial report); `check` never modifies `--baseline` (hash the file before/after every invocation in this test file); no fixture-configured environment variable value ever appears in `check` stdout/stderr or in the baseline file.

**Checkpoint**: User Story 2 is independently functional and testable (informational-only; no gate flags yet).

## Phase 5: User Story 3 - Gate automation on drift severity (Priority: P1)

**Goal**: `--fail-on-drift` / `--fail-on-new` / `--fail-on-risk-increase` each cause the correct, and only the correct, non-zero exit — and the full report is always printed regardless.

**Independent Test**: Run `check --fail-on-new` against a baseline missing one currently-configured server; confirm non-zero exit with the full report still printed.

- [X] T014 [US3] Implement `drift_gate_triggered`, `new_gate_triggered`, and `risk_increase_gate_triggered` (each `fn(&ComparisonReport) -> bool`) in `crates/etherfence-setup/src/baseline.rs` per spec FR-027–FR-030. Add unit tests for each over synthetic `ComparisonReport` values covering every status and a risk-decrease-only case (must not trigger the risk-increase predicate).
- [X] T015 [US3] Wire `--fail-on-drift`/`--fail-on-new`/`--fail-on-risk-increase` into `run_setup_baseline_check` in `crates/etherfence-cli/src/main.rs`: render the full report first, then compute the exit code from any combination of the three gate predicates (non-zero if any passed gate's condition is met), per FR-031.
- [X] T016 [P] [US3] Extend `crates/etherfence-cli/tests/cli_setup_baseline.rs`: table-driven test over all 8 combinations of the 3 gate flags against a fixture with one `new`, one `changed`-with-`risk-increased`, and one `unchanged` server, asserting the exact expected exit code for each combination; a dedicated test asserting the full report is present in stdout even when a gate causes non-zero exit; a dedicated test asserting a risk *decrease* (aggregate rank goes down, nothing else changes) is reported as `changed` drift but does not trigger `--fail-on-risk-increase`.

**Checkpoint**: All three user stories are independently functional and testable; full feature is usable end-to-end.

## Phase 6: Polish & Release Gate

- [X] T017 [P] Update `README.md` (Command overview row + new `setup baseline write`/`check` example section) and `docs/setup-onboarding.md` (new subsection: workflow, safety boundary, gate flags) per plan.md Documentation Updates.
- [X] T018 [P] Update `docs/json-schema.md` with new `ef-setup-baseline/v0.1` and `ef-setup-baseline-comparison/v0.1` sections per contracts/setup-baseline.md.
- [X] T019 [P] Update `docs/architecture.md` (no new trust boundary) and `docs/threat-model.md` (`--baseline`/`--output` are trusted-operator CLI inputs, same model as every other config path) per plan.md Documentation Updates.
- [X] T020 [P] Update `docs/roadmap.md` (new v1.4.0 entry) and `CHANGELOG.md` (new `## [1.4.0]` section: added `setup baseline write`/`check`, `ef-setup-baseline/v0.1`, `ef-setup-baseline-comparison/v0.1`; explicit note that `ef-setup-detect/v0.2` and the pre-existing `scan --write-baseline` feature are unaffected).
- [X] T021 Bump workspace version to `1.4.0` in `Cargo.toml`, regenerate `Cargo.lock`, and update any hardcoded version assertions (e.g. `crates/etherfence-cli/tests/cli_scan.rs`, `docs/install.md`) to match.
- [X] T022 Extend the existing docs-honesty negation-aware prohibited-terms test (mirroring `setup_catalog_docs.rs`'s established pattern) to also scan the new baseline documentation sections for enforcement/blocking/automatic-remediation language.
- [X] T023 Run the full local release gate: `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --workspace`, `cargo build`, `git diff --check`. Fix every failure found.
- [X] T024 Manually walk through every step of `quickstart.md` end-to-end against the local debug build; fix any doc/behavior mismatch found (per the v1.2.0/v1.3.0 lesson that doc claims must be verified against real output, not assumed).

## Dependencies

- **Setup (T001) → Foundational (T002-T006)**: Foundational's tests need the fixture directory to exist conceptually, though T002-T005's unit tests are synthetic/fixture-free; T006 has no fixture dependency either. T001 mainly gates Phase 3+'s integration tests.
- **Foundational (T002-T006) → all user stories**: every story needs the vocabulary types, fingerprint, `build_baseline`, and CLI scaffold.
- **US1 (T007-T008)**: depends only on Foundational. Independent of US2/US3.
- **US2 (T009-T013)**: depends only on Foundational (`compare()` operates on `BaselineDocument`/`SetupDetection` directly — it does not require `write`'s CLI command to exist, only `build_baseline`, which Foundational already provides). Independent of US1's CLI command, though its integration tests (T012-T013) call `write` to produce a baseline file, so in practice T007 should land first even though there is no logical/API dependency.
- **US3 (T014-T016)**: depends on US2 (`compare()`/`ComparisonReport` must exist for the gate predicates to operate over).
- **Polish (T017-T024)**: depends on all user stories being complete.

## Parallel Example

```text
# After Foundational (T002-T006) completes:
T007 [US1] and T009 [US2] can start in parallel (different concerns within baseline.rs,
  but touch the same file — coordinate sequentially in a single-developer session).
T008 [US1], T012 [US2], T013 [US2], T016 [US3] all touch the same test file
  (cli_setup_baseline.rs) — implement sequentially even though marked [P] for
  conceptual independence.
T017, T018, T019, T020 (documentation) are fully independent files — true parallel candidates.
```

## Implementation Strategy

**MVP first**: Setup + Foundational + User Story 1 alone already delivers a usable, testable increment (`setup baseline write`). Recommended full-release scope is **all three P1 stories** (US1+US2+US3) since the spec frames drift detection and gating as the feature's entire value proposition — there is no meaningful partial-release stopping point between US1 and US3 the way v1.2.0/v1.3.0 had optional P2 stories to defer.

**Incremental delivery**: Foundational → US1 (write works, verify with T008) → US2 (check/drift works informationally, verify with T012-T013) → US3 (gates work, verify with T016) → Polish.
