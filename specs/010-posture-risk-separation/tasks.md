# Tasks: Posture Score Risk Separation

**Input**: Design documents from `/specs/010-posture-risk-separation/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/, quickstart.md (all present)

**Tests**: Explicitly requested by the feature's required outcomes (spec.md Requirements FR-014); included throughout.

**Organization**: Tasks are grouped by user story (US1/US2/US3, matching spec.md priorities P1/P1/P2) to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: US1 = score reflects actionable risk, US2 = evidence shows trigger field, US3 = four-way human output separation

---

## Phase 1: Setup

- [X] T001 Confirm the workspace builds clean on `feature/v1.7.4-posture-risk-separation` before any change: `cargo build` at repo root.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Introduce `FindingCategory` and wire it into every existing finding constructor with the correct value, per `contracts/scoring-and-evidence.md`'s fixed table. All three user stories depend on `category` existing and being correct on every `Finding`.

**⚠️ CRITICAL**: No user story work can begin until this phase compiles and passes existing tests (after test-fixture updates in T008).

- [X] T002 Add `FindingCategory` enum (`Inventory`, `Informational`, `#[default] Risk`; kebab-case serde; `.key()`/`.label()` accessors, mirroring `PolicyStatus`) in `crates/etherfence-core/src/lib.rs`.
- [X] T003 Add `#[serde(default)] pub category: FindingCategory` field to the `Finding` struct (append after `evidence`) in `crates/etherfence-core/src/lib.rs`. (depends on T002)
- [X] T004 [P] In `crates/etherfence-detectors/src/lib.rs`: add `category: FindingCategory` to `FindingTemplate` and every call site (`config_parse_error`→Risk, `mcp_configured`→**Inventory + severity Info**, `broad_filesystem`→Risk, `shell_capable`→Risk, `network_capable`→Risk, `exposed_env`→**Inventory + severity Info**, `secret_env_name`→Risk, `tirith_finding`→Informational for both EF-TIRITH-001/002); update the `finding()` builder to pass `category` through. (depends on T003)
- [X] T005 [P] In `crates/etherfence-policy/src/lib.rs`: set `category: FindingCategory::Risk` on both `Finding { ... }` constructor sites (`EF-POL-001..004` builder around line 349, and `tirith_required_finding`/`EF-POL-005` around line 372). (depends on T003)
- [X] T006 Bump the scan-report schema version string `"ef-scan-report/v0.1.2"` → `"ef-scan-report/v0.1.3"` at its construction site in `crates/etherfence-cli/src/main.rs` (`render_scan` report literal) and the debug schema literal in `crates/etherfence-cli/src/verbose.rs` (`render_findings` debug line). (depends on T003)
- [X] T007 Bump `BASELINE_SCHEMA_VERSION` from `"ef-baseline/v0.1.3"` to `"ef-baseline/v0.1.4"` in `crates/etherfence-cli/src/main.rs`. (depends on T003)
- [X] T008 Add an explicit `category` value to every existing `Finding { ... }` struct literal in test code so the workspace compiles: `crates/etherfence-core/src/lib.rs` (posture/summary unit tests), `crates/etherfence-detectors/src/lib.rs` (detector unit tests — mostly covered by T004's builder), `crates/etherfence-policy/src/lib.rs` (policy unit tests), `crates/etherfence-report/src/lib.rs` (renderer unit tests). (depends on T004, T005)
- [X] T009 Checkpoint: `cargo build` and `cargo test --workspace` compile (test *assertions* may still fail pending later phases, but nothing should fail to *compile*). (depends on T004, T005, T008)

**Checkpoint**: Foundation ready — `Finding.category` exists, is correctly assigned everywhere, and the workspace compiles.

---

## Phase 3: User Story 1 — Score reflects actionable risk, not inventory size (Priority: P1) 🎯 MVP

**Goal**: Posture score/grade are computed only from `category == Risk` active findings; `EF-MCP-000`/`EF-MCP-004` never reduce score; `EF-SEC-001` and all other risk findings score exactly as before.

**Independent Test**: `cargo run -- scan --root <fixture-with-only-clean-servers-and-ordinary-env-vars> --format json | jq '.posture.score'` → `100`, regardless of server count; a fixture with `EF-SEC-001` present shows the score reduced by 10.

### Tests for User Story 1

- [X] T010 [P] [US1] Add a unit test in `crates/etherfence-core/src/lib.rs` proving that any number of active `Inventory`/`Informational`-category findings (any severity) leaves `score == 100` and `grade == A`.
- [X] T011 [P] [US1] Add a unit test in `crates/etherfence-core/src/lib.rs` proving `active_findings`/`high`/`medium`/`low`/`info` on `PostureSummary` count only `category == Risk` findings, using a mixed synthetic finding set.
- [X] T012 [P] [US1] Add a unit test in `crates/etherfence-core/src/lib.rs` proving actionable Low/Medium/High findings still reduce score by 2/10/25 respectively (reuse/extend the existing `posture_score_grade_and_priority_are_deterministic` boundary style).
- [X] T013 [P] [US1] Add a unit test in `crates/etherfence-core/src/lib.rs` (or extend `posture_excludes_resolved_and_clamps_score`) proving a `BaselineStatus::Resolved` Risk-category finding remains excluded from the score regardless of category.
- [X] T014 [P] [US1] Add an integration test in `crates/etherfence-cli/tests/cli_scan.rs` running `scan --root tests/fixtures/home --format json` and asserting `EF-MCP-000`/`EF-MCP-004` have `"category":"inventory"`/`"severity":"info"`, while `EF-SEC-001` has `"category":"risk"`/`"severity":"medium"`.

### Implementation for User Story 1

- [X] T015 [US1] Change `PostureSummary::from_findings` in `crates/etherfence-core/src/lib.rs` to filter `active` to `category == FindingCategory::Risk` before computing `high`/`medium`/`low`/`info`/`score`/`priority_risks`/`recommended_actions` (score formula weights unchanged). (depends on T002, T003, T009)
- [X] T016 [US1] Update the existing `PostureSummary` unit tests in `crates/etherfence-core/src/lib.rs` (`posture_score_grade_and_priority_are_deterministic`, `posture_excludes_resolved_and_clamps_score`, `posture_no_scored_findings_is_a_grade`, `posture_grade_boundaries_are_exact`) to set `category: FindingCategory::Risk` explicitly on their synthetic findings and confirm the formula/grade boundaries are unchanged. (depends on T015)
- [X] T017 [US1] Update `crates/etherfence-cli/tests/cli_scan.rs`'s `scan_fixture_json_has_stable_top_level_schema` (and any other test asserting `posture.score`/`posture.grade`/`posture.active_findings` for the `home` fixture) to the new expected values now that `EF-MCP-000`/`EF-MCP-004` no longer contribute. (depends on T015)

**Checkpoint**: User Story 1 is independently functional and testable (quickstart.md steps 2–4).

---

## Phase 4: User Story 2 — Every heuristic finding shows its own trigger evidence (Priority: P1)

**Goal**: Every heuristic finding's evidence names the specific server field (`server`/`command`/`args[N]`/`url`/`env`) and matched value/pattern, deterministically, without ever exposing a secret value.

**Independent Test**: `cargo run -- scan --root tests/fixtures/home --format json | jq '.findings[] | select(.id=="EF-MCP-001") | .evidence'` shows labeled entries; no fixture-derived secret value string appears anywhere in JSON/Markdown/SARIF/human/verbose output.

### Tests for User Story 2

- [X] T018 [P] [US2] Add a unit test in `crates/etherfence-detectors/src/lib.rs` asserting `EF-MCP-001`/`EF-MCP-002`/`EF-MCP-003` evidence entries are `server=`/`command=`/`args[N]=`/`url=` labeled (not bare values).
- [X] T019 [P] [US2] Add a unit test in `crates/etherfence-detectors/src/lib.rs` asserting `EF-MCP-004`/`EF-SEC-001` evidence entries are `env=<name>` labeled and never contain the variable's redacted value token or anything other than the name.
- [X] T020 [P] [US2] Add a unit test in `crates/etherfence-detectors/src/lib.rs` calling `analyze()` twice on identical input and asserting byte-identical evidence vectors (order and content) both times.
- [X] T021 [P] [US2] Add an integration test in `crates/etherfence-cli/tests/cli_scan.rs` asserting a known fixture secret placeholder value never appears in `--format json`, `--format markdown`, `--format sarif`, default human, or `--verbose` output.

### Implementation for User Story 2

- [X] T022 [US2] In `crates/etherfence-detectors/src/lib.rs`, replace `values()`/`matching_values()` with a labeled variant (e.g. returning `Vec<(&'static str, String)>` with labels `"server"`, `"command"`, `"args[N]"`, `"url"`), and update `broad_filesystem_evidence`, `risky_command_evidence`, `network_evidence` to format matches as `label=value`.
- [X] T023 [US2] In `crates/etherfence-detectors/src/lib.rs`, update `exposed_env` and `secret_env_name` to emit `env=<name>` evidence instead of the bare name.
- [X] T024 [US2] In `crates/etherfence-report/src/lib.rs`'s `sarif_result`, add an `"etherfenceCategory": finding.category.key()` property alongside the existing `"etherfenceSeverity"` property. (depends on T002, T003)
- [X] T025 [US2] Update every existing test asserting bare (unlabeled) evidence strings — in `crates/etherfence-detectors/src/lib.rs`, `crates/etherfence-cli/tests/cli_scan.rs`, and `crates/etherfence-report/src/lib.rs` — to the new `field=value` format. (depends on T022, T023)

**Checkpoint**: User Story 2 is independently functional and testable (quickstart.md step 5).

---

## Phase 5: User Story 3 — Human output separates what's observed from what's risky (Priority: P2)

**Goal**: Concise and verbose human output, plus Markdown/`to_human`, distinguish inventory observations, scored risk findings, informational findings, and protection/policy coverage via clearly labeled sections/badges.

**Independent Test**: Default and verbose `scan` output on a mixed fixture show four distinguishable sections/badges as described in `contracts/human-output-grouping.md`.

### Tests for User Story 3

- [X] T026 [P] [US3] Add an integration test in `crates/etherfence-cli/tests/cli_scan.rs` asserting default (non-verbose) output contains "Inventory observations" and "Informational findings" headings, distinct from "Priority findings" and "Protection coverage".
- [X] T027 [P] [US3] Add an integration test in `crates/etherfence-cli/tests/cli_scan.rs` asserting `--verbose` output shows an `OBS` badge on `EF-MCP-000`/`EF-MCP-004` lines, distinct from `HIGH`/`MEDIUM`/`LOW`/`INFO` badges used for risk/informational findings.
- [X] T028 [P] [US3] Replace `scan_verbose_consolidated_excludes_context_and_orders_by_severity` in `crates/etherfence-cli/tests/cli_scan.rs`: assert both `EF-MCP-000` and `EF-MCP-004` are excluded from "Consolidated recommended actions" (generalizing the prior single-ID assertion), while keeping the High-before-Medium ordering assertion for `EF-MCP-001`/`EF-SEC-001`.
- [X] T029 [P] [US3] Add a unit test in `crates/etherfence-report/src/lib.rs` asserting `to_markdown`/`to_human` findings sections are headed by category (Inventory/Informational/Risk) before severity, for a mixed-category fixture report.

### Implementation for User Story 3

- [X] T030 [US3] Add "Inventory observations" and "Informational findings" sections to `render_scan_summary` in `crates/etherfence-cli/src/main.rs`, positioned between the existing "Clients" and "Protection coverage" sections, each a compact summary line derived from `report.findings` filtered by `category`. (depends on T015)
- [X] T031 [US3] In `crates/etherfence-cli/src/verbose.rs`'s `render_findings`, change the badge match from `finding.severity` alone to `finding.category` first (`Inventory` → new `OBS` badge, `Informational` → existing `INFO` badge, `Risk` → existing severity-based badges).
- [X] T032 [US3] In `crates/etherfence-cli/src/verbose.rs`'s `render_consolidated_recommendations`, generalize the `finding.id == "EF-MCP-000"` exclusion to `finding.category != FindingCategory::Risk`.
- [X] T033 [US3] In `crates/etherfence-report/src/lib.rs`, change the findings-grouping loop in both `append_human_findings` (used by `to_human`) and the `## Findings` section of `to_markdown` from `for severity in Severity::ORDERED_DESC` to a category-then-severity nested grouping, with category headings using `FindingCategory::label()`.

**Checkpoint**: User Story 3 is independently functional and testable (quickstart.md step 7). All user stories now integrate: score (US1), evidence (US2), and presentation (US3) are consistent end to end.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Documentation, versioning, fixture regeneration, and the full release quality gate — required by Principle IX before this feature is complete.

- [X] T034 [P] Update `docs/json-schema.md`: add the `Finding.category` row, update the score-formula wording to state it applies only to `category == "risk"` findings, document both schema version bumps (`ef-scan-report/v0.1.3`, `ef-baseline/v0.1.4`), and clarify `posture.*` counts vs. `report.summary.*` counts per `research.md` §6.
- [X] T035 [P] Update `docs/sarif.md` to note the new `properties.etherfenceCategory` field, if that doc enumerates per-result SARIF properties.
- [X] T036 Regenerate `docs/examples/ci/baseline.json` via `cargo run -- scan --root <the fixtures composing it> --write-baseline docs/examples/ci/baseline.json` (or hand-reconcile per fixture) so its `schema_version`, `category`, `severity`, and `evidence` fields match `contracts/scoring-and-evidence.md`. (depends on T004, T006, T007, T022, T023)
- [X] T037 [P] Update `README.md`'s posture-scoring section to describe category-gated scoring, the four output groupings, and field-labeled evidence.
- [X] T038 Update `CHANGELOG.md`: rename `## [Unreleased]` to `## [1.7.4] - 2026-07-13` (keeping its existing content), add a new subsection describing this feature's behavior/compatibility changes, and add a fresh empty `## [Unreleased]` above it.
- [X] T039 Bump `version` in `Cargo.toml` from `1.7.3` to `1.7.4`, and update every version-string assertion (`crates/etherfence-cli/tests/cli_scan.rs`, `docs/install.md` if present) to match.
- [X] T040 Run the full quality gate: `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test`, `cargo build`, `git diff --check` — all clean.
- [X] T041 Manually execute `quickstart.md` end to end against the built binary and confirm every expected output.
- [X] T042 Run `/speckit-analyze` for a final cross-artifact consistency pass across spec.md/plan.md/tasks.md before closing out the feature.

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies.
- **Foundational (Phase 2)**: Depends on Setup. BLOCKS all user stories (T002–T009 must land and compile first).
- **User Stories (Phase 3–5)**: All depend on Foundational completion (T009). US1 (Phase 3) should land first since US3's concise-output section (T030) reads the category-gated `PostureSummary` from US1 (T015) — so while US2 (Phase 4) is fully independent of US1, US3 has a soft dependency on T015 specifically (noted inline above), not on the rest of US1.
- **Polish (Phase 6)**: Depends on all three user stories being complete (baseline regeneration in T036 needs the final evidence format from US2/T022–T023 and category/severity values from Foundational).

### Parallel Opportunities

- T004 and T005 (detectors vs. policy category wiring) run in parallel — different crates.
- All test-writing tasks within a phase (T010–T014, T018–T021, T026–T029) marked `[P]` run in parallel — distinct test functions, mostly distinct files.
- T034, T035, T037 (docs) run in parallel with each other and with T039 (version bump) — distinct files.
- US1 and US2 implementation (Phases 3 and 4) can proceed in parallel by different contributors once Phase 2 lands — US1 touches `etherfence-core`, US2 touches `etherfence-detectors`/`etherfence-report`, no file overlap. US3 should follow after both since it renders both the score (US1) and evidence (indirectly, via the general finding list).

---

## Implementation Strategy

### MVP First

1. Complete Phase 1 (Setup) and Phase 2 (Foundational) — required for anything to compile.
2. Complete Phase 3 (US1) — this alone fixes the core trust problem (score no longer penalizes inventory).
3. **STOP and VALIDATE**: run quickstart.md steps 2–4.
4. Continue with US2 (evidence) and US3 (presentation) to complete the full required-outcomes list.

### Incremental Delivery

Foundational → US1 (score fix, MVP) → US2 (evidence) → US3 (presentation) → Polish (docs/versioning/quality gate) → PR.

---

## Phase 7: Post-Review Remediation (PR #50 review round 1)

A human review of PR #50 found four issues that the original implementation and its tests did not actually satisfy. Each was verified against the code before fixing, then fixed with a regression test:

- [X] T043 [P] **Verbose lacked real category separation (FR-009 violation)** — `render_scan_verbose` had no distinct Inventory observations / Informational findings / Protection coverage sections; findings were only badge-differentiated inside one mixed "Clients & servers" list, and Protection coverage was never rendered in verbose at all. Fixed: restricted "Clients & servers" to `category == risk` findings; added `render_category_section` (grouped by agent) for Inventory/Informational; extracted a shared `coverage::render_protection_coverage` used by both concise and verbose. Test: `scan_verbose_has_four_distinct_category_sections_in_order_with_no_duplication` in `crates/etherfence-cli/tests/cli_scan.rs` (headings, ordering, population, non-duplication).
- [X] T044 [P] **"No secret value ever appears" was not true** — raw `command`/`args[N]`/`url` values were copied verbatim into evidence, so a credential embedded in a URL query string or a `--token=...` argument would leak unredacted; the shipped test only checked two known env-var values. Fixed in `crates/etherfence-detectors/src/lib.rs`: `safe_evidence_value`/`sanitize_url_for_evidence`/`redact_secret_looking_segment` strip URL userinfo/query/fragment and redact secret-shaped `key=value` segments before they reach evidence (bounded heuristic, not a general scanner — documented precisely in `docs/json-schema.md`'s "Evidence redaction scope"). Tests: `url_evidence_strips_userinfo_query_and_fragment`, `args_evidence_redacts_secret_shaped_key_value_segments`.
- [X] T045 [P] **Inventory observations contradicted the header count at non-default `--severity-threshold`** — the section derived its counts from post-severity-filtered `report.findings`, so `--severity-threshold high` showed "No inventory observations recorded" while "MCP servers N configured" (from unfiltered inventory) still showed N. Fixed: both concise and verbose now derive server/env-var counts directly from `report.inventory`, never from findings, so the section is threshold-invariant by construction. Test: `inventory_observations_are_unaffected_by_severity_threshold` (low/medium/high).
- [X] T046 [P] **`--fail-on`/`--fail-on-new` compatibility impact was undocumented and untested** — reclassifying `EF-MCP-000`/`EF-MCP-004` to `info` silently changes `--fail-on low`/`--fail-on-new low` behavior (they no longer trip on inventory-only fixtures) while `docs/json-schema.md` claimed no effect on exit codes. Decision: keep both flags severity-only, not category-aware (documented explicitly, not silently). Test: `fail_on_and_fail_on_new_remain_severity_only_not_category_aware` against the `safe-home` fixture (low/medium/high/info, plus `--fail-on-new`).
- [X] T047 Corrected the "every evidence entry is `field=value`" overclaim in `docs/json-schema.md` and `contracts/scoring-and-evidence.md`: scoped explicitly to MCP heuristic findings (`EF-MCP-000/001/002/003/004`, `EF-SEC-001`); `EF-CFG-001` and `EF-TIRITH-*` evidence formats are unchanged and called out as such.
- [X] T048 Updated CHANGELOG, README, and `spec.md` Assumptions to match the corrected, honest scope of T043–T047 (real verbose sections, bounded redaction, `--fail-on` decision).

Full quality gate (`cargo fmt --check`, `clippy -D warnings`, `cargo test` workspace-wide, `cargo build`, `git diff --check`) re-run clean after this phase.
