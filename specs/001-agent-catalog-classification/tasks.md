---

description: "Task list for Expanded Agent Integration Catalog and MCP Server Classification (v1.2.0)"
---

# Tasks: Expanded Agent Integration Catalog and MCP Server Classification

**Input**: Design documents from `/specs/001-agent-catalog-classification/`
**Prerequisites**: plan.md, spec.md, data-model.md, contracts/, research.md, quickstart.md (all present)

**Tests**: Included — the spec's Success Criteria (SC-002, SC-005, SC-007) and Constitution
Principle V/XI require fixture-backed tests before any tier/rule is claimed as supported, so
test tasks are mandatory here, not optional.

**Organization**: Tasks are grouped by user story (US1/US2/US3 from spec.md) to enable
independent implementation and testing of each story, per plan.md's Project Structure and
Fixture/Test Strategy sections.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel among tasks that are concurrently unblocked (different files, and
  either no dependency on an incomplete task, or all of that task's own dependencies are already
  satisfied by an earlier phase/checkpoint) — not "zero dependencies anywhere in the whole graph."
  See the Dependencies & Execution Order section below for the exact unlock points.
- **[Story]**: US1, US2, or US3 — maps to spec.md's prioritized user stories
- All file paths are relative to the repository root

## Path Conventions

Existing Cargo workspace layout (see plan.md "Project Structure" for the full map):
`crates/etherfence-core/src/lib.rs`, `crates/etherfence-inventory/src/lib.rs`,
`crates/etherfence-setup/src/{lib.rs,catalog.rs,classification.rs}`,
`crates/etherfence-cli/src/main.rs`, `crates/etherfence-cli/tests/`, `tests/fixtures/`.

---

## Phase 1: Setup

**Purpose**: Establish a clean baseline and shared fixture skeleton before any feature code changes.

- [X] T001 Run the full verification gate (`cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --workspace`, `cargo build`, `git diff --check`) on the unmodified branch and record it passes, establishing the pre-feature baseline referenced by the Release Gate Checklist in plan.md.
- [X] T002 [P] Create empty fixture home `tests/fixtures/empty-home/` (directory only, no client config files) per plan.md Fixture Strategy, used by US1's "zero clients detected" test.

**Checkpoint**: Baseline green; new empty-home fixture directory exists.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Shared CLI output-format plumbing used by both `setup catalog` (US1) and the
extended `setup detect` (US2/US3). No user story can wire its `--format` flag without this.

**⚠️ CRITICAL**: Complete before starting US1, US2, or US3 CLI-wiring tasks.

- [X] T003 Add `#[derive(Debug, Clone, Copy, ValueEnum)] enum SetupOutputFormat { Human, Json }` to `crates/etherfence-cli/src/main.rs` (research.md Decision 5) — a narrower enum than the existing `OutputFormat`, offering only `human`/`json`.

**Checkpoint**: `SetupOutputFormat` compiles and is available for use by US1 and US2/US3 CLI tasks.

---

## Phase 3: User Story 1 - See client detection support level at a glance (Priority: P1) 🎯 MVP

**Goal**: `etherfence setup catalog` prints all 10 fixed clients with an honest support tier
and local-presence status, deterministically, read-only, in human and JSON formats.

**Independent Test**: Run `etherfence setup catalog --root <fixture>` against `tests/fixtures/home`,
`tests/fixtures/empty-home`, and `tests/fixtures/windows-home`; verify exactly 10 rows in the
fixed order with correct tier/presence per `contracts/setup-catalog.md`, independent of any MCP
server classification behavior (US2/US3 code paths are not touched by this story).

### Tests for User Story 1

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation (no `catalog` module/command exists yet)**

- [X] T004 [P] [US1] Unit tests in `crates/etherfence-setup/src/catalog.rs` asserting the exact `Vec<CatalogEntry>` (all 10 clients, fixed order, correct tier, correct presence/paths) for fixture roots `tests/fixtures/home`, `tests/fixtures/empty-home`, `tests/fixtures/windows-home`, `tests/fixtures/malformed-home`, `tests/fixtures/multi-path-home` (asserting the `cursor` entry's `config_paths` contains both discovered paths in `CANDIDATES` declaration order — spec Edge Case 2, data-model.md `CatalogEntry` "Multi-path ordering").
- [X] T005 [P] [US1] CLI integration tests in `crates/etherfence-cli/tests/cli_setup.rs` (or a new `crates/etherfence-cli/tests/cli_setup_catalog.rs`) for: `setup catalog` human output row count/order/content against `tests/fixtures/home` and `tests/fixtures/empty-home`; `setup catalog --format json` validates against the `ef-setup-catalog/v0.1` shape in `contracts/setup-catalog.md`; `setup catalog --format json --root tests/fixtures/multi-path-home` asserts the `cursor` entry's `configPaths` contains both fixture paths in `CANDIDATES` order (spec Edge Case 2); two consecutive runs produce byte-identical stdout (SC-002); the command creates/modifies no file (extend the existing `setup_detect_and_plan_are_redacted_and_read_only`-style assertion); exit code is always `0` (FR-006a).

### Implementation for User Story 1

- [X] T006 [US1] Add 5 new `AgentKind` variants (`Hermes`, `Antigravity`, `OpenCode`, `Cline`, `RooCode`) to `crates/etherfence-core/src/lib.rs`, with matching `display_name()`/`key()` arms (data-model.md "AgentKind (extended)").
- [X] T007 [P] [US1] Add `PresenceOnly` `CANDIDATES` entries (Linux and Windows paths) for the 5 new `AgentKind` variants in `crates/etherfence-inventory/src/lib.rs`, mirroring the existing `Tirith` `PresenceOnly` precedent (research.md Decision 2). Depends on T006.
- [X] T008 [US1] Create `crates/etherfence-setup/src/catalog.rs`: `CatalogClient` (10 variants + `ALL` const, data-model.md order), `CatalogSupportTier` enum, `CatalogEntry` struct, the fixed static tier table (Claude-style/Cursor/VS Code = fixture-verified; Windsurf/Gemini CLI/Codex CLI = detect-only; Hermes/Antigravity/OpenCode/Cline-RooCode = advisory-only — research.md Decision 2), and pure `pub fn catalog(root: &Path) -> Vec<CatalogEntry>` built on `etherfence_inventory::discover`, collecting `config_paths` in `discover()`'s existing order with no re-sorting (data-model.md `CatalogEntry` "Multi-path ordering"). Depends on T006, T007.
- [X] T009 [US1] Wire `mod catalog;` and re-export its public types from `crates/etherfence-setup/src/lib.rs`. Depends on T008.
- [X] T010 [US1] Add `SetupCommand::Catalog { root: Option<PathBuf>, format: SetupOutputFormat }` variant, its `run_setup_command` match arm, and `render_setup_catalog_human`/`render_setup_catalog_json` functions to `crates/etherfence-cli/src/main.rs`, per `contracts/setup-catalog.md`. Depends on T003 (Foundational), T009.
- [X] T011 [P] [US1] Add local-presence fixture marker files for the 5 new advisory-only clients under `tests/fixtures/home/` (e.g. `.hermes/config.json`, `.antigravity/config.json`, `.opencode/config.json`, `.cline/config.json`, `.roo/config.json` — exact names per the candidate paths added in T007) and equivalent entries under `tests/fixtures/windows-home/AppData/Roaming/...`. Depends on T007.
- [X] T012 [P] [US1] Create `tests/fixtures/multi-path-home/` with a Cursor config present at both `.cursor/mcp.json` and `.cursor/settings.json` (both already-existing `CANDIDATES` entries for `AgentKind::Cursor` — no inventory code change needed), proving a client can have more than one discovered configuration path without any being dropped (spec Edge Case 2). Depends on T007 (fixture layout mirrors the `CANDIDATES` entries it adds).

**Checkpoint**: `etherfence setup catalog` is fully functional and independently testable; T004/T005 now pass.

---

## Phase 4: User Story 2 - Understand what a locally configured MCP server can do (Priority: P1)

**Goal**: Every MCP server surfaced by `etherfence setup detect` carries a multi-label capability
classification derived purely from static local config, with `unknown` as the honest fallback.

**Independent Test**: Run `etherfence setup detect --format json --root <fixture>` against fixture
MCP server configs covering each curated rule (individually and combined) and one unmatched
server; verify the exact expected label set per fixture, and confirm (by code inspection / the
absence of any network or process API in `classification.rs`) that no network access or process
start ever occurs.

### Tests for User Story 2

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation (no `classification` module exists yet)**

- [X] T013 [P] [US2] Unit tests in `crates/etherfence-setup/src/classification.rs`: one table-driven case per curated rule (filesystem, shell / command execution, network, and at least one combined multi-label server), one case asserting the `[Unknown]` fallback for an unmatched server, and an assertion that `ClassifiedCapabilities.labels` is never empty across all cases (FR-013). Assert `labels` values are the `kebab-case` `Serialize` tokens (e.g. `"shell-command-execution"`, not `"shell / command execution"` — data-model.md "JSON vs. human representation"), and separately assert `human_label()` returns the friendly spec-taxonomy phrasing for each variant.
- [X] T014 [P] [US2] CLI integration tests extending `crates/etherfence-cli/tests/cli_setup.rs`: `setup detect --format json` output includes `capabilities.labels`/`capabilities.evidence` per `contracts/setup-detect-classification.md` for `tests/fixtures/home`, asserting `labels` entries are `kebab-case` tokens; `setup plan` and `setup doctor` human output remain byte-identical to their pre-v1.2.0 fixtures (proving no leakage of the new `SetupServer` fields into commands that don't render them).

### Implementation for User Story 2

- [X] T015 [US2] Create `crates/etherfence-setup/src/classification.rs`: `CapabilityLabel` enum (10 variants + `ALL` const, canonical most-restrictive-first order per data-model.md) with `#[serde(rename_all = "kebab-case")]` and a separate `pub fn human_label(self) -> &'static str` returning the friendly spec-taxonomy phrasing (data-model.md "JSON vs. human representation"), `ClassifiedCapabilities` struct, the curated command/package → label(s) signature table (research.md Decision 6 — exact-match only, no substring/regex heuristics), and pure `pub fn classify_server(server: &McpServer) -> ClassifiedCapabilities`.
- [X] T016 [US2] Wire `mod classification;` and re-export its public types from `crates/etherfence-setup/src/lib.rs`. Depends on T015.
- [X] T017 [US2] Add `capabilities: ClassifiedCapabilities` field to `SetupServer` in `crates/etherfence-setup/src/lib.rs`; update `server_from_mcp` to call `classification::classify_server`. Depends on T016.
- [X] T018 [US2] Add `format: SetupOutputFormat` field to `SetupCommand::Detect` in `crates/etherfence-cli/src/main.rs` (default `Human`, preserving current output exactly when omitted); add JSON rendering (`ef-setup-detect/v0.1`, `capabilities.labels` as `kebab-case` tokens) and extend `render_setup_detect` human output with a `capabilities: ...` line per server using `human_label()`, without altering any existing line. Depends on T003 (Foundational), T017.
- [X] T019 [P] [US2] Add MCP server fixture entries matching curated classification rules to `tests/fixtures/home/.claude.json` (filesystem match), `tests/fixtures/home/.cursor/mcp.json` (shell / command execution match), `tests/fixtures/home/.vscode/mcp.json` (no match → unknown), and `tests/fixtures/home/.windsurf`, `.gemini`, `.codex` configs (network match, and one combined filesystem + shell / command execution multi-label server), per plan.md Fixture Strategy. Depends on T015.
- [X] T020 [P] [US2] Add one MCP server entry with an unparseable/malformed shape to `tests/fixtures/malformed-home/` proving the "malformed config → unknown, no crash" edge case (spec Edge Case 5). Depends on T015.

**Checkpoint**: `etherfence setup detect` now reports capability labels for every server; T013/T014 pass; US1 remains unaffected and independently passing.

---

## Phase 5: User Story 3 - Get a safer starting policy than "allow everything" (Priority: P2)

**Goal**: Every classified MCP server gets a deterministic, deny-by-default starter-policy
recommendation, with `needs_review` escalation for `unknown`, `shell / command execution`, and
`identity / auth` labels, and `Allow` never produced in v1.2.0.

**Independent Test**: Feed the classified fixture servers from US2 through the recommendation
step; verify every recommendation's `tier` is `deny`, and `needs_review` is `true` exactly when
the label set contains `unknown`, `shell / command execution`, or `identity / auth` (and `false`
otherwise), matching quickstart.md step 3.

### Tests for User Story 3

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation (no `recommend` function exists yet)**

- [X] T021 [P] [US3] Unit tests in `crates/etherfence-setup/src/classification.rs`: table-driven test over all combinations of the three escalating labels (`unknown`, `shell / command execution`, `identity / auth`) asserting the exact `needs_review` boolean-OR result (research.md Decision 3); an assertion that `tier` is `RecommendationTier::Deny` for every case exercised in this release; an assertion that no test case ever constructs `RecommendationTier::Allow`.
- [X] T022 [P] [US3] CLI integration test extending `crates/etherfence-cli/tests/cli_setup.rs`: parse `setup detect --format json` output against every checked-in fixture and assert every `recommendation.tier == "deny"` and the `needs_review` escalation rule holds using the `kebab-case` label tokens (mirrors quickstart.md step 3).

### Implementation for User Story 3

- [X] T023 [US3] Add `RecommendationTier` enum and `StarterPolicyRecommendation` struct to `crates/etherfence-setup/src/classification.rs`; implement pure `pub fn recommend(capabilities: &ClassifiedCapabilities) -> StarterPolicyRecommendation` per the derivation rule in data-model.md (`tier` always `Deny`; `needs_review` per Decision 3; deterministic generated `rationale`). Depends on T015.
- [X] T024 [US3] Add `recommendation: StarterPolicyRecommendation` field to `SetupServer` in `crates/etherfence-setup/src/lib.rs`; update `server_from_mcp` to call `classification::recommend`. Depends on T017, T023.
- [X] T025 [US3] Extend `render_setup_detect` human output and the JSON rendering added in T018 (`crates/etherfence-cli/src/main.rs`) to include `recommendation.tier`/`needs_review`/`rationale` per `contracts/setup-detect-classification.md`. Depends on T018, T024.

**Checkpoint**: All three user stories are independently functional; starter-policy recommendations are live end-to-end.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Documentation, release-gate verification, and optional tier-promotion stretch work — required by Constitution Principle IX (Complete Release Packaging) before v1.2.0 ships.

- [X] T026 [P] Update `README.md`: add `etherfence setup catalog` to the "Command overview" table, add a short example subsection, and list `ef-setup-catalog/v0.1`/`ef-setup-detect/v0.1` in the documentation table (plan.md Documentation Updates).
- [X] T027 [P] Update `docs/setup-onboarding.md`: add a new `## etherfence setup catalog` section documenting the four tiers and fixed 10-client list; update the existing "v1.1.0 advisory catalog" section to cross-reference the more granular v1.2.0 tiering without conflating `WriteSupport` (write-capability) with `CatalogSupportTier` (detection confidence) — research.md Decision 2.
- [X] T028 [P] Add `ef-setup-catalog/v0.1` and `ef-setup-detect/v0.1` sections (field tables + example payloads, including the `kebab-case` `CapabilityLabel` token list) to `docs/json-schema.md`, matching the existing `ef-scan-report` documentation style.
- [X] T029 [P] Add a short paragraph to `docs/architecture.md` and `docs/threat-model.md` describing catalog/classification as new, local-only, read-only components with no new trust boundary.
- [X] T030 [P] Append a v1.2.0 entry to `docs/roadmap.md`.
- [X] T031 [P] Add a `## [1.2.0]` section to `CHANGELOG.md` (Added: `setup catalog`, classification, both new schemas, 5 new advisory-only clients; explicit note that no `mcp-proxy`/`scan` behavior changed).
- [X] T032 [P] Add an automated documentation-honesty test (e.g. `crates/etherfence-cli/tests/setup_catalog_docs.rs`, mirroring the existing `mcp_operator_guide.rs`/`install_docs.rs` docs-drift pattern) that greps README/docs/CLI output for prohibited enforcement/blocking language around catalog/classification, making SC-006/FR-026 a regression-tested property rather than a manual release-gate step alone. Depends on T026, T027.
- [X] T033 Run the full Release Gate Checklist from plan.md end-to-end (`cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --workspace` on Linux and Windows CI, `cargo build`, `git diff --check`, plus the fixture/tier/no-`Allow`/no-regression/doc-language checks it lists) and confirm every checklist item. Depends on all prior tasks. (Linux run confirmed locally; Windows leg runs via the existing `rust (windows-latest)` CI matrix job on push/PR — not separately reproducible in this sandbox.)
- [X] T034 Run `quickstart.md` end-to-end manually against a local build to confirm the documented commands produce the documented output. Depends on all prior tasks.
- [ ] T035 [P] Optional/stretch: add catalog-specific fixture tests promoting Windsurf, Gemini CLI, and/or Codex CLI from `detect-only` to `fixture-verified` (research.md Decision 2) — only if time permits; not required to ship v1.2.0. Skipped: explicitly optional per plan.md/research.md, not required to ship.

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — start immediately.
- **Foundational (Phase 2)**: Depends on Setup — BLOCKS all user story CLI-wiring tasks (T010, T018).
- **User Story 1 (Phase 3)**: Depends on Foundational (T003) for T010 only; T004/T006–T009/T011/T012 have no cross-story dependency. Fully independent of US2/US3.
- **User Story 2 (Phase 4)**: Depends on Foundational (T003) for T018 only; otherwise independent of US1. Independent of US3 except that US3 builds on US2's types.
- **User Story 3 (Phase 5)**: Depends on User Story 2 (T015/T017) — recommendations are derived from classification output. Independent of US1.
- **Polish (Phase 6)**: Depends on all three user stories being complete.

### User Story Dependencies

- **US1 (P1)**: No dependency on US2 or US3 — independently implementable and testable first.
- **US2 (P1)**: No dependency on US1. No dependency on US3.
- **US3 (P2)**: Depends on US2 (`ClassifiedCapabilities` is the direct input to `recommend`). Independent of US1.

### Within Each User Story

- Tests (T004/T005, T013/T014, T021/T022) MUST be written and FAIL before their story's implementation tasks.
- Core types/module before CLI wiring: T008→T009→T010 (US1); T015→T016→T017→T018 (US2); T023→T024→T025 (US3).
- Fixtures (T011, T012, T019/T020) can proceed in parallel with core module implementation since they touch different files.

### Parallel Opportunities

- T002 (Setup) is parallel with T001.
- Within US1: T004, T005, T011, T012 are `[P]` once their prerequisite (T007, where applicable) is done; T007 is `[P]` relative to nothing else in flight at that point but depends on T006.
- Within US2: T013, T014, T019, T020 are `[P]`.
- Within US3: T021, T022 are `[P]`.
- **US1 and US2 can be implemented in parallel by different people/agents** once Foundational (T003) is done — they touch disjoint files except both eventually edit `crates/etherfence-cli/src/main.rs` (T010 vs. T018) and `crates/etherfence-setup/src/lib.rs` (T009 vs. T016/T017), so treat those specific file edits as sequential checkpoints even though the stories are logically independent.
- US3 cannot start its core task (T023) until US2's T015/T017 land.
- All of Phase 6 (T026–T032, T035) is `[P]`; T033 and T034 depend on everything before them.

---

## Parallel Example: User Story 1

```bash
# After T003 (Foundational) is done, launch US1's independent pieces together:
Task: "Unit tests in crates/etherfence-setup/src/catalog.rs asserting exact CatalogEntry vecs"
Task: "CLI integration tests in crates/etherfence-cli/tests/cli_setup.rs for setup catalog"
Task: "Add PresenceOnly CANDIDATES entries in crates/etherfence-inventory/src/lib.rs (after T006)"
Task: "Add presence fixture markers under tests/fixtures/home/ and tests/fixtures/windows-home/ (after T007)"
Task: "Create tests/fixtures/multi-path-home/ with a two-path Cursor config (after T007)"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational
3. Complete Phase 3: User Story 1
4. **STOP and VALIDATE**: Run `etherfence setup catalog` against `tests/fixtures/home` and
   `tests/fixtures/empty-home`; confirm all 10 rows, correct tiers, determinism (quickstart.md
   step 1). This alone satisfies the release's most-visible new command.

### Incremental Delivery

1. Setup + Foundational → foundation ready.
2. Add US1 → test independently → `etherfence setup catalog` ships (MVP).
3. Add US2 → test independently → `etherfence setup detect` gains capability labels.
4. Add US3 → test independently → starter-policy recommendations complete the release's safety
   payoff.
5. Polish (Phase 6) → docs, release gate, optional tier promotion → v1.2.0 ships.

### Parallel Team Strategy

With two implementers: once Foundational is done, one takes US1 (client catalog, touches
`etherfence-core`/`etherfence-inventory`/`catalog.rs`) while the other takes US2 then US3
(classification, touches only `classification.rs` and shared `SetupServer`/CLI edits) — the only
coordination point is the shared edits to `crates/etherfence-cli/src/main.rs` and
`crates/etherfence-setup/src/lib.rs` noted above.
