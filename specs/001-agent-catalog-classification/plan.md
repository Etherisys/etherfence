# Implementation Plan: Expanded Agent Integration Catalog and MCP Server Classification

**Branch**: `spec/v1.2.0-expanded-agent-integration-catalog` | **Date**: 2026-07-10 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/001-agent-catalog-classification/spec.md`

## Summary

Add a new, purely informational `etherfence setup catalog` command that
prints a fixed 10-client compatibility matrix (fixture-verified /
detect-only / advisory-only support tiers, plus local presence), and
extend the existing `etherfence setup detect` command with static,
local-only, multi-label MCP server capability classification and
deny-by-default starter-policy recommendations. Both commands gain a
`--format human|json` flag. No new crate, daemon, network access, or
runtime-enforcement change is introduced; all new logic lives in the
existing `etherfence-core` (data types) and `etherfence-setup` (catalog +
classification logic) crates, rendered by `etherfence-cli`.

## Technical Context

**Language/Version**: Rust (2021 edition), `stable` toolchain (matches
existing `dtolnay/rust-toolchain@...` pin in `.github/workflows/ci.yml`)

**Primary Dependencies**: `clap` (derive, CLI), `serde`/`serde_json` (JSON
output), `anyhow` (errors) — all already workspace dependencies; no new
dependency is required.

**Storage**: None (local filesystem reads only; no database, no state
files written by this feature).

**Testing**: `cargo test --workspace` — `cargo test -p etherfence-setup`
for unit-level catalog/classification logic, `cargo test -p
etherfence-cli` for CLI integration tests against checked-in fixture home
directories under `tests/fixtures/`.

**Target Platform**: Linux and Windows (existing CI matrix:
`rust (ubuntu-latest)`, `rust (windows-latest)`).

**Project Type**: Single Rust Cargo workspace, CLI tool (`crates/etherfence-cli`)
backed by library crates.

**Performance Goals**: Not a distinguishing constraint — catalog and
classification operate over the same small, already-bounded local config
set that `scan`/`setup detect` already read (existing
`MAX_CONFIG_FILE_BYTES`-bounded reads apply); no new performance target.

**Constraints**: Fully local, read-only, offline; deterministic output
(stable ordering/fingerprints) required across Linux and Windows per
FR-020; no live MCP protocol interaction (FR-008/FR-009/FR-023); no
command execution from inspected configs (FR-011).

**Scale/Scope**: Fixed 10-client catalog; MCP server classification scales
with however many MCP servers a user has configured locally (typically
single digits to low tens) — no scale requirement beyond correctness and
determinism.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-checked after Phase 1 design (see "Post-Design Re-Check" below).*

| Principle | Compliance approach |
|---|---|
| I. Security-First, Deny-by-Default | Starter-policy recommendations default to `Deny`; `Allow` is never emitted in v1.2.0 (no fixture-verified safe-capability mapping exists yet — see research.md Decision 3). Unrecognized servers/clients resolve to `unknown`/`advisory-only`, never a permissive default. |
| II. Local-First Operation | No daemon, network call, shell hook, browser hook, or kernel hook is introduced. `setup catalog` and the extended `setup detect` are synchronous, invoker-run, local-filesystem-only commands, consistent with existing `setup` family behavior. |
| III. Truth in Claims | Catalog support tiers are named honestly (fixture-verified vs. detect-only vs. advisory-only vs. unknown); docs/CLI text describe this feature as posture/classification/starter-policy guidance, never enforcement (FR-026). |
| IV. Deterministic Output | Catalog rows are emitted in the fixed declared client order; capability labels are emitted in one fixed canonical taxonomy order (see data-model.md); JSON and human output share the same underlying sorted data — see research.md Decision 4 for the cross-platform path-normalization approach. |
| V. Fixture-Backed Findings and Classifications / XI. Catalog Classification Discipline | Only clients with a checked-in fixture asserting the exact catalog row are marked `fixture-verified`; only capability-label rules with a checked-in fixture/test are wired into the classifier — everything else is `detect-only`/`advisory-only`/`unknown`, never silently promoted (see Fixture Strategy below and research.md Decision 2). |
| VI. Schema Compatibility and Explicit Versioning | Two new versioned schemas are introduced: `ef-setup-catalog/v0.1` and `ef-setup-detect/v0.1` (the latter is the *first* JSON schema for `setup detect`, which today is human-text-only — an additive, non-breaking addition). Both are documented in `docs/json-schema.md`. |
| VII. Fail-Closed Runtime Proxy Behavior | Not touched by this feature — `mcp-proxy` code is untouched (FR-022). |
| VIII. Audit Log Safety | Not applicable — this feature writes no audit log and reads no MCP traffic; it reads local config files already read by `setup detect`/`scan` today. |
| IX. Complete Release Packaging | Fixtures and CLI integration tests run on both Linux and Windows via existing CI matrix; docs/CHANGELOG/schema docs updated in the same change (see Documentation Updates below). |
| X. Scope Discipline | Fixed 10-client list, static-only classification, no CI-gate flag on `setup catalog` — all explicitly bounded by the spec's Out of Scope section and re-affirmed here; no additional command or crate is added beyond what's needed. |

No violations requiring justification were identified. Complexity Tracking is intentionally empty.

## Project Structure

### Documentation (this feature)

```text
specs/001-agent-catalog-classification/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md         # Phase 1 output
├── quickstart.md         # Phase 1 output
├── contracts/             # Phase 1 output
│   ├── setup-catalog.md
│   └── setup-detect-classification.md
└── tasks.md              # Phase 2 output (/speckit-tasks — not created here)
```

### Source Code (repository root)

```text
crates/etherfence-core/src/lib.rs        # AgentKind gains 5 new presence-detectable
                                          # variants (Hermes, Antigravity, OpenCode,
                                          # Cline, RooCode); no removals/renames.

crates/etherfence-inventory/src/lib.rs   # CANDIDATES table gains PresenceOnly entries
                                          # (Linux + Windows paths) for the 5 new
                                          # AgentKind variants, mirroring the existing
                                          # Tirith PresenceOnly precedent.

crates/etherfence-setup/src/
├── lib.rs                 # Existing detect()/plan()/apply()/rollback()/doctor()
│                           # unchanged in signature/behavior; server_from_mcp()
│                           # gains a call into classification (new SetupServer
│                           # fields: capabilities, recommendation).
├── catalog.rs              # NEW: pure fn `catalog(root: &Path) -> Vec<CatalogEntry>`
│                           # — the fixed 10-client matrix, presence lookup only.
└── classification.rs       # NEW: pure fns `classify_server(&McpServer) ->
                            # Vec<CapabilityLabel>` and `recommend(&[CapabilityLabel])
                            # -> StarterPolicyRecommendation`; curated evidence-rule
                            # table lives here.

crates/etherfence-cli/src/main.rs        # New `SetupCommand::Catalog { root, format }`
                                          # variant; `SetupCommand::Detect` gains
                                          # `format` flag; new SetupOutputFormat enum
                                          # (Human, Json); new render_setup_catalog_*
                                          # and JSON-rendering functions for detect.

crates/etherfence-cli/tests/
├── cli_setup.rs             # Extended with catalog + classified-detect assertions,
│                             # or a new cli_setup_catalog.rs sibling file.

tests/fixtures/
├── home/                    # Extended: add presence markers for the 5 new
│                             # PresenceOnly clients; add MCP server entries in
│                             # existing client configs covering curated
│                             # classification signatures (filesystem, shell,
│                             # network, unknown-fallback).
├── windows-home/            # Same additions, Windows path shapes.
└── empty-home/               # NEW: a fixture home with none of the 10 catalog
                              # clients present, to test the "not found" row case.
```

**Structure Decision**: Everything is added to the four existing crates
that already own this responsibility (`etherfence-core` for the shared
`AgentKind`/data types, `etherfence-inventory` for local file-presence
detection, `etherfence-setup` for the `setup` command family's business
logic, `etherfence-cli` for CLI parsing/rendering only). No new crate is
introduced. This keeps classifier/catalog logic separated from CLI
rendering (new `.rs` modules in `etherfence-setup`, consumed — never
computed — by `etherfence-cli`), matches the existing single-crate-per-
concern layout, and avoids the regression risk and Scope Discipline cost
of a new crate boundary. See research.md Decision 1 for the alternative
(a dedicated `etherfence-classify` crate) and why it was rejected for
v1.2.0.

## Fixture Strategy

Every claimed tier and every wired classification rule must have a
fixture and a passing test *before* it is described as supported (FR-019,
Constitution Principle V/XI). Concretely:

| Fixture | Purpose |
|---|---|
| `tests/fixtures/home/.claude.json` (existing, extend) | Adds an MCP server entry matching the curated `filesystem` rule — proves `fixture-verified` catalog tier + a positive classification. |
| `tests/fixtures/home/.cursor/mcp.json` (existing, extend) | Adds an MCP server entry matching the curated `shell / command execution` rule — proves a second `fixture-verified` client + the `needs_review` escalation. |
| `tests/fixtures/home/.vscode/mcp.json` (existing, extend) | Adds an MCP server entry that matches **no** curated rule — proves the `unknown` fallback (FR-013) on a `fixture-verified` client. |
| `tests/fixtures/home/.windsurf`, `.gemini`, `.codex` (existing, extend as needed) | Already-present `detect-only` clients; add one MCP server each covering `network` and a combined `filesystem` + `shell / command execution` server (multi-label proof, spec Acceptance Scenario US2-2). |
| `tests/fixtures/home/.hermes`, `.antigravity`, `.opencode`, `.cline`, `.roo` (**new**, presence marker files only, mirroring `.tirith/config.toml`) | Proves `advisory-only` local-presence detection without any MCP server parsing being attempted. |
| `tests/fixtures/empty-home/` (**new**, no client dirs at all) | Proves the "zero clients detected, all 10 rows still print" edge case (spec Edge Case 1). |
| `tests/fixtures/windows-home/` (existing, extend) | Same additions as `home/`, using the existing `AppData/Roaming/...` path shapes, to prove Linux/Windows determinism (FR-020, SC-002) without relying on CI to literally diff cross-OS output — path-normalization unit tests plus mirrored fixtures give equivalent coverage on a single OS. |
| `tests/fixtures/malformed-home/` (existing, extend) | Add one entry with an unparseable/malformed MCP server config to prove the "malformed config → unknown/unreadable, no crash" edge case (spec Edge Case 5). |
| `tests/fixtures/multi-path-home/` (**new**) | A minimal fixture with a Cursor config present at both `.cursor/mcp.json` and `.cursor/settings.json` (both already-existing `CANDIDATES` entries for `AgentKind::Cursor` — no inventory code change needed), proving the "client has more than one configuration path, none dropped, deterministic order" edge case (spec Edge Case 2, FR-003, FR-020). |

**Gate**: a client may be documented/output as `fixture-verified` only
once its row-producing fixture has an accompanying test asserting the
*exact* `CatalogEntry` (tier + presence + path). A classification rule
may be wired into `classification.rs`'s curated table only once its
fixture has an accompanying test asserting the *exact*
`ClassifiedCapabilities` it produces. Windsurf/Gemini CLI/Codex CLI
promotion from `detect-only` to `fixture-verified` (Decision 2) is
optional within v1.2.0 and gated the same way — if their catalog-specific
fixture tests aren't added, they ship as `detect-only`, which is still a
fully honest, spec-compliant outcome.

## Test Strategy

1. **Unit tests, `crates/etherfence-setup/src/catalog.rs`**: assert the
   exact `Vec<CatalogEntry>` (all 10, in order, correct tier/presence) for
   each fixture home (`home`, `empty-home`, `windows-home`,
   `malformed-home`) — pure function, no process spawn needed.
2. **Unit tests, `crates/etherfence-setup/src/classification.rs`**:
   table-driven tests, one case per curated rule (filesystem, shell,
   network, combined multi-label) plus one unmatched-server case
   asserting `[Unknown]`; a separate table-driven test over all 2^3
   combinations of the three escalating labels asserting the exact
   `needs_review` value predicted by Decision 3's boolean-OR rule; an
   assertion that no test case ever produces `RecommendationTier::Allow`.
3. **CLI integration tests, `crates/etherfence-cli/tests/`**: extend
   `cli_setup.rs` (or add `cli_setup_catalog.rs`) following the existing
   `fixture_root`/`run`/`temp_home` helper pattern already in that file:
   - `setup catalog` (human + json) against `home`/`empty-home`, asserting
     row count, order, and field values per `contracts/setup-catalog.md`.
   - `setup catalog` run twice back-to-back, asserting byte-identical
     stdout (determinism, SC-002) — the existing file already has a
     read-only assertion pattern (`setup_detect_and_plan_are_redacted_and_read_only`)
     to extend for "no files created/modified" on `catalog` too.
   - `setup catalog` exit code is always `0` regardless of fixture used —
     asserts FR-006a directly.
   - `setup detect --format json`, asserting the new
     `capabilities`/`recommendation` fields per
     `contracts/setup-detect-classification.md`, and asserting
     `setup plan`/`setup doctor` human output is byte-identical to their
     pre-v1.2.0 fixtures (no leakage — plan.md Post-Design Re-Check).
4. **Workspace regression gate**: `cargo test --workspace` must remain
   fully green — this is the mechanical enforcement of SC-007 and must be
   run (not just assumed) before any tier is promoted or documented.
5. **CI platforms**: no new CI wiring needed — the existing
   `rust (ubuntu-latest)` / `rust (windows-latest)` matrix in
   `.github/workflows/ci.yml` already runs `cargo test --workspace` on
   both platforms, which is sufficient to catch any Linux/Windows
   divergence in the new fixtures/tests.

## Documentation Updates

Per Constitution Principle IX (Complete Release Packaging), all of the
following are updated in the same change as the code:

- **`README.md`**: add `etherfence setup catalog` to the "Command
  overview" table; add a short example under a new subsection (mirroring
  the existing `## \`scan\` example` / `## \`mcp-policy\` example`
  pattern); add `ef-setup-catalog/v0.1` and `ef-setup-detect/v0.1` to the
  documentation table pointing at `docs/json-schema.md`.
- **`docs/setup-onboarding.md`**: add a new `## etherfence setup catalog`
  section documenting the four tiers and the fixed 10-client list; update
  the existing "v1.1.0 advisory catalog" section to cross-reference the
  new, more granular v1.2.0 tiering (Windsurf/Gemini CLI/Codex CLI are no
  longer only "advisory" in the v1.2.0 sense — they are catalog
  `detect-only` — while remaining `WriteSupport::AdvisoryOnly` for `setup
  apply`; the doc must state both facts without conflating them, per
  research.md Decision 2).
- **`docs/json-schema.md`**: add `ef-setup-catalog/v0.1` and
  `ef-setup-detect/v0.1` sections (field tables + example payloads),
  matching the existing style used for `ef-scan-report`.
- **`docs/architecture.md`** and **`docs/threat-model.md`**: add a short
  paragraph describing catalog/classification as new, local-only,
  read-only components with no new trust boundary (they read the same
  config files `scan`/`setup detect` already read).
- **`docs/roadmap.md`**: append the v1.2.0 entry.
- **`CHANGELOG.md`**: new `## [1.2.0]` section (Added: `setup catalog`,
  classification, both new schemas, 5 new advisory-only clients; explicit
  note that no `mcp-proxy`/`scan` behavior changed).
- **No changes required**: `docs/mcp-proxy.md`, `docs/mcp-proxy-operator-guide.md`,
  `docs/mcp-policy-ux.md`, `docs/sarif.md`, `docs/ci.md` — none of these
  are touched by this feature (FR-022, out of scope).

## Release Gate Checklist

Before v1.2.0 is considered shippable, all of the following must be true
— this combines the constitution's Development Workflow gate with this
feature's spec-level Success Criteria:

- [ ] `cargo fmt --check` passes.
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passes.
- [ ] `cargo test --workspace` passes on both Linux and Windows CI runners.
- [ ] `cargo build` succeeds.
- [ ] `git diff --check` passes (no whitespace errors).
- [ ] Every `CatalogClient` marked `fixture-verified` has a passing fixture
      test asserting its exact `CatalogEntry` (SC-005).
- [ ] Every wired capability-label rule has a passing fixture test
      asserting its exact `ClassifiedCapabilities` (SC-005).
- [ ] No test asserts or observes `RecommendationTier::Allow` anywhere in
      v1.2.0 output (Decision 3 invariant).
- [ ] `setup catalog` always exits `0` across every fixture used in tests
      (FR-006a).
- [ ] `setup plan` and `setup doctor` human output is byte-identical to
      their pre-v1.2.0 fixtures (no observable change — FR-027).
- [ ] `README.md`, `docs/setup-onboarding.md`, `docs/json-schema.md`,
      `docs/architecture.md`, `docs/threat-model.md`, `docs/roadmap.md`,
      and `CHANGELOG.md` are all updated (Documentation Updates above).
- [ ] No documentation or command output describes catalog/classification
      as enforcement/blocking (grep for prohibited language, mirroring the
      existing v1.0.1 wording-fix precedent in `CHANGELOG.md`).
- [ ] Spec's Out of Scope items are re-confirmed absent from the diff:
      no live MCP probing, no client beyond the fixed 10, no config
      auto-mutation, no `mcp-proxy`/`ef-mcp-policy` enforcement change, no
      `--fail-on` flag on `setup catalog`.

## Complexity Tracking

*No Constitution Check violations were identified; this table is intentionally empty.*

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| — | — | — |

## Post-Design Re-Check

Re-evaluated after Phase 1 (data-model.md, contracts/, quickstart.md):

- **AgentKind extension** (5 new variants) touches exactly two exhaustive
  `match` sites in `etherfence-core` (`display_name`, `key`); every other
  workspace use of `AgentKind` either matches on specific known variants
  with an existing wildcard arm (`etherfence-setup::write_support_for_agent`)
  or compares by equality (`== AgentKind::Tirith`, `== AgentKind::ClaudeCode`),
  confirmed by inspection — so FR-027 (no regression) holds; the compiler
  enforces the two exhaustive-match updates.
- **`SetupServer`'s two new public fields** (`capabilities`,
  `recommendation`) are additive; no existing external construction site
  exists outside `etherfence-setup::server_from_mcp`, so `setup plan` and
  `setup doctor` rendering — which read only the fields they already read
  — are unchanged in observable output, satisfying "no change to existing
  setup semantics."
- No new violations were introduced by the data model or contracts;
  Constitution Check table above still holds.
