# Tasks: Protection Coverage (v1.7.2)

## Task ordering

Tasks are grouped by user story and ordered by dependency. Tasks marked `[P]`
can run in parallel (different files, no dependency conflict).

---

## Phase 1: Core types (etherfence-core)

- [ ] **T1** — Add `CoverageStatus` enum, `ServerCoverage` struct, and
  `ProtectionCoverage` struct to `crates/etherfence-core/src/lib.rs`.
  Place after existing type definitions (near `PolicyMetadata`). Include
  `Serialize`/`Deserialize` derives with `#[serde(rename_all = "snake_case")]`
  on the enum.

- [ ] **T2** — Add `protection_coverage: Option<ProtectionCoverage>` field to
  `ScanReport` in `crates/etherfence-core/src/lib.rs` with
  `#[serde(skip_serializing_if = "Option::is_none")]`.

- [ ] **T3** — Update `schema_version` in `ScanReport` construction site:
  `crates/etherfence-cli/src/main.rs` line 2276: change
  `"ef-scan-report/v0.1.1"` to `"ef-scan-report/v0.1.2"`.

---

## Phase 2: Policy evaluator (etherfence-policy) [P with Phase 1 after T1]

- [ ] **T4** — Add `coverage: ProtectionCoverage` field to `PolicyEvaluation`
  struct in `crates/etherfence-policy/src/lib.rs`.

- [ ] **T5** — In `evaluate_policy()`, after the existing inventory loop
  (before the Tirith check at line ~172), build a `Vec<ServerCoverage>`:
  - For each `(item, server)` in the main loop:
    - Skip Tirith items (add `NotApplicable` entry)
    - Look up agent policy via existing `agent_policy()` method
    - Determine `CoverageStatus`: `NoPolicyForAgent` if no section,
      `EmptyAllowlist` if allowlist is empty, `Protected` if `same_name`
      match, `Unprotected` otherwise
  - Sort the vec by `(agent.key(), config_path, server_name)`
  - Count statuses to populate `ProtectionCoverage` totals
  - Assign to `evaluation.coverage`

- [ ] **T6** — Update `evaluate_policy()` return to include coverage.

---

## Phase 3: CLI integration (etherfence-cli) [P with Phase 2 after T4]

- [ ] **T7** — In `run_scan()` (`crates/etherfence-cli/src/main.rs` ~line 2230),
  after `evaluate_policy()`, extract `evaluation.coverage` and set it on
  `report.protection_coverage` before constructing the `ScanReport`.

---

## Phase 4: Report rendering (etherfence-report) [P — all 4 sub-tasks]

- [ ] **T8** [P] — Add protection coverage section to `render_scan_summary()`
  in `crates/etherfence-cli/src/main.rs` (between "Clients" and "Priority
  findings"). Use themed `✓ protected` / `✗ unprotected` markers grouped
  by client. Show `~ no policy` for `NoPolicyForAgent`, `— empty allowlist`
  for `EmptyAllowlist`.

- [ ] **T9** [P] — Add coverage badges to `to_human()` inventory listing in
  `crates/etherfence-report/src/lib.rs`. For each MCP server in the inventory,
  annotate with `[protected]` / `[unprotected]` / `[no policy]` /
  `[empty allowlist]`.

- [ ] **T10** [P] — Add `## Protection Coverage` table to `to_markdown()` in
  `crates/etherfence-report/src/lib.rs`. Table columns: Agent, Server, Status,
  Config. Only render when `protection_coverage` is `Some`.

- [ ] **T11** [P] — Add `protectionCoverage` to `sarif_run_properties()` in
  `crates/etherfence-report/src/lib.rs`. Serialize the coverage struct
  into the properties JSON.

---

## Phase 5: Fixtures

- [ ] **T12** — Create `tests/fixtures/coverage-home/` with:
  - `~/.claude.json` — 3 MCP servers (filesystem, memory, github)
  - `~/.cursor/mcp.json` — 2 MCP servers (filesystem, browser-tools)
  - `~/.vscode/mcp.json` — 1 MCP server (lint)
  - A coverage test policy at `tests/fixtures/coverage-home/policy.toml`
    with `[agents."Claude Code"]` allowing filesystem+memory,
    `[agents.Cursor]` allowing only filesystem,
    no `[agents."VS Code"]` section,
    `[agents.Hermes]` with empty `allowed_mcp_servers = []`.

---

## Phase 6: Tests [P — coverage + report + existing tests]

- [ ] **T13** [P] — Add policy unit tests in `crates/etherfence-policy/src/lib.rs`:
  - `coverage_all_protected` — all servers in allowlist
  - `coverage_mixed` — protected + unprotected
  - `coverage_no_agent_section` — `NoPolicyForAgent`
  - `coverage_empty_allowlist` — `EmptyAllowlist`
  - `coverage_tirith_excluded` — `NotApplicable`
  - `coverage_deterministic_order` — stable sort

- [ ] **T14** [P] — Add integration tests in `crates/etherfence-cli/tests/cli_scan_coverage.rs`:
  - `scan_with_policy_shows_coverage_human` — human summary shows coverage
  - `scan_with_policy_shows_coverage_json` — JSON has `protection_coverage`
  - `scan_with_policy_shows_coverage_markdown` — Markdown has coverage table
  - `scan_with_policy_shows_coverage_sarif` — SARIF has `protectionCoverage`
  - `scan_without_policy_no_coverage` — no coverage field without `--policy`
  - `scan_coverage_counts_match` — totals match per-server statuses
  - `scan_coverage_tirith_not_counted` — Tirith excluded from coverage

- [ ] **T15** [P] — Add report unit tests in `crates/etherfence-report/src/lib.rs`:
  - `coverage_human_badges` — verbose output shows coverage badges
  - `coverage_markdown_table` — markdown includes coverage table
  - `coverage_sarif_properties` — SARIF has coverage in properties
  - `no_coverage_when_none` — no coverage output when `protection_coverage` is None

---

## Phase 7: Version bump and docs [P — all sub-tasks]

- [ ] **T16** [P] — Bump workspace version in `Cargo.toml`:
  `[workspace.package] version = "1.7.2"`.

- [ ] **T17** [P] — Add `## [1.7.2]` section to `CHANGELOG.md` documenting
  the protection coverage feature.

- [ ] **T18** [P] — Add v1.7.2 entry to `docs/roadmap.md` under a new
  `## v1.7.2 - protection coverage` section.

- [ ] **T19** [P] — Update `docs/architecture.md`: bump the version reference
  from `v0.4.1` to `v1.7.2` in the opening line (it's stale).

- [ ] **T20** [P] — Update `docs/json-schema.md`: document the new
  `protection_coverage` field and bump the schema version reference.

- [ ] **T21** — Update version assertions in test files:
  - `crates/etherfence-cli/tests/cli_scan.rs` — all `assert_eq!(json["version"], "1.6.2")` → `"1.7.2"`
  - Any other test referencing `CARGO_PKG_VERSION` or hardcoded version

- [ ] **T22** — Regenerate `docs/examples/ci/baseline.json`:
  ```bash
  cargo run -- scan --root tests/fixtures/home --write-baseline docs/examples/ci/baseline.json
  ```
  …and verify the version field: `head -5 docs/examples/ci/baseline.json`.

---

## Phase 8: Verification

- [ ] **T23** — Run full local gate:
  ```bash
  cargo fmt --check
  cargo clippy --all-targets --all-features -- -D warnings
  cargo test --workspace
  cargo build
  git diff --check
  ```
  All must pass with zero warnings and zero test failures.

---

## Dependency graph

```
T1 → T2 → T3 → T4 → T5 → T6 → T7
                          ↘
T8, T9, T10, T11 (parallel after T7)
T12 (after T1, before T13/T14)
T13, T14, T15 (parallel after T6, T12)
T16 → T21 → T22 (sequential)
T17, T18, T19, T20 (parallel after T16)
T23 (after all)

Implementation order:
Phase 1 → Phase 2 → Phase 3 → Phase 4+5 in parallel → Phase 6 in parallel → Phase 7 → Phase 8
```

## Estimated effort

| Phase | Tasks | Est. |
|---|---|---|
| Core types | T1-T3 | Small (3 type defs + 1 version string) |
| Policy evaluator | T4-T6 | Medium (coverage logic in existing loop) |
| CLI integration | T7 | Small (1 field assignment) |
| Report rendering | T8-T11 | Medium (4 format renderers) |
| Fixtures | T12 | Small (5 files) |
| Tests | T13-T15 | Medium (15 test cases) |
| Docs + version | T16-T22 | Small (7 files) |
| Verification | T23 | Small (1 command sequence) |
| **Total** | **23 tasks** | **~4-6 hours** |
