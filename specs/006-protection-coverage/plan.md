# Plan: Protection Coverage (v1.7.2)

## Architecture Decision

### Where coverage data lives

**Decision**: Add `protection_coverage: Option<ProtectionCoverage>` as a new
optional field on `ScanReport`.

**Alternatives considered**:
1. *Put it inside `PolicyMetadata`* — Rejected because coverage is not
   metadata *about* the policy; it's a cross-cutting summary of the
   policy's effect on detected servers.
2. *Put it in `Summary`* — Rejected because `Summary` is count-only and
   doesn't have per-server detail.
3. *New top-level field on `ScanReport`* — **Selected**. This is clean,
   additive, and mirrors how `policy` and `baseline` are already optional
   top-level fields.

### Where coverage is computed

**Decision**: Extend `PolicyEvaluation` to carry coverage data, then populate
`ProtectionCoverage` from it in `run_scan()`.

**Rationale**: The policy evaluator is the only place that iterates every
MCP server and knows the agent→allowlist mapping. Computing coverage there
avoids duplicating the inventory walk. The `PolicyEvaluation` struct grows
a `coverage: ProtectionCoverage` field, which `run_scan()` extracts and
attaches to `ScanReport`.

### Schema version bump

**Decision**: Bump `ef-scan-report/v0.1.1` → `ef-scan-report/v0.1.2`.

**Rationale**: Adding an optional field is backward-compatible (existing
consumers that don't know about `protection_coverage` will ignore it), so
a MINOR bump is correct under the constitution's versioning rules.

## Implementation Strategy

### Crate impact (minimal)

| Crate | Change |
|---|---|
| `etherfence-core` | Add `ProtectionCoverage`, `ServerCoverage`, `CoverageStatus` types; add `protection_coverage` field to `ScanReport` |
| `etherfence-policy` | Extend `PolicyEvaluation` to carry coverage; compute coverage in `evaluate_policy()` |
| `etherfence-cli` | Populate `ScanReport.protection_coverage` from policy eval; pass to renderers |
| `etherfence-report` | Render coverage in human summary, human verbose, Markdown, JSON (via serde), SARIF |

Crates NOT touched: `etherfence-inventory`, `etherfence-detectors`,
`etherfence-mcp`, `etherfence-setup`.

### Phase 1: Core types (etherfence-core)

Add to `crates/etherfence-core/src/lib.rs`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    Covered,
    NotCovered,
    NoPolicyForAgent,
    EmptyAllowlist,
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerCoverage {
    pub agent: AgentKind,
    pub server_name: String,
    pub status: CoverageStatus,
    pub config_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectionCoverage {
    pub total_servers: usize,
    pub covered: usize,
    pub uncovered: usize,
    pub no_policy_for_agent: usize,
    pub empty_allowlist: usize,
    pub not_applicable: usize,
    pub servers: Vec<ServerCoverage>,
}
```

Add to `ScanReport`:
```rust
#[serde(skip_serializing_if = "Option::is_none")]
pub protection_coverage: Option<ProtectionCoverage>,
```

### Phase 2: Policy evaluator (etherfence-policy)

Extend `PolicyEvaluation`:
```rust
pub struct PolicyEvaluation {
    // ... existing fields ...
    pub coverage: ProtectionCoverage,
}
```

In `evaluate_policy()`, after the existing inventory walk:
- Build a `Vec<ServerCoverage>` during the same loop that checks MCP servers
- For each (item, server) pair:
  - Look up agent policy via `self.agent_policy(item.agent)`
  - Determine `CoverageStatus`:
    - Tirith → `NotApplicable`
    - No agent policy → `NoPolicyForAgent`
    - Empty allowlist → `EmptyAllowlist`
    - Server in allowlist → `Covered`
    - Server not in allowlist → `NotCovered`
- After the loop, construct `ProtectionCoverage` with counts and the sorted
  server list.

### Phase 3: CLI integration (etherfence-cli)

In `run_scan()` (line ~2230):
- After `evaluate_policy()`, extract `evaluation.coverage` and set it on
  the `ScanReport`.
- The `ScanReport` is already serialized to JSON via serde, so the new
  field appears automatically in JSON output when `--policy` is active.

### Phase 4: Report rendering (etherfence-report)

#### Human summary (`render_scan_summary`)
Add after the "Clients" section and before "Priority findings":
```
Protection coverage
──────────────────
✓ covered    claude-code / filesystem         (~/.claude.json)
✗ uncovered  claude-code / github             (~/.claude.json)
✓ covered    cursor / filesystem              (~/.cursor/mcp.json)
```

#### Human verbose (`to_human`)
Annotate each MCP server in the inventory listing with its coverage status.

#### Markdown (`to_markdown`)
Add `## Protection Coverage` section with a table.

#### SARIF (`to_sarif`)
Add `protectionCoverage` to `sarif_run_properties()`.

### Phase 5: Tests

New fixtures: `tests/fixtures/coverage-home/` with:
- A Claude config with 3 MCP servers (2 in policy allowlist, 1 not)
- A Cursor config with 2 MCP servers (none in policy allowlist)
- A VS Code config with 1 MCP server (agent not in policy at all)
- A Tirith config (should be excluded from coverage)

New tests:
- `cli_scan_coverage.rs` — integration tests for all output formats
- Policy unit tests for coverage computation
- Report unit tests for coverage rendering

### Phase 6: Docs and version bump

Files to update:
- `Cargo.toml` — version to 1.7.2
- `CHANGELOG.md` — new `## [1.7.2]` section
- `docs/roadmap.md` — add v1.7.2 entry
- `docs/architecture.md` — update version reference
- `docs/json-schema.md` — document `protection_coverage` field
- `docs/examples/ci/baseline.json` — regenerate
- `crates/etherfence-cli/tests/cli_scan.rs` — update version assertions
- `.specify/feature.json` — already updated

## Risk Assessment

| Risk | Likelihood | Mitigation |
|---|---|---|
| Schema version breakage | Low | Additive field only; serde `skip_serializing_if = "Option::is_none"` |
| Policy evaluator performance regression | Very Low | Coverage is computed in the same pass as findings; no additional inventory walk |
| Human output breaking scripts | Low | Coverage section only appears when `--policy` is active; existing no-policy output is byte-identical |
| Tirith exclusion regression | Low | Existing `if item.agent == AgentKind::Tirith { continue; }` guard is preserved |

## Verification

```bash
# Local gate
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
cargo build
git diff --check
```

## Traceability

| Requirement | Implementation |
|---|---|
| FR1 — Coverage computation | `etherfence_policy::evaluate_policy()` extended |
| FR2 — Coverage status values | `CoverageStatus` enum in `etherfence-core` |
| FR3 — JSON shape | Serde-derived serialization on `ProtectionCoverage` |
| FR4 — Human summary | `render_scan_summary()` in `etherfence-cli` |
| FR5 — Human verbose | `to_human()` in `etherfence-report` |
| FR6 — Markdown | `to_markdown()` in `etherfence-report` |
| FR7 — SARIF | `to_sarif()` / `sarif_run_properties()` in `etherfence-report` |
| FR8 — No-policy behavior | `Option<ProtectionCoverage>` — absent when no policy |
| FR9 — Deterministic ordering | Sort by agent key, config path, server name |
| FR10 — Schema version | Bump `ef-scan-report/v0.1.1` → `v0.1.2` |
