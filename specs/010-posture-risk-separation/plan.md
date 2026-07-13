# Implementation Plan: Posture Score Risk Separation

**Branch**: `feature/v1.7.4-posture-risk-separation` | **Date**: 2026-07-13 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/010-posture-risk-separation/spec.md`

## Summary

Separate inventory observations from actionable security risk in EtherFence's posture score by adding an explicit `FindingCategory` (`Inventory` / `Informational` / `Risk`) to every `Finding`, independent of `Severity`. `EF-MCP-000` (server configured) and `EF-MCP-004` (generic env-var presence) move to `Severity::Info` + `category: Inventory` and no longer affect the score; `EF-SEC-001` (secret-shaped env name) and all other existing risk findings are unchanged. Evidence strings across all heuristic detectors are normalized to a `field=value` format (`server=`, `command=`, `args[N]=`, `url=`, `env=`) so every finding names the specific server field it matched, without ever exposing a secret value. Human output (concise and verbose) gains explicit four-way grouping: inventory observations, scored risk findings, informational findings, and the pre-existing protection/policy coverage section. Both `ef-scan-report` (v0.1.2→v0.1.3) and `ef-baseline` (v0.1.3→v0.1.4) schema versions bump, since baseline files embed full `Finding` structs; old baseline files fail closed via the existing schema-version check rather than silently mismatching fingerprints.

## Technical Context

**Language/Version**: Rust (workspace edition per `Cargo.toml`, unchanged)

**Primary Dependencies**: `serde`/`serde_json` (existing), no new external crates

**Storage**: N/A — local files only (scan output, optional baseline JSON file), unchanged

**Testing**: `cargo test` (workspace), fixture-backed integration tests in `crates/etherfence-cli/tests/`, inline unit tests in `etherfence-core`/`etherfence-detectors`/`etherfence-policy`/`etherfence-report`

**Target Platform**: Linux and Windows (CI matrix), unchanged

**Project Type**: CLI (single Rust workspace, multiple crates) — see CLAUDE.md workspace architecture

**Performance Goals**: N/A — no performance-sensitive path touched; scoring/evidence formatting remain O(findings) with no new I/O

**Constraints**: Must preserve determinism (Principle IV) across human/verbose/JSON/Markdown/SARIF; must not weaken `EF-SEC-001`; must not introduce a daemon/hook/network path (N/A — no such surface touched); evidence must never contain secret values

**Scale/Scope**: Touches `etherfence-core` (Finding/FindingCategory/PostureSummary), `etherfence-detectors` (evidence formatting + category/severity assignment), `etherfence-policy` (category assignment for `EF-POL-*`, unchanged severities), `etherfence-report` (Markdown/SARIF/`to_human`), `etherfence-cli` (`main.rs` concise renderer + `verbose.rs`), plus docs/CHANGELOG/schema docs/CI baseline fixture and the version bump. No new crates, no new CLI flags, no new commands.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-checked after Phase 1 design — no changes to this section were needed after design; all decisions in research.md/data-model.md were made to keep every principle below satisfied.*

| # | Principle | Assessment |
|---|---|---|
| I | Security-First, Deny-by-Default | PASS. `FindingCategory::Risk` is the `#[default]` fallback for any legacy/ambiguous data (most conservative: unknown data is treated as scored, not silently excluded). `mcp-proxy` fail-closed behavior is untouched (this feature only touches `scan`). |
| II | Local-First Operation | PASS. No daemon, hook, network, or new dependency introduced. Pure data-model/rendering change to the existing local `scan` command. |
| III | Truth in Claims | PASS. The change directly improves truth-in-claims: the score will no longer overstate risk from pure inventory facts, and evidence will honestly show what triggered each finding. No new blocking/enforcement language is introduced (scan remains scan-only). |
| IV | Deterministic Output | PASS. Category assignment is a fixed, static per-`FindingKind` mapping (no runtime/order dependency); evidence formatting is deterministic given the same server config; human-output grouping order is fixed (`Inventory, Informational, Risk` then severity-desc-then-id within Risk). Verified by regression tests requiring repeat-run byte-identical output. |
| V | Fixture-Backed Findings and Classifications | PASS. The category assignment for every existing finding ID is fixed in a table (`contracts/scoring-and-evidence.md`) and will be asserted by fixture-backed tests for every ID before being described as scoring/non-scoring — no new "advisory" or unproven classification is introduced. |
| VI | Schema Compatibility and Explicit Versioning | PASS. Both `ef-scan-report` (v0.1.2→v0.1.3) and `ef-baseline` (v0.1.3→v0.1.4) bump explicitly, documented in CHANGELOG and `docs/json-schema.md`, with fixture/test coverage of the new fields and the fail-closed old-baseline rejection path. |
| VII | Fail-Closed Runtime Proxy Behavior | N/A. This feature does not touch `mcp-proxy` or any runtime enforcement path — `scan` only. |
| VIII | Audit Log Safety | PASS. Evidence normalization explicitly excludes secret values (only names/patterns), consistent with existing redaction in `etherfence-inventory`; a regression test asserts no secret value appears in any output format. `mcp-proxy`'s audit log is untouched. |
| IX | Complete Release Packaging | PASS. README, CHANGELOG, `docs/json-schema.md`, `docs/sarif.md` (if it names evidence/category), `docs/examples/ci/baseline.json`, and this Spec Kit feature folder all update in the same change; both Linux and Windows are unaffected platform-specifically (pure data/text logic, no OS-specific code), reviewed for compatibility in the quality-gate phase. |
| X | Scope Discipline | PASS. Non-goals explicitly declared in spec.md (`.mcp.json` discovery, Hermes write support, compound risk detection, baseline UX redesign, focus modes) and honored — `EF-CFG-001` is deliberately left unchanged rather than opportunistically reclassified, to avoid scope creep beyond the named required outcomes. |
| XI | Catalog Classification Discipline | N/A. No new client/server catalog entries are added; only existing, already fixture-tested finding IDs are reclassified. |

No violations requiring the Complexity Tracking table below (left empty).

## Project Structure

### Documentation (this feature)

```text
specs/010-posture-risk-separation/
├── plan.md                              # This file
├── research.md                          # Phase 0 output
├── data-model.md                        # Phase 1 output
├── quickstart.md                        # Phase 1 output
├── contracts/
│   ├── scoring-and-evidence.md          # Phase 1 output
│   └── human-output-grouping.md         # Phase 1 output
├── checklists/requirements.md
└── tasks.md                             # Phase 2 output (/speckit-tasks — not created by this command)
```

### Source Code (repository root)

```text
crates/
├── etherfence-core/src/lib.rs           # FindingCategory enum; Finding.category field;
│                                         # PostureSummary::from_findings category gate
├── etherfence-detectors/src/lib.rs      # FindingTemplate gains `category`; severity change
│                                         # for EF-MCP-000/EF-MCP-004; evidence-labeling helpers
├── etherfence-policy/src/lib.rs         # category: Risk for all EF-POL-* constructors
├── etherfence-report/src/lib.rs         # SARIF properties.etherfenceCategory; Markdown/to_human
│                                         # category+severity grouping
├── etherfence-cli/src/main.rs           # render_scan_summary: two new sections; schema version
│                                         # literal bump; version bump to 1.7.4
├── etherfence-cli/src/verbose.rs        # render_findings badge by category; consolidated
│                                         # recommendations filtered by category
└── etherfence-cli/tests/cli_scan.rs     # updated + new assertions (existing test file, no new file)

docs/
├── json-schema.md                       # Finding.category row; score formula wording;
│                                         # schema version bumps; posture.* semantics note
├── sarif.md                             # note new properties.etherfenceCategory field (if applicable)
├── examples/ci/baseline.json            # regenerated: new schema_version, category field,
│                                         # updated severities/evidence/fingerprints for
│                                         # EF-MCP-000/004 and EF-MCP-001/002/003/EF-SEC-001

README.md                                # posture scoring section updated
CHANGELOG.md                             # [Unreleased] → [1.7.4], new subsection
Cargo.toml                               # version 1.7.3 → 1.7.4
```

**Structure Decision**: No new crates, files, or directories beyond the Spec Kit feature folder and the regenerated CI baseline fixture. This is a targeted, in-place change to five existing crates plus docs, matching the existing single-workspace-CLI structure documented in CLAUDE.md.

## Complexity Tracking

*No Constitution Check violations — table intentionally left empty.*
