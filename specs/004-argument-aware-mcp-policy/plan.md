# Implementation Plan: Argument-Aware MCP Runtime Policy

**Branch**: `spec/v1.5.0-argument-aware-mcp-policy` | **Date**: 2026-07-11 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/004-argument-aware-mcp-policy/spec.md`

## Summary

Add a versioned extension `ef-mcp-policy/v0.2` to the existing runtime MCP proxy policy engine
(`crates/etherfence-mcp`) that lets an operator constrain individual `tools/call` argument fields
and MCP method `params` fields — required/forbidden keys, exact-value/enum allowlists, string
length/prefix, numeric bounds, array length/allowed-elements, and URL scheme/host/port/path — via a
bounded, declarative selector syntax, evaluated by the same shared decision functions the live
`mcp-proxy` and the serverless `mcp-policy check` command already both call. `ef-mcp-policy/v0.1`
policies keep parsing and evaluating identically; v0.2 constructs are only legal under
`schema_version = "ef-mcp-policy/v0.2"`.

## Technical Context

**Language/Version**: Rust 1.75+ (workspace `edition = "2021"`, matches `Cargo.toml`)

**Primary Dependencies**: `serde`/`serde_json`/`toml` (already workspace dependencies). No new
external crates: URL parsing, host normalization, and selector resolution are hand-rolled in
`crates/etherfence-mcp/src/policy.rs`, following the existing hand-rolled `LexicalPath`-style
normalizer already used for filesystem path guards in that file, to keep the dependency surface,
audit posture, and determinism guarantees unchanged.

**Storage**: N/A — policy files are local TOML read via the existing
`etherfence_core::read_bounded_text_file` bounded-read helper; no new storage.

**Testing**: `cargo test --workspace` (unit tests in `policy.rs`/`proxy.rs`/`policy_ux.rs`/
`audit.rs`, plus `crates/etherfence-cli/tests/cli_mcp_policy.rs` integration tests).

**Target Platform**: Linux and Windows (both are release-supported per constitution Principle IX);
selector/URL/guard logic must be deterministic on both.

**Project Type**: CLI + local runtime proxy (single Rust workspace, no frontend/backend split).

**Performance Goals**: Not a throughput-sensitive path (one JSON-RPC line at a time, human/agent
request cadence); no explicit numeric target — must not introduce unbounded work per request
(selector depth and guard counts are bounded at policy-load time, so per-request evaluation cost is
bounded by policy size, not request content).

**Constraints**: Fail-closed per guard (spec FR-013); no daemon/background service (constitution
Principle II); no new dependency; audit/CLI output must never contain a guarded value (spec
FR-027); exactly one decision-evaluation code path shared by `mcp-proxy` and `mcp-policy check`
(spec FR-020).

**Scale/Scope**: Extends one crate's policy schema/evaluator and one CLI subcommand family; touches
`crates/etherfence-mcp` (schema, evaluator, audit) and `crates/etherfence-cli` (`mcp-policy`
subcommands), plus example policies, fixtures, and docs. No new crate is added.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Check | Status |
|---|---|---|
| I. Security-First, Deny-by-Default | Every new guard primitive fails closed (deny) on missing key, wrong type, malformed value, or unresolved selector (spec FR-013); unconfigured guards make no behavior change (FR-014). | PASS |
| II. Local-First Operation | No new dependency, no daemon, no network call added; URL guard *parses* a value already present in the request, it never dials out. | PASS |
| III. Truth in Claims | Spec FR-030 explicitly forbids claiming a guarded tool call makes the server "safe"; roadmap/threat-model/compatibility docs state guard coverage is scoped to configured fields only, and `docs/mcp-proxy.md`'s stale "no argument-aware rules"/"argument values never inspected" limitations bullets were corrected in the same change. | PASS |
| IV. Deterministic Output | Guard evaluation is pure (JSON value in, decision out); `fields`/guard tables are `BTreeMap`-keyed (like existing `path_rules`/`servers`) so TOML key order never affects output; audit records remain deterministic JSONL. | PASS |
| V. Fixture-Backed Findings | Every guard primitive has a fixture-backed allow + fail-closed-deny test (policy.rs `v2_guard_tests`, proxy.rs integration tests, CLI `us1`-`us4` tests) — SC-002 met. | PASS |
| VI. Schema Compatibility and Explicit Versioning | New schema id `ef-mcp-policy/v0.2`; v0.1 unaffected (164 pre-existing tests unchanged); v0.2-only constructs rejected under `schema_version = v0.1` (FR-003); CHANGELOG and `docs/mcp-policy-ux.md` schema docs updated in the same change. | PASS |
| VII. Fail-Closed Runtime Proxy Behavior | Guard decisions only ever narrow (deny) an otherwise-allowed call; a missing/invalid v0.2 construct is a policy *load* failure (proxy never starts), matching existing v0.1 behavior for malformed path rules. | PASS |
| VIII. Audit Log Safety | `AuditRecord` gains guard identifier fields only (key/selector/reason-category), never the evaluated value or full arguments/params object (FR-027); redaction tests in `audit.rs` and CLI `never_echoes_a_denied_credential_bearing_url` test. | PASS |
| IX. Complete Release Packaging | Docs (`mcp-policy-ux`/`mcp-proxy`/`mcp-proxy-operator-guide`/`architecture`/`threat-model`/`roadmap`/`mcp-compatibility-matrix`/`ci`), CHANGELOG, and four new example policies updated in the same release; workspace version bumped to 1.5.0; Windows-style URL/selector cases follow the existing Windows path-guard test pattern (selector/URL logic is platform-independent string handling, no OS-specific path separator dependency). | PASS |
| X. Scope Discipline | Non-goals explicit in spec (FR-028–FR-030): no NLP/prompt-injection detection, no regex/scripting language, no DLP/SQL analysis, no remote proxying, no daemon. | PASS |
| XI. Catalog Classification Discipline | N/A — this feature does not touch client/server catalogs. | N/A |

No violations requiring the Complexity Tracking table.

## Project Structure

### Documentation (this feature)

```text
specs/004-argument-aware-mcp-policy/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md         # Phase 1 output
├── quickstart.md         # Phase 1 output
├── contracts/
│   └── ef-mcp-policy-v0.2.md   # TOML schema contract for the new guard constructs
├── checklists/
│   └── requirements.md
└── tasks.md              # Phase 2 output (/speckit-tasks — not created here)
```

### Source Code (repository root)

```text
crates/etherfence-mcp/src/
├── policy.rs        # Schema types (FieldGuard, ScalarValue, selector parsing/resolution),
│                     # validation, decide_tool_argument_guards, decide_method_param_guards
├── proxy.rs          # inspect_client_line / inspect_server_line wiring (call sites only;
│                     # no decision logic duplicated here)
├── policy_ux.rs       # explain_policy / dry_run_check extended to surface v0.2 guards
│                       # (no new decision logic — calls the same proxy.rs functions)
├── audit.rs           # AuditRecord guard fields + redaction
└── unicode.rs          # Reused as-is for selector segment / guard-type-name hygiene

crates/etherfence-cli/src/
└── main.rs            # mcp-policy validate/explain/init/check CLI surface, new init profile

examples/policies/
├── mcp-github-scoped-orgs.toml           # User Story 1
├── mcp-messaging-named-destinations.toml # User Story 2
├── mcp-browser-approved-hosts.toml       # User Story 3
└── mcp-readonly-operation-guard.toml     # User Story 4

crates/etherfence-cli/tests/cli_mcp_policy.rs   # CLI integration tests for the above
docs/                                            # schema/migration/operator/architecture/
                                                  # threat-model/roadmap/compatibility updates
```

**Structure Decision**: This is an additive change entirely within the existing two-crate policy
surface (`etherfence-mcp` for schema/evaluator/audit, `etherfence-cli` for the `mcp-policy`
subcommand family). No new crate, module boundary, or project layout change is introduced; new
Rust items live in the existing files that already own each concern (schema/decision logic in
`policy.rs`, call-site wiring in `proxy.rs`, CLI-facing summaries in `policy_ux.rs`, redaction in
`audit.rs`), matching how the v0.1 path guard itself is organized today.

## Complexity Tracking

*No Constitution Check violations — table not needed.*
