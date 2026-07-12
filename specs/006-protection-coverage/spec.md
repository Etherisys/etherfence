# Spec: Protection Coverage (v1.7.2)

## Feature ID
`006-protection-coverage`

## Status
Draft — ready for plan phase

## Overview

Extend `etherfence scan` so users can immediately see which detected MCP servers
are actually covered by an active scan policy, not just which servers exist
or what risks they have. This release answers: **"What is EtherFence protecting?"**

The feature adds one new additive, optional section to the scan output across
all formats (human summary, human verbose, JSON, Markdown, SARIF) that maps
each detected MCP server to its protection status under the currently loaded
policy.

## Motivation

Today when a user runs `etherfence scan --policy strict.toml`:

- The summary shows total findings counts and a policy line like
  `Policy: strict — checks=12, pass=8, violations=4`.
- The `pass` count tells the user *how many* servers passed, but not *which* ones.
- The `violations` generate `EF-POL-001` findings listing each unexpected server,
  but there is no positive list of "these servers are covered."
- A user cannot answer "what is EtherFence protecting?" without manually
  cross-referencing inventory output with the policy file.

v1.7.2 fixes this by adding a **Protection Coverage** summary that lists every
detected MCP server alongside its protection status, so the answer is immediate
and scannable.

Posture scoring (e.g., a "protection score" or weighted risk metric) is
explicitly deferred to v1.7.3 (Effective Posture). This release is purely
about visibility: showing what IS and IS NOT covered, without computing
a score from it.

## User Stories

### US1 — Protection visibility in human summary (P1)
As a security-conscious operator running `etherfence scan --policy strict.toml`,
I want to see a "Protection coverage" section in the human summary that lists
which MCP servers are covered and which are not, so I can immediately
understand my coverage without reading the full verbose report or the policy file.

**Acceptance**: When a policy is active, the human summary shows a "Protection
coverage" section between "Clients" and "Priority findings" with a per-server
status line. When no policy is active, the section is absent.

### US2 — Protection visibility in verbose human output (P1)
As an operator running `etherfence scan --policy strict.toml --verbose`,
I want the full human report to include protection coverage per server in the
inventory section, so I have complete information when doing detailed reviews.

**Acceptance**: The verbose human output includes `[covered]` / `[uncovered]`
badges on each MCP server in the inventory listing.

### US3 — Protection coverage in JSON output (P1)
As a CI pipeline consuming `etherfence scan --format json --policy ci.toml`,
I want a `protection_coverage` object in the JSON report so my downstream
dashboards and alerting can consume coverage data programmatically.

**Acceptance**: JSON output includes an optional `protection_coverage` field
with `total_servers`, `covered`, `uncovered`, and a `servers` array of
`{agent, server_name, status, config_path}` objects. The field is absent when
no policy is loaded.

### US4 — Protection coverage in Markdown output (P2)
As a reviewer reading a scan report in a PR comment, I want the Markdown
report to include a protection coverage table so I can assess coverage
without accessing the machine.

**Acceptance**: Markdown output includes a "## Protection Coverage" section
with a table listing each server and its status when a policy is active.

### US5 — Protection coverage in SARIF output (P2)
As a CI pipeline producing SARIF, I want protection coverage metadata in
the SARIF `run.properties` so coverage data is available in SARIF consumers.

**Acceptance**: SARIF `run.properties` includes `protectionCoverage` with the
same shape as the JSON `protection_coverage` field.

### US6 — No breaking changes to existing output (P1)
As an existing user of `etherfence scan` without `--policy`, I want the output
to be byte-identical to v1.6.x output so my scripts and CI gates are unaffected.

**Acceptance**: Running `etherfence scan` (no `--policy`) produces output that
is byte-identical to v1.6.2 output. Running with `--policy` adds the new
coverage section but otherwise preserves existing structure and field names.

## Functional Requirements

### FR1 — Coverage computation
The system SHALL compute protection coverage for every detected MCP server when
a scan policy (`--policy` or `--policy-profile`) is active.

### FR2 — Coverage status values
Each server SHALL have exactly one of these coverage statuses:

| Status | Meaning |
|---|---|
| `covered` | Server name appears in the agent's `allowed_mcp_servers` list; no EF-POL-001 violation generated |
| `uncovered` | Server name does NOT appear in the agent's `allowed_mcp_servers` list; EF-POL-001 violation generated |
| `no_policy_for_agent` | The policy has no `[agents.<name>]` section for this agent type at all |
| `empty_allowlist` | The agent's policy section exists but `allowed_mcp_servers` is empty (implicitly allows all) |
| `not_applicable` | The agent type is Tirith (policy evaluation skips Tirith inventory items) |

### FR3 — Coverage data shape (JSON)
```json
{
  "protection_coverage": {
    "total_servers": 8,
    "covered": 5,
    "uncovered": 2,
    "no_policy_for_agent": 0,
    "empty_allowlist": 0,
    "not_applicable": 1,
    "servers": [
      {
        "agent": "claude-code",
        "server_name": "filesystem",
        "status": "covered",
        "config_path": "~/.claude.json"
      }
    ]
  }
}
```

### FR4 — Human summary coverage section
When a policy is active, the default human scan output SHALL include a
"Protection coverage" section between "Clients" and "Priority findings".
The section SHALL list each server with a `✓ covered` or `✗ uncovered`
marker, grouped by client.

### FR5 — Human verbose coverage
The verbose human output SHALL annotate each MCP server in the inventory
listing with its coverage status badge.

### FR6 — Markdown coverage
The Markdown output SHALL include a `## Protection Coverage` section with a
table listing agent, server name, status, and config path when a policy is active.

### FR7 — SARIF coverage
The SARIF output SHALL include `protectionCoverage` in `run.properties` with
the same structure as the JSON coverage object.

### FR8 — No-policy behavior
When no `--policy` or `--policy-profile` is provided, SHALL NOT emit any
protection coverage data in any output format.

### FR9 — Deterministic ordering
Server coverage entries SHALL be ordered deterministically: by agent key,
then by config path, then by server name. This matches the existing inventory
ordering.

### FR10 — Schema version
The scan report schema version SHALL be updated from `ef-scan-report/v0.1.1`
to `ef-scan-report/v0.1.2` to reflect the new optional field.

## Entities

### ProtectionCoverage (new, on ScanReport)
- `total_servers: usize` — total MCP servers across all inventory items (excluding Tirith)
- `covered: usize` — count of servers with status `covered`
- `uncovered: usize` — count of servers with status `uncovered`
- `no_policy_for_agent: usize` — count where no agent policy section exists
- `empty_allowlist: usize` — count where allowlist is empty
- `not_applicable: usize` — count of Tirith servers (policy evaluation skips them)
- `servers: Vec<ServerCoverage>` — per-server details

### ServerCoverage (new)
- `agent: AgentKind` — which AI client agent
- `server_name: String` — MCP server name as configured
- `status: CoverageStatus` — protection status
- `config_path: String` — tilde-display config path

### CoverageStatus (new enum)
- `Covered`
- `NotCovered`
- `NoPolicyForAgent`
- `EmptyAllowlist`
- `NotApplicable`

## Edge Cases

1. **No MCP servers detected** → `protection_coverage` has `total_servers: 0`
   and empty `servers` array.
2. **Policy has no `[agents]` sections at all** → every server gets
   `no_policy_for_agent`.
3. **Policy has `[agents.claude-code]` with empty `allowed_mcp_servers`** →
   every Claude Code server gets `empty_allowlist` (implicitly allows all,
   no violation).
4. **Multiple config files for the same agent** → each config file's servers
   are listed separately; coverage is computed per-server, per-config.
5. **Same server name in multiple configs** → each occurrence is a separate
   coverage entry (different `config_path`).
6. **Tirith inventory items** → `not_applicable`; Tirith is excluded from
   coverage counting because policy evaluation skips Tirith inventory items.
7. **Agent display name vs agent key matching** → the policy evaluator already
   matches by `agent.display_name()` then falls back to `agent.key()`.
   Coverage SHALL use the same matching logic.

## Success Criteria

1. `etherfence scan --policy examples/policies/strict.toml` shows a
   "Protection coverage" section in the human summary.
2. `etherfence scan --policy ... --format json` includes the
   `protection_coverage` object with correct counts.
3. `etherfence scan --policy ... --format markdown` includes the
   coverage table.
4. `etherfence scan --policy ... --format sarif` includes coverage
   in run.properties.
5. `etherfence scan` (no policy) produces byte-identical output to v1.6.2.
6. All existing tests pass with updated version assertions.
7. New fixture-backed tests cover: policy with covered+uncovered servers,
   empty allowlist, no agent section, no MCP servers, Tirith exclusion.
8. `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`,
   `cargo test --workspace`, `cargo build` all pass.

## Non-Goals (explicitly deferred)

- **Posture scoring** — computing a single numeric "protection score" or
  weighted risk metric. Deferred to v1.7.3 (Effective Posture).
- **Policy recommendation engine** — suggesting which servers to add to
  the allowlist. That belongs to `etherfence setup`, not `scan`.
- **Changes to `etherfence setup` output** — this feature targets `scan` only.
- **Changes to `etherfence mcp-proxy` or `etherfence mcp-policy`** — no
  runtime enforcement behavior changes.
- **New CLI flags** — coverage is always shown when `--policy` is active;
  no opt-in/opt-out flag in v1.7.2.

## Constitution Check

| Principle | Status | Notes |
|---|---|---|
| I. Security-First, Deny-by-Default | ✅ Pass | Coverage is purely informational; no enforcement change |
| II. Local-First Operation | ✅ Pass | No new network/daemon/service dependency |
| III. Truth in Claims | ✅ Pass | Coverage labels are factual: "covered" = in allowlist, nothing more |
| IV. Deterministic Output | ✅ Pass | Server ordering is deterministic by agent key + config path + server name |
| V. Fixture-Backed Findings | ✅ Pass | New fixtures will back every coverage status variant |
| VI. Schema Compatibility | ✅ Pass | Additive optional field; schema bump to v0.1.2 |
| VII. Fail-Closed Runtime Proxy | ✅ N/A | No proxy changes |
| VIII. Audit Log Safety | ✅ Pass | Coverage data contains only server names and agent kinds — no secrets |
| IX. Complete Release Packaging | ✅ Pass | Will include doc updates, CHANGELOG, version bump, baseline regen |
| X. Scope Discipline | ✅ Pass | Scope is protection visibility only; posture scoring is explicit non-goal |
| XI. Catalog Classification Discipline | ✅ Pass | Coverage status derives from policy matching, not catalog expansion |

## Assumptions

1. The existing `evaluate_policy()` function already walks every MCP server;
   coverage data can be computed in the same pass.
2. The `allow_empty_allowlist` behavior (empty = allows all) is intentional
   and should be reflected in coverage as `empty_allowlist` rather than
   `uncovered`.
3. Tirith inventory items are correctly excluded from MCP server coverage
   because the evaluator skips them (`if item.agent == AgentKind::Tirith`).
4. The `ef-scan-report/v0.1.2` schema bump is additive-only: no field
   renames, removals, or semantic changes to existing fields.
