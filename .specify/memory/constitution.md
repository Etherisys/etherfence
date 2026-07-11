<!--
Sync Impact Report
- Version change: (template, unratified) → 1.0.0
- Rationale: Initial ratification. .specify/memory/constitution.md previously
  held only the unfilled template; this is the first concrete constitution,
  so it is seeded at 1.0.0 rather than treated as an amendment.
- Modified principles: none (first fill; no prior named principles existed)
- Added principles:
  I. Security-First, Deny-by-Default
  II. Local-First Operation
  III. Truth in Claims
  IV. Deterministic Output
  V. Fixture-Backed Findings and Classifications
  VI. Schema Compatibility and Explicit Versioning
  VII. Fail-Closed Runtime Proxy Behavior
  VIII. Audit Log Safety
  IX. Complete Release Packaging
  X. Scope Discipline
  XI. Catalog Classification Discipline (added specifically to protect v1.2.0
      client/MCP-server catalog work against open-ended, assertion-based
      expansion)
- Added sections: Technology & Release Constraints; Development Workflow
- Removed sections: none
- Templates checked for alignment:
  ✅ .specify/templates/plan-template.md — Constitution Check gate is
     generic ("[Gates determined based on constitution file]"); no edit
     needed.
  ✅ .specify/templates/spec-template.md — no hardcoded principle
     references; no edit needed.
  ✅ .specify/templates/tasks-template.md — no hardcoded principle
     references; no edit needed.
  ✅ .specify/templates/checklist-template.md — no hardcoded principle
     references; no edit needed.
  ✅ .specify/templates/commands/ — directory does not exist in this repo;
     nothing to sync.
  ✅ README.md / CHANGELOG.md / docs/ — already consistent in substance
     with these principles (scan-only vs. proxy scoping, fail-closed
     language, generic-path fixtures, compatibility-matrix "tested vs.
     untested" framing); no factual corrections required by this
     amendment.
- Follow-up TODOs: none. RATIFICATION_DATE was not separately supplied by
  the user; it is set equal to the amendment date since this is the initial
  ratification.
-->

# EtherFence Constitution

## Core Principles

### I. Security-First, Deny-by-Default
Every feature MUST default to the least-privileged, most-conservative
behavior. When a policy, config, or classification is missing, ambiguous,
malformed, or cannot be loaded, the system MUST deny/refuse the risky
action rather than silently allow it. No feature may ship with an
implicit "allow unless denied" default anywhere in the enforcement path.

### II. Local-First Operation
EtherFence MUST remain fully local-first with no exceptions: no cloud
dependency, no daemon requirement, no hidden or background network
service, no shell hook, no browser hook, and no kernel hook. Every
command runs to completion as a local, invoker-initiated process. Adding
any of the forbidden mechanisms above is a breaking architectural change
and MUST NOT be introduced silently inside a feature or bugfix — it
requires an explicit, separately-reviewed constitutional amendment.

### III. Truth in Claims
Documentation, CLI output, scan reports, and status text MUST never
claim runtime blocking, interception, or enforcement for a capability
that is actually scan-only, setup/onboarding, catalog/classification, or
advisory. Every command and doc section MUST state plainly what it does
and does not do, including known coverage gaps. Overclaiming production
readiness, universal compatibility, or certification of any third-party
client/server is prohibited; claims MUST be scoped to what is
fixture-tested (see Principle V).

### IV. Deterministic Output
All machine- and human-readable output (JSON, Markdown, SARIF, CLI text,
audit logs) MUST be deterministic for a given input: stable ordering,
stable fingerprints/IDs, and stable field sets and names across runs on
the same input and version. Non-determinism (unsorted maps, wall-clock
timestamps in comparable fields, randomized iteration) in any output path
is treated as a defect, not a style issue, because downstream CI gates
and baselines depend on reproducibility.

### V. Fixture-Backed Findings and Classifications
No detection rule, finding, risk classification, or catalog entry (agent,
client, or MCP server category) may be described as "supported" or
relied upon in default behavior unless it is backed by a checked-in
fixture and an automated test asserting the exact expected output. Logic
without fixture coverage MUST be labeled `advisory`, `unknown`, or
`needs-review` and MUST NOT silently influence default severities,
default policy profiles, or pass/fail CI gates.

### VI. Schema Compatibility and Explicit Versioning
Every externally-consumed schema (scan report JSON/SARIF, MCP proxy
policy, baseline format) carries an explicit version identifier (e.g.
`ef-scan-report/vX.Y`, `ef-mcp-policy/vX.Y`). A change is backward
compatible only if existing consumers parsing the prior version continue
to work unmodified. Any incompatible change to field names, field
semantics, required fields, or enforcement semantics MUST bump the
schema version, MUST be called out in the CHANGELOG, and MUST update all
schema documentation in the same change.

### VII. Fail-Closed Runtime Proxy Behavior
The `mcp-proxy` runtime boundary — the only runtime-enforcement surface
in EtherFence — MUST fail closed: a missing, invalid, or unparseable
policy MUST prevent the wrapped MCP server from starting, and any
in-flight decision the proxy cannot confidently classify MUST be denied,
never forwarded. This behavior is a compatibility- and security-critical
invariant; no change may weaken it, and every change touching proxy
decision logic MUST include tests proving fail-closed behavior is
preserved for the new/changed code paths.

### VIII. Audit Log Safety
Audit logs and any other persisted operational record MUST NOT contain
secrets, raw sensitive payloads, full message/tool-call bodies, or
credentials. Logging MUST record decisions, method/tool names, and
redacted/summarized context sufficient for review, never the raw
arguments, file contents, or values that could themselves be sensitive.
Any new log field MUST be reviewed against this principle and covered by
a redaction test before it ships.

### IX. Complete Release Packaging
A release is not done until it is complete on both supported platforms
(Linux and Windows) where the changed behavior is platform-relevant, and
until docs, CHANGELOG, examples, schemas, and CI are updated to match
the shipped behavior. Code-only changes without matching documentation,
changelog entries, or example/policy updates MUST NOT be released.

### X. Scope Discipline
Every release (and every constitution-governed spec) MUST declare a
named, fixed scope and an explicit non-goals list before implementation
begins. Work that expands scope mid-release MUST either be rejected to a
future release or trigger an explicit scope amendment to the spec —
scope MUST NOT silently grow through incremental commits.

### XI. Catalog Classification Discipline
Client and MCP-server catalogs (agent detectors, integration profiles,
compatibility entries) MUST NOT expand by assertion. A client or MCP
server category may be marked `supported` only when it has explicit,
deterministic detection/classification logic *and* fixture-backed tests
proving that logic's exact output. Any catalog entry lacking both MUST be
labeled `advisory`, `unknown`, or `needs-review`, MUST be excluded from
default-supported counts and marketing/status claims, and MUST NOT
silently affect default severities or default policy profiles. This
principle exists specifically to prevent open-ended catalog growth
(e.g. adding client/server names without matching detection code and
tests) from being mistaken for verified support — see Principle V, which
this principle specializes for catalog data.

## Technology & Release Constraints

EtherFence is implemented in Rust only; no components in other languages
may be added to the enforcement or detection path. The following
capabilities remain permanently out of scope unless a future
constitutional amendment explicitly opens them: daemon mode, an API
service or control plane, shell hooks, command interception,
terminal-command scanning (duplicating Tirith), network/TLS interception,
DLP or content inspection, an auto-update system, and central/fleet
management. Fixtures, docs, and examples MUST use only generic
placeholder paths (e.g. `/home/user/...`, `/Users/example/...`,
`C:/Users/example/...`) — real personal paths MUST NOT appear in checked-in
content. Any change touching policy/config file reads MUST enforce
bounded, regular-file-only reads (no unbounded reads of special files or
untrusted-size input).

## Development Workflow

Every change MUST pass the full local verification gate before it is
considered complete: `cargo fmt --check`, `cargo clippy --all-targets
--all-features -- -D warnings`, `cargo test --workspace`, `cargo build`,
and `git diff --check`. Releases are cut only through the reviewed,
`workflow_dispatch`-only release automation (or its documented manual
fallback) — never by ad hoc tagging. Any workflow step that interpolates
user- or event-supplied input into a shell `run:` block MUST pass that
input through an `env:` variable first, never direct `${{ }}`
interpolation into shell source. Spec/plan/task artifacts produced under
`.specify/` MUST include an explicit Constitution Check that verifies
compliance with every principle above before implementation begins.

## Governance

This constitution supersedes all other project practices, READMEs, and
prior informal conventions where they conflict. Amendments require: (1)
a written rationale for the change, (2) a version bump per the policy
below, (3) propagation of the change into any dependent `.specify/`
templates, README/docs sections, and CHANGELOG, in the same amending
change — no amendment is complete until dependent artifacts are
updated. Constitution versioning follows semantic versioning: MAJOR for
backward-incompatible principle removals/redefinitions or removal of a
forbidden-mechanism guarantee (e.g. permitting a daemon), MINOR for a new
principle or materially expanded guidance, PATCH for clarification or
wording fixes with no semantic change. All specs, plans, and PRs MUST be
reviewed for compliance with this constitution; any complexity or
deviation MUST be explicitly justified in the spec/plan, not silently
introduced in implementation.

**Version**: 1.0.0 | **Ratified**: 2026-07-10 | **Last Amended**: 2026-07-10
