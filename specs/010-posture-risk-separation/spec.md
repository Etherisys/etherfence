# Feature Specification: Posture Score Risk Separation

**Feature Branch**: `feature/v1.7.4-posture-risk-separation`

**Created**: 2026-07-13

**Status**: Draft

**Input**: User description: "Make EtherFence posture results trustworthy and explainable by separating inventory observations from actionable security risk. EF-MCP-000 and generic env-var presence must not reduce the posture score; secret-specific findings like EF-SEC-001 must keep scoring; every heuristic finding must show which server field/value triggered it without leaking secrets; human output must distinguish inventory observations, scored risk findings, informational findings, and protection/policy coverage; all output formats stay deterministic and backward compatible where practical."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Score reflects actionable risk, not inventory size (Priority: P1)

As an operator running `etherfence scan`, when I configure additional MCP servers that introduce no risky capability (no broad filesystem access, no risky command/network hints, no secret-looking environment variables), my posture score and grade do not drop just because more servers now exist or because those servers happen to have ordinary (non-secret) environment variables set.

**Why this priority**: This is the core trust problem the release exists to fix — today, the score conflates "how much is configured" with "how risky is it," which makes the score meaningless for comparing a well-configured setup against a risky one, and actively discourages legitimate MCP adoption.

**Independent Test**: Run `scan` against a fixture with N configured MCP servers that have zero risky heuristics but nonzero environment variables with ordinary (non-secret-shaped) names, and confirm the score/grade equal the zero-finding baseline (100/A), regardless of N.

**Acceptance Scenarios**:

1. **Given** a fixture with several MCP servers configured, none matching any risk heuristic, **When** `scan` runs, **Then** the posture score is 100 and grade is A, unaffected by the number of configured servers.
2. **Given** a server with an environment variable whose name does not look secret-shaped (e.g. `LOG_LEVEL`, `REGION`), **When** `scan` runs, **Then** no score deduction occurs for that variable's presence.
3. **Given** a server with an environment variable whose name is secret-shaped (e.g. `API_KEY`, `AUTH_TOKEN`), **When** `scan` runs, **Then** the existing secret-specific finding still fires and still reduces the score exactly as before.

---

### User Story 2 - Every heuristic finding shows its own trigger evidence (Priority: P1)

As an operator or security reviewer triaging a finding, I can see exactly which field on which server (command, args, url, or an environment variable name) and which matched pattern caused a heuristic finding to fire, without ever seeing the underlying secret value, so I can judge for myself whether it's a false positive.

**Why this priority**: Explainability is what makes the remaining scored findings trustworthy after inventory noise is removed — an opaque "this server is risky" verdict is no more actionable than today's flat noise if the reviewer can't see why.

**Independent Test**: For each heuristic detector (broad filesystem access, risky command/tool hint, network-capable tool hint, secret-looking environment name), run against a fixture server and confirm the finding's evidence names the specific field (e.g. `command`, `args[1]`, `env:API_KEY`) and the matched value/pattern, and that no raw secret value ever appears in evidence, JSON, Markdown, or SARIF output.

**Acceptance Scenarios**:

1. **Given** a server whose `args` contain a path matching the broad-filesystem heuristic, **When** the finding is produced, **Then** its evidence identifies the `args` field and the matched path/pattern.
2. **Given** a server with an environment variable named `DB_PASSWORD` (redacted value), **When** the secret-name finding fires, **Then** its evidence names the variable and never includes the variable's actual value in any output format.
3. **Given** the same input scanned twice, **When** evidence is generated, **Then** the evidence content and ordering are byte-identical across runs.

---

### User Story 3 - Human output separates what's observed from what's risky (Priority: P2)

As an operator reading the default or verbose human report, I can immediately tell apart four kinds of information: plain inventory facts (e.g. "3 MCP servers are configured"), findings that actually lowered my score, informational findings that don't affect scoring, and protection/policy coverage signals (e.g. Tirith detected) — instead of one undifferentiated list of findings sorted only by severity.

**Why this priority**: This is the presentation-layer payoff of the scoring fix — without a visual split, a still-correct score is undermined by a report that keeps implying inventory and informational items are equally "wrong" as scored risk.

**Independent Test**: Render the default and verbose human reports against a fixture containing at least one item of each of the four kinds, and confirm each appears under its own clearly labeled section, with no item appearing in more than one section.

**Acceptance Scenarios**:

1. **Given** a scan with inventory-only findings, scored risk findings, informational findings, and Tirith protection-coverage detection all present, **When** the default human report renders, **Then** each is shown in its own section with a clear heading, and the scored-risk section is what drives the displayed score commentary.
2. **Given** the same fixture, **When** the verbose report renders, **Then** the same four-way separation holds for the full finding list, not only the top-N summary.

---

### Edge Cases

- A server with zero findings of any kind (fully clean) still appears in the inventory-observations section so operators can confirm it was seen, but contributes nothing to the score.
- A finding whose severity previously implied it was scored (e.g. today's `Severity::Low` on `EF-MCP-000`/`EF-MCP-004`) is reclassified as non-scoring; historical baseline entries recorded under the old severity must still resolve/match correctly (fingerprint is severity-independent) so previously-accepted baseline suppressions are not silently reopened.
- A resolved (baseline-suppressed) finding that would otherwise be a scored risk finding must remain excluded from the score exactly as it is today — non-scoring reclassification must not be confused with baseline resolution, which is a separate mechanism.
- An environment variable name that matches secret-shaped patterns case-insensitively or via substring (e.g. `MyApiKey`) must still be caught by the secret-specific finding, not miscategorized as generic presence.
- A server with only generic (non-secret) environment variables and no other heuristic match produces an informational finding, not an absent one — the fact that env vars exist remains visible, it just doesn't cost score.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The posture scoring calculation MUST NOT deduct points for a finding whose sole content is "this MCP server/config exists" (the current `EF-MCP-000` finding) — this fact MUST remain visible in output but MUST NOT influence score or grade.
- **FR-002**: The posture scoring calculation MUST NOT deduct points for a finding whose sole content is "this server has one or more environment variables present" with no secret-shaped name (the current `EF-MCP-004` finding) — this fact MUST remain visible in output but MUST NOT influence score or grade.
- **FR-003**: The existing secret-shaped environment variable name finding (`EF-SEC-001`) MUST continue to be produced under exactly the same matching logic and MUST continue to deduct score exactly as it does today — this requirement is not weakened by FR-001/FR-002.
- **FR-004**: All other existing actionable risk findings (broad filesystem access, risky command/tool hints, network-capable tool hints, and all scan-policy findings) MUST continue to deduct score under their current severities, unchanged.
- **FR-005**: Every finding produced by a heuristic (pattern-matching) detector MUST expose evidence that deterministically identifies both the specific server field examined (e.g. command, an individual argument, url, or a specific environment variable name) and the matched value or pattern that caused the finding, in a consistent, machine-parseable shape across finding kinds.
- **FR-006**: No finding's evidence, and no other field in human, JSON, Markdown, or SARIF output, MUST ever contain the actual value of an environment variable or any other value classified as secret-shaped — only names/patterns of matched fields may appear, consistent with existing redaction of environment variable values.
- **FR-007**: The system MUST expose a category for every finding — distinguishing at minimum "inventory observation" (non-scoring, purely descriptive), "informational" (non-scoring, contextual), and "scored risk" (severity-weighted, actionable) — independent of and in addition to the existing severity level, so that severity continues to represent risk magnitude only and category alone determines whether a finding affects the score.
- **FR-008**: Default (concise) human output MUST present inventory observations, scored risk findings, informational findings, and protection/policy coverage as visually distinct, clearly labeled sections rather than a single flat severity-sorted list.
- **FR-009**: Verbose human output MUST preserve the same four-way separation across the complete finding list, not only a top-N subset.
- **FR-010**: JSON, Markdown, and SARIF output MUST remain fully deterministic for identical input: stable field ordering, stable finding ordering, and no wall-clock or non-deterministic values in any comparable field.
- **FR-011**: Any change to a finding's severity, any new category field, or any other change to the `ef-scan-report` schema's field names or semantics MUST bump the schema version, MUST be recorded in the CHANGELOG, and MUST be reflected in `docs/json-schema.md` and any other affected schema documentation in the same change.
- **FR-012**: Existing consumers parsing prior scan report versions MUST continue to work unmodified wherever practical; any unavoidable incompatibility MUST be explicitly called out in the CHANGELOG and docs rather than silently shipped.
- **FR-013**: README, CHANGELOG, `docs/json-schema.md`, `docs/sarif.md` (and any other doc describing the scoring model, finding categories, or affected finding IDs), and `docs/examples/ci/baseline.json` MUST be updated to accurately reflect the new scoring model, the new category concept, and which finding IDs are scoring vs. non-scoring.
- **FR-014**: Regression tests MUST prove: (a) any number of zero-risk configured MCP servers does not reduce the score; (b) increasing only inventory-observation or informational findings does not change the score; (c) actionable Low, Medium, and High findings still change the score exactly as their weights dictate; (d) a resolved (baseline-suppressed) finding remains excluded from the score; (e) heuristic evidence deterministically identifies the matched field across repeated runs; (f) no secret value is ever emitted in any output format.

### Key Entities

- **Finding**: An individual observation produced by a detector or policy evaluator, identified by a stable ID (e.g. `EF-MCP-000`, `EF-SEC-001`), carrying a severity (risk magnitude), a category (whether and how it affects scoring — see Assumptions), and evidence (which field/value triggered it).
- **Finding Category**: A classification orthogonal to severity that determines whether a finding is an inventory observation, informational context, or a scored risk finding contributing to the posture score.
- **Posture Summary**: The aggregate score, grade, and counts derived from the set of active (non-baseline-resolved) findings for a scan, computed only from scored-risk-category findings.
- **Evidence Entry**: A single piece of trigger evidence attached to a finding, naming the specific server field examined and the matched value/pattern, never a raw secret value.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A fixture with any number of MCP servers that have no actionable risk heuristics and only non-secret-shaped environment variables always scores 100/A, regardless of server count.
- **SC-002**: A fixture combining actionable Low, Medium, and High findings produces the same score reduction as the existing formula (`-2`/`-10`/`-25` respectively, clamped to 0) applied only to scored-risk-category findings — inventory and informational findings contribute zero.
- **SC-003**: 100% of heuristic finding kinds expose evidence that names the specific matched server field, verified by fixture-backed tests for every existing detector.
- **SC-004**: No test or manual review of JSON/Markdown/SARIF/human output for any fixture finds a raw secret-classified value anywhere in output.
- **SC-005**: Default and verbose human reports for a mixed fixture show four clearly separated sections (inventory, scored risk, informational, protection coverage) confirmed by fixture-backed rendering tests.
- **SC-006**: The full required Rust validation gate (`cargo fmt --check`, `clippy -D warnings`, `cargo test --workspace`, `cargo build`, `git diff --check`) passes with zero regressions in unrelated fixtures/tests.
- **SC-007**: Every schema, doc, and example file affected by the scoring/category change is updated and internally consistent — no doc describes the pre-change scoring behavior after the change lands.

## Assumptions

- "Inventory observation" and "informational" are both non-scoring categories but remain semantically distinct: inventory observations are purely descriptive facts about what's configured (e.g. `EF-MCP-000`, and generic environment-variable presence, i.e. today's `EF-MCP-004`), while informational findings are contextual signals that aren't inventory facts but also aren't actionable risk (e.g. the existing `EF-TIRITH-*` detection findings). The exact category assigned to each existing finding ID is a plan-level decision; this spec fixes the outcome (which IDs score and which don't) rather than the exact label taxonomy.
- Reclassifying `EF-MCP-000` and `EF-MCP-004` off the scored path is a behavior change to the `ef-scan-report` schema's effective semantics (their severity and/or a new category field changes) and therefore requires an explicit schema version bump per FR-011, even though the top-level JSON shape may otherwise be additive.
- "Protection/policy coverage" refers to the existing separate coverage concept (e.g. Tirith detection, scan-policy evaluation) already surfaced today; this feature only requires it be clearly delineated from the other three categories in human output, not redesigned.
- Backward compatibility is "preserved where practical" per the explicit constraint in this feature's brief — an additive category field and a documented severity change for two specific finding IDs is considered practical and acceptable; consumers that hardcoded the old severity of `EF-MCP-000`/`EF-MCP-004` or the exact old score for fixtures containing them will see a documented, versioned change.
- Out of scope for this feature (deferred to later v1.7.x releases): `.mcp.json` discovery, Hermes write support, compound/correlated risk detection across multiple findings, baseline UX redesign, and scan focus modes/profiles. No work in this feature may expand into these areas.
