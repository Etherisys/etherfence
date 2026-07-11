# Phase 0 Research: Expanded Agent Integration Catalog and MCP Server Classification

Grounded in inspection of the actual v1.0.1 EtherFence workspace (see plan.md
"Project Structure" for exact files), not assumptions from the spec alone.
Each item below resolves a Technical Context/design unknown as
Decision / Rationale / Alternatives considered.

## Decision 1: New logic lives in existing crates, not a new crate

**Decision**: Add `catalog.rs` and `classification.rs` as new modules
inside `crates/etherfence-setup`, extend `crates/etherfence-core`'s
`AgentKind`, and extend `crates/etherfence-inventory`'s `CANDIDATES`
table. No new crate is added to the workspace.

**Rationale**: `etherfence setup catalog` and the classification extension
to `etherfence setup detect` are both members of the existing `setup`
command family, which already lives entirely in `etherfence-setup` and is
rendered by `etherfence-cli`. Classification needs the same `McpServer`
data (`command`/`args`/`env`/`url`) that `etherfence-setup::server_from_mcp`
already receives — reusing that call site avoids a second discovery pass
and keeps one source of truth. The user's architecture preference ("keep
detector/catalog/classifier logic separated from CLI rendering") is about
a *layering* boundary (library vs. CLI), not a *crate-count* requirement;
the existing codebase already achieves that layering with one crate per
concern, and `etherfence-setup` is the correct concern here.

**Alternatives considered**:
- *A new `etherfence-classify` crate.* Rejected: would require
  `etherfence-setup` to depend on it (or vice versa) purely to share the
  `McpServer` type it already has, adds a workspace member for a handful
  of pure functions, and has no reuse target outside `setup detect` in
  this release — pure Scope Discipline cost with no benefit at this scope.
- *Folding catalog/classification into `etherfence-detectors`.* Rejected:
  `etherfence-detectors::analyze` operates on the `scan` pipeline's
  `Finding`/`Severity` model and is consumed by `scan`, a materially
  different report shape and command than `setup`; reusing it would mean
  either a parallel Finding-shaped output (not what the spec asks for) or
  entangling two independent report schemas.

## Decision 2: Which of the 10 fixed clients start at which support tier

**Decision**: At v1.2.0 ship time:
- **fixture-verified**: Claude-style config, Cursor, VS Code — the three
  clients that already have both parsing logic *and* existing
  fixture-backed tests (`etherfence-inventory`'s existing test suite, plus
  new catalog-specific fixture tests added by this feature per FR-019).
- **detect-only**: Windsurf, Gemini CLI, Codex CLI — these already have
  real JSON-parsing detection logic and existing inventory-level fixture
  tests (confirmed: `tests/fixtures/home/.windsurf`, `.gemini`, `.codex`
  already exist and are asserted against in
  `crates/etherfence-inventory/src/lib.rs` tests), but do not yet have a
  fixture test asserting the *catalog row's exact tier claim* — so they
  start `detect-only` and may be promoted to `fixture-verified` within
  this same release if catalog-level fixtures are added for them (tracked
  as an explicit, optional task, not a requirement to ship v1.2.0).
- **advisory-only**: Hermes, Antigravity, OpenCode, Cline / Roo Code —
  these have zero existing detection code (confirmed: no `AgentKind`
  variant, no `CANDIDATES` entries). This feature adds `AgentKind`
  variants and `PresenceOnly` `CANDIDATES` entries for them (mirroring the
  existing `Tirith` `PresenceOnly` precedent) so the catalog can honestly
  report local presence/absence — but no JSON/TOML parsing or MCP-server
  extraction is attempted for them, so they remain `advisory-only`, never
  `fixture-verified` or `detect-only`.
- **unknown/unsupported**: reserved in the type system for a client whose
  detection state cannot be determined (e.g., an unreadable/corrupted
  candidate path); not assigned to any of the 10 fixed clients by default
  at ship time.

**Rationale**: This maps tiers onto *actual, inspectable code state*
rather than aspiration, directly satisfying Constitution Principle XI
(Catalog Classification Discipline) and spec FR-019. It also correctly
separates this tier (detection/classification confidence) from the
pre-existing, orthogonal `WriteSupport` enum in `etherfence-setup`
(write-capability for `setup apply`, unrelated to catalog display) —
Windsurf/Gemini CLI/Codex CLI are `WriteSupport::AdvisoryOnly` today (they
are not rewritten by `setup apply`) while independently being catalog
`detect-only` (their presence/servers *are* reliably parsed). These two
axes must not be conflated in code or docs.

**Alternatives considered**: Treating "advisory-only" clients as fully
`unknown` was rejected — the spec's own Assumptions section defines
`advisory-only` as "named and described but no dedicated detection logic,"
distinct from `unknown`; collapsing the two would lose the honest
distinction between "we don't recognize this at all" and "we know about
it, we just haven't built detection for it yet."

## Decision 3: Starter-policy recommendation model — `Deny`/`Allow` tier plus a `needs_review` flag, `Allow` never emitted in v1.2.0

**Decision**: `StarterPolicyRecommendation` has two axes: `tier`
(`Deny` | `Allow`) and `needs_review: bool`. The `unknown`,
`shell / command execution`, and `identity / auth` capability labels each
independently force `needs_review = true` (FR-016). No curated
classification rule shipped in v1.2.0 sets `tier = Allow` — every server
recommendation this release is `Deny`, with `needs_review` distinguishing
"flag for immediate manual review" from "default-denied, lower urgency."

**Rationale**: FR-017 permits `Allow` only for a specific
capability/server combination that is itself fixture-verified as safe.
Doing that honestly requires asserting, with a fixture and a test, that a
named real-world MCP server is safe to default-allow — a much stronger
claim than "we can classify its capabilities," and one this release has
no fixture basis for yet (Constitution Principle V). Shipping a
two-value tier that is always `Deny` in practice, but keeping `Allow` in
the type system, satisfies FR-015 (a single fixed, deterministic
merge rule — reduced to a simple boolean OR over three labels, not an
invented 10-item ranking) without inventing false confidence, and leaves
room for a future release to add a fixture-verified `Allow` rule without
a schema change.

**Alternatives considered**: A full ranked precedence order across all 10
capability labels (as sketched informally during specification) was
considered and rejected for v1.2.0 — with `tier` always `Deny`, a full
ranking has no observable effect beyond the three escalating labels
already required by FR-016, so specifying one further would be
unfalsifiable-by-test complexity for its own sake, contradicting the
"prefer conservative defaults" clarification guidance.

## Decision 4: Deterministic ordering and cross-platform path normalization

**Decision**: Catalog rows are emitted in one fixed declared order (the
10 clients in the order given in the spec). Capability labels within a
server's label set are emitted in one fixed canonical taxonomy order,
most-restrictive-first: `unknown`, `shell / command execution`,
`identity / auth`, `security tooling`, `database`,
`messaging / collaboration`, `SaaS / API`, `network`, `browser`,
`filesystem`. MCP servers within a client are sorted by server name
(byte-wise, matching the existing `item.mcp_servers.sort_by(|a, b|
a.name.cmp(&b.name))` convention already used in
`etherfence-inventory::parse_candidate`). Discovered config paths are
displayed using the OS-native separator returned by
`Path::display()` (matching existing `setup detect` behavior), but any
value used as a *sort key or comparison* is first normalized to forward
slashes so Linux and Windows produce the same relative ordering for
equivalent configurations.

**Rationale**: A single fixed declaration order requires no runtime
sorting logic for the catalog (10 known clients, always the same 10
rows) and is trivially deterministic. Ordering capability labels
most-restrictive-first is a deliberate, security-tool-appropriate
UX choice (the riskiest capability is always the first thing an operator
sees) and reuses the same fixed order already needed for Decision 3's
label-to-`needs_review` mapping — one canonical order serves both
purposes. Server-name sorting reuses an existing, already-tested
convention rather than inventing a new one. Path-separator normalization
for comparison-only (never for display) matches how `FR-020`/`SC-002`
must hold without changing the already-established `Path::display()`
convention for human-facing output.

**Alternatives considered**: Alphabetical capability-label ordering was
considered for readability but rejected — it would require a *second*,
different fixed order from the one already needed for the
`needs_review` merge rule, adding complexity without adding
determinism (both orders are equally deterministic) or safety.

**Addendum (multi-path clients)**: A client with more than one discovered
config path (spec Edge Case 2) lists its paths in `etherfence_inventory
::discover()`'s existing order — itself the fixed `CANDIDATES` table
declaration order per agent, already identical on Linux and Windows — so
no additional sorting or normalization step is needed for `config_paths`
specifically; see data-model.md `CatalogEntry` "Multi-path ordering."

## Decision 5: Output format — dedicated `Human`/`Json` enum, not the existing 4-value `OutputFormat`

**Decision**: Add a new `#[derive(ValueEnum)] enum SetupOutputFormat { Human, Json }`
in `etherfence-cli`, used by both `setup catalog --format` and the new
`setup detect --format` flag, rather than reusing the existing
`OutputFormat` (`Human`/`Json`/`Markdown`/`Sarif`) used by `scan`.

**Rationale**: `Markdown` and `Sarif` are not required by FR-020a and have
no defined meaning for a client/capability catalog (SARIF in particular is
a static-analysis-results format tied to `scan`'s finding model); offering
them would invite either dead code paths or an ad hoc partial
implementation, both worse than a narrower, honest CLI surface. `setup
detect`'s new `--format` flag defaults to `Human`, preserving today's
default output exactly (constraint: "Preserve existing CLI behavior").

**Alternatives considered**: Reusing `OutputFormat` and returning a clap
error for unsupported values (`Markdown`/`Sarif`) at runtime was
considered and rejected — it would let `--format sarif` parse
successfully at the CLI-argument level only to fail later, a worse user
experience than a `ValueEnum` that only ever offers valid choices.

## Decision 6: Classification evidence rules — curated exact-match table only, no fuzzy/substring heuristics

**Decision**: `classification.rs` matches an MCP server's `command` +
first meaningful argument (e.g., the resolved package name for an
`npx`/`uvx`-style invocation) against a small, curated, checked-in table
mapping known command/package identifiers to capability label sets. Any
server not matching an entry in that table is labeled `unknown` only —
no partial-credit, substring, or path-shape heuristics are used.

**Rationale**: Directly implements the stated architecture preference
("avoid broad string-matching that creates false confidence; unknown is
safer than overclassification") and Constitution Principle V/XI (no label
without a fixture-backed rule). A curated table is trivially
fixture-testable one entry at a time (FR-014/FR-019/SC-005) and its
absence-implies-`unknown` behavior directly satisfies FR-013.

**Alternatives considered**: Regex/substring matching against full
argument strings (e.g., "contains the word 'file'") was considered and
rejected as exactly the kind of false-confidence heuristic the
clarification and architecture preference explicitly warned against —
it would be neither deterministic-by-inspection nor reliably
fixture-testable at the granularity FR-014 requires.

## Remaining NEEDS CLARIFICATION

None. All Technical Context fields and design unknowns are resolved above.
