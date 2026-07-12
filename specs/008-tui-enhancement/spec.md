# Feature Specification: Terminal UI Enhancement (v1.7.3)

**Feature branch**: `feature/v1.7.3-tui-enhancement`
**Version**: 1.7.3
**Status**: draft
**Scope**: Human-facing terminal UI — banner and verbose scan output only.

---

## User stories

### US1 — Polished startup banner
As a security practitioner running `etherfence scan`, I want the startup banner to feel like a polished security CLI tool so that product identity, version, and scan mode are immediately clear before I read the scan report.

### US2 — Verbose scan output that prioritizes context
As a security reviewer running `etherfence scan --verbose`, I want the output organized by AI client and MCP server so that I can understand the security posture of each tool and its servers without scrolling through long undifferentiated lists.

### US3 — Clean verbose output without internal noise
As a security reviewer, I want `--verbose` to show only meaningful findings and contextual information, not internal schema IDs, status strings, or repeated boilerplate, so that I can focus on what needs attention.

### US4 — Narrow terminal support
As a user on a 80-column terminal or CI log viewer, I want the output to remain readable without horizontal scrolling, with reasonable fallbacks when Unicode or ANSI are unavailable.

### US5 — Identical machine-readable output
As an automation consumer, I want JSON, Markdown, and SARIF output to remain byte-identical with v1.7.2 for identical scan inputs, so that my CI pipelines and dashboards are not broken.

---

## Functional requirements

### FR1 — Banner footer beneath the splash
The startup banner SHALL be enhanced with a compact separator and metadata line beneath the existing ASCII art. The ASCII art itself SHALL NOT be modified.

**Acceptance criteria:**
- AC1.1: When the terminal is ≥100 columns wide, the standard banner renders with the existing 6-line `ETHER FENCE` ASCII art followed by a horizontal rule separator, then a metadata line containing the product tagline, version, and scan mode.
- AC1.2: When the terminal is <100 columns wide, the compact banner renders with its existing single-line `ETHERFENCE` text followed by the same separator + metadata treatment, scaled to fit.
- AC1.3: The metadata line SHALL include version (`v1.7.3`) and the scan mode (e.g., `LOCAL POSTURE ASSESSMENT` for `scan`, or empty for other commands).
- AC1.4: Colors follow the existing cyan/purple/dim-white/dark-gray palette. No new color constants are introduced without justification.
- AC1.5: When colors are disabled (redirected, NO_COLOR, CI, dumb terminal), the ASCII art and metadata render in plain text without ANSI escapes.
- AC1.6: The banner is suppressed for `OutputMode::Machine` and `OutputMode::Protocol`, unchanged from v1.7.2.

### FR2 — Redesigned verbose scan output
`etherfence scan --verbose` SHALL produce human-readable output organized by:
1. Overall posture summary (score, grade, scope)
2. Per-client sections with per-server findings
3. Consolidated recommended actions (deduplicated across servers)

**Acceptance criteria:**
- AC2.1: The top of verbose output SHALL show the overall posture: score/grade, scope, and assessment — matching the executive summary style.
- AC2.2: Each detected AI client SHALL be a labeled section showing its display name and config path.
- AC2.3: Within each client section, every MCP server SHALL be listed with its finding status and relevant finding details.
- AC2.4: Findings that affect multiple servers under one client SHALL be listed once per client, with affected server names noted.
- AC2.5: Recommended actions SHALL be consolidated so identical recommendations (same finding ID and text) appear once, with affected clients and servers grouped beneath.

### FR3 — Removal of internal noise from verbose
The `--verbose` output SHALL NOT display internal implementation details that are not meaningful to a security reviewer.

**Acceptance criteria:**
- AC3.1: Schema version identifiers (e.g., `ef-scan-report/v0.1.2`) SHALL NOT appear in verbose human output.
- AC3.2: Internal status strings (e.g., `stable-local-scan`) SHALL NOT appear in verbose human output.
- AC3.3: `not_applicable` values SHALL be suppressed when zero (no policy evaluation performed).
- AC3.4: Finding fingerprints SHALL NOT appear in verbose human output by default; a `--debug` flag SHALL be added to restore full technical evidence including fingerprints and schema IDs.
- AC3.5: `policy-status` internals (e.g., `policy_not_applicable`) SHALL NOT appear in verbose human output.
- AC3.6: JSON, Markdown, and SARIF output SHALL continue to include all technical fields (fingerprints, schema versions, policy-status) — no fields removed from machine formats.

### FR4 — Narrow terminal and fallback support
The verbose output SHALL be readable on 80-column terminals and SHALL degrade gracefully when ANSI or Unicode is unavailable.

**Acceptance criteria:**
- AC4.1: All banner and verbose output lines SHALL wrap to the detected terminal width (minimum 60 columns).
- AC4.2: Box-drawing characters (─, ┌, ┐, └, ┘, │) SHALL fall back to ASCII equivalents (dash, space) when the terminal does not support Unicode.
- AC4.3: ANSI color codes SHALL be omitted when `colors_enabled()` returns false.
- AC4.4: The existing `checkmark` (✓) and `circle` (◌) characters used in the summary SHALL fall back to ASCII equivalents (`[OK]`, `[  ]`) when Unicode is unsupported.
- AC4.5: The compact banner is selected for terminals narrower than 100 columns, unchanged from v1.7.2.

---

## Success criteria

- SC1: `etherfence scan` on an 80-column terminal shows a readable banner with metadata line and no horizontal overflow.
- SC2: `etherfence scan --verbose` on a test fixture produces output organized by client → server → findings → recommendations with no schema IDs, fingerprints, or internal status strings visible.
- SC3: `etherfence scan --format json` against the same fixture produces byte-identical output to v1.7.2 (modulo the version field bump).
- SC4: `etherfence scan --format sarif` against the same fixture produces byte-identical output to v1.7.2.
- SC5: All existing tests pass (no regressions in scan logic, findings, scoring, policy evaluation).
- SC6: New snapshot tests cover: standard banner rendering, compact banner rendering, verbose output structure.
- SC7: `NO_COLOR=1 etherfence scan` produces no ANSI escape sequences in human output.
- SC8: `TERM=dumb etherfence scan` produces no ANSI escape sequences and no box-drawing characters.

---

## Non-goals

- Changing the ASCII art banner content or layout.
- Modifying discovery, finding generation, scoring, grading, or policy evaluation logic.
- Changing JSON, Markdown, or SARIF output formats (beyond the version string bump).
- Adding new color themes or ANSI styling beyond the existing palette.
- Adding charting, graphs, or dashboard-style terminal widgets.
- Adding interactive features to scan output.
- Changing `etherfence setup` human output (beyond the shared banner module).
- Adding daemon, cloud, or shell-hook features (Constitution Principle II).

---

## Assumptions

1. The existing `UiTheme` in `ui.rs` with console/Style is sufficient for the verbose redesign.
2. `terminal_size` and `anstream` crates continue to provide adequate terminal capability detection.
3. The `etherfence-report` crate's `to_human_with_width` is the correct target for the verbose redesign.
4. Unicode fallback can follow the pattern: detect `unicode_width` support or use environment hints (`TERM`, `LANG`).

---

## Constitution check

| Principle | Assessment |
|-----------|-----------|
| I. Deny-by-Default | Not applicable — purely human output rendering, no policy decisions affected. |
| II. Local-First | Not affected — no daemon, cloud, hook, or network addition. |
| III. Truth in Claims | Must not introduce blocking/enforcement language — the scan output already includes the read-only disclaimer. Verbose redesign must preserve the existing Note. No new claims of protection or enforcement. |
| IV. Deterministic Output | Machine formats unchanged. Human output must be deterministic (fixed ordering by client name, then server name, then finding ID). |
| V. Fixture-Backed | New rendering paths must be tested against checked-in fixtures. |
| VI. Schema Compatibility | No schema changes. Version bump only in Cargo.toml. |
| VII. Fail-Closed Proxy | Not applicable — no proxy changes. |
| VIII. Audit Log Safety | Not applicable — no new logging. |
| IX. Complete Release Packaging | Must update CHANGELOG, docs, version, tests, baseline. |
| X. Scope Discipline | Scope is limited to banner + verbose rendering. No feature creep. |
| XI. Catalog Classification | Not applicable — no catalog changes. |
