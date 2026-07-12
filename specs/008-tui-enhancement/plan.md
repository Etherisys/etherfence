# Implementation Plan: Terminal UI Enhancement (v1.7.3)

**Plan version**: 1.0
**Last updated**: 2026-07-12
**Feature**: specs/008-tui-enhancement

---

## Architecture overview

The change is purely in the human-rendering path. No scan logic, detection, scoring, policy evaluation, or machine-format output is modified.

```
┌─────────────────────────────────────────────────────┐
│  etherfence-cli/src/main.rs                         │
│  ┌───────────────────────────────────────────────┐  │
│  │ run_scan()                                    │  │
│  │  OutputFormat::Human + verbose                │  │
│  │    → render_scan_verbose()  [NEW, themed]     │  │
│  │  OutputFormat::Human + !verbose               │  │
│  │    → render_scan_summary() [existing]         │  │
│  │  OutputFormat::Json/Markdown/Sarif            │  │
│  │    → etherfence_report::to_*  [unchanged]     │  │
│  └───────────────────────────────────────────────┘  │
│                                                      │
│  ┌───────────────────────────────────────────────┐  │
│  │ banner.rs                                     │  │
│  │  render_standard_banner() → enhanced          │  │
│  │  render_compact_banner()  → enhanced          │  │
│  └───────────────────────────────────────────────┘  │
│                                                      │
│  ┌───────────────────────────────────────────────┐  │
│  │ ui.rs                                         │  │
│  │  + unicode_supported()  [NEW]                 │  │
│  │  + box_draw_{top,bottom,mid}(width) [NEW]    │  │
│  │  + unicode_symbols()     [NEW]                │  │
│  └───────────────────────────────────────────────┘  │
│                                                      │
│  ┌───────────────────────────────────────────────┐  │
│  │ verbose.rs  [NEW MODULE]                      │  │
│  │  render_scan_verbose(report, options)         │  │
│  │    → themed, client→server→findings→rec       │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

## Component changes

### 1. Banner enhancement (`crates/etherfence-cli/src/banner.rs`)

**Current state**: `render_standard_banner()` prints the 6-line ASCII art followed by a dim tagline and dark-gray version, each with static padding.

**Target state**: The ASCII art is followed by a horizontal rule separator, then a metadata line showing the tagline, version, and scan mode.

Design decision — **separator + metadata line** (not boxed footer):
```
███████╗████████╗██╗  ██╗███████╗██████╗ ███████╗███████╗███╗   ██╗ ██████╗███████╗
... (5 more lines of ASCII art, unchanged) ...
──────────────────────────────────────────────────────────────────────────────
AI Agent Security Posture & Runtime Control           v1.7.3 · LOCAL POSTURE ASSESSMENT
──────────────────────────────────────────────────────────────────────────────
```

**Rationale**: The separator approach is cleaner on narrow terminals than a full-width box. The ASCII art is wide (~78 chars for the longest line), so an enclosing box would crowd it.

Changes:
- `render_startup_banner()` accepts an optional `mode_label: Option<&str>` parameter.
- The label is `"LOCAL POSTURE ASSESSMENT"` for `scan`, absent for other commands.
- Rule width: `min(terminal_width, 80)` for standard, `terminal_width` for compact.
- Unicode box-drawing `─` falls back to `-` when `unicode_supported()` is false.
- `command_banner_mode()` is extended to return a label string alongside the `OutputMode`.

### 2. Unicode fallback (`crates/etherfence-cli/src/ui.rs`)

New function: `pub(crate) fn unicode_supported() -> bool`

Detection logic:
```rust
pub(crate) fn unicode_supported() -> bool {
    // Unicode is assumed supported unless:
    // - TERM=dumb
    // - NO_UNICODE or ASCII_ONLY env var is set
    // - LC_ALL=C or LANG=C (no UTF-8 locale)
    let term = std::env::var("TERM").unwrap_or_default();
    if term == "dumb" { return false; }
    if std::env::var_os("NO_UNICODE").is_some() { return false; }
    if std::env::var_os("ASCII_ONLY").is_some() { return false; }
    let lang = std::env::var("LANG").unwrap_or_default();
    let lc_all = std::env::var("LC_ALL").unwrap_or_default();
    if lang.ends_with("C") || lc_all.ends_with("C") { return false; }
    true
}
```

New symbol helpers:
```rust
pub(crate) fn checkmark() -> &'static str {
    if unicode_supported() { "✓" } else { "[OK]" }
}
pub(crate) fn circle() -> &'static str {
    if unicode_supported() { "◌" } else { "[  ]" }
}
pub(crate) fn cross() -> &'static str {
    if unicode_supported() { "✗" } else { "[!!]" }
}
pub(crate) fn tilde() -> &'static str {
    if unicode_supported() { "~" } else { "~" }
}
pub(crate) fn rule_char() -> &'static str {
    if unicode_supported() { "─" } else { "-" }
}
```

### 3. Verbose redesign (`crates/etherfence-cli/src/verbose.rs` — NEW)

New module with `render_scan_verbose(report: &ScanReport, debug: bool) -> String`.

**Information hierarchy** (top to bottom):

```
SECURITY POSTURE
────────────────
Score:  75/100 — GRADE C
Scope:  Agent & MCP server posture
Assessment:  ...

CLIENTS & SERVERS
─────────────────

Claude Code  (~/.claude.json)
  ── MCP server: brave-search  [HIGH · EF-MCP-001]
     Unauthenticated MCP tools can be accessed by any prompt
     → Run `etherfence setup` to secure this server.

  ── MCP server: github  [LOW · EF-MCP-002]
     MCP server configured but not policy-protected
     (No policy file found for this agent.)

Hermes  (~/.hermes/config.yaml)
  ── MCP server: stitch  [MEDIUM · EF-CONFIG-003]
     ...

CONSOLIDATED RECOMMENDED ACTIONS
────────────────────────────────
1. [EF-MCP-001] Run `etherfence setup` to secure unauthenticated MCP servers
   Affected: Claude Code/brave-search, Claude Code/filesystem

2. [EF-CONFIG-003] Review MCP tool allowlists in policy files
   Affected: Hermes/stitch

NOTE: This scan command is read-only posture discovery...
Run `etherfence scan --verbose --debug` for full technical evidence including fingerprints.
```

**Key design decisions**:
- Findings grouped by client, then by server within each client.
- Each finding line shows: `[SEVERITY · FINDING_ID]` badge + title.
- Indented rationale and recommendation follow.
- Identical recommendations (same finding_id) are deduplicated in the consolidated section.
- Low-severity findings like "MCP server configured" (INFO level) appear beneath the server as supporting context, not as prominent risks.
- In `--debug` mode: fingerprints, schema versions, policy-status, and baseline-status are shown per finding.
- The `etherfence_report::to_human_with_width` function is kept unchanged for its unit tests and as the "legacy diagnostic" path, but it's no longer called from `run_scan`.

### 4. `--debug` flag (`crates/etherfence-cli/src/main.rs`)

New field on `ScanOptions`:
```rust
#[arg(long)]
debug: bool,
```

Validated: `--debug` without `--verbose` is a warning but not an error (debug mode only adds detail to verbose output; on its own it's harmless and we still render the summary).

In `run_scan()`:
```rust
OutputFormat::Human if options.verbose => {
    render_scan_verbose(&report, options.debug)
}
```

### 5. Version bump

In `Cargo.toml`: `version = "1.7.3"`.
Regenerate `docs/examples/ci/baseline.json`.
Update version assertions in `crates/etherfence-cli/tests/cli_scan.rs`.
Update `docs/install.md`, `docs/json-schema.md`, `CHANGELOG.md`.
Update report crate tests that check version strings.

### 6. Tests

**New tests:**
- `banner.rs` tests: metadata line rendering with/without mode label, Unicode fallback for rule chars, compact banner with metadata.
- `verbose.rs` tests (or integration tests in `cli_scan.rs`): verbose output structure against fixture, deduplication of recommendations, `--debug` mode includes fingerprints, no schema IDs in normal verbose.
- `ui.rs` tests: `unicode_supported()` returns false for TERM=dumb, NO_UNICODE, LANG=C.

**Updated snapshots:**
- `docs/examples/ci/baseline.json` — version string only.

**Unchanged tests:**
- All tests in `etherfence-report/src/lib.rs` — the `to_human`/`to_human_with_width` path is preserved.
- All other integration tests in `cli_scan.rs`, `cli_demo.rs`, `cli_setup.rs`, etc.

---

## Risk assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Terminal width detection fails in CI | Medium | Low | Fall back to DEFAULT_HUMAN_WIDTH (80) |
| Unicode detection wrong on some terminals | Low | Medium | Conservative defaults; ASCII fallback always safe |
| Test snapshot drift | High | Low | Regenerate baseline, review diffs carefully |
| Verbose redesign breaks tooling that parses verbose output | Low | High | `--verbose` is documented as human-readable only; machine consumers should use JSON/SARIF |

---

## Constitution check

All 11 principles assessed. No violations. Key points:
- **III (Truth in Claims)**: No blocking/enforcement language added. Existing disclaimer preserved.
- **IV (Deterministic Output)**: Client→server ordering is stable (alphabetical by display name). Finding ordering within a server is by severity then ID.
- **V (Fixture-Backed)**: New rendering tests use the existing `tests/fixtures/home` directory.
- **VI (Schema Compatibility)**: No schema changes. Version field in output is CARGO_PKG_VERSION bump only.
- **IX (Complete Release Packaging)**: All docs, CHANGELOG, install.md, baseline updated.
- **X (Scope Discipline)**: Only banner.rs, ui.rs, verbose.rs (new), main.rs wire-up, and docs/tests change.

---

## Implementation order

1. **ui.rs** — Add `unicode_supported()`, symbol helpers, rule helpers.
2. **banner.rs** — Add metadata line + separator. Thread mode label from `command_banner_mode()`.
3. **verbose.rs** — New module: `render_scan_verbose()`.
4. **main.rs** — Wire up: pass mode label to banner, add `--debug` flag, call `render_scan_verbose()` for verbose output, update `render_scan_summary()` to use Unicode fallbacks.
5. **Version bump** — Cargo.toml, CHANGELOG, docs, baseline, test assertions.
6. **Tests** — Banner tests, verbose tests, Unicode fallback tests.
7. **Gate** — fmt, clippy, test, build, diff check.
8. **Commit + PR** — Single commit on feature branch, push, open PR.
