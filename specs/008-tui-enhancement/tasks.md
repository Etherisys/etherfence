# Tasks: Terminal UI Enhancement (v1.7.3)

**Feature**: specs/008-tui-enhancement
**Branch**: feature/v1.7.3-tui-enhancement
**Implementation order**: Within each phase, tasks are sequential unless marked `[P]` (parallel — touches different files).

---

## Phase 1: Unicode fallback and terminal helpers

### T1.1 — Add `unicode_supported()` to ui.rs
**File**: `crates/etherfence-cli/src/ui.rs`
**Story**: US4 (narrow terminal support)

Add `pub(crate) fn unicode_supported() -> bool` that returns false when:
- `TERM=dumb`
- `NO_UNICODE` env var is set
- `LANG=C` or `LC_ALL=C` (no UTF-8 locale)

Add symbol helpers returning `&'static str`:
- `checkmark()` → `"✓"` / `"[OK]"`
- `circle()` → `"◌"` / `"[  ]"`
- `cross_mark()` → `"✗"` / `"[!!]"`
- `rule_char()` → `"─"` / `"-"`

Add `pub(crate) fn box_top(width: usize) -> String` and `pub(crate) fn box_bottom(width: usize) -> String` using rule chars.

### T1.2 [P] — Unit tests for Unicode fallback
**File**: `crates/etherfence-cli/src/ui.rs` (add `#[cfg(test)] mod tests`)

Tests:
- `unicode_supported_true_for_normal_term`
- `unicode_supported_false_for_dumb_term`
- `unicode_supported_false_for_no_unicode_env`
- `unicode_supported_false_for_lang_c`
- `checkmark_returns_ascii_when_unicode_disabled`
- `rule_char_returns_ascii_when_unicode_disabled`

---

## Phase 2: Banner enhancement

### T2.1 — Add mode label to banner rendering
**File**: `crates/etherfence-cli/src/banner.rs`

- Add `mode_label: Option<&str>` parameter to `render_startup_banner()` and `print_startup_banner()`.
- Propagate to `render_standard_banner()` and `render_compact_banner()`.
- After the existing ASCII art, render a horizontal rule separator followed by the metadata line.
- Standard: `"AI Agent Security Posture & Runtime Control           v{VERSION} · {MODE_LABEL}"`
- When mode_label is None: `"AI Agent Security Posture & Runtime Control           v{VERSION}"`
- Rule width: `min(terminal_width, 80)` using `ui::rule_char()`.
- Rule is centered within the available width.

### T2.2 — Wire mode label from `command_banner_mode()`
**File**: `crates/etherfence-cli/src/main.rs`

- Change `command_banner_mode()` return type from `banner::OutputMode` to `(banner::OutputMode, Option<String>)`.
- Return `Some("LOCAL POSTURE ASSESSMENT")` for `Command::Scan` with `OutputFormat::Human`.
- Return `None` for all other commands.
- Update the call site in `main()` to unpack and pass the label.

### T2.3 [P] — Unit tests for enhanced banner
**File**: `crates/etherfence-cli/src/banner.rs` (`#[cfg(test)] mod tests`)

Existing tests preserved. New tests:
- `standard_banner_includes_metadata_line_with_mode`
- `standard_banner_includes_metadata_line_without_mode`
- `compact_banner_includes_metadata_line`
- `metadata_line_uses_ascii_when_unicode_disabled`
- `mode_label_not_in_machine_mode`
- `colors_disabled_shows_plain_text_metadata`

---

## Phase 3: Verbose redesign

### T3.1 — Create `verbose.rs` module with `render_scan_verbose()`
**File**: `crates/etherfence-cli/src/verbose.rs` (NEW)
**Deps**: T1.1 (symbol helpers)

New function:
```rust
pub(crate) fn render_scan_verbose(report: &ScanReport, debug: bool) -> String
```

**Section 1: Overall posture** — score/grade, scope, assessment, summary counts.

**Section 2: Clients & servers** — for each inventory item (grouped by agent display name):
- Client header: `AgentName  (config_path)`
- For each MCP server under that client:
  - Server name
  - List findings affecting this server (matched by `finding.agent == item.agent && finding.target` contains the server name... actually, findings have `target` and `config_path` fields).

  Wait — let me reconsider. Findings have:
  - `agent`: e.g., "Claude Code"
  - `target`: e.g., "MCP: brave-search" or "config"
  - `config_path`: e.g., "~/.claude.json"

  The mapping is: finding → inventory item by `agent` + `config_path` match. Then within that item, a finding may target a specific MCP server (target starts with "MCP: ") or the config/agent overall.

**Section 3: Consolidated recommendations** — deduplicate by `finding_id`:
- Group all findings by their `id` (finding_id like EF-MCP-001).
- For each unique finding_id, show the recommendation once.
- List affected clients/servers beneath.

**Section 4: Note** — read-only disclaimer + pointer to `--debug`.

Debug mode: Append per-finding technical evidence (fingerprint, schema_version, policy_status, baseline_status) in muted text after each finding's recommendation.

### T3.2 — Wire `render_scan_verbose()` into `run_scan()`
**File**: `crates/etherfence-cli/src/main.rs`

- Add `mod verbose;` at top.
- Add `debug: bool` field to `ScanOptions` struct.
- Add `#[arg(long)] debug: bool` to the `Scan` command.
- In `run_scan()`, replace `etherfence_report::to_human_with_width(...)` with `verbose::render_scan_verbose(&report, options.debug)`.

### T3.3 [P] — Integration tests for verbose output
**File**: `crates/etherfence-cli/tests/cli_scan.rs` (or new `tests/cli_verbose.rs`)

Tests against `tests/fixtures/home`:
- `verbose_scan_has_posture_section` — output contains "Security posture" section with score/grade.
- `verbose_scan_groups_by_client` — output shows client names as section headers.
- `verbose_scan_has_consolidated_recommendations` — deduplicated recommendations section.
- `verbose_scan_no_schema_versions` — no "ef-scan-report" or "stable-local-scan" in output.
- `verbose_scan_no_fingerprints_by_default` — no fingerprint hex strings in normal verbose.
- `verbose_scan_debug_includes_fingerprints` — `--debug` mode includes fingerprints.
- `verbose_scan_debug_includes_schema` — `--debug` mode includes schema version.
- `verbose_scan_json_unchanged` — `--format json` output matches expected structure (version field updated).

---

## Phase 4: Version bump and docs

### T4.1 — Bump version to 1.7.3
**Files**: `Cargo.toml`, `crates/etherfence-cli/tests/cli_scan.rs`, `crates/etherfence-report/src/lib.rs`

- `Cargo.toml`: `version = "1.7.3"`.
- `cli_scan.rs`: Update all version assertions from `"1.7.2"` to `"1.7.3"`.
- `etherfence-report/src/lib.rs`: Update version string in test `ScanReport` constructions.
- Regenerate `docs/examples/ci/baseline.json`:
  ```bash
  cargo run --bin etherfence -- scan --root tests/fixtures/home --write-baseline docs/examples/ci/baseline.json
  ```
- Verify: `head -5 docs/examples/ci/baseline.json` shows `"version": "1.7.3"`.

### T4.2 [P] — Update CHANGELOG.md
**File**: `CHANGELOG.md`

Add `## [1.7.3]` section with:
- Banner enhancement with metadata line
- Redesigned `--verbose` output organized by client/server
- New `--debug` flag for technical evidence in verbose mode
- Unicode fallback for narrow/ASCII-only terminals
- Preserved machine-readable output compatibility

### T4.3 [P] — Update docs
**Files**: `docs/install.md`, `docs/json-schema.md`

- `docs/install.md`: Update version banner, archive paths, and version assertion.
- `docs/json-schema.md`: Update schema version line if applicable (no schema change in this release — just the version reference).

---

## Phase 5: Gate and release

### T5.1 — Full CI gate
```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
cargo build
git diff --check
```

### T5.2 — Commit and push
- Stage all changes.
- Commit: `feat(v1.7.3): terminal UI enhancement — banner metadata, themed verbose, --debug, Unicode fallback`
- Push to `feature/v1.7.3-tui-enhancement`.

### T5.3 — Open PR
- Create PR against `origin/main`.
- Title: `feat(v1.7.3): terminal UI enhancement`
- Body: Summary of changes, screenshots of new banner and verbose output (if applicable).
- DO NOT merge.

---

## Dependency graph

```
T1.1 (unicode helpers) ──┬── T2.1 (banner enhancement) ── T2.2 (wire label) ── T2.3 (banner tests)
                         │
                         ├── T3.1 (verbose module) ── T3.2 (wire verbose) ── T3.3 (verbose tests)
                         │
                         └── [Phase 4 can start after T3.2]

T1.2 (unicode tests) [P] with T1.1

Phase 4 (version/docs) [P] with Phase 3

Phase 5 (gate/release) depends on all previous phases.
```
