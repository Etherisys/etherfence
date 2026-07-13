# Contract: Four-Way Human Output Grouping

Every human-readable rendering path (concise `render_scan_summary`, verbose `render_scan_verbose`, and the `etherfence-report` crate's `to_human`/`to_markdown`) must let a reader distinguish, via clearly labeled sections/headings, between:

1. **Inventory observations** — `category == "inventory"` findings (`EF-MCP-000`, `EF-MCP-004`). Purely descriptive; never implies risk.
2. **Scored risk findings** — `category == "risk"` findings. These drive the posture score and are what "Priority findings" / "Consolidated recommended actions" describe.
3. **Informational findings** — `category == "informational"` findings (`EF-TIRITH-*`). Contextual, not actionable remediation, not inventory.
4. **Protection / policy coverage** — the pre-existing, structurally separate `report.protection_coverage` (unchanged by this feature).

## Per-surface behavior

### Concise (`render_scan_summary`, `main.rs`)

- Existing section order preserved: Security posture → Overall status → Clients → **[new] Inventory observations** → **[new] Informational findings** → Protection coverage → Priority findings → Next steps → footer note.
- "Inventory observations" and "Informational findings" are short summary sections (a heading plus one or a few compact lines), consistent with the concise view's existing "executive summary" design — not a full per-finding dump (that stays behind `--verbose`).
- "Priority findings" is unchanged in heading/mechanics; it is already exclusively risk-category once `PostureSummary` is category-gated.
- If there are zero inventory-category findings, the "Inventory observations" section states so explicitly rather than being silently omitted (consistent with existing sections like "Protection coverage" always rendering their heading when the underlying data is present at all — mirrored here for symmetry across runs, so the report shape doesn't change based on data presence in a way that breaks diffing).

### Verbose (`render_scan_verbose`/`render_findings`, `verbose.rs`)

- Per-server/per-agent-level finding lists keep their existing single ordered list, but each finding's badge is now derived from `(category, severity)`: `Inventory` → `OBS` badge (muted), `Informational` → `INFO` badge (muted, unchanged from today), `Risk` → existing `HIGH`/`MEDIUM`/`LOW`/`INFO`-by-severity badges (unchanged).
- Sort order within a finding list stays severity-desc-then-id (unchanged sort key), so category does not reorder findings — only the badge label changes.
- "Consolidated recommended actions" excludes any finding whose `category != "risk"` (generalizing the existing `id == "EF-MCP-000"` special-case) — this also removes `EF-MCP-004` and `EF-TIRITH-*` from ever appearing there, which is intentional (they are not actionable remediations).

### Markdown / `to_human` (`etherfence-report/src/lib.rs`)

- The findings section groups by category first (`Inventory`, `Informational`, `Risk` in that order), then by `Severity::ORDERED_DESC` within `Risk` (there is currently no more than one severity value present within `Inventory`/`Informational` given the fixed table in `scoring-and-evidence.md`, but the nested grouping is written generally, not special-cased to today's exact severity assignments).
- Heading text uses the category's `.label()` (e.g. "Inventory Observations", "Informational Findings", "Risk Findings" for Markdown `###`/`####`; analogous plain-text headings for `to_human`).

## Determinism

All of the above must produce byte-identical output across repeated runs on the same input (Principle IV) — grouping is derived deterministically from `category`/`severity`/`id`, never from map iteration order or wall-clock values.

## Non-goals

- No new machine-readable summary counts (e.g. no new `inventory_findings_total` field on `Summary` or `PostureSummary`) — the four-way split is a human-output presentation contract; machine consumers already have `category` per-`Finding` to compute their own groupings if desired.
- No redesign of the `ProtectionCoverage` section itself.
