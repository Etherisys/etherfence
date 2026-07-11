# Phase 1 Data Model: MCP Server Integrity Baseline and Drift Detection

All new types live in `crates/etherfence-setup/src/baseline.rs` unless
noted. All `Serialize` derives use `#[serde(rename_all = "camelCase")]` for
structs and `#[serde(rename_all = "kebab-case")]` for enums, matching the
existing `trust.rs`/`classification.rs` convention exactly, so JSON output
never needs a hand-maintained second label table (CLI human rendering
reuses the existing `kebab_label()` helper in `main.rs` for every new enum,
the same way it already does for trust-assessment enums).

## `ReviewState`

```rust
pub enum ReviewState {
    Unreviewed,
}
```

Single-variant in v1.4.0 (spec FR-026/Assumptions) — present so a future
review workflow can extend this enum additively without a schema bump of
its own field shape (only its value set would grow).

## `BaselineServerEntry`

| Field | Type | Notes |
|---|---|---|
| `fingerprint` | `String` | SHA-256 hex, research.md Decision 3. |
| `agentKind` | `String` | `AgentKind::key()` (stable machine identifier, e.g. `"vs-code"`) — one of the fingerprint's three inputs. **Added during implementation** (review finding #4): the first draft used `AgentKind::display_name()` for both the fingerprint and this field, which would make a future display-name rewording silently reidentify every server for that agent as removed+added. |
| `agent` | `String` | `AgentKind::display_name()` — human-facing only, never a fingerprint input. |
| `configSource` | `String` | `SetupDetection.config_path`, copied verbatim. |
| `serverName` | `String` | `SetupServer.name`, copied verbatim. |
| `transport` | `ServerTransport` | Reused from `etherfence_setup` (already `Serialize`, kebab-case). |
| `commandFingerprint` | `Option<String>` | research.md Decision 4. `None` iff invocation not applicable. |
| `argumentsFingerprint` | `Option<String>` | research.md Decision 4. `None` iff invocation not applicable. |
| `packageIdentity` | `Option<String>` | Copied from `trust_assessment.invocation.package_identity`. |
| `packageVersionExpression` | `Option<VersionExpressionKind>` | Copied from `trust_assessment.invocation.version_expression`. Reused enum from `trust.rs`. |
| `executablePath` | `ExecutablePathClassification` | Copied from `trust_assessment.executable_path`. Reused enum from `trust.rs`. |
| `sha256` | `Option<String>` | Copied from `trust_assessment.sha256`. Omitted (not null) when absent — `skip_serializing_if = "Option::is_none"`. |
| `environmentVariableNames` | `Vec<String>` | Sorted, deduplicated names only from `server.env`; never values/hints. |
| `capabilityLabels` | `Vec<CapabilityLabel>` | Sorted (canonical order), deduplicated, from `capabilities.labels`. Reused enum from `classification.rs`. |
| `trustIndicators` | `Vec<IndicatorSummary>` | Sorted by `id`. See below. |
| `artifactIdentity` | `ArtifactIdentityConfidence` | Copied verbatim. Reused enum from `trust.rs`. |
| `configurationRisk` | `ConfigurationRiskStatus` | Copied verbatim. Reused enum from `trust.rs`. |
| `aggregate` | `AggregateAssessmentStatus` | Copied verbatim. Reused enum from `trust.rs`. |
| `reviewState` | `ReviewState` | Always `Unreviewed` in v1.4.0. |

`sha256` uses `skip_serializing_if = "Option::is_none"` (omitted-not-null),
matching the existing convention already established for this exact field
on `TrustAssessment` in v1.3.0 (contracts/setup-detect-trust-assessment.md
precedent) — carried over unchanged rather than reinvented.

## `IndicatorSummary`

| Field | Type | Notes |
|---|---|---|
| `id` | `String` | e.g. `"EF-TRUST-PIN-001"`. Reused verbatim from `TrustIndicator.id`. |
| `category` | `IndicatorCategory` | Reused enum from `trust.rs`. |
| `severity` | `Severity` | Reused enum from `etherfence-core`. |

Never includes `summary`/`rationale`/`evidence`/`remediation` (research.md
Decision 6) — those are narrative fields not needed for set-equality drift
detection and are intentionally excluded from the persisted safety
boundary.

## `BaselineDocument`

| Field | Type | Notes |
|---|---|---|
| `schemaVersion` | `String` | Always `"ef-setup-baseline/v0.1"`. |
| `root` | `String` | `root.display().to_string()`, matching `setup detect`'s existing `root` field convention. |
| `servers` | `Vec<BaselineServerEntry>` | Sorted per research.md Decision 9. |

## `DriftReason`

Closed enum, exactly the 15 variants from spec FR-014
(`executable-hash-changed`, `command-changed`, `arguments-changed`,
`package-identity-changed`, `package-version-changed`,
`environment-variable-names-changed`, `transport-changed`,
`server-added`, `server-removed`, `capability-set-changed`,
`trust-indicator-set-changed`, `artifact-identity-changed`,
`configuration-risk-changed`, `risk-increased`,
`executable-became-unverifiable`).

**Added during implementation**: `configuration-risk-changed` (review
finding #5). The original 14-variant design relied on `trust-indicator-
set-changed` (compared by `id` only) plus `risk-increased` (increase-only)
to make configuration-risk drift observable; a review found this could in
principle miss a risk *decrease*, or a same-id severity change, being
silently folded into `unchanged`. Fixed two ways: `trust-indicator-set-
changed` now compares the full `(id, category, severity)` tuple (still
just a `Vec<IndicatorSummary>` equality check, since `IndicatorSummary`
already derives `PartialEq`), and this new reason directly compares
`configurationRisk` itself, independent of how indicators are compared —
belt-and-suspenders rather than relying on one derivation path.

## `ComparisonStatus`

```rust
pub enum ComparisonStatus {
    Unchanged,
    New,
    Changed,
    Missing,
    Unverifiable,
}
```

## `RiskDirection`

```rust
pub enum RiskDirection {
    Increased,
    Decreased,
    Unchanged,
    NotApplicable, // `new` or `missing` entries — no baseline+current pair to compare
}
```

## `ComparisonEntry`

| Field | Type | Notes |
|---|---|---|
| `fingerprint` | `String` | Same algorithm as `BaselineServerEntry.fingerprint`. |
| `agentKind` | `String` | From whichever side (baseline/current) has the entry; identical when both do. |
| `agent` | `String` | From whichever side (baseline/current) has the entry; identical when both do. |
| `configSource` | `String` | Same. |
| `serverName` | `String` | Same. |
| `transport` | `ServerTransport` | Same. |
| `status` | `ComparisonStatus` | Spec FR-009–FR-013. |
| `reasons` | `Vec<DriftReason>` | Sorted by the fixed `DriftReason` declaration order (mirrors `trust.rs`'s `IndicatorCategory` canonical-order pattern) — never insertion order. |
| `baselineRisk` | `Option<AggregateAssessmentStatus>` | `None` for `new`. |
| `currentRisk` | `Option<AggregateAssessmentStatus>` | `None` for `missing`. |
| `riskDirection` | `RiskDirection` | Derived via `risk_rank` (research.md Decision 7). |

## `ComparisonReport`

| Field | Type | Notes |
|---|---|---|
| `schemaVersion` | `String` | Always `"ef-setup-baseline-comparison/v0.1"`. |
| `root` | `String` | Current scan root. |
| `entries` | `Vec<ComparisonEntry>` | Sorted per research.md Decision 9. |

## Public functions (`etherfence-setup::baseline`)

```rust
pub fn fingerprint(agent_kind: &str, config_source: &str, server_name: &str) -> String;
pub fn build_baseline(root: &Path, items: &[InventoryItem]) -> BaselineDocument;
pub fn compare(baseline: &BaselineDocument, current_items: &[InventoryItem], root: &Path) -> ComparisonReport;
pub fn validate_baseline(baseline: &BaselineDocument) -> Result<(), String>;
pub fn risk_rank(status: AggregateAssessmentStatus) -> u8;
pub fn drift_gate_triggered(report: &ComparisonReport) -> bool;   // --fail-on-drift
pub fn new_gate_triggered(report: &ComparisonReport) -> bool;     // --fail-on-new
pub fn risk_increase_gate_triggered(report: &ComparisonReport) -> bool; // --fail-on-risk-increase
```

**Revised during implementation**: `build_baseline`/`compare` take
`&[InventoryItem]` (`etherfence_inventory::discover`'s raw output), not
`&[SetupDetection]` — `SetupDetection`/`SetupServer` never carry the raw
`command`/`args` text needed to compute `commandFingerprint`/
`argumentsFingerprint` (deliberately, so `setup detect`'s JSON output never
leaks them). `build_baseline` instead calls the crate's existing
(crate-private) `server_from_mcp` directly per raw `McpServer` — the exact
same classification/trust-assessment path `detect()` already uses,
accessible from a child module without any visibility change — so it has
both the raw fields (for fingerprinting/hashing, never persisted) and the
derived fields (capabilities/trust/transport) in scope at once.
`fingerprint` also dropped its fourth (`transport`) parameter (research.md
Decision 3) and takes `agent_kind` (a stable machine key), not the display
name (research.md/review finding #4). Internally, `fingerprint` and the
argument fingerprint both hash a canonical JSON-array encoding
(`serde_json::to_vec`) of their inputs rather than a delimiter-joined
string — review finding #1 found the original `"\u{1}"`-joined encoding
collision-prone since none of the joined fields is proven to exclude the
empty string or any particular character.

`validate_baseline` (added post-review, hardening recommendation): checks
that a freshly parsed `BaselineDocument` is internally consistent —
fingerprints match their own identity fields, no duplicate fingerprints,
well-formed `sha256` hex, sorted/deduplicated set fields, and `aggregate`
consistent with `artifactIdentity`/`configurationRisk` (reusing `trust.rs`'s
existing `aggregate()` function, not a reimplementation) — before the
caller ever compares against it. `etherfence-cli`'s `read_setup_baseline`
calls this immediately after parsing and fails closed (non-zero exit) on
any `Err`.

All eight are pure functions with no I/O; `etherfence-cli` owns reading the
baseline file (via `etherfence_core::read_bounded_text_file_no_follow` —
review finding #2 — rather than the general `read_bounded_text_file`, so a
symlinked `--baseline` path fails closed instead of being silently
followed), calling `etherfence_inventory::discover(&root)` for current
state, calling these functions, then rendering/exiting. `write` without
`--overwrite` uses atomic exclusive file creation
(`OpenOptions::create_new`), and `write --overwrite` writes to a temp file
in the same directory and atomically renames it into place (review
finding #3) — neither path is a separate existence-check followed by a
write.

## State transitions

There is no persisted process/lifecycle state — `BaselineDocument` is
write-once-then-read-only data (FR-032). The only "transition" is the
comparison classification itself, which is a pure function of two
snapshots (baseline, current) with no side effects and no memory of
previous `check` runs.
