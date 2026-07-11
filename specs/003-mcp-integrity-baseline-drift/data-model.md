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
| `agent` | `String` | `SetupDetection.agent` (display name), copied verbatim. |
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

Closed enum, exactly the 14 variants from spec FR-014
(`executable-hash-changed`, `command-changed`, `arguments-changed`,
`package-identity-changed`, `package-version-changed`,
`environment-variable-names-changed`, `transport-changed`,
`server-added`, `server-removed`, `capability-set-changed`,
`trust-indicator-set-changed`, `artifact-identity-changed`,
`risk-increased`, `executable-became-unverifiable`).

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
pub fn fingerprint(agent: &str, config_source: &str, server_name: &str) -> String;
pub fn build_baseline(root: &Path, items: &[InventoryItem]) -> BaselineDocument;
pub fn compare(baseline: &BaselineDocument, current_items: &[InventoryItem], root: &Path) -> ComparisonReport;
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
derived fields (capabilities/trust/transport) in scope at once. `fingerprint`
also dropped its fourth (`transport`) parameter — see research.md Decision 3.

All seven are pure functions with no I/O; `etherfence-cli` owns reading the
baseline file, calling `etherfence_setup::detect(&root)` for current state,
calling these functions, then rendering/exiting.

## State transitions

There is no persisted process/lifecycle state — `BaselineDocument` is
write-once-then-read-only data (FR-032). The only "transition" is the
comparison classification itself, which is a pure function of two
snapshots (baseline, current) with no side effects and no memory of
previous `check` runs.
