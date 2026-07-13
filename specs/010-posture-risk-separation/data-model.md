# Data Model: Posture Score Risk Separation

## New: `FindingCategory` (etherfence-core)

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingCategory {
    /// A purely descriptive fact about what is configured. Never scores.
    Inventory,
    /// Contextual signal that is neither inventory nor actionable risk. Never scores.
    Informational,
    /// Actionable, severity-weighted risk. The only category that contributes to score.
    #[default]
    Risk,
}
```

- Mirrors the existing `Severity`/`FindingKind`/`PolicyStatus` enum conventions already in `crates/etherfence-core/src/lib.rs`: `kebab-case` serde, a `.key()` accessor for stable machine tokens (for SARIF `properties.etherfenceCategory` and any future kebab-label rendering), and a `.label()` accessor for human display ("Inventory", "Informational", "Scored risk").
- `#[default]` is `Risk` — the most conservative/scored option (Principle I), used only as the `#[serde(default)]` fallback for `Finding.category` when deserializing data that predates this field.

## Changed: `Finding` (etherfence-core)

```rust
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub kind: FindingKind,
    pub agent: AgentKind,
    pub target: String,
    pub config_path: String,
    pub rationale: String,
    pub impact: String,
    pub recommendation: String,
    pub references: Vec<String>,
    pub fingerprint: String,
    pub baseline_status: BaselineStatus,
    #[serde(default)]
    pub policy_status: PolicyStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    #[serde(default)]                      // NEW FIELD
    pub category: FindingCategory,          // NEW FIELD
}
```

Placed after `evidence` (append at the end) to keep the JSON field order stable for anything doing positional diffing, and to match the project's convention of appending new fields at the struct's tail (see `policy_status`/`policy_id` additions in prior releases).

### Finding-kind → category assignment (unchanged severities except the two called out)

| ID | `FindingKind` | Severity (before → after) | Category |
|---|---|---|---|
| `EF-CFG-001` | `ConfigParseError` | Low → Low (unchanged) | Risk |
| `EF-MCP-000` | `McpServerConfigured` | **Low → Info** | **Inventory** |
| `EF-MCP-001` | `BroadFilesystemAccess` | High → High (unchanged) | Risk |
| `EF-MCP-002` | `RiskyCommandToolHint` | Medium → Medium (unchanged) | Risk |
| `EF-MCP-003` | `NetworkCapableToolHint` | Medium → Medium (unchanged) | Risk |
| `EF-MCP-004` | `ExposedMcpEnvironment` | **Low → Info** | **Inventory** |
| `EF-SEC-001` | `SecretLookingEnvName` | Medium → Medium (unchanged) | Risk |
| `EF-TIRITH-001` | `TirithBinaryDetected` | Info → Info (unchanged) | Informational |
| `EF-TIRITH-002` | `TirithConfigDetected` | Info → Info (unchanged) | Informational |
| `EF-POL-001..005` | `Policy*` | unchanged | Risk |

`EF-CFG-001` is explicitly kept as `Risk`/unchanged: a config file that failed to parse is an actionable operational problem (the required outcomes only name `EF-MCP-000` and generic env-var presence for reclassification; widening scope to `EF-CFG-001` is out of scope per Scope Discipline).

## Changed: evidence string format (no type change, `Vec<String>` unchanged)

| Detector | Evidence today | Evidence after |
|---|---|---|
| `mcp_configured` (`EF-MCP-000`) | `server=<name>`, `command=<v>`, `url=<v>` | unchanged (already labeled) |
| `broad_filesystem` (`EF-MCP-001`) | bare matched value(s), e.g. `filesystem`, `/home/user` | `server=<v>` / `command=<v>` / `args[<i>]=<v>` / `url=<v>` |
| `shell_capable` (`EF-MCP-002`) | bare matched value(s) | same labeled scheme |
| `network_capable` (`EF-MCP-003`) | bare matched value(s) | same labeled scheme |
| `exposed_env` (`EF-MCP-004`) | bare env var name(s) | `env=<name>` |
| `secret_env_name` (`EF-SEC-001`) | bare env var name(s) | `env=<name>` |

Never includes a redacted secret *value* — only names/patterns, exactly as today (`redact_env_value()` in `etherfence-inventory` still turns values into `<set>`/`<empty>` before a `Finding` ever sees them).

**Fingerprint consequence**: `finding_fingerprint()` hashes evidence, so `EF-MCP-001/002/003/004` and `EF-SEC-001` fingerprints change for any finding whose evidence previously lacked a label. This is why the baseline schema version bumps (see below) — old baseline files fail closed with a clear regenerate message rather than silently mismatching.

## Changed: `PostureSummary::from_findings` (etherfence-core)

Behavior change: the active-finding population used for `score`, `grade`, `active_findings`, `high`, `medium`, `low`, `info`, `priority_risks`, and `recommended_actions` is now filtered to `category == FindingCategory::Risk` (in addition to the existing `baseline_status != Resolved` filter). The score formula weights themselves are unchanged: `score = clamp(100 - 25*high - 10*medium - 2*low, 0, 100)`.

No new fields on `PostureSummary` — same struct shape, narrower input population.

## Changed: schema versions

| Schema | Before | After |
|---|---|---|
| Scan report | `ef-scan-report/v0.1.2` | `ef-scan-report/v0.1.3` |
| Baseline file | `ef-baseline/v0.1.3` | `ef-baseline/v0.1.4` |

Both constants (`"ef-scan-report/v0.1.2".to_string()` literal in `main.rs`/`verbose.rs`'s debug line, and `BASELINE_SCHEMA_VERSION` in `main.rs`) get updated at every occurrence.

## Unchanged

- `Summary`/`Summary::from_counts` — no code change; naturally reflects new severities once detector templates change.
- `ProtectionCoverage`, `PolicyMetadata`, `BaselineComparison` — untouched.
- SARIF `level` mapping (`sarif_level`) — stays purely severity-based; unaffected by category.
- SARIF gains one new additive `properties.etherfenceCategory` field per result (analogous to the existing `etherfenceSeverity`), not a version-relevant change to the SARIF format itself.
