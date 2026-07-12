# Data Model: Protection Coverage (v1.7.2)

## New Types (etherfence-core)

### CoverageStatus

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    /// Server is in the agent's allowed_mcp_servers list.
    Covered,
    /// Server is NOT in the agent's allowed_mcp_servers list.
    NotCovered,
    /// No [agents.<name>] section exists for this agent in the policy.
    NoPolicyForAgent,
    /// Agent section exists but allowed_mcp_servers is empty (implicit allow-all).
    EmptyAllowlist,
    /// Coverage not applicable (e.g., Tirith inventory items).
    NotApplicable,
}
```

### ServerCoverage

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerCoverage {
    pub agent: AgentKind,
    pub server_name: String,
    pub status: CoverageStatus,
    pub config_path: String,
}
```

### ProtectionCoverage

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectionCoverage {
    pub total_servers: usize,
    pub covered: usize,
    pub uncovered: usize,
    pub no_policy_for_agent: usize,
    pub empty_allowlist: usize,
    pub not_applicable: usize,
    pub servers: Vec<ServerCoverage>,
}
```

## Modified Types

### ScanReport (additive field)

```rust
pub struct ScanReport {
    // ... existing fields unchanged ...
    pub schema_version: String,
    pub tool: String,
    pub version: String,
    pub status: String,
    pub scanned_root: String,
    pub inventory: Vec<InventoryItem>,
    pub findings: Vec<Finding>,
    pub summary: Summary,
    pub policy: Option<PolicyMetadata>,
    pub baseline: Option<BaselineComparison>,
    // NEW:
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protection_coverage: Option<ProtectionCoverage>,
}
```

### PolicyEvaluation (additive field)

```rust
pub struct PolicyEvaluation {
    pub policy_schema_version: String,
    pub policy_name: String,
    pub policy_description: String,
    pub require_tirith: bool,
    pub findings: Vec<Finding>,
    pub checks_total: usize,
    pub pass: usize,
    pub violation: usize,
    pub not_applicable: usize,
    // NEW:
    pub coverage: ProtectionCoverage,
}
```

## JSON Schema (ef-scan-report/v0.1.2)

The `protection_coverage` field is optional. When absent, the report is
identical to `ef-scan-report/v0.1.1`.

```json
{
  "schema_version": "ef-scan-report/v0.1.2",
  "protection_coverage": {
    "total_servers": 8,
    "covered": 5,
    "uncovered": 2,
    "no_policy_for_agent": 0,
    "empty_allowlist": 0,
    "not_applicable": 1,
    "servers": [
      {
        "agent": "claude-code",
        "server_name": "filesystem",
        "status": "covered",
        "config_path": "~/.claude.json"
      }
    ]
  }
}
```

## Ordering

`servers` is sorted deterministically:
1. `agent.key()` ascending
2. `config_path` ascending
3. `server_name` ascending

## Coverage Status Decision Matrix

| Condition | Status |
|---|---|
| Agent is Tirith | `NotApplicable` |
| No `[agents.<agent_display_name>]` or `[agents.<agent_key>]` section | `NoPolicyForAgent` |
| Section exists, `allowed_mcp_servers` is empty | `EmptyAllowlist` |
| Section exists, server name matches allowed list | `Covered` |
| Section exists, server name does NOT match allowed list | `NotCovered` |

## Name Matching

Uses the existing `check_mcp_server` logic:
1. If `allowed_mcp_servers` is empty → `EmptyAllowlist` (implicit allow-all)
2. If any entry in `allowed_mcp_servers` matches via `same_name()` → `Covered`
3. Otherwise → `NotCovered`

Agent lookup uses the existing dual-key strategy:
1. `agent.display_name()` (e.g., "Claude Code")
2. Falls back to `agent.key()` (e.g., "claude-code")
