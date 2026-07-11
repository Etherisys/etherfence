# Phase 1 Data Model: Guided Secure Setup

This extends the existing `etherfence-setup` and `etherfence-inventory` crate models. Only new/changed shapes are described.

## ClientAdapter (new trait in inventory crate)

```rust
/// A client adapter describes one AI client's detection, parsing, and writing
/// behavior. Each supported AI client implements this trait.
pub trait ClientAdapter {
    /// Stable identifier matching AgentKind variant.
    fn agent_kind(&self) -> AgentKind;

    /// Human-readable display name.
    fn display_name(&self) -> &'static str;

    /// Executable names to search on PATH for installation detection.
    fn binary_names(&self) -> &'static [&'static str];

    /// Known installation directories (relative to HOME/APPDATA).
    fn install_dirs(&self) -> &'static [&'static str];

    /// Known config file paths (relative to HOME/APPDATA), with format hint.
    fn config_probes(&self) -> &'static [ConfigProbe];

    /// Known project/workspace config paths.
    fn project_probes(&self) -> &'static [&'static str];

    /// Can EtherFence parse MCP server config from this client?
    fn read_support(&self) -> ReadSupport;

    /// Can EtherFence safely rewrite MCP server config for this client?
    fn write_support(&self) -> WriteSupport;

    /// Parse MCP servers from a config file's raw content.
    fn parse_mcp_servers(&self, content: &str, format: ConfigFormat) -> ParsedMcpResult;
}
```

## ConfigProbe

```rust
pub struct ConfigProbe {
    /// Relative path from scan root (HOME).
    pub relative_path: &'static str,
    /// Expected format (JSON, YAML, TOML).
    pub format: ConfigFormat,
    /// Root key(s) where MCP servers live in this format.
    pub mcp_key: McpKey,
}

pub enum McpKey {
    /// Standard "mcpServers" object at top level.
    TopLevelMcpServers,
    /// Nested under "mcp" -> "servers" (VS Code settings.json).
    NestedMcpServers,
    /// OpenCode: "mcp" -> {name} -> {type:"local", command: [...]}
    OpenCodeMcp,
    /// Hermes: YAML "mcp_servers:" key.
    HermesMcpServers,
    /// Codex CLI: TOML "[mcp_servers]" tables.
    CodexTomlMcpServers,
    /// Antigravity: "mcpServers" with serverUrl remote support.
    AntigravityMcpServers,
}
```

## ConfigFormat (extended)

```rust
pub enum ConfigFormat {
    Json,
    Toml,
    Yaml,       // NEW: Hermes config.yaml
    PresenceOnly,
}
```

## ReadSupport (new enum)

```rust
pub enum ReadSupport {
    /// Full MCP server parsing from config.
    Full,
    /// Config file detected but MCP parsing not yet implemented.
    PresenceOnly,
    /// Config format not supported.
    Unsupported,
}
```

## WriteSupport (existing, unchanged)

```rust
pub enum WriteSupport {
    Supported,
    AdvisoryOnly,
}
```

## ClientDetection (new struct — replaces single boolean)

```rust
pub struct ClientDetection {
    pub agent: AgentKind,
    pub display_name: String,

    /// Binary found on PATH.
    pub installed: bool,
    /// At least one config file found.
    pub configured: bool,
    /// Config files found (paths).
    pub config_paths: Vec<String>,
    /// Installation directories found.
    pub install_paths: Vec<String>,

    /// MCP servers parsed from config.
    pub mcp_servers: Vec<McpServer>,
    /// Detection evidence strings.
    pub evidence: Vec<String>,

    pub read_support: ReadSupport,
    pub write_support: WriteSupport,
}
```

Derived field for backward compatibility: `found_locally = installed || configured`.

## SetupWizardPlan (new struct)

```rust
pub struct SetupWizardPlan {
    pub root: String,
    pub detections: Vec<ClientDetection>,
    /// Servers selected by user for wrapping.
    pub selected_servers: Vec<SelectedServer>,
    /// Servers skipped by user.
    pub skipped_servers: Vec<SkippedServer>,
    /// Package pinning changes to apply.
    pub pinning_changes: Vec<PinningChange>,
    /// Generated policies.
    pub policies: Vec<PolicyGeneration>,
    /// Actions derived from selections (mirrors SetupAction).
    pub actions: Vec<SetupAction>,
}
```

## SelectedServer

```rust
pub struct SelectedServer {
    pub agent: AgentKind,
    pub config_path: String,
    pub server_name: String,
    pub policy_type: PolicyType,
    /// If CustomToolAllowlist, the user-entered tool names.
    pub custom_tool_allowlist: Vec<String>,
}
```

## PolicyType

```rust
pub enum PolicyType {
    /// tools.allow = [], methods.allow = ["tools/list"]
    DenyAllQuarantine,
    /// Fixture-verified curated policy (server-name → known policy file).
    Curated,
    /// User entered explicit tool names.
    CustomToolAllowlist,
}
```

## PinningChange

```rust
pub struct PinningChange {
    pub config_path: String,
    pub server_name: String,
    pub runner: PackageRunner,
    /// Original args (redacted package spec).
    pub original_args: Vec<String>,
    /// New args with exact version.
    pub new_args: Vec<String>,
    /// The exact version being pinned.
    pub pinned_version: String,
}
```

## PackageVersionStatus (new enum for trust integration)

```rust
pub enum PackageVersionStatus {
    ExactPin(String),       // e.g. "@1.2.3", "==1.2.3"
    Omitted,                // no version at all
    MutableTag(String),     // @latest, @next, @beta
    Range(String),          // ^1.2.0, ~1.2.0, >=1.2
    Ambiguous,              // malformed or unrecognized
    NotApplicable,          // not a package-runner command
}
```

## GuidedStep (wizard state machine)

```rust
pub enum GuidedStep {
    Scan,
    SelectClients,
    SelectServers,
    ResolveBlockers,
    SelectPosture,
    Preview,
    Confirm,
    Complete,
}
```

## Schema Compatibility

No existing schemas are version-bumped. Changes are additive:
- `ClientDetection` is a new struct; existing `SetupDetection` preserved for backward compat in machine-readable output.
- `generated_policy_template()` changes output content but not the TOML schema grammar.
- The catalog's 10-row matrix remains the same; `found_locally` is derived from new fields.
