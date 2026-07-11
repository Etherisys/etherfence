use anyhow::{Context, Result};
use etherfence_core::{read_bounded_text_file, MAX_CONFIG_FILE_BYTES};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use crate::unicode::{
    inspect_method_name, inspect_path_value, inspect_policy_identifier, inspect_tool_name,
};

pub const SUPPORTED_MCP_POLICY_SCHEMA_VERSION: &str = "ef-mcp-policy/v0.1";
/// Schema version that unlocks the v0.2 argument/param guard constructs
/// (`require_keys`, `forbid_keys`, `fields`) documented in
/// `specs/004-argument-aware-mcp-policy/contracts/ef-mcp-policy-v0.2.md`.
/// v0.1 parsing and evaluation are otherwise completely unchanged.
pub const SUPPORTED_MCP_POLICY_SCHEMA_VERSION_V2: &str = "ef-mcp-policy/v0.2";
/// All schema versions this build accepts, in the order checked.
pub const SUPPORTED_MCP_POLICY_SCHEMA_VERSIONS: &[&str] = &[
    SUPPORTED_MCP_POLICY_SCHEMA_VERSION,
    SUPPORTED_MCP_POLICY_SCHEMA_VERSION_V2,
];
/// Maximum number of `.`-separated segments a v0.2 field-guard selector may
/// have. Bounded so selector resolution is always O(1) work relative to
/// policy size, never request-content-dependent.
const MAX_SELECTOR_SEGMENTS: usize = 8;

/// Methods the proxy always allows because they are required for MCP protocol
/// initialization and liveness. These are never subject to method policy and
/// are always forwarded to the server.
pub const ALWAYS_ALLOWED_METHODS: &[&str] = &["initialize", "notifications/initialized", "ping"];

/// The built-in default allowed method list when no `[methods]` section is
/// present in the policy. This preserves v0.2.x behavior: only `tools/list`
/// and `tools/call` are allowed; everything else is denied by default.
pub const DEFAULT_ALLOWED_METHODS: &[&str] = &["tools/list", "tools/call"];

/// Direction of an MCP/JSON-RPC request through the stdio proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodDirection {
    ClientToServer,
    ServerToClient,
}

impl MethodDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            MethodDirection::ClientToServer => "client_to_server",
            MethodDirection::ServerToClient => "server_to_client",
        }
    }
}

/// Minimal MCP boundary proxy policy: exact-match tool-name allow/deny lists
/// plus optional method-level allow/deny lists.
#[derive(Debug, Clone, Deserialize)]
pub struct McpPolicyFile {
    pub schema_version: String,
    pub name: String,
    #[serde(default)]
    pub tools: ToolRules,
    #[serde(default)]
    pub methods: Option<MethodRules>,
    #[serde(default)]
    pub path_rules: BTreeMap<String, PathRule>,
    #[serde(default)]
    pub servers: BTreeMap<String, ServerPolicy>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ServerPolicy {
    #[serde(default)]
    pub tools: ToolRules,
    #[serde(default)]
    pub methods: Option<MethodRules>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ToolRules {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(flatten)]
    pub path_guards: BTreeMap<String, ToolPathGuard>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ToolPathGuard {
    #[serde(default)]
    pub arguments: Option<ArgumentGuard>,
}

/// Method-level allow/deny rules. When present, these control which JSON-RPC
/// methods the proxy forwards to the server. When absent, the built-in default
/// allows only `tools/list` and `tools/call`.
///
/// The `allow` and `deny` lists use exact string matching. A special entry
/// `"*"` in the `allow` list means "allow all known and unknown methods"
/// (explicitly opt-in permissive). The deny list always wins over allow.
///
/// Unknown methods (not in any list and not in the built-in defaults) are
/// denied by default unless explicitly allowed.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct MethodRules {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(flatten)]
    pub path_guards: BTreeMap<String, MethodPathGuard>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct MethodPathGuard {
    #[serde(default)]
    pub params: Option<ArgumentGuard>,
}

/// One guarded `arguments` (tool call) or `params` (method) object: the v0.1
/// path/URI containment guard plus the v0.2 structural argument guards
/// (required/forbidden keys and per-selector field guards). All v0.2 fields
/// default to empty so a v0.1 policy's `arguments`/`params` table parses
/// exactly as it always has.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ArgumentGuard {
    #[serde(default)]
    pub path_keys: Vec<String>,
    #[serde(default)]
    pub uri_keys: Vec<String>,
    /// Required whenever `path_keys`/`uri_keys` is non-empty (enforced by
    /// `validate_argument_guard`, not by serde) so v0.1's "path_rule is
    /// mandatory" behavior is unchanged; made `Option` at the type level only
    /// so a v0.2 policy can configure a guard with no path containment at
    /// all.
    #[serde(default)]
    pub path_rule: Option<String>,
    /// v0.2: keys that must be present in the guarded object.
    #[serde(default)]
    pub require_keys: Vec<String>,
    /// v0.2: keys that must be absent from the guarded object.
    #[serde(default)]
    pub forbid_keys: Vec<String>,
    /// v0.2: per-selector field guards, keyed by the bounded selector syntax
    /// (see `validate_selector`). `BTreeMap` keeps iteration deterministic.
    #[serde(default)]
    pub fields: BTreeMap<String, FieldGuard>,
}

/// A TOML-native scalar used by `FieldGuard::Exact`, `FieldGuard::Enum`, and
/// `FieldGuard::ArrayGuard::allowed_elements`. Comparison against a request's
/// JSON value is exact type-and-value equality; there is no cross-type
/// coercion (an `Int` never matches a JSON string, etc).
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(untagged)]
pub enum ScalarValue {
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
}

impl ScalarValue {
    fn matches(&self, value: &Value) -> bool {
        match (self, value) {
            (ScalarValue::Bool(expected), Value::Bool(actual)) => expected == actual,
            (ScalarValue::Str(expected), Value::String(actual)) => expected == actual,
            (ScalarValue::Int(expected), Value::Number(actual)) => {
                actual.as_i64() == Some(*expected)
            }
            (ScalarValue::Float(expected), Value::Number(actual)) => {
                actual.as_f64() == Some(*expected)
            }
            _ => false,
        }
    }
}

/// A single v0.2 field-guard primitive, targeting one selector inside a
/// guarded `arguments`/`params` object. Every variant fails closed
/// (`field_missing`/`field_wrong_type`) when the selector does not resolve
/// to a value of the expected JSON kind — see `evaluate_field_guard`.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum FieldGuard {
    #[serde(rename = "exact")]
    Exact { value: ScalarValue },
    #[serde(rename = "enum")]
    Enum { values: Vec<ScalarValue> },
    #[serde(rename = "string")]
    StringGuard {
        #[serde(default)]
        min_length: Option<usize>,
        #[serde(default)]
        max_length: Option<usize>,
        #[serde(default)]
        prefix: Option<String>,
    },
    #[serde(rename = "number")]
    NumberGuard {
        #[serde(default)]
        min: Option<f64>,
        #[serde(default)]
        max: Option<f64>,
    },
    #[serde(rename = "array")]
    ArrayGuard {
        #[serde(default)]
        min_items: Option<usize>,
        #[serde(default)]
        max_items: Option<usize>,
        #[serde(default)]
        allowed_elements: Option<Vec<ScalarValue>>,
    },
    #[serde(rename = "url")]
    UrlGuard {
        #[serde(default)]
        schemes: Vec<String>,
        #[serde(default)]
        hosts: Vec<String>,
        #[serde(default)]
        ports: Vec<u16>,
        #[serde(default)]
        path_prefixes: Vec<String>,
    },
}

impl FieldGuard {
    /// The `type =` tag this guard was configured with, for `mcp-policy
    /// explain` and audit-safe display; never includes configured values.
    pub fn kind(&self) -> &'static str {
        match self {
            FieldGuard::Exact { .. } => "exact",
            FieldGuard::Enum { .. } => "enum",
            FieldGuard::StringGuard { .. } => "string",
            FieldGuard::NumberGuard { .. } => "number",
            FieldGuard::ArrayGuard { .. } => "array",
            FieldGuard::UrlGuard { .. } => "url",
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct PathRule {
    #[serde(default)]
    pub allow_roots: Vec<String>,
    #[serde(default)]
    pub deny_roots: Vec<String>,
}

/// The decision the proxy made for one MCP tool call or method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
    PolicyError,
}

impl Decision {
    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Deny => "deny",
            Decision::PolicyError => "policy_error",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDecision {
    pub decision: Decision,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathInputKind {
    Path,
    Uri,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathPolicyDecision {
    pub decision: Decision,
    pub reason: String,
    pub rule_name: String,
    pub key_name: String,
    pub classification: String,
}

/// The decision produced by a v0.2 argument/param guard (`require_keys`,
/// `forbid_keys`, or a `fields` selector). Sibling of [`PathPolicyDecision`];
/// never carries the evaluated request value, only safe identifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardPolicyDecision {
    pub decision: Decision,
    pub reason: String,
    pub guard_key: String,
    pub selector: String,
    pub reason_category: String,
}

// `path` here is an explicit, trusted-operator CLI input (`mcp-proxy
// --policy`); see the doc comment on `read_bounded_text_file` for the
// CLI-vs-future-API path trust model this crate follows.
pub fn load_mcp_policy(path: &Path) -> Result<McpPolicyFile> {
    let content = read_bounded_text_file(path, MAX_CONFIG_FILE_BYTES)
        .with_context(|| format!("reading MCP proxy policy file {}", path.display()))?;
    parse_mcp_policy(&content)
        .with_context(|| format!("parsing MCP proxy policy file {}", path.display()))
}

pub fn parse_mcp_policy(content: &str) -> Result<McpPolicyFile> {
    let policy: McpPolicyFile = toml::from_str(content)?;
    if !SUPPORTED_MCP_POLICY_SCHEMA_VERSIONS.contains(&policy.schema_version.as_str()) {
        anyhow::bail!(
            "unsupported MCP proxy policy schema_version {:?}; supported schema_version values are {:?}",
            policy.schema_version,
            SUPPORTED_MCP_POLICY_SCHEMA_VERSIONS
        );
    }
    if policy.name.trim().is_empty() {
        anyhow::bail!("MCP proxy policy name must not be empty");
    }
    validate_policy_unicode_hygiene(&policy)?;
    for (name, rule) in &policy.path_rules {
        if name.trim().is_empty() {
            anyhow::bail!("MCP proxy path rule names must not be empty");
        }
        if rule.allow_roots.is_empty() {
            anyhow::bail!(
                "MCP proxy path rule {name:?} must configure at least one allow_roots entry"
            );
        }
    }
    Ok(policy)
}

fn validate_policy_unicode_hygiene(policy: &McpPolicyFile) -> Result<()> {
    let is_v2 = policy.schema_version == SUPPORTED_MCP_POLICY_SCHEMA_VERSION_V2;
    validate_policy_identifier(&policy.name, "MCP proxy policy name")?;
    validate_tool_rules(&policy.tools, is_v2, "global tool policy")?;
    if let Some(methods) = &policy.methods {
        validate_method_rules(methods, is_v2, "global method policy")?;
    }
    for rule_name in policy.path_rules.keys() {
        validate_policy_identifier(rule_name, "MCP proxy path rule name")?;
    }
    for (server_name, server) in &policy.servers {
        validate_policy_identifier(server_name, "MCP proxy server policy name")?;
        validate_tool_rules(&server.tools, is_v2, "server-specific tool policy")?;
        if let Some(methods) = &server.methods {
            validate_method_rules(methods, is_v2, "server-specific method policy")?;
        }
    }
    Ok(())
}

fn validate_tool_rules(rules: &ToolRules, is_v2: bool, context: &str) -> Result<()> {
    for tool_name in rules.allow.iter().chain(rules.deny.iter()) {
        validate_tool_name(tool_name, context)?;
    }
    for (tool_name, guard) in &rules.path_guards {
        validate_tool_name(tool_name, "MCP proxy tool path guard key")?;
        if let Some(arguments) = &guard.arguments {
            validate_argument_guard(arguments, is_v2, "MCP proxy tool argument guard")?;
        }
    }
    Ok(())
}

fn validate_method_rules(rules: &MethodRules, is_v2: bool, context: &str) -> Result<()> {
    for method in rules.allow.iter().chain(rules.deny.iter()) {
        validate_method_name(method, context)?;
    }
    for (method, guard) in &rules.path_guards {
        validate_method_name(method, "MCP proxy method path guard key")?;
        if let Some(params) = &guard.params {
            validate_argument_guard(params, is_v2, "MCP proxy method param guard")?;
        }
    }
    Ok(())
}

/// Validates one `arguments`/`params` guard table: the v0.1 path/URI
/// containment fields (unchanged rules) plus, when present, the v0.2
/// structural guards. Fails closed on any duplicate/conflicting, unbounded,
/// or otherwise malformed construct per FR-015 through FR-019.
fn validate_argument_guard(guard: &ArgumentGuard, is_v2: bool, context: &str) -> Result<()> {
    let has_path_fields = !guard.path_keys.is_empty() || !guard.uri_keys.is_empty();
    match &guard.path_rule {
        Some(path_rule) => {
            validate_policy_identifier(path_rule, "MCP proxy referenced path rule name")?
        }
        None if has_path_fields => {
            anyhow::bail!("{context} must configure path_rule when path_keys or uri_keys is set")
        }
        None => {}
    }
    for key in guard.path_keys.iter().chain(guard.uri_keys.iter()) {
        validate_policy_identifier(key, context)?;
    }

    let has_v2_construct =
        !guard.require_keys.is_empty() || !guard.forbid_keys.is_empty() || !guard.fields.is_empty();
    if has_v2_construct && !is_v2 {
        anyhow::bail!(
            "{context} uses ef-mcp-policy/v0.2 argument-guard fields (require_keys/forbid_keys/fields) \
             but the policy schema_version is not {SUPPORTED_MCP_POLICY_SCHEMA_VERSION_V2:?}"
        );
    }
    if !has_v2_construct {
        return Ok(());
    }

    for key in guard.require_keys.iter().chain(guard.forbid_keys.iter()) {
        validate_policy_identifier(key, context)?;
    }
    let required: HashSet<&str> = guard.require_keys.iter().map(String::as_str).collect();
    for forbidden in &guard.forbid_keys {
        if required.contains(forbidden.as_str()) {
            anyhow::bail!(
                "{context} key {forbidden:?} is listed in both require_keys and forbid_keys"
            );
        }
    }

    for (selector, field_guard) in &guard.fields {
        validate_selector(selector, context)?;
        validate_field_guard(field_guard, context)?;
    }
    Ok(())
}

/// Validates a v0.2 field-guard selector: non-empty, bounded depth,
/// `[A-Za-z0-9_-]+` segments only, each passing the same Unicode-hygiene
/// check used for every other policy identifier.
fn validate_selector(selector: &str, context: &str) -> Result<()> {
    if selector.trim().is_empty() {
        anyhow::bail!("{context} selector must not be empty");
    }
    let segments: Vec<&str> = selector.split('.').collect();
    if segments.len() > MAX_SELECTOR_SEGMENTS {
        anyhow::bail!(
            "{context} selector {selector:?} exceeds the maximum of {MAX_SELECTOR_SEGMENTS} segments"
        );
    }
    for segment in &segments {
        if segment.is_empty() {
            anyhow::bail!("{context} selector {selector:?} has an empty segment");
        }
        if let Some(risk) = inspect_policy_identifier(segment) {
            anyhow::bail!(
                "{context} selector {selector:?} rejected: {}",
                risk.reason()
            );
        }
        if !segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            anyhow::bail!(
                "{context} selector {selector:?} has a segment with a disallowed character"
            );
        }
    }
    Ok(())
}

fn validate_field_guard(guard: &FieldGuard, context: &str) -> Result<()> {
    match guard {
        FieldGuard::Exact { .. } => {}
        FieldGuard::Enum { values } => {
            if values.is_empty() {
                anyhow::bail!("{context} enum guard must configure at least one value");
            }
        }
        FieldGuard::StringGuard {
            min_length,
            max_length,
            ..
        } => validate_bounds(*min_length, *max_length, context)?,
        FieldGuard::NumberGuard { min, max } => {
            if let (Some(min), Some(max)) = (min, max) {
                if min > max {
                    anyhow::bail!("{context} number guard min must not exceed max");
                }
            }
        }
        FieldGuard::ArrayGuard {
            min_items,
            max_items,
            allowed_elements,
        } => {
            validate_bounds(*min_items, *max_items, context)?;
            if let Some(allowed) = allowed_elements {
                if allowed.is_empty() {
                    anyhow::bail!(
                        "{context} array guard allowed_elements must not be empty when configured"
                    );
                }
            }
        }
        FieldGuard::UrlGuard {
            schemes,
            hosts,
            ports,
            path_prefixes,
        } => {
            for scheme in schemes {
                let lower = scheme.to_ascii_lowercase();
                if lower != "http" && lower != "https" {
                    anyhow::bail!(
                        "{context} url guard scheme {scheme:?} is not supported (only http/https)"
                    );
                }
            }
            for host in hosts {
                if host.is_empty()
                    || !host.is_ascii()
                    || host.contains('@')
                    || host.contains('/')
                    || host.chars().any(char::is_whitespace)
                {
                    anyhow::bail!("{context} url guard host {host:?} is invalid");
                }
                if let Some(risk) = inspect_policy_identifier(host) {
                    anyhow::bail!(
                        "{context} url guard host {host:?} rejected: {}",
                        risk.reason()
                    );
                }
            }
            for prefix in path_prefixes {
                let valid = prefix == "/" || (prefix.starts_with('/') && prefix.ends_with('/'));
                if !valid {
                    anyhow::bail!(
                        "{context} url guard path_prefixes entry {prefix:?} must be \"/\" or start and end with '/'"
                    );
                }
            }
            if schemes.is_empty()
                && hosts.is_empty()
                && ports.is_empty()
                && path_prefixes.is_empty()
            {
                anyhow::bail!(
                    "{context} url guard configures no constraints (schemes/hosts/ports/path_prefixes are all empty)"
                );
            }
        }
    }
    Ok(())
}

fn validate_bounds(min: Option<usize>, max: Option<usize>, context: &str) -> Result<()> {
    if let (Some(min), Some(max)) = (min, max) {
        if min > max {
            anyhow::bail!("{context} guard min must not exceed max");
        }
    }
    Ok(())
}

fn validate_policy_identifier(value: &str, context: &str) -> Result<()> {
    if let Some(risk) = inspect_policy_identifier(value) {
        anyhow::bail!("{context} rejected: {}", risk.reason());
    }
    Ok(())
}

fn validate_method_name(value: &str, context: &str) -> Result<()> {
    if let Some(risk) = inspect_method_name(value) {
        anyhow::bail!("{context} rejected: {}", risk.reason());
    }
    Ok(())
}

fn validate_tool_name(value: &str, context: &str) -> Result<()> {
    if let Some(risk) = inspect_tool_name(value) {
        anyhow::bail!("{context} rejected: {}", risk.reason());
    }
    Ok(())
}

pub fn decide_tool_argument_paths(
    policy: &McpPolicyFile,
    tool_name: &str,
    arguments: Option<&serde_json::Value>,
) -> Option<PathPolicyDecision> {
    let guard = policy
        .tools
        .path_guards
        .get(tool_name)?
        .arguments
        .as_ref()?;
    // A guard table with no `path_rule` is a v0.2-only guard (require_keys /
    // forbid_keys / fields, no path containment at all); there is nothing
    // for the v0.1 path decision to evaluate.
    guard.path_rule.as_ref()?;
    Some(decide_path_keys(
        policy,
        guard,
        arguments,
        PathInputKind::Path,
    ))
}

pub fn decide_method_param_paths(
    policy: &McpPolicyFile,
    method: &str,
    params: Option<&serde_json::Value>,
) -> Option<PathPolicyDecision> {
    let guard = policy
        .methods
        .as_ref()?
        .path_guards
        .get(method)?
        .params
        .as_ref()?;
    guard.path_rule.as_ref()?;
    Some(decide_path_keys(policy, guard, params, PathInputKind::Uri))
}

fn decide_path_keys(
    policy: &McpPolicyFile,
    guard: &ArgumentGuard,
    container: Option<&serde_json::Value>,
    default_kind: PathInputKind,
) -> PathPolicyDecision {
    let rule_name = guard
        .path_rule
        .clone()
        .expect("caller guarantees path_rule is Some");
    let Some(rule) = policy.path_rules.get(&rule_name) else {
        return path_decision(
            Decision::Deny,
            "path rule referenced by path guard was not found",
            rule_name,
            first_configured_key(guard),
            "rule_not_found",
        );
    };

    for key in &guard.path_keys {
        let decision = decide_one_path_key(rule, &rule_name, container, key, PathInputKind::Path);
        if decision.decision != Decision::Allow {
            return decision;
        }
    }
    for key in &guard.uri_keys {
        let decision = decide_one_path_key(rule, &rule_name, container, key, PathInputKind::Uri);
        if decision.decision != Decision::Allow {
            return decision;
        }
    }
    if guard.path_keys.is_empty() && guard.uri_keys.is_empty() {
        return path_decision(
            Decision::Deny,
            "path guard has no configured path_keys or uri_keys",
            rule_name,
            "<none>".to_string(),
            "path_parse_error",
        );
    }

    path_decision(
        Decision::Allow,
        match default_kind {
            PathInputKind::Path => {
                "path argument is inside an allowed root and outside denied roots"
            }
            PathInputKind::Uri => {
                "URI parameter resolves inside an allowed root and outside denied roots"
            }
        },
        rule_name,
        first_configured_key(guard),
        "inside_allowed_root",
    )
}

fn decide_one_path_key(
    rule: &PathRule,
    rule_name: &str,
    container: Option<&serde_json::Value>,
    key: &str,
    kind: PathInputKind,
) -> PathPolicyDecision {
    let Some(value) = container
        .and_then(serde_json::Value::as_object)
        .and_then(|object| object.get(key))
        .and_then(serde_json::Value::as_str)
    else {
        return path_decision(
            Decision::Deny,
            "path-like key is missing or is not a string",
            rule_name.to_string(),
            key.to_string(),
            "path_parse_error",
        );
    };
    evaluate_path_value(rule, rule_name, key, kind, value)
}

fn evaluate_path_value(
    rule: &PathRule,
    rule_name: &str,
    key: &str,
    kind: PathInputKind,
    raw_value: &str,
) -> PathPolicyDecision {
    if inspect_path_value(raw_value).is_some() {
        return path_decision(
            Decision::Deny,
            "unicode_suspicious_path_value",
            rule_name.to_string(),
            key.to_string(),
            "unicode_suspicious_path_value",
        );
    }
    let Some(candidate) = normalize_path_value(raw_value, kind) else {
        return path_decision(
            Decision::Deny,
            "path-like value could not be parsed or normalized",
            rule_name.to_string(),
            key.to_string(),
            "path_parse_error",
        );
    };
    let allow_roots: Option<Vec<String>> = rule
        .allow_roots
        .iter()
        .map(|root| normalize_path_value(root, PathInputKind::Path))
        .collect();
    let Some(allow_roots) = allow_roots else {
        return path_decision(
            Decision::Deny,
            "configured allow root could not be parsed or normalized",
            rule_name.to_string(),
            key.to_string(),
            "path_parse_error",
        );
    };
    let deny_roots: Option<Vec<String>> = rule
        .deny_roots
        .iter()
        .map(|root| normalize_path_value(root, PathInputKind::Path))
        .collect();
    let Some(deny_roots) = deny_roots else {
        return path_decision(
            Decision::Deny,
            "configured deny root could not be parsed or normalized",
            rule_name.to_string(),
            key.to_string(),
            "path_parse_error",
        );
    };
    if deny_roots
        .iter()
        .any(|root| path_has_root(&candidate, root))
    {
        return path_decision(
            Decision::Deny,
            "inside_denied_root",
            rule_name.to_string(),
            key.to_string(),
            "inside_denied_root",
        );
    }
    if !allow_roots
        .iter()
        .any(|root| path_has_root(&candidate, root))
    {
        return path_decision(
            Decision::Deny,
            "outside_allowed_roots",
            rule_name.to_string(),
            key.to_string(),
            "outside_allowed_roots",
        );
    }
    path_decision(
        Decision::Allow,
        "inside_allowed_root",
        rule_name.to_string(),
        key.to_string(),
        "inside_allowed_root",
    )
}

fn normalize_path_value(raw_value: &str, kind: PathInputKind) -> Option<String> {
    if raw_value.is_empty() || raw_value.contains('\0') {
        return None;
    }
    let local_path = match kind {
        PathInputKind::Path => {
            if raw_value.contains("://") {
                return None;
            }
            raw_value.to_string()
        }
        PathInputKind::Uri => extract_file_uri_path(raw_value)?,
    };
    normalize_local_path(&local_path)
}

fn extract_file_uri_path(uri: &str) -> Option<String> {
    let rest = uri.strip_prefix("file://")?;
    if rest.contains('%') || rest.contains('\0') {
        return None;
    }
    if let Some(path) = rest.strip_prefix("localhost/") {
        return Some(format!("/{path}"));
    }
    if rest.starts_with('/') {
        return Some(rest.to_string());
    }
    None
}

fn normalize_local_path(raw_path: &str) -> Option<String> {
    let path = raw_path.replace('\\', "/");
    if is_windows_absolute(&path) {
        let drive = path[..1].to_ascii_lowercase();
        let rest = &path[2..];
        let components = normalize_components(rest)?;
        return Some(format!("{drive}:/{components}").to_ascii_lowercase());
    }
    if path.starts_with('/') {
        let components = normalize_components(&path)?;
        return Some(format!("/{components}"));
    }
    None
}

fn is_windows_absolute(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'/'
}

fn normalize_components(path: &str) -> Option<String> {
    let mut components: Vec<&str> = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            value if value.contains('\0') => return None,
            value => components.push(value),
        }
    }
    Some(components.join("/"))
}

fn path_has_root(candidate: &str, root: &str) -> bool {
    if root == "/" {
        return candidate.starts_with('/');
    }
    if root.len() == 3 && root.as_bytes()[1] == b':' && root.ends_with('/') {
        return candidate.starts_with(root);
    }
    candidate == root
        || candidate
            .strip_prefix(root)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn first_configured_key(guard: &ArgumentGuard) -> String {
    guard
        .path_keys
        .first()
        .or_else(|| guard.uri_keys.first())
        .cloned()
        .unwrap_or_else(|| "<none>".to_string())
}

fn path_decision(
    decision: Decision,
    reason: &str,
    rule_name: String,
    key_name: String,
    classification: &str,
) -> PathPolicyDecision {
    PathPolicyDecision {
        decision,
        reason: reason.to_string(),
        rule_name,
        key_name,
        classification: classification.to_string(),
    }
}

// --- v0.2 argument/param guards ---

/// Resolve a bounded selector (see `validate_selector`) against a JSON
/// value. Each segment is an object key or, when the current container is an
/// array, an all-digits index. Any mismatch (missing key, non-numeric index
/// against an array, out-of-range index, or a scalar reached before the
/// selector is exhausted) resolves to `None` — the caller treats this
/// identically to "field missing", which is the correct fail-closed
/// behavior for an unresolvable selector.
fn resolve_selector<'a>(container: &'a Value, selector: &str) -> Option<&'a Value> {
    let mut current = container;
    for segment in selector.split('.') {
        current = match current {
            Value::Object(map) => map.get(segment)?,
            Value::Array(items) => items.get(segment.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(current)
}

/// A URL guard value, parsed by hand (see
/// `specs/004-argument-aware-mcp-policy/research.md` Decisions 1-4): no
/// external URL-parsing dependency, ambiguity fails closed rather than being
/// guessed at.
struct ParsedGuardUrl {
    scheme: String,
    host: String,
    port: Option<u16>,
    path: String,
}

/// Parse a value as a URL guard would need to for scheme/host/port/path
/// matching. Returns `None` (malformed, fail closed) for: any `%` anywhere
/// in the value (percent-encoding is how allowlist checks get bypassed —
/// see Decision 3), any userinfo (`@`) in the authority (confusable-host
/// attack — see Decision 2), a non-ASCII or empty host, or an unparseable
/// scheme/authority.
fn parse_guarded_url(raw: &str) -> Option<ParsedGuardUrl> {
    if raw.is_empty() || raw.contains('%') || raw.contains('\0') {
        return None;
    }
    if inspect_path_value(raw).is_some() {
        return None;
    }
    let (scheme, rest) = raw.split_once("://")?;
    if scheme.is_empty() || !scheme.bytes().all(|b| b.is_ascii_alphabetic()) {
        return None;
    }
    let scheme = scheme.to_ascii_lowercase();
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let remainder = &rest[authority_end..];
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let (host_part, port_part) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    if host_part.is_empty() || !host_part.is_ascii() {
        return None;
    }
    let host = host_part.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty()
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return None;
    }
    let port = match port_part {
        Some(port) => Some(port.parse::<u16>().ok()?),
        None => default_port_for_scheme(&scheme),
    };
    let path = if remainder.is_empty() || remainder.starts_with('?') || remainder.starts_with('#') {
        "/".to_string()
    } else {
        let path_end = remainder.find(['?', '#']).unwrap_or(remainder.len());
        remainder[..path_end].to_string()
    };
    Some(ParsedGuardUrl {
        scheme,
        host,
        port,
        path,
    })
}

/// "Effective port" per research.md Decision 4: only `http`/`https` get an
/// implicit default; every other scheme requires an explicit `:port` for a
/// port allowlist to ever match.
fn default_port_for_scheme(scheme: &str) -> Option<u16> {
    match scheme {
        "http" => Some(80),
        "https" => Some(443),
        _ => None,
    }
}

fn normalize_host_for_compare(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// Boundary-safe path-prefix match. `validate_field_guard` already requires
/// every configured `path_prefixes` entry to be `"/"` or to both start and
/// end with `/`, so a plain `starts_with` is boundary-safe here (no
/// `"/v1"`-matches-`"/v10"` risk).
fn url_path_has_prefix(path: &str, prefix: &str) -> bool {
    path.starts_with(prefix)
}

/// Evaluate one field guard against the value resolved for its selector
/// (`None` when the selector did not resolve at all). Returns
/// `(allowed, reason_category)`; `reason_category` is always one of the
/// closed-set strings documented in data-model.md and never contains the
/// evaluated value.
fn evaluate_field_guard(guard: &FieldGuard, value: Option<&Value>) -> (bool, &'static str) {
    match guard {
        FieldGuard::Exact { value: expected } => match value {
            None => (false, "field_missing"),
            Some(actual) if expected.matches(actual) => (true, "guard_allowed"),
            Some(_) => (false, "exact_value_mismatch"),
        },
        FieldGuard::Enum { values } => match value {
            None => (false, "field_missing"),
            Some(actual) if values.iter().any(|scalar| scalar.matches(actual)) => {
                (true, "guard_allowed")
            }
            Some(_) => (false, "enum_value_not_allowed"),
        },
        FieldGuard::StringGuard {
            min_length,
            max_length,
            prefix,
        } => match value {
            None => (false, "field_missing"),
            Some(Value::String(s)) => {
                let len = s.chars().count();
                if min_length.is_some_and(|min| len < min) {
                    return (false, "string_too_short");
                }
                if max_length.is_some_and(|max| len > max) {
                    return (false, "string_too_long");
                }
                if let Some(prefix) = prefix {
                    if !s.starts_with(prefix.as_str()) {
                        return (false, "string_prefix_mismatch");
                    }
                }
                (true, "guard_allowed")
            }
            Some(_) => (false, "field_wrong_type"),
        },
        FieldGuard::NumberGuard { min, max } => match value {
            None => (false, "field_missing"),
            Some(Value::Number(n)) => {
                let Some(n) = n.as_f64() else {
                    return (false, "field_wrong_type");
                };
                if min.is_some_and(|min| n < min) {
                    return (false, "number_below_minimum");
                }
                if max.is_some_and(|max| n > max) {
                    return (false, "number_above_maximum");
                }
                (true, "guard_allowed")
            }
            Some(_) => (false, "field_wrong_type"),
        },
        FieldGuard::ArrayGuard {
            min_items,
            max_items,
            allowed_elements,
        } => match value {
            None => (false, "field_missing"),
            Some(Value::Array(items)) => {
                if min_items.is_some_and(|min| items.len() < min) {
                    return (false, "array_too_short");
                }
                if max_items.is_some_and(|max| items.len() > max) {
                    return (false, "array_too_long");
                }
                if let Some(allowed) = allowed_elements {
                    let all_allowed = items
                        .iter()
                        .all(|item| allowed.iter().any(|scalar| scalar.matches(item)));
                    if !all_allowed {
                        return (false, "array_element_not_allowed");
                    }
                }
                (true, "guard_allowed")
            }
            Some(_) => (false, "field_wrong_type"),
        },
        FieldGuard::UrlGuard {
            schemes,
            hosts,
            ports,
            path_prefixes,
        } => match value {
            None => (false, "field_missing"),
            Some(Value::String(raw)) => {
                let Some(parsed) = parse_guarded_url(raw) else {
                    return (false, "url_malformed");
                };
                if !schemes.is_empty()
                    && !schemes
                        .iter()
                        .any(|s| s.eq_ignore_ascii_case(&parsed.scheme))
                {
                    return (false, "url_scheme_not_allowed");
                }
                if !hosts.is_empty()
                    && !hosts
                        .iter()
                        .any(|host| normalize_host_for_compare(host) == parsed.host)
                {
                    return (false, "url_host_not_allowed");
                }
                if !ports.is_empty() {
                    match parsed.port {
                        Some(port) if ports.contains(&port) => {}
                        _ => return (false, "url_port_not_allowed"),
                    }
                }
                if !path_prefixes.is_empty()
                    && !path_prefixes
                        .iter()
                        .any(|prefix| url_path_has_prefix(&parsed.path, prefix))
                {
                    return (false, "url_path_prefix_not_allowed");
                }
                (true, "guard_allowed")
            }
            Some(_) => (false, "field_wrong_type"),
        },
    }
}

fn field_guard_deny_reason(category: &str) -> &'static str {
    match category {
        "field_missing" => "guarded field is missing from the request",
        "field_wrong_type" => "guarded field has an unexpected JSON type",
        "exact_value_mismatch" => "guarded field does not equal the configured exact value",
        "enum_value_not_allowed" => "guarded field value is not in the configured allowlist",
        "string_too_short" => "guarded string field is shorter than the configured minimum length",
        "string_too_long" => "guarded string field is longer than the configured maximum length",
        "string_prefix_mismatch" => {
            "guarded string field does not start with the configured prefix"
        }
        "number_below_minimum" => "guarded numeric field is below the configured minimum",
        "number_above_maximum" => "guarded numeric field is above the configured maximum",
        "array_too_short" => "guarded array field has fewer items than the configured minimum",
        "array_too_long" => "guarded array field has more items than the configured maximum",
        "array_element_not_allowed" => {
            "guarded array field contains an element outside the configured allowlist"
        }
        "url_malformed" => "guarded URL field could not be parsed",
        "url_scheme_not_allowed" => "guarded URL field's scheme is not in the configured allowlist",
        "url_host_not_allowed" => "guarded URL field's host is not in the configured allowlist",
        "url_port_not_allowed" => {
            "guarded URL field's effective port is not in the configured allowlist"
        }
        "url_path_prefix_not_allowed" => {
            "guarded URL field's path is outside the configured allowed prefixes"
        }
        _ => "guarded field failed policy evaluation",
    }
}

fn guard_decision(
    decision: Decision,
    reason: &str,
    guard_key: &str,
    selector: &str,
    category: &str,
) -> GuardPolicyDecision {
    GuardPolicyDecision {
        decision,
        reason: reason.to_string(),
        guard_key: guard_key.to_string(),
        selector: selector.to_string(),
        reason_category: category.to_string(),
    }
}

/// Evaluate the v0.2 `require_keys`/`forbid_keys`/`fields` guards for one
/// `ArgumentGuard`. Returns `None` when no v0.2 construct is configured at
/// all (no override — the v0.1-only decision, if any, stands unchanged).
/// Checks `require_keys`, then `forbid_keys`, then `fields` in `BTreeMap`
/// (deterministic) order; the first failure wins.
fn decide_argument_guard(
    guard_key: &str,
    guard: &ArgumentGuard,
    container: Option<&Value>,
) -> Option<GuardPolicyDecision> {
    if guard.require_keys.is_empty() && guard.forbid_keys.is_empty() && guard.fields.is_empty() {
        return None;
    }
    let object = container.and_then(Value::as_object);
    for required in &guard.require_keys {
        if !object.is_some_and(|o| o.contains_key(required)) {
            return Some(guard_decision(
                Decision::Deny,
                "required key is missing from the guarded object",
                guard_key,
                required,
                "required_key_missing",
            ));
        }
    }
    for forbidden in &guard.forbid_keys {
        if object.is_some_and(|o| o.contains_key(forbidden)) {
            return Some(guard_decision(
                Decision::Deny,
                "forbidden key is present in the guarded object",
                guard_key,
                forbidden,
                "forbidden_key_present",
            ));
        }
    }
    for (selector, field_guard) in &guard.fields {
        let resolved = container.and_then(|c| resolve_selector(c, selector));
        let (allowed, category) = evaluate_field_guard(field_guard, resolved);
        if !allowed {
            return Some(guard_decision(
                Decision::Deny,
                field_guard_deny_reason(category),
                guard_key,
                selector,
                category,
            ));
        }
    }
    Some(guard_decision(
        Decision::Allow,
        "all configured argument/param guards were satisfied",
        guard_key,
        "<none>",
        "guard_allowed",
    ))
}

/// v0.2 counterpart to [`decide_tool_argument_paths`]: evaluates
/// `require_keys`/`forbid_keys`/`fields` configured on a tool's `arguments`
/// guard. Only the global `[tools."<tool>".arguments]` scope is checked,
/// mirroring the v0.1 path guard's scope exactly (no server-specific
/// argument-guard scope exists today).
pub fn decide_tool_argument_guards(
    policy: &McpPolicyFile,
    tool_name: &str,
    arguments: Option<&Value>,
) -> Option<GuardPolicyDecision> {
    let guard = policy
        .tools
        .path_guards
        .get(tool_name)?
        .arguments
        .as_ref()?;
    decide_argument_guard(tool_name, guard, arguments)
}

/// v0.2 counterpart to [`decide_method_param_paths`], but — unlike the v0.1
/// path guard, which the live proxy only ever consults for `resources/read`
/// — applicable to any method with a configured `params` guard. This is
/// purely additive new v0.2 capability; it does not change which methods
/// the v0.1 path guard covers.
pub fn decide_method_param_guards(
    policy: &McpPolicyFile,
    method: &str,
    params: Option<&Value>,
) -> Option<GuardPolicyDecision> {
    let guard = policy
        .methods
        .as_ref()?
        .path_guards
        .get(method)?
        .params
        .as_ref()?;
    decide_argument_guard(method, guard, params)
}

/// Deterministic decision for a tool name: deny-list match wins, then
/// allow-list membership is required, and everything else is denied.
pub fn decide_tool_call(
    policy: &McpPolicyFile,
    server_name: &str,
    tool_name: &str,
) -> PolicyDecision {
    if let Some(risk) = inspect_tool_name(tool_name) {
        return PolicyDecision {
            decision: Decision::Deny,
            reason: risk.reason().to_string(),
        };
    }
    if policy.tools.deny.iter().any(|entry| entry == tool_name) {
        return PolicyDecision {
            decision: Decision::Deny,
            reason: "tool name is in the global policy deny list".to_string(),
        };
    }
    let server_tools = policy.servers.get(server_name).map(|server| &server.tools);
    if server_tools.is_some_and(|tools| tools.deny.iter().any(|entry| entry == tool_name)) {
        return PolicyDecision {
            decision: Decision::Deny,
            reason: format!(
                "tool name is in the server-specific policy deny list for {server_name}"
            ),
        };
    }
    if server_tools.is_some_and(|tools| tools.allow.iter().any(|entry| entry == tool_name)) {
        return PolicyDecision {
            decision: Decision::Allow,
            reason: format!(
                "tool name is in the server-specific policy allow list for {server_name}"
            ),
        };
    }
    if policy.tools.allow.iter().any(|entry| entry == tool_name) {
        return PolicyDecision {
            decision: Decision::Allow,
            reason: "tool name is in the global policy allow list".to_string(),
        };
    }
    PolicyDecision {
        decision: Decision::Deny,
        reason: format!(
            "default deny: tool name is not in the server-specific or global policy allow list for {server_name}"
        ),
    }
}

/// Whether a client→server method is always allowed (protocol-required) and
/// should never be subject to method policy checks.
pub fn is_always_allowed_method(method: &str) -> bool {
    ALWAYS_ALLOWED_METHODS.contains(&method)
}

fn is_always_allowed_for_direction(direction: MethodDirection, method: &str) -> bool {
    match direction {
        MethodDirection::ClientToServer => is_always_allowed_method(method),
        // MCP ping can be initiated by either peer as a liveness probe. Other
        // server→client methods, including roots/list, sampling/createMessage,
        // and elicitation/create, must be explicitly allowed by policy.
        MethodDirection::ServerToClient => method == "ping",
    }
}

/// Determine whether a JSON-RPC method is allowed by the method policy.
///
/// Decision order:
/// 1. Always-allowed methods (initialize, notifications/initialized, ping)
///    → allow unconditionally.
/// 2. Method in global `[methods].deny` → deny.
/// 3. Method in server-specific `[servers.<name>.methods].deny` → deny.
/// 4. Method in server-specific `[servers.<name>.methods].allow` → allow.
/// 5. Method in global `[methods].allow` → allow.
/// 6. If global `[methods].allow` contains `"*"` → allow.
/// 7. If no `[methods]` section exists at all (global and server), use the
///    built-in default: allow `tools/list` and `tools/call`, deny everything
///    else.
/// 8. If a `[methods]` section exists but the method is not listed → deny
///    (default deny for unknown methods).
pub fn decide_method(policy: &McpPolicyFile, server_name: &str, method: &str) -> PolicyDecision {
    decide_method_for_direction(policy, server_name, MethodDirection::ClientToServer, method)
}

pub fn decide_method_for_direction(
    policy: &McpPolicyFile,
    server_name: &str,
    direction: MethodDirection,
    method: &str,
) -> PolicyDecision {
    if let Some(risk) = inspect_method_name(method) {
        return PolicyDecision {
            decision: Decision::Deny,
            reason: risk.reason().to_string(),
        };
    }
    if is_always_allowed_for_direction(direction, method) {
        return PolicyDecision {
            decision: Decision::Allow,
            reason: format!(
                "method is always allowed for {} (protocol-required)",
                direction.as_str()
            ),
        };
    }

    let global_methods = policy.methods.as_ref();
    let server_methods = policy
        .servers
        .get(server_name)
        .and_then(|server| server.methods.as_ref());

    // 2. Global deny wins.
    if global_methods.is_some_and(|m| m.deny.iter().any(|entry| entry == method)) {
        return PolicyDecision {
            decision: Decision::Deny,
            reason: "method is in the global policy deny list".to_string(),
        };
    }

    // 3. Server-specific deny.
    if server_methods.is_some_and(|m| m.deny.iter().any(|entry| entry == method)) {
        return PolicyDecision {
            decision: Decision::Deny,
            reason: format!("method is in the server-specific policy deny list for {server_name}"),
        };
    }

    // 4. Server-specific allow.
    if server_methods.is_some_and(|m| m.allow.iter().any(|entry| entry == method)) {
        return PolicyDecision {
            decision: Decision::Allow,
            reason: format!("method is in the server-specific policy allow list for {server_name}"),
        };
    }

    // 5. Global allow.
    if global_methods.is_some_and(|m| m.allow.iter().any(|entry| entry == method)) {
        return PolicyDecision {
            decision: Decision::Allow,
            reason: "method is in the global policy allow list".to_string(),
        };
    }

    // 6. Wildcard allow.
    if global_methods.is_some_and(|m| m.allow.iter().any(|entry| entry == "*")) {
        return PolicyDecision {
            decision: Decision::Allow,
            reason: "method allowed by global wildcard".to_string(),
        };
    }

    // 7. Built-in default when no method policy is configured at all.
    if global_methods.is_none() && server_methods.is_none() {
        if DEFAULT_ALLOWED_METHODS.contains(&method) {
            return PolicyDecision {
                decision: Decision::Allow,
                reason: "method allowed by built-in default (no [methods] policy configured)"
                    .to_string(),
            };
        }
        return PolicyDecision {
            decision: Decision::Deny,
            reason: "default deny: method is not in the built-in default allow list and no [methods] policy is configured".to_string(),
        };
    }

    // 8. A [methods] section exists but the method is not listed → deny.
    PolicyDecision {
        decision: Decision::Deny,
        reason: format!(
            "default deny: method is not in the server-specific or global method allow list for {server_name}"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const VALID_POLICY: &str = r#"
schema_version = "ef-mcp-policy/v0.1"
name = "minimal-mcp-boundary"

[tools]
allow = ["github.list_repos", "filesystem.read"]
deny = ["filesystem.read_secret", "shell.run"]
"#;

    const PATH_POLICY: &str = r#"
schema_version = "ef-mcp-policy/v0.1"
name = "path-aware"

[tools]
allow = ["filesystem.read"]

[methods]
allow = ["tools/list", "tools/call", "resources/read"]

[path_rules.project_readonly]
allow_roots = ["/home/user/project"]
deny_roots = ["/home/user/project/.git", "/home/user/project/secrets"]

[tools."filesystem.read".arguments]
path_keys = ["path"]
path_rule = "project_readonly"

[methods."resources/read".params]
uri_keys = ["uri"]
path_rule = "project_readonly"
"#;

    #[test]
    fn parses_valid_policy() {
        let policy = parse_mcp_policy(VALID_POLICY).expect("valid policy");
        assert_eq!(policy.schema_version, SUPPORTED_MCP_POLICY_SCHEMA_VERSION);
        assert_eq!(policy.name, "minimal-mcp-boundary");
        assert_eq!(policy.tools.allow.len(), 2);
        assert_eq!(policy.tools.deny.len(), 2);
        assert!(policy.servers.is_empty());
        assert!(policy.methods.is_none());
    }

    #[test]
    fn parses_per_server_policy() {
        let content = r#"
schema_version = "ef-mcp-policy/v0.1"
name = "scoped"

[tools]
allow = ["global.allowed"]
deny = ["global.denied"]

[servers.filesystem.tools]
allow = ["filesystem.read"]
deny = ["filesystem.write"]
"#;
        let policy = parse_mcp_policy(content).expect("valid scoped policy");
        let filesystem = policy.servers.get("filesystem").expect("server scope");
        assert_eq!(filesystem.tools.allow, vec!["filesystem.read"]);
        assert_eq!(filesystem.tools.deny, vec!["filesystem.write"]);
    }

    #[test]
    fn parses_method_policy() {
        let content = r#"
schema_version = "ef-mcp-policy/v0.1"
name = "method-scoped"

[methods]
allow = ["tools/list", "tools/call", "resources/list", "resources/read"]
deny = ["sampling/createMessage"]

[tools]
allow = ["filesystem.read"]
"#;
        let policy = parse_mcp_policy(content).expect("valid method policy");
        let methods = policy.methods.expect("methods section");
        assert_eq!(
            methods.allow,
            vec![
                "tools/list",
                "tools/call",
                "resources/list",
                "resources/read"
            ]
        );
        assert_eq!(methods.deny, vec!["sampling/createMessage"]);
    }

    #[test]
    fn parses_per_server_method_policy() {
        let content = r#"
schema_version = "ef-mcp-policy/v0.1"
name = "server-method-scoped"

[methods]
allow = ["tools/list", "tools/call"]

[servers.filesystem.methods]
allow = ["resources/list", "resources/read"]
deny = ["prompts/get"]

[servers.filesystem.tools]
allow = ["filesystem.read"]
"#;
        let policy = parse_mcp_policy(content).expect("valid server method policy");
        let filesystem = policy.servers.get("filesystem").expect("server scope");
        let methods = filesystem.methods.as_ref().expect("server methods");
        assert_eq!(methods.allow, vec!["resources/list", "resources/read"]);
        assert_eq!(methods.deny, vec!["prompts/get"]);
    }

    #[test]
    fn parses_path_rules_and_guards() {
        let policy = parse_mcp_policy(PATH_POLICY).expect("valid path-aware policy");
        assert!(policy.path_rules.contains_key("project_readonly"));
        assert!(policy.tools.path_guards.contains_key("filesystem.read"));
        assert!(policy
            .methods
            .as_ref()
            .expect("methods")
            .path_guards
            .contains_key("resources/read"));
    }

    #[test]
    fn path_guard_allows_path_under_allowed_root() {
        let policy = parse_mcp_policy(PATH_POLICY).expect("policy");
        let decision = decide_tool_argument_paths(
            &policy,
            "filesystem.read",
            Some(&json!({"path": "/home/user/project/docs/readme.md"})),
        )
        .expect("path guard");
        assert_eq!(decision.decision, Decision::Allow);
        assert_eq!(decision.classification, "inside_allowed_root");
    }

    #[test]
    fn path_guard_denies_path_outside_allowed_root() {
        let policy = parse_mcp_policy(PATH_POLICY).expect("policy");
        let decision = decide_tool_argument_paths(
            &policy,
            "filesystem.read",
            Some(&json!({"path": "/home/user/other/file.txt"})),
        )
        .expect("path guard");
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(decision.classification, "outside_allowed_roots");
    }

    #[test]
    fn path_guard_denies_denied_root_before_allow() {
        let policy = parse_mcp_policy(PATH_POLICY).expect("policy");
        let decision = decide_tool_argument_paths(
            &policy,
            "filesystem.read",
            Some(&json!({"path": "/home/user/project/secrets/token.txt"})),
        )
        .expect("path guard");
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(decision.classification, "inside_denied_root");
    }

    #[test]
    fn path_guard_denies_traversal_outside_allowed_root() {
        let policy = parse_mcp_policy(PATH_POLICY).expect("policy");
        let decision = decide_tool_argument_paths(
            &policy,
            "filesystem.read",
            Some(&json!({"path": "/home/user/project/../secrets/token.txt"})),
        )
        .expect("path guard");
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(decision.classification, "outside_allowed_roots");
    }

    #[test]
    fn path_guard_denies_malformed_path_when_configured() {
        let policy = parse_mcp_policy(PATH_POLICY).expect("policy");
        let decision = decide_tool_argument_paths(
            &policy,
            "filesystem.read",
            Some(&json!({"path": "../secrets/token.txt"})),
        )
        .expect("path guard");
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(decision.classification, "path_parse_error");
    }

    #[test]
    fn uri_guard_handles_file_uri_and_denies_non_file_uri() {
        let policy = parse_mcp_policy(PATH_POLICY).expect("policy");
        let allowed = decide_method_param_paths(
            &policy,
            "resources/read",
            Some(&json!({"uri": "file:///home/user/project/docs/readme.md"})),
        )
        .expect("uri guard");
        assert_eq!(allowed.decision, Decision::Allow);

        let denied = decide_method_param_paths(
            &policy,
            "resources/read",
            Some(&json!({"uri": "https://example.invalid/resource"})),
        )
        .expect("uri guard");
        assert_eq!(denied.decision, Decision::Deny);
        assert_eq!(denied.classification, "path_parse_error");
    }

    #[test]
    fn path_guard_supports_windows_style_paths_lexically() {
        let content = r#"
schema_version = "ef-mcp-policy/v0.1"
name = "windows-paths"

[tools]
allow = ["filesystem.read"]

[path_rules.win_project]
allow_roots = ["C:\\Users\\user\\project"]
deny_roots = ["C:\\Users\\user\\project\\secrets"]

[tools."filesystem.read".arguments]
path_keys = ["path"]
path_rule = "win_project"
"#;
        let policy = parse_mcp_policy(content).expect("policy");
        let allowed = decide_tool_argument_paths(
            &policy,
            "filesystem.read",
            Some(&json!({"path": "C:\\Users\\user\\project\\docs\\readme.md"})),
        )
        .expect("path guard");
        assert_eq!(allowed.decision, Decision::Allow);
        let denied = decide_tool_argument_paths(
            &policy,
            "filesystem.read",
            Some(&json!({"path": "C:\\Users\\user\\project\\secrets\\token.txt"})),
        )
        .expect("path guard");
        assert_eq!(denied.classification, "inside_denied_root");
    }

    #[test]
    fn windows_deny_root_blocks_case_variant_candidate() {
        let content = r#"
schema_version = "ef-mcp-policy/v0.1"
name = "windows-case-deny"

[tools]
allow = ["filesystem.read"]

[path_rules.win_project]
allow_roots = ["C:/Users/Alice/project"]
deny_roots = ["C:/Users/Alice/project/secrets"]

[tools."filesystem.read".arguments]
path_keys = ["path"]
path_rule = "win_project"
"#;
        let policy = parse_mcp_policy(content).expect("policy");
        let decision = decide_tool_argument_paths(
            &policy,
            "filesystem.read",
            Some(&json!({"path": "C:/Users/Alice/project/Secrets/token.txt"})),
        )
        .expect("path guard");
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(decision.classification, "inside_denied_root");
    }

    #[test]
    fn windows_allow_root_allows_case_variant_candidate() {
        let content = r#"
schema_version = "ef-mcp-policy/v0.1"
name = "windows-case-allow"

[tools]
allow = ["filesystem.read"]

[path_rules.win_project]
allow_roots = ["C:/Users/Alice/project"]

[tools."filesystem.read".arguments]
path_keys = ["path"]
path_rule = "win_project"
"#;
        let policy = parse_mcp_policy(content).expect("policy");
        let decision = decide_tool_argument_paths(
            &policy,
            "filesystem.read",
            Some(&json!({"path": "c:/users/alice/PROJECT/docs/readme.md"})),
        )
        .expect("path guard");
        assert_eq!(decision.decision, Decision::Allow);
        assert_eq!(decision.classification, "inside_allowed_root");
    }

    #[test]
    fn windows_deny_root_wins_after_case_folding() {
        let content = r#"
schema_version = "ef-mcp-policy/v0.1"
name = "windows-case-deny-wins"

[tools]
allow = ["filesystem.read"]

[path_rules.win_project]
allow_roots = ["C:/Users/Alice/project"]
deny_roots = ["c:/users/alice/PROJECT/SECRETS"]

[tools."filesystem.read".arguments]
path_keys = ["path"]
path_rule = "win_project"
"#;
        let policy = parse_mcp_policy(content).expect("policy");
        let decision = decide_tool_argument_paths(
            &policy,
            "filesystem.read",
            Some(&json!({"path": "C:/Users/Alice/project/secrets/token.txt"})),
        )
        .expect("path guard");
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(decision.classification, "inside_denied_root");
    }

    #[test]
    fn rejects_unsupported_schema_version() {
        let content = VALID_POLICY.replace("ef-mcp-policy/v0.1", "ef-mcp-policy/v9.9");
        let error = parse_mcp_policy(&content).expect_err("unsupported schema");
        assert!(error.to_string().contains("unsupported"));
    }

    #[test]
    fn rejects_missing_schema_version() {
        let error = parse_mcp_policy("name = \"x\"").expect_err("missing schema_version");
        assert!(error.to_string().contains("schema_version"));
    }

    #[test]
    fn rejects_invalid_toml() {
        assert!(parse_mcp_policy("not valid toml [").is_err());
    }

    #[test]
    fn rejects_empty_name() {
        let content = VALID_POLICY.replace("minimal-mcp-boundary", " ");
        assert!(parse_mcp_policy(&content).is_err());
    }

    #[test]
    fn rejects_non_ascii_method_allow_entry() {
        let content = r#"
schema_version = "ef-mcp-policy/v0.1"
name = "unicode-method"

[methods]
allow = ["tοols/call"]
"#;
        let error = parse_mcp_policy(content).expect_err("non-ASCII method rejected");
        assert!(error.to_string().contains("unicode_non_ascii_method"));
    }

    #[test]
    fn rejects_bidi_control_in_method_tool_and_path_rule_names() {
        let method_error = parse_mcp_policy(
            r#"
schema_version = "ef-mcp-policy/v0.1"
name = "unicode-method-bidi"

[methods]
allow = ["tools/\u202ecall"]
"#,
        )
        .expect_err("bidi method rejected");
        assert!(method_error
            .to_string()
            .contains("unicode_bidi_control_detected"));

        let tool_error = parse_mcp_policy(
            r#"
schema_version = "ef-mcp-policy/v0.1"
name = "unicode-tool-bidi"

[tools]
allow = ["filesystem.\u202eread"]
"#,
        )
        .expect_err("bidi tool rejected");
        assert!(tool_error
            .to_string()
            .contains("unicode_bidi_control_detected"));

        let path_rule_error = parse_mcp_policy(
            r#"
schema_version = "ef-mcp-policy/v0.1"
name = "unicode-rule-bidi"

[path_rules."project\u202ereadonly"]
allow_roots = ["/home/user/project"]
"#,
        )
        .expect_err("bidi path rule rejected");
        assert!(path_rule_error
            .to_string()
            .contains("unicode_bidi_control_detected"));
    }

    #[test]
    fn rejects_zero_width_in_method_tool_and_path_rule_names() {
        let zero_width = "\u{200B}";
        let method_error = parse_mcp_policy(&format!(
            r#"
schema_version = "ef-mcp-policy/v0.1"
name = "unicode-method-zero-width"

[methods]
allow = ["tools/{zero_width}call"]
"#,
        ))
        .expect_err("zero-width method rejected");
        assert!(method_error
            .to_string()
            .contains("unicode_zero_width_detected"));

        let tool_error = parse_mcp_policy(&format!(
            r#"
schema_version = "ef-mcp-policy/v0.1"
name = "unicode-tool-zero-width"

[tools]
allow = ["filesystem.{zero_width}read"]
"#,
        ))
        .expect_err("zero-width tool rejected");
        assert!(tool_error
            .to_string()
            .contains("unicode_zero_width_detected"));

        let path_rule_error = parse_mcp_policy(&format!(
            r#"
schema_version = "ef-mcp-policy/v0.1"
name = "unicode-rule-zero-width"

[path_rules."project{zero_width}readonly"]
allow_roots = ["/home/user/project"]
"#,
        ))
        .expect_err("zero-width path rule rejected");
        assert!(path_rule_error
            .to_string()
            .contains("unicode_zero_width_detected"));
    }

    #[test]
    fn rejects_zero_width_path_guard_key_and_non_ascii_policy_identifier() {
        let zero_width = "\u{200B}";
        let key_error = parse_mcp_policy(&format!(
            r#"
schema_version = "ef-mcp-policy/v0.1"
name = "unicode-key"

[tools]
allow = ["filesystem.read"]

[path_rules.project_readonly]
allow_roots = ["/home/user/project"]

[tools."filesystem.read".arguments]
path_keys = ["pa{zero_width}th"]
path_rule = "project_readonly"
"#,
        ))
        .expect_err("zero-width path key rejected");
        assert!(key_error
            .to_string()
            .contains("unicode_zero_width_detected"));

        let name_error = parse_mcp_policy(
            r#"
schema_version = "ef-mcp-policy/v0.1"
name = "policу"
"#,
        )
        .expect_err("non-ASCII policy identifier rejected");
        assert!(name_error
            .to_string()
            .contains("unicode_non_ascii_identifier"));
    }

    #[test]
    fn load_fails_for_missing_file() {
        let error =
            load_mcp_policy(Path::new("/nonexistent/mcp-policy.toml")).expect_err("missing file");
        assert!(error.to_string().contains("reading MCP proxy policy"));
    }

    #[test]
    fn allow_listed_tool_is_allowed() {
        let policy = parse_mcp_policy(VALID_POLICY).unwrap();
        let decision = decide_tool_call(&policy, "default", "filesystem.read");
        assert_eq!(decision.decision, Decision::Allow);
        assert!(decision.reason.contains("allow list"));
    }

    #[test]
    fn deny_listed_tool_is_denied() {
        let policy = parse_mcp_policy(VALID_POLICY).unwrap();
        let decision = decide_tool_call(&policy, "default", "shell.run");
        assert_eq!(decision.decision, Decision::Deny);
        assert!(decision.reason.contains("deny list"));
    }

    #[test]
    fn unlisted_tool_is_denied_by_default() {
        let policy = parse_mcp_policy(VALID_POLICY).unwrap();
        let decision = decide_tool_call(&policy, "default", "browser.open");
        assert_eq!(decision.decision, Decision::Deny);
        assert!(decision.reason.contains("default deny"));
    }

    #[test]
    fn deny_list_wins_over_allow_list() {
        let content = r#"
schema_version = "ef-mcp-policy/v0.1"
name = "overlap"

[tools]
allow = ["shell.run"]
deny = ["shell.run"]
"#;
        let policy = parse_mcp_policy(content).unwrap();
        let decision = decide_tool_call(&policy, "default", "shell.run");
        assert_eq!(decision.decision, Decision::Deny);
    }

    #[test]
    fn server_deny_wins_over_server_allow_and_global_allow() {
        let content = r#"
schema_version = "ef-mcp-policy/v0.1"
name = "overlap"

[tools]
allow = ["filesystem.read"]

[servers.filesystem.tools]
allow = ["filesystem.read"]
deny = ["filesystem.read"]
"#;
        let policy = parse_mcp_policy(content).unwrap();
        let decision = decide_tool_call(&policy, "filesystem", "filesystem.read");
        assert_eq!(decision.decision, Decision::Deny);
        assert!(decision.reason.contains("server-specific"));
    }

    #[test]
    fn global_deny_wins_over_server_allow() {
        let content = r#"
schema_version = "ef-mcp-policy/v0.1"
name = "overlap"

[tools]
deny = ["filesystem.read"]

[servers.filesystem.tools]
allow = ["filesystem.read"]
"#;
        let policy = parse_mcp_policy(content).unwrap();
        let decision = decide_tool_call(&policy, "filesystem", "filesystem.read");
        assert_eq!(decision.decision, Decision::Deny);
        assert!(decision.reason.contains("global"));
    }

    #[test]
    fn server_scope_changes_decision_for_same_tool_name() {
        let content = r#"
schema_version = "ef-mcp-policy/v0.1"
name = "scoped"

[servers.filesystem.tools]
allow = ["read"]

[servers.github.tools]
deny = ["read"]
"#;
        let policy = parse_mcp_policy(content).unwrap();
        assert_eq!(
            decide_tool_call(&policy, "filesystem", "read").decision,
            Decision::Allow
        );
        assert_eq!(
            decide_tool_call(&policy, "github", "read").decision,
            Decision::Deny
        );
        assert_eq!(
            decide_tool_call(&policy, "default", "read").decision,
            Decision::Deny
        );
    }

    #[test]
    fn matching_is_exact_not_prefix() {
        let policy = parse_mcp_policy(VALID_POLICY).unwrap();
        assert_eq!(
            decide_tool_call(&policy, "default", "filesystem.read_secret").decision,
            Decision::Deny
        );
        assert_eq!(
            decide_tool_call(&policy, "default", "filesystem.rea").decision,
            Decision::Deny
        );
        assert_eq!(
            decide_tool_call(&policy, "default", "filesystem.read2").decision,
            Decision::Deny
        );
    }

    // --- Method policy tests ---

    #[test]
    fn default_method_policy_allows_tools_list_and_call() {
        let policy = parse_mcp_policy(VALID_POLICY).unwrap();
        assert_eq!(
            decide_method(&policy, "default", "tools/list").decision,
            Decision::Allow
        );
        assert_eq!(
            decide_method(&policy, "default", "tools/call").decision,
            Decision::Allow
        );
    }

    #[test]
    fn default_method_policy_denies_resources_read() {
        let policy = parse_mcp_policy(VALID_POLICY).unwrap();
        let d = decide_method(&policy, "default", "resources/read");
        assert_eq!(d.decision, Decision::Deny);
        assert!(d.reason.contains("built-in default"));
    }

    #[test]
    fn default_method_policy_denies_unknown_method() {
        let policy = parse_mcp_policy(VALID_POLICY).unwrap();
        let d = decide_method(&policy, "default", "some/custom/method");
        assert_eq!(d.decision, Decision::Deny);
        assert!(d.reason.contains("built-in default"));
    }

    #[test]
    fn always_allowed_methods_bypass_policy() {
        let content = r#"
schema_version = "ef-mcp-policy/v0.1"
name = "strict-methods"

[methods]
allow = []
deny = ["initialize", "notifications/initialized", "ping"]
"#;
        let policy = parse_mcp_policy(content).unwrap();
        for method in ALWAYS_ALLOWED_METHODS {
            assert_eq!(
                decide_method(&policy, "default", method).decision,
                Decision::Allow,
                "always-allowed method {method} should bypass deny"
            );
        }
    }

    #[test]
    fn explicit_method_allow_list_lets_resources_read_through() {
        let content = r#"
schema_version = "ef-mcp-policy/v0.1"
name = "resources-allowed"

[methods]
allow = ["tools/list", "tools/call", "resources/list", "resources/read"]

[tools]
allow = ["filesystem.read"]
"#;
        let policy = parse_mcp_policy(content).unwrap();
        assert_eq!(
            decide_method(&policy, "default", "resources/read").decision,
            Decision::Allow
        );
        assert_eq!(
            decide_method(&policy, "default", "resources/list").decision,
            Decision::Allow
        );
    }

    #[test]
    fn method_deny_wins_over_allow() {
        let content = r#"
schema_version = "ef-mcp-policy/v0.1"
name = "deny-wins"

[methods]
allow = ["resources/read"]
deny = ["resources/read"]
"#;
        let policy = parse_mcp_policy(content).unwrap();
        assert_eq!(
            decide_method(&policy, "default", "resources/read").decision,
            Decision::Deny
        );
    }

    #[test]
    fn server_method_deny_wins_over_global_allow() {
        let content = r#"
schema_version = "ef-mcp-policy/v0.1"
name = "server-deny-wins"

[methods]
allow = ["resources/read"]

[servers.fs.methods]
deny = ["resources/read"]
"#;
        let policy = parse_mcp_policy(content).unwrap();
        let d = decide_method(&policy, "fs", "resources/read");
        assert_eq!(d.decision, Decision::Deny);
        assert!(d.reason.contains("server-specific"));
    }

    #[test]
    fn server_method_allow_lets_through_when_global_is_silent() {
        let content = r#"
schema_version = "ef-mcp-policy/v0.1"
name = "server-allow"

[methods]
allow = ["tools/list", "tools/call"]

[servers.fs.methods]
allow = ["resources/list", "resources/read"]
"#;
        let policy = parse_mcp_policy(content).unwrap();
        assert_eq!(
            decide_method(&policy, "fs", "resources/read").decision,
            Decision::Allow
        );
        // Global doesn't allow resources/read, and server scope is "fs" not "default".
        assert_eq!(
            decide_method(&policy, "default", "resources/read").decision,
            Decision::Deny
        );
    }

    #[test]
    fn wildcard_allow_lets_unknown_methods_through() {
        let content = r#"
schema_version = "ef-mcp-policy/v0.1"
name = "wildcard"

[methods]
allow = ["*"]
deny = ["sampling/createMessage"]
"#;
        let policy = parse_mcp_policy(content).unwrap();
        assert_eq!(
            decide_method(&policy, "default", "some/custom/method").decision,
            Decision::Allow
        );
        assert_eq!(
            decide_method(&policy, "default", "sampling/createMessage").decision,
            Decision::Deny
        );
    }

    #[test]
    fn explicit_methods_section_denies_unlisted_methods() {
        let content = r#"
schema_version = "ef-mcp-policy/v0.1"
name = "explicit"

[methods]
allow = ["tools/list", "tools/call"]
"#;
        let policy = parse_mcp_policy(content).unwrap();
        let d = decide_method(&policy, "default", "resources/read");
        assert_eq!(d.decision, Decision::Deny);
        assert!(d.reason.contains("not in the server-specific or global"));
    }

    #[test]
    fn prompts_get_denied_by_default() {
        let policy = parse_mcp_policy(VALID_POLICY).unwrap();
        assert_eq!(
            decide_method(&policy, "default", "prompts/get").decision,
            Decision::Deny
        );
    }

    #[test]
    fn sampling_create_message_denied_by_default() {
        let policy = parse_mcp_policy(VALID_POLICY).unwrap();
        assert_eq!(
            decide_method(&policy, "default", "sampling/createMessage").decision,
            Decision::Deny
        );
    }

    #[test]
    fn completion_complete_denied_by_default() {
        let policy = parse_mcp_policy(VALID_POLICY).unwrap();
        assert_eq!(
            decide_method(&policy, "default", "completion/complete").decision,
            Decision::Deny
        );
    }

    #[test]
    fn roots_list_denied_by_default() {
        let policy = parse_mcp_policy(VALID_POLICY).unwrap();
        assert_eq!(
            decide_method(&policy, "default", "roots/list").decision,
            Decision::Deny
        );
    }
}

#[cfg(test)]
mod v2_guard_tests {
    use super::*;
    use serde_json::json;

    fn policy_with_tool_guard(guard_toml: &str) -> McpPolicyFile {
        let content = format!(
            r#"
schema_version = "ef-mcp-policy/v0.2"
name = "v2-guard-test"

[tools]
allow = ["demo.tool"]

{guard_toml}
"#
        );
        parse_mcp_policy(&content).expect("valid v0.2 policy")
    }

    fn policy_with_method_guard(guard_toml: &str) -> McpPolicyFile {
        let content = format!(
            r#"
schema_version = "ef-mcp-policy/v0.2"
name = "v2-method-guard-test"

[methods]
allow = ["tools/list", "tools/call", "demo/method"]

{guard_toml}
"#
        );
        parse_mcp_policy(&content).expect("valid v0.2 policy")
    }

    // --- schema gating ---

    #[test]
    fn v1_policy_rejects_require_keys() {
        let content = r#"
schema_version = "ef-mcp-policy/v0.1"
name = "v1-with-v2-construct"

[tools]
allow = ["demo.tool"]

[tools."demo.tool".arguments]
require_keys = ["org"]
"#;
        let error = parse_mcp_policy(content).expect_err("v2 construct under v0.1 rejected");
        assert!(error.to_string().contains("ef-mcp-policy/v0.2"));
    }

    #[test]
    fn v1_policy_rejects_field_guard() {
        let content = r#"
schema_version = "ef-mcp-policy/v0.1"
name = "v1-with-v2-field"

[tools]
allow = ["demo.tool"]

[tools."demo.tool".arguments.fields.org]
type = "exact"
value = "my-org"
"#;
        let error = parse_mcp_policy(content).expect_err("v2 field guard under v0.1 rejected");
        assert!(error.to_string().contains("ef-mcp-policy/v0.2"));
    }

    #[test]
    fn v2_schema_version_is_accepted() {
        let policy = policy_with_tool_guard(
            r#"
[tools."demo.tool".arguments]
require_keys = ["org"]
"#,
        );
        assert_eq!(policy.schema_version, "ef-mcp-policy/v0.2");
    }

    // --- validation ---

    #[test]
    fn rejects_key_both_required_and_forbidden() {
        let content = r#"
schema_version = "ef-mcp-policy/v0.2"
name = "conflict"

[tools]
allow = ["demo.tool"]

[tools."demo.tool".arguments]
require_keys = ["org"]
forbid_keys = ["org"]
"#;
        let error = parse_mcp_policy(content).expect_err("conflicting require/forbid rejected");
        assert!(error
            .to_string()
            .contains("listed in both require_keys and forbid_keys"));
    }

    #[test]
    fn rejects_empty_enum_values() {
        let content = r#"
schema_version = "ef-mcp-policy/v0.2"
name = "empty-enum"

[tools]
allow = ["demo.tool"]

[tools."demo.tool".arguments.fields.org]
type = "enum"
values = []
"#;
        let error = parse_mcp_policy(content).expect_err("empty enum rejected");
        assert!(error.to_string().contains("at least one value"));
    }

    #[test]
    fn rejects_empty_allowed_elements_when_configured() {
        let content = r#"
schema_version = "ef-mcp-policy/v0.2"
name = "empty-allowed-elements"

[tools]
allow = ["demo.tool"]

[tools."demo.tool".arguments.fields.fields]
type = "array"
allowed_elements = []
"#;
        let error = parse_mcp_policy(content).expect_err("empty allowed_elements rejected");
        assert!(error
            .to_string()
            .contains("allowed_elements must not be empty"));
    }

    #[test]
    fn rejects_impossible_numeric_range() {
        let content = r#"
schema_version = "ef-mcp-policy/v0.2"
name = "impossible-range"

[tools]
allow = ["demo.tool"]

[tools."demo.tool".arguments.fields.limit]
type = "number"
min = 100
max = 1
"#;
        let error = parse_mcp_policy(content).expect_err("min > max rejected");
        assert!(error.to_string().contains("min must not exceed max"));
    }

    #[test]
    fn rejects_impossible_string_length_range() {
        let content = r#"
schema_version = "ef-mcp-policy/v0.2"
name = "impossible-string-range"

[tools]
allow = ["demo.tool"]

[tools."demo.tool".arguments.fields.name]
type = "string"
min_length = 10
max_length = 1
"#;
        let error = parse_mcp_policy(content).expect_err("min_length > max_length rejected");
        assert!(error.to_string().contains("min must not exceed max"));
    }

    #[test]
    fn rejects_selector_exceeding_max_depth() {
        let selector = (0..MAX_SELECTOR_SEGMENTS + 1)
            .map(|i| format!("s{i}"))
            .collect::<Vec<_>>()
            .join(".");
        let content = format!(
            r#"
schema_version = "ef-mcp-policy/v0.2"
name = "too-deep"

[tools]
allow = ["demo.tool"]

[tools."demo.tool".arguments.fields."{selector}"]
type = "exact"
value = "x"
"#
        );
        let error = parse_mcp_policy(&content).expect_err("selector too deep rejected");
        assert!(error.to_string().contains("exceeds the maximum"));
    }

    #[test]
    fn rejects_selector_with_empty_segment() {
        let content = r#"
schema_version = "ef-mcp-policy/v0.2"
name = "empty-segment"

[tools]
allow = ["demo.tool"]

[tools."demo.tool".arguments.fields."a..b"]
type = "exact"
value = "x"
"#;
        let error = parse_mcp_policy(content).expect_err("empty selector segment rejected");
        assert!(error.to_string().contains("empty segment"));
    }

    #[test]
    fn rejects_selector_with_disallowed_character() {
        let content = r#"
schema_version = "ef-mcp-policy/v0.2"
name = "bad-char"

[tools]
allow = ["demo.tool"]

[tools."demo.tool".arguments.fields."a b"]
type = "exact"
value = "x"
"#;
        let error =
            parse_mcp_policy(content).expect_err("disallowed character in selector rejected");
        assert!(error.to_string().contains("disallowed character"));
    }

    #[test]
    fn rejects_bidi_selector_segment() {
        let content = format!(
            r#"
schema_version = "ef-mcp-policy/v0.2"
name = "bidi-selector"

[tools]
allow = ["demo.tool"]

[tools."demo.tool".arguments.fields."a{}b"]
type = "exact"
value = "x"
"#,
            '\u{202E}'
        );
        let error = parse_mcp_policy(&content).expect_err("bidi selector segment rejected");
        assert!(error.to_string().contains("unicode_bidi_control_detected"));
    }

    #[test]
    fn rejects_url_guard_with_unsupported_scheme() {
        let content = r#"
schema_version = "ef-mcp-policy/v0.2"
name = "bad-scheme"

[tools]
allow = ["demo.tool"]

[tools."demo.tool".arguments.fields.url]
type = "url"
schemes = ["ftp"]
"#;
        let error = parse_mcp_policy(content).expect_err("unsupported scheme rejected");
        assert!(error.to_string().contains("only http/https"));
    }

    #[test]
    fn rejects_url_guard_with_invalid_host() {
        let content = r#"
schema_version = "ef-mcp-policy/v0.2"
name = "bad-host"

[tools]
allow = ["demo.tool"]

[tools."demo.tool".arguments.fields.url]
type = "url"
hosts = ["user@evil.example"]
"#;
        let error = parse_mcp_policy(content).expect_err("invalid host rejected");
        assert!(error.to_string().contains("is invalid"));
    }

    #[test]
    fn rejects_url_guard_with_no_constraints() {
        let content = r#"
schema_version = "ef-mcp-policy/v0.2"
name = "no-constraints"

[tools]
allow = ["demo.tool"]

[tools."demo.tool".arguments.fields.url]
type = "url"
"#;
        let error = parse_mcp_policy(content).expect_err("meaningless url guard rejected");
        assert!(error.to_string().contains("configures no constraints"));
    }

    #[test]
    fn rejects_url_guard_path_prefix_without_boundary() {
        let content = r#"
schema_version = "ef-mcp-policy/v0.2"
name = "bad-prefix"

[tools]
allow = ["demo.tool"]

[tools."demo.tool".arguments.fields.url]
type = "url"
path_prefixes = ["/v1"]
"#;
        let error = parse_mcp_policy(content).expect_err("unbounded path prefix rejected");
        assert!(error.to_string().contains("start and end with '/'"));
    }

    #[test]
    fn rejects_unknown_field_guard_type() {
        let content = r#"
schema_version = "ef-mcp-policy/v0.2"
name = "unknown-type"

[tools]
allow = ["demo.tool"]

[tools."demo.tool".arguments.fields.org]
type = "regex"
pattern = ".*"
"#;
        assert!(parse_mcp_policy(content).is_err());
    }

    #[test]
    fn rejects_missing_path_rule_when_path_keys_configured() {
        let content = r#"
schema_version = "ef-mcp-policy/v0.2"
name = "missing-path-rule"

[tools]
allow = ["demo.tool"]

[tools."demo.tool".arguments]
path_keys = ["path"]
"#;
        let error = parse_mcp_policy(content).expect_err("missing path_rule rejected");
        assert!(error.to_string().contains("must configure path_rule"));
    }

    // --- require_keys / forbid_keys evaluation ---

    #[test]
    fn require_keys_allows_when_present() {
        let policy = policy_with_tool_guard(
            r#"
[tools."demo.tool".arguments]
require_keys = ["org", "repo"]
"#,
        );
        let decision = decide_tool_argument_guards(
            &policy,
            "demo.tool",
            Some(&json!({"org": "my-org", "repo": "svc"})),
        )
        .expect("guard configured");
        assert_eq!(decision.decision, Decision::Allow);
    }

    #[test]
    fn require_keys_denies_when_missing() {
        let policy = policy_with_tool_guard(
            r#"
[tools."demo.tool".arguments]
require_keys = ["org", "repo"]
"#,
        );
        let decision =
            decide_tool_argument_guards(&policy, "demo.tool", Some(&json!({"org": "my-org"})))
                .expect("guard configured");
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(decision.reason_category, "required_key_missing");
        assert_eq!(decision.selector, "repo");
    }

    #[test]
    fn require_keys_denies_when_container_absent() {
        let policy = policy_with_tool_guard(
            r#"
[tools."demo.tool".arguments]
require_keys = ["org"]
"#,
        );
        let decision =
            decide_tool_argument_guards(&policy, "demo.tool", None).expect("guard configured");
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(decision.reason_category, "required_key_missing");
    }

    #[test]
    fn forbid_keys_denies_regardless_of_value() {
        let policy = policy_with_tool_guard(
            r#"
[tools."demo.tool".arguments]
forbid_keys = ["bypass"]
"#,
        );
        let decision =
            decide_tool_argument_guards(&policy, "demo.tool", Some(&json!({"bypass": false})))
                .expect("guard configured");
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(decision.reason_category, "forbidden_key_present");
    }

    #[test]
    fn forbid_keys_allows_when_absent() {
        let policy = policy_with_tool_guard(
            r#"
[tools."demo.tool".arguments]
forbid_keys = ["bypass"]
"#,
        );
        let decision = decide_tool_argument_guards(&policy, "demo.tool", Some(&json!({"x": 1})))
            .expect("guard configured");
        assert_eq!(decision.decision, Decision::Allow);
    }

    #[test]
    fn no_guard_configured_returns_none() {
        let policy = policy_with_tool_guard(
            r#"
[tools."demo.tool".arguments]
path_rule = "unused"
"#,
        );
        assert!(decide_tool_argument_guards(&policy, "demo.tool", Some(&json!({}))).is_none());
    }

    // --- exact / enum ---

    #[test]
    fn exact_guard_allows_matching_value() {
        let policy = policy_with_tool_guard(
            r#"
[tools."demo.tool".arguments.fields.mode]
type = "exact"
value = "read"
"#,
        );
        let decision =
            decide_tool_argument_guards(&policy, "demo.tool", Some(&json!({"mode": "read"})))
                .unwrap();
        assert_eq!(decision.decision, Decision::Allow);
    }

    #[test]
    fn exact_guard_denies_mismatched_value() {
        let policy = policy_with_tool_guard(
            r#"
[tools."demo.tool".arguments.fields.mode]
type = "exact"
value = "read"
"#,
        );
        let decision =
            decide_tool_argument_guards(&policy, "demo.tool", Some(&json!({"mode": "write"})))
                .unwrap();
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(decision.reason_category, "exact_value_mismatch");
    }

    #[test]
    fn enum_guard_allows_member_and_denies_non_member() {
        let policy = policy_with_tool_guard(
            r#"
[tools."demo.tool".arguments.fields.org]
type = "enum"
values = ["my-org"]
"#,
        );
        let allowed =
            decide_tool_argument_guards(&policy, "demo.tool", Some(&json!({"org": "my-org"})))
                .unwrap();
        assert_eq!(allowed.decision, Decision::Allow);
        let denied =
            decide_tool_argument_guards(&policy, "demo.tool", Some(&json!({"org": "other-org"})))
                .unwrap();
        assert_eq!(denied.decision, Decision::Deny);
        assert_eq!(denied.reason_category, "enum_value_not_allowed");
    }

    #[test]
    fn enum_guard_denies_missing_field() {
        let policy = policy_with_tool_guard(
            r#"
[tools."demo.tool".arguments.fields.org]
type = "enum"
values = ["my-org"]
"#,
        );
        let decision = decide_tool_argument_guards(&policy, "demo.tool", Some(&json!({}))).unwrap();
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(decision.reason_category, "field_missing");
    }

    // --- string: length + prefix ---

    #[test]
    fn string_guard_length_bounds() {
        let policy = policy_with_tool_guard(
            r#"
[tools."demo.tool".arguments.fields.name]
type = "string"
min_length = 2
max_length = 4
"#,
        );
        assert_eq!(
            decide_tool_argument_guards(&policy, "demo.tool", Some(&json!({"name": "ok"})))
                .unwrap()
                .decision,
            Decision::Allow
        );
        let too_short =
            decide_tool_argument_guards(&policy, "demo.tool", Some(&json!({"name": "a"}))).unwrap();
        assert_eq!(too_short.reason_category, "string_too_short");
        let too_long =
            decide_tool_argument_guards(&policy, "demo.tool", Some(&json!({"name": "toolong"})))
                .unwrap();
        assert_eq!(too_long.reason_category, "string_too_long");
    }

    #[test]
    fn string_guard_prefix_and_wrong_type() {
        let policy = policy_with_tool_guard(
            r#"
[tools."demo.tool".arguments.fields.repo]
type = "string"
prefix = "my-org/"
"#,
        );
        assert_eq!(
            decide_tool_argument_guards(&policy, "demo.tool", Some(&json!({"repo": "my-org/svc"})))
                .unwrap()
                .decision,
            Decision::Allow
        );
        let mismatch = decide_tool_argument_guards(
            &policy,
            "demo.tool",
            Some(&json!({"repo": "other-org/svc"})),
        )
        .unwrap();
        assert_eq!(mismatch.reason_category, "string_prefix_mismatch");
        let wrong_type =
            decide_tool_argument_guards(&policy, "demo.tool", Some(&json!({"repo": 5}))).unwrap();
        assert_eq!(wrong_type.reason_category, "field_wrong_type");
    }

    // --- number bounds ---

    #[test]
    fn number_guard_bounds_and_wrong_type() {
        let policy = policy_with_tool_guard(
            r#"
[tools."demo.tool".arguments.fields.limit]
type = "number"
min = 1
max = 100
"#,
        );
        assert_eq!(
            decide_tool_argument_guards(&policy, "demo.tool", Some(&json!({"limit": 10})))
                .unwrap()
                .decision,
            Decision::Allow
        );
        let below =
            decide_tool_argument_guards(&policy, "demo.tool", Some(&json!({"limit": 0}))).unwrap();
        assert_eq!(below.reason_category, "number_below_minimum");
        let above =
            decide_tool_argument_guards(&policy, "demo.tool", Some(&json!({"limit": 1000})))
                .unwrap();
        assert_eq!(above.reason_category, "number_above_maximum");
        let wrong_type =
            decide_tool_argument_guards(&policy, "demo.tool", Some(&json!({"limit": "10"})))
                .unwrap();
        assert_eq!(wrong_type.reason_category, "field_wrong_type");
    }

    // --- array: length + allowed elements ---

    #[test]
    fn array_guard_length_and_allowed_elements() {
        let policy = policy_with_tool_guard(
            r#"
[tools."demo.tool".arguments.fields.fields]
type = "array"
min_items = 1
max_items = 2
allowed_elements = ["id", "title"]
"#,
        );
        assert_eq!(
            decide_tool_argument_guards(&policy, "demo.tool", Some(&json!({"fields": ["id"]})))
                .unwrap()
                .decision,
            Decision::Allow
        );
        let too_short =
            decide_tool_argument_guards(&policy, "demo.tool", Some(&json!({"fields": []})))
                .unwrap();
        assert_eq!(too_short.reason_category, "array_too_short");
        let too_long = decide_tool_argument_guards(
            &policy,
            "demo.tool",
            Some(&json!({"fields": ["id", "title", "status"]})),
        )
        .unwrap();
        assert_eq!(too_long.reason_category, "array_too_long");
        let not_allowed = decide_tool_argument_guards(
            &policy,
            "demo.tool",
            Some(&json!({"fields": ["id", "secret"]})),
        )
        .unwrap();
        assert_eq!(not_allowed.reason_category, "array_element_not_allowed");
    }

    // --- url guard ---

    fn url_policy() -> McpPolicyFile {
        policy_with_tool_guard(
            r#"
[tools."demo.tool".arguments.fields.url]
type = "url"
schemes = ["https"]
hosts = ["api.example.invalid"]
ports = [443]
path_prefixes = ["/v1/"]
"#,
        )
    }

    #[test]
    fn url_guard_allows_matching_url() {
        let policy = url_policy();
        let decision = decide_tool_argument_guards(
            &policy,
            "demo.tool",
            Some(&json!({"url": "https://api.example.invalid/v1/search?q=x"})),
        )
        .unwrap();
        assert_eq!(decision.decision, Decision::Allow);
    }

    #[test]
    fn url_guard_denies_wrong_scheme() {
        let policy = url_policy();
        let decision = decide_tool_argument_guards(
            &policy,
            "demo.tool",
            Some(&json!({"url": "http://api.example.invalid/v1/search"})),
        )
        .unwrap();
        assert_eq!(decision.reason_category, "url_scheme_not_allowed");
    }

    #[test]
    fn url_guard_denies_unlisted_host() {
        let policy = url_policy();
        let decision = decide_tool_argument_guards(
            &policy,
            "demo.tool",
            Some(&json!({"url": "https://evil.example/v1/search"})),
        )
        .unwrap();
        assert_eq!(decision.reason_category, "url_host_not_allowed");
    }

    #[test]
    fn url_guard_denies_userinfo_confusable_authority() {
        let policy = url_policy();
        let decision = decide_tool_argument_guards(
            &policy,
            "demo.tool",
            Some(&json!({"url": "https://api.example.invalid@evil.example/v1/x"})),
        )
        .unwrap();
        assert_eq!(decision.reason_category, "url_malformed");
    }

    #[test]
    fn url_guard_denies_percent_encoded_value() {
        let policy = url_policy();
        let decision = decide_tool_argument_guards(
            &policy,
            "demo.tool",
            Some(&json!({"url": "https://api.example.invalid/v1/%2e%2e"})),
        )
        .unwrap();
        assert_eq!(decision.reason_category, "url_malformed");
    }

    #[test]
    fn url_guard_denies_out_of_prefix_path() {
        let policy = url_policy();
        let decision = decide_tool_argument_guards(
            &policy,
            "demo.tool",
            Some(&json!({"url": "https://api.example.invalid/v2/search"})),
        )
        .unwrap();
        assert_eq!(decision.reason_category, "url_path_prefix_not_allowed");
    }

    #[test]
    fn url_guard_denies_wrong_port() {
        let policy = policy_with_tool_guard(
            r#"
[tools."demo.tool".arguments.fields.url]
type = "url"
schemes = ["https"]
ports = [8443]
"#,
        );
        let decision = decide_tool_argument_guards(
            &policy,
            "demo.tool",
            Some(&json!({"url": "https://api.example.invalid/x"})),
        )
        .unwrap();
        assert_eq!(decision.reason_category, "url_port_not_allowed");
    }

    #[test]
    fn url_guard_uses_explicit_port_when_present() {
        let policy = policy_with_tool_guard(
            r#"
[tools."demo.tool".arguments.fields.url]
type = "url"
ports = [8443]
"#,
        );
        let decision = decide_tool_argument_guards(
            &policy,
            "demo.tool",
            Some(&json!({"url": "https://api.example.invalid:8443/x"})),
        )
        .unwrap();
        assert_eq!(decision.decision, Decision::Allow);
    }

    // --- nested selector ---

    #[test]
    fn nested_selector_resolves_object_field() {
        let policy = policy_with_tool_guard(
            r#"
[tools."demo.tool".arguments.fields."filter.status"]
type = "enum"
values = ["open", "closed"]
"#,
        );
        let allowed = decide_tool_argument_guards(
            &policy,
            "demo.tool",
            Some(&json!({"filter": {"status": "open"}})),
        )
        .unwrap();
        assert_eq!(allowed.decision, Decision::Allow);
        let denied = decide_tool_argument_guards(
            &policy,
            "demo.tool",
            Some(&json!({"filter": {"status": "archived"}})),
        )
        .unwrap();
        assert_eq!(denied.reason_category, "enum_value_not_allowed");
    }

    #[test]
    fn nested_selector_denies_when_intermediate_missing_or_wrong_type() {
        let policy = policy_with_tool_guard(
            r#"
[tools."demo.tool".arguments.fields."filter.status"]
type = "enum"
values = ["open"]
"#,
        );
        let missing_filter =
            decide_tool_argument_guards(&policy, "demo.tool", Some(&json!({}))).unwrap();
        assert_eq!(missing_filter.reason_category, "field_missing");
        let wrong_type_filter = decide_tool_argument_guards(
            &policy,
            "demo.tool",
            Some(&json!({"filter": "not-an-object"})),
        )
        .unwrap();
        assert_eq!(wrong_type_filter.reason_category, "field_missing");
    }

    #[test]
    fn nested_selector_resolves_array_index() {
        let policy = policy_with_tool_guard(
            r#"
[tools."demo.tool".arguments.fields."items.0.id"]
type = "exact"
value = "abc"
"#,
        );
        let allowed = decide_tool_argument_guards(
            &policy,
            "demo.tool",
            Some(&json!({"items": [{"id": "abc"}]})),
        )
        .unwrap();
        assert_eq!(allowed.decision, Decision::Allow);
        let out_of_range =
            decide_tool_argument_guards(&policy, "demo.tool", Some(&json!({"items": []}))).unwrap();
        assert_eq!(out_of_range.reason_category, "field_missing");
    }

    // --- method param guards apply beyond resources/read ---

    #[test]
    fn method_param_guard_applies_to_custom_method() {
        let policy = policy_with_method_guard(
            r#"
[methods."demo/method".params]
require_keys = ["destination"]

[methods."demo/method".params.fields.destination]
type = "enum"
values = ["eng-alerts"]
"#,
        );
        let allowed = decide_method_param_guards(
            &policy,
            "demo/method",
            Some(&json!({"destination": "eng-alerts"})),
        )
        .unwrap();
        assert_eq!(allowed.decision, Decision::Allow);
        let denied = decide_method_param_guards(
            &policy,
            "demo/method",
            Some(&json!({"destination": "random"})),
        )
        .unwrap();
        assert_eq!(denied.decision, Decision::Deny);
    }

    #[test]
    fn scalar_matches_does_not_coerce_across_types() {
        assert!(!ScalarValue::Int(5).matches(&json!("5")));
        assert!(!ScalarValue::Str("5".to_string()).matches(&json!(5)));
        assert!(ScalarValue::Int(5).matches(&json!(5)));
        assert!(ScalarValue::Bool(true).matches(&json!(true)));
    }
}
