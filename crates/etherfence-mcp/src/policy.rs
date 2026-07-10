use anyhow::{Context, Result};
use etherfence_core::{read_bounded_text_file, MAX_CONFIG_FILE_BYTES};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

use crate::unicode::{
    inspect_method_name, inspect_path_value, inspect_policy_identifier, inspect_tool_name,
};

pub const SUPPORTED_MCP_POLICY_SCHEMA_VERSION: &str = "ef-mcp-policy/v0.1";

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
    pub arguments: Option<PathKeyGuard>,
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
    pub params: Option<PathKeyGuard>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct PathKeyGuard {
    #[serde(default)]
    pub path_keys: Vec<String>,
    #[serde(default)]
    pub uri_keys: Vec<String>,
    pub path_rule: String,
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
    if policy.schema_version != SUPPORTED_MCP_POLICY_SCHEMA_VERSION {
        anyhow::bail!(
            "unsupported MCP proxy policy schema_version {:?}; supported schema_version is {:?}",
            policy.schema_version,
            SUPPORTED_MCP_POLICY_SCHEMA_VERSION
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
    validate_policy_identifier(&policy.name, "MCP proxy policy name")?;
    validate_tool_rules(&policy.tools, "global tool policy")?;
    if let Some(methods) = &policy.methods {
        validate_method_rules(methods, "global method policy")?;
    }
    for rule_name in policy.path_rules.keys() {
        validate_policy_identifier(rule_name, "MCP proxy path rule name")?;
    }
    for (server_name, server) in &policy.servers {
        validate_policy_identifier(server_name, "MCP proxy server policy name")?;
        validate_tool_rules(&server.tools, "server-specific tool policy")?;
        if let Some(methods) = &server.methods {
            validate_method_rules(methods, "server-specific method policy")?;
        }
    }
    Ok(())
}

fn validate_tool_rules(rules: &ToolRules, context: &str) -> Result<()> {
    for tool_name in rules.allow.iter().chain(rules.deny.iter()) {
        validate_tool_name(tool_name, context)?;
    }
    for (tool_name, guard) in &rules.path_guards {
        validate_tool_name(tool_name, "MCP proxy tool path guard key")?;
        if let Some(arguments) = &guard.arguments {
            validate_path_key_guard(arguments, "MCP proxy tool argument path guard")?;
        }
    }
    Ok(())
}

fn validate_method_rules(rules: &MethodRules, context: &str) -> Result<()> {
    for method in rules.allow.iter().chain(rules.deny.iter()) {
        validate_method_name(method, context)?;
    }
    for (method, guard) in &rules.path_guards {
        validate_method_name(method, "MCP proxy method path guard key")?;
        if let Some(params) = &guard.params {
            validate_path_key_guard(params, "MCP proxy method param path guard")?;
        }
    }
    Ok(())
}

fn validate_path_key_guard(guard: &PathKeyGuard, context: &str) -> Result<()> {
    validate_policy_identifier(&guard.path_rule, "MCP proxy referenced path rule name")?;
    for key in guard.path_keys.iter().chain(guard.uri_keys.iter()) {
        validate_policy_identifier(key, context)?;
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
    Some(decide_path_keys(policy, guard, params, PathInputKind::Uri))
}

fn decide_path_keys(
    policy: &McpPolicyFile,
    guard: &PathKeyGuard,
    container: Option<&serde_json::Value>,
    default_kind: PathInputKind,
) -> PathPolicyDecision {
    let rule_name = guard.path_rule.clone();
    let Some(rule) = policy.path_rules.get(&guard.path_rule) else {
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

fn first_configured_key(guard: &PathKeyGuard) -> String {
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
