use anyhow::{Context, Result};
use etherfence_core::{read_bounded_text_file, MAX_CONFIG_FILE_BYTES};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

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
    Ok(policy)
}

/// Deterministic decision for a tool name: deny-list match wins, then
/// allow-list membership is required, and everything else is denied.
pub fn decide_tool_call(
    policy: &McpPolicyFile,
    server_name: &str,
    tool_name: &str,
) -> PolicyDecision {
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

    const VALID_POLICY: &str = r#"
schema_version = "ef-mcp-policy/v0.1"
name = "minimal-mcp-boundary"

[tools]
allow = ["github.list_repos", "filesystem.read"]
deny = ["filesystem.read_secret", "shell.run"]
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
