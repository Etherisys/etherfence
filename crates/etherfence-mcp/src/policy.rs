use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

pub const SUPPORTED_MCP_POLICY_SCHEMA_VERSION: &str = "ef-mcp-policy/v0.1";

/// Minimal MCP boundary proxy policy: exact-match tool-name allow/deny lists.
#[derive(Debug, Clone, Deserialize)]
pub struct McpPolicyFile {
    pub schema_version: String,
    pub name: String,
    #[serde(default)]
    pub tools: ToolRules,
    #[serde(default)]
    pub servers: BTreeMap<String, ServerPolicy>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ServerPolicy {
    #[serde(default)]
    pub tools: ToolRules,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ToolRules {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

/// The decision the proxy made for one MCP tool call.
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

pub fn load_mcp_policy(path: &Path) -> Result<McpPolicyFile> {
    let content = fs::read_to_string(path)
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
}
