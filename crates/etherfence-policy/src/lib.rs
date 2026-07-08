use anyhow::{Context, Result};
use etherfence_core::{
    AgentKind, BaselineStatus, Finding, FindingKind, InventoryItem, McpServer, PolicyStatus,
    Severity,
};
use regex::Regex;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

pub const SUPPORTED_POLICY_SCHEMA_VERSION: &str = "ef-policy/v0.1";

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyFile {
    pub schema_version: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub require_tirith: bool,
    #[serde(default)]
    pub agents: HashMap<String, AgentPolicy>,
    #[serde(default)]
    pub filesystem: FilesystemPolicy,
    #[serde(default)]
    pub environment: EnvironmentPolicy,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct AgentPolicy {
    #[serde(default)]
    pub allowed_mcp_servers: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct FilesystemPolicy {
    #[serde(default)]
    pub allowed_path_prefixes: Vec<String>,
    #[serde(default)]
    pub denied_paths: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct EnvironmentPolicy {
    #[serde(default)]
    pub allowed_name_patterns: Vec<String>,
    #[serde(default)]
    pub deny_secret_like_names: bool,
}

#[derive(Debug, Clone)]
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
}

struct CompiledPolicy {
    file: PolicyFile,
    allowed_env_name_patterns: Vec<Regex>,
}

pub fn load_policy(path: &Path) -> Result<PolicyFile> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("reading policy file {}", path.display()))?;
    parse_policy(&content).with_context(|| format!("parsing policy file {}", path.display()))
}

pub fn parse_policy(content: &str) -> Result<PolicyFile> {
    let policy: PolicyFile = toml::from_str(content)?;
    validate_policy_schema(&policy)?;
    Ok(policy)
}

fn validate_policy_schema(policy: &PolicyFile) -> Result<()> {
    if policy.schema_version != SUPPORTED_POLICY_SCHEMA_VERSION {
        anyhow::bail!(
            "unsupported policy schema_version {:?}; supported schema_version is {:?}",
            policy.schema_version,
            SUPPORTED_POLICY_SCHEMA_VERSION
        );
    }
    Ok(())
}

pub fn evaluate_policy(
    policy: &PolicyFile,
    inventory: &[InventoryItem],
) -> Result<PolicyEvaluation> {
    let compiled = CompiledPolicy::new(policy.clone())?;
    let mut findings = Vec::new();
    let mut checks_total = 0usize;
    let mut pass = 0usize;
    let mut not_applicable = 0usize;

    for item in inventory {
        if item.agent == AgentKind::Tirith {
            continue;
        }
        if item.mcp_servers.is_empty() {
            checks_total += 1;
            not_applicable += 1;
            continue;
        }
        for server in &item.mcp_servers {
            checks_total += 1;
            if let Some(finding) = compiled.check_mcp_server(item, server) {
                findings.push(finding);
            } else {
                pass += 1;
            }

            if is_filesystem_capable(server) {
                let paths = filesystem_paths(server);
                if paths.is_empty() {
                    checks_total += 1;
                    not_applicable += 1;
                }
                for path in paths {
                    checks_total += 1;
                    if let Some(finding) = compiled.check_filesystem_path(item, server, &path) {
                        findings.push(finding);
                    } else {
                        pass += 1;
                    }
                }
            }

            for env in &server.env {
                checks_total += 1;
                if let Some(finding) = compiled.check_environment_name(item, server, &env.name) {
                    findings.push(finding);
                } else {
                    pass += 1;
                }

                if compiled.file.environment.deny_secret_like_names {
                    checks_total += 1;
                    if secret_looking_name(&env.name) {
                        findings.push(policy_finding(
                            item,
                            &server.name,
                            vec![format!("env={}", env.name)],
                            FindingTemplate {
                                id: "EF-POL-004",
                                policy_id: "secret-like-env-name",
                                title: "Secret-like MCP environment variable exposure",
                                severity: Severity::High,
                                kind: FindingKind::PolicySecretLikeEnvironmentExposure,
                                rationale: "The policy denies exposing secret-looking environment variable names to MCP servers.",
                                impact: "Credential-bearing environment variables may be available to a server outside the expected policy posture.",
                                recommendation: "Remove the variable from the MCP server environment or replace it with a narrower non-secret configuration value.",
                            },
                        ));
                    } else {
                        pass += 1;
                    }
                }
            }
        }
    }

    if compiled.file.require_tirith {
        checks_total += 1;
        if inventory.iter().any(|item| item.agent == AgentKind::Tirith) {
            pass += 1;
        } else {
            findings.push(tirith_required_finding(&compiled.file.name));
        }
    }

    findings.sort_by(|a, b| {
        a.id.cmp(&b.id)
            .then_with(|| a.agent.key().cmp(b.agent.key()))
            .then_with(|| a.target.cmp(&b.target))
            .then_with(|| a.evidence.cmp(&b.evidence))
    });

    let violation = findings.len();
    Ok(PolicyEvaluation {
        policy_schema_version: compiled.file.schema_version,
        policy_name: compiled.file.name,
        policy_description: compiled.file.description,
        require_tirith: compiled.file.require_tirith,
        findings,
        checks_total,
        pass,
        violation,
        not_applicable,
    })
}

impl CompiledPolicy {
    fn new(file: PolicyFile) -> Result<Self> {
        let allowed_env_name_patterns = file
            .environment
            .allowed_name_patterns
            .iter()
            .map(|pattern| {
                Regex::new(pattern).with_context(|| {
                    format!("invalid environment.allowed_name_patterns regex {pattern:?}")
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            file,
            allowed_env_name_patterns,
        })
    }

    fn check_mcp_server(&self, item: &InventoryItem, server: &McpServer) -> Option<Finding> {
        let agent_policy = self.agent_policy(item.agent)?;
        if agent_policy.allowed_mcp_servers.is_empty()
            || agent_policy
                .allowed_mcp_servers
                .iter()
                .any(|allowed| same_name(allowed, &server.name))
        {
            return None;
        }
        Some(policy_finding(
            item,
            &server.name,
            vec![format!("server={}", server.name)],
            FindingTemplate {
                id: "EF-POL-001",
                policy_id: "unexpected-mcp-server",
                title: "Unexpected MCP server for agent policy",
                severity: Severity::High,
                kind: FindingKind::PolicyUnexpectedMcpServer,
                rationale: "The MCP server is not in the policy allowlist for this agent.",
                impact: "Unexpected MCP servers can expand an agent's reachable tools, data, or network surface beyond the expected posture.",
                recommendation: "Remove the MCP server or add it to the agent's allowed_mcp_servers after review.",
            },
        ))
    }

    fn check_filesystem_path(
        &self,
        item: &InventoryItem,
        server: &McpServer,
        path: &str,
    ) -> Option<Finding> {
        let denied = is_broad_filesystem_path(path)
            || self
                .file
                .filesystem
                .denied_paths
                .iter()
                .any(|denied| normalized_path(path) == normalized_path(denied));
        let allowed = !self.file.filesystem.allowed_path_prefixes.is_empty()
            && self
                .file
                .filesystem
                .allowed_path_prefixes
                .iter()
                .any(|prefix| path_has_prefix(path, prefix));
        if denied || !allowed {
            Some(policy_finding(
                item,
                &server.name,
                vec![format!("path={path}")],
                FindingTemplate {
                    id: "EF-POL-002",
                    policy_id: "disallowed-filesystem-path",
                    title: "Disallowed filesystem path exposure",
                    severity: Severity::High,
                    kind: FindingKind::PolicyDisallowedFilesystemPath,
                    rationale: "A filesystem-capable MCP server exposes a path outside the policy's allowed prefixes or matching a broad denied path.",
                    impact: "Broad or unapproved filesystem grants can expose sensitive local files to agent workflows.",
                    recommendation: "Restrict filesystem-capable MCP servers to explicit project prefixes such as /path/to/project and avoid root or home-directory-wide grants.",
                },
            ))
        } else {
            None
        }
    }

    fn check_environment_name(
        &self,
        item: &InventoryItem,
        server: &McpServer,
        name: &str,
    ) -> Option<Finding> {
        if self.allowed_env_name_patterns.is_empty()
            || self
                .allowed_env_name_patterns
                .iter()
                .any(|pattern| pattern.is_match(name))
        {
            return None;
        }
        Some(policy_finding(
            item,
            &server.name,
            vec![format!("env={name}")],
            FindingTemplate {
                id: "EF-POL-003",
                policy_id: "disallowed-env-name",
                title: "Disallowed MCP environment variable exposure",
                severity: Severity::Medium,
                kind: FindingKind::PolicyDisallowedEnvironmentExposure,
                rationale: "The MCP server receives an environment variable name that does not match the policy's allowed name patterns.",
                impact: "Unexpected environment exposure can leak operational context or credentials into MCP server processes.",
                recommendation: "Remove the variable or update allowed_name_patterns after confirming the exposure is required and safe.",
            },
        ))
    }

    fn agent_policy(&self, agent: AgentKind) -> Option<&AgentPolicy> {
        self.file
            .agents
            .get(agent.display_name())
            .or_else(|| self.file.agents.get(agent.key()))
    }
}

struct FindingTemplate {
    id: &'static str,
    policy_id: &'static str,
    title: &'static str,
    severity: Severity,
    kind: FindingKind,
    rationale: &'static str,
    impact: &'static str,
    recommendation: &'static str,
}

fn policy_finding(
    item: &InventoryItem,
    target: &str,
    evidence: Vec<String>,
    template: FindingTemplate,
) -> Finding {
    let mut finding = Finding {
        id: template.id.to_string(),
        title: template.title.to_string(),
        severity: template.severity,
        kind: template.kind,
        agent: item.agent,
        target: target.to_string(),
        config_path: item.config_path.clone(),
        rationale: template.rationale.to_string(),
        impact: template.impact.to_string(),
        recommendation: template.recommendation.to_string(),
        references: Vec::new(),
        fingerprint: String::new(),
        baseline_status: BaselineStatus::NotApplicable,
        policy_status: PolicyStatus::Violation,
        policy_id: Some(template.policy_id.to_string()),
        evidence,
    };
    finding.refresh_fingerprint();
    finding
}

fn tirith_required_finding(policy_name: &str) -> Finding {
    let mut finding = Finding {
        id: "EF-POL-005".to_string(),
        title: "Tirith not detected when required by policy".to_string(),
        severity: Severity::High,
        kind: FindingKind::PolicyRequiredTirithMissing,
        agent: AgentKind::Tirith,
        target: "tirith".to_string(),
        config_path: "policy".to_string(),
        rationale: "The policy requires Tirith to be detected, but EtherFence did not find a Tirith config marker or tirith binary on PATH.".to_string(),
        impact: "Expected complementary terminal-command controls may be absent from this local AI-agent posture.".to_string(),
        recommendation: "Install or configure Tirith for the host, or set require_tirith = false if this posture is not expected.".to_string(),
        references: Vec::new(),
        fingerprint: String::new(),
        baseline_status: BaselineStatus::NotApplicable,
        policy_status: PolicyStatus::Violation,
        policy_id: Some("tirith-required".to_string()),
        evidence: vec![format!("policy={policy_name}"), "require_tirith=true".to_string()],
    };
    finding.refresh_fingerprint();
    finding
}

fn is_filesystem_capable(server: &McpServer) -> bool {
    let haystack = server_values(server).join(" ").to_ascii_lowercase();
    ["filesystem", "file-system", "read_file", "write_file", "fs"]
        .iter()
        .any(|needle| haystack.contains(needle))
}

fn filesystem_paths(server: &McpServer) -> Vec<String> {
    let mut seen = HashSet::new();
    server_values(server)
        .into_iter()
        .filter(|value| looks_like_path(value))
        .filter_map(|value| {
            let normalized = normalized_path(&value);
            seen.insert(normalized.clone()).then_some(normalized)
        })
        .collect()
}

fn server_values(server: &McpServer) -> Vec<String> {
    let mut values = vec![server.name.clone()];
    if let Some(command) = &server.command {
        values.push(command.clone());
    }
    values.extend(server.args.clone());
    if let Some(url) = &server.url {
        values.push(url.clone());
    }
    values
}

fn looks_like_path(value: &str) -> bool {
    let value = value.trim();
    value == "/"
        || value.starts_with("/home/")
        || value.starts_with("/Users/")
        || value.starts_with("/path/")
}

fn is_broad_filesystem_path(path: &str) -> bool {
    let path = normalized_path(path);
    path == "/"
        || path == "/home"
        || path == "/home/user"
        || path == "/Users"
        || path == "/Users/example"
        || home_wide_grant(&path)
}

fn home_wide_grant(path: &str) -> bool {
    let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
    matches!(parts.as_slice(), ["home", _] | ["Users", _])
}

fn path_has_prefix(path: &str, prefix: &str) -> bool {
    let path = normalized_path(path);
    let prefix = normalized_path(prefix);
    path == prefix || path.starts_with(&format!("{prefix}/"))
}

fn normalized_path(path: &str) -> String {
    let path = path.trim().trim_end_matches('/');
    if path.is_empty() {
        "/".to_string()
    } else if path == "/" {
        path.to_string()
    } else {
        path.replace('\\', "/")
    }
}

fn same_name(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
}

fn secret_looking_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    [
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASS",
        "API_KEY",
        "ACCESS_KEY",
        "PRIVATE_KEY",
        "CREDENTIAL",
        "AUTH",
    ]
    .iter()
    .any(|needle| upper.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherfence_core::{EnvVar, McpServer};

    fn strict_policy() -> PolicyFile {
        parse_policy(
            r#"
schema_version = "ef-policy/v0.1"
name = "strict-local-ai-agent-policy"
description = "Strict local AI agent policy for policy evaluator tests."
require_tirith = true

[agents."Claude Code"]
allowed_mcp_servers = ["filesystem", "github"]

[filesystem]
allowed_path_prefixes = ["/path/to/project"]
denied_paths = ["/", "/home/user", "/Users/example"]

[environment]
allowed_name_patterns = ["^GITHUB_", "^NODE_"]
deny_secret_like_names = true
"#,
        )
        .expect("valid policy")
    }

    fn inventory() -> Vec<InventoryItem> {
        vec![InventoryItem {
            agent: AgentKind::ClaudeCode,
            config_path: "~/.claude.json".to_string(),
            mcp_servers: vec![
                McpServer {
                    name: "filesystem".to_string(),
                    command: Some("npx".to_string()),
                    args: vec![
                        "@modelcontextprotocol/server-filesystem".to_string(),
                        "/home/user".to_string(),
                    ],
                    env: vec![EnvVar {
                        name: "API_TOKEN".to_string(),
                        value_hint: Some("<set>".to_string()),
                    }],
                    url: None,
                },
                McpServer {
                    name: "slack".to_string(),
                    command: Some("node".to_string()),
                    args: Vec::new(),
                    env: vec![EnvVar {
                        name: "NODE_ENV".to_string(),
                        value_hint: Some("<set>".to_string()),
                    }],
                    url: None,
                },
            ],
            evidence: Vec::new(),
        }]
    }

    #[test]
    fn parses_policy_toml() {
        let policy = strict_policy();
        assert_eq!(policy.name, "strict-local-ai-agent-policy");
        assert_eq!(policy.schema_version, SUPPORTED_POLICY_SCHEMA_VERSION);
        assert!(policy.require_tirith);
        assert_eq!(
            policy.agents["Claude Code"].allowed_mcp_servers,
            vec!["filesystem", "github"]
        );
    }

    #[test]
    fn rejects_unsupported_policy_schema_version() {
        let err = parse_policy(
            r#"
schema_version = "ef-policy/v9.9"
name = "future-policy"
"#,
        )
        .expect_err("unsupported schema should fail");
        assert!(err
            .to_string()
            .contains("unsupported policy schema_version"));
    }

    #[test]
    fn generates_expected_policy_violations() {
        let result = evaluate_policy(&strict_policy(), &inventory()).expect("evaluate policy");
        let ids: Vec<&str> = result
            .findings
            .iter()
            .map(|finding| finding.id.as_str())
            .collect();
        assert!(ids.contains(&"EF-POL-001"));
        assert!(ids.contains(&"EF-POL-002"));
        assert!(ids.contains(&"EF-POL-003"));
        assert!(ids.contains(&"EF-POL-004"));
        assert!(ids.contains(&"EF-POL-005"));
        assert!(result.findings.iter().all(|finding| {
            finding.policy_status == PolicyStatus::Violation && finding.policy_id.is_some()
        }));
    }

    #[test]
    fn allowed_project_path_and_env_pattern_pass() {
        let policy = strict_policy();
        let inventory = vec![
            InventoryItem {
                agent: AgentKind::ClaudeCode,
                config_path: "~/.claude.json".to_string(),
                mcp_servers: vec![McpServer {
                    name: "filesystem".to_string(),
                    command: Some("npx".to_string()),
                    args: vec![
                        "@modelcontextprotocol/server-filesystem".to_string(),
                        "/path/to/project/app".to_string(),
                    ],
                    env: vec![EnvVar {
                        name: "GITHUB_TOKEN".to_string(),
                        value_hint: Some("<set>".to_string()),
                    }],
                    url: None,
                }],
                evidence: Vec::new(),
            },
            InventoryItem {
                agent: AgentKind::Tirith,
                config_path: "~/.tirith/config.toml".to_string(),
                mcp_servers: Vec::new(),
                evidence: vec!["Tirith file present".to_string()],
            },
        ];
        let result = evaluate_policy(&policy, &inventory).expect("evaluate policy");
        assert!(result
            .findings
            .iter()
            .all(|finding| finding.id != "EF-POL-002"));
        assert!(result
            .findings
            .iter()
            .all(|finding| finding.id != "EF-POL-003"));
        assert!(result
            .findings
            .iter()
            .any(|finding| finding.id == "EF-POL-004"));
    }
}
