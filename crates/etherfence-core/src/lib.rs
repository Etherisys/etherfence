use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AgentKind {
    ClaudeCode,
    Cursor,
    VsCode,
    Windsurf,
    GeminiCli,
    CodexCli,
    Tirith,
}

impl AgentKind {
    pub fn display_name(self) -> &'static str {
        match self {
            Self::ClaudeCode => "Claude Code",
            Self::Cursor => "Cursor",
            Self::VsCode => "VS Code",
            Self::Windsurf => "Windsurf",
            Self::GeminiCli => "Gemini CLI",
            Self::CodexCli => "Codex CLI",
            Self::Tirith => "Tirith",
        }
    }

    pub fn key(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::Cursor => "cursor",
            Self::VsCode => "vs-code",
            Self::Windsurf => "windsurf",
            Self::GeminiCli => "gemini-cli",
            Self::CodexCli => "codex-cli",
            Self::Tirith => "tirith",
        }
    }
}

impl fmt::Display for AgentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.display_name())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvVar {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_hint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpServer {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<EnvVar>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryItem {
    pub agent: AgentKind,
    pub config_path: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mcp_servers: Vec<McpServer>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

impl Severity {
    pub const ORDERED_DESC: [Severity; 4] = [
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingKind {
    McpServerConfigured,
    BroadFilesystemAccess,
    RiskyCommandToolHint,
    NetworkCapableToolHint,
    ExposedMcpEnvironment,
    SecretLookingEnvName,
    TirithBinaryDetected,
    TirithConfigDetected,
    PolicyUnexpectedMcpServer,
    PolicyDisallowedFilesystemPath,
    PolicyDisallowedEnvironmentExposure,
    PolicySecretLikeEnvironmentExposure,
    PolicyRequiredTirithMissing,
}

impl FindingKind {
    pub fn key(self) -> &'static str {
        match self {
            Self::McpServerConfigured => "mcp-server-configured",
            Self::BroadFilesystemAccess => "broad-filesystem-access",
            Self::RiskyCommandToolHint => "risky-command-tool-hint",
            Self::NetworkCapableToolHint => "network-capable-tool-hint",
            Self::ExposedMcpEnvironment => "exposed-mcp-environment",
            Self::SecretLookingEnvName => "secret-looking-env-name",
            Self::TirithBinaryDetected => "tirith-binary-detected",
            Self::TirithConfigDetected => "tirith-config-detected",
            Self::PolicyUnexpectedMcpServer => "policy-unexpected-mcp-server",
            Self::PolicyDisallowedFilesystemPath => "policy-disallowed-filesystem-path",
            Self::PolicyDisallowedEnvironmentExposure => "policy-disallowed-environment-exposure",
            Self::PolicySecretLikeEnvironmentExposure => "policy-secret-like-environment-exposure",
            Self::PolicyRequiredTirithMissing => "policy-required-tirith-missing",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BaselineStatus {
    New,
    Existing,
    Resolved,
    NotApplicable,
}

impl BaselineStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Existing => "existing",
            Self::Resolved => "resolved",
            Self::NotApplicable => "not_applicable",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStatus {
    Pass,
    Violation,
    #[default]
    NotApplicable,
}

impl PolicyStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Violation => "violation",
            Self::NotApplicable => "not_applicable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
}

impl Finding {
    pub fn refresh_fingerprint(&mut self) {
        self.fingerprint = finding_fingerprint(self);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    pub inventory_items: usize,
    pub findings_total: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl Summary {
    pub fn from_counts(inventory_items: usize, findings: &[Finding]) -> Self {
        Self {
            inventory_items,
            findings_total: findings.len(),
            high: findings
                .iter()
                .filter(|f| f.severity == Severity::High)
                .count(),
            medium: findings
                .iter()
                .filter(|f| f.severity == Severity::Medium)
                .count(),
            low: findings
                .iter()
                .filter(|f| f.severity == Severity::Low)
                .count(),
            info: findings
                .iter()
                .filter(|f| f.severity == Severity::Info)
                .count(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineComparison {
    pub baseline_path: String,
    pub new: usize,
    pub existing: usize,
    pub resolved: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyMetadata {
    pub policy_path: String,
    pub policy_schema_version: String,
    pub policy_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub policy_description: String,
    pub require_tirith: bool,
    pub checks_total: usize,
    pub pass: usize,
    pub violation: usize,
    pub not_applicable: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanReport {
    pub schema_version: String,
    pub tool: String,
    pub version: String,
    pub status: String,
    pub scanned_root: String,
    pub inventory: Vec<InventoryItem>,
    pub findings: Vec<Finding>,
    pub summary: Summary,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline: Option<BaselineComparison>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineFile {
    pub schema_version: String,
    pub tool: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    pub findings: Vec<Finding>,
}

pub fn finding_fingerprint(finding: &Finding) -> String {
    let mut evidence = finding.evidence.clone();
    evidence.sort();
    evidence.dedup();
    let material = format!(
        "id={}\nagent={}\nconfig_path={}\ntarget={}\nkind={}\nevidence={}",
        finding.id,
        finding.agent.key(),
        normalize_path(&finding.config_path),
        finding.target,
        finding.kind.key(),
        evidence
            .into_iter()
            .map(|item| normalize_path(&item))
            .collect::<Vec<_>>()
            .join("\u{1f}")
    );
    format!("efp1-{:016x}", fnv1a64(material.as_bytes()))
}

fn normalize_path(value: &str) -> String {
    value
        .replace('\\', "/")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_finding(evidence: Vec<String>) -> Finding {
        let mut finding = Finding {
            id: "EF-MCP-001".to_string(),
            title: "Broad filesystem access hint".to_string(),
            severity: Severity::High,
            kind: FindingKind::BroadFilesystemAccess,
            agent: AgentKind::ClaudeCode,
            target: "filesystem".to_string(),
            config_path: "~/.claude.json".to_string(),
            rationale: "rationale".to_string(),
            impact: "impact".to_string(),
            recommendation: "recommendation".to_string(),
            references: Vec::new(),
            fingerprint: String::new(),
            baseline_status: BaselineStatus::NotApplicable,
            policy_status: PolicyStatus::NotApplicable,
            policy_id: None,
            evidence,
        };
        finding.refresh_fingerprint();
        finding
    }

    #[test]
    fn fingerprint_is_stable_for_same_finding_and_sorted_evidence() {
        let a = sample_finding(vec!["/home/user".to_string(), "filesystem".to_string()]);
        let b = sample_finding(vec!["filesystem".to_string(), "/home/user".to_string()]);
        assert_eq!(a.fingerprint, b.fingerprint);
        assert!(a.fingerprint.starts_with("efp1-"));
    }

    #[test]
    fn fingerprint_changes_for_different_target() {
        let a = sample_finding(vec!["/home/user".to_string()]);
        let mut b = a.clone();
        b.target = "other".to_string();
        b.refresh_fingerprint();
        assert_ne!(a.fingerprint, b.fingerprint);
    }
}
