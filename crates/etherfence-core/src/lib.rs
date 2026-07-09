use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::io;
use std::io::Read;
use std::path::Path;

/// Maximum size accepted for policy, MCP proxy policy, and scanned agent
/// config files (5 MiB). These are small structured text files; anything
/// larger is almost certainly not a legitimate config and should not be
/// read fully into memory.
pub const MAX_CONFIG_FILE_BYTES: u64 = 5 * 1024 * 1024;

/// Maximum size accepted for baseline files (25 MiB). Baselines accumulate
/// findings over time so they are allowed to grow larger than config files.
pub const MAX_BASELINE_FILE_BYTES: u64 = 25 * 1024 * 1024;

/// Reads a UTF-8 text file, rejecting it if it exceeds `max_bytes`.
///
/// The limit is enforced against the actual bytes read, not against
/// `stat`-reported file size: special files (procfs entries, device nodes
/// like `/dev/zero`, FIFOs) can report a length of zero or an unreliable
/// size while still producing unbounded or unexpected data on read, so a
/// pre-read `metadata.len()` check alone is not a real bound. This function
/// also rejects any path that is not a regular file, and caps the read
/// itself at `max_bytes + 1` via a bounded reader so no more than that
/// many bytes are ever pulled into memory regardless of what `stat` says.
///
/// This only bounds the amount of data read; it does not sandbox or
/// validate `path` in any way. In EtherFence's CLI, paths passed to this
/// function (`--policy`, `--baseline`, `--write-baseline`, `mcp-proxy
/// --policy`, `--audit-log`, and scanned agent config files) are explicit,
/// trusted-operator inputs — the security boundary is "the person running
/// the CLI chose this path," not path containment. Any future EtherFence
/// surface that accepts a path string from an untrusted caller (an API,
/// UI, or MCP-exposed tool) must additionally constrain that path under an
/// explicit base directory and reject traversal before it ever reaches
/// this helper.
pub fn read_bounded_text_file(path: &Path, max_bytes: u64) -> io::Result<String> {
    let file = fs::File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        ));
    }

    let read_limit = max_bytes.saturating_add(1);
    let mut buf = Vec::new();
    file.take(read_limit).read_to_end(&mut buf)?;

    if buf.len() as u64 > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "file {} exceeds the maximum allowed size of {} bytes",
                path.display(),
                max_bytes
            ),
        ));
    }

    String::from_utf8(buf).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("file {} is not valid UTF-8", path.display()),
        )
    })
}

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

/// Evidence prefix used by inventory items whose config file could not be parsed.
pub const PARSE_ERROR_EVIDENCE_PREFIX: &str = "parse-error:";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingKind {
    ConfigParseError,
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
            Self::ConfigParseError => "config-parse-error",
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
    pub policy_source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_profile: Option<String>,
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
    fn fingerprint_normalizes_windows_path_separators() {
        let mut windows = sample_finding(vec![
            r"C:\Users\example\Projects\demo".to_string(),
            "filesystem".to_string(),
        ]);
        windows.config_path = r"~\AppData\Roaming\Code\User\settings.json".to_string();
        windows.refresh_fingerprint();

        let mut normalized = sample_finding(vec![
            "C:/Users/example/Projects/demo".to_string(),
            "filesystem".to_string(),
        ]);
        normalized.config_path = "~/AppData/Roaming/Code/User/settings.json".to_string();
        normalized.refresh_fingerprint();

        assert_eq!(windows.fingerprint, normalized.fingerprint);
    }

    #[test]
    fn fingerprint_changes_for_different_target() {
        let a = sample_finding(vec!["/home/user".to_string()]);
        let mut b = a.clone();
        b.target = "other".to_string();
        b.refresh_fingerprint();
        assert_ne!(a.fingerprint, b.fingerprint);
    }

    fn write_temp_file(name: &str, contents: &[u8]) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "etherfence-core-test-{}-{}-{:016x}",
            std::process::id(),
            name,
            fnv1a64(contents)
        ));
        fs::write(&path, contents).expect("write temp file");
        path
    }

    #[test]
    fn read_bounded_text_file_accepts_file_exactly_at_limit() {
        let contents = vec![b'a'; 16];
        let path = write_temp_file("at-limit", &contents);

        let result = read_bounded_text_file(&path, 16);

        fs::remove_file(&path).ok();
        assert_eq!(result.unwrap(), "a".repeat(16));
    }

    #[test]
    fn read_bounded_text_file_rejects_file_over_limit() {
        let contents = vec![b'a'; 17];
        let path = write_temp_file("over-limit", &contents);

        let result = read_bounded_text_file(&path, 16);

        fs::remove_file(&path).ok();
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn read_bounded_text_file_rejects_invalid_utf8() {
        let contents = vec![0xff, 0xfe, 0xfd];
        let path = write_temp_file("invalid-utf8", &contents);

        let result = read_bounded_text_file(&path, 1024);

        fs::remove_file(&path).ok();
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn read_bounded_text_file_rejects_directory() {
        let dir = std::env::temp_dir();

        let result = read_bounded_text_file(&dir, 1024);

        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[cfg(unix)]
    #[test]
    fn read_bounded_text_file_rejects_unbounded_device_file() {
        let path = Path::new("/dev/zero");
        if !path.exists() {
            return;
        }

        // /dev/zero reports a length of 0 via stat but produces infinite
        // data on read; a `metadata.len()` pre-check alone would let this
        // through. The bounded reader must reject it without hanging.
        let result = read_bounded_text_file(path, 1024);

        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
