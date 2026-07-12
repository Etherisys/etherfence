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
    // Checked via `fs::metadata` before `File::open` (rather than via
    // `File::open` + `File::metadata`) so that non-regular paths are
    // rejected with a consistent `InvalidInput` error on every platform.
    // On Windows, `File::open`-ing a directory can itself fail with a
    // platform-specific error (e.g. permission denied) before an
    // `is_file()` check on the opened handle is ever reached.
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        ));
    }

    let file = fs::File::open(path)?;
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

/// Opens `path` for reading, refusing to follow a symlink at the final
/// path component. On Unix this is enforced atomically by the kernel via
/// `O_NOFOLLOW` — mirrors `etherfence-setup::trust`'s `open_no_follow`.
/// There is no portable `O_NOFOLLOW` equivalent on Windows; there this
/// performs a plain open and relies on the post-read identity check in
/// `read_bounded_text_file_no_follow` to detect a swapped file after the
/// fact.
fn open_no_follow(path: &Path) -> io::Result<fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // O_NOFOLLOW. Value is the same across all Linux architectures
        // (the only Unix target in this project's CI matrix); avoided
        // pulling in the `libc` crate for a single constant.
        const O_NOFOLLOW: i32 = 0o400_000;
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW)
            .open(path)
    }
    #[cfg(not(unix))]
    {
        fs::File::open(path)
    }
}

/// Like [`read_bounded_text_file`], but additionally refuses to follow a
/// symlink at `path`: a pre-open `symlink_metadata` check rejects a
/// symlink outright, the open itself refuses to follow one at the kernel
/// level on Unix (`O_NOFOLLOW`, closing the race between the check and
/// the open), and the opened file's identity is re-validated against a
/// fresh path-based check after the read completes (catching a
/// replacement that happens mid-read). Used for files where silently
/// following a swapped symlink would be misleading rather than merely a
/// containment concern — currently the v1.4.0 `--baseline` file read.
pub fn read_bounded_text_file_no_follow(path: &Path, max_bytes: u64) -> io::Result<String> {
    let pre = fs::symlink_metadata(path)?;
    if pre.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is a symlink; refusing to follow it", path.display()),
        ));
    }
    if !pre.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        ));
    }

    let file = open_no_follow(path)?;
    let mut handle = same_file::Handle::from_file(file)?;
    if !handle.as_file().metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        ));
    }

    let read_limit = max_bytes.saturating_add(1);
    let mut buf = Vec::new();
    handle
        .as_file_mut()
        .take(read_limit)
        .read_to_end(&mut buf)?;

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

    // Re-check both the lexical path (in case it was replaced with a
    // symlink or non-regular file while the read was in progress) and
    // file identity (in case a same-named replacement file coincidentally
    // matches) before trusting the bytes just read.
    let post = fs::symlink_metadata(path)?;
    if post.file_type().is_symlink() || !post.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} changed identity while being read", path.display()),
        ));
    }
    let post_handle = same_file::Handle::from_path(path)?;
    if handle != post_handle {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} was replaced while being read", path.display()),
        ));
    }

    String::from_utf8(buf).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("file {} is not valid UTF-8", path.display()),
        )
    })
}

/// MCP config read support level for a client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReadSupport {
    /// Full MCP server parsing from config files.
    Full,
    /// Config file detected but MCP parsing not yet implemented.
    PresenceOnly,
    /// Config format not supported.
    Unsupported,
}

/// MCP config write support level for a client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WriteSupportKind {
    Supported,
    AdvisoryOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigFormat {
    Json,
    Toml,
    Yaml,
    PresenceOnly,
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
    Hermes,
    Antigravity,
    OpenCode,
    Cline,
    RooCode,
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
            Self::Hermes => "Hermes",
            Self::Antigravity => "Antigravity",
            Self::OpenCode => "OpenCode",
            Self::Cline => "Cline",
            Self::RooCode => "Roo Code",
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
            Self::Hermes => "hermes",
            Self::Antigravity => "antigravity",
            Self::OpenCode => "open-code",
            Self::Cline => "cline",
            Self::RooCode => "roo-code",
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

/// Fixed, deterministic posture grade derived from displayed active findings.
/// This is advisory presentation metadata; it never changes scan semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PostureGrade {
    A,
    B,
    C,
    D,
    F,
}

impl PostureGrade {
    pub fn from_score(score: u8) -> Self {
        match score {
            90..=100 => Self::A,
            75..=89 => Self::B,
            55..=74 => Self::C,
            30..=54 => Self::D,
            _ => Self::F,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::B => "B",
            Self::C => "C",
            Self::D => "D",
            Self::F => "F",
        }
    }
}

/// Explicit selection context for advisory posture. The score is intentionally
/// not an unfiltered host-wide security score.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostureScope {
    /// Stable token describing the pre-existing report selection flow.
    pub finding_selection: String,
    /// Effective severity threshold applied to findings before posture derives.
    pub severity_threshold: Severity,
    /// Stable token describing treatment of historical baseline evidence.
    pub resolved_baseline_findings: String,
}

impl PostureScope {
    pub fn displayed_active(severity_threshold: Severity) -> Self {
        Self {
            finding_selection: "displayed-active-findings".to_string(),
            severity_threshold,
            resolved_baseline_findings: "excluded".to_string(),
        }
    }

    pub fn human_label(&self) -> String {
        format!(
            "Displayed active findings at severity threshold: {}",
            self.severity_threshold.label().to_lowercase()
        )
    }
}

/// A selected active finding in the concise posture experience.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostureRisk {
    pub finding_id: String,
    pub severity: Severity,
    pub title: String,
    pub agent: AgentKind,
    pub target: String,
    pub fingerprint: String,
    pub why_this_matters: String,
}

/// An existing finding recommendation linked to a posture priority risk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecommendedAction {
    pub finding_id: String,
    pub recommendation: String,
}

/// Deterministic, advisory scan posture derived from displayed active findings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostureSummary {
    pub scope: PostureScope,
    pub score: u8,
    pub grade: PostureGrade,
    pub assessment: String,
    pub active_findings: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub priority_risks: Vec<PostureRisk>,
    pub recommended_actions: Vec<RecommendedAction>,
}

impl PostureSummary {
    /// Derives posture after the caller's established finding-selection flow.
    /// Resolved baseline entries remain report evidence but are historical and
    /// therefore never lower the score or consume a priority slot.
    pub fn from_findings(findings: &[Finding], severity_threshold: Severity) -> Self {
        let mut active: Vec<&Finding> = findings
            .iter()
            .filter(|finding| finding.baseline_status != BaselineStatus::Resolved)
            .collect();
        let high = active
            .iter()
            .filter(|finding| finding.severity == Severity::High)
            .count();
        let medium = active
            .iter()
            .filter(|finding| finding.severity == Severity::Medium)
            .count();
        let low = active
            .iter()
            .filter(|finding| finding.severity == Severity::Low)
            .count();
        let info = active
            .iter()
            .filter(|finding| finding.severity == Severity::Info)
            .count();
        let score = (100_i32 - (25 * high as i32) - (10 * medium as i32) - (2 * low as i32))
            .clamp(0, 100) as u8;
        let grade = PostureGrade::from_score(score);

        active.sort_by(|left, right| {
            right
                .severity
                .cmp(&left.severity)
                .then_with(|| left.id.cmp(&right.id))
                .then_with(|| left.target.cmp(&right.target))
                .then_with(|| left.agent.key().cmp(right.agent.key()))
                .then_with(|| left.fingerprint.cmp(&right.fingerprint))
        });
        let priority_risks: Vec<PostureRisk> = active
            .iter()
            .filter(|finding| finding.severity != Severity::Info)
            .take(3)
            .map(|finding| PostureRisk {
                finding_id: finding.id.clone(),
                severity: finding.severity,
                title: finding.title.clone(),
                agent: finding.agent,
                target: finding.target.clone(),
                fingerprint: finding.fingerprint.clone(),
                why_this_matters: finding.impact.clone(),
            })
            .collect();
        let recommended_actions = active
            .iter()
            .filter(|finding| finding.severity != Severity::Info)
            .take(3)
            .map(|finding| RecommendedAction {
                finding_id: finding.id.clone(),
                recommendation: finding.recommendation.clone(),
            })
            .collect();
        let assessment = if high == 0 && medium == 0 && low == 0 {
            "No active scored findings are displayed. This is not proof that the host is secure."
                .to_string()
        } else {
            match grade {
                PostureGrade::A => {
                    "Posture risks are limited, but findings still need review.".to_string()
                }
                PostureGrade::B => "Review findings to improve posture.".to_string(),
                PostureGrade::C => "Meaningful posture risks need review.".to_string(),
                PostureGrade::D => "High-priority posture risks need prompt review.".to_string(),
                PostureGrade::F => {
                    "Multiple significant posture risks need prompt review.".to_string()
                }
            }
        };

        Self {
            scope: PostureScope::displayed_active(severity_threshold),
            score,
            grade,
            assessment,
            active_findings: active.len(),
            high,
            medium,
            low,
            info,
            priority_risks,
            recommended_actions,
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

// ── Protection Coverage (v1.7.2) ───────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    /// Server is in the agent's allowed_mcp_servers list.
    Protected,
    /// Server is NOT in the agent's allowed_mcp_servers list.
    Unprotected,
    /// No [agents.<name>] section exists for this agent in the policy.
    NoPolicyForAgent,
    /// Agent section exists but allowed_mcp_servers is empty (implicit allow-all).
    EmptyAllowlist,
    /// Coverage not applicable (e.g., Tirith inventory items).
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerCoverage {
    pub agent: AgentKind,
    pub server_name: String,
    pub status: CoverageStatus,
    pub config_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectionCoverage {
    pub total_servers: usize,
    pub protected: usize,
    pub unprotected: usize,
    pub no_policy_for_agent: usize,
    pub empty_allowlist: usize,
    pub not_applicable: usize,
    pub servers: Vec<ServerCoverage>,
}

// ───────────────────────────────────────────────────────────────────────

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
    pub posture: Option<PostureSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline: Option<BaselineComparison>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protection_coverage: Option<ProtectionCoverage>,
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

    #[test]
    fn posture_score_grade_and_priority_are_deterministic() {
        let mut zeta = sample_finding(vec!["zeta".to_string()]);
        zeta.id = "EF-Z-001".to_string();
        zeta.target = "zeta".to_string();
        zeta.refresh_fingerprint();
        let mut alpha = sample_finding(vec!["alpha".to_string()]);
        alpha.id = "EF-A-001".to_string();
        alpha.target = "alpha".to_string();
        alpha.refresh_fingerprint();
        let mut medium = sample_finding(vec!["medium".to_string()]);
        medium.id = "EF-M-001".to_string();
        medium.severity = Severity::Medium;
        medium.refresh_fingerprint();
        let posture = PostureSummary::from_findings(&[zeta, medium, alpha], Severity::Info);

        assert_eq!(posture.score, 40);
        assert_eq!(posture.grade, PostureGrade::D);
        assert_eq!(posture.priority_risks.len(), 3);
        assert_eq!(posture.priority_risks[0].finding_id, "EF-A-001");
        assert_eq!(posture.priority_risks[1].finding_id, "EF-Z-001");
        assert_eq!(posture.recommended_actions[0].finding_id, "EF-A-001");
    }

    #[test]
    fn posture_excludes_resolved_and_clamps_score() {
        let mut resolved = sample_finding(vec!["resolved".to_string()]);
        resolved.baseline_status = BaselineStatus::Resolved;
        let active: Vec<Finding> = (0..5)
            .map(|index| {
                let mut finding = sample_finding(vec![format!("active-{index}")]);
                finding.id = format!("EF-A-{index:03}");
                finding.refresh_fingerprint();
                finding
            })
            .collect();
        let mut findings = active;
        findings.push(resolved);
        let posture = PostureSummary::from_findings(&findings, Severity::Info);

        assert_eq!(posture.score, 0);
        assert_eq!(posture.grade, PostureGrade::F);
        assert_eq!(posture.active_findings, 5);
        assert_eq!(posture.high, 5);
        assert_eq!(posture.priority_risks.len(), 3);
        assert!(posture
            .priority_risks
            .iter()
            .all(|risk| risk.finding_id != "EF-MCP-001"));
    }

    #[test]
    fn posture_no_scored_findings_is_a_grade() {
        let mut info = sample_finding(vec!["info".to_string()]);
        info.severity = Severity::Info;
        info.refresh_fingerprint();
        let posture = PostureSummary::from_findings(&[info], Severity::Info);

        assert_eq!(posture.score, 100);
        assert_eq!(posture.grade, PostureGrade::A);
        assert!(posture.assessment.contains("not proof"));
        assert!(posture.priority_risks.is_empty());
        assert!(posture.recommended_actions.is_empty());
    }

    #[test]
    fn posture_grade_boundaries_are_exact() {
        let cases = [
            (100, PostureGrade::A),
            (90, PostureGrade::A),
            (89, PostureGrade::B),
            (75, PostureGrade::B),
            (74, PostureGrade::C),
            (55, PostureGrade::C),
            (54, PostureGrade::D),
            (30, PostureGrade::D),
            (29, PostureGrade::F),
            (0, PostureGrade::F),
        ];

        for (score, expected_grade) in cases {
            assert_eq!(
                PostureGrade::from_score(score),
                expected_grade,
                "score={score}"
            );
        }
    }

    #[test]
    fn posture_scope_records_the_effective_display_threshold() {
        let posture = PostureSummary::from_findings(&[], Severity::High);

        assert_eq!(posture.scope.finding_selection, "displayed-active-findings");
        assert_eq!(posture.scope.severity_threshold, Severity::High);
        assert_eq!(posture.scope.resolved_baseline_findings, "excluded");
        assert_eq!(
            posture.scope.human_label(),
            "Displayed active findings at severity threshold: high"
        );
    }

    #[test]
    fn posture_repeated_input_has_identical_priority_and_action_order() {
        let mut first = sample_finding(vec!["first".to_string()]);
        first.id = "EF-B-001".to_string();
        first.target = "first".to_string();
        first.refresh_fingerprint();
        let mut second = sample_finding(vec!["second".to_string()]);
        second.id = "EF-A-001".to_string();
        second.target = "second".to_string();
        second.refresh_fingerprint();
        let findings = vec![first, second];

        let initial = PostureSummary::from_findings(&findings, Severity::Info);
        let repeated = PostureSummary::from_findings(&findings, Severity::Info);

        assert_eq!(initial.priority_risks, repeated.priority_risks);
        assert_eq!(initial.recommended_actions, repeated.recommended_actions);
        assert_eq!(
            initial
                .priority_risks
                .iter()
                .map(|risk| risk.finding_id.as_str())
                .collect::<Vec<_>>(),
            vec!["EF-A-001", "EF-B-001"]
        );
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

    #[test]
    fn read_bounded_text_file_no_follow_accepts_a_regular_file() {
        let path = write_temp_file("no-follow-regular", b"hello");
        let result = read_bounded_text_file_no_follow(&path, 1024);
        fs::remove_file(&path).ok();
        assert_eq!(result.unwrap(), "hello");
    }

    #[cfg(unix)]
    #[test]
    fn read_bounded_text_file_no_follow_rejects_a_symlink_to_a_valid_file() {
        let target = write_temp_file("no-follow-symlink-target", b"hello");
        let link = target.with_extension("link");
        std::os::unix::fs::symlink(&target, &link).expect("create symlink");

        let result = read_bounded_text_file_no_follow(&link, 1024);

        fs::remove_file(&link).ok();
        fs::remove_file(&target).ok();
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[cfg(unix)]
    #[test]
    fn read_bounded_text_file_no_follow_rejects_a_symlink_to_a_directory() {
        let dir = std::env::temp_dir();
        let link = dir.join(format!(
            "etherfence-core-test-no-follow-dir-link-{}",
            std::process::id()
        ));
        let _ = fs::remove_file(&link);
        std::os::unix::fs::symlink(&dir, &link).expect("create symlink to directory");

        let result = read_bounded_text_file_no_follow(&link, 1024);

        fs::remove_file(&link).ok();
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[cfg(unix)]
    #[test]
    fn read_bounded_text_file_no_follow_rejects_a_broken_symlink() {
        let dir = std::env::temp_dir();
        let missing = dir.join(format!(
            "etherfence-core-test-no-follow-missing-target-{}",
            std::process::id()
        ));
        let link = dir.join(format!(
            "etherfence-core-test-no-follow-broken-link-{}",
            std::process::id()
        ));
        let _ = fs::remove_file(&link);
        std::os::unix::fs::symlink(&missing, &link).expect("create broken symlink");

        let result = read_bounded_text_file_no_follow(&link, 1024);

        fs::remove_file(&link).ok();
        assert!(result.is_err());
    }

    #[test]
    fn read_bounded_text_file_no_follow_rejects_a_directory() {
        let dir = std::env::temp_dir();
        let result = read_bounded_text_file_no_follow(&dir, 1024);
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
