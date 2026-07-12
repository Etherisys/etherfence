//! Interactive setup wizard — state machine, package pinning logic, and
//! plan building (v1.6.0+).
//!
//! Every function here is pure over already-discovered configuration data.
//! Nothing here starts a process, opens a network connection, or invokes any
//! MCP protocol method.

use crate::classification::{self, CapabilityLabel};
use crate::trust::{PackageRunner as TrustPackageRunner, TrustAssessment, VersionExpressionKind};
use crate::{
    generated_policy_template, sanitize_policy_identifier, SetupAction, SetupActionKind,
    SetupDetection, SetupServer,
};
use etherfence_core::McpServer;
use serde::Serialize;
use std::collections::HashMap;

// -----------------------------------------------------------------------
// Package version status (wizard-level, extends VersionExpressionKind
// with NotApplicable for non-runner invocations)
// -----------------------------------------------------------------------

/// Package version pinning status for the interactive wizard.
///
/// Adds `NotApplicable` beyond the trust module's `VersionExpressionKind`
/// so non-runner invocations (bare executables, remote URLs) are explicitly
/// distinguished from an assessed-but-unpinned state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PackageVersionStatus {
    /// An exact version is already pinned (e.g. `pkg@1.2.3`, `pkg==1.2.3`).
    ExactPin,
    /// No version was specified at all (e.g. bare `uvx pkg`).
    Omitted,
    /// A mutable tag was used (e.g. `pkg@latest`, `pkg@beta`).
    MutableTag,
    /// A range specifier was used (e.g. `pkg>=1.0`, `pkg^1.0`).
    Range,
    /// The version expression is not recognized or could not be parsed.
    Ambiguous,
    /// No package runner was detected — invocation is not applicable.
    NotApplicable,
}

impl PackageVersionStatus {
    /// Returns `true` when the current pinning is acceptable and does not
    /// require wizard intervention.
    pub fn is_acceptable(self) -> bool {
        matches!(
            self,
            PackageVersionStatus::ExactPin | PackageVersionStatus::NotApplicable
        )
    }

    /// Returns `true` when the wizard should prompt the user to pin a
    /// version for this server.
    pub fn needs_pinning(self) -> bool {
        matches!(
            self,
            PackageVersionStatus::Omitted
                | PackageVersionStatus::MutableTag
                | PackageVersionStatus::Range
                | PackageVersionStatus::Ambiguous
        )
    }

    pub fn human_label(self) -> &'static str {
        match self {
            PackageVersionStatus::ExactPin => "exactly pinned",
            PackageVersionStatus::Omitted => "omitted",
            PackageVersionStatus::MutableTag => "mutable tag",
            PackageVersionStatus::Range => "version range",
            PackageVersionStatus::Ambiguous => "ambiguous",
            PackageVersionStatus::NotApplicable => "not applicable",
        }
    }
}

impl From<VersionExpressionKind> for PackageVersionStatus {
    fn from(kind: VersionExpressionKind) -> Self {
        match kind {
            VersionExpressionKind::ExactlyPinned => PackageVersionStatus::ExactPin,
            VersionExpressionKind::Omitted => PackageVersionStatus::Omitted,
            VersionExpressionKind::MutableTag => PackageVersionStatus::MutableTag,
            VersionExpressionKind::VersionRange => PackageVersionStatus::Range,
            VersionExpressionKind::UnsupportedOrAmbiguous => PackageVersionStatus::Ambiguous,
        }
    }
}

// -----------------------------------------------------------------------
// Wizard package runner
// -----------------------------------------------------------------------

/// A recognized package runner for the interactive wizard.
///
/// Mirrors `trust::PackageRunner` but uses `Pipx` instead of `PipxRun`
/// since the wizard tracks the launcher command (`pipx`) rather than the
/// subcommand form (`pipx run`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WizardPackageRunner {
    Npx,
    Uvx,
    Pipx,
}

impl WizardPackageRunner {
    fn runner_token(self) -> &'static str {
        match self {
            WizardPackageRunner::Npx => "npx",
            WizardPackageRunner::Uvx => "uvx",
            WizardPackageRunner::Pipx => "pipx",
        }
    }
}

impl From<TrustPackageRunner> for WizardPackageRunner {
    fn from(r: TrustPackageRunner) -> Self {
        match r {
            TrustPackageRunner::Npx => WizardPackageRunner::Npx,
            TrustPackageRunner::Uvx => WizardPackageRunner::Uvx,
            TrustPackageRunner::PipxRun => WizardPackageRunner::Pipx,
        }
    }
}

// -----------------------------------------------------------------------
// Pinning change
// -----------------------------------------------------------------------

/// A proposed pinning change for one MCP server's package-runner invocation.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PinningChange {
    /// Owning agent display name; filled by `build_wizard_plan` (empty when
    /// produced by a direct `resolve_pinning` call).
    #[serde(default)]
    pub agent: String,
    /// Owning config display path; filled by `build_wizard_plan` (empty when
    /// produced by a direct `resolve_pinning` call).
    #[serde(default)]
    pub config_path: String,
    pub server_name: String,
    pub runner: Option<WizardPackageRunner>,
    pub package_identity: Option<String>,
    pub current_status: PackageVersionStatus,
    pub proposed_version: Option<String>,
    /// The full pinned argument list that replaces the server's current args.
    pub pinned_args: Vec<String>,
    /// Human-readable explanation of the change.
    pub rationale: String,
}

// -----------------------------------------------------------------------
// Policy types, entries, and trust overrides
// -----------------------------------------------------------------------

/// The kind of MCP proxy policy to generate for a server.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyType {
    /// Full deny-all quarantine policy generated via `generated_policy_template`.
    DenyAllQuarantine,
    /// Curated policy derived from capability classification.
    Curated,
    /// Deny-all with a custom tool allowlist.
    CustomToolAllowlist(Vec<String>),
}

/// One generated and validated MCP proxy policy file, ready for writing.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyEntry {
    /// Owning agent display name.
    pub agent: String,
    /// Owning config display path.
    pub config_path: String,
    pub server_name: String,
    pub policy_type: PolicyType,
    /// The full validated TOML content.
    pub content: String,
    /// Relative or absolute path for the policy file.
    pub path: String,
}

/// A user-initiated trust override acknowledging one or more raised
/// indicators.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustOverride {
    pub agent: String,
    pub config_path: String,
    pub server_name: String,
    pub accepted_indicator_ids: Vec<String>,
    pub rationale: String,
}

// -----------------------------------------------------------------------
// Server identity and user selections (marshalled from wizard prompts)
// -----------------------------------------------------------------------

/// The full identity of one MCP server within one configuration file.
///
/// Two configuration files of the same client can define a server with
/// the same name (e.g. `~/.claude.json` and `~/.claude/settings.json`);
/// every selection, pin, policy, trust override, preview lookup, and
/// apply directive must therefore be scoped by all three fields, never by
/// `agent:server_name` alone.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WizardServerId {
    pub agent: String,
    pub config_path: String,
    pub server_name: String,
}

/// User choices gathered during the interactive wizard session.
#[derive(Debug, Clone, Default)]
pub struct WizardSelections {
    /// Servers selected for processing.
    pub selected: Vec<WizardServerId>,
    /// Proposed version pins per selected server.
    pub version_pins: HashMap<WizardServerId, String>,
    /// Policy type per selected server.
    pub policy_types: HashMap<WizardServerId, PolicyType>,
    /// Trust overrides per selected server (indicator IDs to accept).
    pub trust_overrides: HashMap<WizardServerId, Vec<String>>,
}

// -----------------------------------------------------------------------
// Selected server (intermediate representation)
// -----------------------------------------------------------------------

/// A flattened, user-selected server with its resolved pinning metadata
/// and the invocation state the user reviewed. Apply must verify the
/// expected state still holds before writing anything.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SelectedServer {
    pub agent: String,
    pub config_path: String,
    pub server_name: String,
    pub trust_assessment: TrustAssessment,
    pub existing_status: PackageVersionStatus,
    pub runner: Option<WizardPackageRunner>,
    pub package_identity: Option<String>,
    /// The command the user reviewed. Kept out of serialized output (raw
    /// invocation text is deliberately never persisted); enforced at
    /// apply time so post-preview drift aborts the whole operation.
    #[serde(skip)]
    pub expected_command: Option<String>,
    /// The argument list the user reviewed (see `expected_command`).
    #[serde(skip)]
    pub expected_args: Vec<String>,
    /// The remote URL the user reviewed (see `expected_command`).
    #[serde(skip)]
    pub expected_url: Option<String>,
    /// SHA-256 of the server's complete canonical JSON entry as read at
    /// detection time. Binds the plan to every server-specific field the
    /// user reviewed — including `env` — not just command/args/url.
    #[serde(skip)]
    pub expected_entry_sha256: String,
}

impl SelectedServer {
    /// This server's full identity.
    pub fn id(&self) -> WizardServerId {
        WizardServerId {
            agent: self.agent.clone(),
            config_path: self.config_path.clone(),
            server_name: self.server_name.clone(),
        }
    }
}

// -----------------------------------------------------------------------
// Wizard plan
// -----------------------------------------------------------------------

/// The complete plan produced by `build_wizard_plan` after the user makes
/// their selections.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WizardPlan {
    pub root: String,
    pub detections: Vec<SetupDetection>,
    pub selected_servers: Vec<SelectedServer>,
    pub pinning_changes: Vec<PinningChange>,
    pub policies: Vec<PolicyEntry>,
    pub actions: Vec<SetupAction>,
    pub trust_overrides: Vec<TrustOverride>,
}

// =======================================================================
// Version-status extraction helpers
// =======================================================================

/// Recognised npx boolean flags that precede the package argument.
const NPX_BOOLEAN_FLAGS: &[&str] = &["-y", "--yes"];
/// Recognised npx value-takes-argument flags.
const NPX_VALUE_FLAGS: &[&str] = &["--package"];

/// Resolves the npx package argument similarly to `classification::resolve_package_arg`.
///
/// Fails closed (`None`) when an unrecognised option appears before the
/// package token: treating an unknown flag as the package identity would
/// let the pin rewriter corrupt the invocation.
fn resolve_npx_token(args: &[String]) -> Option<&str> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if NPX_BOOLEAN_FLAGS.contains(&arg.as_str()) {
            continue;
        }
        if let Some(value) = arg.strip_prefix("--package=") {
            return Some(value);
        }
        if NPX_VALUE_FLAGS.contains(&arg.as_str()) {
            return iter.next().map(String::as_str);
        }
        if arg.starts_with('-') {
            // Unknown pre-package option: the package position is
            // ambiguous, so refuse to guess.
            return None;
        }
        return Some(arg.as_str());
    }
    None
}

/// Resolves the uvx package token: `--from <spec>` or positional arg.
fn resolve_uvx_token(args: &[String]) -> Option<&str> {
    let first = args.first()?;
    if first == "--from" {
        return args.get(1).map(String::as_str);
    }
    if first.starts_with('-') {
        return None;
    }
    Some(first.as_str())
}

/// Resolves the pipx package token: `--spec <spec>` or positional arg.
fn resolve_pipx_token(args: &[String]) -> Option<&str> {
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

/// Split an npx `[@scope/]pkg[@version]` token into (identity, version).
fn split_npx_package_identity(token: &str) -> (&str, Option<&str>) {
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

/// Closed set of npm dist-tags treated as mutable.
const MUTABLE_NPM_TAGS: &[&str] = &["latest", "next", "beta", "alpha", "canary", "rc"];

/// Check if a version expression looks like an npm range.
fn looks_like_npm_range(version: &str) -> bool {
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

/// Returns true when the version string looks like an exact semver.
fn looks_like_exact_version(version: &str) -> bool {
    matches!(version.chars().next(), Some(c) if c.is_ascii_digit())
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '+')
}

/// Classifies an npm-style version suffix.
fn classify_npm_version(version: Option<&str>) -> PackageVersionStatus {
    match version {
        None => PackageVersionStatus::Omitted,
        Some("") => PackageVersionStatus::Ambiguous,
        Some(v) if MUTABLE_NPM_TAGS.contains(&v) => PackageVersionStatus::MutableTag,
        Some(v) if looks_like_npm_range(v) => PackageVersionStatus::Range,
        Some(v) if looks_like_exact_version(v) => PackageVersionStatus::ExactPin,
        Some(_) => PackageVersionStatus::Ambiguous,
    }
}

/// Check if a version string is a valid PEP 440 exact version identifier.
fn is_exact_pep440_version(version: &str) -> bool {
    if version.is_empty() || version.contains(['*', ',', ';', ' ']) {
        return false;
    }
    matches!(version.chars().next(), Some(c) if c.is_ascii_digit())
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+'))
}

/// Classifies a PEP 440 style token into (package_identity, status).
fn classify_pep440(token: &str) -> (&str, PackageVersionStatus) {
    if let Some(idx) = token.find("===") {
        let package = &token[..idx];
        return (package, PackageVersionStatus::Ambiguous);
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
                PackageVersionStatus::Ambiguous
            } else {
                PackageVersionStatus::Range
            };
            return (package, kind);
        }
    }
    (token, PackageVersionStatus::Omitted)
}

fn classify_pep440_rest(rest: &str, op: &str) -> PackageVersionStatus {
    if rest.is_empty() {
        return PackageVersionStatus::Ambiguous;
    }
    if rest.contains(',') || rest.contains(';') {
        return PackageVersionStatus::Range;
    }
    if op != "==" {
        return PackageVersionStatus::Range;
    }
    if is_exact_pep440_version(rest) {
        PackageVersionStatus::ExactPin
    } else if rest.contains('*') {
        PackageVersionStatus::Range
    } else {
        PackageVersionStatus::Ambiguous
    }
}

// =======================================================================
// Public API
// =======================================================================

/// Extracts the package version status from a command + argument list.
///
/// Returns `(runner, package_identity, status)`. When the command is not
/// a recognised package runner (`npx`, `uvx`, `pipx run`), returns
/// `(None, None, NotApplicable)`.
pub fn extract_package_version(
    command: &str,
    args: &[String],
) -> (
    Option<WizardPackageRunner>,
    Option<String>,
    PackageVersionStatus,
) {
    let name = classification::launcher_name(command);
    let runner = match name {
        "npx" => Some(TrustPackageRunner::Npx),
        "uvx" => Some(TrustPackageRunner::Uvx),
        "pipx" if args.first().map(String::as_str) == Some("run") => {
            Some(TrustPackageRunner::PipxRun)
        }
        _ => None,
    };

    let Some(runner) = runner else {
        return (None, None, PackageVersionStatus::NotApplicable);
    };

    let wizard_runner: WizardPackageRunner = runner.into();

    let token = match runner {
        TrustPackageRunner::Npx => resolve_npx_token(args),
        TrustPackageRunner::Uvx => resolve_uvx_token(args),
        TrustPackageRunner::PipxRun => resolve_pipx_token(args),
    };

    let Some(token) = token.filter(|t| !t.is_empty()) else {
        return (Some(wizard_runner), None, PackageVersionStatus::Ambiguous);
    };

    let (package, status) = match runner {
        TrustPackageRunner::Npx => {
            let (pkg, version) = split_npx_package_identity(token);
            (pkg.to_string(), classify_npm_version(version))
        }
        TrustPackageRunner::Uvx | TrustPackageRunner::PipxRun => {
            let (pkg, kind) = classify_pep440(token);
            (pkg.to_string(), kind)
        }
    };

    if package.is_empty() {
        return (Some(wizard_runner), None, PackageVersionStatus::Ambiguous);
    }

    (Some(wizard_runner), Some(package), status)
}

/// Resolves a pinning change for a server given a proposed version.
///
/// Returns `None` when the server does not use a recognised runner or
/// when pinning is not applicable.
pub fn resolve_pinning(server: &McpServer, proposed_version: &str) -> Option<PinningChange> {
    let command = server.command.as_deref()?;
    let (runner, package_identity, current_status) = extract_package_version(command, &server.args);

    if !current_status.needs_pinning() && current_status != PackageVersionStatus::ExactPin {
        // NotApplicable — no pinning possible.
        return None;
    }

    let runner = runner?;
    // Without a confidently resolved package identity there is nothing
    // safe to rewrite — fail closed rather than guess.
    let package = package_identity.as_deref()?;

    let pinned_args = build_pinned_args(&runner, &server.args, package, proposed_version)?;

    let rationale = if current_status == PackageVersionStatus::ExactPin {
        format!(
            "{} invocation for '{}' already has an exact pin ({}); replacing with {}",
            runner.runner_token(),
            package,
            extract_existing_version(&runner, &server.args)
                .unwrap_or_else(|| "<unknown>".to_string()),
            proposed_version
        )
    } else {
        format!(
            "{} invocation for '{}' has {} version ({});
             pinning to exact version {}",
            runner.runner_token(),
            package,
            current_status.human_label(),
            extract_existing_version(&runner, &server.args).unwrap_or_else(|| "<none>".to_string()),
            proposed_version
        )
    };

    Some(PinningChange {
        agent: String::new(),
        config_path: String::new(),
        server_name: server.name.clone(),
        runner: Some(runner),
        package_identity,
        current_status,
        proposed_version: Some(proposed_version.to_string()),
        pinned_args,
        rationale,
    })
}

/// Extracts the existing version expression from a server's args for
/// display purposes.
fn extract_existing_version(runner: &WizardPackageRunner, args: &[String]) -> Option<String> {
    let trust_runner = match runner {
        WizardPackageRunner::Npx => TrustPackageRunner::Npx,
        WizardPackageRunner::Uvx => TrustPackageRunner::Uvx,
        WizardPackageRunner::Pipx => TrustPackageRunner::PipxRun,
    };

    let token = match trust_runner {
        TrustPackageRunner::Npx => resolve_npx_token(args)?,
        TrustPackageRunner::Uvx => resolve_uvx_token(args)?,
        TrustPackageRunner::PipxRun => resolve_pipx_token(args)?,
    };

    match runner {
        WizardPackageRunner::Npx => {
            let (_, version) = split_npx_package_identity(token);
            version.map(ToString::to_string)
        }
        WizardPackageRunner::Uvx | WizardPackageRunner::Pipx => {
            let (_, rest) = split_pep440_op(token);
            rest.map(ToString::to_string)
        }
    }
}

/// Splits a token at the first PEP 440 operator into (package, version_part).
fn split_pep440_op(token: &str) -> (&str, Option<&str>) {
    // Handle @ separator (npm-style) — uvx can use this too.
    if let Some(idx) = token.rfind('@') {
        if idx > 0 {
            return (&token[..idx], Some(&token[idx + 1..]));
        }
    }
    const TWO_CHAR_OPS: &[&str] = &["===", "==", ">=", "<=", "!=", "~="];
    for op in TWO_CHAR_OPS {
        if let Some(idx) = token.find(op) {
            return (&token[..idx], Some(&token[idx + op.len()..]));
        }
    }
    for op in &['>', '<'] {
        if let Some(idx) = token.find(*op) {
            return (&token[..idx], Some(&token[idx + 1..]));
        }
    }
    (token, None)
}

/// Builds the pinned argument list for a runner, preserving non-version
/// arguments (tool name, launcher flags, etc).
///
/// Returns `None` when the package position cannot be identified with
/// certainty (unknown pre-package options, no package token at all) —
/// rewriting anything else would corrupt the invocation.
fn build_pinned_args(
    runner: &WizardPackageRunner,
    original_args: &[String],
    package_identity: &str,
    proposed_version: &str,
) -> Option<Vec<String>> {
    match runner {
        WizardPackageRunner::Npx => {
            build_npx_pinned_args(original_args, package_identity, proposed_version)
        }
        WizardPackageRunner::Uvx => {
            build_uvx_pinned_args(original_args, package_identity, proposed_version)
        }
        WizardPackageRunner::Pipx => {
            build_pipx_pinned_args(original_args, package_identity, proposed_version)
        }
    }
}

/// Build pinned args for npx. Replaces the package spec's version portion.
fn build_npx_pinned_args(
    original_args: &[String],
    _package_identity: &str,
    proposed_version: &str,
) -> Option<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    let mut saw_package = false;

    let mut iter = original_args.iter();
    while let Some(arg) = iter.next() {
        if saw_package {
            // Remaining args after the package token stay as-is.
            out.push(arg.clone());
            continue;
        }

        // Pass through the launcher flags we know about.
        if NPX_BOOLEAN_FLAGS.contains(&arg.as_str()) {
            out.push(arg.clone());
            continue;
        }
        if let Some(value) = arg.strip_prefix("--package=") {
            // Replace the value portion with the pinned version.
            let (pkg, _) = split_npx_package_identity(value);
            out.push(format!("--package={}@{}", pkg, proposed_version));
            saw_package = true;
            continue;
        }
        if NPX_VALUE_FLAGS.contains(&arg.as_str()) {
            out.push(arg.clone());
            let next = iter.next()?;
            let (pkg, _) = split_npx_package_identity(next);
            out.push(format!("{}@{}", pkg, proposed_version));
            saw_package = true;
            continue;
        }
        if arg.starts_with('-') {
            // Unknown pre-package option — the package position is
            // ambiguous; refuse to rewrite.
            return None;
        }

        // This is the package arg — replace with pinned version.
        let (pkg, _) = split_npx_package_identity(arg);
        out.push(format!("{}@{}", pkg, proposed_version));
        saw_package = true;
    }

    saw_package.then_some(out)
}

/// Build pinned args for uvx.
fn build_uvx_pinned_args(
    original_args: &[String],
    _package_identity: &str,
    proposed_version: &str,
) -> Option<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    let mut saw_package = false;

    let mut iter = original_args.iter();
    while let Some(arg) = iter.next() {
        if saw_package {
            out.push(arg.clone());
            continue;
        }

        if arg == "--from" {
            out.push(arg.clone());
            let next = iter.next()?;
            let (pkg, _) = split_pep440_op(next);
            out.push(format!("{}=={}", pkg, proposed_version));
            saw_package = true;
            continue;
        }

        if arg.starts_with('-') {
            // Unknown pre-package option — refuse to guess the package
            // position (mirrors `resolve_uvx_token`).
            return None;
        }

        // First positional — the package spec.
        let (pkg, _) = split_pep440_op(arg);
        out.push(format!("{}=={}", pkg, proposed_version));
        saw_package = true;
    }

    saw_package.then_some(out)
}

/// Build pinned args for pipx run.
fn build_pipx_pinned_args(
    original_args: &[String],
    _package_identity: &str,
    proposed_version: &str,
) -> Option<Vec<String>> {
    let mut out = Vec::new();
    // Pre-args before "run" are kept as-is (though typically there are none).
    let mut after_run = false;
    let mut saw_package = false;

    let mut iter = original_args.iter().peekable();
    while let Some(arg) = iter.next() {
        if !after_run {
            out.push(arg.clone());
            if arg == "run" {
                after_run = true;
            }
            continue;
        }

        if saw_package {
            out.push(arg.clone());
            continue;
        }

        if arg == "--spec" {
            out.push(arg.clone());
            let next = iter.next()?;
            let (pkg, _) = split_pep440_op(next);
            out.push(format!("{}=={}", pkg, proposed_version));
            saw_package = true;
            continue;
        }

        if arg.starts_with('-') {
            // Unknown pre-package option — refuse to guess the package
            // position (mirrors `resolve_pipx_token`).
            return None;
        }

        // First positional after `run` — the package spec.
        let (pkg, _) = split_pep440_op(arg);
        out.push(format!("{}=={}", pkg, proposed_version));
        saw_package = true;
    }

    (after_run && saw_package).then_some(out)
}

/// Extracts trust-assessment-backed version status for a `SetupServer`.
#[allow(dead_code)]
fn status_for_server(server: &SetupServer) -> PackageVersionStatus {
    match server.trust_assessment.invocation.version_expression {
        Some(kind) => PackageVersionStatus::from(kind),
        None => {
            // Fall back to extraction if version_expression wasn't set
            // (e.g. non-runner server).
            let command = ""; // We don't have the raw command here.
            let args: &[String] = &[];
            let (_, _, status) = extract_package_version(command, args);
            status
        }
    }
}

// =======================================================================
// Plan building
// =======================================================================

/// Builds a complete wizard plan from discovery output and user selections.
///
/// For each selected server in `detections`, this function:
///
/// 1. Resolves the current package version status.
/// 2. Builds a `PinningChange` with pinned args for the proposed version.
/// 3. Generates an MCP proxy policy according to the chosen `PolicyType`.
/// 4. Validates every generated policy before including it.
/// 5. Produces `SetupAction` entries for the plan.
///
/// Returns `Err` when a generated policy fails validation.
pub fn build_wizard_plan(
    detections: &[SetupDetection],
    selections: &WizardSelections,
    root: &str,
) -> Result<WizardPlan, String> {
    let mut selected_servers: Vec<SelectedServer> = Vec::new();
    let mut pinning_changes: Vec<PinningChange> = Vec::new();
    let mut policies: Vec<PolicyEntry> = Vec::new();
    let mut actions: Vec<SetupAction> = Vec::new();
    let mut trust_overrides: Vec<TrustOverride> = Vec::new();

    // Reject duplicate selections up front.
    {
        let mut seen: std::collections::HashSet<&WizardServerId> = std::collections::HashSet::new();
        for id in &selections.selected {
            if !seen.insert(id) {
                return Err(format!(
                    "duplicate selection for '{}' in {} ({})",
                    id.server_name, id.config_path, id.agent
                ));
            }
        }
    }

    // Every selection must resolve to exactly one detected server.
    let mut matched: std::collections::HashSet<&WizardServerId> = std::collections::HashSet::new();

    // Collect flat inventory of all servers with their trust assessments.
    for detection in detections {
        for server in &detection.servers {
            let id = WizardServerId {
                agent: detection.agent.clone(),
                config_path: detection.config_path.clone(),
                server_name: server.name.clone(),
            };
            let Some(id) = selections.selected.iter().find(|s| **s == id) else {
                continue;
            };
            matched.insert(id);

            // Eligibility: the plan may only promise changes apply can
            // actually make. Anything else must fail at plan time, never
            // surface as a silent no-op at apply time.
            if server.wrapped {
                return Err(format!(
                    "'{}' in {} is already protected by etherfence mcp-proxy and cannot be selected",
                    server.name, detection.config_path
                ));
            }
            if server.transport != crate::ServerTransport::Stdio {
                return Err(format!(
                    "'{}' in {} is not a local stdio server and cannot be wrapped",
                    server.name, detection.config_path
                ));
            }
            if detection.write_support != crate::WriteSupport::Supported {
                return Err(format!(
                    "'{}' is in advisory-only config {} which EtherFence cannot modify",
                    server.name, detection.config_path
                ));
            }

            // Resolve package version status from the server's real
            // invocation as parsed out of its config file.
            let (runner, package_identity, existing_status) = match server.command.as_deref() {
                Some(command) => extract_package_version(command, &server.args),
                None => (None, None, PackageVersionStatus::NotApplicable),
            };

            // The apply drift gate needs a snapshot of the complete
            // reviewed entry; a selectable server without one means the
            // configuration could not be read consistently at detection.
            let expected_entry_sha256 = server.raw_entry_sha256.clone().ok_or_else(|| {
                format!(
                    "could not snapshot the configuration entry for '{}' in {}; re-run the wizard",
                    server.name, detection.config_path
                )
            })?;

            let sel = SelectedServer {
                agent: detection.agent.clone(),
                config_path: detection.config_path.clone(),
                server_name: server.name.clone(),
                trust_assessment: server.trust_assessment.clone(),
                existing_status,
                runner,
                package_identity,
                expected_command: server.command.clone(),
                expected_args: server.args.clone(),
                expected_url: server.url.clone(),
                expected_entry_sha256,
            };
            selected_servers.push(sel);

            // Pinning change, computed against the server's real command
            // and argument list so the planned rewrite matches what apply
            // will actually mutate. Fail closed instead of silently
            // dropping a pin the user asked for.
            if let Some(version) = selections.version_pins.get(id) {
                let runner = runner.ok_or_else(|| {
                    format!(
                        "cannot pin '{}': no recognised package runner (npx, uvx, pipx run) in its invocation",
                        server.name
                    )
                })?;
                validate_exact_version(runner, version)
                    .map_err(|e| format!("cannot pin '{}': {e}", server.name))?;
                let mcp = McpServer {
                    name: server.name.clone(),
                    command: server.command.clone(),
                    args: server.args.clone(),
                    env: Vec::new(),
                    url: server.url.clone(),
                };
                let mut change = resolve_pinning(&mcp, version).ok_or_else(|| {
                    format!(
                        "cannot pin '{}': its current invocation does not support version pinning",
                        server.name
                    )
                })?;
                change.agent = detection.agent.clone();
                change.config_path = detection.config_path.clone();
                pinning_changes.push(change);
            }

            // Policy generation.
            match selections.policy_types.get(id) {
                Some(PolicyType::DenyAllQuarantine) | None => {
                    let content = generated_policy_template(&server.name)
                        .map_err(|e| format!("failed to generate quarantine policy: {e}"))?;
                    // Validate: parse_mcp_policy also serves as a validation check.
                    etherfence_mcp::parse_mcp_policy(&content).map_err(|e| {
                        format!("policy validation failed for '{}': {e}", server.name)
                    })?;
                    let path = format!(
                        ".etherfence/policies/{}.toml",
                        sanitize_policy_identifier(&server.name)
                    );
                    policies.push(PolicyEntry {
                        agent: detection.agent.clone(),
                        config_path: detection.config_path.clone(),
                        server_name: server.name.clone(),
                        policy_type: PolicyType::DenyAllQuarantine,
                        content,
                        path,
                    });
                }
                Some(PolicyType::Curated) => {
                    let content =
                        generate_curated_policy(&server.name, &server.capabilities.labels)?;
                    etherfence_mcp::parse_mcp_policy(&content).map_err(|e| {
                        format!(
                            "curated policy validation failed for '{}': {e}",
                            server.name
                        )
                    })?;
                    let path = format!(
                        ".etherfence/policies/{}.toml",
                        sanitize_policy_identifier(&server.name)
                    );
                    policies.push(PolicyEntry {
                        agent: detection.agent.clone(),
                        config_path: detection.config_path.clone(),
                        server_name: server.name.clone(),
                        policy_type: PolicyType::Curated,
                        content,
                        path,
                    });
                }
                Some(PolicyType::CustomToolAllowlist(tools)) => {
                    let content = generate_custom_allowlist_policy(&server.name, tools)?;
                    etherfence_mcp::parse_mcp_policy(&content).map_err(|e| {
                        format!(
                            "custom allowlist policy validation failed for '{}': {e}",
                            server.name
                        )
                    })?;
                    let path = format!(
                        ".etherfence/policies/{}.toml",
                        sanitize_policy_identifier(&server.name)
                    );
                    policies.push(PolicyEntry {
                        agent: detection.agent.clone(),
                        config_path: detection.config_path.clone(),
                        server_name: server.name.clone(),
                        policy_type: PolicyType::CustomToolAllowlist(tools.clone()),
                        content,
                        path,
                    });
                }
            }

            // Eligibility was enforced above, so the only plannable
            // action is a wrap.
            actions.push(SetupAction {
                agent: detection.agent.clone(),
                config_path: detection.config_path.clone(),
                server_name: server.name.clone(),
                action: SetupActionKind::Wrap,
                reason: "server selected for wizard processing".to_string(),
            });

            // Trust overrides.
            if let Some(accepted_ids) = selections.trust_overrides.get(id) {
                trust_overrides.push(TrustOverride {
                    agent: detection.agent.clone(),
                    config_path: detection.config_path.clone(),
                    server_name: server.name.clone(),
                    accepted_indicator_ids: accepted_ids.clone(),
                    rationale: "user accepted trust indicators during wizard review".to_string(),
                });
            }
        }
    }

    // Every selection must have matched a detected server; a selection
    // pointing at nothing means the environment changed under the wizard.
    for id in &selections.selected {
        if !matched.contains(id) {
            return Err(format!(
                "selected server '{}' was not found in {} ({}); the configuration may have changed",
                id.server_name, id.config_path, id.agent
            ));
        }
    }

    Ok(WizardPlan {
        root: root.to_string(),
        detections: detections.to_vec(),
        selected_servers,
        pinning_changes,
        policies,
        actions,
        trust_overrides,
    })
}

/// Applies a wizard-built plan selectively: only the servers the plan
/// selected are pinned, given their planned policy, and wrapped. Servers
/// the user skipped — and configs without any selected server — are left
/// untouched. See `crate::apply_selected` for the fail-closed semantics.
pub fn apply_wizard_plan(root: &std::path::Path, plan: &WizardPlan) -> anyhow::Result<()> {
    crate::apply_selected(root, plan)
}

/// Validates that a proposed version string is an exact, immutable version
/// for the given package runner. Rejects mutable tags (`latest`, `beta`),
/// ranges (`^1.2`, `>=2`), and anything ambiguous — the wizard's pinning
/// promise is only meaningful for an exact version.
pub fn validate_exact_version(runner: WizardPackageRunner, version: &str) -> Result<(), String> {
    let version = version.trim();
    if version.is_empty() {
        return Err("version must not be empty".to_string());
    }
    match runner {
        WizardPackageRunner::Npx => {
            if MUTABLE_NPM_TAGS.contains(&version) {
                Err(format!(
                    "'{version}' is a mutable npm dist-tag, not an exact version"
                ))
            } else if looks_like_npm_range(version) {
                Err(format!(
                    "'{version}' is a version range, not an exact version"
                ))
            } else if semver::Version::parse(version).is_err() {
                // npm treats partial versions like `1` or `1.2` as ranges;
                // only a full, valid `major.minor.patch` (with optional
                // prerelease/build metadata) is an immutable exact pin.
                Err(format!(
                    "'{version}' is not a complete exact npm version (expected major.minor.patch, e.g. 1.2.3)"
                ))
            } else if !looks_like_exact_version(version) {
                Err(format!(
                    "'{version}' is not an exact npm version (expected e.g. 1.2.3)"
                ))
            } else {
                Ok(())
            }
        }
        WizardPackageRunner::Uvx | WizardPackageRunner::Pipx => {
            if is_exact_pep440_version(version) {
                Ok(())
            } else {
                Err(format!(
                    "'{version}' is not an exact PEP 440 version (expected e.g. 1.2.3)"
                ))
            }
        }
    }
}

/// Generates a curated policy for a server based on its capability labels.
/// Uses the deny-all template as a starting point and optionally relaxes
/// tool allow rules for safer capabilities.
fn generate_curated_policy(
    server_name: &str,
    labels: &[CapabilityLabel],
) -> Result<String, String> {
    // Start from the deny-all quarantine template.
    let base = generated_policy_template(server_name)
        .map_err(|e| format!("failed to generate base policy: {e}"))?;

    // For capabilities that are "safe" enough, we can allow specific tools.
    // Currently only Filesystem and Browser get curated allowances.
    let has_filesystem = labels.contains(&CapabilityLabel::Filesystem);
    let has_browser = labels.contains(&CapabilityLabel::Browser);
    let has_network = labels.contains(&CapabilityLabel::Network);

    // Build an enhanced policy content.
    // For now: deny-all is the default; curated just means we applied
    // the template.  Future versions can add per-capability method/tool
    // allowances here.
    let mut content = base;

    // If the server only does filesystem/browser/network (no shell, no
    // identity/auth), we can add curated method allowances.
    let has_restricted = labels.contains(&CapabilityLabel::Unknown)
        || labels.contains(&CapabilityLabel::ShellCommandExecution)
        || labels.contains(&CapabilityLabel::IdentityAuth);

    if !has_restricted && (has_filesystem || has_browser || has_network) {
        // Allow `tools/call` in addition to `tools/list` so the server
        // can actually function under the curated policy.
        content = content.replace(
            "allow = [\"tools/list\"]",
            "allow = [\"tools/list\", \"tools/call\"]",
        );
    }

    Ok(content)
}

/// Generates a deny-all policy with a custom tool allowlist.
fn generate_custom_allowlist_policy(
    server_name: &str,
    allowed_tools: &[String],
) -> Result<String, String> {
    let safe_name = sanitize_policy_identifier(server_name);
    let tools_allow: String = if allowed_tools.is_empty() {
        String::new()
    } else {
        let entries: Vec<String> = allowed_tools.iter().map(|t| format!("\"{}\"", t)).collect();
        format!("allow = [{}]", entries.join(", "))
    };

    let content = format!(
        r#"schema_version = "ef-mcp-policy/v0.1"
name = "etherfence-setup-{safe_name}"

[methods]
allow = ["tools/list", "tools/call"]
deny = []

[tools]
{tools_allow}
deny = []
"#,
        tools_allow = if tools_allow.is_empty() {
            "allow = []".to_string()
        } else {
            tools_allow
        }
    );

    etherfence_mcp::parse_mcp_policy(&content)
        .map_err(|e| format!("custom allowlist policy validation failed: {e}"))?;
    Ok(content)
}

// =======================================================================
// Additional exports required by lib.rs
// =======================================================================

/// A configuration change entry for the wizard plan.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub enum ConfigChange {
    /// Wrap the server with etherfence mcp-proxy.
    Wrap,
    /// Pin the package version.
    PinVersion {
        server_name: String,
        runner: WizardPackageRunner,
        package: String,
        from_version: Option<String>,
        to_version: String,
    },
    /// Apply a generated policy.
    ApplyPolicy {
        server_name: String,
        policy_type: PolicyType,
        path: String,
    },
    /// Add a trust override.
    TrustOverride(TrustOverride),
    /// Skip the server (no change).
    Skip { reason: String },
}

/// Wizard server selection — identifies a server and its processing state.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct WizardServerSelection {
    pub agent: String,
    pub config_path: String,
    pub server_name: String,
    pub key: String,
    pub existing_status: PackageVersionStatus,
    pub runner: Option<WizardPackageRunner>,
    pub package_identity: Option<String>,
    pub needs_review: bool,
    pub selected: bool,
    pub pinned_version: Option<String>,
    pub policy_type: Option<PolicyType>,
}

/// Policy generation state — tracks which policies have been generated.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct PolicyGeneration {
    pub server_name: String,
    pub policy_type: PolicyType,
    pub content: String,
    pub path: String,
    pub validated: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server_from_mcp;

    fn mcp_server(name: &str, command: Option<&str>, args: &[&str]) -> McpServer {
        McpServer {
            name: name.to_string(),
            command: command.map(ToOwned::to_owned),
            args: args.iter().map(ToString::to_string).collect(),
            env: Vec::new(),
            url: None,
        }
    }

    // -----------------------------------------------------------------------
    // extract_package_version tests
    // -----------------------------------------------------------------------

    #[test]
    fn non_runner_returns_not_applicable() {
        let (runner, pkg, status) = extract_package_version("python", &["script.py".to_string()]);
        assert!(runner.is_none());
        assert!(pkg.is_none());
        assert_eq!(status, PackageVersionStatus::NotApplicable);
    }

    #[test]
    fn remote_url_command_returns_not_applicable() {
        let (runner, pkg, status) = extract_package_version("", &[]);
        assert!(runner.is_none());
        assert!(pkg.is_none());
        assert_eq!(status, PackageVersionStatus::NotApplicable);
    }

    #[test]
    fn npx_exact_pin_detected() {
        let (runner, pkg, status) = extract_package_version(
            "npx",
            &["@modelcontextprotocol/server-filesystem@1.2.3".to_string()],
        );
        assert_eq!(runner, Some(WizardPackageRunner::Npx));
        assert_eq!(
            pkg.as_deref(),
            Some("@modelcontextprotocol/server-filesystem")
        );
        assert_eq!(status, PackageVersionStatus::ExactPin);
    }

    #[test]
    fn npx_omitted_version_detected() {
        let (runner, _pkg, status) = extract_package_version(
            "npx",
            &["@modelcontextprotocol/server-filesystem".to_string()],
        );
        assert_eq!(runner, Some(WizardPackageRunner::Npx));
        assert_eq!(status, PackageVersionStatus::Omitted);
    }

    #[test]
    fn npx_mutable_tag_detected() {
        let (runner, pkg, status) = extract_package_version(
            "npx",
            &["@modelcontextprotocol/server-filesystem@latest".to_string()],
        );
        assert_eq!(runner, Some(WizardPackageRunner::Npx));
        assert_eq!(
            pkg.as_deref(),
            Some("@modelcontextprotocol/server-filesystem")
        );
        assert_eq!(status, PackageVersionStatus::MutableTag);
    }

    #[test]
    fn npx_version_range_detected() {
        let (_runner, _pkg, status) = extract_package_version(
            "npx",
            &["@modelcontextprotocol/server-filesystem@^1.0".to_string()],
        );
        assert_eq!(status, PackageVersionStatus::Range);
    }

    #[test]
    fn npx_beta_tag_is_mutable() {
        let (_runner, _pkg, status) = extract_package_version(
            "npx",
            &["@modelcontextprotocol/server-filesystem@beta".to_string()],
        );
        assert_eq!(status, PackageVersionStatus::MutableTag);
    }

    #[test]
    fn npx_dash_y_flag_skipped() {
        let (runner, _pkg, status) = extract_package_version(
            "npx",
            &[
                "-y".to_string(),
                "@modelcontextprotocol/server-filesystem@1.2.3".to_string(),
            ],
        );
        assert_eq!(runner, Some(WizardPackageRunner::Npx));
        assert_eq!(status, PackageVersionStatus::ExactPin);
    }

    #[test]
    fn npx_scoped_without_version_omitted() {
        let (runner, pkg, status) =
            extract_package_version("npx", &["@scope/my-package".to_string()]);
        assert_eq!(runner, Some(WizardPackageRunner::Npx));
        assert_eq!(pkg.as_deref(), Some("@scope/my-package"));
        assert_eq!(status, PackageVersionStatus::Omitted);
    }

    #[test]
    fn npx_scoped_with_exact_pin() {
        let (runner, pkg, status) =
            extract_package_version("npx", &["@scope/my-package@4.5.6".to_string()]);
        assert_eq!(runner, Some(WizardPackageRunner::Npx));
        assert_eq!(pkg.as_deref(), Some("@scope/my-package"));
        assert_eq!(status, PackageVersionStatus::ExactPin);
    }

    #[test]
    fn npx_unsimple_package_works() {
        let (runner, pkg, status) =
            extract_package_version("npx", &["some-package@1.0.0".to_string()]);
        assert_eq!(runner, Some(WizardPackageRunner::Npx));
        assert_eq!(pkg.as_deref(), Some("some-package"));
        assert_eq!(status, PackageVersionStatus::ExactPin);
    }

    #[test]
    fn uvx_positional_omitted() {
        let (runner, pkg, status) = extract_package_version("uvx", &["web-search-mcp".to_string()]);
        assert_eq!(runner, Some(WizardPackageRunner::Uvx));
        assert_eq!(pkg.as_deref(), Some("web-search-mcp"));
        assert_eq!(status, PackageVersionStatus::Omitted);
    }

    #[test]
    fn uvx_exact_pin_detected() {
        let (runner, pkg, status) =
            extract_package_version("uvx", &["web-search-mcp==0.2.1".to_string()]);
        assert_eq!(runner, Some(WizardPackageRunner::Uvx));
        assert_eq!(pkg.as_deref(), Some("web-search-mcp"));
        assert_eq!(status, PackageVersionStatus::ExactPin);
    }

    #[test]
    fn uvx_from_flag_version_omitted() {
        let (runner, pkg, status) = extract_package_version(
            "uvx",
            &[
                "--from".to_string(),
                "web-search-mcp".to_string(),
                "search".to_string(),
            ],
        );
        assert_eq!(runner, Some(WizardPackageRunner::Uvx));
        assert_eq!(pkg.as_deref(), Some("web-search-mcp"));
        assert_eq!(status, PackageVersionStatus::Omitted);
    }

    #[test]
    fn uvx_range_detected() {
        let (_runner, _pkg, status) =
            extract_package_version("uvx", &["web-search-mcp>=1.0".to_string()]);
        assert_eq!(status, PackageVersionStatus::Range);
    }

    #[test]
    fn pipx_run_positional_omitted() {
        let (runner, pkg, status) =
            extract_package_version("pipx", &["run".to_string(), "py-spy".to_string()]);
        assert_eq!(runner, Some(WizardPackageRunner::Pipx));
        assert_eq!(pkg.as_deref(), Some("py-spy"));
        assert_eq!(status, PackageVersionStatus::Omitted);
    }

    #[test]
    fn pipx_run_exact_pin_detected() {
        let (runner, pkg, status) =
            extract_package_version("pipx", &["run".to_string(), "py-spy==0.3.14".to_string()]);
        assert_eq!(runner, Some(WizardPackageRunner::Pipx));
        assert_eq!(pkg.as_deref(), Some("py-spy"));
        assert_eq!(status, PackageVersionStatus::ExactPin);
    }

    #[test]
    fn pipx_run_spec_flag_with_pin() {
        let (runner, pkg, status) = extract_package_version(
            "pipx",
            &[
                "run".to_string(),
                "--spec".to_string(),
                "py-spy==0.3.14".to_string(),
                "py-spy".to_string(),
            ],
        );
        assert_eq!(runner, Some(WizardPackageRunner::Pipx));
        assert_eq!(pkg.as_deref(), Some("py-spy"));
        assert_eq!(status, PackageVersionStatus::ExactPin);
    }

    #[test]
    fn pipx_run_spec_flag_with_range() {
        let (_runner, _pkg, status) = extract_package_version(
            "pipx",
            &[
                "run".to_string(),
                "--spec".to_string(),
                "py-spy>=0.3".to_string(),
                "py-spy".to_string(),
            ],
        );
        assert_eq!(status, PackageVersionStatus::Range);
    }

    #[test]
    fn pipx_bare_command_no_run_returns_not_applicable() {
        // `pipx` without `run` as the first arg is not a pipx-run invocation.
        let (runner, pkg, status) = extract_package_version("pipx", &["list".to_string()]);
        assert!(runner.is_none());
        assert!(pkg.is_none());
        assert_eq!(status, PackageVersionStatus::NotApplicable);
    }

    #[test]
    fn npx_absolute_path_resolves_correctly() {
        let (runner, _pkg, status) = extract_package_version(
            "/usr/local/bin/npx",
            &["@modelcontextprotocol/server-filesystem@1.2.3".to_string()],
        );
        assert_eq!(runner, Some(WizardPackageRunner::Npx));
        assert_eq!(status, PackageVersionStatus::ExactPin);
    }

    // -----------------------------------------------------------------------
    // PackageVersionStatus helper tests
    // -----------------------------------------------------------------------

    #[test]
    fn exact_pin_is_acceptable() {
        assert!(PackageVersionStatus::ExactPin.is_acceptable());
    }

    #[test]
    fn not_applicable_is_acceptable() {
        assert!(PackageVersionStatus::NotApplicable.is_acceptable());
    }

    #[test]
    fn omitted_needs_pinning() {
        assert!(PackageVersionStatus::Omitted.needs_pinning());
    }

    #[test]
    fn mutable_tag_needs_pinning() {
        assert!(PackageVersionStatus::MutableTag.needs_pinning());
    }

    #[test]
    fn range_needs_pinning() {
        assert!(PackageVersionStatus::Range.needs_pinning());
    }

    #[test]
    fn ambiguous_needs_pinning() {
        assert!(PackageVersionStatus::Ambiguous.needs_pinning());
    }

    #[test]
    fn exact_pin_does_not_need_pinning() {
        assert!(!PackageVersionStatus::ExactPin.needs_pinning());
    }

    #[test]
    fn not_applicable_does_not_need_pinning() {
        assert!(!PackageVersionStatus::NotApplicable.needs_pinning());
    }

    // -----------------------------------------------------------------------
    // resolve_pinning tests
    // -----------------------------------------------------------------------

    #[test]
    fn resolve_pinning_npx_omitted_pins_version() {
        let server = mcp_server(
            "filesystem",
            Some("npx"),
            &["@modelcontextprotocol/server-filesystem"],
        );
        let change = resolve_pinning(&server, "1.2.3").expect("should produce pinning change");
        assert_eq!(change.server_name, "filesystem");
        assert_eq!(change.runner, Some(WizardPackageRunner::Npx));
        assert_eq!(
            change.package_identity.as_deref(),
            Some("@modelcontextprotocol/server-filesystem")
        );
        assert_eq!(change.current_status, PackageVersionStatus::Omitted);
        assert_eq!(change.proposed_version.as_deref(), Some("1.2.3"));
        assert_eq!(
            change.pinned_args,
            vec!["@modelcontextprotocol/server-filesystem@1.2.3".to_string()]
        );
    }

    #[test]
    fn resolve_pinning_npx_with_dash_y_preserves_flag() {
        let server = mcp_server(
            "filesystem",
            Some("npx"),
            &["-y", "@modelcontextprotocol/server-filesystem"],
        );
        let change = resolve_pinning(&server, "2.0.0").expect("should produce pinning change");
        assert_eq!(
            change.pinned_args,
            vec![
                "-y".to_string(),
                "@modelcontextprotocol/server-filesystem@2.0.0".to_string(),
            ]
        );
    }

    #[test]
    fn resolve_pinning_npx_replace_mutable_tag() {
        let server = mcp_server(
            "filesystem",
            Some("npx"),
            &["@modelcontextprotocol/server-filesystem@latest"],
        );
        let change = resolve_pinning(&server, "3.4.5").expect("should produce pinning change");
        assert!(change.rationale.contains("mutable tag"));
        assert_eq!(
            change.pinned_args,
            vec!["@modelcontextprotocol/server-filesystem@3.4.5".to_string()]
        );
    }

    #[test]
    fn resolve_pinning_npx_replace_range() {
        let server = mcp_server(
            "filesystem",
            Some("npx"),
            &["@modelcontextprotocol/server-filesystem@^2.0"],
        );
        let change = resolve_pinning(&server, "2.5.0").expect("should produce pinning change");
        assert_eq!(change.current_status, PackageVersionStatus::Range);
        assert_eq!(
            change.pinned_args,
            vec!["@modelcontextprotocol/server-filesystem@2.5.0".to_string()]
        );
    }

    #[test]
    fn resolve_pinning_uvx_omitted() {
        let server = mcp_server("search", Some("uvx"), &["web-search-mcp"]);
        let change = resolve_pinning(&server, "0.2.1").expect("should produce pinning change");
        assert_eq!(change.runner, Some(WizardPackageRunner::Uvx));
        assert_eq!(
            change.pinned_args,
            vec!["web-search-mcp==0.2.1".to_string()]
        );
    }

    #[test]
    fn resolve_pinning_uvx_from_flag() {
        let server = mcp_server(
            "search",
            Some("uvx"),
            &["--from", "web-search-mcp", "search"],
        );
        let change = resolve_pinning(&server, "0.2.1").expect("should produce pinning change");
        assert_eq!(
            change.pinned_args,
            vec![
                "--from".to_string(),
                "web-search-mcp==0.2.1".to_string(),
                "search".to_string(),
            ]
        );
    }

    #[test]
    fn resolve_pinning_pipx_run() {
        let server = mcp_server("profiler", Some("pipx"), &["run", "py-spy"]);
        let change = resolve_pinning(&server, "0.3.14").expect("should produce pinning change");
        assert_eq!(change.runner, Some(WizardPackageRunner::Pipx));
        assert_eq!(
            change.pinned_args,
            vec!["run".to_string(), "py-spy==0.3.14".to_string()]
        );
    }

    #[test]
    fn resolve_pinning_pipx_run_with_spec() {
        let server = mcp_server(
            "profiler",
            Some("pipx"),
            &["run", "--spec", "py-spy>=0.3", "py-spy"],
        );
        let change = resolve_pinning(&server, "0.3.14").expect("should produce pinning change");
        assert_eq!(
            change.pinned_args,
            vec![
                "run".to_string(),
                "--spec".to_string(),
                "py-spy==0.3.14".to_string(),
                "py-spy".to_string(),
            ]
        );
    }

    #[test]
    fn resolve_pinning_non_runner_returns_none() {
        let server = mcp_server("script", Some("python"), &["server.py"]);
        assert!(resolve_pinning(&server, "1.0.0").is_none());
    }

    #[test]
    fn resolve_pinning_already_exact_returns_change() {
        // Even already-pinned servers get a change if the user proposes a
        // different version.
        let server = mcp_server(
            "filesystem",
            Some("npx"),
            &["@modelcontextprotocol/server-filesystem@1.2.3"],
        );
        let change = resolve_pinning(&server, "2.0.0").expect("should produce pinning change");
        assert_eq!(change.current_status, PackageVersionStatus::ExactPin);
        assert_eq!(
            change.pinned_args,
            vec!["@modelcontextprotocol/server-filesystem@2.0.0".to_string()]
        );
    }

    // -----------------------------------------------------------------------
    // build_pinned_args tests
    // -----------------------------------------------------------------------

    #[test]
    fn pin_npx_with_additional_args_preserved() {
        let args = build_npx_pinned_args(
            &[
                "-y".to_string(),
                "@scope/pkg".to_string(),
                "/path".to_string(),
            ],
            "@scope/pkg",
            "1.0.0",
        )
        .expect("package position must resolve");
        assert_eq!(
            args,
            vec![
                "-y".to_string(),
                "@scope/pkg@1.0.0".to_string(),
                "/path".to_string(),
            ]
        );
    }

    #[test]
    fn pin_npx_with_package_flag() {
        let args = build_npx_pinned_args(
            &[
                "--package".to_string(),
                "@scope/pkg".to_string(),
                "run".to_string(),
            ],
            "@scope/pkg",
            "1.0.0",
        )
        .expect("package position must resolve");
        assert_eq!(
            args,
            vec![
                "--package".to_string(),
                "@scope/pkg@1.0.0".to_string(),
                "run".to_string(),
            ]
        );
    }

    #[test]
    fn pin_npx_with_package_eq_flag() {
        let args =
            build_npx_pinned_args(&["--package=@scope/pkg".to_string()], "@scope/pkg", "1.0.0")
                .expect("package position must resolve");
        assert_eq!(args, vec!["--package=@scope/pkg@1.0.0".to_string()]);
    }

    #[test]
    fn pin_uvx_positional() {
        let args = build_uvx_pinned_args(
            &["mytool".to_string(), "arg1".to_string()],
            "mytool",
            "0.5.0",
        )
        .expect("package position must resolve");
        assert_eq!(args, vec!["mytool==0.5.0".to_string(), "arg1".to_string()]);
    }

    #[test]
    fn pin_uvx_from_flag() {
        let args = build_uvx_pinned_args(
            &[
                "--from".to_string(),
                "mytool@latest".to_string(),
                "run".to_string(),
            ],
            "mytool",
            "0.5.0",
        )
        .expect("package position must resolve");
        assert_eq!(
            args,
            vec![
                "--from".to_string(),
                "mytool==0.5.0".to_string(),
                "run".to_string(),
            ]
        );
    }

    #[test]
    fn pin_pipx_run_positional() {
        let args = build_pipx_pinned_args(
            &["run".to_string(), "pkg".to_string(), "arg1".to_string()],
            "pkg",
            "1.0.0",
        )
        .expect("package position must resolve");
        assert_eq!(
            args,
            vec![
                "run".to_string(),
                "pkg==1.0.0".to_string(),
                "arg1".to_string()
            ]
        );
    }

    #[test]
    fn pin_pipx_run_spec_flag() {
        let args = build_pipx_pinned_args(
            &[
                "run".to_string(),
                "--spec".to_string(),
                "pkg".to_string(),
                "pkg".to_string(),
                "arg1".to_string(),
            ],
            "pkg",
            "1.0.0",
        )
        .expect("package position must resolve");
        assert_eq!(
            args,
            vec![
                "run".to_string(),
                "--spec".to_string(),
                "pkg==1.0.0".to_string(),
                "pkg".to_string(),
                "arg1".to_string(),
            ]
        );
    }

    // -----------------------------------------------------------------------
    // Policy generation tests
    // -----------------------------------------------------------------------

    #[test]
    fn generated_policy_template_validates() {
        let content = generated_policy_template("test-server").unwrap();
        assert!(content.contains("schema_version = \"ef-mcp-policy/v0.1\""));
        assert!(content.contains("allow = []"));
        assert!(etherfence_mcp::parse_mcp_policy(&content).is_ok());
    }

    #[test]
    fn custom_allowlist_policy_validates() {
        let content = generate_custom_allowlist_policy(
            "test-server",
            &["read_file".to_string(), "write_file".to_string()],
        )
        .unwrap();
        assert!(content.contains("tools/list"));
        assert!(content.contains("read_file"));
        assert!(content.contains("write_file"));
        assert!(etherfence_mcp::parse_mcp_policy(&content).is_ok());
    }

    #[test]
    fn custom_allowlist_empty_tools_produces_allow_empty() {
        let content = generate_custom_allowlist_policy("empty", &[]).unwrap();
        assert!(content.contains("allow = []") || content.contains("allow = [\n]"));
        assert!(etherfence_mcp::parse_mcp_policy(&content).is_ok());
    }

    #[test]
    fn curated_policy_validates_with_fs_capability() {
        let labels = vec![CapabilityLabel::Filesystem];
        let content = generate_curated_policy("fs-server", &labels).unwrap();
        assert!(etherfence_mcp::parse_mcp_policy(&content).is_ok());
    }

    // -----------------------------------------------------------------------
    // build_wizard_plan tests
    // -----------------------------------------------------------------------

    fn sample_detection(agent: &str, server_name: &str) -> SetupDetection {
        let server = mcp_server(server_name, Some("npx"), &["some-package"]);
        let mut setup_server = server_from_mcp(&server);
        // Real detections snapshot the raw JSON entry; synthetic test
        // detections fake one so plan building can proceed.
        setup_server.raw_entry_sha256 = Some("test-entry-snapshot".to_string());
        SetupDetection {
            agent: agent.to_string(),
            config_path: format!("~/.config/{agent}/mcp.json"),
            write_support: crate::WriteSupport::Supported,
            servers: vec![setup_server],
            notes: Vec::new(),
        }
    }

    fn sample_id(agent: &str, server_name: &str) -> WizardServerId {
        WizardServerId {
            agent: agent.to_string(),
            config_path: format!("~/.config/{agent}/mcp.json"),
            server_name: server_name.to_string(),
        }
    }

    #[test]
    fn build_wizard_plan_selects_servers() {
        let detections = vec![sample_detection("test-agent", "test-server")];
        let id = sample_id("test-agent", "test-server");
        let mut selections = WizardSelections {
            selected: vec![id.clone()],
            ..WizardSelections::default()
        };
        selections.version_pins.insert(id, "1.2.3".to_string());

        let plan = build_wizard_plan(&detections, &selections, "/home/user")
            .expect("plan building should succeed");

        assert_eq!(plan.root, "/home/user");
        assert_eq!(plan.selected_servers.len(), 1);
        assert_eq!(plan.selected_servers[0].server_name, "test-server");
        assert_eq!(plan.selected_servers[0].agent, "test-agent");
        // Should have a pinning change and a deny-all policy (default).
        assert!(
            !plan.pinning_changes.is_empty(),
            "should have pinning changes"
        );
        assert!(!plan.policies.is_empty(), "should have policies");
    }

    #[test]
    fn build_wizard_plan_with_custom_allowlist() {
        let detections = vec![sample_detection("agent", "custom-server")];
        let id = sample_id("agent", "custom-server");
        let mut selections = WizardSelections {
            selected: vec![id.clone()],
            ..WizardSelections::default()
        };
        selections.policy_types.insert(
            id,
            PolicyType::CustomToolAllowlist(vec!["read".to_string()]),
        );

        let plan = build_wizard_plan(&detections, &selections, "/tmp").unwrap();
        let policy = &plan.policies[0];
        assert!(matches!(
            policy.policy_type,
            PolicyType::CustomToolAllowlist(_)
        ));
        assert!(policy.content.contains("read"));
        assert!(etherfence_mcp::parse_mcp_policy(&policy.content).is_ok());
    }

    #[test]
    fn build_wizard_plan_skips_unselected_servers() {
        let detections = vec![sample_detection("agent", "server-a")];
        let selections = WizardSelections::default();
        let plan = build_wizard_plan(&detections, &selections, "/").unwrap();
        assert_eq!(plan.selected_servers.len(), 0);
        assert!(plan.policies.is_empty());
        assert!(plan.pinning_changes.is_empty());
    }

    #[test]
    fn build_wizard_plan_scopes_selection_to_one_config() {
        // The same agent + server name in two config files: selecting one
        // must never pull in the other.
        let mut first = sample_detection("agent", "dup");
        first.config_path = "~/.claude.json".to_string();
        let mut second = sample_detection("agent", "dup");
        second.config_path = "~/.claude/settings.json".to_string();

        let selections = WizardSelections {
            selected: vec![WizardServerId {
                agent: "agent".to_string(),
                config_path: "~/.claude.json".to_string(),
                server_name: "dup".to_string(),
            }],
            ..WizardSelections::default()
        };
        let plan = build_wizard_plan(&[first, second], &selections, "/").unwrap();
        assert_eq!(plan.selected_servers.len(), 1);
        assert_eq!(plan.selected_servers[0].config_path, "~/.claude.json");
        assert_eq!(plan.policies.len(), 1);
        assert_eq!(plan.policies[0].config_path, "~/.claude.json");
    }

    #[test]
    fn build_wizard_plan_rejects_remote_server_selection() {
        let mcp = McpServer {
            name: "remote-server".to_string(),
            command: None,
            args: Vec::new(),
            env: Vec::new(),
            url: Some("http://example.com/mcp".to_string()),
        };
        let setup_server = server_from_mcp(&mcp);
        let detection = SetupDetection {
            agent: "agent".to_string(),
            config_path: "~/.config/agent/mcp.json".to_string(),
            write_support: crate::WriteSupport::Supported,
            servers: vec![setup_server],
            notes: Vec::new(),
        };
        let selections = WizardSelections {
            selected: vec![sample_id("agent", "remote-server")],
            ..WizardSelections::default()
        };
        let error = build_wizard_plan(&[detection], &selections, "/").unwrap_err();
        assert!(error.contains("not a local stdio server"), "{error}");
    }

    #[test]
    fn build_wizard_plan_rejects_wrapped_server_selection() {
        let mcp = McpServer {
            name: "already".to_string(),
            command: Some("etherfence".to_string()),
            args: vec!["mcp-proxy".to_string(), "--policy".to_string()],
            env: Vec::new(),
            url: None,
        };
        let setup_server = server_from_mcp(&mcp);
        let detection = SetupDetection {
            agent: "agent".to_string(),
            config_path: "~/.config/agent/mcp.json".to_string(),
            write_support: crate::WriteSupport::Supported,
            servers: vec![setup_server],
            notes: Vec::new(),
        };
        let selections = WizardSelections {
            selected: vec![sample_id("agent", "already")],
            ..WizardSelections::default()
        };
        let error = build_wizard_plan(&[detection], &selections, "/").unwrap_err();
        assert!(error.contains("already protected"), "{error}");
    }

    #[test]
    fn build_wizard_plan_rejects_advisory_only_selection() {
        let mut detection = sample_detection("agent", "server");
        detection.write_support = crate::WriteSupport::AdvisoryOnly;
        let selections = WizardSelections {
            selected: vec![sample_id("agent", "server")],
            ..WizardSelections::default()
        };
        let error = build_wizard_plan(&[detection], &selections, "/").unwrap_err();
        assert!(error.contains("advisory-only"), "{error}");
    }

    #[test]
    fn build_wizard_plan_rejects_selection_of_unknown_server() {
        let detections = vec![sample_detection("agent", "server")];
        let selections = WizardSelections {
            selected: vec![sample_id("agent", "no-such-server")],
            ..WizardSelections::default()
        };
        let error = build_wizard_plan(&detections, &selections, "/").unwrap_err();
        assert!(error.contains("was not found"), "{error}");
    }

    #[test]
    fn build_wizard_plan_trust_overrides() {
        let detections = vec![sample_detection("agent", "server")];
        let id = sample_id("agent", "server");
        let mut selections = WizardSelections {
            selected: vec![id.clone()],
            ..WizardSelections::default()
        };
        selections
            .trust_overrides
            .insert(id, vec!["EF-TRUST-PIN-001".to_string()]);

        let plan = build_wizard_plan(&detections, &selections, "/").unwrap();
        assert_eq!(plan.trust_overrides.len(), 1);
        assert_eq!(
            plan.trust_overrides[0].accepted_indicator_ids,
            vec!["EF-TRUST-PIN-001"]
        );
        assert_eq!(
            plan.trust_overrides[0].config_path,
            "~/.config/agent/mcp.json"
        );
    }

    // -----------------------------------------------------------------------
    // validate_exact_version tests
    // -----------------------------------------------------------------------

    #[test]
    fn npm_partial_and_malformed_versions_are_rejected() {
        for bad in ["1", "1.2", "1..2", "1foo", "latest", "^1.2", ">=2", "foo"] {
            assert!(
                validate_exact_version(WizardPackageRunner::Npx, bad).is_err(),
                "npm version {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn npm_full_semver_versions_are_accepted() {
        for good in ["1.2.3", "0.1.0", "2.0.0-rc.1", "1.2.3+build.5"] {
            assert!(
                validate_exact_version(WizardPackageRunner::Npx, good).is_ok(),
                "npm version {good:?} must be accepted"
            );
        }
    }

    #[test]
    fn pep440_exact_versions_validate() {
        assert!(validate_exact_version(WizardPackageRunner::Uvx, "0.2.1").is_ok());
        assert!(validate_exact_version(WizardPackageRunner::Pipx, "0.3.14").is_ok());
        assert!(validate_exact_version(WizardPackageRunner::Uvx, ">=1.0").is_err());
        assert!(validate_exact_version(WizardPackageRunner::Uvx, "1.0.*").is_err());
    }

    // -----------------------------------------------------------------------
    // Unknown npx option fail-closed tests
    // -----------------------------------------------------------------------

    #[test]
    fn npx_unknown_flag_before_package_is_ambiguous() {
        let (runner, pkg, status) = extract_package_version(
            "npx",
            &["--loglevel=silent".to_string(), "some-package".to_string()],
        );
        assert_eq!(runner, Some(WizardPackageRunner::Npx));
        assert!(pkg.is_none());
        assert_eq!(status, PackageVersionStatus::Ambiguous);
    }

    #[test]
    fn npx_unknown_flag_prevents_pin_rewrite() {
        let server = mcp_server(
            "srv",
            Some("npx"),
            &["--node-options=--max-old-space-size=4096", "some-package"],
        );
        assert!(
            resolve_pinning(&server, "1.2.3").is_none(),
            "unknown pre-package npx options must fail closed, not be rewritten"
        );
    }

    #[test]
    fn pin_builders_refuse_unknown_pre_package_flags() {
        assert!(
            build_npx_pinned_args(&["-q".to_string(), "pkg".to_string()], "pkg", "1.0.0").is_none()
        );
        assert!(
            build_uvx_pinned_args(&["-q".to_string(), "pkg".to_string()], "pkg", "1.0.0").is_none()
        );
        assert!(build_pipx_pinned_args(
            &["run".to_string(), "-q".to_string(), "pkg".to_string()],
            "pkg",
            "1.0.0"
        )
        .is_none());
    }
}
