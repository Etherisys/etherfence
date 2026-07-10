use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use etherfence_core::{
    read_bounded_text_file, BaselineComparison, BaselineFile, BaselineStatus, Finding,
    PolicyMetadata, ScanReport, Severity, Summary, MAX_BASELINE_FILE_BYTES, MAX_CONFIG_FILE_BYTES,
};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Parser)]
#[command(
    name = "etherfence",
    version,
    about = "AI Agent Security Posture & Runtime Control"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Discover local AI agent/MCP configuration and print a posture report.
    Scan {
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
        format: OutputFormat,
        /// Only display findings at or above this severity.
        #[arg(long, value_enum, default_value_t = CliSeverity::Info)]
        severity_threshold: CliSeverity,
        /// Exit non-zero when findings at or above this severity exist.
        #[arg(long, value_enum)]
        fail_on: Option<CliSeverity>,
        /// Compare current findings with a JSON baseline file.
        #[arg(long)]
        baseline: Option<PathBuf>,
        /// Evaluate scan results against a TOML scan-only policy file.
        #[arg(long)]
        policy: Option<PathBuf>,
        /// Evaluate scan results against a built-in scan-only policy profile.
        #[arg(long)]
        policy_profile: Option<String>,
        /// Write current findings to a JSON baseline file.
        #[arg(long)]
        write_baseline: Option<PathBuf>,
        /// Exit non-zero when new findings at or above this severity exist. Requires --baseline.
        #[arg(long, value_enum)]
        fail_on_new: Option<CliSeverity>,
        /// Scan root. Defaults to HOME. Intended for tests and controlled scans.
        #[arg(long, hide = true)]
        root: Option<PathBuf>,
    },
    /// Inspect built-in scan-only policy profile examples.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Experimental: run an MCP stdio boundary proxy that inspects every
    /// client→server JSON-RPC method, enforces method-level and tool-level
    /// allow/deny policy, and audits decisions. Fails closed when the policy
    /// cannot be loaded.
    McpProxy {
        /// TOML MCP proxy policy file (schema ef-mcp-policy/v0.1).
        #[arg(long)]
        policy: PathBuf,
        /// Append JSONL audit records for tool-call decisions to this file.
        #[arg(long)]
        audit_log: Option<PathBuf>,
        /// Logical MCP server policy scope. Defaults to `default`.
        #[arg(long, default_value = "default")]
        server_name: String,
        /// MCP server command and arguments, after `--`.
        #[arg(last = true, required = true)]
        server_command: Vec<String>,
    },
    /// Local, serverless MCP policy UX: validate, explain, generate, and
    /// dry-run-check `ef-mcp-policy/v0.1` policies without starting an MCP
    /// server or executing any tool.
    McpPolicy {
        #[command(subcommand)]
        command: McpPolicyCommand,
    },
}

#[derive(Debug, Subcommand)]
enum McpPolicyCommand {
    /// Parse and validate an MCP proxy policy file.
    Validate {
        /// TOML MCP proxy policy file (schema ef-mcp-policy/v0.1).
        policy: PathBuf,
    },
    /// Print a deterministic human-readable summary of an MCP proxy policy,
    /// including warnings for risky or confusing policy shapes.
    Explain {
        /// TOML MCP proxy policy file (schema ef-mcp-policy/v0.1).
        policy: PathBuf,
    },
    /// Generate a starter MCP proxy policy from a built-in profile.
    Init {
        /// Built-in profile name. Run without `--output` to preview.
        #[arg(long)]
        profile: String,
        /// Write the policy to this file instead of stdout.
        #[arg(long)]
        output: Option<PathBuf>,
        /// Allow overwriting an existing `--output` file.
        #[arg(long)]
        overwrite: bool,
    },
    /// Dry-run one JSON-RPC request/notification against a policy without
    /// starting or contacting an MCP server and without executing any tool.
    Check {
        /// TOML MCP proxy policy file (schema ef-mcp-policy/v0.1).
        #[arg(long)]
        policy: PathBuf,
        /// A JSON-RPC request/notification, either inline JSON (starting with
        /// `{` or `[`) or a path to a file containing it.
        #[arg(long)]
        request: String,
        /// Logical MCP server policy scope. Defaults to `default`.
        #[arg(long, default_value = "default")]
        server_name: String,
        /// Direction the request/notification travels.
        #[arg(long, value_enum, default_value_t = CheckDirection::ClientToServer)]
        direction: CheckDirection,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CheckDirection {
    ClientToServer,
    ServerToClient,
}

impl From<CheckDirection> for etherfence_mcp::MethodDirection {
    fn from(value: CheckDirection) -> Self {
        match value {
            CheckDirection::ClientToServer => etherfence_mcp::MethodDirection::ClientToServer,
            CheckDirection::ServerToClient => etherfence_mcp::MethodDirection::ServerToClient,
        }
    }
}

struct McpPolicyProfile {
    name: &'static str,
    description: &'static str,
    content: &'static str,
}

const MCP_POLICY_PROFILES: &[McpPolicyProfile] = &[
    McpPolicyProfile {
        name: "minimal",
        description: "Minimal global + per-server tool allow/deny boundary.",
        content: include_str!("../../../examples/policies/mcp-minimal-boundary.toml"),
    },
    McpPolicyProfile {
        name: "strict-method-only",
        description: "Explicit [methods] allow/deny restricted to tools/list and tools/call.",
        content: include_str!("../../../examples/policies/mcp-strict-method-only.toml"),
    },
    McpPolicyProfile {
        name: "filesystem-project-readonly",
        description: "Project-root read-only filesystem tool with a path guard.",
        content: include_str!("../../../examples/policies/mcp-filesystem-project-readonly.toml"),
    },
    McpPolicyProfile {
        name: "filesystem-project-readonly-hardened",
        description:
            "Project-root read-only filesystem tool with expanded credential-path deny_roots.",
        content: include_str!(
            "../../../examples/policies/mcp-filesystem-project-readonly-hardened.toml"
        ),
    },
    McpPolicyProfile {
        name: "resources-project-only",
        description: "Project-root-only resources/read over file:// URIs, plus tool policy.",
        content: include_str!("../../../examples/policies/mcp-resources-project-only.toml"),
    },
];

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    /// List built-in policy profiles.
    List,
    /// Show the TOML for a built-in policy profile.
    Show { profile: String },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
    Markdown,
    Sarif,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliSeverity {
    Info,
    Low,
    Medium,
    High,
}

impl From<CliSeverity> for Severity {
    fn from(value: CliSeverity) -> Self {
        match value {
            CliSeverity::Info => Severity::Info,
            CliSeverity::Low => Severity::Low,
            CliSeverity::Medium => Severity::Medium,
            CliSeverity::High => Severity::High,
        }
    }
}

struct BuiltInPolicy {
    name: &'static str,
    description: &'static str,
    content: &'static str,
}

const BUILT_IN_POLICIES: &[BuiltInPolicy] = &[
    BuiltInPolicy {
        name: "developer-laptop",
        description: "Balanced scan-only posture policy for local AI coding agents on developer workstations.",
        content: include_str!("../../../examples/policies/developer-laptop.toml"),
    },
    BuiltInPolicy {
        name: "ci-runner",
        description: "Stricter scan-only posture policy for CI runners and ephemeral automation hosts.",
        content: include_str!("../../../examples/policies/ci-runner.toml"),
    },
    BuiltInPolicy {
        name: "research-workstation",
        description: "Research-friendly scan-only posture policy allowing browser/search MCP use while still denying broad filesystem and secret exposure.",
        content: include_str!("../../../examples/policies/research-workstation.toml"),
    },
    BuiltInPolicy {
        name: "strict",
        description: "Strict scan-only posture policy for validating narrow local AI-agent posture.",
        content: include_str!("../../../examples/policies/strict.toml"),
    },
];

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan {
            format,
            severity_threshold,
            fail_on,
            baseline,
            policy,
            policy_profile,
            write_baseline,
            fail_on_new,
            root,
        } => run_scan(ScanOptions {
            format,
            severity_threshold: severity_threshold.into(),
            fail_on: fail_on.map(Severity::from),
            baseline,
            policy,
            policy_profile,
            write_baseline,
            fail_on_new: fail_on_new.map(Severity::from),
            root,
        }),
        Command::Policy { command } => run_policy_command(command),
        Command::McpProxy {
            policy,
            audit_log,
            server_name,
            server_command,
        } => run_mcp_proxy(&policy, audit_log.as_deref(), &server_name, &server_command),
        Command::McpPolicy { command } => run_mcp_policy_command(command),
    }
}

fn run_mcp_policy_command(command: McpPolicyCommand) -> Result<()> {
    match command {
        McpPolicyCommand::Validate { policy } => run_mcp_policy_validate(&policy),
        McpPolicyCommand::Explain { policy } => run_mcp_policy_explain(&policy),
        McpPolicyCommand::Init {
            profile,
            output,
            overwrite,
        } => run_mcp_policy_init(&profile, output.as_deref(), overwrite),
        McpPolicyCommand::Check {
            policy,
            request,
            server_name,
            direction,
        } => run_mcp_policy_check(&policy, &request, &server_name, direction),
    }
}

fn run_mcp_policy_validate(policy_path: &Path) -> Result<()> {
    let policy = etherfence_mcp::load_mcp_policy(policy_path)?;
    println!(
        "OK: {} is a valid MCP proxy policy (name={:?}, schema_version={:?}).",
        policy_path.display(),
        policy.name,
        policy.schema_version
    );
    Ok(())
}

fn run_mcp_policy_explain(policy_path: &Path) -> Result<()> {
    let policy = etherfence_mcp::load_mcp_policy(policy_path)?;
    let explanation = etherfence_mcp::explain_policy(&policy);
    print!("{}", render_mcp_policy_explanation(&explanation));
    Ok(())
}

fn run_mcp_policy_init(profile: &str, output: Option<&Path>, overwrite: bool) -> Result<()> {
    let profile_def = MCP_POLICY_PROFILES
        .iter()
        .find(|candidate| candidate.name == profile)
        .with_context(|| {
            let entries: Vec<String> = MCP_POLICY_PROFILES
                .iter()
                .map(|p| format!("{} ({})", p.name, p.description))
                .collect();
            format!(
                "unknown MCP policy init profile {profile:?}; supported profiles: {}",
                entries.join(", ")
            )
        })?;
    match output {
        Some(path) => {
            if path.exists() && !overwrite {
                anyhow::bail!(
                    "refusing to overwrite existing file {} (pass --overwrite to replace it)",
                    path.display()
                );
            }
            fs::write(path, profile_def.content)
                .with_context(|| format!("writing MCP policy init output {}", path.display()))?;
            println!("Wrote MCP policy profile {profile:?} to {}", path.display());
        }
        None => {
            print!("{}", profile_def.content);
        }
    }
    Ok(())
}

fn run_mcp_policy_check(
    policy_path: &Path,
    request: &str,
    server_name: &str,
    direction: CheckDirection,
) -> Result<()> {
    let policy = etherfence_mcp::load_mcp_policy(policy_path)?;
    let raw_request = load_mcp_check_request(request)?;
    serde_json::from_str::<serde_json::Value>(&raw_request)
        .context("--request is not valid JSON")?;
    let outcome =
        etherfence_mcp::dry_run_check(&policy, server_name, direction.into(), &raw_request);
    print!("{}", render_mcp_check_outcome(&outcome));
    Ok(())
}

// `request` is an explicit, trusted-operator CLI input (`mcp-policy check
// --request`); see the doc comment on `read_bounded_text_file` for the
// CLI-vs-future-API path trust model this crate follows.
fn load_mcp_check_request(request: &str) -> Result<String> {
    let trimmed = request.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        Ok(request.to_string())
    } else {
        read_bounded_text_file(Path::new(request), MAX_CONFIG_FILE_BYTES)
            .with_context(|| format!("reading --request input file {request}"))
    }
}

fn render_mcp_policy_explanation(explanation: &etherfence_mcp::PolicyExplanation) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "Policy name: {}", explanation.name);
    let _ = writeln!(out, "Schema version: {}", explanation.schema_version);
    let _ = writeln!(out);

    let _ = writeln!(out, "Global methods:");
    if explanation.global_methods.configured {
        let _ = writeln!(
            out,
            "  allow: {}",
            format_list(&explanation.global_methods.allow)
        );
        let _ = writeln!(
            out,
            "  deny: {}",
            format_list(&explanation.global_methods.deny)
        );
    } else {
        let _ = writeln!(
            out,
            "  (not configured; built-in default allows only tools/list and tools/call)"
        );
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "Global tools:");
    let _ = writeln!(
        out,
        "  allow: {}",
        format_list(&explanation.global_tools.allow)
    );
    let _ = writeln!(
        out,
        "  deny: {}",
        format_list(&explanation.global_tools.deny)
    );
    let _ = writeln!(out);

    if explanation.servers.is_empty() {
        let _ = writeln!(out, "Server scopes: (none configured)");
    } else {
        let _ = writeln!(out, "Server scopes:");
        for server in &explanation.servers {
            let _ = writeln!(out, "  [{}]", server.name);
            let _ = writeln!(out, "    tools.allow: {}", format_list(&server.tools.allow));
            let _ = writeln!(out, "    tools.deny: {}", format_list(&server.tools.deny));
            match &server.methods {
                Some(methods) => {
                    let _ = writeln!(out, "    methods.allow: {}", format_list(&methods.allow));
                    let _ = writeln!(out, "    methods.deny: {}", format_list(&methods.deny));
                }
                None => {
                    let _ = writeln!(
                        out,
                        "    methods: (not configured; falls back to global policy/built-in default)"
                    );
                }
            }
        }
    }
    let _ = writeln!(out);

    if explanation.path_rules.is_empty() {
        let _ = writeln!(out, "Path rules: (none configured)");
    } else {
        let _ = writeln!(out, "Path rules:");
        for rule in &explanation.path_rules {
            let _ = writeln!(out, "  [{}]", rule.name);
            let _ = writeln!(out, "    allow_roots: {}", format_list(&rule.allow_roots));
            let _ = writeln!(out, "    deny_roots: {}", format_list(&rule.deny_roots));
        }
    }
    let _ = writeln!(out);

    if explanation.guards.is_empty() {
        let _ = writeln!(out, "Guarded keys: (none configured)");
    } else {
        let _ = writeln!(out, "Guarded keys:");
        for guard in &explanation.guards {
            let scope_label = match &guard.server_name {
                Some(server) => format!("{} (server={server})", guard.scope.as_str()),
                None => guard.scope.as_str().to_string(),
            };
            let keys: Vec<&str> = guard
                .path_keys
                .iter()
                .chain(guard.uri_keys.iter())
                .map(String::as_str)
                .collect();
            let _ = writeln!(
                out,
                "  {scope_label} {:?} -> path_rule={:?} keys={}",
                guard.key,
                guard.path_rule,
                format_list(&keys)
            );
        }
    }
    let _ = writeln!(out);

    let _ = writeln!(
        out,
        "Unicode/homograph hardening: always enabled (v0.4.1) -- bidi controls, zero-width/invisible characters, and non-ASCII policy/runtime identifiers are rejected at parse time or denied at runtime before matching."
    );
    let _ = writeln!(
        out,
        "Audit redaction posture: when --audit-log is used, only decisions, reasons, method/tool names, safe path classification, and argument/param key names are recorded; argument/param values, full paths, and URIs are never logged."
    );
    let _ = writeln!(out);

    if explanation.warnings.is_empty() {
        let _ = writeln!(out, "Warnings: (none)");
    } else {
        let _ = writeln!(out, "Warnings:");
        for warning in &explanation.warnings {
            let _ = writeln!(out, "  - {warning}");
        }
    }
    out
}

fn format_list<S: AsRef<str>>(items: &[S]) -> String {
    if items.is_empty() {
        "(none)".to_string()
    } else {
        items
            .iter()
            .map(|item| item.as_ref())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn render_mcp_check_outcome(outcome: &etherfence_mcp::CheckOutcome) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "Decision: {}", outcome.decision.to_uppercase());
    let _ = writeln!(
        out,
        "Would be forwarded: {}",
        if outcome.forwarded { "yes" } else { "no" }
    );
    let _ = writeln!(
        out,
        "Inspected by policy: {}",
        if outcome.inspected { "yes" } else { "no" }
    );
    let _ = writeln!(out, "Category: {}", outcome.event);
    if let Some(method) = &outcome.method {
        let _ = writeln!(out, "Method: {method}");
    }
    if let Some(tool) = &outcome.tool {
        let _ = writeln!(out, "Tool: {tool}");
    }
    if let Some(rule) = &outcome.path_rule {
        let _ = writeln!(
            out,
            "Path decision: rule={:?} key={:?} classification={:?}",
            rule,
            outcome.path_key.as_deref().unwrap_or("<none>"),
            outcome.path_classification.as_deref().unwrap_or("<none>")
        );
    }
    let _ = writeln!(out, "Reason: {}", outcome.reason);
    let _ = writeln!(
        out,
        "Note: this is a local, serverless dry run. No MCP server was started or contacted and no tool was executed."
    );
    out
}

fn run_mcp_proxy(
    policy_path: &Path,
    audit_log_path: Option<&Path>,
    server_name: &str,
    server_command: &[String],
) -> Result<()> {
    let mut audit_log = match audit_log_path.map(etherfence_mcp::AuditLog::open) {
        Some(result) => match result {
            Ok(log) => Some(log),
            Err(error) => {
                // Audit open failure is fatal up front: the operator asked for
                // an audit log and we cannot honor it. Fail closed before the
                // server starts.
                eprintln!("etherfence mcp-proxy: {error:#}");
                std::process::exit(etherfence_mcp::exit_code::INTERNAL_ERROR);
            }
        },
        None => None,
    };
    let policy = match etherfence_mcp::load_mcp_policy(policy_path) {
        Ok(policy) => policy,
        Err(error) => {
            // Fail closed: record the policy error and never start the server.
            if let Some(log) = audit_log.as_mut() {
                if let Err(audit_error) = log.write(&etherfence_mcp::AuditRecord::policy_error(
                    &format!("{error:#}"),
                )) {
                    eprintln!(
                        "etherfence mcp-proxy: audit write failed (continuing): {audit_error:#}"
                    );
                }
            }
            eprintln!("etherfence mcp-proxy: fail closed, MCP server not started: {error:#}");
            std::process::exit(etherfence_mcp::exit_code::INVALID_POLICY);
        }
    };
    let exit_code = match etherfence_mcp::run_proxy(
        std::io::stdin().lock(),
        std::io::stdout(),
        server_command,
        &policy,
        server_name,
        audit_log,
    ) {
        Ok(code) => code,
        Err(proxy_error) => {
            // The child has already been reaped inside run_proxy. Surface the
            // documented exit code and message.
            eprintln!("etherfence mcp-proxy: {}", proxy_error.message());
            proxy_error.code()
        }
    };
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

fn run_policy_command(command: PolicyCommand) -> Result<()> {
    match command {
        PolicyCommand::List => {
            for policy in BUILT_IN_POLICIES {
                println!("{}\t{}", policy.name, policy.description);
            }
            Ok(())
        }
        PolicyCommand::Show { profile } => {
            let policy = BUILT_IN_POLICIES
                .iter()
                .find(|policy| policy.name == profile)
                .with_context(|| format!("unknown built-in policy profile {profile:?}"))?;
            print!("{}", policy.content);
            Ok(())
        }
    }
}

struct ScanOptions {
    format: OutputFormat,
    severity_threshold: Severity,
    fail_on: Option<Severity>,
    baseline: Option<PathBuf>,
    policy: Option<PathBuf>,
    policy_profile: Option<String>,
    write_baseline: Option<PathBuf>,
    fail_on_new: Option<Severity>,
    root: Option<PathBuf>,
}

fn run_scan(options: ScanOptions) -> Result<()> {
    if options.fail_on_new.is_some() && options.baseline.is_none() {
        anyhow::bail!("--fail-on-new requires --baseline");
    }
    if options.policy.is_some() && options.policy_profile.is_some() {
        anyhow::bail!("--policy and --policy-profile are mutually exclusive; use --policy <file> for a custom policy file or --policy-profile <name> for a built-in profile");
    }

    let (scanned_root, inventory) = if let Some(root) = &options.root {
        (
            root.display().to_string(),
            etherfence_inventory::discover(root),
        )
    } else {
        let roots = etherfence_inventory::default_scan_roots();
        let scanned_root = roots
            .iter()
            .map(|root| root.display().to_string())
            .collect::<Vec<_>>()
            .join(",");
        (scanned_root, etherfence_inventory::discover_roots(&roots))
    };
    let mut current_findings = etherfence_detectors::analyze(&inventory);
    let mut policy_meta = None;

    if let Some(policy_source) = load_scan_policy(&options)? {
        let policy = policy_source.policy;
        let evaluation = etherfence_policy::evaluate_policy(&policy, &inventory)?;
        current_findings.extend(evaluation.findings);
        policy_meta = Some(PolicyMetadata {
            policy_path: policy_source.display_path,
            policy_source: policy_source.source,
            policy_profile: policy_source.profile,
            policy_schema_version: evaluation.policy_schema_version,
            policy_name: evaluation.policy_name,
            policy_description: evaluation.policy_description,
            require_tirith: evaluation.require_tirith,
            checks_total: evaluation.checks_total,
            pass: evaluation.pass,
            violation: evaluation.violation,
            not_applicable: evaluation.not_applicable,
        });
    }

    if let Some(path) = &options.write_baseline {
        write_baseline(path, &current_findings)?;
    }

    let should_fail = options
        .fail_on
        .map(|threshold| has_findings_at_or_above(&current_findings, threshold))
        .unwrap_or(false);

    let mut baseline_meta = None;
    let mut resolved_findings = Vec::new();
    if let Some(path) = &options.baseline {
        let baseline = read_baseline(path)?;
        let comparison = apply_baseline(&mut current_findings, &baseline.findings, path);
        resolved_findings = comparison.resolved_findings;
        baseline_meta = Some(comparison.meta);
    }

    let should_fail_new = options
        .fail_on_new
        .map(|threshold| has_new_findings_at_or_above(&current_findings, threshold))
        .unwrap_or(false);

    let mut display_findings = current_findings;
    display_findings.extend(resolved_findings);
    display_findings.retain(|finding| finding.severity >= options.severity_threshold);

    let summary = Summary::from_counts(inventory.len(), &display_findings);
    let report = ScanReport {
        schema_version: "ef-scan-report/v0.1.1".to_string(),
        tool: "etherfence".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        status: "stable-local-scan".to_string(),
        scanned_root,
        inventory,
        findings: display_findings,
        summary,
        policy: policy_meta,
        baseline: baseline_meta,
    };
    let output = match options.format {
        OutputFormat::Human => etherfence_report::to_human(&report),
        OutputFormat::Json => etherfence_report::to_json(&report)?,
        OutputFormat::Markdown => etherfence_report::to_markdown(&report),
        OutputFormat::Sarif => etherfence_report::to_sarif(&report)?,
    };
    println!("{output}");
    if should_fail || should_fail_new {
        std::process::exit(2);
    }
    Ok(())
}

struct LoadedScanPolicy {
    policy: etherfence_policy::PolicyFile,
    display_path: String,
    source: String,
    profile: Option<String>,
}

fn load_scan_policy(options: &ScanOptions) -> Result<Option<LoadedScanPolicy>> {
    if let Some(path) = &options.policy {
        return Ok(Some(LoadedScanPolicy {
            policy: etherfence_policy::load_policy(path)?,
            display_path: path.display().to_string(),
            source: "file".to_string(),
            profile: None,
        }));
    }

    if let Some(profile) = &options.policy_profile {
        let built_in = find_built_in_policy(profile)?;
        return Ok(Some(LoadedScanPolicy {
            policy: etherfence_policy::parse_policy(built_in.content)
                .with_context(|| format!("parsing built-in policy profile {profile:?}"))?,
            display_path: format!("builtin:{profile}"),
            source: "built-in-profile".to_string(),
            profile: Some(profile.clone()),
        }));
    }

    Ok(None)
}

fn find_built_in_policy(profile: &str) -> Result<&'static BuiltInPolicy> {
    BUILT_IN_POLICIES
        .iter()
        .find(|policy| policy.name == profile)
        .with_context(|| {
            format!(
                "unknown built-in policy profile {profile:?}; run `etherfence policy list` to see available profiles"
            )
        })
}

struct BaselineApplyResult {
    meta: BaselineComparison,
    resolved_findings: Vec<Finding>,
}

fn apply_baseline(
    current: &mut [Finding],
    baseline_findings: &[Finding],
    baseline_path: &Path,
) -> BaselineApplyResult {
    let baseline_by_fingerprint: HashMap<String, Finding> = baseline_findings
        .iter()
        .cloned()
        .map(|finding| (finding.fingerprint.clone(), finding))
        .collect();
    let mut current_fingerprints = HashSet::new();
    let mut new = 0;
    let mut existing = 0;

    for finding in current.iter_mut() {
        current_fingerprints.insert(finding.fingerprint.clone());
        if baseline_by_fingerprint.contains_key(&finding.fingerprint) {
            finding.baseline_status = BaselineStatus::Existing;
            existing += 1;
        } else {
            finding.baseline_status = BaselineStatus::New;
            new += 1;
        }
    }

    let mut resolved_findings: Vec<Finding> = baseline_by_fingerprint
        .into_iter()
        .filter_map(|(fingerprint, mut finding)| {
            if current_fingerprints.contains(&fingerprint) {
                None
            } else {
                finding.baseline_status = BaselineStatus::Resolved;
                Some(finding)
            }
        })
        .collect();
    resolved_findings.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));

    let meta = BaselineComparison {
        baseline_path: baseline_path.display().to_string(),
        new,
        existing,
        resolved: resolved_findings.len(),
    };

    BaselineApplyResult {
        meta,
        resolved_findings,
    }
}

// `path` here is an explicit, trusted-operator CLI input (`--baseline`);
// see the doc comment on `read_bounded_text_file` for the CLI-vs-future-API
// path trust model this crate follows.
fn read_baseline(path: &Path) -> Result<BaselineFile> {
    let content = read_bounded_text_file(path, MAX_BASELINE_FILE_BYTES)
        .with_context(|| format!("reading baseline file {}", path.display()))?;
    serde_json::from_str(&content)
        .with_context(|| format!("parsing baseline file {}", path.display()))
}

fn write_baseline(path: &Path, findings: &[Finding]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating baseline directory {}", parent.display()))?;
    }
    let baseline = BaselineFile {
        schema_version: "ef-baseline/v0.1.3".to_string(),
        tool: "etherfence".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        created_at: None,
        findings: findings.to_vec(),
    };
    let content = serde_json::to_string_pretty(&baseline)?;
    fs::write(path, format!("{content}\n"))
        .with_context(|| format!("writing baseline file {}", path.display()))
}

fn has_findings_at_or_above(findings: &[Finding], threshold: Severity) -> bool {
    findings.iter().any(|finding| finding.severity >= threshold)
}

fn has_new_findings_at_or_above(findings: &[Finding], threshold: Severity) -> bool {
    findings.iter().any(|finding| {
        finding.baseline_status == BaselineStatus::New && finding.severity >= threshold
    })
}
