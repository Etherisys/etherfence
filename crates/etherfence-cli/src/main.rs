use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use etherfence_core::{
    BaselineComparison, BaselineFile, BaselineStatus, Finding, PolicyMetadata, ScanReport,
    Severity, Summary,
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
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
    Markdown,
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

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan {
            format,
            severity_threshold,
            fail_on,
            baseline,
            policy,
            write_baseline,
            fail_on_new,
            root,
        } => run_scan(ScanOptions {
            format,
            severity_threshold: severity_threshold.into(),
            fail_on: fail_on.map(Severity::from),
            baseline,
            policy,
            write_baseline,
            fail_on_new: fail_on_new.map(Severity::from),
            root,
        }),
    }
}

struct ScanOptions {
    format: OutputFormat,
    severity_threshold: Severity,
    fail_on: Option<Severity>,
    baseline: Option<PathBuf>,
    policy: Option<PathBuf>,
    write_baseline: Option<PathBuf>,
    fail_on_new: Option<Severity>,
    root: Option<PathBuf>,
}

fn run_scan(options: ScanOptions) -> Result<()> {
    if options.fail_on_new.is_some() && options.baseline.is_none() {
        anyhow::bail!("--fail-on-new requires --baseline");
    }

    let root = options
        .root
        .unwrap_or_else(etherfence_inventory::default_scan_root);
    let inventory = etherfence_inventory::discover(&root);
    let mut current_findings = etherfence_detectors::analyze(&inventory);
    let mut policy_meta = None;

    if let Some(path) = &options.policy {
        let policy = etherfence_policy::load_policy(path)?;
        let evaluation = etherfence_policy::evaluate_policy(&policy, &inventory)?;
        current_findings.extend(evaluation.findings);
        policy_meta = Some(PolicyMetadata {
            policy_path: path.display().to_string(),
            policy_name: evaluation.policy_name,
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
        status: "pre-alpha-scan-only".to_string(),
        scanned_root: root.display().to_string(),
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
    };
    println!("{output}");
    if should_fail || should_fail_new {
        std::process::exit(2);
    }
    Ok(())
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

fn read_baseline(path: &Path) -> Result<BaselineFile> {
    let content = fs::read_to_string(path)
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
