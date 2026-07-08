use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use etherfence_core::{Finding, ScanReport, Severity, Summary};
use std::path::PathBuf;

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
            root,
        } => run_scan(
            format,
            severity_threshold.into(),
            fail_on.map(Severity::from),
            root,
        ),
    }
}

fn run_scan(
    format: OutputFormat,
    severity_threshold: Severity,
    fail_on: Option<Severity>,
    root: Option<PathBuf>,
) -> Result<()> {
    let root = root.unwrap_or_else(etherfence_inventory::default_scan_root);
    let inventory = etherfence_inventory::discover(&root);
    let all_findings = etherfence_detectors::analyze(&inventory);
    let should_fail = fail_on
        .map(|threshold| has_findings_at_or_above(&all_findings, threshold))
        .unwrap_or(false);
    let findings: Vec<Finding> = all_findings
        .into_iter()
        .filter(|finding| finding.severity >= severity_threshold)
        .collect();
    let summary = Summary::from_counts(inventory.len(), &findings);
    let report = ScanReport {
        schema_version: "ef-scan-report/v0.1.1".to_string(),
        tool: "etherfence".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        status: "pre-alpha-scan-only".to_string(),
        scanned_root: root.display().to_string(),
        inventory,
        findings,
        summary,
    };
    let output = match format {
        OutputFormat::Human => etherfence_report::to_human(&report),
        OutputFormat::Json => etherfence_report::to_json(&report)?,
        OutputFormat::Markdown => etherfence_report::to_markdown(&report),
    };
    println!("{output}");
    if should_fail {
        std::process::exit(2);
    }
    Ok(())
}

fn has_findings_at_or_above(findings: &[Finding], threshold: Severity) -> bool {
    findings.iter().any(|finding| finding.severity >= threshold)
}
