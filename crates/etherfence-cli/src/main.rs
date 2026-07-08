use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use etherfence_core::{ScanReport, Summary};
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
        /// Scan root. Defaults to HOME. Intended for tests and controlled scans.
        #[arg(long, hide = true)]
        root: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan { format, root } => run_scan(format, root),
    }
}

fn run_scan(format: OutputFormat, root: Option<PathBuf>) -> Result<()> {
    let root = root.unwrap_or_else(etherfence_inventory::default_scan_root);
    let inventory = etherfence_inventory::discover(&root);
    let findings = etherfence_detectors::analyze(&inventory);
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
    };
    println!("{output}");
    Ok(())
}
