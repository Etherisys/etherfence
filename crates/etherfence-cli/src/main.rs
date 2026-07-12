mod banner;
mod ui;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use etherfence_core::{
    read_bounded_text_file, read_bounded_text_file_no_follow, BaselineComparison, BaselineFile,
    BaselineStatus, Finding, PolicyMetadata, PostureSummary, ScanReport, Severity, Summary,
    MAX_BASELINE_FILE_BYTES, MAX_CONFIG_FILE_BYTES,
};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
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
        /// Show full evidence in human output: schema/status metadata,
        /// rationale, recommendation, complete finding list, and full
        /// fingerprints. Human format only.
        #[arg(long)]
        verbose: bool,
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
    /// Safely detect, plan, apply, rollback, and doctor local MCP proxy onboarding.
    /// Run without a subcommand to launch the guided setup wizard.
    Setup {
        #[command(subcommand)]
        command: Option<SetupCommand>,
    },
}

#[derive(Debug, Subcommand)]
enum SetupCommand {
    /// Detect known AI client MCP configs without modifying files.
    Detect {
        /// Setup root. Defaults to HOME. Intended for tests and controlled local onboarding.
        #[arg(long, hide = true)]
        root: Option<PathBuf>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = SetupOutputFormat::Human)]
        format: SetupOutputFormat,
    },
    /// Print the fixed v1.2.0 client compatibility/catalog matrix
    /// (fixture-verified / detect-only / advisory-only support tiers, plus
    /// local presence) without modifying files.
    Catalog {
        /// Setup root. Defaults to HOME. Intended for tests and controlled local onboarding.
        #[arg(long, hide = true)]
        root: Option<PathBuf>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = SetupOutputFormat::Human)]
        format: SetupOutputFormat,
    },
    /// Show the redacted wrapping plan without modifying files.
    Plan {
        /// Setup root. Defaults to HOME. Intended for tests and controlled local onboarding.
        #[arg(long, hide = true)]
        root: Option<PathBuf>,
    },
    /// Back up supported configs, generate policies, and wrap eligible stdio MCP servers.
    Apply {
        /// Setup root. Defaults to HOME. Intended for tests and controlled local onboarding.
        #[arg(long, hide = true)]
        root: Option<PathBuf>,
    },
    /// Restore EtherFence-created setup backups.
    Rollback {
        /// Setup root. Defaults to HOME. Intended for tests and controlled local onboarding.
        #[arg(long, hide = true)]
        root: Option<PathBuf>,
    },
    /// Check setup health without starting MCP servers.
    Doctor {
        /// Setup root. Defaults to HOME. Intended for tests and controlled local onboarding.
        #[arg(long, hide = true)]
        root: Option<PathBuf>,
    },
    /// Write and check deterministic MCP server integrity baselines
    /// (schema ef-setup-baseline/v0.1) and detect drift against them
    /// (schema ef-setup-baseline-comparison/v0.1). Read-only over the
    /// scanned root; never auto-updates or auto-accepts a baseline.
    Baseline {
        #[command(subcommand)]
        command: SetupBaselineCommand,
    },
}

#[derive(Debug, Subcommand)]
enum SetupBaselineCommand {
    /// Write a new deterministic integrity baseline. Refuses to overwrite
    /// an existing output file unless `--overwrite` is passed.
    Write {
        /// Setup root. Defaults to HOME. Intended for tests and controlled local onboarding.
        #[arg(long, hide = true)]
        root: Option<PathBuf>,
        /// Baseline output file (schema ef-setup-baseline/v0.1).
        #[arg(long)]
        output: PathBuf,
        /// Allow overwriting an existing output file.
        #[arg(long)]
        overwrite: bool,
    },
    /// Compare current MCP server state against a previously written
    /// baseline. Never modifies the baseline file.
    Check {
        /// Setup root. Defaults to HOME. Intended for tests and controlled local onboarding.
        #[arg(long, hide = true)]
        root: Option<PathBuf>,
        /// Baseline file to compare against (schema ef-setup-baseline/v0.1).
        #[arg(long)]
        baseline: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = SetupOutputFormat::Human)]
        format: SetupOutputFormat,
        /// Exit non-zero if any server is new, changed, missing, or unverifiable.
        #[arg(long)]
        fail_on_drift: bool,
        /// Exit non-zero if any server is new.
        #[arg(long)]
        fail_on_new: bool,
        /// Exit non-zero if any server's aggregate risk increased since the baseline.
        #[arg(long)]
        fail_on_risk_increase: bool,
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
    McpPolicyProfile {
        name: "github-scoped-orgs",
        description:
            "v0.2: GitHub issue tool restricted to a named organization/repository via enum/prefix field guards.",
        content: include_str!("../../../examples/policies/mcp-github-scoped-orgs.toml"),
    },
    McpPolicyProfile {
        name: "messaging-named-destinations",
        description:
            "v0.2: Messaging tool restricted to named destinations, with a forbidden bypass key.",
        content: include_str!("../../../examples/policies/mcp-messaging-named-destinations.toml"),
    },
    McpPolicyProfile {
        name: "browser-approved-hosts",
        description:
            "v0.2: Browser/API tool restricted to approved HTTPS hosts via the URL field guard.",
        content: include_str!("../../../examples/policies/mcp-browser-approved-hosts.toml"),
    },
    McpPolicyProfile {
        name: "readonly-operation-guard",
        description:
            "v0.2: General-purpose tool restricted to read-only operations with numeric and nested-selector field guards.",
        content: include_str!("../../../examples/policies/mcp-readonly-operation-guard.toml"),
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

/// Output format for the `setup` command family (`catalog`, `detect`).
/// Narrower than `OutputFormat`: `Markdown`/`Sarif` have no defined meaning
/// for a client/capability catalog (research.md Decision 5).
#[derive(Debug, Clone, Copy, ValueEnum)]
enum SetupOutputFormat {
    Human,
    Json,
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

/// Classifies each CLI command into a banner output mode.
///
/// Human-facing commands show the startup splash on an interactive color
/// terminal; machine formats (JSON, Markdown, SARIF, raw TOML) and MCP
/// protocol traffic never do. The banner module additionally suppresses
/// the splash for redirected stdout, CI, NO_COLOR, CLICOLOR=0, and
/// TERM=dumb.
fn command_banner_mode(command: &Command) -> banner::OutputMode {
    match command {
        Command::Scan { format, .. } => match format {
            OutputFormat::Human => banner::OutputMode::Human,
            OutputFormat::Json | OutputFormat::Markdown | OutputFormat::Sarif => {
                banner::OutputMode::Machine
            }
        },
        // `policy list`/`policy show` emit machine-consumable lists and
        // raw TOML for piping into files.
        Command::Policy { .. } => banner::OutputMode::Machine,
        // The proxy speaks MCP JSON-RPC over stdio; nothing may pollute it.
        Command::McpProxy { .. } => banner::OutputMode::Protocol,
        Command::McpPolicy { command } => match command {
            // `mcp-policy init` emits raw policy TOML for piping.
            McpPolicyCommand::Init { .. } => banner::OutputMode::Machine,
            McpPolicyCommand::Validate { .. }
            | McpPolicyCommand::Explain { .. }
            | McpPolicyCommand::Check { .. } => banner::OutputMode::Human,
        },
        Command::Setup { command } => match command {
            // Bare `etherfence setup` launches the interactive wizard.
            None => banner::OutputMode::Human,
            Some(SetupCommand::Detect { format, .. })
            | Some(SetupCommand::Catalog { format, .. }) => match format {
                SetupOutputFormat::Human => banner::OutputMode::Human,
                SetupOutputFormat::Json => banner::OutputMode::Machine,
            },
            Some(SetupCommand::Baseline { command }) => match command {
                SetupBaselineCommand::Write { .. } => banner::OutputMode::Human,
                SetupBaselineCommand::Check { format, .. } => match format {
                    SetupOutputFormat::Human => banner::OutputMode::Human,
                    SetupOutputFormat::Json => banner::OutputMode::Machine,
                },
            },
            Some(SetupCommand::Plan { .. })
            | Some(SetupCommand::Apply { .. })
            | Some(SetupCommand::Rollback { .. })
            | Some(SetupCommand::Doctor { .. }) => banner::OutputMode::Human,
        },
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    banner::print_startup_banner(command_banner_mode(&cli.command));
    match cli.command {
        Command::Scan {
            format,
            verbose,
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
            verbose,
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
        Command::Setup { command } => run_setup_command(command),
    }
}

fn run_setup_command(command: Option<SetupCommand>) -> Result<()> {
    let cmd = match command {
        Some(cmd) => cmd,
        None => return run_setup_wizard(),
    };
    match cmd {
        SetupCommand::Detect { root, format } => {
            let root = setup_root(root);
            let detections = etherfence_setup::detect(&root);
            match format {
                SetupOutputFormat::Human => print!("{}", render_setup_detect(&root, &detections)),
                SetupOutputFormat::Json => {
                    print!("{}", render_setup_detect_json(&root, &detections)?)
                }
            }
            Ok(())
        }
        SetupCommand::Catalog { root, format } => {
            let root = setup_root(root);
            let entries = etherfence_setup::catalog(&root);
            match format {
                SetupOutputFormat::Human => {
                    print!("{}", render_setup_catalog_human(&root, &entries))
                }
                SetupOutputFormat::Json => {
                    print!("{}", render_setup_catalog_json(&root, &entries)?)
                }
            }
            Ok(())
        }
        SetupCommand::Plan { root } => {
            let root = setup_root(root);
            let plan = etherfence_setup::plan(&root);
            print!("{}", render_setup_plan(&plan));
            Ok(())
        }
        SetupCommand::Apply { root } => etherfence_setup::apply(&setup_root(root)),
        SetupCommand::Rollback { root } => etherfence_setup::rollback(&setup_root(root)),
        SetupCommand::Doctor { root } => {
            let root = setup_root(root);
            let report = etherfence_setup::doctor(&root);
            print!("{}", render_setup_doctor(&report));
            Ok(())
        }
        SetupCommand::Baseline { command } => run_setup_baseline_command(command),
    }
}

fn setup_root(root: Option<PathBuf>) -> PathBuf {
    root.unwrap_or_else(etherfence_inventory::default_scan_root)
}

fn run_setup_baseline_command(command: SetupBaselineCommand) -> Result<()> {
    match command {
        SetupBaselineCommand::Write {
            root,
            output,
            overwrite,
        } => run_setup_baseline_write(setup_root(root), &output, overwrite),
        SetupBaselineCommand::Check {
            root,
            baseline,
            format,
            fail_on_drift,
            fail_on_new,
            fail_on_risk_increase,
        } => run_setup_baseline_check(
            setup_root(root),
            &baseline,
            format,
            fail_on_drift,
            fail_on_new,
            fail_on_risk_increase,
        ),
    }
}

fn run_setup_baseline_write(root: PathBuf, output: &Path, overwrite: bool) -> Result<()> {
    let items = etherfence_inventory::discover(&root);
    let baseline = etherfence_setup::build_baseline(&root, &items);
    let content = serde_json::to_string_pretty(&baseline)
        .context("serializing MCP server integrity baseline")?;
    let bytes = format!("{content}\n");
    if let Some(parent) = output.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| {
                format!("creating baseline output directory {}", parent.display())
            })?;
        }
    }
    if overwrite {
        // Write to a temp file in the same directory, then atomically
        // rename over the destination. `fs::rename` replaces whatever is
        // at `output` (including a symlink, which it replaces rather than
        // follows) as a single filesystem operation — there is no window
        // where a concurrent reader could see a partially written file.
        atomic_write_baseline(output, bytes.as_bytes())?;
    } else {
        // Exclusive creation closes the TOCTOU race a separate
        // `output.exists()` check-then-`fs::write()` would have: the
        // open+create is a single atomic syscall, so a file (or symlink)
        // created at `output` between a hypothetical check and write can
        // never be silently overwritten. `create_new` also fails if
        // `output` is a pre-existing symlink (even a dangling one), so a
        // fresh baseline is never written through a symlink at this path.
        use std::io::Write as _;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)
            .map_err(|error| {
                if error.kind() == io::ErrorKind::AlreadyExists {
                    anyhow::anyhow!(
                        "refusing to overwrite existing baseline file {} (pass --overwrite to replace it)",
                        output.display()
                    )
                } else {
                    anyhow::Error::new(error).context(format!(
                        "creating baseline output file {}",
                        output.display()
                    ))
                }
            })?;
        file.write_all(bytes.as_bytes())
            .with_context(|| format!("writing baseline file {}", output.display()))?;
    }
    print!(
        "{}",
        render_setup_baseline_write_human(&root, output, baseline.servers.len())
    );
    Ok(())
}

/// A `u64` that is unpredictable in practice (a fresh `RandomState`'s
/// internal SipHash keys are seeded from OS randomness, mixed here with a
/// high-resolution timestamp and the process id) without adding a new
/// dependency for it. Used only to name a temp file an attacker cannot
/// pre-stage a symlink at — this is not a cryptographic primitive.
fn unpredictable_suffix() -> u64 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut hasher = RandomState::new().build_hasher();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    hasher.write_u128(nanos);
    hasher.write_u32(std::process::id());
    hasher.finish()
}

/// Writes `content` to a freshly, exclusively created temp file in
/// `path`'s directory, then atomically renames it over `path`. Used only
/// for the explicit `--overwrite` case; see `run_setup_baseline_write` for
/// the exclusive-create path used when `--overwrite` is absent.
///
/// The temp filename is unpredictable and opened with `create_new` (never
/// a plain `fs::write`, which both creates *and* follows an existing
/// symlink): an attacker who can write into the same directory cannot
/// pre-stage a symlink at the exact path this function will use and have
/// EtherFence write through it — `create_new` fails outright if anything,
/// including a symlink, already exists at the candidate path, and a
/// bounded retry loop picks a fresh candidate on that specific collision.
fn atomic_write_baseline(path: &Path, content: &[u8]) -> Result<()> {
    use std::io::Write as _;

    let dir = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "baseline".to_string());

    const MAX_ATTEMPTS: u32 = 16;
    let mut tmp_file = None;
    let mut tmp_path = None;
    for _ in 0..MAX_ATTEMPTS {
        let candidate = dir.join(format!(
            ".{file_name}.tmp-etherfence-{:016x}",
            unpredictable_suffix()
        ));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => {
                tmp_file = Some(file);
                tmp_path = Some(candidate);
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(anyhow::Error::new(error)
                    .context(format!("creating temp baseline file in {}", dir.display())))
            }
        }
    }
    let (mut file, tmp) = tmp_file
        .zip(tmp_path)
        .context("failed to create a unique temp baseline file after repeated attempts")?;

    if let Err(error) = file.write_all(content) {
        let _ = fs::remove_file(&tmp);
        return Err(anyhow::Error::new(error)
            .context(format!("writing temp baseline file {}", tmp.display())));
    }
    drop(file);

    fs::rename(&tmp, path).map_err(|error| {
        let _ = fs::remove_file(&tmp);
        anyhow::Error::new(error).context(format!(
            "atomically replacing {} with {}",
            path.display(),
            tmp.display()
        ))
    })?;
    Ok(())
}

fn read_setup_baseline(path: &Path) -> Result<etherfence_setup::BaselineDocument> {
    // No-follow: a `--baseline` path that is a symlink must fail closed
    // rather than silently comparing against whatever it happens to point
    // at (see `etherfence_core::read_bounded_text_file_no_follow`'s
    // doc comment for the exact race this closes versus the general
    // `read_bounded_text_file` helper used elsewhere in this CLI).
    let content = read_bounded_text_file_no_follow(path, MAX_BASELINE_FILE_BYTES)
        .with_context(|| format!("reading baseline file {}", path.display()))?;
    let baseline: etherfence_setup::BaselineDocument = serde_json::from_str(&content)
        .with_context(|| format!("parsing baseline file {}", path.display()))?;
    etherfence_setup::validate_baseline(&baseline).map_err(|error| {
        anyhow::anyhow!(
            "baseline file {} failed consistency validation: {error}",
            path.display()
        )
    })?;
    Ok(baseline)
}

fn run_setup_baseline_check(
    root: PathBuf,
    baseline_path: &Path,
    format: SetupOutputFormat,
    fail_on_drift: bool,
    fail_on_new: bool,
    fail_on_risk_increase: bool,
) -> Result<()> {
    let baseline = read_setup_baseline(baseline_path)?;
    let items = etherfence_inventory::discover(&root);
    let report = etherfence_setup::compare(&baseline, &items, &root);

    match format {
        SetupOutputFormat::Human => {
            print!(
                "{}",
                render_setup_baseline_check_human(&root, baseline_path, &report)
            )
        }
        SetupOutputFormat::Json => {
            print!("{}", render_setup_baseline_check_json(&report)?)
        }
    }

    let should_fail = (fail_on_drift && etherfence_setup::drift_gate_triggered(&report))
        || (fail_on_new && etherfence_setup::new_gate_triggered(&report))
        || (fail_on_risk_increase && etherfence_setup::risk_increase_gate_triggered(&report));
    if should_fail {
        std::process::exit(2);
    }
    Ok(())
}

fn render_setup_baseline_write_human(root: &Path, output: &Path, server_count: usize) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "EtherFence setup baseline write");
    let _ = writeln!(out, "Root: {}", root.display());
    let _ = writeln!(
        out,
        "Mode: read-only over the scanned root; wrote a new baseline file."
    );
    let _ = writeln!(
        out,
        "Wrote baseline ({server_count} servers) to {}",
        output.display()
    );
    out
}

fn render_setup_baseline_check_human(
    root: &Path,
    baseline_path: &Path,
    report: &etherfence_setup::ComparisonReport,
) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "EtherFence setup baseline check");
    let _ = writeln!(out, "Root: {}", root.display());
    let _ = writeln!(out, "Baseline: {}", baseline_path.display());
    let _ = writeln!(out, "Mode: read-only; the baseline file was not modified.");
    let _ = writeln!(out);

    let mut unchanged = 0usize;
    let mut changed = 0usize;
    let mut new = 0usize;
    let mut missing = 0usize;
    let mut unverifiable = 0usize;

    for entry in &report.entries {
        match entry.status {
            etherfence_setup::ComparisonStatus::Unchanged => unchanged += 1,
            etherfence_setup::ComparisonStatus::Changed => changed += 1,
            etherfence_setup::ComparisonStatus::New => new += 1,
            etherfence_setup::ComparisonStatus::Missing => missing += 1,
            etherfence_setup::ComparisonStatus::Unverifiable => unverifiable += 1,
        }
        if entry.status == etherfence_setup::ComparisonStatus::Unchanged {
            continue;
        }
        let _ = writeln!(
            out,
            "- {}:{} [{}] at {}",
            entry.agent,
            entry.server_name,
            comparison_status_label(entry.status),
            entry.config_source
        );
        let _ = writeln!(out, "  transport={}", transport_label(entry.transport));
        let reasons: Vec<&str> = entry
            .reasons
            .iter()
            .map(|r| drift_reason_label(*r))
            .collect();
        let _ = writeln!(out, "  reasons: {}", reasons.join(", "));
        let risk_from = entry
            .baseline_risk
            .map(|s| kebab_label(&s))
            .unwrap_or_else(|| "n/a".to_string());
        let risk_to = entry
            .current_risk
            .map(|s| kebab_label(&s))
            .unwrap_or_else(|| "n/a".to_string());
        let _ = writeln!(
            out,
            "  risk: {risk_from} -> {risk_to} ({})",
            risk_direction_label(entry.risk_direction)
        );
    }

    let _ = writeln!(
        out,
        "Summary: {unchanged} unchanged, {changed} changed, {new} new, {missing} missing, {unverifiable} unverifiable"
    );
    out
}

fn render_setup_baseline_check_json(report: &etherfence_setup::ComparisonReport) -> Result<String> {
    Ok(format!("{}\n", serde_json::to_string_pretty(report)?))
}

fn comparison_status_label(value: etherfence_setup::ComparisonStatus) -> &'static str {
    match value {
        etherfence_setup::ComparisonStatus::Unchanged => "unchanged",
        etherfence_setup::ComparisonStatus::New => "new",
        etherfence_setup::ComparisonStatus::Changed => "changed",
        etherfence_setup::ComparisonStatus::Missing => "missing",
        etherfence_setup::ComparisonStatus::Unverifiable => "unverifiable",
    }
}

fn drift_reason_label(value: etherfence_setup::DriftReason) -> &'static str {
    match value {
        etherfence_setup::DriftReason::ExecutableHashChanged => "executable-hash-changed",
        etherfence_setup::DriftReason::CommandChanged => "command-changed",
        etherfence_setup::DriftReason::ArgumentsChanged => "arguments-changed",
        etherfence_setup::DriftReason::PackageIdentityChanged => "package-identity-changed",
        etherfence_setup::DriftReason::PackageVersionChanged => "package-version-changed",
        etherfence_setup::DriftReason::EnvironmentVariableNamesChanged => {
            "environment-variable-names-changed"
        }
        etherfence_setup::DriftReason::TransportChanged => "transport-changed",
        etherfence_setup::DriftReason::ServerAdded => "server-added",
        etherfence_setup::DriftReason::ServerRemoved => "server-removed",
        etherfence_setup::DriftReason::CapabilitySetChanged => "capability-set-changed",
        etherfence_setup::DriftReason::TrustIndicatorSetChanged => "trust-indicator-set-changed",
        etherfence_setup::DriftReason::ArtifactIdentityChanged => "artifact-identity-changed",
        etherfence_setup::DriftReason::ConfigurationRiskChanged => "configuration-risk-changed",
        etherfence_setup::DriftReason::RiskIncreased => "risk-increased",
        etherfence_setup::DriftReason::ExecutableBecameUnverifiable => {
            "executable-became-unverifiable"
        }
    }
}

fn risk_direction_label(value: etherfence_setup::RiskDirection) -> &'static str {
    match value {
        etherfence_setup::RiskDirection::Increased => "increased",
        etherfence_setup::RiskDirection::Decreased => "decreased",
        etherfence_setup::RiskDirection::Unchanged => "unchanged",
        etherfence_setup::RiskDirection::NotApplicable => "not-applicable",
    }
}

fn render_setup_detect(root: &Path, detections: &[etherfence_setup::SetupDetection]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "EtherFence setup detect");
    let _ = writeln!(out, "Root: {}", root.display());
    let _ = writeln!(
        out,
        "Mode: read-only; no configs, policies, backups, or state were modified."
    );
    if detections.is_empty() {
        let _ = writeln!(out, "Known MCP configs: none detected");
        return out;
    }
    for detection in detections {
        let _ = writeln!(
            out,
            "- {} [{}] at {}",
            detection.agent,
            write_support_label(detection.write_support),
            detection.config_path
        );
        if detection.servers.is_empty() {
            let _ = writeln!(out, "  MCP servers: none");
        }
        for server in &detection.servers {
            let _ = writeln!(
                out,
                "  - {} transport={} wrapped={}",
                server.name,
                transport_label(server.transport),
                server.wrapped
            );
            let labels: Vec<&str> = server
                .capabilities
                .labels
                .iter()
                .copied()
                .map(etherfence_setup::human_label)
                .collect();
            let _ = writeln!(out, "    capabilities: {}", labels.join(", "));
            let _ = writeln!(
                out,
                "    recommendation: {} (needs-review={}) — {}",
                recommendation_tier_label(server.recommendation.tier),
                server.recommendation.needs_review,
                server.recommendation.rationale
            );
            let trust = &server.trust_assessment;
            let _ = writeln!(
                out,
                "    trust: artifact-identity={} configuration-risk={} aggregate={} needs-review={}",
                kebab_label(&trust.artifact_identity),
                kebab_label(&trust.configuration_risk),
                kebab_label(&trust.aggregate),
                trust.needs_review
            );
            let _ = writeln!(
                out,
                "    trust artifact-identity rationale: {}",
                trust.artifact_identity_rationale
            );
            if trust.indicators.is_empty() {
                let _ = writeln!(out, "    trust indicators: none");
            } else {
                let _ = writeln!(out, "    trust indicators:");
                for indicator in &trust.indicators {
                    let _ = writeln!(
                        out,
                        "      - {} [{}] {}: {}",
                        indicator.id,
                        kebab_label(&indicator.severity),
                        kebab_label(&indicator.category),
                        indicator.summary
                    );
                }
            }
        }
        for note in &detection.notes {
            let _ = writeln!(out, "  note: {note}");
        }
    }
    out
}

fn render_setup_detect_json(
    root: &Path,
    detections: &[etherfence_setup::SetupDetection],
) -> Result<String> {
    let report = serde_json::json!({
        "etherfenceSchemaVersion": "ef-setup-detect/v0.2",
        "root": root.display().to_string(),
        "detections": detections,
    });
    Ok(format!("{}\n", serde_json::to_string_pretty(&report)?))
}

fn render_setup_catalog_human(root: &Path, entries: &[etherfence_setup::CatalogEntry]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "EtherFence setup catalog");
    let _ = writeln!(out, "Root: {}", root.display());
    let _ = writeln!(
        out,
        "Mode: read-only; no configs, policies, backups, or state were modified."
    );
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Client                  Tier               Found  Config path(s)"
    );
    for entry in entries {
        let paths = if entry.config_paths.is_empty() {
            "-".to_string()
        } else {
            entry.config_paths.join(", ")
        };
        let _ = writeln!(
            out,
            "{:<23} {:<18} {:<6} {}",
            entry.client.display_name(),
            catalog_tier_label(entry.tier),
            if entry.found_locally { "yes" } else { "no" },
            paths
        );
    }
    out
}

fn render_setup_catalog_json(
    root: &Path,
    entries: &[etherfence_setup::CatalogEntry],
) -> Result<String> {
    let report = serde_json::json!({
        "etherfenceSchemaVersion": "ef-setup-catalog/v0.1",
        "root": root.display().to_string(),
        "clients": entries,
    });
    Ok(format!("{}\n", serde_json::to_string_pretty(&report)?))
}

fn catalog_tier_label(value: etherfence_setup::CatalogSupportTier) -> &'static str {
    match value {
        etherfence_setup::CatalogSupportTier::FixtureVerified => "fixture-verified",
        etherfence_setup::CatalogSupportTier::DetectOnly => "detect-only",
        etherfence_setup::CatalogSupportTier::AdvisoryOnly => "advisory-only",
        etherfence_setup::CatalogSupportTier::Unknown => "unknown",
    }
}

/// Renders any `Serialize` enum (trust-assessment vocabulary/severity/
/// category types) using its existing kebab-case JSON token, so CLI human
/// output never drifts from the JSON contract via a second hand-maintained
/// label table.
fn kebab_label(value: &impl serde::Serialize) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}

fn recommendation_tier_label(value: etherfence_setup::RecommendationTier) -> &'static str {
    match value {
        etherfence_setup::RecommendationTier::Deny => "deny",
        etherfence_setup::RecommendationTier::Allow => "allow",
    }
}

fn render_setup_plan(plan: &etherfence_setup::SetupPlan) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "EtherFence setup plan");
    let _ = writeln!(out, "Root: {}", plan.root);
    let _ = writeln!(out, "Mode: read-only; this is a redacted proposal only.");
    if plan.actions.is_empty() {
        let _ = writeln!(out, "Actions: none");
        return out;
    }
    let _ = writeln!(out, "Actions:");
    for action in &plan.actions {
        let _ = writeln!(
            out,
            "- {}:{} -> {} ({})",
            action.agent,
            action.server_name,
            action_kind_label(action.action),
            action.reason
        );
        let _ = writeln!(out, "  config: {}", action.config_path);
    }
    out
}

fn render_setup_doctor(report: &etherfence_setup::DoctorReport) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "EtherFence setup doctor");
    let _ = writeln!(out, "Root: {}", report.root);
    let _ = writeln!(out, "Mode: read-only; MCP servers were not started.");
    for check in &report.checks {
        let _ = writeln!(
            out,
            "- {} {}: {}",
            doctor_status_label(check.status),
            check.subject,
            check.message
        );
    }
    out
}

fn write_support_label(value: etherfence_setup::WriteSupport) -> &'static str {
    match value {
        etherfence_setup::WriteSupport::Supported => "write-supported",
        etherfence_setup::WriteSupport::AdvisoryOnly => "advisory-only",
    }
}

fn transport_label(value: etherfence_setup::ServerTransport) -> &'static str {
    match value {
        etherfence_setup::ServerTransport::Stdio => "stdio",
        etherfence_setup::ServerTransport::Remote => "remote",
        etherfence_setup::ServerTransport::Unknown => "unknown",
    }
}

fn action_kind_label(value: etherfence_setup::SetupActionKind) -> &'static str {
    match value {
        etherfence_setup::SetupActionKind::Wrap => "wrap",
        etherfence_setup::SetupActionKind::SkipAlreadyWrapped => "skip-already-wrapped",
        etherfence_setup::SetupActionKind::AdvisoryOnly => "advisory-only",
        etherfence_setup::SetupActionKind::SkipNonStdio => "skip-non-stdio",
    }
}

fn doctor_status_label(value: etherfence_setup::DoctorStatus) -> &'static str {
    match value {
        etherfence_setup::DoctorStatus::Ok => "OK",
        etherfence_setup::DoctorStatus::Warn => "WARN",
        etherfence_setup::DoctorStatus::Fail => "FAIL",
    }
}

fn run_setup_wizard() -> Result<()> {
    use dialoguer::console::Term;
    use dialoguer::{Confirm, Input, MultiSelect, Select};
    use std::collections::HashMap;

    let term = Term::stderr();
    if !term.is_term() {
        anyhow::bail!(
            "The guided setup wizard requires an interactive terminal (TTY).\n\
             For non-interactive use, run one of the explicit subcommands:\n\n  \
             etherfence setup detect        Detect AI client MCP configs\n  \
             etherfence setup catalog       Show client compatibility matrix\n  \
             etherfence setup plan          Show wrapping plan\n  \
             etherfence setup apply         Apply setup changes\n  \
             etherfence setup rollback      Restore setup backups\n  \
             etherfence setup doctor        Check setup health\n  \
             etherfence setup baseline      Manage integrity baselines\n\n\
             See etherfence setup --help for more details."
        );
    }

    // ---- helpers for interrupt-safe dialoguer calls ----
    fn interact_or_bail<T>(result: Result<T, dialoguer::Error>) -> Result<T> {
        match result {
            Ok(v) => Ok(v),
            Err(dialoguer::Error::IO(e)) if e.kind() == std::io::ErrorKind::Interrupted => {
                anyhow::bail!("Setup wizard cancelled by user (Ctrl+C). No changes were made.")
            }
            Err(e) => Err(anyhow::Error::from(e)),
        }
    }

    fn interact_opt_or_bail<T>(result: Result<Option<T>, dialoguer::Error>) -> Result<Option<T>> {
        match result {
            Ok(v) => Ok(v),
            Err(dialoguer::Error::IO(e)) if e.kind() == std::io::ErrorKind::Interrupted => {
                anyhow::bail!("Setup wizard cancelled by user (Ctrl+C). No changes were made.")
            }
            Err(e) => Err(anyhow::Error::from(e)),
        }
    }

    fn interact_text_or_bail(result: Result<String, dialoguer::Error>) -> Result<String> {
        match result {
            Ok(v) => Ok(v),
            Err(dialoguer::Error::IO(e)) if e.kind() == std::io::ErrorKind::Interrupted => {
                anyhow::bail!("Setup wizard cancelled by user (Ctrl+C). No changes were made.")
            }
            Err(e) => Err(anyhow::Error::from(e)),
        }
    }

    let root = etherfence_inventory::default_scan_root();
    let theme = ui::UiTheme::for_stderr();

    /// Plain-text risk badge for prompt items (dialoguer renders items
    /// itself, so styled text is kept out of selectable rows).
    fn plain_risk_badge(status: etherfence_setup::AggregateAssessmentStatus) -> &'static str {
        match status {
            etherfence_setup::AggregateAssessmentStatus::HighRisk => "HIGH RISK",
            etherfence_setup::AggregateAssessmentStatus::NeedsReview => "REVIEW",
            etherfence_setup::AggregateAssessmentStatus::Unknown => "UNKNOWN",
            _ => "OK",
        }
    }

    fn invocation_line(command: &str, args: &[String]) -> String {
        if args.is_empty() {
            command.to_string()
        } else {
            format!("{command} {}", args.join(" "))
        }
    }

    // -----------------------------------------------------------------
    // Step 1 - Scan
    // -----------------------------------------------------------------
    eprintln!();
    eprintln!("{}", theme.step(1, 7, "Scan environment"));

    let detections = etherfence_setup::detect(&root);
    if detections.is_empty() {
        eprintln!("No known AI client MCP configurations were detected.");
        eprintln!("Run 'etherfence setup catalog' to see which clients EtherFence can detect.");
        return Ok(());
    }

    // Group detections by client so one client with several config files
    // reads as one client. `can_configure` is true when at least one of
    // its configs is writable by setup apply.
    struct ClientGroup {
        agent: String,
        detection_indices: Vec<usize>,
        server_count: usize,
        can_configure: bool,
    }
    let mut clients: Vec<ClientGroup> = Vec::new();
    for (index, detection) in detections.iter().enumerate() {
        let writable = detection.write_support == etherfence_setup::WriteSupport::Supported;
        match clients
            .iter_mut()
            .find(|group| group.agent == detection.agent)
        {
            Some(group) => {
                group.detection_indices.push(index);
                group.server_count += detection.servers.len();
                group.can_configure |= writable;
            }
            None => clients.push(ClientGroup {
                agent: detection.agent.clone(),
                detection_indices: vec![index],
                server_count: detection.servers.len(),
                can_configure: writable,
            }),
        }
    }

    for group in &clients {
        let marker = if group.server_count > 0 {
            theme.success.apply_to("\u{2713}").to_string()
        } else {
            theme.muted.apply_to("\u{25cb}").to_string()
        };
        eprintln!(
            "{marker} {}{}   {}",
            ui::pad(&group.agent, 20),
            ui::pad(&ui::count_servers(group.server_count), 16),
            theme.support_badge(group.can_configure)
        );
    }
    eprintln!();

    // -----------------------------------------------------------------
    // Step 2 - Choose AI clients
    // -----------------------------------------------------------------
    eprintln!("{}", theme.step(2, 7, "Choose AI clients"));
    eprintln!("Select the clients EtherFence should configure.");
    eprintln!(
        "{}",
        theme
            .muted
            .apply_to("Detect-only clients can be selected for review, but cannot be modified.")
    );
    eprintln!();

    let client_prompt_items: Vec<String> = clients
        .iter()
        .map(|group| {
            format!(
                "{}{}   {}",
                ui::pad(&group.agent, 20),
                ui::pad(&ui::count_servers(group.server_count), 16),
                if group.can_configure {
                    "CAN CONFIGURE"
                } else {
                    "DETECT ONLY"
                }
            )
        })
        .collect();

    let client_indices = interact_opt_or_bail(
        MultiSelect::new()
            .items(&client_prompt_items)
            .with_prompt("Space selects, Enter continues")
            .interact_opt(),
    )?;

    let client_indices = match client_indices {
        Some(idx) if !idx.is_empty() => idx,
        _ => {
            eprintln!("No clients selected. Exiting wizard; no changes were made.");
            return Ok(());
        }
    };
    let selected_servers_total: usize = client_indices
        .iter()
        .map(|&idx| clients[idx].server_count)
        .sum();
    eprintln!(
        "Selected: {} client(s) · {}\n",
        client_indices.len(),
        ui::count_servers(selected_servers_total)
    );

    // -----------------------------------------------------------------
    // Step 3 - Choose MCP servers (per client configuration)
    // -----------------------------------------------------------------
    eprintln!("{}", theme.step(3, 7, "Choose MCP servers"));

    let mut version_pins: HashMap<etherfence_setup::WizardServerId, String> = HashMap::new();
    let mut policy_types: HashMap<etherfence_setup::WizardServerId, etherfence_setup::PolicyType> =
        HashMap::new();
    let mut selected_ids: Vec<etherfence_setup::WizardServerId> = Vec::new();

    for &client_idx in &client_indices {
        let group = &clients[client_idx];
        for &idx in &group.detection_indices {
            let client = &detections[idx];
            if client.servers.is_empty() {
                continue;
            }

            eprintln!();
            eprintln!(
                "{} \u{b7} {}",
                theme.heading.apply_to(&client.agent),
                theme.path.apply_to(&client.config_path)
            );

            if client.write_support != etherfence_setup::WriteSupport::Supported {
                eprintln!(
                    "{}",
                    theme.muted.apply_to(
                        "EtherFence can detect but not modify this configuration; servers are listed for review only."
                    )
                );
                for server in &client.servers {
                    eprintln!(
                        "  {} {}",
                        ui::pad(&server.name, 24),
                        plain_risk_badge(server.trust_assessment.aggregate)
                    );
                }
                continue;
            }

            // Already-protected and remote servers are shown for context
            // but are not selectable: the wizard cannot change them, so
            // offering them would only produce false-success plans.
            let mut selectable: Vec<usize> = Vec::new();
            for (index, server) in client.servers.iter().enumerate() {
                if server.wrapped {
                    eprintln!(
                        "  {} {}",
                        ui::pad(&server.name, 24),
                        theme.muted.apply_to("already protected — no action needed")
                    );
                } else if server.transport != etherfence_setup::ServerTransport::Stdio {
                    eprintln!(
                        "  {} {}",
                        ui::pad(&server.name, 24),
                        theme.muted.apply_to("remote server — cannot be wrapped")
                    );
                } else {
                    selectable.push(index);
                }
            }
            if selectable.is_empty() {
                continue;
            }

            let server_items: Vec<String> = selectable
                .iter()
                .map(|&index| {
                    let server = &client.servers[index];
                    format!(
                        "{} {}",
                        ui::pad(&server.name, 24),
                        plain_risk_badge(server.trust_assessment.aggregate)
                    )
                })
                .collect();

            let picks = interact_opt_or_bail(
                MultiSelect::new()
                    .items(&server_items)
                    .with_prompt("Space selects, Enter continues")
                    .interact_opt(),
            )?;

            let picks = match picks {
                Some(ref p) if p.is_empty() => continue,
                Some(p) => p,
                None => continue,
            };

            for &pick in &picks {
                let server = &client.servers[selectable[pick]];
                let id = etherfence_setup::WizardServerId {
                    agent: client.agent.clone(),
                    config_path: client.config_path.clone(),
                    server_name: server.name.clone(),
                };

                // ---------------------------------------------------------
                // Step 4 (per server) - Resolve trust and pinning issues
                // ---------------------------------------------------------
                eprintln!();
                eprintln!("{}", theme.step(4, 7, "Resolve trust and pinning"));
                eprintln!("Server");
                eprintln!("  {} / {}", client.agent, theme.info.apply_to(&server.name));
                if let Some(command) = server.command.as_deref() {
                    eprintln!("Current invocation");
                    eprintln!(
                        "  {}",
                        theme.path.apply_to(invocation_line(command, &server.args))
                    );
                }

                let mut quarantine_only = false;
                // Nothing is committed to the selections until every
                // decision for this server is complete: any skip path
                // below simply `continue`s and the server stays fully
                // unselected.
                let mut pending_pin: Option<String> = None;

                match server.trust_assessment.aggregate {
                    etherfence_setup::AggregateAssessmentStatus::HighRisk => {
                        eprintln!(
                            "{}  this server cannot receive a permissive setup",
                            theme.danger.apply_to("HIGH RISK")
                        );
                        for ind in &server.trust_assessment.indicators {
                            if ind.severity >= etherfence_core::Severity::High {
                                eprintln!("  \u{2022} {}", ind.summary);
                            }
                        }
                        let choice = interact_or_bail(
                            Select::new()
                                .items(&[
                                    "Skip this server (recommended)",
                                    "Proceed with quarantine-only mode",
                                ])
                                .with_prompt("High-risk action")
                                .default(0)
                                .interact(),
                        )?;
                        match choice {
                            1 => quarantine_only = true,
                            _ => {
                                eprintln!(
                                    "{}",
                                    theme.muted.apply_to("Skipped. No changes for this server.")
                                );
                                continue;
                            }
                        }
                    }
                    etherfence_setup::AggregateAssessmentStatus::NeedsReview => {
                        eprintln!(
                            "{}  trust indicators were raised for this server",
                            theme.warning.apply_to("REVIEW")
                        );
                    }
                    etherfence_setup::AggregateAssessmentStatus::Unknown => {
                        eprintln!(
                            "{}  publisher identity could not be verified",
                            theme.warning.apply_to("UNKNOWN")
                        );
                    }
                    _ => {}
                }

                // Package version pinning, assessed from the server's real
                // invocation. Only exact, immutable versions are accepted.
                let (runner, _pkg, version_status) = match server.command.as_deref() {
                    Some(command) => {
                        etherfence_setup::extract_package_version(command, &server.args)
                    }
                    None => (
                        None,
                        None,
                        etherfence_setup::PackageVersionStatus::NotApplicable,
                    ),
                };
                if let Some(runner) = runner {
                    if version_status.needs_pinning() {
                        eprintln!("Issue");
                        eprintln!(
                            "  No exact package version is specified ({}).",
                            version_status.human_label()
                        );
                        eprintln!("  Future installs may execute different code.");
                        let version = interact_text_or_bail(
                            Input::new()
                                .with_prompt(
                                    "Enter an exact version (e.g. 1.2.3; empty skips pinning)",
                                )
                                .allow_empty(true)
                                .validate_with(|input: &String| -> Result<(), String> {
                                    if input.trim().is_empty() {
                                        return Ok(());
                                    }
                                    etherfence_setup::validate_exact_version(runner, input.trim())
                                })
                                .interact_text(),
                        )?;
                        let version = version.trim();
                        if !version.is_empty() {
                            // Preview the pinned invocation from the real args.
                            let mcp = etherfence_core::McpServer {
                                name: server.name.clone(),
                                command: server.command.clone(),
                                args: server.args.clone(),
                                env: Vec::new(),
                                url: server.url.clone(),
                            };
                            if let Some(change) = etherfence_setup::resolve_pinning(&mcp, version) {
                                eprintln!("Result");
                                eprintln!(
                                    "  {}",
                                    theme.success.apply_to(invocation_line(
                                        server.command.as_deref().unwrap_or_default(),
                                        &change.pinned_args
                                    ))
                                );
                            }
                            pending_pin = Some(version.to_string());
                        }
                    }
                }

                // ---------------------------------------------------------
                // Step 5 (per server) - Choose policy posture
                // ---------------------------------------------------------
                eprintln!();
                eprintln!("{}", theme.step(5, 7, "Choose policy posture"));
                let posture_items: &[&str] = if quarantine_only {
                    &["Deny-all quarantine (only option for high-risk)"]
                } else {
                    &[
                        "Deny-all quarantine (safe default)",
                        "Custom tool allowlist (type tool names)",
                        "Skip this server",
                    ]
                };
                let posture_choice = interact_or_bail(
                    Select::new()
                        .items(posture_items)
                        .with_prompt(format!("Policy posture for '{}'", server.name))
                        .default(0)
                        .interact(),
                )?;

                let policy_type = if quarantine_only {
                    etherfence_setup::PolicyType::DenyAllQuarantine
                } else {
                    match posture_choice {
                        0 => etherfence_setup::PolicyType::DenyAllQuarantine,
                        1 => {
                            let tools = interact_text_or_bail(
                                Input::new()
                                    .with_prompt("Allowed tool names (comma-separated)")
                                    .interact_text(),
                            )?;
                            let allowlist: Vec<String> = tools
                                .split(',')
                                .map(|t| t.trim().to_string())
                                .filter(|t| !t.is_empty())
                                .collect();
                            etherfence_setup::PolicyType::CustomToolAllowlist(allowlist)
                        }
                        _ => {
                            eprintln!(
                                "{}",
                                theme.muted.apply_to("Skipped. No changes for this server.")
                            );
                            continue;
                        }
                    }
                };

                // All decisions made — commit this server's selection.
                selected_ids.push(id.clone());
                if let Some(version) = pending_pin {
                    version_pins.insert(id.clone(), version);
                }
                policy_types.insert(id, policy_type);
            }
        }
    }

    if selected_ids.is_empty() {
        eprintln!("\nNo servers selected for configuration. Exiting wizard; no changes were made.");
        return Ok(());
    }

    // Build WizardSelections and construct the plan via wizard.rs engine
    let selections = etherfence_setup::WizardSelections {
        selected: selected_ids,
        version_pins,
        policy_types,
        trust_overrides: HashMap::new(),
    };

    let plan =
        etherfence_setup::build_wizard_plan(&detections, &selections, &root.display().to_string())
            .map_err(|e| anyhow::anyhow!("{e}"))?;

    // -----------------------------------------------------------------
    // Step 6 - Review exact changes (from the plan, not local state)
    // -----------------------------------------------------------------
    eprintln!();
    eprintln!("{}", theme.step(6, 7, "Review changes"));

    let mut config_paths: Vec<&str> = Vec::new();
    for server in &plan.selected_servers {
        if !config_paths.contains(&server.config_path.as_str()) {
            config_paths.push(&server.config_path);
        }
    }

    for config_path in &config_paths {
        let first = plan
            .selected_servers
            .iter()
            .find(|s| s.config_path == *config_path)
            .expect("config path came from selected servers");
        eprintln!("{}", theme.heading.apply_to(&first.agent));
        eprintln!("  Configuration: {}", theme.path.apply_to(config_path));
        eprintln!();
        for server in plan
            .selected_servers
            .iter()
            .filter(|s| s.config_path == *config_path)
        {
            eprintln!("  {}", theme.info.apply_to(&server.server_name));
            if let Some(pin) = plan
                .pinning_changes
                .iter()
                .find(|c| c.config_path == *config_path && c.server_name == server.server_name)
            {
                eprintln!(
                    "    {} Pin package       {} \u{2192} {}",
                    theme.success.apply_to("\u{2713}"),
                    pin.package_identity.as_deref().unwrap_or("<package>"),
                    theme.success.apply_to(pin.pinned_args.join(" "))
                );
            }
            let policy_label = plan
                .policies
                .iter()
                .find(|p| p.config_path == *config_path && p.server_name == server.server_name)
                .map(|p| match &p.policy_type {
                    etherfence_setup::PolicyType::DenyAllQuarantine => {
                        "deny-all quarantine".to_string()
                    }
                    etherfence_setup::PolicyType::Curated => "curated profile".to_string(),
                    etherfence_setup::PolicyType::CustomToolAllowlist(t) => {
                        format!("custom allowlist: {}", t.join(", "))
                    }
                })
                .unwrap_or_else(|| "deny-all quarantine".to_string());
            eprintln!(
                "    {} Generate policy   {policy_label}",
                theme.success.apply_to("\u{2713}")
            );
            eprintln!(
                "    {} Add proxy         etherfence mcp-proxy",
                theme.success.apply_to("\u{2713}")
            );
            eprintln!(
                "    {} Create backup     .etherfence/backups/",
                theme.success.apply_to("\u{2713}")
            );
        }
        eprintln!();
    }

    // The unchanged section proves the wizard respects the selections.
    let mut unchanged: Vec<String> = Vec::new();
    for detection in &detections {
        for server in &detection.servers {
            let selected = plan.selected_servers.iter().any(|s| {
                s.agent == detection.agent
                    && s.config_path == detection.config_path
                    && s.server_name == server.name
            });
            if !selected {
                unchanged.push(format!("{} / {}", detection.agent, server.name));
            }
        }
    }
    for group in &clients {
        if group.server_count == 0 {
            unchanged.push(group.agent.clone());
        }
    }
    if !unchanged.is_empty() {
        eprintln!("{}", theme.heading.apply_to("Unchanged"));
        for entry in &unchanged {
            eprintln!("  {}", theme.muted.apply_to(entry));
        }
        eprintln!();
    }

    eprintln!(
        "{}",
        theme.key_value("Policies", &plan.policies.len().to_string())
    );
    eprintln!(
        "{}",
        theme.key_value("Configs", &config_paths.len().to_string())
    );
    eprintln!(
        "{}",
        theme.key_value("Servers", &plan.selected_servers.len().to_string())
    );

    // -----------------------------------------------------------------
    // Step 7 - Apply and verify
    // -----------------------------------------------------------------
    eprintln!();
    eprintln!("{}", theme.step(7, 7, "Apply and verify"));

    let confirmed = interact_or_bail(
        Confirm::new()
            .with_prompt("Apply these changes?")
            .default(false)
            .interact(),
    )?;

    if !confirmed {
        eprintln!("Setup cancelled. No changes were made.");
        return Ok(());
    }

    if let Err(error) = etherfence_setup::apply_wizard_plan(&root, &plan) {
        eprintln!();
        eprintln!("{}", theme.section("Setup failed"));
        eprintln!("{} {error:#}", theme.danger.apply_to("\u{2717}"));
        eprintln!(
            "{} Automatic rollback restored the original configuration and removed generated policies (unless the error above reports a cleanup failure).",
            theme.success.apply_to("\u{2713}")
        );
        anyhow::bail!("setup apply failed; no partial changes should remain");
    }

    eprintln!();
    eprintln!("{}", theme.section("Setup complete"));
    eprintln!(
        "{} Backed up {} configuration file(s)",
        theme.success.apply_to("\u{2713}"),
        config_paths.len()
    );
    eprintln!(
        "{} Generated {} MCP policy file(s)",
        theme.success.apply_to("\u{2713}"),
        plan.policies.len()
    );
    eprintln!(
        "{} Protected {} server(s) with etherfence mcp-proxy",
        theme.success.apply_to("\u{2713}"),
        plan.selected_servers.len()
    );
    for pin in &plan.pinning_changes {
        eprintln!(
            "{} Pinned {} to {}",
            theme.success.apply_to("\u{2713}"),
            pin.package_identity.as_deref().unwrap_or(&pin.server_name),
            pin.proposed_version.as_deref().unwrap_or("<version>")
        );
    }
    if !unchanged.is_empty() {
        eprintln!(
            "{} Left {} server(s)/client(s) unchanged",
            theme.muted.apply_to("\u{25cb}"),
            unchanged.len()
        );
    }
    eprintln!();
    eprintln!("Next:");
    eprintln!(
        "  {}   Verify the result",
        theme.info.apply_to("etherfence setup doctor")
    );
    eprintln!(
        "  {}   Undo all changes",
        theme.info.apply_to("etherfence setup rollback")
    );
    eprintln!();
    Ok(())
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

    if explanation.argument_guards.is_empty() {
        let _ = writeln!(out, "Argument/param field guards: (none configured)");
    } else {
        let _ = writeln!(out, "Argument/param field guards:");
        for guard in &explanation.argument_guards {
            let scope_label = match &guard.server_name {
                Some(server) => format!("{} (server={server})", guard.scope.as_str()),
                None => guard.scope.as_str().to_string(),
            };
            let _ = writeln!(out, "  {scope_label} {:?}", guard.key);
            if !guard.require_keys.is_empty() {
                let _ = writeln!(
                    out,
                    "    require_keys: {}",
                    format_list(&guard.require_keys)
                );
            }
            if !guard.forbid_keys.is_empty() {
                let _ = writeln!(out, "    forbid_keys: {}", format_list(&guard.forbid_keys));
            }
            for field in &guard.fields {
                let _ = writeln!(
                    out,
                    "    fields.{:?} -> type={}",
                    field.selector, field.kind
                );
            }
        }
    }
    let _ = writeln!(out);

    let _ = writeln!(
        out,
        "Unicode/homograph hardening: always enabled (v0.4.1) -- bidi controls, zero-width/invisible characters, and non-ASCII policy/runtime identifiers are rejected at parse time or denied at runtime before matching. v0.2 field-guard selector segments are covered by the same hardening."
    );
    let _ = writeln!(
        out,
        "Audit redaction posture: when --audit-log is used, only decisions, reasons, method/tool names, safe path classification, guard/selector names, and argument/param key names are recorded; argument/param values, full paths, URIs, and guarded field values are never logged."
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
    if let Some(guard_key) = &outcome.guard_key {
        let _ = writeln!(
            out,
            "Guard decision: key={:?} selector={:?} reason_category={:?}",
            guard_key,
            outcome.guard_selector.as_deref().unwrap_or("<none>"),
            outcome.guard_reason_category.as_deref().unwrap_or("<none>")
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
    verbose: bool,
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
    let posture = PostureSummary::from_findings(&display_findings);
    let report = ScanReport {
        schema_version: "ef-scan-report/v0.1.1".to_string(),
        tool: "etherfence".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        status: "stable-local-scan".to_string(),
        scanned_root,
        inventory,
        findings: display_findings,
        summary,
        posture: Some(posture),
        policy: policy_meta,
        baseline: baseline_meta,
    };
    let output = match options.format {
        OutputFormat::Human if options.verbose => etherfence_report::to_human(&report),
        OutputFormat::Human => render_scan_summary(&report),
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

/// Default human scan output: a readable executive summary. Full evidence
/// (rationale, recommendation, complete finding list, fingerprints) stays
/// behind `--verbose`.
fn render_scan_summary(report: &ScanReport) -> String {
    use std::fmt::Write as _;
    let theme = ui::UiTheme::for_stdout();
    let mut out = String::new();

    // Group configs by client so one client with several config files
    // reads as one client, not several installations.
    let mut clients: Vec<(String, usize)> = Vec::new();
    for item in &report.inventory {
        let name = item.agent.display_name().to_string();
        match clients.iter_mut().find(|(client, _)| *client == name) {
            Some((_, servers)) => *servers += item.mcp_servers.len(),
            None => clients.push((name, item.mcp_servers.len())),
        }
    }
    let total_servers: usize = report
        .inventory
        .iter()
        .map(|item| item.mcp_servers.len())
        .sum();

    let _ = writeln!(out, "{}", theme.section("Security posture"));
    let _ = writeln!(
        out,
        "{}",
        theme.key_value(
            "Scanned",
            &theme.path.apply_to(&report.scanned_root).to_string()
        )
    );
    let _ = writeln!(
        out,
        "{}",
        theme.key_value("AI clients", &format!("{} detected", clients.len()))
    );
    let _ = writeln!(
        out,
        "{}",
        theme.key_value("MCP servers", &format!("{total_servers} configured"))
    );
    let _ = writeln!(
        out,
        "{}",
        theme.key_value(
            "Findings",
            &ui::severity_counts(
                &theme,
                report.summary.high,
                report.summary.medium,
                report.summary.low,
                report.summary.info,
            )
        )
    );
    if let Some(posture) = &report.posture {
        let grade_style = match posture.grade {
            etherfence_core::PostureGrade::A | etherfence_core::PostureGrade::B => &theme.success,
            etherfence_core::PostureGrade::C => &theme.warning,
            etherfence_core::PostureGrade::D | etherfence_core::PostureGrade::F => &theme.danger,
        };
        let _ = writeln!(
            out,
            "{}",
            theme.key_value(
                "Posture",
                &format!(
                    "{}/100 — {}",
                    posture.score,
                    grade_style.apply_to(format!("GRADE {}", posture.grade.label()))
                )
            )
        );
        let _ = writeln!(
            out,
            "{}",
            theme.key_value("Assessment", &posture.assessment)
        );
    }
    if let Some(baseline) = &report.baseline {
        let _ = writeln!(
            out,
            "{}",
            theme.key_value(
                "Baseline",
                &format!(
                    "new={}, existing={}, resolved={}",
                    baseline.new, baseline.existing, baseline.resolved
                )
            )
        );
    }
    if let Some(policy) = &report.policy {
        let _ = writeln!(
            out,
            "{}",
            theme.key_value(
                "Policy",
                &format!(
                    "{} — checks={}, pass={}, violations={}",
                    policy.policy_name, policy.checks_total, policy.pass, policy.violation
                )
            )
        );
    }

    let overall = if report.summary.high > 0 {
        theme.danger.apply_to("NEEDS ATTENTION").to_string()
    } else if report.summary.medium > 0 {
        theme.warning.apply_to("NEEDS REVIEW").to_string()
    } else if report.summary.findings_total > 0 {
        theme.info.apply_to("LOW-RISK OBSERVATIONS").to_string()
    } else {
        theme.success.apply_to("NO FINDINGS").to_string()
    };
    let _ = writeln!(out, "\nOverall status:  {overall}");

    let _ = writeln!(out, "\n{}", theme.section("Clients"));
    if clients.is_empty() {
        let _ = writeln!(
            out,
            "No supported agent config files found in conservative scan paths."
        );
    }
    for (client, servers) in &clients {
        let marker = if *servers > 0 {
            theme.success.apply_to("\u{2713}").to_string()
        } else {
            theme.muted.apply_to("\u{25cb}").to_string()
        };
        let servers_label = if *servers > 0 {
            ui::count_servers(*servers)
        } else {
            theme.muted.apply_to(ui::count_servers(0)).to_string()
        };
        let _ = writeln!(out, "{marker} {}{servers_label}", ui::pad(client, 20));
    }

    let _ = writeln!(out, "\n{}", theme.section("Priority findings"));
    if let Some(posture) = &report.posture {
        if posture.priority_risks.is_empty() {
            let _ = writeln!(
                out,
                "No active scored findings are displayed. Missing files are skipped gracefully; this does not prove the host is secure."
            );
        } else {
            for risk in &posture.priority_risks {
                let badge = match risk.severity {
                    Severity::High => theme.danger.apply_to(ui::pad("HIGH", 7)).to_string(),
                    Severity::Medium => theme.warning.apply_to(ui::pad("MEDIUM", 7)).to_string(),
                    Severity::Low => theme.info.apply_to(ui::pad("LOW", 7)).to_string(),
                    Severity::Info => theme.muted.apply_to(ui::pad("INFO", 7)).to_string(),
                };
                let _ = writeln!(
                    out,
                    "{badge} {}  {}",
                    risk.title,
                    theme.muted.apply_to(&risk.finding_id)
                );
                let _ = writeln!(out, "        {} / {}", risk.agent, risk.target);
                let _ = writeln!(out, "        Why this matters: {}", risk.why_this_matters);
            }
            let remaining = posture
                .active_findings
                .saturating_sub(posture.priority_risks.len());
            if remaining > 0 {
                let _ = writeln!(
                    out,
                    "{} {remaining} additional active finding(s) — run `etherfence scan --verbose` for the full list",
                    theme.muted.apply_to(ui::pad("…", 7))
                );
            }
        }
    } else if report.findings.is_empty() {
        let _ = writeln!(
            out,
            "None displayed. Missing files are skipped gracefully; this does not prove the host is secure."
        );
    }

    let _ = writeln!(out, "\n{}", theme.section("Next steps"));
    if let Some(posture) = &report.posture {
        for (index, action) in posture.recommended_actions.iter().enumerate() {
            let _ = writeln!(
                out,
                "{}. {} {}",
                index + 1,
                theme.muted.apply_to(format!("[{}]", action.finding_id)),
                action.recommendation
            );
        }
    }
    let _ = writeln!(
        out,
        "Run {} for full evidence and fingerprints.",
        theme.info.apply_to("`etherfence scan --verbose`")
    );
    let _ = writeln!(
        out,
        "Run {} to secure detected MCP servers.",
        theme.info.apply_to("`etherfence setup`")
    );

    let _ = write!(
        out,
        "\n{}",
        theme.muted.apply_to(
            "Note: This scan command is read-only posture discovery. It does not block, proxy, hook, or intercept runtime activity. Runtime MCP boundary enforcement is available separately through `etherfence mcp-proxy`. Findings are posture risks/hints, not confirmed exploitability."
        )
    );
    out
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
