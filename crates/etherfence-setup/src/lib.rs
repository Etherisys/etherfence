use anyhow::{Context, Result};
use etherfence_core::{
    read_bounded_text_file, AgentKind, InventoryItem, McpServer, MAX_CONFIG_FILE_BYTES,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value as JsonValue};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

mod baseline;
mod catalog;
mod classification;
mod trust;
mod wizard;

pub use baseline::{
    build_baseline, compare, drift_gate_triggered, fingerprint, new_gate_triggered,
    risk_increase_gate_triggered, risk_rank, validate_baseline, BaselineDocument,
    BaselineServerEntry, ComparisonEntry, ComparisonReport, ComparisonStatus, DriftReason,
    IndicatorSummary, ReviewState, RiskDirection, BASELINE_SCHEMA_VERSION,
    COMPARISON_SCHEMA_VERSION,
};
pub use catalog::{catalog, CatalogClient, CatalogEntry, CatalogSupportTier};
pub use classification::{
    classify_server, human_label, recommend, CapabilityLabel, ClassifiedCapabilities,
    RecommendationTier, StarterPolicyRecommendation,
};
pub use etherfence_core::WriteSupportKind as WriteSupport;
pub use trust::{
    aggregate, assess_trust, configuration_risk_from_indicators, human_label_version_expression,
    needs_review, sort_indicators, AggregateAssessmentStatus, ArtifactIdentityConfidence,
    ConfigurationRiskStatus, EvidenceField, EvidenceKey, ExecutablePathClassification,
    IndicatorCategory, InvocationAssessment, ObscuredLaunchPattern, PackageRunner,
    ShellWrapperKind, TrustAssessment, TrustIndicator, VersionExpressionKind,
};
pub use wizard::{
    apply_wizard_plan, build_wizard_plan, extract_package_version, resolve_pinning,
    validate_exact_version, PackageVersionStatus, PinningChange, PolicyEntry, PolicyType,
    SelectedServer, WizardPackageRunner, WizardPlan, WizardSelections,
};

const BACKUP_MARKER: &str = "etherfence-setup-backup/v1";
const BACKUP_DIR: &str = ".etherfence/backups";
const POLICY_DIR: &str = ".etherfence/policies";
const MANIFEST_FILE: &str = "manifest.json";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetupDetection {
    pub agent: String,
    pub config_path: String,
    pub write_support: WriteSupport,
    pub servers: Vec<SetupServer>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServerTransport {
    Stdio,
    Remote,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetupServer {
    pub name: String,
    pub transport: ServerTransport,
    pub wrapped: bool,
    pub capabilities: ClassifiedCapabilities,
    pub recommendation: StarterPolicyRecommendation,
    pub trust_assessment: TrustAssessment,
    /// Raw invocation command from the parsed config. Kept out of JSON
    /// output (the detect/baseline contracts stay unchanged); retained in
    /// memory so the wizard can plan and apply pinning against the real
    /// invocation instead of a reconstruction.
    #[serde(skip)]
    pub command: Option<String>,
    /// Raw invocation arguments from the parsed config (see `command`).
    #[serde(skip)]
    pub args: Vec<String>,
    /// Raw remote URL from the parsed config (see `command`).
    #[serde(skip)]
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SetupPlan {
    pub root: String,
    pub detections: Vec<SetupDetection>,
    pub actions: Vec<SetupAction>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SetupAction {
    pub agent: String,
    pub config_path: String,
    pub server_name: String,
    pub action: SetupActionKind,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SetupActionKind {
    Wrap,
    SkipAlreadyWrapped,
    AdvisoryOnly,
    SkipNonStdio,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    pub root: String,
    pub checks: Vec<DoctorCheck>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorCheck {
    pub status: DoctorStatus,
    pub subject: String,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DoctorStatus {
    Ok,
    Warn,
    Fail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackupManifest {
    marker: String,
    original_path: String,
    backup_path: String,
    backup_hash: String,
    post_apply_hash: String,
    #[serde(default)]
    policy_paths: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
enum SupportedShape {
    TopLevelMcpServers,
    NestedMcpServers,
}

struct SupportedConfig {
    relative_path: &'static str,
    shape: SupportedShape,
}

#[derive(Debug)]
struct PreparedApply {
    original_path: PathBuf,
    backup_dir: PathBuf,
    backup_path: PathBuf,
    original_content: Vec<u8>,
    next_content: Vec<u8>,
    policies: Vec<PreparedPolicy>,
}

#[derive(Debug)]
struct PreparedPolicy {
    path: PathBuf,
    content: Vec<u8>,
}

struct RollbackOperation {
    manifest_path: PathBuf,
    manifest: BackupManifest,
    original_path: PathBuf,
    backup_path: PathBuf,
}

const SUPPORTED_CONFIGS: &[SupportedConfig] = &[
    SupportedConfig {
        relative_path: ".claude.json",
        shape: SupportedShape::TopLevelMcpServers,
    },
    SupportedConfig {
        relative_path: ".claude/settings.json",
        shape: SupportedShape::TopLevelMcpServers,
    },
    SupportedConfig {
        relative_path: "AppData/Roaming/Claude/settings.json",
        shape: SupportedShape::TopLevelMcpServers,
    },
    SupportedConfig {
        relative_path: ".cursor/mcp.json",
        shape: SupportedShape::TopLevelMcpServers,
    },
    SupportedConfig {
        relative_path: "AppData/Roaming/Cursor/User/mcp.json",
        shape: SupportedShape::TopLevelMcpServers,
    },
    SupportedConfig {
        relative_path: ".vscode/mcp.json",
        shape: SupportedShape::TopLevelMcpServers,
    },
    SupportedConfig {
        relative_path: ".vscode/settings.json",
        shape: SupportedShape::NestedMcpServers,
    },
    SupportedConfig {
        relative_path: ".config/Code/User/settings.json",
        shape: SupportedShape::NestedMcpServers,
    },
    SupportedConfig {
        relative_path: "AppData/Roaming/Code/User/settings.json",
        shape: SupportedShape::NestedMcpServers,
    },
];

pub fn detect(root: &Path) -> Vec<SetupDetection> {
    etherfence_inventory::discover(root)
        .into_iter()
        .map(detection_from_inventory)
        .collect()
}

pub fn plan(root: &Path) -> SetupPlan {
    let detections = detect(root);
    let mut actions = Vec::new();
    for detection in &detections {
        for server in &detection.servers {
            let (action, reason) = match (detection.write_support, server.transport, server.wrapped)
            {
                (_, _, true) => (
                    SetupActionKind::SkipAlreadyWrapped,
                    "server is already wrapped by etherfence mcp-proxy".to_string(),
                ),
                (WriteSupport::AdvisoryOnly, _, false) => (
                    SetupActionKind::AdvisoryOnly,
                    "client is advisory-only for v1.1.0; no rewrite will be performed".to_string(),
                ),
                (WriteSupport::Supported, ServerTransport::Stdio, false) => (
                    SetupActionKind::Wrap,
                    "supported stdio MCP server can be wrapped by etherfence mcp-proxy".to_string(),
                ),
                (WriteSupport::Supported, _, false) => (
                    SetupActionKind::SkipNonStdio,
                    "only local stdio MCP servers can be wrapped".to_string(),
                ),
            };
            actions.push(SetupAction {
                agent: detection.agent.clone(),
                config_path: detection.config_path.clone(),
                server_name: server.name.clone(),
                action,
                reason,
            });
        }
    }
    SetupPlan {
        root: root.display().to_string(),
        detections,
        actions,
    }
}

pub fn doctor(root: &Path) -> DoctorReport {
    let setup_plan = plan(root);
    let mut checks = Vec::new();
    if setup_plan.detections.is_empty() {
        checks.push(DoctorCheck {
            status: DoctorStatus::Warn,
            subject: root.display().to_string(),
            message: "no known AI client MCP configs were detected".to_string(),
        });
    }
    for detection in &setup_plan.detections {
        if detection.servers.is_empty() {
            checks.push(DoctorCheck {
                status: DoctorStatus::Ok,
                subject: detection.config_path.clone(),
                message: format!("{} config detected with no MCP servers", detection.agent),
            });
        }
        for server in &detection.servers {
            let status = if server.wrapped {
                DoctorStatus::Ok
            } else if detection.write_support == WriteSupport::Supported
                && server.transport == ServerTransport::Stdio
            {
                DoctorStatus::Warn
            } else {
                DoctorStatus::Ok
            };
            let message = if server.wrapped {
                "server is already wrapped by etherfence mcp-proxy".to_string()
            } else if detection.write_support == WriteSupport::Supported
                && server.transport == ServerTransport::Stdio
            {
                "server is eligible for setup apply wrapping".to_string()
            } else {
                "server is advisory-only or not a local stdio server".to_string()
            };
            checks.push(DoctorCheck {
                status,
                subject: format!("{}:{}", detection.agent, server.name),
                message,
            });
        }
    }
    for manifest in find_backup_manifests(root) {
        match read_manifest(&manifest).and_then(|m| validate_manifest_scope(root, &manifest, &m)) {
            Ok(_) => checks.push(DoctorCheck {
                status: DoctorStatus::Ok,
                subject: manifest.display().to_string(),
                message: "EtherFence setup backup manifest is well-formed".to_string(),
            }),
            Err(error) => checks.push(DoctorCheck {
                status: DoctorStatus::Fail,
                subject: manifest.display().to_string(),
                message: format!("backup manifest is invalid: {error:#}"),
            }),
        }
    }
    DoctorReport {
        root: setup_plan.root,
        checks,
    }
}

pub fn apply(root: &Path) -> Result<()> {
    let prepared = prepare_apply(root)?;
    write_prepared_changes(root, &prepared)
}

fn write_prepared_changes(root: &Path, prepared: &[PreparedApply]) -> Result<()> {
    let mut completed: Vec<&PreparedApply> = Vec::new();
    for change in prepared {
        if let Err(error) = write_prepared_apply(root, change) {
            let mut cleanup_errors = Vec::new();
            cleanup_prepared_apply(change, false, &mut cleanup_errors);
            for completed_change in completed.iter().rev() {
                cleanup_prepared_apply(completed_change, true, &mut cleanup_errors);
            }
            if cleanup_errors.is_empty() {
                return Err(error);
            }
            anyhow::bail!(
                "{error:#}; additionally failed best-effort apply cleanup: {}",
                cleanup_errors.join("; ")
            );
        }
        completed.push(change);
    }
    Ok(())
}

/// One selected server's apply-time instructions, derived from a
/// `wizard::WizardPlan`.
struct WizardDirective {
    pin_version: Option<String>,
    policy_content: Option<String>,
}

/// One selected server's fully resolved change, ready to be written.
struct PlannedServerChange {
    server_name: String,
    pinned_args: Option<Vec<String>>,
    policy: Vec<u8>,
    policy_path: PathBuf,
}

/// Applies a wizard plan selectively: only the servers the user selected
/// are pinned, given a policy, and wrapped. Every other server and every
/// config without a selected server is left untouched.
///
/// Fails closed: if a selected server disappeared from its config, or a
/// promised version pin cannot be applied to the server's real invocation,
/// the whole apply is aborted before any file is written.
pub(crate) fn apply_selected(root: &Path, plan: &wizard::WizardPlan) -> Result<()> {
    let prepared = prepare_wizard_apply(root, plan)?;
    write_prepared_changes(root, &prepared)
}

fn prepare_wizard_apply(root: &Path, plan: &wizard::WizardPlan) -> Result<Vec<PreparedApply>> {
    let mut prepared = Vec::new();
    for config in SUPPORTED_CONFIGS {
        let path = root.join(config.relative_path);
        if !path.is_file() {
            continue;
        }
        let mut directives: std::collections::BTreeMap<String, WizardDirective> =
            std::collections::BTreeMap::new();
        for server in &plan.selected_servers {
            if !display_path_matches(&server.config_path, config.relative_path) {
                continue;
            }
            let pin_version = plan
                .pinning_changes
                .iter()
                .find(|change| {
                    change.config_path == server.config_path
                        && change.server_name == server.server_name
                })
                .and_then(|change| change.proposed_version.clone());
            let policy_content = plan
                .policies
                .iter()
                .find(|policy| {
                    policy.config_path == server.config_path
                        && policy.server_name == server.server_name
                })
                .map(|policy| policy.content.clone());
            directives.insert(
                server.server_name.clone(),
                WizardDirective {
                    pin_version,
                    policy_content,
                },
            );
        }
        if directives.is_empty() {
            continue;
        }
        if let Some(change) = prepare_wizard_config(&path, config, &directives)? {
            prepared.push(change);
        }
    }
    Ok(prepared)
}

fn prepare_wizard_config(
    path: &Path,
    config: &SupportedConfig,
    directives: &std::collections::BTreeMap<String, WizardDirective>,
) -> Result<Option<PreparedApply>> {
    let original_content = fs::read(path)
        .with_context(|| format!("reading supported MCP config {}", path.display()))?;
    if original_content.len() as u64 > MAX_CONFIG_FILE_BYTES {
        anyhow::bail!("config {} exceeds size limit", path.display());
    }
    let content = std::str::from_utf8(&original_content)
        .with_context(|| format!("supported MCP config {} is not UTF-8", path.display()))?;
    let mut value: JsonValue = serde_json::from_str(content)
        .with_context(|| format!("parsing supported MCP config JSON {}", path.display()))?;

    let policy_dir = path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(POLICY_DIR);
    let mut policies = Vec::new();
    {
        let Some(servers) = servers_object_mut(&mut value, config.shape) else {
            anyhow::bail!(
                "config {} no longer contains an MCP servers object; aborting wizard apply",
                path.display()
            );
        };
        let mut changes: Vec<PlannedServerChange> = Vec::new();
        for (server_name, directive) in directives {
            let Some(server_value) = servers.get(server_name) else {
                anyhow::bail!(
                    "selected server '{}' no longer exists in {}; aborting wizard apply",
                    server_name,
                    path.display()
                );
            };
            let server = json_server(server_name, server_value);
            if transport_for_server(&server) != ServerTransport::Stdio {
                // Remote servers cannot be wrapped; the plan records these
                // as skip-non-stdio actions.
                continue;
            }
            if is_wrapped_server(&server) {
                continue;
            }
            let pinned_args = match &directive.pin_version {
                Some(version) => {
                    let change = wizard::resolve_pinning(&server, version).with_context(|| {
                        format!(
                            "planned version pin for '{}' cannot be applied to its current invocation in {}; aborting wizard apply",
                            server_name,
                            path.display()
                        )
                    })?;
                    Some(change.pinned_args)
                }
                None => None,
            };
            let policy = match &directive.policy_content {
                Some(content) => {
                    etherfence_mcp::parse_mcp_policy(content).with_context(|| {
                        format!("planned policy for '{server_name}' failed validation")
                    })?;
                    content.clone()
                }
                None => generated_policy_template(server_name)?,
            };
            let policy_path =
                policy_dir.join(format!("{}.toml", sanitize_policy_identifier(server_name)));
            changes.push(PlannedServerChange {
                server_name: server_name.clone(),
                pinned_args,
                policy: policy.into_bytes(),
                policy_path,
            });
        }
        if changes.is_empty() {
            return Ok(None);
        }
        for change in changes {
            let Some(server_value) = servers.get_mut(&change.server_name) else {
                continue;
            };
            if let Some(args) = change.pinned_args {
                if let Some(object) = server_value.as_object_mut() {
                    object.insert(
                        "args".to_string(),
                        JsonValue::Array(args.into_iter().map(JsonValue::String).collect()),
                    );
                }
            }
            wrap_server_value(server_value, &change.server_name, &change.policy_path)?;
            policies.push(PreparedPolicy {
                path: change.policy_path,
                content: change.policy,
            });
        }
    }

    let next_content = serde_json::to_vec_pretty(&value)?;
    let backup_dir = timestamped_backup_dir(path)?;
    Ok(Some(PreparedApply {
        original_path: path.to_path_buf(),
        backup_path: backup_dir.join("original.json"),
        backup_dir,
        original_content,
        next_content,
        policies,
    }))
}

/// Matches a detection's display config path (e.g. `~/.claude.json`, or an
/// absolute path when it sat outside the scan root) against a supported
/// config's root-relative path.
fn display_path_matches(display: &str, relative: &str) -> bool {
    let display = display.replace('\\', "/");
    let relative = relative.replace('\\', "/");
    display == relative
        || display
            .strip_suffix(&relative)
            .is_some_and(|prefix| prefix.ends_with('/'))
}

pub fn rollback(root: &Path) -> Result<()> {
    let mut operations = Vec::new();
    for manifest_path in find_backup_manifests(root) {
        let manifest = read_manifest(&manifest_path)?;
        let (original_path, backup_path) =
            validate_manifest_scope(root, &manifest_path, &manifest)?;
        let backup_content = fs::read(&backup_path)
            .with_context(|| format!("reading backup {}", backup_path.display()))?;
        if sha256_hex(&backup_content) != manifest.backup_hash {
            anyhow::bail!(
                "backup hash mismatch for {}; refusing rollback",
                backup_path.display()
            );
        }
        let current_content = fs::read(&original_path)
            .with_context(|| format!("reading current config {}", original_path.display()))?;
        if sha256_hex(&current_content) != manifest.post_apply_hash {
            anyhow::bail!(
                "current config {} changed after setup apply; refusing to overwrite user edits",
                original_path.display()
            );
        }
        operations.push(RollbackOperation {
            manifest_path,
            manifest,
            original_path,
            backup_path,
        });
    }

    for operation in operations {
        fs::copy(&operation.backup_path, &operation.original_path).with_context(|| {
            format!(
                "restoring {} from EtherFence backup {}",
                operation.original_path.display(),
                operation.backup_path.display()
            )
        })?;
        for policy_path in &operation.manifest.policy_paths {
            let policy_path = safe_manifest_path(root, policy_path)?;
            if policy_path.is_file() {
                fs::remove_file(&policy_path).with_context(|| {
                    format!(
                        "removing EtherFence-generated policy {}",
                        policy_path.display()
                    )
                })?;
            }
        }
        if let Some(dir) = operation.manifest_path.parent() {
            let _ = fs::remove_dir_all(dir);
        }
    }
    Ok(())
}

pub fn generated_policy_template(server_name: &str) -> Result<String> {
    let safe_name = sanitize_policy_identifier(server_name);
    let content = format!(
        r#"schema_version = "ef-mcp-policy/v0.1"
name = "etherfence-setup-{safe_name}"

[methods]
allow = ["tools/list"]
deny = []

[tools]
allow = []
deny = []
"#
    );
    etherfence_mcp::parse_mcp_policy(&content)?;
    Ok(content)
}

fn prepare_apply(root: &Path) -> Result<Vec<PreparedApply>> {
    let mut prepared = Vec::new();
    for config in SUPPORTED_CONFIGS {
        let path = root.join(config.relative_path);
        if !path.is_file() {
            continue;
        }
        if let Some(change) = prepare_config(&path, config)? {
            prepared.push(change);
        }
    }
    Ok(prepared)
}

fn prepare_config(path: &Path, config: &SupportedConfig) -> Result<Option<PreparedApply>> {
    let original_content = fs::read(path)
        .with_context(|| format!("reading supported MCP config {}", path.display()))?;
    if original_content.len() as u64 > MAX_CONFIG_FILE_BYTES {
        anyhow::bail!("config {} exceeds size limit", path.display());
    }
    let content = std::str::from_utf8(&original_content)
        .with_context(|| format!("supported MCP config {} is not UTF-8", path.display()))?;
    let mut value: JsonValue = serde_json::from_str(content)
        .with_context(|| format!("parsing supported MCP config JSON {}", path.display()))?;

    let policy_dir = path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(POLICY_DIR);
    let mut policies = Vec::new();
    {
        let Some(servers) = servers_object_mut(&mut value, config.shape) else {
            return Ok(None);
        };
        let mut changes = Vec::new();
        for (server_name, server_value) in servers.iter() {
            let server = json_server(server_name, server_value);
            if transport_for_server(&server) == ServerTransport::Stdio
                && !is_wrapped_server(&server)
            {
                let policy = generated_policy_template(server_name)?;
                let policy_path =
                    policy_dir.join(format!("{}.toml", sanitize_policy_identifier(server_name)));
                changes.push((server_name.clone(), policy.into_bytes(), policy_path));
            }
        }
        if changes.is_empty() {
            return Ok(None);
        }
        for (server_name, policy, policy_path) in changes {
            let Some(server_value) = servers.get_mut(&server_name) else {
                continue;
            };
            wrap_server_value(server_value, &server_name, &policy_path)?;
            policies.push(PreparedPolicy {
                path: policy_path,
                content: policy,
            });
        }
    }

    let next_content = serde_json::to_vec_pretty(&value)?;
    let backup_dir = timestamped_backup_dir(path)?;
    Ok(Some(PreparedApply {
        original_path: path.to_path_buf(),
        backup_path: backup_dir.join("original.json"),
        backup_dir,
        original_content,
        next_content,
        policies,
    }))
}

fn write_prepared_apply(root: &Path, change: &PreparedApply) -> Result<()> {
    fs::create_dir_all(&change.backup_dir).with_context(|| {
        format!(
            "creating EtherFence backup dir {}",
            change.backup_dir.display()
        )
    })?;
    atomic_write(&change.backup_path, &change.original_content)?;
    for policy in &change.policies {
        atomic_write(&policy.path, &policy.content)?;
    }
    write_manifest(root, change)?;
    atomic_write(&change.original_path, &change.next_content)?;
    Ok(())
}

fn cleanup_prepared_apply(change: &PreparedApply, restore_config: bool, errors: &mut Vec<String>) {
    if restore_config {
        if let Err(error) = atomic_write(&change.original_path, &change.original_content) {
            errors.push(format!(
                "restore {}: {error:#}",
                change.original_path.display()
            ));
        }
    }
    for policy in &change.policies {
        if policy.path.is_file() {
            if let Err(error) = fs::remove_file(&policy.path) {
                errors.push(format!("remove {}: {error:#}", policy.path.display()));
            }
        }
        remove_empty_parent_dirs(policy.path.parent(), 2);
    }
    if change.backup_dir.is_dir() {
        if let Err(error) = fs::remove_dir_all(&change.backup_dir) {
            errors.push(format!("remove {}: {error:#}", change.backup_dir.display()));
        }
    }
    remove_empty_parent_dirs(change.backup_dir.parent(), 2);
}

fn remove_empty_parent_dirs(start: Option<&Path>, max_depth: usize) {
    let mut current = start.map(Path::to_path_buf);
    for _ in 0..max_depth {
        let Some(path) = current else {
            return;
        };
        current = path.parent().map(Path::to_path_buf);
        let _ = fs::remove_dir(&path);
    }
}

fn servers_object_mut(
    value: &mut JsonValue,
    shape: SupportedShape,
) -> Option<&mut JsonMap<String, JsonValue>> {
    match shape {
        SupportedShape::TopLevelMcpServers => value.get_mut("mcpServers")?.as_object_mut(),
        SupportedShape::NestedMcpServers => {
            if value
                .get("mcp")
                .and_then(|mcp| mcp.get("servers"))
                .is_some()
            {
                return value.get_mut("mcp")?.get_mut("servers")?.as_object_mut();
            }
            value.get_mut("mcpServers")?.as_object_mut()
        }
    }
}

fn wrap_server_value(value: &mut JsonValue, server_name: &str, policy_path: &Path) -> Result<()> {
    let Some(object) = value.as_object_mut() else {
        return Ok(());
    };
    let original_command = object
        .get("command")
        .and_then(JsonValue::as_str)
        .context("stdio MCP server has no string command")?
        .to_string();
    let original_args = object
        .get("args")
        .and_then(JsonValue::as_array)
        .map(|args| args.to_vec())
        .unwrap_or_default();
    let mut args = vec![
        JsonValue::String("mcp-proxy".to_string()),
        JsonValue::String("--policy".to_string()),
        JsonValue::String(policy_path.display().to_string()),
        JsonValue::String("--server-name".to_string()),
        JsonValue::String(server_name.to_string()),
        JsonValue::String("--".to_string()),
        JsonValue::String(original_command),
    ];
    args.extend(original_args);
    object.insert(
        "command".to_string(),
        JsonValue::String("etherfence".to_string()),
    );
    object.insert("args".to_string(), JsonValue::Array(args));
    Ok(())
}

fn detection_from_inventory(item: InventoryItem) -> SetupDetection {
    let write_support = write_support_for_agent(item.agent, &item.config_path);
    let mut notes = item.evidence;
    if write_support == WriteSupport::AdvisoryOnly {
        notes.push("advisory-only in v1.1.0; setup apply will not rewrite this config".to_string());
    }
    SetupDetection {
        agent: item.agent.display_name().to_string(),
        config_path: item.config_path,
        write_support,
        servers: item.mcp_servers.iter().map(server_from_mcp).collect(),
        notes,
    }
}

pub(crate) fn server_from_mcp(server: &McpServer) -> SetupServer {
    let capabilities = classification::classify_server(server);
    let recommendation = classification::recommend(&capabilities);
    let trust_assessment = trust::assess_trust(server);
    SetupServer {
        name: server.name.clone(),
        transport: transport_for_server(server),
        wrapped: is_wrapped_server(server),
        capabilities,
        recommendation,
        trust_assessment,
        command: server.command.clone(),
        args: server.args.clone(),
        url: server.url.clone(),
    }
}

fn write_support_for_agent(agent: AgentKind, config_path: &str) -> WriteSupport {
    match agent {
        AgentKind::ClaudeCode | AgentKind::Cursor => WriteSupport::Supported,
        AgentKind::VsCode if is_supported_vscode_config(config_path) => WriteSupport::Supported,
        _ => WriteSupport::AdvisoryOnly,
    }
}

fn is_supported_vscode_config(config_path: &str) -> bool {
    config_path.ends_with(".vscode/mcp.json")
        || config_path.ends_with(".vscode/settings.json")
        || config_path.ends_with("Code/User/settings.json")
}

fn transport_for_server(server: &McpServer) -> ServerTransport {
    if server.command.is_some() {
        ServerTransport::Stdio
    } else if server.url.is_some() {
        ServerTransport::Remote
    } else {
        ServerTransport::Unknown
    }
}

fn is_wrapped_server(server: &McpServer) -> bool {
    let command = server.command.as_deref().unwrap_or_default();
    let command_path = PathBuf::from(command);
    let command_name = command_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(command);
    command_name == "etherfence" && server.args.iter().any(|arg| arg == "mcp-proxy")
}

fn json_server(name: &str, value: &JsonValue) -> McpServer {
    let command = value
        .get("command")
        .and_then(JsonValue::as_str)
        .map(ToOwned::to_owned);
    let url = value
        .get("url")
        .or_else(|| value.get("serverUrl"))
        .and_then(JsonValue::as_str)
        .map(ToOwned::to_owned);
    let args = value
        .get("args")
        .and_then(JsonValue::as_array)
        .map(|args| {
            args.iter()
                .filter_map(JsonValue::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default();
    McpServer {
        name: name.to_string(),
        command,
        args,
        env: Vec::new(),
        url,
    }
}

fn timestamped_backup_dir(path: &Path) -> Result<PathBuf> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before UNIX epoch")?
        .as_millis();
    Ok(path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(BACKUP_DIR)
        .join(format!("{millis}")))
}

fn write_manifest(root: &Path, change: &PreparedApply) -> Result<()> {
    let manifest = BackupManifest {
        marker: BACKUP_MARKER.to_string(),
        original_path: relative_or_absolute(root, &change.original_path),
        backup_path: relative_or_absolute(root, &change.backup_path),
        backup_hash: sha256_hex(&change.original_content),
        post_apply_hash: sha256_hex(&change.next_content),
        policy_paths: change
            .policies
            .iter()
            .map(|policy| relative_or_absolute(root, &policy.path))
            .collect(),
    };
    let content = serde_json::to_vec_pretty(&manifest)?;
    atomic_write(&change.backup_dir.join(MANIFEST_FILE), &content)
}

fn read_manifest(path: &Path) -> Result<BackupManifest> {
    let content = read_bounded_text_file(path, MAX_CONFIG_FILE_BYTES)
        .with_context(|| format!("reading backup manifest {}", path.display()))?;
    let manifest: BackupManifest = serde_json::from_str(&content)
        .with_context(|| format!("parsing backup manifest {}", path.display()))?;
    if manifest.marker != BACKUP_MARKER {
        anyhow::bail!("backup manifest marker is not EtherFence setup owned");
    }
    Ok(manifest)
}

fn find_backup_manifests(root: &Path) -> Vec<PathBuf> {
    let mut manifests = Vec::new();
    for config in SUPPORTED_CONFIGS {
        let config_path = root.join(config.relative_path);
        let backup_root = config_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(BACKUP_DIR);
        let Ok(entries) = fs::read_dir(&backup_root) else {
            continue;
        };
        for entry in entries.flatten() {
            let manifest = entry.path().join(MANIFEST_FILE);
            if manifest.is_file() {
                manifests.push(manifest);
            }
        }
    }
    manifests.sort();
    manifests.dedup();
    manifests
}

fn validate_manifest_scope(
    root: &Path,
    manifest_path: &Path,
    manifest: &BackupManifest,
) -> Result<(PathBuf, PathBuf)> {
    let original = safe_manifest_path(root, &manifest.original_path)?;
    let backup = safe_manifest_path(root, &manifest.backup_path)?;
    let expected_backup = manifest_path
        .parent()
        .context("backup manifest has no parent directory")?
        .join("original.json");
    if backup != expected_backup {
        anyhow::bail!(
            "manifest {} backup_path must equal sibling original.json",
            manifest_path.display()
        );
    }
    let supported = SUPPORTED_CONFIGS.iter().any(|config| {
        let supported_original = root.join(config.relative_path);
        let expected_backup_root = supported_original
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(BACKUP_DIR);
        original == supported_original && manifest_path.starts_with(expected_backup_root)
    });
    if !supported {
        anyhow::bail!(
            "manifest {} does not target a supported setup config backup location",
            manifest_path.display()
        );
    }
    Ok((original, backup))
}

fn safe_manifest_path(root: &Path, raw: &str) -> Result<PathBuf> {
    let path = PathBuf::from(raw);
    if path.is_absolute() {
        if path.starts_with(root) {
            Ok(path)
        } else {
            anyhow::bail!("manifest path is outside setup root")
        }
    } else if raw.contains("..") {
        anyhow::bail!("manifest path contains traversal")
    } else {
        Ok(root.join(path))
    }
}

fn relative_or_absolute(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .map(|relative| relative.display().to_string())
        .unwrap_or_else(|_| path.display().to_string())
}

fn atomic_write(path: &Path, content: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    let tmp = path.with_extension("tmp-etherfence");
    fs::write(&tmp, content).with_context(|| format!("writing temp file {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| {
        format!(
            "atomically replacing {} with {}",
            path.display(),
            tmp.display()
        )
    })?;
    Ok(())
}

fn sha256_hex(content: &[u8]) -> String {
    format!("{:x}", Sha256::digest(content))
}

fn sanitize_policy_identifier(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('-');
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "server".to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_policy_template_validates() {
        let policy = generated_policy_template("filesystem").unwrap();
        assert!(policy.contains("schema_version = \"ef-mcp-policy/v0.1\""));
        assert!(policy.contains("tools/list"));
        assert!(
            !policy.contains("[\"*\"]"),
            "generated policy must not contain wildcard allow-all"
        );
        assert!(
            policy.contains("allow = []"),
            "generated policy tools.allow must be deny-all"
        );
    }

    #[test]
    fn wrapped_server_detection_uses_command_and_mcp_proxy_arg() {
        let server = McpServer {
            name: "fs".to_string(),
            command: Some("/usr/local/bin/etherfence".to_string()),
            args: vec![
                "mcp-proxy".to_string(),
                "--policy".to_string(),
                "p.toml".to_string(),
            ],
            env: Vec::new(),
            url: None,
        };
        assert!(is_wrapped_server(&server));
    }
}
