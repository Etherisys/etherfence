//! Deterministic MCP server integrity baseline and drift-detection
//! comparison (v1.4.0).
//!
//! Every type and function here is pure over an already-discovered
//! `InventoryItem` list (`etherfence_inventory::discover`'s output) plus the
//! existing crate-private `server_from_mcp` classification/trust-assessment
//! path this crate's `detect()` already uses — nothing here starts a
//! process, opens a network connection, or duplicates the discovery,
//! classification, or hashing engines. `trust.rs`/`classification.rs` are
//! not modified by this module.
//!
//! Persisted/emitted fields are restricted to the safe allowlist in spec
//! FR-024: normalized identity, command/argument *fingerprints* (hashes,
//! never raw text), package identity/version, executable path/hash,
//! environment variable *names* (never values), capability labels, trust
//! indicator id/category/severity, and the v1.3.0 trust/risk vocabulary.
//! Raw command/argument text, environment values, secrets, file contents,
//! and MCP traffic are never read into any type in this module.

use crate::trust::{
    aggregate, AggregateAssessmentStatus, ArtifactIdentityConfidence, ConfigurationRiskStatus,
    ExecutablePathClassification, IndicatorCategory, VersionExpressionKind,
};
use crate::{server_from_mcp, CapabilityLabel, ServerTransport};
use etherfence_core::{InventoryItem, Severity};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::Path;

pub const BASELINE_SCHEMA_VERSION: &str = "ef-setup-baseline/v0.1";
pub const COMPARISON_SCHEMA_VERSION: &str = "ef-setup-baseline-comparison/v0.1";

// ---------------------------------------------------------------------
// Baseline document (written by `write`, read by `check`)
// ---------------------------------------------------------------------

/// Forward-compatible, currently-static review-state field (spec FR-026):
/// v1.4.0 has no interactive review workflow, so every entry is written as
/// `Unreviewed`. Present so a future release can extend this enum
/// additively without changing `BaselineServerEntry`'s field shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReviewState {
    Unreviewed,
}

/// A safe, structured summary of one raised trust indicator (spec FR-018,
/// research.md Decision 6) — deliberately omits `summary`/`rationale`/
/// `evidence`/`remediation`; those are narrative fields not needed for
/// set-equality drift detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IndicatorSummary {
    pub id: String,
    pub category: IndicatorCategory,
    pub severity: Severity,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BaselineServerEntry {
    pub fingerprint: String,
    /// Stable machine identifier (`AgentKind::key()`, e.g. `"vs-code"`) —
    /// this, not `agent`, is one of the fingerprint's inputs. A future
    /// rewording of `AgentKind::display_name()` (e.g. "VS Code" ->
    /// "Visual Studio Code") must never change identity/fingerprints.
    pub agent_kind: String,
    /// Human-facing display name (`AgentKind::display_name()`), for
    /// readability only — never used to derive the fingerprint or to
    /// match entries across a baseline/current comparison.
    pub agent: String,
    pub config_source: String,
    pub server_name: String,
    pub transport: ServerTransport,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub command_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub arguments_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub package_identity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub package_version_expression: Option<VersionExpressionKind>,
    pub executable_path: ExecutablePathClassification,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sha256: Option<String>,
    pub environment_variable_names: Vec<String>,
    pub capability_labels: Vec<CapabilityLabel>,
    pub trust_indicators: Vec<IndicatorSummary>,
    pub artifact_identity: ArtifactIdentityConfidence,
    pub configuration_risk: ConfigurationRiskStatus,
    pub aggregate: AggregateAssessmentStatus,
    pub review_state: ReviewState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BaselineDocument {
    pub schema_version: String,
    pub root: String,
    pub servers: Vec<BaselineServerEntry>,
}

// ---------------------------------------------------------------------
// Comparison report (`check` output)
// ---------------------------------------------------------------------

/// Closed drift-reason enum (spec FR-014). Declaration order below is the
/// canonical sort order (research.md/data-model.md) — never insertion
/// order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DriftReason {
    ExecutableHashChanged,
    CommandChanged,
    ArgumentsChanged,
    PackageIdentityChanged,
    PackageVersionChanged,
    EnvironmentVariableNamesChanged,
    TransportChanged,
    ServerAdded,
    ServerRemoved,
    CapabilitySetChanged,
    TrustIndicatorSetChanged,
    ArtifactIdentityChanged,
    ConfigurationRiskChanged,
    RiskIncreased,
    ExecutableBecameUnverifiable,
}

impl DriftReason {
    pub const ALL: [DriftReason; 15] = [
        DriftReason::ExecutableHashChanged,
        DriftReason::CommandChanged,
        DriftReason::ArgumentsChanged,
        DriftReason::PackageIdentityChanged,
        DriftReason::PackageVersionChanged,
        DriftReason::EnvironmentVariableNamesChanged,
        DriftReason::TransportChanged,
        DriftReason::ServerAdded,
        DriftReason::ServerRemoved,
        DriftReason::CapabilitySetChanged,
        DriftReason::TrustIndicatorSetChanged,
        DriftReason::ArtifactIdentityChanged,
        DriftReason::ConfigurationRiskChanged,
        DriftReason::RiskIncreased,
        DriftReason::ExecutableBecameUnverifiable,
    ];

    fn canonical_index(self) -> usize {
        Self::ALL
            .iter()
            .position(|reason| *reason == self)
            .expect("DriftReason::ALL is exhaustive")
    }
}

fn sort_drift_reasons(reasons: &mut Vec<DriftReason>) {
    reasons.sort_by_key(|reason| reason.canonical_index());
    reasons.dedup();
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ComparisonStatus {
    Unchanged,
    New,
    Changed,
    Missing,
    Unverifiable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RiskDirection {
    Increased,
    Decreased,
    Unchanged,
    NotApplicable,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ComparisonEntry {
    pub fingerprint: String,
    pub agent_kind: String,
    pub agent: String,
    pub config_source: String,
    pub server_name: String,
    pub transport: ServerTransport,
    pub status: ComparisonStatus,
    pub reasons: Vec<DriftReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_risk: Option<AggregateAssessmentStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_risk: Option<AggregateAssessmentStatus>,
    pub risk_direction: RiskDirection,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ComparisonReport {
    pub schema_version: String,
    pub root: String,
    pub entries: Vec<ComparisonEntry>,
}

// ---------------------------------------------------------------------
// Identity fingerprint (spec FR-006/FR-007/FR-008, research.md Decision 3)
// ---------------------------------------------------------------------

fn transport_token(transport: ServerTransport) -> &'static str {
    match transport {
        ServerTransport::Stdio => "stdio",
        ServerTransport::Remote => "remote",
        ServerTransport::Unknown => "unknown",
    }
}

/// Deterministic identity fingerprint derived from three inputs: the
/// agent's *stable machine key* (`AgentKind::key()`, e.g. `"vs-code"` —
/// never its human-facing `display_name()`, which is presentation text
/// that can be reworded without any security-relevant change), normalized
/// config-source identity (inventory's existing `~/`-normalized
/// `config_path` convention), and server name.
///
/// Encoded as a JSON array (`serde_json::to_vec`) before hashing, not a
/// delimiter-joined string: a naive `join("\u{1}")` (the first
/// implementation) is not collision-free, because `McpServer` fields are
/// arbitrary operator-controlled strings with no proof they exclude any
/// particular character — `["a", "b"]` and `["a\u{1}b"]` would hash
/// identically under a plain join. JSON's own string escaping guarantees
/// that two distinct 3-tuples of strings always serialize to different
/// byte sequences, so encoding as `["agent_kind","config_source","server_name"]`
/// and hashing *that* is unambiguous regardless of what characters any
/// input contains.
///
/// Transport is deliberately *not* part of the fingerprint even though the
/// server-identity requirement names it as an input for collision
/// avoidance: `server_name` is already a unique JSON object key within one
/// `config_source`, and `config_source`+agent are unique per discovered
/// config file, so (agent_kind, config_source, server_name) alone is
/// already collision-free for every entry `etherfence_inventory::discover`
/// can produce — two distinct real servers can never share this triple.
/// Folding transport into the fingerprint as well would make a server's
/// transport change indistinguishable from that server being removed and
/// a different one being added (the fingerprint would change), making the
/// closed `transport-changed` drift reason permanently unreachable.
/// Keeping transport out of the fingerprint and comparing it as a normal
/// mutable field (see `drift_reasons_for_pair`) is what makes
/// `transport-changed` an observable, fixture-testable drift reason
/// instead of dead code.
pub fn fingerprint(agent_kind: &str, config_source: &str, server_name: &str) -> String {
    let encoded = serde_json::to_vec(&(agent_kind, config_source, server_name))
        .expect("a tuple of &str always serializes to JSON");
    format!("{:x}", Sha256::digest(&encoded))
}

fn content_fingerprint(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

/// Fingerprints an argument sequence as a canonical JSON array
/// (`serde_json::to_vec`) rather than a delimiter-joined string: a plain
/// `args.join("\u{1}")` cannot distinguish `[]` from `[""]`, or
/// `["a", "b"]` from `["a\u{1}b"]`, since `McpServer.args` accepts
/// arbitrary strings with no guarantee they exclude the empty string or
/// any particular control character. JSON array encoding is
/// position/length-unambiguous by construction, so two distinct argument
/// sequences always hash differently.
fn arguments_fingerprint(args: &[String]) -> String {
    let encoded = serde_json::to_vec(args).expect("a slice of String always serializes to JSON");
    format!("{:x}", Sha256::digest(&encoded))
}

// ---------------------------------------------------------------------
// Building baseline entries from raw discovery output
// ---------------------------------------------------------------------

fn capability_sort_key(label: CapabilityLabel) -> usize {
    CapabilityLabel::ALL
        .iter()
        .position(|candidate| *candidate == label)
        .expect("CapabilityLabel::ALL is exhaustive")
}

fn sort_entry_key(entry: &BaselineServerEntry) -> (String, String, String, &'static str) {
    (
        entry.agent_kind.clone(),
        entry.config_source.clone(),
        entry.server_name.clone(),
        transport_token(entry.transport),
    )
}

/// Builds the full set of baseline entries for one discovery pass. Reuses
/// the crate's existing (crate-private) `server_from_mcp` — the exact same
/// classification/trust-assessment path `detect()` uses — for every raw
/// `McpServer`, so capability labels, trust indicators, and the trust/risk
/// vocabulary can never disagree with what `setup detect` would report for
/// the same input. Raw `command`/`args`/`env` values are read here only
/// long enough to compute safe fingerprints/names; they are never stored.
pub fn build_baseline(root: &Path, items: &[InventoryItem]) -> BaselineDocument {
    let mut servers: Vec<BaselineServerEntry> = Vec::new();
    for item in items {
        for mcp_server in &item.mcp_servers {
            let setup_server = server_from_mcp(mcp_server);
            let invocation_applicable = setup_server.trust_assessment.invocation.applicable;

            let mut environment_variable_names: Vec<String> =
                mcp_server.env.iter().map(|env| env.name.clone()).collect();
            environment_variable_names.sort();
            environment_variable_names.dedup();

            let mut capability_labels = setup_server.capabilities.labels.clone();
            capability_labels.sort_by_key(|label| capability_sort_key(*label));
            capability_labels.dedup();

            let mut trust_indicators: Vec<IndicatorSummary> = setup_server
                .trust_assessment
                .indicators
                .iter()
                .map(|indicator| IndicatorSummary {
                    id: indicator.id.clone(),
                    category: indicator.category,
                    severity: indicator.severity,
                })
                .collect();
            trust_indicators.sort_by(|a, b| a.id.cmp(&b.id));

            let agent_kind = item.agent.key().to_string();
            let agent = item.agent.display_name().to_string();
            let config_source = item.config_path.clone();
            let fp = fingerprint(&agent_kind, &config_source, &setup_server.name);

            servers.push(BaselineServerEntry {
                fingerprint: fp,
                agent_kind,
                agent,
                config_source,
                server_name: setup_server.name.clone(),
                transport: setup_server.transport,
                command_fingerprint: invocation_applicable
                    .then(|| mcp_server.command.as_deref().map(content_fingerprint))
                    .flatten(),
                arguments_fingerprint: invocation_applicable
                    .then(|| arguments_fingerprint(&mcp_server.args)),
                package_identity: setup_server
                    .trust_assessment
                    .invocation
                    .package_identity
                    .clone(),
                package_version_expression: setup_server
                    .trust_assessment
                    .invocation
                    .version_expression,
                executable_path: setup_server.trust_assessment.executable_path,
                sha256: setup_server.trust_assessment.sha256.clone(),
                environment_variable_names,
                capability_labels,
                trust_indicators,
                artifact_identity: setup_server.trust_assessment.artifact_identity,
                configuration_risk: setup_server.trust_assessment.configuration_risk,
                aggregate: setup_server.trust_assessment.aggregate,
                review_state: ReviewState::Unreviewed,
            });
        }
    }
    servers.sort_by(|a, b| sort_entry_key(a).cmp(&sort_entry_key(b)));
    BaselineDocument {
        schema_version: BASELINE_SCHEMA_VERSION.to_string(),
        root: etherfence_core::home_relative_root(root),
        servers,
    }
}

// ---------------------------------------------------------------------
// Baseline consistency validation (hardening: fail closed on a
// hand-edited or corrupted baseline rather than silently comparing
// against misleading data)
// ---------------------------------------------------------------------

fn is_valid_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Validates that a freshly parsed `BaselineDocument` is internally
/// consistent *before* it is ever compared against, so that hand-editing
/// or corruption fails closed (a descriptive `Err`) instead of silently
/// producing a misleading comparison. Pure function, no I/O — the caller
/// (`etherfence-cli`) decides how to report the error.
pub fn validate_baseline(baseline: &BaselineDocument) -> Result<(), String> {
    if baseline.schema_version != BASELINE_SCHEMA_VERSION {
        return Err(format!(
            "unsupported schema version {:?} (expected {:?})",
            baseline.schema_version, BASELINE_SCHEMA_VERSION
        ));
    }

    let mut seen_fingerprints = HashSet::new();
    let mut seen_identities = HashSet::new();
    for entry in &baseline.servers {
        let expected_fingerprint =
            fingerprint(&entry.agent_kind, &entry.config_source, &entry.server_name);
        if entry.fingerprint != expected_fingerprint {
            return Err(format!(
                "server {:?} at {:?} has a fingerprint that does not match its own identity fields (possible hand-editing or corruption)",
                entry.server_name, entry.config_source
            ));
        }
        if !seen_fingerprints.insert(entry.fingerprint.clone()) {
            return Err(format!(
                "duplicate fingerprint {:?} in baseline",
                entry.fingerprint
            ));
        }
        let identity = (
            entry.agent_kind.clone(),
            entry.config_source.clone(),
            entry.server_name.clone(),
        );
        if !seen_identities.insert(identity) {
            return Err(format!(
                "duplicate server identity (agentKind={:?}, configSource={:?}, serverName={:?}) in baseline",
                entry.agent_kind, entry.config_source, entry.server_name
            ));
        }
        if let Some(sha) = &entry.sha256 {
            if !is_valid_sha256_hex(sha) {
                return Err(format!(
                    "server {:?} has a malformed sha256 value",
                    entry.server_name
                ));
            }
        }

        let mut sorted_env = entry.environment_variable_names.clone();
        sorted_env.sort();
        sorted_env.dedup();
        if sorted_env != entry.environment_variable_names {
            return Err(format!(
                "server {:?} environmentVariableNames is not sorted and deduplicated",
                entry.server_name
            ));
        }

        let mut sorted_caps = entry.capability_labels.clone();
        sorted_caps.sort_by_key(|label| capability_sort_key(*label));
        sorted_caps.dedup();
        if sorted_caps != entry.capability_labels {
            return Err(format!(
                "server {:?} capabilityLabels is not sorted and deduplicated",
                entry.server_name
            ));
        }

        let ids: Vec<&str> = entry
            .trust_indicators
            .iter()
            .map(|i| i.id.as_str())
            .collect();
        let mut sorted_unique_ids = ids.clone();
        sorted_unique_ids.sort();
        sorted_unique_ids.dedup();
        if ids != sorted_unique_ids {
            return Err(format!(
                "server {:?} trustIndicators is not sorted by id, or contains a duplicate id",
                entry.server_name
            ));
        }

        let expected_aggregate = aggregate(entry.artifact_identity, entry.configuration_risk);
        if expected_aggregate != entry.aggregate {
            return Err(format!(
                "server {:?} aggregate is inconsistent with its artifactIdentity/configurationRisk",
                entry.server_name
            ));
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------
// Risk ordering (spec FR-021/FR-022, research.md Decision 7)
// ---------------------------------------------------------------------

/// Fixed total order over the 5 `AggregateAssessmentStatus` values, least
/// to most severe (spec FR-021): reused directly rather than introducing a
/// second, parallel risk scale.
pub fn risk_rank(status: AggregateAssessmentStatus) -> u8 {
    match status {
        AggregateAssessmentStatus::VerifiedLocal => 0,
        AggregateAssessmentStatus::KnownSource => 1,
        AggregateAssessmentStatus::Unknown => 2,
        AggregateAssessmentStatus::NeedsReview => 3,
        AggregateAssessmentStatus::HighRisk => 4,
    }
}

fn risk_direction(
    baseline: AggregateAssessmentStatus,
    current: AggregateAssessmentStatus,
) -> RiskDirection {
    let (b, c) = (risk_rank(baseline), risk_rank(current));
    if c > b {
        RiskDirection::Increased
    } else if c < b {
        RiskDirection::Decreased
    } else {
        RiskDirection::Unchanged
    }
}

// ---------------------------------------------------------------------
// Comparison (spec FR-009-FR-023)
// ---------------------------------------------------------------------

fn drift_reasons_for_pair(
    baseline: &BaselineServerEntry,
    current: &BaselineServerEntry,
) -> Vec<DriftReason> {
    let mut reasons = Vec::new();

    let hash_changed = baseline.sha256 != current.sha256;
    if hash_changed && baseline.sha256.is_some() && current.sha256.is_some() {
        reasons.push(DriftReason::ExecutableHashChanged);
    }
    if baseline.command_fingerprint != current.command_fingerprint {
        reasons.push(DriftReason::CommandChanged);
    }
    if baseline.arguments_fingerprint != current.arguments_fingerprint {
        reasons.push(DriftReason::ArgumentsChanged);
    }
    if baseline.package_identity != current.package_identity {
        reasons.push(DriftReason::PackageIdentityChanged);
    }
    if baseline.package_version_expression != current.package_version_expression {
        reasons.push(DriftReason::PackageVersionChanged);
    }
    if baseline.environment_variable_names != current.environment_variable_names {
        reasons.push(DriftReason::EnvironmentVariableNamesChanged);
    }
    if baseline.transport != current.transport {
        reasons.push(DriftReason::TransportChanged);
    }
    if baseline.capability_labels != current.capability_labels {
        reasons.push(DriftReason::CapabilitySetChanged);
    }
    // Compares the full `(id, category, severity)` tuple, not just IDs:
    // an indicator whose id is unchanged but whose severity changed (e.g.
    // after a future EtherFence version reclassifies it) must still count
    // as drift, since severity is what `configuration_risk` is actually
    // derived from (`IndicatorSummary` derives `PartialEq`/`Eq`, and both
    // sides are already sorted by id, so a direct `Vec` comparison is
    // exact and order-stable).
    if baseline.trust_indicators != current.trust_indicators {
        reasons.push(DriftReason::TrustIndicatorSetChanged);
    }
    if baseline.artifact_identity != current.artifact_identity {
        reasons.push(DriftReason::ArtifactIdentityChanged);
    }
    // Direct comparison closes a gap a set-of-reasons approach alone could
    // miss: `configurationRisk` could in principle move (in either
    // direction) without changing `artifactIdentity`, and without the
    // indicator *id* set changing if a future version reassigns severity
    // for an existing id — comparing the field itself, independent of how
    // indicators are compared above, is what actually guarantees a risk
    // change is never silently reported as `unchanged` (a decrease must
    // still surface as drift, per spec FR-023).
    if baseline.configuration_risk != current.configuration_risk {
        reasons.push(DriftReason::ConfigurationRiskChanged);
    }
    if risk_rank(current.aggregate) > risk_rank(baseline.aggregate) {
        reasons.push(DriftReason::RiskIncreased);
    }
    // FR-012/Decision 8: the executable that was hash-verified in the
    // baseline can no longer be hashed now, distinct from a hash that
    // simply changed (both sides present but different digests).
    let became_unverifiable = baseline.artifact_identity
        == ArtifactIdentityConfidence::VerifiedLocal
        && baseline.sha256.is_some()
        && current.sha256.is_none();
    if became_unverifiable {
        reasons.push(DriftReason::ExecutableBecameUnverifiable);
    }

    sort_drift_reasons(&mut reasons);
    reasons
}

/// Compares a previously written baseline against a fresh discovery pass.
/// Pure function — never reads or writes any file itself; the caller
/// (`etherfence-cli`) owns all I/O.
pub fn compare(
    baseline: &BaselineDocument,
    current_items: &[InventoryItem],
    root: &Path,
) -> ComparisonReport {
    let current = build_baseline(root, current_items);

    let mut entries: Vec<ComparisonEntry> = Vec::new();

    for baseline_entry in &baseline.servers {
        let current_entry = current
            .servers
            .iter()
            .find(|entry| entry.fingerprint == baseline_entry.fingerprint);

        let entry = match current_entry {
            None => ComparisonEntry {
                fingerprint: baseline_entry.fingerprint.clone(),
                agent_kind: baseline_entry.agent_kind.clone(),
                agent: baseline_entry.agent.clone(),
                config_source: baseline_entry.config_source.clone(),
                server_name: baseline_entry.server_name.clone(),
                transport: baseline_entry.transport,
                status: ComparisonStatus::Missing,
                reasons: vec![DriftReason::ServerRemoved],
                baseline_risk: Some(baseline_entry.aggregate),
                current_risk: None,
                risk_direction: RiskDirection::NotApplicable,
            },
            Some(current_entry) => {
                let mut reasons = drift_reasons_for_pair(baseline_entry, current_entry);
                // `ArtifactIdentityChanged` and `RiskIncreased` are necessary
                // side effects of the exact same fact `ExecutableBecameUnverifiable`
                // reports (a hash-verified executable losing its verified
                // status mechanically drops artifact identity and raises
                // risk rank) — not independent findings. So a reason set
                // containing only those alongside `ExecutableBecameUnverifiable`
                // still yields `Unverifiable`, not the more generic `Changed`;
                // any other reason present means something independent also
                // drifted, so status falls back to `Changed` (research.md
                // Decision 8).
                let core_reasons_present = reasons.iter().any(|reason| {
                    !matches!(
                        reason,
                        DriftReason::ArtifactIdentityChanged
                            | DriftReason::RiskIncreased
                            | DriftReason::ExecutableBecameUnverifiable
                    )
                });
                let status = if reasons.is_empty() {
                    ComparisonStatus::Unchanged
                } else if reasons.contains(&DriftReason::ExecutableBecameUnverifiable)
                    && !core_reasons_present
                {
                    ComparisonStatus::Unverifiable
                } else {
                    ComparisonStatus::Changed
                };
                sort_drift_reasons(&mut reasons);
                ComparisonEntry {
                    fingerprint: baseline_entry.fingerprint.clone(),
                    agent_kind: current_entry.agent_kind.clone(),
                    agent: current_entry.agent.clone(),
                    config_source: current_entry.config_source.clone(),
                    server_name: current_entry.server_name.clone(),
                    transport: current_entry.transport,
                    status,
                    reasons,
                    baseline_risk: Some(baseline_entry.aggregate),
                    current_risk: Some(current_entry.aggregate),
                    risk_direction: risk_direction(
                        baseline_entry.aggregate,
                        current_entry.aggregate,
                    ),
                }
            }
        };
        entries.push(entry);
    }

    for current_entry in &current.servers {
        let in_baseline = baseline
            .servers
            .iter()
            .any(|entry| entry.fingerprint == current_entry.fingerprint);
        if in_baseline {
            continue;
        }
        entries.push(ComparisonEntry {
            fingerprint: current_entry.fingerprint.clone(),
            agent_kind: current_entry.agent_kind.clone(),
            agent: current_entry.agent.clone(),
            config_source: current_entry.config_source.clone(),
            server_name: current_entry.server_name.clone(),
            transport: current_entry.transport,
            status: ComparisonStatus::New,
            reasons: vec![DriftReason::ServerAdded],
            baseline_risk: None,
            current_risk: Some(current_entry.aggregate),
            risk_direction: RiskDirection::NotApplicable,
        });
    }

    entries.sort_by(|a, b| {
        (
            a.agent_kind.clone(),
            a.config_source.clone(),
            a.server_name.clone(),
            transport_token(a.transport),
        )
            .cmp(&(
                b.agent_kind.clone(),
                b.config_source.clone(),
                b.server_name.clone(),
                transport_token(b.transport),
            ))
    });

    ComparisonReport {
        schema_version: COMPARISON_SCHEMA_VERSION.to_string(),
        root: etherfence_core::home_relative_root(root),
        entries,
    }
}

// ---------------------------------------------------------------------
// Gate predicates (spec FR-027-FR-030)
// ---------------------------------------------------------------------

/// `--fail-on-drift`: any status other than `unchanged`.
pub fn drift_gate_triggered(report: &ComparisonReport) -> bool {
    report
        .entries
        .iter()
        .any(|entry| entry.status != ComparisonStatus::Unchanged)
}

/// `--fail-on-new`: any `new` status.
pub fn new_gate_triggered(report: &ComparisonReport) -> bool {
    report
        .entries
        .iter()
        .any(|entry| entry.status == ComparisonStatus::New)
}

/// `--fail-on-risk-increase`: any entry carrying `risk-increased` among its
/// drift reasons. A risk decrease never satisfies this gate (spec FR-023).
pub fn risk_increase_gate_triggered(report: &ComparisonReport) -> bool {
    report
        .entries
        .iter()
        .any(|entry| entry.reasons.contains(&DriftReason::RiskIncreased))
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherfence_core::{AgentKind, EnvVar, McpServer};

    fn item(agent: AgentKind, config_path: &str, servers: Vec<McpServer>) -> InventoryItem {
        InventoryItem {
            agent,
            config_path: config_path.to_string(),
            mcp_servers: servers,
            evidence: Vec::new(),
        }
    }

    fn stdio_server(name: &str, command: &str, args: &[&str]) -> McpServer {
        McpServer {
            name: name.to_string(),
            command: Some(command.to_string()),
            args: args.iter().map(|a| a.to_string()).collect(),
            env: Vec::new(),
            url: None,
        }
    }

    #[test]
    fn fingerprint_changes_when_any_single_input_changes() {
        let base = fingerprint("Claude Code", "~/.claude.json", "filesystem");
        assert_ne!(base, fingerprint("Cursor", "~/.claude.json", "filesystem"));
        assert_ne!(
            base,
            fingerprint("Claude Code", "~/.cursor/mcp.json", "filesystem")
        );
        assert_ne!(base, fingerprint("Claude Code", "~/.claude.json", "other"));
    }

    #[test]
    fn fingerprint_is_stable_for_identical_inputs() {
        let a = fingerprint("Claude Code", "~/.claude.json", "filesystem");
        let b = fingerprint("Claude Code", "~/.claude.json", "filesystem");
        assert_eq!(a, b);
    }

    #[test]
    fn build_baseline_is_deterministic_across_repeated_calls() {
        let items = vec![item(
            AgentKind::ClaudeCode,
            "~/.claude.json",
            vec![stdio_server(
                "filesystem",
                "npx",
                &["-y", "@modelcontextprotocol/server-filesystem"],
            )],
        )];
        let root = Path::new("/home/example");
        let first = build_baseline(root, &items);
        let second = build_baseline(root, &items);
        assert_eq!(
            serde_json::to_string(&first).unwrap(),
            serde_json::to_string(&second).unwrap()
        );
    }

    #[test]
    fn risk_rank_is_totally_ordered() {
        assert!(
            risk_rank(AggregateAssessmentStatus::VerifiedLocal)
                < risk_rank(AggregateAssessmentStatus::KnownSource)
        );
        assert!(
            risk_rank(AggregateAssessmentStatus::KnownSource)
                < risk_rank(AggregateAssessmentStatus::Unknown)
        );
        assert!(
            risk_rank(AggregateAssessmentStatus::Unknown)
                < risk_rank(AggregateAssessmentStatus::NeedsReview)
        );
        assert!(
            risk_rank(AggregateAssessmentStatus::NeedsReview)
                < risk_rank(AggregateAssessmentStatus::HighRisk)
        );
    }

    #[test]
    fn unchanged_status_when_nothing_differs() {
        let items = vec![item(
            AgentKind::ClaudeCode,
            "~/.claude.json",
            vec![stdio_server(
                "filesystem",
                "npx",
                &["-y", "@modelcontextprotocol/server-filesystem"],
            )],
        )];
        let root = Path::new("/home/example");
        let baseline = build_baseline(root, &items);
        let report = compare(&baseline, &items, root);
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.entries[0].status, ComparisonStatus::Unchanged);
        assert!(report.entries[0].reasons.is_empty());
    }

    #[test]
    fn command_changed_is_detected() {
        let root = Path::new("/home/example");
        let baseline_items = vec![item(
            AgentKind::ClaudeCode,
            "~/.claude.json",
            vec![stdio_server(
                "filesystem",
                "npx",
                &["-y", "@modelcontextprotocol/server-filesystem"],
            )],
        )];
        let current_items = vec![item(
            AgentKind::ClaudeCode,
            "~/.claude.json",
            vec![stdio_server(
                "filesystem",
                "uvx",
                &["-y", "@modelcontextprotocol/server-filesystem"],
            )],
        )];
        let baseline = build_baseline(root, &baseline_items);
        let report = compare(&baseline, &current_items, root);
        assert_eq!(report.entries[0].status, ComparisonStatus::Changed);
        assert!(report.entries[0]
            .reasons
            .contains(&DriftReason::CommandChanged));
    }

    #[test]
    fn arguments_changed_ignores_env_var_reordering_but_not_membership() {
        let root = Path::new("/home/example");
        let mut server_a = stdio_server(
            "filesystem",
            "npx",
            &["-y", "@modelcontextprotocol/server-filesystem"],
        );
        server_a.env = vec![
            EnvVar {
                name: "A".to_string(),
                value_hint: None,
            },
            EnvVar {
                name: "B".to_string(),
                value_hint: None,
            },
        ];
        let mut server_b = server_a.clone();
        server_b.env = vec![
            EnvVar {
                name: "B".to_string(),
                value_hint: None,
            },
            EnvVar {
                name: "A".to_string(),
                value_hint: None,
            },
        ];
        let baseline_items = vec![item(
            AgentKind::ClaudeCode,
            "~/.claude.json",
            vec![server_a],
        )];
        let reordered_items = vec![item(
            AgentKind::ClaudeCode,
            "~/.claude.json",
            vec![server_b.clone()],
        )];
        let baseline = build_baseline(root, &baseline_items);
        let report = compare(&baseline, &reordered_items, root);
        assert_eq!(report.entries[0].status, ComparisonStatus::Unchanged);

        let mut server_c = server_b;
        server_c.env.push(EnvVar {
            name: "C".to_string(),
            value_hint: None,
        });
        let added_items = vec![item(
            AgentKind::ClaudeCode,
            "~/.claude.json",
            vec![server_c],
        )];
        let report2 = compare(&baseline, &added_items, root);
        assert_eq!(report2.entries[0].status, ComparisonStatus::Changed);
        assert!(report2.entries[0]
            .reasons
            .contains(&DriftReason::EnvironmentVariableNamesChanged));
    }

    #[test]
    fn new_and_missing_statuses() {
        let root = Path::new("/home/example");
        let baseline_items = vec![item(
            AgentKind::ClaudeCode,
            "~/.claude.json",
            vec![stdio_server("filesystem", "npx", &["-y", "pkg"])],
        )];
        let baseline = build_baseline(root, &baseline_items);

        let current_items_missing: Vec<InventoryItem> = vec![];
        let report_missing = compare(&baseline, &current_items_missing, root);
        assert_eq!(report_missing.entries[0].status, ComparisonStatus::Missing);
        assert_eq!(
            report_missing.entries[0].reasons,
            vec![DriftReason::ServerRemoved]
        );

        let current_items_new = vec![item(
            AgentKind::ClaudeCode,
            "~/.claude.json",
            vec![
                stdio_server("filesystem", "npx", &["-y", "pkg"]),
                stdio_server("other", "npx", &["-y", "pkg2"]),
            ],
        )];
        let report_new = compare(&baseline, &current_items_new, root);
        let new_entry = report_new
            .entries
            .iter()
            .find(|e| e.server_name == "other")
            .unwrap();
        assert_eq!(new_entry.status, ComparisonStatus::New);
        assert_eq!(new_entry.reasons, vec![DriftReason::ServerAdded]);
    }

    #[test]
    fn duplicate_server_names_across_agents_are_never_conflated() {
        let root = Path::new("/home/example");
        let items = vec![
            item(
                AgentKind::ClaudeCode,
                "~/.claude.json",
                vec![stdio_server("filesystem", "npx", &["-y", "pkg"])],
            ),
            item(
                AgentKind::Cursor,
                "~/.cursor/mcp.json",
                vec![stdio_server("filesystem", "uvx", &["pkg2"])],
            ),
        ];
        let baseline = build_baseline(root, &items);
        assert_eq!(baseline.servers.len(), 2);
        assert_ne!(
            baseline.servers[0].fingerprint,
            baseline.servers[1].fingerprint
        );
        let report = compare(&baseline, &items, root);
        assert_eq!(report.entries.len(), 2);
        assert!(report
            .entries
            .iter()
            .all(|e| e.status == ComparisonStatus::Unchanged));
    }

    #[test]
    fn gate_predicates() {
        let root = Path::new("/home/example");
        let baseline_items = vec![item(
            AgentKind::ClaudeCode,
            "~/.claude.json",
            vec![stdio_server("filesystem", "npx", &["-y", "pkg"])],
        )];
        let baseline = build_baseline(root, &baseline_items);

        let unchanged_report = compare(&baseline, &baseline_items, root);
        assert!(!drift_gate_triggered(&unchanged_report));
        assert!(!new_gate_triggered(&unchanged_report));
        assert!(!risk_increase_gate_triggered(&unchanged_report));

        let new_items = vec![item(
            AgentKind::ClaudeCode,
            "~/.claude.json",
            vec![
                stdio_server("filesystem", "npx", &["-y", "pkg"]),
                stdio_server("extra", "npx", &["-y", "pkg2"]),
            ],
        )];
        let new_report = compare(&baseline, &new_items, root);
        assert!(drift_gate_triggered(&new_report));
        assert!(new_gate_triggered(&new_report));
        assert!(!risk_increase_gate_triggered(&new_report));
    }

    // --- Review finding #1: fingerprint/argument-fingerprint ambiguity ---

    #[test]
    fn arguments_fingerprint_distinguishes_empty_array_from_array_of_empty_string() {
        let empty: Vec<String> = vec![];
        let one_empty: Vec<String> = vec!["".to_string()];
        assert_ne!(
            arguments_fingerprint(&empty),
            arguments_fingerprint(&one_empty)
        );
    }

    #[test]
    fn arguments_fingerprint_does_not_collide_across_element_boundaries() {
        let two_elements = vec!["a".to_string(), "b".to_string()];
        let one_element_with_control_char = vec!["a\u{1}b".to_string()];
        assert_ne!(
            arguments_fingerprint(&two_elements),
            arguments_fingerprint(&one_element_with_control_char)
        );
    }

    #[test]
    fn arguments_fingerprint_distinguishes_different_counts_of_empty_arguments() {
        let one_empty = vec!["".to_string()];
        let two_empty = vec!["".to_string(), "".to_string()];
        assert_ne!(
            arguments_fingerprint(&one_empty),
            arguments_fingerprint(&two_empty)
        );
    }

    #[test]
    fn arguments_fingerprint_handles_unicode_and_control_characters_without_colliding() {
        let a = vec!["héllo\u{0}wörld".to_string(), "🎉".to_string()];
        let b = vec!["héllo".to_string(), "\u{0}wörld\u{1}🎉".to_string()];
        assert_ne!(arguments_fingerprint(&a), arguments_fingerprint(&b));
        assert_eq!(arguments_fingerprint(&a), arguments_fingerprint(&a));
    }

    #[test]
    fn identity_fingerprint_does_not_collide_across_field_boundaries() {
        // "a" + "\x01" + "bc" (as a single config_source) must not collide
        // with "a\x01b" + "\x01" + "c" split differently across fields.
        let x = fingerprint("a", "\u{1}bc", "d");
        let y = fingerprint("a\u{1}b", "c", "d");
        assert_ne!(x, y);
    }

    #[test]
    fn fingerprint_uses_agent_kind_not_display_name() {
        // Review finding #4: a display-name rewording must never change
        // the fingerprint. build_baseline uses AgentKind::key(), not
        // display_name(); verify the two differ for at least one variant
        // and that the fingerprint tracks the stable key.
        assert_ne!(AgentKind::VsCode.key(), AgentKind::VsCode.display_name());
        let root = Path::new("/home/example");
        let items = vec![item(
            AgentKind::VsCode,
            "~/.vscode/mcp.json",
            vec![stdio_server("filesystem", "npx", &["-y", "pkg"])],
        )];
        let baseline = build_baseline(root, &items);
        assert_eq!(
            baseline.servers[0].fingerprint,
            fingerprint("vs-code", "~/.vscode/mcp.json", "filesystem")
        );
        assert_eq!(baseline.servers[0].agent_kind, "vs-code");
        assert_eq!(baseline.servers[0].agent, "VS Code");
    }

    // --- Review finding #5: risk decrease must never report `unchanged` ---

    fn synthetic_entry(
        configuration_risk: ConfigurationRiskStatus,
        artifact_identity: ArtifactIdentityConfidence,
        indicators: Vec<IndicatorSummary>,
    ) -> BaselineServerEntry {
        let agg = aggregate(artifact_identity, configuration_risk);
        BaselineServerEntry {
            fingerprint: fingerprint("claude-code", "~/.claude.json", "filesystem"),
            agent_kind: "claude-code".to_string(),
            agent: "Claude Code".to_string(),
            config_source: "~/.claude.json".to_string(),
            server_name: "filesystem".to_string(),
            transport: ServerTransport::Stdio,
            command_fingerprint: Some(content_fingerprint("npx")),
            arguments_fingerprint: Some(arguments_fingerprint(&["pkg".to_string()])),
            package_identity: None,
            package_version_expression: None,
            executable_path: ExecutablePathClassification::PathResolvedCommand,
            sha256: None,
            environment_variable_names: Vec::new(),
            capability_labels: vec![CapabilityLabel::Unknown],
            trust_indicators: indicators,
            artifact_identity,
            configuration_risk,
            aggregate: agg,
            review_state: ReviewState::Unreviewed,
        }
    }

    #[test]
    fn configuration_risk_decrease_is_never_reported_as_unchanged() {
        // Same indicator *id* set on both sides (so a naive id-only
        // comparison would see no difference), but configuration_risk
        // itself differs — this must still surface as drift, never
        // `unchanged` (spec FR-023's "a decrease is always visible").
        let indicator = IndicatorSummary {
            id: "EF-TRUST-PIN-001".to_string(),
            category: IndicatorCategory::PackagePinning,
            severity: Severity::Medium,
        };
        let baseline_entry = synthetic_entry(
            ConfigurationRiskStatus::NeedsReview,
            ArtifactIdentityConfidence::KnownSource,
            vec![indicator.clone()],
        );
        let current_entry = synthetic_entry(
            ConfigurationRiskStatus::NoKnownIndicators,
            ArtifactIdentityConfidence::KnownSource,
            vec![indicator],
        );
        let reasons = drift_reasons_for_pair(&baseline_entry, &current_entry);
        assert!(
            reasons.contains(&DriftReason::ConfigurationRiskChanged),
            "reasons: {reasons:?}"
        );
        assert!(!reasons.is_empty());
    }

    #[test]
    fn trust_indicator_severity_change_is_detected_even_with_same_id() {
        // Same id, different severity — a naive id-only set comparison
        // would miss this; the full-tuple comparison must not.
        let baseline_entry = synthetic_entry(
            ConfigurationRiskStatus::NeedsReview,
            ArtifactIdentityConfidence::KnownSource,
            vec![IndicatorSummary {
                id: "EF-TRUST-PIN-001".to_string(),
                category: IndicatorCategory::PackagePinning,
                severity: Severity::Medium,
            }],
        );
        let current_entry = synthetic_entry(
            ConfigurationRiskStatus::NeedsReview,
            ArtifactIdentityConfidence::KnownSource,
            vec![IndicatorSummary {
                id: "EF-TRUST-PIN-001".to_string(),
                category: IndicatorCategory::PackagePinning,
                severity: Severity::High,
            }],
        );
        let reasons = drift_reasons_for_pair(&baseline_entry, &current_entry);
        assert!(
            reasons.contains(&DriftReason::TrustIndicatorSetChanged),
            "reasons: {reasons:?}"
        );
    }

    // --- Additional hardening: validate_baseline ---

    fn valid_document(root: &Path, items: &[InventoryItem]) -> BaselineDocument {
        build_baseline(root, items)
    }

    #[test]
    fn validate_baseline_accepts_a_freshly_built_document() {
        let root = Path::new("/home/example");
        let items = vec![item(
            AgentKind::ClaudeCode,
            "~/.claude.json",
            vec![stdio_server("filesystem", "npx", &["-y", "pkg"])],
        )];
        let doc = valid_document(root, &items);
        assert!(validate_baseline(&doc).is_ok());
    }

    #[test]
    fn validate_baseline_rejects_wrong_schema_version() {
        let root = Path::new("/home/example");
        let items = vec![item(
            AgentKind::ClaudeCode,
            "~/.claude.json",
            vec![stdio_server("filesystem", "npx", &["-y", "pkg"])],
        )];
        let mut doc = valid_document(root, &items);
        doc.schema_version = "ef-setup-baseline/v9.9".to_string();
        assert!(validate_baseline(&doc).is_err());
    }

    #[test]
    fn validate_baseline_rejects_fingerprint_mismatch() {
        let root = Path::new("/home/example");
        let items = vec![item(
            AgentKind::ClaudeCode,
            "~/.claude.json",
            vec![stdio_server("filesystem", "npx", &["-y", "pkg"])],
        )];
        let mut doc = valid_document(root, &items);
        doc.servers[0].fingerprint = "0".repeat(64);
        assert!(validate_baseline(&doc).is_err());
    }

    #[test]
    fn validate_baseline_rejects_duplicate_fingerprints() {
        let root = Path::new("/home/example");
        let items = vec![item(
            AgentKind::ClaudeCode,
            "~/.claude.json",
            vec![stdio_server("filesystem", "npx", &["-y", "pkg"])],
        )];
        let mut doc = valid_document(root, &items);
        let clone = doc.servers[0].clone();
        doc.servers.push(clone);
        assert!(validate_baseline(&doc).is_err());
    }

    #[test]
    fn validate_baseline_rejects_malformed_sha256() {
        let root = Path::new("/home/example");
        let items = vec![item(
            AgentKind::ClaudeCode,
            "~/.claude.json",
            vec![stdio_server("filesystem", "npx", &["-y", "pkg"])],
        )];
        let mut doc = valid_document(root, &items);
        doc.servers[0].sha256 = Some("not-a-valid-hex-digest".to_string());
        assert!(validate_baseline(&doc).is_err());
    }

    #[test]
    fn validate_baseline_rejects_unsorted_environment_variable_names() {
        let root = Path::new("/home/example");
        let items = vec![item(
            AgentKind::ClaudeCode,
            "~/.claude.json",
            vec![stdio_server("filesystem", "npx", &["-y", "pkg"])],
        )];
        let mut doc = valid_document(root, &items);
        doc.servers[0].environment_variable_names = vec!["B".to_string(), "A".to_string()];
        assert!(validate_baseline(&doc).is_err());
    }

    #[test]
    fn validate_baseline_rejects_aggregate_inconsistent_with_axes() {
        let root = Path::new("/home/example");
        let items = vec![item(
            AgentKind::ClaudeCode,
            "~/.claude.json",
            vec![stdio_server("filesystem", "npx", &["-y", "pkg"])],
        )];
        let mut doc = valid_document(root, &items);
        doc.servers[0].artifact_identity = ArtifactIdentityConfidence::VerifiedLocal;
        doc.servers[0].configuration_risk = ConfigurationRiskStatus::NoKnownIndicators;
        doc.servers[0].aggregate = AggregateAssessmentStatus::HighRisk; // inconsistent
        assert!(validate_baseline(&doc).is_err());
    }
}
