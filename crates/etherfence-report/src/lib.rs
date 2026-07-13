use anyhow::Result;
use etherfence_core::{CoverageStatus, Finding, ScanReport, Severity};
use serde_json::{json, Value as JsonValue};

pub mod human_layout;

use human_layout::{wrap_prefixed, DEFAULT_HUMAN_WIDTH};

pub fn to_json(report: &ScanReport) -> Result<String> {
    Ok(serde_json::to_string_pretty(report)?)
}

pub fn to_sarif(report: &ScanReport) -> Result<String> {
    let sarif = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": report.tool,
                    "version": report.version,
                    "informationUri": "https://github.com/Etherisys/etherfence",
                    "rules": sarif_rules(&report.findings),
                }
            },
            "results": report.findings.iter().map(sarif_result).collect::<Vec<_>>(),
            "properties": sarif_run_properties(report)?,
        }]
    });
    Ok(serde_json::to_string_pretty(&sarif)?)
}

fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

fn sarif_rule_name(finding: &Finding) -> String {
    finding
        .kind
        .key()
        .split('-')
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

/// One SARIF rule per distinct finding ID, in first-seen order.
fn sarif_rules(findings: &[Finding]) -> Vec<JsonValue> {
    let mut rules = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for finding in findings {
        if !seen.insert(finding.id.clone()) {
            continue;
        }
        rules.push(json!({
            "id": finding.id,
            "name": sarif_rule_name(finding),
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.rationale},
            "help": {
                "text": format!(
                    "Impact: {} Recommendation: {}",
                    finding.impact, finding.recommendation
                )
            },
            "defaultConfiguration": {"level": sarif_level(finding.severity)},
            "properties": {
                "etherfenceKind": finding.kind.key(),
                "etherfenceSeverity": finding.severity.label().to_ascii_lowercase(),
            }
        }));
    }
    rules
}

fn sarif_result(finding: &Finding) -> JsonValue {
    let mut properties = json!({
        "agent": finding.agent.key(),
        "target": finding.target,
        "configPath": finding.config_path,
        "etherfenceSeverity": finding.severity.label().to_ascii_lowercase(),
        "baselineStatus": finding.baseline_status.label(),
        "policyStatus": finding.policy_status.label(),
        "evidence": finding.evidence,
    });
    if let Some(policy_id) = &finding.policy_id {
        properties["policyId"] = json!(policy_id);
    }
    json!({
        "ruleId": finding.id,
        "level": sarif_level(finding.severity),
        "message": {
            "text": format!(
                "{}: {} Impact: {} Recommendation: {}",
                finding.title, finding.rationale, finding.impact, finding.recommendation
            )
        },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": finding.config_path}
            },
            "logicalLocations": [{
                "name": finding.target,
                "fullyQualifiedName": format!("{}::{}", finding.agent.key(), finding.target),
            }]
        }],
        "partialFingerprints": {
            "etherfenceFingerprint/v1": finding.fingerprint,
        },
        "properties": properties,
    })
}

fn sarif_run_properties(report: &ScanReport) -> Result<JsonValue> {
    let mut properties = json!({
        "etherfenceSchemaVersion": report.schema_version,
        "status": report.status,
        "scannedRoot": report.scanned_root,
        "summary": serde_json::to_value(&report.summary)?,
    });
    if let Some(policy) = &report.policy {
        properties["policy"] = serde_json::to_value(policy)?;
    }
    if let Some(baseline) = &report.baseline {
        properties["baseline"] = serde_json::to_value(baseline)?;
    }
    if let Some(coverage) = &report.protection_coverage {
        properties["protectionCoverage"] = serde_json::to_value(coverage)?;
    }
    Ok(properties)
}

pub fn to_human(report: &ScanReport) -> String {
    to_human_with_width(report, DEFAULT_HUMAN_WIDTH)
}

/// Render verbose human output within an explicit display-column width.
/// Styling is intentionally absent here; the CLI applies its existing theme to
/// the summary, while this complete-evidence path remains safely plain-text.
pub fn to_human_with_width(report: &ScanReport, width: usize) -> String {
    let mut out = String::new();
    out.push_str("EtherFence scan report\n");
    out.push_str("======================\n");
    append_wrapped(
        &mut out,
        "Schema: ",
        "        ",
        &report.schema_version,
        width,
    );
    append_wrapped(&mut out, "Status: ", "        ", &report.status, width);
    append_wrapped(
        &mut out,
        "Scanned root: ",
        "              ",
        &report.scanned_root,
        width,
    );
    append_wrapped(&mut out, "", "", &summary_line(report), width);
    out.push('\n');
    append_human_posture(&mut out, report, width);
    append_human_baseline(&mut out, report, width);
    append_human_policy(&mut out, report, width);
    out.push('\n');
    append_human_inventory(&mut out, report, width);
    append_human_findings(&mut out, report, width);
    out.push('\n');
    append_wrapped(
        &mut out,
        "Note: ",
        "      ",
        "This scan command is read-only posture discovery. It does not block, proxy, hook, or intercept runtime activity. Runtime MCP boundary enforcement is available separately through `etherfence mcp-proxy`. Findings are posture risks/hints, not confirmed exploitability.",
        width,
    );
    out
}

pub fn to_markdown(report: &ScanReport) -> String {
    let mut out = String::new();
    out.push_str("# EtherFence Scan Report\n\n");
    out.push_str(&format!("- Schema: `{}`\n", report.schema_version));
    out.push_str(&format!("- Status: `{}`\n", report.status));
    out.push_str(&format!("- Scanned root: `{}`\n\n", report.scanned_root));

    append_markdown_posture(&mut out, report);
    out.push_str("## Summary\n\n");
    out.push_str("| Inventory items | Findings | High | Medium | Low | Info |\n");
    out.push_str("| ---: | ---: | ---: | ---: | ---: | ---: |\n");
    out.push_str(&format!(
        "| {} | {} | {} | {} | {} | {} |\n\n",
        report.summary.inventory_items,
        report.summary.findings_total,
        report.summary.high,
        report.summary.medium,
        report.summary.low,
        report.summary.info
    ));

    if let Some(baseline) = &report.baseline {
        out.push_str("## Baseline Comparison\n\n");
        out.push_str(&format!("- Baseline: `{}`\n", baseline.baseline_path));
        out.push_str(&format!("- New findings: {}\n", baseline.new));
        out.push_str(&format!("- Existing findings: {}\n", baseline.existing));
        out.push_str(&format!("- Resolved findings: {}\n\n", baseline.resolved));
    }

    if let Some(policy) = &report.policy {
        out.push_str("## Policy Summary\n\n");
        out.push_str(&format!("- Policy: `{}`\n", policy.policy_name));
        out.push_str(&format!(
            "- Policy schema: `{}`\n",
            policy.policy_schema_version
        ));
        if !policy.policy_description.is_empty() {
            out.push_str(&format!("- Description: {}\n", policy.policy_description));
        }
        out.push_str(&format!("- Policy file: `{}`\n", policy.policy_path));
        out.push_str(&format!("- Policy source: `{}`\n", policy.policy_source));
        if let Some(profile) = &policy.policy_profile {
            out.push_str(&format!("- Policy profile: `{profile}`\n"));
        }
        out.push_str(&format!("- Require Tirith: `{}`\n", policy.require_tirith));
        out.push_str(&format!("- Checks: {}\n", policy.checks_total));
        out.push_str(&format!("- Pass: {}\n", policy.pass));
        out.push_str(&format!("- Violations: {}\n", policy.violation));
        out.push_str(&format!("- Not applicable: {}\n\n", policy.not_applicable));
    }

    if let Some(coverage) = &report.protection_coverage {
        out.push_str("## Protection Coverage\n\n");
        out.push_str("| Metric | Count |\n");
        out.push_str("| ---: | :--- |\n");
        out.push_str(&format!("| Total servers | {} |\n", coverage.total_servers));
        out.push_str(&format!("| Covered | {} |\n", coverage.covered));
        out.push_str(&format!("| Not covered | {} |\n", coverage.not_covered));
        out.push_str(&format!(
            "| No policy for agent | {} |\n",
            coverage.no_policy_for_agent
        ));
        out.push_str(&format!(
            "| Empty allowlist | {} |\n",
            coverage.empty_allowlist
        ));
        out.push_str(&format!(
            "| Not applicable | {} |\n",
            coverage.not_applicable
        ));
        out.push_str("\n### Per-Server Coverage\n\n");
        out.push_str("| Agent | Server | Config Path | Status |\n");
        out.push_str("| --- | --- | --- | --- |\n");
        for server in &coverage.servers {
            out.push_str(&format!(
                "| {} | `{}` | `{}` | {} |\n",
                server.agent,
                server.server_name,
                server.config_path,
                coverage_md_label(&server.status),
            ));
        }
        out.push('\n');
    }

    out.push_str("## Inventory\n\n");
    if report.inventory.is_empty() {
        out.push_str("No supported agent config files found in conservative scan paths.\n\n");
    } else {
        for item in &report.inventory {
            out.push_str(&format!("- **{}** (`{}`)", item.agent, item.config_path));
            if item.mcp_servers.is_empty() {
                out.push('\n');
            } else {
                out.push_str(&format!(": {} MCP server(s)\n", item.mcp_servers.len()));
            }
        }
        out.push('\n');
    }

    out.push_str("## Findings\n\n");
    if report.findings.is_empty() {
        out.push_str("No findings displayed. Missing files are skipped gracefully; this does not prove the host is secure.\n\n");
    } else {
        for severity in Severity::ORDERED_DESC {
            let findings: Vec<&Finding> = report
                .findings
                .iter()
                .filter(|finding| finding.severity == severity)
                .collect();
            if findings.is_empty() {
                continue;
            }
            out.push_str(&format!("### {}\n\n", severity.label()));
            for finding in findings {
                out.push_str(&format!("#### {} - {}\n\n", finding.id, finding.title));
                out.push_str(&format!(
                    "- Status: `{}`\n",
                    finding.baseline_status.label()
                ));
                out.push_str(&format!(
                    "- Policy status: `{}`\n",
                    finding.policy_status.label()
                ));
                if let Some(policy_id) = &finding.policy_id {
                    out.push_str(&format!("- Policy ID: `{policy_id}`\n"));
                }
                out.push_str(&format!("- Fingerprint: `{}`\n", finding.fingerprint));
                out.push_str(&format!("- Agent: **{}**\n", finding.agent));
                out.push_str(&format!("- Target: `{}`\n", finding.target));
                out.push_str(&format!("- Config: `{}`\n", finding.config_path));
                out.push_str(&format!("- Rationale: {}\n", finding.rationale));
                out.push_str(&format!("- Impact: {}\n", finding.impact));
                out.push_str(&format!("- Recommendation: {}\n\n", finding.recommendation));
            }
        }
    }
    out.push_str("_This scan command is read-only posture discovery. It does not block, proxy, hook, or intercept runtime activity. Runtime MCP boundary enforcement is available separately through `etherfence mcp-proxy`. Findings are posture risks/hints, not confirmed exploitability._\n");
    out
}

fn append_human_posture(out: &mut String, report: &ScanReport, width: usize) {
    let Some(posture) = &report.posture else {
        return;
    };
    append_wrapped(
        out,
        "Security posture: ",
        "                  ",
        &format!("{}/100 (grade {})", posture.score, posture.grade.label()),
        width,
    );
    append_wrapped(
        out,
        "Scope: ",
        "       ",
        &posture.scope.human_label(),
        width,
    );
    append_wrapped(
        out,
        "Assessment: ",
        "            ",
        &posture.assessment,
        width,
    );
    if !posture.priority_risks.is_empty() {
        out.push_str("Priority risks:\n");
        for risk in &posture.priority_risks {
            append_wrapped(
                out,
                "- ",
                "  ",
                &format!(
                    "{} {} [{} / {}]",
                    risk.finding_id, risk.title, risk.agent, risk.target
                ),
                width,
            );
            append_wrapped(
                out,
                "  Why this matters: ",
                "                    ",
                &risk.why_this_matters,
                width,
            );
        }
        out.push_str("Recommended actions:\n");
        for action in &posture.recommended_actions {
            append_wrapped(
                out,
                &format!("- [{}] ", action.finding_id),
                "  ",
                &action.recommendation,
                width,
            );
        }
    }
}

fn append_markdown_posture(out: &mut String, report: &ScanReport) {
    let Some(posture) = &report.posture else {
        return;
    };
    out.push_str("## Security Posture\n\n");
    out.push_str("| Score | Grade | Active findings | High | Medium | Low | Info |\n");
    out.push_str("| ---: | --- | ---: | ---: | ---: | ---: | ---: |\n");
    out.push_str(&format!(
        "| {} | {} | {} | {} | {} | {} | {} |\n\n",
        posture.score,
        posture.grade.label(),
        posture.active_findings,
        posture.high,
        posture.medium,
        posture.low,
        posture.info
    ));
    out.push_str(&format!("**Scope:** {}\n\n", posture.scope.human_label()));
    out.push_str(&format!("**Assessment:** {}\n\n", posture.assessment));
    if !posture.priority_risks.is_empty() {
        out.push_str("### Priority Risks\n\n");
        for risk in &posture.priority_risks {
            out.push_str(&format!(
                "- **{}** `{}` — {} / {}\n  - Why this matters: {}\n",
                risk.title, risk.finding_id, risk.agent, risk.target, risk.why_this_matters
            ));
        }
        out.push_str("\n### Recommended Next Actions\n\n");
        for action in &posture.recommended_actions {
            out.push_str(&format!(
                "- [`{}`] {}\n",
                action.finding_id, action.recommendation
            ));
        }
        out.push('\n');
    }
}

fn summary_line(report: &ScanReport) -> String {
    format!(
        "Summary: {} inventory item(s), {} finding(s): high={}, medium={}, low={}, info={}",
        report.summary.inventory_items,
        report.summary.findings_total,
        report.summary.high,
        report.summary.medium,
        report.summary.low,
        report.summary.info
    )
}

fn append_human_baseline(out: &mut String, report: &ScanReport, width: usize) {
    if let Some(baseline) = &report.baseline {
        append_wrapped(
            out,
            "Baseline: ",
            "          ",
            &format!(
                "{} (new={}, existing={}, resolved={})",
                baseline.baseline_path, baseline.new, baseline.existing, baseline.resolved
            ),
            width,
        );
    }
}

fn append_human_policy(out: &mut String, report: &ScanReport, width: usize) {
    if let Some(policy) = &report.policy {
        append_wrapped(
            out,
            "Policy: ",
            "        ",
            &format!(
                "{} ({}, source={}, schema={}) checks={}, pass={}, violations={}, not_applicable={}, require_tirith={}",
                policy.policy_name,
                policy.policy_path,
                policy.policy_source,
                policy.policy_schema_version,
                policy.checks_total,
                policy.pass,
                policy.violation,
                policy.not_applicable,
                policy.require_tirith
            ),
            width,
        );
    }
}

fn append_human_inventory(out: &mut String, report: &ScanReport, width: usize) {
    if report.inventory.is_empty() {
        append_wrapped(
            out,
            "Inventory: ",
            "           ",
            "no supported agent config files found in conservative scan paths.",
            width,
        );
        out.push('\n');
    } else {
        out.push_str("Inventory:\n");
        for item in &report.inventory {
            let detail = if item.mcp_servers.is_empty() {
                format!("{} ({})", item.agent, item.config_path)
            } else if let Some(coverage) = &report.protection_coverage {
                let badges: Vec<String> = item
                    .mcp_servers
                    .iter()
                    .map(|server| {
                        let status = coverage
                            .servers
                            .iter()
                            .find(|sc| {
                                sc.agent.key() == item.agent.key()
                                    && sc.server_name == server.name
                                    && sc.config_path == item.config_path
                            })
                            .map(|sc| &sc.status);
                        let badge = status.map(coverage_badge).unwrap_or("[unknown]");
                        format!("{} {}", server.name, badge)
                    })
                    .collect();
                let servers_str = badges.join(", ");
                format!("{} ({}): {}", item.agent, item.config_path, servers_str)
            } else {
                format!(
                    "{} ({}): {} MCP server(s)",
                    item.agent,
                    item.config_path,
                    item.mcp_servers.len()
                )
            };
            append_wrapped(out, "- ", "  ", &detail, width);
        }
        out.push('\n');
    }
}

fn append_human_findings(out: &mut String, report: &ScanReport, width: usize) {
    if report.findings.is_empty() {
        append_wrapped(
            out,
            "Findings: ",
            "          ",
            "none displayed. Missing files are skipped gracefully; this does not prove the host is secure.",
            width,
        );
    } else {
        out.push_str("Findings by severity:\n");
        for severity in Severity::ORDERED_DESC {
            let findings: Vec<&Finding> = report
                .findings
                .iter()
                .filter(|finding| finding.severity == severity)
                .collect();
            if findings.is_empty() {
                continue;
            }
            out.push_str(&format!("\n{}\n", severity.label()));
            for finding in findings {
                append_wrapped(
                    out,
                    "- ",
                    "  ",
                    &format!(
                        "{} {}: {} [{} / {}] status={} policy_status={} fingerprint={}",
                        finding.id,
                        finding.title,
                        finding.target,
                        finding.agent,
                        finding.config_path,
                        finding.baseline_status.label(),
                        finding.policy_status.label(),
                        finding.fingerprint
                    ),
                    width,
                );
                append_wrapped(
                    out,
                    "  Rationale: ",
                    "             ",
                    &finding.rationale,
                    width,
                );
                append_wrapped(
                    out,
                    "  Recommendation: ",
                    "                  ",
                    &finding.recommendation,
                    width,
                );
            }
        }
    }
}

fn append_wrapped(out: &mut String, prefix: &str, continuation: &str, text: &str, width: usize) {
    for line in wrap_prefixed(prefix, continuation, text, width) {
        out.push_str(&line);
        out.push('\n');
    }
}

/// Human-verbose badge for a coverage status.
fn coverage_badge(status: &CoverageStatus) -> &'static str {
    match status {
        CoverageStatus::Covered => "[covered]",
        CoverageStatus::NotCovered => "[not covered]",
        CoverageStatus::NoPolicyForAgent => "[no policy]",
        CoverageStatus::EmptyAllowlist => "[empty allowlist]",
        CoverageStatus::NotApplicable => "[not applicable]",
    }
}

/// Readable label for markdown / SARIF tables.
fn coverage_md_label(status: &CoverageStatus) -> &'static str {
    match status {
        CoverageStatus::Covered => "covered",
        CoverageStatus::NotCovered => "not covered",
        CoverageStatus::NoPolicyForAgent => "no policy for agent",
        CoverageStatus::EmptyAllowlist => "empty allowlist",
        CoverageStatus::NotApplicable => "not applicable",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherfence_core::{ScanReport, Summary};

    #[test]
    fn renders_empty_human_report() {
        let report = ScanReport {
            schema_version: "ef-scan-report/v0.1.2".to_string(),
            tool: "etherfence".to_string(),
            version: "0.1.3".to_string(),
            status: "stable-local-scan".to_string(),
            scanned_root: "/home/user".to_string(),
            inventory: Vec::new(),
            findings: Vec::new(),
            summary: Summary::from_counts(0, &[]),
            posture: None,
            policy: None,
            baseline: None,
            protection_coverage: None,
        };
        let rendered = to_human(&report);
        assert!(rendered.contains("Status: stable-local-scan"));
        assert!(!rendered.to_lowercase().contains("pre-alpha"));
        assert!(!rendered.contains("EtherFence is scan-only"));
        assert!(rendered.contains("This scan command is read-only posture discovery"));
        assert!(rendered.contains("Runtime MCP boundary enforcement is available"));
        assert!(rendered.contains("separately through `etherfence mcp-proxy`"));
        assert!(rendered.contains("Schema: ef-scan-report/v0.1.2"));
    }

    #[test]
    fn renders_empty_markdown_report() {
        let report = ScanReport {
            schema_version: "ef-scan-report/v0.1.2".to_string(),
            tool: "etherfence".to_string(),
            version: "0.1.3".to_string(),
            status: "stable-local-scan".to_string(),
            scanned_root: "/home/user".to_string(),
            inventory: Vec::new(),
            findings: Vec::new(),
            summary: Summary::from_counts(0, &[]),
            posture: None,
            policy: None,
            baseline: None,
            protection_coverage: None,
        };
        let rendered = to_markdown(&report);
        assert!(rendered.contains("# EtherFence Scan Report"));
        assert!(rendered.contains("## Summary"));
        assert!(rendered.contains("## Findings"));
        assert!(rendered.contains("- Status: `stable-local-scan`"));
        assert!(!rendered.to_lowercase().contains("pre-alpha"));
        assert!(rendered.contains("This scan command is read-only posture discovery"));
    }

    #[test]
    fn renders_posture_in_human_and_markdown_reports() {
        use etherfence_core::{PostureGrade, PostureScope, PostureSummary};
        let report = ScanReport {
            schema_version: "ef-scan-report/v0.1.2".to_string(),
            tool: "etherfence".to_string(),
            version: "1.7.0".to_string(),
            status: "stable-local-scan".to_string(),
            scanned_root: "/home/user".to_string(),
            inventory: Vec::new(),
            findings: Vec::new(),
            summary: Summary::from_counts(0, &[]),
            posture: Some(PostureSummary {
                scope: PostureScope::displayed_active(Severity::Info),
                score: 100,
                grade: PostureGrade::A,
                assessment: "No active scored findings are displayed. This is not proof that the host is secure.".to_string(),
                active_findings: 0,
                high: 0,
                medium: 0,
                low: 0,
                info: 0,
                priority_risks: Vec::new(),
                recommended_actions: Vec::new(),
            }),
            policy: None,
            baseline: None,
            protection_coverage: None,
        };
        assert!(to_human(&report).contains("Security posture: 100/100 (grade A)"));
        assert!(to_human(&report)
            .contains("Scope: Displayed active findings at severity threshold: info"));
        assert!(to_markdown(&report).contains("## Security Posture"));
        assert!(to_markdown(&report)
            .contains("**Scope:** Displayed active findings at severity threshold: info"));
    }

    #[test]
    fn informational_only_posture_has_no_human_priority_action() {
        use etherfence_core::{PostureGrade, PostureScope, PostureSummary};
        let report = ScanReport {
            schema_version: "ef-scan-report/v0.1.2".to_string(),
            tool: "etherfence".to_string(),
            version: "1.7.1".to_string(),
            status: "stable-local-scan".to_string(),
            scanned_root: "/home/user".to_string(),
            inventory: Vec::new(),
            findings: Vec::new(),
            summary: Summary::from_counts(0, &[]),
            posture: Some(PostureSummary {
                scope: PostureScope::displayed_active(Severity::Info),
                score: 100,
                grade: PostureGrade::A,
                assessment: "No active scored findings are displayed. This is not proof that the host is secure.".to_string(),
                active_findings: 1,
                high: 0,
                medium: 0,
                low: 0,
                info: 1,
                priority_risks: Vec::new(),
                recommended_actions: Vec::new(),
            }),
            policy: None,
            baseline: None,
            protection_coverage: None,
        };
        let rendered = to_human_with_width(&report, 42);
        assert!(rendered.contains("Security posture: 100/100"));
        assert!(!rendered.contains("Priority risks:"));
        assert!(!rendered.contains("Recommended actions:"));
    }

    #[test]
    fn verbose_human_wraps_long_unicode_risks_and_actions_at_narrow_width() {
        use etherfence_core::{
            AgentKind, PostureGrade, PostureRisk, PostureScope, PostureSummary, RecommendedAction,
        };
        let report = ScanReport {
            schema_version: "ef-scan-report/v0.1.2".to_string(),
            tool: "etherfence".to_string(),
            version: "1.7.1".to_string(),
            status: "stable-local-scan".to_string(),
            scanned_root: "/home/example/a-very-long-root".to_string(),
            inventory: Vec::new(),
            findings: Vec::new(),
            summary: Summary::from_counts(0, &[]),
            posture: Some(PostureSummary {
                scope: PostureScope::displayed_active(Severity::High),
                score: 75,
                grade: PostureGrade::B,
                assessment: "Long assessment text remains readable on constrained terminals.".to_string(),
                active_findings: 1,
                high: 1,
                medium: 0,
                low: 0,
                info: 0,
                priority_risks: vec![PostureRisk {
                    finding_id: "EF-LONG-001".to_string(),
                    severity: Severity::High,
                    title: "Extremely long ASCII title with Unicode 影響範囲".to_string(),
                    agent: AgentKind::ClaudeCode,
                    target: "very-long-target-name-for-regression".to_string(),
                    fingerprint: "efp1-test".to_string(),
                    why_this_matters: "Long impact text must not detach from the finding it explains.".to_string(),
                }],
                recommended_actions: vec![RecommendedAction {
                    finding_id: "EF-LONG-001".to_string(),
                    recommendation: "Review the long recommendation before making any local configuration change.".to_string(),
                }],
            }),
            policy: None,
            baseline: None,
            protection_coverage: None,
        };
        let rendered = to_human_with_width(&report, 42);
        assert!(rendered
            .lines()
            .all(|line| human_layout::display_width(line) <= 42));
        assert!(rendered.contains("- EF-LONG-001"));
        assert!(rendered.contains("- [EF-LONG-001]"));
        let lines: Vec<&str> = rendered.lines().collect();
        let risk_index = lines
            .iter()
            .position(|line| line.starts_with("- EF-LONG-001"))
            .expect("priority risk line");
        assert!(lines[risk_index + 1].starts_with("  "));
        let action_index = lines
            .iter()
            .position(|line| line.starts_with("- [EF-LONG-001]"))
            .expect("recommended action line");
        assert!(lines[action_index + 1].starts_with("  "));
    }

    #[test]
    fn sarif_maps_severities_to_levels() {
        assert_eq!(sarif_level(Severity::High), "error");
        assert_eq!(sarif_level(Severity::Medium), "warning");
        assert_eq!(sarif_level(Severity::Low), "note");
        assert_eq!(sarif_level(Severity::Info), "note");
    }

    #[test]
    fn renders_sarif_with_rule_and_result_for_finding() {
        use etherfence_core::{AgentKind, BaselineStatus, FindingKind, PolicyStatus};
        let mut finding = Finding {
            id: "EF-MCP-001".to_string(),
            title: "Broad filesystem access hint".to_string(),
            severity: Severity::High,
            kind: FindingKind::BroadFilesystemAccess,
            agent: AgentKind::ClaudeCode,
            target: "filesystem".to_string(),
            config_path: "~/.claude.json".to_string(),
            rationale: "rationale text.".to_string(),
            impact: "impact text.".to_string(),
            recommendation: "recommendation text.".to_string(),
            references: Vec::new(),
            fingerprint: String::new(),
            baseline_status: BaselineStatus::NotApplicable,
            policy_status: PolicyStatus::NotApplicable,
            policy_id: None,
            evidence: vec!["/home/user".to_string()],
        };
        finding.refresh_fingerprint();
        let report = ScanReport {
            schema_version: "ef-scan-report/v0.1.2".to_string(),
            tool: "etherfence".to_string(),
            version: "0.1.8".to_string(),
            status: "stable-local-scan".to_string(),
            scanned_root: "/home/user".to_string(),
            inventory: Vec::new(),
            findings: vec![finding],
            summary: Summary::from_counts(0, &[]),
            posture: None,
            policy: None,
            baseline: None,
            protection_coverage: None,
        };
        let rendered = to_sarif(&report).expect("sarif renders");
        let sarif: JsonValue = serde_json::from_str(&rendered).expect("valid JSON");
        assert_eq!(sarif["version"], "2.1.0");
        let run = &sarif["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], "etherfence");
        assert_eq!(run["tool"]["driver"]["version"], "0.1.8");
        let rule = &run["tool"]["driver"]["rules"][0];
        assert_eq!(rule["id"], "EF-MCP-001");
        assert_eq!(rule["name"], "BroadFilesystemAccess");
        assert_eq!(rule["defaultConfiguration"]["level"], "error");
        let result = &run["results"][0];
        assert_eq!(result["ruleId"], "EF-MCP-001");
        assert_eq!(result["level"], "error");
        assert_eq!(
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "~/.claude.json"
        );
        assert!(result["partialFingerprints"]["etherfenceFingerprint/v1"]
            .as_str()
            .unwrap()
            .starts_with("efp1-"));
        assert_eq!(result["properties"]["baselineStatus"], "not_applicable");
    }
}
