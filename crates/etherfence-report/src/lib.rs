use anyhow::Result;
use etherfence_core::{Finding, ScanReport, Severity};
use serde_json::{json, Value as JsonValue};

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
                    "informationUri": "https://github.com/Etherisys-id/etherfence",
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
    Ok(properties)
}

pub fn to_human(report: &ScanReport) -> String {
    let mut out = String::new();
    out.push_str("EtherFence scan report\n");
    out.push_str("======================\n");
    out.push_str(&format!("Schema: {}\n", report.schema_version));
    out.push_str(&format!("Status: {}\n", report.status));
    out.push_str(&format!("Scanned root: {}\n", report.scanned_root));
    out.push_str(&summary_line(report));
    out.push('\n');
    append_human_baseline(&mut out, report);
    append_human_policy(&mut out, report);
    out.push('\n');
    append_human_inventory(&mut out, report);
    append_human_findings(&mut out, report);
    out.push_str("\nNote: This scan command is read-only posture discovery. It does not block, proxy, hook, or intercept runtime activity. Runtime MCP boundary enforcement is available separately through `etherfence mcp-proxy`. Findings are posture risks/hints, not confirmed exploitability.\n");
    out
}

pub fn to_markdown(report: &ScanReport) -> String {
    let mut out = String::new();
    out.push_str("# EtherFence Scan Report\n\n");
    out.push_str(&format!("- Schema: `{}`\n", report.schema_version));
    out.push_str(&format!("- Status: `{}`\n", report.status));
    out.push_str(&format!("- Scanned root: `{}`\n\n", report.scanned_root));

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

fn append_human_baseline(out: &mut String, report: &ScanReport) {
    if let Some(baseline) = &report.baseline {
        out.push_str(&format!(
            "Baseline: {} (new={}, existing={}, resolved={})\n",
            baseline.baseline_path, baseline.new, baseline.existing, baseline.resolved
        ));
    }
}

fn append_human_policy(out: &mut String, report: &ScanReport) {
    if let Some(policy) = &report.policy {
        out.push_str(&format!(
            "Policy: {} ({}, source={}, schema={}) checks={}, pass={}, violations={}, not_applicable={}, require_tirith={}\n",
            policy.policy_name,
            policy.policy_path,
            policy.policy_source,
            policy.policy_schema_version,
            policy.checks_total,
            policy.pass,
            policy.violation,
            policy.not_applicable,
            policy.require_tirith
        ));
    }
}

fn append_human_inventory(out: &mut String, report: &ScanReport) {
    if report.inventory.is_empty() {
        out.push_str(
            "Inventory: no supported agent config files found in conservative scan paths.\n\n",
        );
    } else {
        out.push_str("Inventory:\n");
        for item in &report.inventory {
            out.push_str(&format!("- {} ({})", item.agent, item.config_path));
            if item.mcp_servers.is_empty() {
                out.push('\n');
            } else {
                out.push_str(&format!(": {} MCP server(s)\n", item.mcp_servers.len()));
            }
        }
        out.push('\n');
    }
}

fn append_human_findings(out: &mut String, report: &ScanReport) {
    if report.findings.is_empty() {
        out.push_str("Findings: none displayed. Missing files are skipped gracefully; this does not prove the host is secure.\n");
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
                out.push_str(&format!(
                    "- {} {}: {} [{} / {}] status={} policy_status={} fingerprint={}\n",
                    finding.id,
                    finding.title,
                    finding.target,
                    finding.agent,
                    finding.config_path,
                    finding.baseline_status.label(),
                    finding.policy_status.label(),
                    finding.fingerprint
                ));
                out.push_str(&format!("  Rationale: {}\n", finding.rationale));
                out.push_str(&format!("  Recommendation: {}\n", finding.recommendation));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherfence_core::{ScanReport, Summary};

    #[test]
    fn renders_empty_human_report() {
        let report = ScanReport {
            schema_version: "ef-scan-report/v0.1.1".to_string(),
            tool: "etherfence".to_string(),
            version: "0.1.3".to_string(),
            status: "stable-local-scan".to_string(),
            scanned_root: "/home/user".to_string(),
            inventory: Vec::new(),
            findings: Vec::new(),
            summary: Summary::from_counts(0, &[]),
            policy: None,
            baseline: None,
        };
        let rendered = to_human(&report);
        assert!(rendered.contains("Status: stable-local-scan"));
        assert!(!rendered.to_lowercase().contains("pre-alpha"));
        assert!(!rendered.contains("EtherFence is scan-only"));
        assert!(rendered.contains("This scan command is read-only posture discovery"));
        assert!(
            rendered.contains("Runtime MCP boundary enforcement is available separately through")
        );
        assert!(rendered.contains("Schema: ef-scan-report/v0.1.1"));
    }

    #[test]
    fn renders_empty_markdown_report() {
        let report = ScanReport {
            schema_version: "ef-scan-report/v0.1.1".to_string(),
            tool: "etherfence".to_string(),
            version: "0.1.3".to_string(),
            status: "stable-local-scan".to_string(),
            scanned_root: "/home/user".to_string(),
            inventory: Vec::new(),
            findings: Vec::new(),
            summary: Summary::from_counts(0, &[]),
            policy: None,
            baseline: None,
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
            schema_version: "ef-scan-report/v0.1.1".to_string(),
            tool: "etherfence".to_string(),
            version: "0.1.8".to_string(),
            status: "stable-local-scan".to_string(),
            scanned_root: "/home/user".to_string(),
            inventory: Vec::new(),
            findings: vec![finding],
            summary: Summary::from_counts(0, &[]),
            policy: None,
            baseline: None,
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
