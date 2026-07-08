use anyhow::Result;
use etherfence_core::{Finding, ScanReport, Severity};

pub fn to_json(report: &ScanReport) -> Result<String> {
    Ok(serde_json::to_string_pretty(report)?)
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
    out.push_str("\nNote: EtherFence is scan-only pre-alpha posture discovery. It does not block, proxy, hook, or intercept runtime activity. Findings are posture risks/hints, not confirmed exploitability.\n");
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
        out.push_str(&format!("- Policy file: `{}`\n", policy.policy_path));
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
    out.push_str("_Scan-only pre-alpha output. Findings are posture risks/hints, not confirmed exploitability._\n");
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
            "Policy: {} ({}) checks={}, pass={}, violations={}, not_applicable={}, require_tirith={}\n",
            policy.policy_name,
            policy.policy_path,
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
            status: "pre-alpha-scan-only".to_string(),
            scanned_root: "/home/user".to_string(),
            inventory: Vec::new(),
            findings: Vec::new(),
            summary: Summary::from_counts(0, &[]),
            policy: None,
            baseline: None,
        };
        let rendered = to_human(&report);
        assert!(rendered.contains("scan-only"));
        assert!(rendered.contains("Schema: ef-scan-report/v0.1.1"));
    }

    #[test]
    fn renders_empty_markdown_report() {
        let report = ScanReport {
            schema_version: "ef-scan-report/v0.1.1".to_string(),
            tool: "etherfence".to_string(),
            version: "0.1.3".to_string(),
            status: "pre-alpha-scan-only".to_string(),
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
    }
}
