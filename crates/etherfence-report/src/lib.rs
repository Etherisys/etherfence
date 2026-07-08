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
    out.push_str(&format!(
        "Summary: {} inventory item(s), {} finding(s): high={}, medium={}, low={}, info={}\n\n",
        report.summary.inventory_items,
        report.summary.findings_total,
        report.summary.high,
        report.summary.medium,
        report.summary.low,
        report.summary.info
    ));

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

    if report.findings.is_empty() {
        out.push_str("Findings: none. Missing files are skipped gracefully; this does not prove the host is secure.\n");
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
                    "- {} {}: {} [{} / {}]\n",
                    finding.id, finding.title, finding.target, finding.agent, finding.config_path
                ));
                out.push_str(&format!("  Rationale: {}\n", finding.rationale));
                out.push_str(&format!("  Recommendation: {}\n", finding.recommendation));
            }
        }
    }
    out.push_str("\nNote: EtherFence is scan-only pre-alpha posture discovery. It does not block, proxy, hook, or intercept runtime activity. Findings are posture risks/hints, not confirmed exploitability.\n");
    out
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
            version: "0.1.1".to_string(),
            status: "pre-alpha-scan-only".to_string(),
            scanned_root: "/home/user".to_string(),
            inventory: Vec::new(),
            findings: Vec::new(),
            summary: Summary::from_counts(0, &[]),
        };
        let rendered = to_human(&report);
        assert!(rendered.contains("scan-only"));
        assert!(rendered.contains("Schema: ef-scan-report/v0.1.1"));
    }
}
