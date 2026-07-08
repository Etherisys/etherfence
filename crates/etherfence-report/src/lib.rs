use anyhow::Result;
use etherfence_core::{ScanReport, Severity};

pub fn to_json(report: &ScanReport) -> Result<String> {
    Ok(serde_json::to_string_pretty(report)?)
}

pub fn to_human(report: &ScanReport) -> String {
    let mut out = String::new();
    out.push_str("EtherFence v0.1 scan report\n");
    out.push_str("================================\n");
    out.push_str(&format!("Status: {}\n", report.status));
    out.push_str(&format!("Scanned root: {}\n", report.scanned_root));
    out.push_str(&format!("Inventory items: {}\n", report.inventory.len()));
    out.push_str(&format!("Findings: {}\n\n", report.findings.len()));

    if report.inventory.is_empty() {
        out.push_str(
            "Inventory: no supported agent config files found in conservative v0.1 paths.\n\n",
        );
    } else {
        out.push_str("Inventory:\n");
        for item in &report.inventory {
            out.push_str(&format!("- {} ({})", item.agent, item.config_path));
            if item.mcp_servers.is_empty() {
                out.push('\n');
            } else {
                out.push_str(&format!(": {} MCP server(s)\n", item.mcp_servers.len()));
                for server in &item.mcp_servers {
                    out.push_str(&format!("  - {}\n", server.name));
                }
            }
        }
        out.push('\n');
    }

    if report.findings.is_empty() {
        out.push_str("Findings: none. Missing files are skipped gracefully; this does not prove the host is secure.\n");
    } else {
        out.push_str("Findings:\n");
        for finding in &report.findings {
            out.push_str(&format!(
                "- [{}] {}: {} ({})\n",
                severity_label(finding.severity),
                finding.agent,
                finding.message,
                finding.config_path
            ));
            for evidence in &finding.evidence {
                out.push_str(&format!("  evidence: {evidence}\n"));
            }
        }
    }
    out.push_str("\nNote: EtherFence v0.1.0 is scan-only pre-alpha posture discovery. It does not block, proxy, hook, or intercept runtime activity.\n");
    out
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "INFO",
        Severity::Low => "LOW",
        Severity::Medium => "MEDIUM",
        Severity::High => "HIGH",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherfence_core::ScanReport;

    #[test]
    fn renders_empty_human_report() {
        let report = ScanReport {
            tool: "etherfence".to_string(),
            version: "0.1.0".to_string(),
            status: "pre-alpha-scan-only".to_string(),
            scanned_root: "/home/user".to_string(),
            inventory: Vec::new(),
            findings: Vec::new(),
        };
        let rendered = to_human(&report);
        assert!(rendered.contains("scan-only"));
    }
}
