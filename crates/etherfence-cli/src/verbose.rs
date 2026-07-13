//! Themed verbose scan output: organised by client then server,
//! with consolidated recommendations. Used by `scan --verbose`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use etherfence_core::{
    AgentKind, Finding, FindingCategory, InventoryItem, PostureSummary, ScanReport, Severity,
    PARSE_ERROR_EVIDENCE_PREFIX,
};

use crate::coverage;
use crate::ui::{self, UiTheme};

/// Render the complete themed verbose scan output.
pub(crate) fn render_scan_verbose(report: &ScanReport, debug: bool) -> String {
    let theme = UiTheme::for_stdout();
    let width = ui::human_width();
    let mut out = String::new();

    // ── Overall posture ────────────────────────────────────────────
    render_posture_header(&mut out, &theme, report, width);

    // ── Clients & servers (scored risk findings only) ───────────────
    render_clients_and_servers(&mut out, &theme, report, width, debug);

    // ── Inventory observations ──────────────────────────────────────
    render_category_section(
        &mut out,
        &theme,
        report,
        FindingCategory::Inventory,
        "Inventory observations",
        width,
        debug,
    );

    // ── Informational findings ──────────────────────────────────────
    render_category_section(
        &mut out,
        &theme,
        report,
        FindingCategory::Informational,
        "Informational findings",
        width,
        debug,
    );

    // ── Protection coverage ──────────────────────────────────────────
    if let Some(protection_coverage) = &report.protection_coverage {
        coverage::render_protection_coverage(&mut out, &theme, protection_coverage);
    }

    // ── Consolidated recommendations ───────────────────────────────
    render_consolidated_recommendations(&mut out, &theme, report, width);

    // ── Footer note ────────────────────────────────────────────────
    let _ = writeln!(out, "\n{}", theme.section("Note"));
    let _ = writeln!(
        out,
        "{}",
        ui::wrap_prefixed(
            "",
            "",
            "This scan command is read-only posture discovery. It does not block, proxy, hook, or intercept runtime activity. Runtime MCP boundary enforcement is available separately through `etherfence mcp-proxy`. Findings are posture risks/hints, not confirmed exploitability.",
            width,
        )
    );
    if !debug {
        let _ = writeln!(
            out,
            "\n{}",
            ui::wrap_prefixed(
                "",
                "",
                &theme.muted.apply_to(
                    "Run `etherfence scan --verbose --debug` for full technical evidence including fingerprints and schema details."
                ).to_string(),
                width,
            )
        );
    }
    out
}

// ── Posture header ───────────────────────────────────────────────

fn render_posture_header(out: &mut String, theme: &UiTheme, report: &ScanReport, width: usize) {
    let _ = writeln!(out, "{}", theme.section("Security posture"));

    let _ = writeln!(
        out,
        "{}",
        theme.key_value_wrapped("Scanned", &report.scanned_root, width)
    );

    let total_clients = report
        .inventory
        .iter()
        .map(|item| item.agent.display_name().to_string())
        .collect::<BTreeSet<_>>()
        .len();
    let _ = writeln!(
        out,
        "{}",
        theme.key_value("AI clients", &format!("{total_clients} detected"))
    );

    let total_servers: usize = report
        .inventory
        .iter()
        .map(|item| item.mcp_servers.len())
        .sum();
    let _ = writeln!(
        out,
        "{}",
        theme.key_value("MCP servers", &format!("{total_servers} configured"))
    );

    // Severity breakdown
    let _ = writeln!(
        out,
        "{}",
        theme.key_value_wrapped(
            "Findings",
            &ui::severity_counts(
                theme,
                report.summary.high,
                report.summary.medium,
                report.summary.low,
                report.summary.info,
            ),
            width,
        )
    );

    // Posture score
    if let Some(posture) = &report.posture {
        let grade_style = grade_style(posture, theme);
        let _ = writeln!(
            out,
            "{}",
            theme.key_value(
                "Posture",
                &format!(
                    "{}/100 {} {}",
                    posture.score,
                    ui::em_dash(),
                    grade_style.apply_to(format!("GRADE {}", posture.grade.label()))
                )
            )
        );
        let _ = writeln!(
            out,
            "{}",
            theme.key_value_wrapped("Scope", &posture.scope.human_label(), width)
        );
        let _ = writeln!(
            out,
            "{}",
            theme.key_value_wrapped("Assessment", &posture.assessment, width)
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
                    "{} {} checks={}, pass={}, violations={}",
                    policy.policy_name,
                    ui::em_dash(),
                    policy.checks_total,
                    policy.pass,
                    policy.violation
                )
            )
        );
    }
}

// ── Clients & servers ────────────────────────────────────────────

fn render_clients_and_servers(
    out: &mut String,
    theme: &UiTheme,
    report: &ScanReport,
    width: usize,
    debug: bool,
) {
    let _ = writeln!(out, "\n{}", theme.section("Clients & servers"));

    if report.inventory.is_empty() {
        let _ = writeln!(
            out,
            "No supported agent config files found in conservative scan paths."
        );
        return;
    }

    // Group inventory items by agent display name so one client with
    // several config files reads as one client, not several installations.
    let mut agents: BTreeMap<String, (AgentKind, Vec<&InventoryItem>)> = BTreeMap::new();
    for item in &report.inventory {
        let key = item.agent.display_name().to_string();
        agents
            .entry(key)
            .or_insert_with(|| (item.agent, Vec::new()))
            .1
            .push(item);
    }

    // Map findings: (agent_str, config_path) → Vec<&Finding>. Restricted to
    // scored-risk findings — inventory and informational findings have their
    // own dedicated sections (see `render_category_section`) and must not be
    // duplicated here.
    let mut findings_map: BTreeMap<(String, String), Vec<&Finding>> = BTreeMap::new();
    for finding in &report.findings {
        if finding.category != FindingCategory::Risk {
            continue;
        }
        let key = (finding.agent.to_string(), finding.config_path.clone());
        findings_map.entry(key).or_default().push(finding);
    }

    for (agent, items) in agents.values() {
        let agent_name = agent.display_name();
        let total_servers: usize = items.iter().map(|i| i.mcp_servers.len()).sum();
        let has_parse_error = items.iter().any(|i| {
            i.evidence
                .iter()
                .any(|e| e.starts_with(PARSE_ERROR_EVIDENCE_PREFIX))
        });

        // Collect all config paths for this agent
        let config_paths: Vec<&str> = items.iter().map(|i| i.config_path.as_str()).collect();

        // Client header: agent name + config paths
        let _ = writeln!(out);
        let _ = writeln!(out, "{}", theme.heading.apply_to(agent_name));
        for path in &config_paths {
            let _ = writeln!(out, "  {}", theme.muted.apply_to(format!("({path})")));
        }

        if total_servers > 0 {
            // Show per-server findings across all configs for this agent
            for item in items {
                for server in &item.mcp_servers {
                    let server_findings: Vec<&&Finding> = findings_map
                        .get(&(agent.to_string(), item.config_path.clone()))
                        .map(|findings| {
                            findings
                                .iter()
                                .filter(|f| f.target == server.name)
                                .collect()
                        })
                        .unwrap_or_default();

                    let has_findings = !server_findings.is_empty();
                    // Status reflects actionable risk, not inventory/informational
                    // findings: a server with only non-scoring findings is "OK".
                    let highest_risk_severity = server_findings
                        .iter()
                        .filter(|f| f.category == FindingCategory::Risk)
                        .map(|f| f.severity)
                        .max();

                    let status_marker = match highest_risk_severity {
                        Some(Severity::High) => {
                            theme.danger.apply_to("HIGH".to_string()).to_string()
                        }
                        Some(Severity::Medium) => {
                            theme.warning.apply_to("MEDIUM".to_string()).to_string()
                        }
                        Some(Severity::Low) => theme.info.apply_to("LOW".to_string()).to_string(),
                        Some(Severity::Info) => {
                            theme.muted.apply_to("INFO".to_string()).to_string()
                        }
                        None => theme.success.apply_to("OK").to_string(),
                    };

                    let server_pad = if width < 60 {
                        14
                    } else if width < 80 {
                        20
                    } else {
                        28
                    };

                    let _ = writeln!(
                        out,
                        "  {}  {}  {}",
                        ui::pad(&server.name, server_pad),
                        status_marker,
                        theme
                            .muted
                            .apply_to(format!("{} finding(s)", server_findings.len()))
                    );

                    if has_findings {
                        let sf: Vec<&Finding> = server_findings.iter().map(|f| **f).collect();
                        render_findings(out, theme, &sf, width, debug);
                    }
                }
            }
        } else if has_parse_error {
            let _ = writeln!(
                out,
                "  {}",
                theme.warning.apply_to(format!(
                    "Configuration could not be parsed {} server state unknown.",
                    ui::em_dash()
                ))
            );
        } else {
            let _ = writeln!(
                out,
                "  {}",
                theme.muted.apply_to("No MCP servers configured.")
            );
        }

        // Agent-level findings that don't target a specific server
        let mut agent_level: Vec<&Finding> = Vec::new();
        for item in items {
            if let Some(findings) = findings_map.get(&(agent.to_string(), item.config_path.clone()))
            {
                for finding in findings {
                    let targets_server = items
                        .iter()
                        .any(|i| i.mcp_servers.iter().any(|s| finding.target == s.name));
                    if !targets_server {
                        agent_level.push(finding);
                    }
                }
            }
        }
        if !agent_level.is_empty() {
            let _ = writeln!(out, "\n  {}:", theme.muted.apply_to("Agent-level"));
            render_findings(out, theme, &agent_level, width, debug);
        }
    }
}

// ── Category sections (inventory / informational) ────────────────

/// Renders every finding of `category`, grouped by agent, under its own
/// section heading. Used for "Inventory observations" and "Informational
/// findings" so these non-scoring categories are structurally separated
/// from the scored-risk findings in "Clients & servers" above — not merely
/// badge-differentiated within the same list.
fn render_category_section(
    out: &mut String,
    theme: &UiTheme,
    report: &ScanReport,
    category: FindingCategory,
    heading: &str,
    width: usize,
    debug: bool,
) {
    let _ = writeln!(out, "\n{}", theme.section(heading));

    let mut by_agent: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
    for finding in &report.findings {
        if finding.category != category {
            continue;
        }
        by_agent
            .entry(finding.agent.to_string())
            .or_default()
            .push(finding);
    }

    if by_agent.is_empty() {
        let _ = writeln!(out, "None.");
        return;
    }

    for (agent, findings) in &by_agent {
        let _ = writeln!(out, "\n{}", theme.heading.apply_to(agent));
        render_findings(out, theme, findings, width, debug);
    }
}

fn render_findings(
    out: &mut String,
    theme: &UiTheme,
    findings: &[&Finding],
    width: usize,
    debug: bool,
) {
    let mut findings: Vec<&&Finding> = findings.iter().collect();
    // Stable order: severity desc, then id asc
    findings.sort_by_key(|f| (std::cmp::Reverse(f.severity), &f.id));

    for finding in findings {
        let badge = match finding.category {
            FindingCategory::Inventory => theme.muted.apply_to(ui::pad("OBS", 7)).to_string(),
            FindingCategory::Informational => theme.muted.apply_to(ui::pad("INFO", 7)).to_string(),
            FindingCategory::Risk => match finding.severity {
                Severity::High => theme.danger.apply_to(ui::pad("HIGH", 7)).to_string(),
                Severity::Medium => theme.warning.apply_to(ui::pad("MEDIUM", 7)).to_string(),
                Severity::Low => theme.info.apply_to(ui::pad("LOW", 7)).to_string(),
                Severity::Info => theme.muted.apply_to(ui::pad("INFO", 7)).to_string(),
            },
        };

        let prefix = format!("    {badge} ");
        let continuation = "            ";
        let header = ui::wrap_prefixed(
            &prefix,
            continuation,
            &format!("{}  {}", finding.id, finding.title),
            width,
        );
        let _ = writeln!(out, "{header}");

        let _ = writeln!(
            out,
            "{}",
            ui::wrap_prefixed(
                "          Scope: ",
                "                 ",
                &format!(
                    "{} / {}",
                    finding.agent,
                    etherfence_report::human_layout::sanitize_untrusted_text(&finding.target)
                ),
                width,
            )
        );
        let _ = writeln!(
            out,
            "{}",
            ui::wrap_prefixed(
                "          Rationale: ",
                "                    ",
                &finding.rationale,
                width,
            )
        );
        let _ = writeln!(
            out,
            "{}",
            ui::wrap_prefixed(
                "          Recommendation: ",
                "                         ",
                &finding.recommendation,
                width,
            )
        );

        if debug {
            let _ = writeln!(
                out,
                "{}",
                theme.muted.apply_to(ui::wrap_prefixed(
                    "          ── ",
                    "             ",
                    &format!(
                        "fingerprint={}  schema={}  policy_status={}  baseline={}",
                        finding.fingerprint,
                        "ef-scan-report/v0.1.3",
                        finding.policy_status.label(),
                        finding.baseline_status.label(),
                    ),
                    width,
                ))
            );
        }
    }
}

// ── Consolidated recommendations ─────────────────────────────────

fn render_consolidated_recommendations(
    out: &mut String,
    theme: &UiTheme,
    report: &ScanReport,
    width: usize,
) {
    let _ = writeln!(
        out,
        "\n{}",
        theme.section("Consolidated recommended actions")
    );

    if report.findings.is_empty() {
        let _ = writeln!(out, "No findings to act on.");
        return;
    }

    // Group findings by id. Inventory/informational findings are supporting
    // context — already shown in the sections above — not actionable
    // remediations, so only scored-risk findings become numbered recommendations.
    let mut by_id: BTreeMap<&str, Vec<&Finding>> = BTreeMap::new();
    for finding in &report.findings {
        if finding.category != FindingCategory::Risk {
            continue;
        }
        by_id.entry(&finding.id).or_default().push(finding);
    }

    if by_id.is_empty() {
        let _ = writeln!(out, "No findings to act on.");
        return;
    }

    // Order by severity (highest first), then finding id — deterministic and
    // consistent with the summary's severity-ordered "Next steps".
    let mut groups: Vec<(&&str, &Vec<&Finding>)> = by_id.iter().collect();
    groups.sort_by(|a, b| {
        let a_sev = a.1.iter().map(|f| f.severity).max();
        let b_sev = b.1.iter().map(|f| f.severity).max();
        b_sev.cmp(&a_sev).then_with(|| a.0.cmp(b.0))
    });

    let mut index = 0;
    for (finding_id, findings) in groups {
        index += 1;
        let first = findings.first().unwrap();
        let _ = writeln!(
            out,
            "{}",
            ui::wrap_prefixed(
                &format!("{}. [{}] ", index, finding_id),
                "   ",
                &first.recommendation,
                width,
            )
        );

        // Affected clients/servers
        let mut affected: Vec<String> = Vec::new();
        for finding in findings {
            let entry = format!(
                "{}/{}",
                finding.agent,
                etherfence_report::human_layout::sanitize_untrusted_text(&finding.target)
            );
            if !affected.contains(&entry) {
                affected.push(entry);
            }
        }
        let affected_str = affected.join(", ");
        let _ = writeln!(
            out,
            "{}",
            ui::wrap_prefixed(
                "   ",
                "   ",
                &theme
                    .muted
                    .apply_to(format!("Affected: {affected_str}"))
                    .to_string(),
                width,
            )
        );
    }

    let _ = writeln!(
        out,
        "\n{}",
        ui::wrap_prefixed(
            "",
            "",
            &theme
                .muted
                .apply_to("Run `etherfence setup` to set up deny-by-default `mcp-proxy` policies for detected MCP servers.")
                .to_string(),
            width,
        )
    );
}

fn grade_style<'a>(posture: &PostureSummary, theme: &'a UiTheme) -> &'a dialoguer::console::Style {
    use etherfence_core::PostureGrade;
    match posture.grade {
        PostureGrade::A | PostureGrade::B => &theme.success,
        PostureGrade::C => &theme.warning,
        PostureGrade::D | PostureGrade::F => &theme.danger,
    }
}
