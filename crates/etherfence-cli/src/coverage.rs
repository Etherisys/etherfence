//! Shared "Protection coverage" rendering, used identically by the concise
//! (`main.rs`) and verbose (`verbose.rs`) human renderers so the two views
//! can never drift from each other.

use std::fmt::Write as _;

use etherfence_core::{CoverageStatus, ProtectionCoverage};

use crate::ui::{self, UiTheme};

pub(crate) fn render_protection_coverage(
    out: &mut String,
    theme: &UiTheme,
    coverage: &ProtectionCoverage,
) {
    let _ = writeln!(out, "\n{}", theme.section("Protection coverage"));
    let _ = writeln!(
        out,
        "{}",
        theme.key_value("Total servers", &coverage.total_servers.to_string())
    );
    let status_line = format!(
        "covered={}, not covered={}, no policy={}, empty allowlist={}",
        coverage.covered,
        coverage.not_covered,
        coverage.no_policy_for_agent,
        coverage.empty_allowlist
    );
    let _ = writeln!(out, "{}", theme.key_value("Status", &status_line));
    if coverage.not_applicable > 0 {
        let _ = writeln!(
            out,
            "{}",
            theme.key_value("Not applicable", &coverage.not_applicable.to_string())
        );
    }

    let mut current_agent = String::new();
    for server in &coverage.servers {
        if server.agent.display_name() != current_agent {
            current_agent = server.agent.display_name().to_string();
            let _ = writeln!(out, "\n{}:", theme.info.apply_to(&current_agent));
        }
        let marker: String = match server.status {
            CoverageStatus::Covered => theme
                .success
                .apply_to(format!("{} covered", ui::checkmark()))
                .to_string(),
            CoverageStatus::NotCovered => theme
                .danger
                .apply_to(format!("{} not covered", ui::cross_mark()))
                .to_string(),
            CoverageStatus::NoPolicyForAgent => theme
                .warning
                .apply_to("~ no policy".to_string())
                .to_string(),
            CoverageStatus::EmptyAllowlist => theme
                .muted
                .apply_to(format!("{} empty allowlist", ui::rule_char()))
                .to_string(),
            CoverageStatus::NotApplicable => theme
                .muted
                .apply_to("  not applicable".to_string())
                .to_string(),
        };
        let _ = writeln!(
            out,
            "  {marker}  {}  {}",
            ui::pad(&server.server_name, 24),
            theme.muted.apply_to(&server.config_path)
        );
    }
}
