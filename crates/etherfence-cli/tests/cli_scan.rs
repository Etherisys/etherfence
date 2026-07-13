use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn fixture_root(name: &str) -> String {
    format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn policy_path(profile: &str) -> String {
    format!(
        "{}/../../examples/policies/{profile}.toml",
        env!("CARGO_MANIFEST_DIR")
    )
}

fn strict_policy() -> String {
    policy_path("strict")
}

fn ci_runner_policy() -> String {
    policy_path("ci-runner")
}

fn temp_file(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "etherfence-{name}-{}-{nanos}.json",
        std::process::id()
    ))
}

fn run(args: &[&str]) -> std::process::Output {
    run_with_env(args, &[])
}

fn run_with_env(args: &[&str], env: &[(&str, &str)]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_etherfence"));
    command.args(args).envs(env.iter().copied());
    command.output().expect("run etherfence scan")
}

#[test]
fn scan_fixture_json_has_stable_top_level_schema() {
    let root = fixture_root("home");
    let output = run(&["scan", "--root", &root, "--format", "json"]);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");

    assert_eq!(json["schema_version"], "ef-scan-report/v0.1.3");
    assert_eq!(json["tool"], "etherfence");
    assert_eq!(json["version"], "1.7.4");
    assert_eq!(json["status"], "stable-local-scan");
    assert!(json.get("scanned_root").is_some());
    assert!(json["inventory"].is_array());
    assert!(json["findings"].is_array());
    assert!(json["summary"].is_object());
    assert_eq!(json["summary"]["inventory_items"], 12);
    let posture = &json["posture"];
    assert_eq!(posture["score"], 0);
    assert_eq!(posture["grade"], "f");
    assert!(posture["assessment"]
        .as_str()
        .unwrap()
        .contains("prompt review"));
    assert!(posture["priority_risks"].is_array());
    assert_eq!(posture["priority_risks"].as_array().unwrap().len(), 3);
    assert_eq!(
        posture["priority_risks"][0]["finding_id"],
        posture["recommended_actions"][0]["finding_id"]
    );

    let first = json["findings"]
        .as_array()
        .unwrap()
        .first()
        .expect("at least one finding");
    for key in [
        "id",
        "title",
        "severity",
        "agent",
        "target",
        "rationale",
        "impact",
        "recommendation",
        "references",
        "fingerprint",
        "baseline_status",
        "policy_status",
        "category",
    ] {
        assert!(first.get(key).is_some(), "missing finding key {key}");
    }

    let findings = json["findings"].as_array().unwrap();
    let ids: Vec<&str> = findings
        .iter()
        .filter_map(|finding| finding["id"].as_str())
        .collect();
    assert!(ids.contains(&"EF-MCP-001"));
    assert!(ids.contains(&"EF-MCP-002"));
    assert!(ids.contains(&"EF-MCP-003"));
    assert!(ids.contains(&"EF-MCP-004"));
    assert!(ids.contains(&"EF-SEC-001"));
    assert!(ids.contains(&"EF-TIRITH-002"));

    // EF-MCP-000/004 are pure inventory facts: informational severity, never
    // scored. EF-SEC-001 is preserved exactly as a scored, actionable finding.
    for finding in findings {
        match finding["id"].as_str().unwrap() {
            "EF-MCP-000" | "EF-MCP-004" => {
                assert_eq!(finding["severity"], "info");
                assert_eq!(finding["category"], "inventory");
            }
            "EF-SEC-001" => {
                assert_eq!(finding["severity"], "medium");
                assert_eq!(finding["category"], "risk");
            }
            "EF-TIRITH-001" | "EF-TIRITH-002" => {
                assert_eq!(finding["severity"], "info");
                assert_eq!(finding["category"], "informational");
            }
            _ => {}
        }
    }
}

#[test]
fn scan_windows_fixture_json_discovers_windows_style_configs() {
    let root = fixture_root("windows-home");
    let output = run(&["scan", "--root", &root, "--format", "json"]);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(json["summary"]["inventory_items"], 11);
    assert!(json["inventory"].as_array().unwrap().iter().any(|item| {
        item["agent"] == "vs-code"
            && item["config_path"] == "~/AppData/Roaming/Code/User/settings.json"
    }));
    assert!(json["findings"].as_array().unwrap().iter().any(|finding| {
        finding["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .any(|evidence| {
                evidence
                    .as_str()
                    .unwrap_or_default()
                    .contains("C:/Users/example")
            })
    }));
}

#[test]
fn scan_fixture_human_default_is_executive_summary() {
    let root = fixture_root("home");
    let output = run(&["scan", "--root", &root]);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Security posture"));
    assert!(stdout.contains("Posture"));
    assert!(stdout.contains("GRADE F"));
    assert!(stdout.contains("Scope"));
    assert!(stdout.contains("Displayed active scored-risk findings at severity threshold: info"));
    assert!(stdout.contains("Assessment"));
    assert!(stdout.contains("Overall status:"));
    assert!(stdout.contains("Clients"));
    assert!(stdout.contains("Inventory observations"));
    assert!(stdout.contains("Informational findings"));
    assert!(stdout.contains("Priority findings"));
    assert!(stdout.contains("Why this matters:"));
    assert!(stdout.contains("Next steps"));
    assert!(stdout.contains("`etherfence scan --verbose`"));
    assert!(stdout.contains("`etherfence setup`"));
    // High findings surface with their IDs even in the summary.
    assert!(stdout.contains("HIGH"));
    assert!(stdout.contains("EF-MCP-001"));
    // Full evidence stays behind --verbose.
    assert!(!stdout.contains("Rationale:"));
    assert!(!stdout.contains("fingerprint=efp1-"));
    // The read-only, no-overclaiming note stays on the default view.
    assert!(stdout.contains("This scan command is read-only posture discovery"));
    assert!(stdout.contains("exploitability"));
}

#[test]
fn human_posture_is_narrow_plain_and_deterministic() {
    let root = fixture_root("home");
    let args = ["scan", "--root", &root];
    let first = run_with_env(&args, &[("COLUMNS", "42"), ("NO_COLOR", "1")]);
    let second = run_with_env(&args, &[("COLUMNS", "42"), ("NO_COLOR", "1")]);
    assert!(first.status.success());
    assert_eq!(first.stdout, second.stdout);
    let stdout = String::from_utf8_lossy(&first.stdout);
    assert!(!stdout.contains("\u{1b}["));
    assert!(stdout.contains("EF-MCP-001"));
    assert!(stdout.contains("[EF-MCP-001]"));
    assert!(stdout
        .lines()
        .all(|line| etherfence_report::human_layout::display_width(line) <= 42));

    let verbose = run_with_env(
        &["scan", "--root", &root, "--verbose"],
        &[("COLUMNS", "42"), ("NO_COLOR", "1")],
    );
    assert!(verbose.status.success());
    let verbose_stdout = String::from_utf8_lossy(&verbose.stdout);
    assert!(!verbose_stdout.contains("\u{1b}["));
    assert!(verbose_stdout.contains("Rationale:"));
    assert!(verbose_stdout
        .lines()
        .all(|line| etherfence_report::human_layout::display_width(line) <= 42));
}

#[test]
fn very_narrow_terminal_clamps_to_minimum_and_is_safe() {
    let root = fixture_root("home");
    // COLUMNS=15 is below MIN_SUPPORTED_WIDTH (30). Wrapped sections
    // must fit within MIN_SUPPORTED_WIDTH. Fixed-layout lines (client
    // list, overall status) use key_value() which does not wrap but
    // is short enough to be readable even when the terminal is tiny.
    let output = run_with_env(
        &["scan", "--root", &root],
        &[("COLUMNS", "15"), ("NO_COLOR", "1")],
    );
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("\u{1b}["));
    let min = etherfence_report::human_layout::MIN_SUPPORTED_WIDTH;

    // Wrapped sections (scope, assessment, findings, risk body, note)
    // must respect the clamped width.
    let scope_start = stdout.find("Scope ").unwrap();
    let assessment_end = stdout.find("Assessment").unwrap()
        + stdout[stdout.find("Assessment").unwrap()..]
            .find("\n\n")
            .unwrap_or(stdout.len() - stdout.find("Assessment").unwrap());
    for line in stdout[scope_start..assessment_end].lines() {
        assert!(
            etherfence_report::human_layout::display_width(line) <= min,
            "scope/assessment line too wide: {line:?}"
        );
    }

    // The note footer is wrapped too.
    let note_start = stdout.find("Note:").unwrap();
    for line in stdout[note_start..].lines() {
        assert!(
            etherfence_report::human_layout::display_width(line) <= min,
            "note line too wide: {line:?}"
        );
    }

    // Reasonable content still present.
    assert!(stdout.contains("EF-MCP-001"));
    assert!(stdout.contains("NEEDS ATTENTION"));
    assert!(stdout.contains("exploitability"));
}

#[test]
fn scan_fixture_human_verbose_groups_by_severity_and_guidance() {
    let root = fixture_root("home");
    let output = run(&["scan", "--root", &root, "--verbose"]);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Security posture"));
    assert!(stdout.contains("Scope"));
    assert!(stdout.contains("Clients & servers"));
    assert!(stdout.contains("HIGH"));
    assert!(stdout.contains("Rationale:"));
    assert!(stdout.contains("Recommendation:"));
    assert!(stdout.contains("Consolidated recommended actions"));
    assert!(stdout.contains("exploitability"));
    // Fingerprints only appear in --debug mode
    assert!(!stdout.contains("fingerprint=efp1-"));
    // No legacy schema/status noise
    assert!(!stdout.contains("stable-local-scan"));
}

#[test]
fn scan_verbose_consolidated_excludes_context_and_orders_by_severity() {
    // F-16 / v1.7.4: EF-MCP-000 ("MCP server configured") and EF-MCP-004
    // ("MCP environment variables exposed") are non-scoring inventory
    // observations, not actionable remediations, so neither may appear as a
    // consolidated action (the bracketed `[ID]` form is only used there).
    // F-11: consolidated actions are ordered by severity then id — the High
    // EF-MCP-001 is first, ahead of the Medium EF-SEC-001.
    let root = fixture_root("home");
    let output = run(&["scan", "--root", &root, "--verbose"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        !stdout.contains("[EF-MCP-000]"),
        "EF-MCP-000 must not be a consolidated recommendation"
    );
    assert!(
        !stdout.contains("[EF-MCP-004]"),
        "EF-MCP-004 must not be a consolidated recommendation (non-scoring inventory observation)"
    );
    assert!(
        stdout.contains("1. [EF-MCP-001]"),
        "High finding must be #1"
    );
    let high = stdout.find("[EF-MCP-001]").expect("EF-MCP-001 present");
    let sec = stdout.find("[EF-SEC-001]").expect("EF-SEC-001 present");
    assert!(
        high < sec,
        "High EF-MCP-001 must precede Medium EF-SEC-001 in consolidated actions"
    );
}

#[test]
fn scan_verbose_shows_obs_badge_for_inventory_findings() {
    // v1.7.4: EF-MCP-000/EF-MCP-004 are non-scoring inventory observations and
    // must render with a distinct `OBS` badge, not a HIGH/MEDIUM/LOW/INFO
    // severity badge, so they read as "observed" rather than "risky".
    let root = fixture_root("home");
    let output = run(&["scan", "--root", &root, "--verbose"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("OBS"),
        "verbose output must show an OBS badge for inventory findings"
    );
}

#[test]
fn scan_verbose_has_four_distinct_category_sections_in_order_with_no_duplication() {
    // FR-009: verbose output must structurally separate inventory
    // observations, scored risk findings, informational findings, and
    // protection/policy coverage into their own sections — not merely
    // differentiate them by badge within a single mixed list.
    let root = fixture_root("home");
    let output = run(&[
        "scan",
        "--root",
        &root,
        "--policy-profile",
        "developer-laptop",
        "--verbose",
    ]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    let clients_pos = stdout
        .find("Clients & servers")
        .expect("Clients & servers heading");
    let inventory_pos = stdout
        .find("Inventory observations")
        .expect("Inventory observations heading");
    let informational_pos = stdout
        .find("Informational findings")
        .expect("Informational findings heading");
    let coverage_pos = stdout
        .find("Protection coverage")
        .expect("Protection coverage heading");
    let consolidated_pos = stdout
        .find("Consolidated recommended actions")
        .expect("Consolidated recommended actions heading");

    // Ordering: risk findings first, then inventory, then informational,
    // then protection coverage, then the consolidated action list.
    assert!(clients_pos < inventory_pos);
    assert!(inventory_pos < informational_pos);
    assert!(informational_pos < coverage_pos);
    assert!(coverage_pos < consolidated_pos);

    // Population: EF-MCP-000/EF-MCP-004 (inventory) live only in the
    // Inventory observations section, never in Clients & servers.
    let clients_section = &stdout[clients_pos..inventory_pos];
    let inventory_section = &stdout[inventory_pos..informational_pos];
    assert!(
        !clients_section.contains("EF-MCP-000"),
        "EF-MCP-000 must not appear in Clients & servers"
    );
    assert!(
        !clients_section.contains("EF-MCP-004"),
        "EF-MCP-004 must not appear in Clients & servers"
    );
    assert!(inventory_section.contains("EF-MCP-000"));
    assert!(inventory_section.contains("EF-MCP-004"));

    // EF-TIRITH-002 (informational) lives only in Informational findings.
    let informational_section = &stdout[informational_pos..coverage_pos];
    assert!(!clients_section.contains("EF-TIRITH-002"));
    assert!(!inventory_section.contains("EF-TIRITH-002"));
    assert!(informational_section.contains("EF-TIRITH-002"));

    // A scored-risk finding (EF-MCP-001) lives only in Clients & servers,
    // never duplicated into the inventory/informational sections.
    assert!(clients_section.contains("EF-MCP-001"));
    assert!(!inventory_section.contains("EF-MCP-001"));
    assert!(!informational_section.contains("EF-MCP-001"));

    // Non-duplication, globally: every finding ID/target pair appears in
    // exactly one of the three finding-derived sections above.
    for id in ["EF-MCP-000", "EF-MCP-004", "EF-TIRITH-002", "EF-MCP-001"] {
        let occurrences = [clients_section, inventory_section, informational_section]
            .iter()
            .filter(|section| section.contains(id))
            .count();
        assert_eq!(occurrences, 1, "{id} must appear in exactly one section");
    }
}

#[test]
fn no_secret_value_ever_appears_in_any_output_format() {
    // FR-006 / SC-004: the `home` fixture's MCP servers carry env vars with
    // secret-shaped names whose configured values are "fixture-value" and
    // "test-fixture-key-redacted". Those raw values must never appear in any
    // scan output format — only the (non-secret) variable names may appear.
    let root = fixture_root("home");
    let secret_values = ["fixture-value", "test-fixture-key-redacted"];

    for format in ["human", "markdown", "sarif", "json"] {
        let output = run(&["scan", "--root", &root, "--format", format]);
        assert!(output.status.success(), "format={format}");
        let stdout = String::from_utf8_lossy(&output.stdout);
        for secret in secret_values {
            assert!(
                !stdout.contains(secret),
                "format={format} must never contain the raw secret value {secret:?}"
            );
        }
    }

    let verbose = run(&["scan", "--root", &root, "--verbose", "--debug"]);
    assert!(verbose.status.success());
    let verbose_stdout = String::from_utf8_lossy(&verbose.stdout);
    for secret in secret_values {
        assert!(
            !verbose_stdout.contains(secret),
            "verbose --debug output must never contain the raw secret value {secret:?}"
        );
    }
}

#[test]
fn scan_verbose_debug_shows_fingerprints_and_schema() {
    // F-20: positive coverage for the v1.7.3 `--debug` flag.
    let root = fixture_root("home");
    let output = run(&["scan", "--root", &root, "--verbose", "--debug"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("fingerprint=efp1-"),
        "debug shows fingerprints"
    );
    assert!(
        stdout.contains("schema=ef-scan-report/v0.1.3"),
        "debug shows schema id"
    );

    // Without --debug the same metadata is absent.
    let plain = run(&["scan", "--root", &root, "--verbose"]);
    assert!(!String::from_utf8_lossy(&plain.stdout).contains("fingerprint=efp1-"));
}

#[test]
fn scan_debug_requires_verbose() {
    // F-19: `--debug` without `--verbose` must fail (clap `requires`), not be a
    // silent no-op.
    let root = fixture_root("home");
    let output = run(&["scan", "--root", &root, "--debug"]);
    assert!(!output.status.success(), "--debug alone must be rejected");
    assert!(String::from_utf8_lossy(&output.stderr).contains("--verbose"));
}

#[test]
fn scan_verbose_distinguishes_unparsable_from_zero_server_configs() {
    // F-20 / v1.7.3 claim 2: an unparsable config reads "server state unknown",
    // distinct from a confirmed zero-server "No MCP servers configured".
    let root = fixture_root("malformed-home");
    let output = run(&["scan", "--root", &root, "--verbose"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Configuration could not be parsed"),
        "unparsable config must be surfaced as parse failure"
    );
}

#[test]
fn scan_fixture_human_status_and_note_are_v1_compatible() {
    let root = fixture_root("home");
    let output = run(&["scan", "--root", &root, "--verbose"]);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(!stdout.to_lowercase().contains("pre-alpha"));
    assert!(!stdout.contains("EtherFence is scan-only"));

    assert!(stdout.contains("This scan command is read-only posture discovery"));
    assert!(stdout.contains("Runtime MCP boundary enforcement is available"));
    assert!(stdout.contains("`etherfence mcp-proxy`"));
}

#[test]
fn severity_threshold_high_displays_only_high_findings() {
    let root = fixture_root("home");
    let output = run(&[
        "scan",
        "--root",
        &root,
        "--severity-threshold",
        "high",
        "--verbose",
    ]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("HIGH"));
    assert!(stdout.contains("EF-MCP-001"));
    assert!(!stdout.contains("\nMEDIUM\n"));
    assert!(!stdout.contains("\nLOW\n"));
    assert!(!stdout.contains("\nINFO\n"));
    assert!(stdout.contains("5 high"));
}

#[test]
fn inventory_observations_are_unaffected_by_severity_threshold() {
    // Inventory facts (server counts) must never disappear or contradict
    // the "MCP servers ... configured" header count just because
    // --severity-threshold filters out the non-scoring EF-MCP-000/EF-MCP-004
    // findings that would otherwise back a naive finding-derived count.
    let root = fixture_root("home");

    let default_output = run(&["scan", "--root", &root]);
    assert!(default_output.status.success());
    let default_stdout = String::from_utf8_lossy(&default_output.stdout);
    let configured_line = default_stdout
        .lines()
        .find(|line| line.contains("MCP servers") && line.contains("configured"))
        .expect("MCP servers configured header line");
    let expected_count: usize = configured_line
        .split_whitespace()
        .find_map(|token| token.parse::<usize>().ok())
        .expect("a server count in the header line");
    assert!(expected_count > 0);

    for threshold in ["low", "medium", "high"] {
        let output = run(&["scan", "--root", &root, "--severity-threshold", threshold]);
        assert!(output.status.success(), "threshold={threshold}");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("Inventory observations"),
            "threshold={threshold} must still show the Inventory observations section"
        );
        assert!(
            stdout.contains(&format!("{expected_count} (non-scoring)")),
            "threshold={threshold} inventory count must match the header count ({expected_count}), stdout:\n{stdout}"
        );
        assert!(
            !stdout.contains("No inventory observations recorded"),
            "threshold={threshold} must never claim zero inventory observations while servers are configured"
        );
    }
}

#[test]
fn posture_scope_is_visible_and_matches_the_effective_threshold_in_all_formats() {
    let root = fixture_root("home");
    let expected_scope = "Displayed active scored-risk findings at severity threshold: high";

    let default_human = run(&["scan", "--root", &root, "--severity-threshold", "high"]);
    assert!(default_human.status.success());
    assert!(String::from_utf8_lossy(&default_human.stdout).contains(expected_scope));

    let verbose_human = run(&[
        "scan",
        "--root",
        &root,
        "--severity-threshold",
        "high",
        "--verbose",
    ]);
    assert!(verbose_human.status.success());
    assert!(String::from_utf8_lossy(&verbose_human.stdout).contains(expected_scope));

    let markdown = run(&[
        "scan",
        "--root",
        &root,
        "--severity-threshold",
        "high",
        "--format",
        "markdown",
    ]);
    assert!(markdown.status.success());
    assert!(
        String::from_utf8_lossy(&markdown.stdout).contains(&format!("**Scope:** {expected_scope}"))
    );

    let json = run(&[
        "scan",
        "--root",
        &root,
        "--severity-threshold",
        "high",
        "--format",
        "json",
    ]);
    assert!(json.status.success());
    let report: Value = serde_json::from_slice(&json.stdout).expect("valid JSON output");
    assert_eq!(
        report["posture"]["scope"]["finding_selection"],
        "displayed-active-risk-category-findings"
    );
    assert_eq!(report["posture"]["scope"]["severity_threshold"], "high");
    assert_eq!(
        report["posture"]["scope"]["resolved_baseline_findings"],
        "excluded"
    );
}

#[test]
fn fail_on_high_returns_non_zero_when_high_findings_exist() {
    let root = fixture_root("home");
    let output = run(&["scan", "--root", &root, "--fail-on", "high"]);

    assert_eq!(output.status.code(), Some(2));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("EF-MCP-001"));
}

#[test]
fn fail_on_high_returns_zero_when_no_high_findings_exist() {
    let root = fixture_root("safe-home");
    let output = run(&["scan", "--root", &root, "--fail-on", "high", "--verbose"]);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("0 high"));
}

#[test]
fn fail_on_and_fail_on_new_remain_severity_only_not_category_aware() {
    // v1.7.4 decision (documented in CHANGELOG/docs/README): --fail-on and
    // --fail-on-new stay purely severity-based, unchanged code. Reclassifying
    // EF-MCP-000 from low to info is therefore an intentional, documented
    // compatibility change: `--fail-on low` no longer trips on a fixture whose
    // only finding is the now-info-severity "MCP server configured" fact,
    // whereas v1.7.3 (where it was low) would have failed here.
    let root = fixture_root("safe-home");

    // "safe-home" has exactly one active finding: EF-MCP-000 at `info`.
    let fail_on_low = run(&["scan", "--root", &root, "--fail-on", "low"]);
    assert!(
        fail_on_low.status.success(),
        "--fail-on low must now pass on an inventory-only (info-severity) fixture"
    );

    let fail_on_medium = run(&["scan", "--root", &root, "--fail-on", "medium"]);
    assert!(fail_on_medium.status.success());

    let fail_on_high = run(&["scan", "--root", &root, "--fail-on", "high"]);
    assert!(fail_on_high.status.success());

    // --fail-on info still trips on the inventory finding: threshold-based
    // gating is unchanged, only the finding's severity value changed.
    let fail_on_info = run(&["scan", "--root", &root, "--fail-on", "info"]);
    assert_eq!(
        fail_on_info.status.code(),
        Some(2),
        "--fail-on info must still trip on any active finding, inventory or not"
    );

    // --fail-on-new mirrors the same severity-only semantics against a
    // baseline that doesn't yet know about this finding.
    let baseline = temp_file("fail-on-new-severity-semantics");
    let empty_baseline = r#"{"schema_version":"ef-baseline/v0.1.4","tool":"etherfence","version":"0","findings":[]}"#;
    std::fs::write(&baseline, empty_baseline).expect("write empty baseline");
    let baseline_s = baseline.to_string_lossy().to_string();

    let fail_on_new_low = run(&[
        "scan",
        "--root",
        &root,
        "--baseline",
        &baseline_s,
        "--fail-on-new",
        "low",
    ]);
    assert!(
        fail_on_new_low.status.success(),
        "--fail-on-new low must now pass for a new info-severity inventory finding"
    );

    let fail_on_new_info = run(&[
        "scan",
        "--root",
        &root,
        "--baseline",
        &baseline_s,
        "--fail-on-new",
        "info",
    ]);
    assert_eq!(
        fail_on_new_info.status.code(),
        Some(2),
        "--fail-on-new info must still trip on the new inventory finding"
    );
}

#[test]
fn markdown_output_has_review_headings_and_guidance() {
    let root = fixture_root("home");
    let output = run(&["scan", "--root", &root, "--format", "markdown"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("# EtherFence Scan Report"));
    assert!(stdout.contains("## Security Posture"));
    assert!(stdout.contains("### Priority Risks"));
    assert!(stdout.contains("### Recommended Next Actions"));
    assert!(stdout.contains("## Summary"));
    assert!(stdout.contains("| Inventory items | Findings | High | Medium | Low | Info |"));
    assert!(stdout.contains("## Inventory"));
    assert!(stdout.contains("## Findings"));
    assert!(stdout.contains("### HIGH"));
    assert!(stdout.contains("#### EF-MCP-001 - Broad filesystem access hint"));
    assert!(stdout.contains("- Status: `not_applicable`"));
    assert!(stdout.contains("- Fingerprint: `efp1-"));
    assert!(stdout.contains("- Rationale:"));
    assert!(stdout.contains("- Impact:"));
    assert!(stdout.contains("- Recommendation:"));
    assert!(stdout.contains("- Status: `stable-local-scan`"));
    assert!(!stdout.to_lowercase().contains("pre-alpha"));
    assert!(stdout.contains("This scan command is read-only posture discovery"));
    assert!(stdout.contains("Runtime MCP boundary enforcement is available"));
}

#[test]
fn write_baseline_creates_json_with_fingerprints() {
    let root = fixture_root("home");
    let baseline = temp_file("write-baseline");
    let baseline_s = baseline.to_string_lossy().to_string();
    let output = run(&["scan", "--root", &root, "--write-baseline", &baseline_s]);

    assert!(output.status.success());
    let content = std::fs::read(&baseline).expect("baseline file exists");
    let json: Value = serde_json::from_slice(&content).expect("valid baseline json");
    assert_eq!(json["schema_version"], "ef-baseline/v0.1.4");
    assert_eq!(json["tool"], "etherfence");
    assert!(json["findings"].as_array().unwrap().len() > 10);
    assert!(json["findings"][0]["fingerprint"]
        .as_str()
        .unwrap()
        .starts_with("efp1-"));
}

#[test]
fn baseline_marks_existing_findings() {
    let root = fixture_root("home");
    let baseline = temp_file("existing");
    let baseline_s = baseline.to_string_lossy().to_string();
    assert!(
        run(&["scan", "--root", &root, "--write-baseline", &baseline_s])
            .status
            .success()
    );

    let output = run(&[
        "scan",
        "--root",
        &root,
        "--baseline",
        &baseline_s,
        "--format",
        "json",
    ]);
    assert!(output.status.success());
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(json["baseline"]["new"], 0);
    assert_eq!(json["baseline"]["resolved"], 0);
    assert!(json["baseline"]["existing"].as_u64().unwrap() > 10);
    assert!(json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .all(|finding| finding["baseline_status"] == "existing"));
}

#[test]
fn baseline_detects_new_findings() {
    let safe_root = fixture_root("safe-home");
    let risky_root = fixture_root("home");
    let baseline = temp_file("new");
    let baseline_s = baseline.to_string_lossy().to_string();
    assert!(run(&[
        "scan",
        "--root",
        &safe_root,
        "--write-baseline",
        &baseline_s
    ])
    .status
    .success());

    let output = run(&[
        "scan",
        "--root",
        &risky_root,
        "--baseline",
        &baseline_s,
        "--format",
        "json",
        "--severity-threshold",
        "high",
    ]);
    assert!(output.status.success());
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert!(json["baseline"]["new"].as_u64().unwrap() >= 3);
    assert!(json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|finding| finding["baseline_status"] == "new"));
}

#[test]
fn baseline_reports_resolved_findings() {
    let risky_root = fixture_root("home");
    let safe_root = fixture_root("safe-home");
    let baseline = temp_file("resolved");
    let baseline_s = baseline.to_string_lossy().to_string();
    assert!(run(&[
        "scan",
        "--root",
        &risky_root,
        "--write-baseline",
        &baseline_s
    ])
    .status
    .success());

    let output = run(&[
        "scan",
        "--root",
        &safe_root,
        "--baseline",
        &baseline_s,
        "--verbose",
    ]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("resolved="));
}

#[test]
fn fail_on_new_high_returns_non_zero_for_new_high_findings() {
    let safe_root = fixture_root("safe-home");
    let risky_root = fixture_root("home");
    let baseline = temp_file("fail-new");
    let baseline_s = baseline.to_string_lossy().to_string();
    assert!(run(&[
        "scan",
        "--root",
        &safe_root,
        "--write-baseline",
        &baseline_s
    ])
    .status
    .success());

    let output = run(&[
        "scan",
        "--root",
        &risky_root,
        "--baseline",
        &baseline_s,
        "--fail-on-new",
        "high",
    ]);
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn fail_on_new_high_returns_zero_when_high_findings_are_existing() {
    let root = fixture_root("home");
    let baseline = temp_file("fail-existing");
    let baseline_s = baseline.to_string_lossy().to_string();
    assert!(
        run(&["scan", "--root", &root, "--write-baseline", &baseline_s])
            .status
            .success()
    );

    let output = run(&[
        "scan",
        "--root",
        &root,
        "--baseline",
        &baseline_s,
        "--fail-on-new",
        "high",
    ]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("new=0"));
    assert!(stdout.contains("existing="));
}

#[test]
fn policy_json_includes_metadata_and_policy_findings() {
    let root = fixture_root("home");
    let policy = strict_policy();
    let output = run(&[
        "scan", "--root", &root, "--policy", &policy, "--format", "json",
    ]);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(
        json["policy"]["policy_name"],
        "strict-local-ai-agent-policy"
    );
    assert_eq!(json["policy"]["require_tirith"], true);
    assert_eq!(json["policy"]["policy_source"], "file");
    assert!(json["policy"].get("policy_profile").is_none());
    assert_eq!(json["policy"]["policy_schema_version"], "ef-policy/v0.1");
    assert!(json["policy"]["policy_description"]
        .as_str()
        .unwrap()
        .contains("Strict scan-only"));
    assert!(json["policy"]["violation"].as_u64().unwrap() > 0);
    assert!(json["findings"].as_array().unwrap().iter().any(|finding| {
        finding["id"] == "EF-POL-001"
            && finding["policy_status"] == "violation"
            && finding["policy_id"] == "unexpected-mcp-server"
    }));
}

#[test]
fn policy_fail_on_high_returns_non_zero_for_high_policy_violations() {
    let root = fixture_root("home");
    let policy = strict_policy();
    let output = run(&[
        "scan",
        "--root",
        &root,
        "--policy",
        &policy,
        "--fail-on",
        "high",
        "--verbose",
    ]);

    assert_eq!(output.status.code(), Some(2));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Policy"));
    assert!(stdout.contains("EF-POL-001"));
}

#[test]
fn policy_baseline_fail_on_new_high_returns_zero_when_policy_findings_are_existing() {
    let root = fixture_root("home");
    let policy = strict_policy();
    let baseline = temp_file("policy-existing");
    let baseline_s = baseline.to_string_lossy().to_string();
    assert!(run(&[
        "scan",
        "--root",
        &root,
        "--policy",
        &policy,
        "--write-baseline",
        &baseline_s,
    ])
    .status
    .success());

    let output = run(&[
        "scan",
        "--root",
        &root,
        "--policy",
        &policy,
        "--baseline",
        &baseline_s,
        "--fail-on-new",
        "high",
        "--verbose",
    ]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("new=0"));
    assert!(stdout.contains("Policy"));
}

#[test]
fn markdown_policy_output_has_policy_summary() {
    let root = fixture_root("home");
    let policy = strict_policy();
    let output = run(&[
        "scan", "--root", &root, "--policy", &policy, "--format", "markdown",
    ]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("## Policy Summary"));
    assert!(stdout.contains("- Policy: `strict-local-ai-agent-policy`"));
    assert!(stdout.contains("- Policy status: `violation`"));
}

#[test]
fn invalid_policy_file_fails_with_clear_error() {
    let root = fixture_root("home");
    let policy_path = temp_file("invalid-policy");
    std::fs::write(&policy_path, "[policy\nname = broken\n").expect("write invalid policy");
    let policy_s = policy_path.to_string_lossy().to_string();
    let output = run(&["scan", "--root", &root, "--policy", &policy_s]);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("parsing policy file"), "stderr: {stderr}");
}

#[test]
fn unsupported_policy_schema_fails_with_clear_error() {
    let root = fixture_root("home");
    let policy_path = temp_file("unsupported-policy");
    std::fs::write(
        &policy_path,
        "schema_version = \"ef-policy/v9.9\"\nname = \"future\"\n",
    )
    .expect("write unsupported policy");
    let policy_s = policy_path.to_string_lossy().to_string();
    let output = run(&["scan", "--root", &root, "--policy", &policy_s]);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unsupported policy schema_version"),
        "stderr: {stderr}"
    );
}

#[test]
fn built_in_example_policies_parse_and_scan_fixture() {
    let root = fixture_root("home");
    for profile in [
        "developer-laptop",
        "ci-runner",
        "research-workstation",
        "strict",
    ] {
        let policy = policy_path(profile);
        let output = run(&[
            "scan", "--root", &root, "--policy", &policy, "--format", "json",
        ]);
        assert!(
            output.status.success(),
            "profile={profile} stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
        assert_eq!(json["policy"]["policy_schema_version"], "ef-policy/v0.1");
        let expected_name = if profile == "strict" {
            "strict-local-ai-agent-policy"
        } else {
            profile
        };
        assert_eq!(json["policy"]["policy_name"], expected_name);
    }
}

#[test]
fn scan_policy_profile_developer_laptop_works_and_sets_builtin_metadata() {
    let root = fixture_root("home");
    let output = run(&[
        "scan",
        "--root",
        &root,
        "--policy-profile",
        "developer-laptop",
        "--format",
        "json",
    ]);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(json["policy"]["policy_name"], "developer-laptop");
    assert_eq!(json["policy"]["policy_path"], "builtin:developer-laptop");
    assert_eq!(json["policy"]["policy_source"], "built-in-profile");
    assert_eq!(json["policy"]["policy_profile"], "developer-laptop");
    assert_eq!(json["policy"]["policy_schema_version"], "ef-policy/v0.1");
}

#[test]
fn scan_policy_profile_ci_runner_works() {
    let root = fixture_root("home");
    let output = run(&[
        "scan",
        "--root",
        &root,
        "--policy-profile",
        "ci-runner",
        "--format",
        "json",
    ]);

    assert!(output.status.success());
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(json["policy"]["policy_name"], "ci-runner");
    assert!(json["policy"]["violation"].as_u64().unwrap() > 0);
}

#[test]
fn scan_policy_profile_ci_runner_works_with_windows_fixture() {
    let root = fixture_root("windows-home");
    let output = run(&[
        "scan",
        "--root",
        &root,
        "--policy-profile",
        "ci-runner",
        "--format",
        "json",
    ]);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(json["policy"]["policy_name"], "ci-runner");
    assert_eq!(json["policy"]["policy_source"], "built-in-profile");
    assert!(json["policy"]["violation"].as_u64().unwrap() > 0);
}

#[test]
fn scan_policy_profile_unknown_fails_clearly() {
    let root = fixture_root("home");
    let output = run(&["scan", "--root", &root, "--policy-profile", "unknown"]);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unknown built-in policy profile \"unknown\""),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains("etherfence policy list"),
        "stderr: {stderr}"
    );
}

#[test]
fn scan_policy_file_and_policy_profile_are_mutually_exclusive() {
    let root = fixture_root("home");
    let policy = ci_runner_policy();
    let output = run(&[
        "scan",
        "--root",
        &root,
        "--policy",
        &policy,
        "--policy-profile",
        "ci-runner",
    ]);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("mutually exclusive"), "stderr: {stderr}");
    assert!(stderr.contains("--policy <file>"), "stderr: {stderr}");
    assert!(
        stderr.contains("--policy-profile <name>"),
        "stderr: {stderr}"
    );
}

#[test]
fn policy_profile_ci_runner_fail_on_high_behaves_like_policy_file() {
    let root = fixture_root("home");
    let policy = ci_runner_policy();
    let file_output = run(&[
        "scan",
        "--root",
        &root,
        "--policy",
        &policy,
        "--fail-on",
        "high",
    ]);
    let profile_output = run(&[
        "scan",
        "--root",
        &root,
        "--policy-profile",
        "ci-runner",
        "--fail-on",
        "high",
        "--verbose",
    ]);

    assert_eq!(file_output.status.code(), Some(2));
    assert_eq!(profile_output.status.code(), Some(2));
    let stdout = String::from_utf8_lossy(&profile_output.stdout);
    assert!(stdout.contains("ci-runner"));
}

#[test]
fn policy_profile_ci_runner_baseline_fail_on_new_high_works() {
    let root = fixture_root("home");
    let baseline = temp_file("policy-profile-existing");
    let baseline_s = baseline.to_string_lossy().to_string();
    assert!(run(&[
        "scan",
        "--root",
        &root,
        "--policy-profile",
        "ci-runner",
        "--write-baseline",
        &baseline_s,
    ])
    .status
    .success());

    let output = run(&[
        "scan",
        "--root",
        &root,
        "--policy-profile",
        "ci-runner",
        "--baseline",
        &baseline_s,
        "--fail-on-new",
        "high",
        "--verbose",
    ]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("new=0"));
    assert!(stdout.contains("ci-runner"));
}

#[test]
fn ci_runner_policy_has_deterministic_policy_findings_on_risky_fixture() {
    let root = fixture_root("home");
    let policy = policy_path("ci-runner");
    let output = run(&[
        "scan", "--root", &root, "--policy", &policy, "--format", "json",
    ]);

    assert!(output.status.success());
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    let ids: Vec<&str> = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|finding| finding["id"].as_str())
        .filter(|id| id.starts_with("EF-POL"))
        .collect();
    assert!(ids.contains(&"EF-POL-001"));
    assert!(ids.contains(&"EF-POL-002"));
    assert!(ids.contains(&"EF-POL-003"));
    assert!(ids.contains(&"EF-POL-004"));
    assert_eq!(json["policy"]["policy_name"], "ci-runner");
    assert_eq!(
        json["policy"]["violation"].as_u64().unwrap(),
        ids.len() as u64
    );
}

#[test]
fn scan_minimal_fixture_has_inventory_but_no_findings() {
    let root = fixture_root("minimal-home");
    let output = run(&["scan", "--root", &root, "--format", "json"]);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(json["summary"]["inventory_items"], 5);
    assert_eq!(json["summary"]["findings_total"], 0);
    assert!(json["findings"].as_array().unwrap().is_empty());
}

#[test]
fn scan_multi_fixture_reports_all_servers_deterministically() {
    let root = fixture_root("multi-home");
    let output = run(&["scan", "--root", &root, "--format", "json"]);

    assert!(output.status.success());
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    let claude = json["inventory"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["agent"] == "claude-code")
        .expect("claude inventory item");
    let names: Vec<&str> = claude["mcp_servers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|server| server["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["fetch", "filesystem", "github"]);

    let ids: Vec<&str> = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|finding| finding["id"].as_str())
        .collect();
    assert!(ids.contains(&"EF-MCP-001"));
    assert!(ids.contains(&"EF-SEC-001"));
    assert!(!ids.contains(&"EF-CFG-001"));

    let second = run(&["scan", "--root", &root, "--format", "json"]);
    assert_eq!(output.stdout, second.stdout, "scan output is deterministic");
}

#[test]
fn scan_malformed_fixture_succeeds_and_reports_parse_findings() {
    let root = fixture_root("malformed-home");
    let output = run(&["scan", "--root", &root, "--format", "json"]);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(json["summary"]["inventory_items"], 6);
    let parse_findings: Vec<&Value> = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|finding| finding["id"] == "EF-CFG-001")
        .collect();
    assert_eq!(parse_findings.len(), 2, "claude JSON and codex TOML");
    for finding in parse_findings {
        assert_eq!(finding["severity"], "low");
        assert_eq!(finding["kind"], "config-parse-error");
        assert!(finding["evidence"][0]
            .as_str()
            .unwrap()
            .starts_with("parse-error:"));
    }
}

fn sarif_results(json: &Value) -> &Vec<Value> {
    json["runs"][0]["results"]
        .as_array()
        .expect("results array")
}

fn sarif_rules(json: &Value) -> &Vec<Value> {
    json["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .expect("rules array")
}

#[test]
fn sarif_output_is_valid_and_maps_severity_levels() {
    let root = fixture_root("home");
    let output = run(&["scan", "--root", &root, "--format", "sarif"]);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid SARIF JSON");
    assert_eq!(json["version"], "2.1.0");
    assert_eq!(
        json["$schema"],
        "https://json.schemastore.org/sarif-2.1.0.json"
    );
    let driver = &json["runs"][0]["tool"]["driver"];
    assert_eq!(driver["name"], "etherfence");
    assert_eq!(driver["version"], "1.7.4");

    let rules = sarif_rules(&json);
    let rule_ids: Vec<&str> = rules
        .iter()
        .map(|rule| rule["id"].as_str().unwrap())
        .collect();
    let mut deduped = rule_ids.clone();
    deduped.sort();
    deduped.dedup();
    assert_eq!(deduped.len(), rule_ids.len(), "rule IDs are unique");
    assert!(rule_ids.contains(&"EF-MCP-001"));

    let results = sarif_results(&json);
    assert!(!results.is_empty());
    for result in results {
        let rule_id = result["ruleId"].as_str().unwrap();
        assert!(
            rule_ids.contains(&rule_id),
            "result rule {rule_id} declared"
        );
        let level = result["level"].as_str().unwrap();
        let severity = result["properties"]["etherfenceSeverity"].as_str().unwrap();
        let expected = match severity {
            "high" => "error",
            "medium" => "warning",
            "low" | "info" => "note",
            other => panic!("unexpected severity {other}"),
        };
        assert_eq!(level, expected);
        assert!(result["partialFingerprints"]["etherfenceFingerprint/v1"]
            .as_str()
            .unwrap()
            .starts_with("efp1-"));
    }

    let mcp = results
        .iter()
        .find(|result| result["ruleId"] == "EF-MCP-001")
        .expect("broad filesystem result");
    assert_eq!(mcp["level"], "error");
    assert_eq!(
        mcp["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "~/.claude.json"
    );
    assert_eq!(mcp["properties"]["agent"], "claude-code");
    assert_eq!(mcp["properties"]["target"], "filesystem");
    let message = mcp["message"]["text"].as_str().unwrap();
    assert!(message.contains("Broad filesystem access hint"));
    assert!(message.contains("Impact:"));
    assert!(message.contains("Recommendation:"));
}

#[test]
fn sarif_policy_scan_includes_policy_rule_and_result() {
    let root = fixture_root("home");
    let policy = strict_policy();
    let output = run(&[
        "scan", "--root", &root, "--policy", &policy, "--format", "sarif",
    ]);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid SARIF JSON");
    assert!(sarif_rules(&json)
        .iter()
        .any(|rule| rule["id"] == "EF-POL-001"));
    let policy_result = sarif_results(&json)
        .iter()
        .find(|result| result["ruleId"] == "EF-POL-001")
        .expect("policy violation result");
    assert_eq!(policy_result["level"], "error");
    assert_eq!(policy_result["properties"]["policyStatus"], "violation");
    assert_eq!(
        policy_result["properties"]["policyId"],
        "unexpected-mcp-server"
    );
    assert_eq!(
        json["runs"][0]["properties"]["policy"]["policy_name"],
        "strict-local-ai-agent-policy"
    );
}

#[test]
fn sarif_policy_profile_scan_works() {
    let root = fixture_root("home");
    let output = run(&[
        "scan",
        "--root",
        &root,
        "--policy-profile",
        "ci-runner",
        "--format",
        "sarif",
    ]);

    assert!(output.status.success());
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid SARIF JSON");
    assert_eq!(
        json["runs"][0]["properties"]["policy"]["policy_source"],
        "built-in-profile"
    );
    assert!(sarif_results(&json)
        .iter()
        .any(|result| result["ruleId"].as_str().unwrap().starts_with("EF-POL")));
}

#[test]
fn sarif_baseline_scan_marks_existing_findings() {
    let root = fixture_root("home");
    let baseline = temp_file("sarif-baseline");
    let baseline_s = baseline.to_string_lossy().to_string();
    assert!(
        run(&["scan", "--root", &root, "--write-baseline", &baseline_s])
            .status
            .success()
    );

    let output = run(&[
        "scan",
        "--root",
        &root,
        "--baseline",
        &baseline_s,
        "--format",
        "sarif",
    ]);
    assert!(output.status.success());
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid SARIF JSON");
    assert_eq!(json["runs"][0]["properties"]["baseline"]["new"], 0);
    assert!(sarif_results(&json)
        .iter()
        .all(|result| result["properties"]["baselineStatus"] == "existing"));
}

#[test]
fn sarif_severity_threshold_high_only_emits_error_results() {
    let root = fixture_root("home");
    let output = run(&[
        "scan",
        "--root",
        &root,
        "--severity-threshold",
        "high",
        "--format",
        "sarif",
    ]);

    assert!(output.status.success());
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid SARIF JSON");
    let results = sarif_results(&json);
    assert!(!results.is_empty());
    assert!(results.iter().all(|result| result["level"] == "error"));
}

#[test]
fn fingerprints_are_stable_across_repeated_scans() {
    let root = fixture_root("home");
    let extract = |output: &std::process::Output| -> Vec<String> {
        let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
        json["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|finding| finding["fingerprint"].as_str().unwrap().to_string())
            .collect()
    };
    let first = run(&["scan", "--root", &root, "--format", "json"]);
    let second = run(&["scan", "--root", &root, "--format", "json"]);
    assert!(first.status.success() && second.status.success());
    let first_prints = extract(&first);
    assert!(!first_prints.is_empty());
    assert_eq!(first_prints, extract(&second));
}

#[test]
fn policy_list_and_show_work_for_builtin_profiles() {
    let list = run(&["policy", "list"]);
    assert!(list.status.success());
    let stdout = String::from_utf8_lossy(&list.stdout);
    assert!(stdout.contains("developer-laptop"));
    assert!(stdout.contains("ci-runner"));
    assert!(stdout.contains("research-workstation"));
    assert!(stdout.contains("strict"));

    let show = run(&["policy", "show", "developer-laptop"]);
    assert!(show.status.success());
    let stdout = String::from_utf8_lossy(&show.stdout);
    assert!(stdout.contains("schema_version = \"ef-policy/v0.1\""));
    assert!(stdout.contains("name = \"developer-laptop\""));
}

#[test]
fn scan_human_output_sanitizes_control_sequences_in_server_name() {
    // Regression: an MCP server name is configuration-derived, not trusted
    // terminal input. `tests/fixtures/hostile-terminal-home/.claude.json`
    // defines a server whose name embeds an OSC 8 hyperlink (pointing at
    // `evil.example`) and a CSI erase-screen sequence. The executive-summary
    // human view (default format) must never forward those bytes to the
    // terminal, whether the value happens to fit on one wrapped line or is
    // printed directly via a coverage row.
    let root = fixture_root("hostile-terminal-home");
    let output = run(&[
        "scan",
        "--root",
        &root,
        "--policy-profile",
        "developer-laptop",
    ]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains('\u{1b}'),
        "no raw escape byte may appear in human output:\n{stdout}"
    );
    assert!(
        !stdout.contains("evil.example"),
        "the OSC 8 hyperlink target must not reach the terminal:\n{stdout}"
    );
    assert!(
        stdout.contains("safe-looking-name"),
        "the sanitized, non-control portion of the name must still be visible:\n{stdout}"
    );
}
