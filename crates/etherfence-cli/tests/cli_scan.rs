use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn fixture_root(name: &str) -> String {
    format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn strict_policy() -> String {
    format!(
        "{}/../../examples/policies/strict.toml",
        env!("CARGO_MANIFEST_DIR")
    )
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
    Command::new(env!("CARGO_BIN_EXE_etherfence"))
        .args(args)
        .output()
        .expect("run etherfence scan")
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

    assert_eq!(json["schema_version"], "ef-scan-report/v0.1.1");
    assert_eq!(json["tool"], "etherfence");
    assert_eq!(json["version"], "0.1.4");
    assert_eq!(json["status"], "pre-alpha-scan-only");
    assert!(json.get("scanned_root").is_some());
    assert!(json["inventory"].is_array());
    assert!(json["findings"].is_array());
    assert!(json["summary"].is_object());
    assert_eq!(json["summary"]["inventory_items"], 7);

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
    ] {
        assert!(first.get(key).is_some(), "missing finding key {key}");
    }

    let ids: Vec<&str> = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|finding| finding["id"].as_str())
        .collect();
    assert!(ids.contains(&"EF-MCP-001"));
    assert!(ids.contains(&"EF-MCP-002"));
    assert!(ids.contains(&"EF-MCP-003"));
    assert!(ids.contains(&"EF-MCP-004"));
    assert!(ids.contains(&"EF-SEC-001"));
    assert!(ids.contains(&"EF-TIRITH-002"));
}

#[test]
fn scan_fixture_human_groups_by_severity_and_guidance() {
    let root = fixture_root("home");
    let output = run(&["scan", "--root", &root]);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Summary:"));
    assert!(stdout.contains("Findings by severity:"));
    assert!(stdout.contains("HIGH"));
    assert!(stdout.contains("Rationale:"));
    assert!(stdout.contains("Recommendation:"));
    assert!(stdout.contains("fingerprint=efp1-"));
    assert!(stdout.contains("posture risks/hints, not confirmed exploitability"));
}

#[test]
fn severity_threshold_high_displays_only_high_findings() {
    let root = fixture_root("home");
    let output = run(&["scan", "--root", &root, "--severity-threshold", "high"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("HIGH"));
    assert!(stdout.contains("EF-MCP-001"));
    assert!(!stdout.contains("\nMEDIUM\n"));
    assert!(!stdout.contains("\nLOW\n"));
    assert!(!stdout.contains("\nINFO\n"));
    assert!(stdout
        .contains("Summary: 7 inventory item(s), 3 finding(s): high=3, medium=0, low=0, info=0"));
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
    let output = run(&["scan", "--root", &root, "--fail-on", "high"]);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("high=0"));
}

#[test]
fn markdown_output_has_review_headings_and_guidance() {
    let root = fixture_root("home");
    let output = run(&["scan", "--root", &root, "--format", "markdown"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("# EtherFence Scan Report"));
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
    assert_eq!(json["schema_version"], "ef-baseline/v0.1.3");
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

    let output = run(&["scan", "--root", &safe_root, "--baseline", &baseline_s]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("resolved="));
    assert!(stdout.contains("status=resolved"));
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
    ]);

    assert_eq!(output.status.code(), Some(2));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Policy:"));
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
    ]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("new=0"));
    assert!(stdout.contains("Policy:"));
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
