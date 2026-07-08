use serde_json::Value;
use std::process::Command;

fn fixture_root(name: &str) -> String {
    format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn scan_fixture_json_has_stable_top_level_schema() {
    let root = fixture_root("home");
    let output = Command::new(env!("CARGO_BIN_EXE_etherfence"))
        .args(["scan", "--root", &root, "--format", "json"])
        .output()
        .expect("run etherfence scan");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");

    assert_eq!(json["schema_version"], "ef-scan-report/v0.1.1");
    assert_eq!(json["tool"], "etherfence");
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
    let output = Command::new(env!("CARGO_BIN_EXE_etherfence"))
        .args(["scan", "--root", &root])
        .output()
        .expect("run etherfence scan");

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
    assert!(stdout.contains("posture risks/hints, not confirmed exploitability"));
}

#[test]
fn severity_threshold_high_displays_only_high_findings() {
    let root = fixture_root("home");
    let output = Command::new(env!("CARGO_BIN_EXE_etherfence"))
        .args(["scan", "--root", &root, "--severity-threshold", "high"])
        .output()
        .expect("run etherfence scan");

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
    let output = Command::new(env!("CARGO_BIN_EXE_etherfence"))
        .args(["scan", "--root", &root, "--fail-on", "high"])
        .output()
        .expect("run etherfence scan");

    assert_eq!(output.status.code(), Some(2));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("EF-MCP-001"));
}

#[test]
fn fail_on_high_returns_zero_when_no_high_findings_exist() {
    let root = fixture_root("safe-home");
    let output = Command::new(env!("CARGO_BIN_EXE_etherfence"))
        .args(["scan", "--root", &root, "--fail-on", "high"])
        .output()
        .expect("run etherfence scan");

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
    let output = Command::new(env!("CARGO_BIN_EXE_etherfence"))
        .args(["scan", "--root", &root, "--format", "markdown"])
        .output()
        .expect("run etherfence scan");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("# EtherFence Scan Report"));
    assert!(stdout.contains("## Summary"));
    assert!(stdout.contains("| Inventory items | Findings | High | Medium | Low | Info |"));
    assert!(stdout.contains("## Inventory"));
    assert!(stdout.contains("## Findings"));
    assert!(stdout.contains("### HIGH"));
    assert!(stdout.contains("#### EF-MCP-001 - Broad filesystem access hint"));
    assert!(stdout.contains("- Rationale:"));
    assert!(stdout.contains("- Impact:"));
    assert!(stdout.contains("- Recommendation:"));
}
