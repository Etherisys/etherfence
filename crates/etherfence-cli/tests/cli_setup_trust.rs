use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture_root(name: &str) -> PathBuf {
    PathBuf::from(format!(
        "{}/../../tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_etherfence"))
        .args(args)
        .output()
        .expect("run etherfence setup detect")
}

fn detect_json(root: &Path) -> Value {
    let output = run(&[
        "setup",
        "detect",
        "--format",
        "json",
        "--root",
        root.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("valid JSON")
}

fn find_server<'a>(json: &'a Value, agent: &str, server_name: &str) -> &'a Value {
    json["detections"]
        .as_array()
        .expect("detections array")
        .iter()
        .find(|d| d["agent"] == agent)
        .unwrap_or_else(|| panic!("missing agent {agent}"))["servers"]
        .as_array()
        .expect("servers array")
        .iter()
        .find(|s| s["name"] == server_name)
        .unwrap_or_else(|| panic!("missing server {server_name}"))
}

// --- T020/T028/T034: full trustAssessment JSON shape per contract ---

#[test]
fn schema_version_is_bumped_to_v0_2() {
    let json = detect_json(&fixture_root("trust-home"));
    assert_eq!(json["etherfenceSchemaVersion"], "ef-setup-detect/v0.2");
}

#[test]
fn npx_pinned_package_has_no_pinning_indicator_and_known_source_identity() {
    let json = detect_json(&fixture_root("trust-home"));
    let server = find_server(&json, "Claude Code", "npx-pinned");
    let trust = &server["trustAssessment"];
    assert_eq!(trust["invocation"]["runner"], "npx");
    assert_eq!(
        trust["invocation"]["packageIdentity"],
        "@modelcontextprotocol/server-filesystem"
    );
    assert_eq!(trust["invocation"]["versionExpression"], "exactly-pinned");
    assert_eq!(trust["artifactIdentity"], "known-source");
    assert_eq!(trust["configurationRisk"], "no-known-indicators");
    assert_eq!(trust["aggregate"], "known-source");
    assert_eq!(trust["needsReview"], false);
    assert_eq!(trust["indicators"].as_array().unwrap().len(), 0);
}

#[test]
fn npx_omitted_version_raises_pin_001_and_needs_review() {
    let json = detect_json(&fixture_root("trust-home"));
    let server = find_server(&json, "Claude Code", "npx-omitted");
    let trust = &server["trustAssessment"];
    assert_eq!(trust["invocation"]["versionExpression"], "omitted");
    let indicators = trust["indicators"].as_array().unwrap();
    assert!(indicators.iter().any(|i| i["id"] == "EF-TRUST-PIN-001"));
    assert_eq!(trust["needsReview"], true);
}

#[test]
fn malformed_runner_invocation_is_reported_distinctly() {
    let json = detect_json(&fixture_root("trust-home"));
    let server = find_server(&json, "Claude Code", "npx-malformed");
    let trust = &server["trustAssessment"];
    assert_eq!(trust["invocation"]["malformedRunnerInvocation"], true);
    assert!(trust["invocation"].get("versionExpression").is_none());
    let indicators = trust["indicators"].as_array().unwrap();
    assert!(indicators.iter().any(|i| i["id"] == "EF-TRUST-PIN-005"));
}

#[test]
fn shell_wrapper_json_field_is_rendered() {
    let json = detect_json(&fixture_root("trust-home"));
    let server = find_server(&json, "Windsurf", "wrap-bash-c");
    let trust = &server["trustAssessment"];
    assert_eq!(trust["invocation"]["shellWrapper"], "bash-c");
    let indicators = trust["indicators"].as_array().unwrap();
    assert!(indicators.iter().any(|i| i["id"] == "EF-TRUST-SHW-001"));
}

#[test]
fn direct_launch_has_no_shell_wrapper_field() {
    let json = detect_json(&fixture_root("trust-home"));
    let server = find_server(&json, "Windsurf", "direct-negative-control");
    let trust = &server["trustAssessment"];
    assert!(trust["invocation"].get("shellWrapper").is_none());
}

#[test]
fn obscured_launch_patterns_json_field_is_rendered() {
    let json = detect_json(&fixture_root("trust-home"));
    let server = find_server(&json, "Gemini CLI", "obs-pipe-to-shell-downloader");
    let trust = &server["trustAssessment"];
    let patterns = trust["invocation"]["obscuredLaunchPatterns"]
        .as_array()
        .expect("obscuredLaunchPatterns array");
    assert!(patterns.iter().any(|p| p == "pipe-to-shell-downloader"));
    let indicators = trust["indicators"].as_array().unwrap();
    assert!(indicators.iter().any(|i| i["id"] == "EF-TRUST-OBS-001"));
    // High-severity obscured-launch indicator forces high-risk aggregate.
    assert_eq!(trust["configurationRisk"], "high-risk");
    assert_eq!(trust["aggregate"], "high-risk");
}

#[test]
fn full_trust_assessment_shape_matches_contract() {
    let json = detect_json(&fixture_root("trust-home"));
    let server = find_server(&json, "Claude Code", "npx-pinned");
    let trust = &server["trustAssessment"];
    for field in [
        "artifactIdentity",
        "configurationRisk",
        "aggregate",
        "needsReview",
        "invocation",
        "executablePath",
        "indicators",
    ] {
        assert!(trust.get(field).is_some(), "missing field {field}");
    }
    // sha256 is omitted (absent key), never null, when no verified hash exists.
    assert!(trust.get("sha256").is_none());
    assert!(trust["indicators"].is_array());
    assert!(trust["invocation"]["applicable"].as_bool().unwrap());
}

// --- T035: determinism ---

#[test]
fn setup_detect_json_is_byte_identical_across_repeated_runs() {
    let root = fixture_root("trust-home");
    let first = run(&[
        "setup",
        "detect",
        "--format",
        "json",
        "--root",
        root.to_str().unwrap(),
    ]);
    let second = run(&[
        "setup",
        "detect",
        "--format",
        "json",
        "--root",
        root.to_str().unwrap(),
    ]);
    assert!(first.status.success() && second.status.success());
    assert_eq!(first.stdout, second.stdout);
}

// --- T041: setup plan/doctor human output unchanged by this feature ---

#[test]
fn setup_plan_and_doctor_human_output_do_not_mention_trust_assessment() {
    let root = fixture_root("home");
    let plan = run(&["setup", "plan", "--root", root.to_str().unwrap()]);
    assert!(plan.status.success());
    let plan_stdout = String::from_utf8_lossy(&plan.stdout);
    assert!(!plan_stdout.contains("trust:"));
    assert!(!plan_stdout.contains("trust indicators"));

    let doctor = run(&["setup", "doctor", "--root", root.to_str().unwrap()]);
    assert!(doctor.status.success());
    let doctor_stdout = String::from_utf8_lossy(&doctor.stdout);
    assert!(!doctor_stdout.contains("trust:"));
    assert!(!doctor_stdout.contains("trust indicators"));
}

// --- T044: environment-variable redaction ---

#[test]
fn environment_variable_values_never_appear_in_human_or_json_output() {
    let root = fixture_root("trust-home");
    let human = run(&["setup", "detect", "--root", root.to_str().unwrap()]);
    assert!(human.status.success());
    let human_stdout = String::from_utf8_lossy(&human.stdout);
    assert!(!human_stdout.contains("fixture-secret-value"));

    let json = run(&[
        "setup",
        "detect",
        "--format",
        "json",
        "--root",
        root.to_str().unwrap(),
    ]);
    assert!(json.status.success());
    let json_stdout = String::from_utf8_lossy(&json.stdout);
    assert!(!json_stdout.contains("fixture-secret-value"));
}

#[test]
fn env_category_and_secret_like_indicators_are_rendered() {
    let json = detect_json(&fixture_root("trust-home"));
    let loader = find_server(&json, "VS Code", "env-loader-injection");
    let indicators = loader["trustAssessment"]["indicators"].as_array().unwrap();
    assert!(indicators.iter().any(|i| i["id"] == "EF-TRUST-ENV-001"));

    let dual = find_server(&json, "VS Code", "env-dual-match");
    let dual_indicators = dual["trustAssessment"]["indicators"].as_array().unwrap();
    assert!(dual_indicators
        .iter()
        .any(|i| i["id"] == "EF-TRUST-ENV-003"));
    assert!(dual_indicators
        .iter()
        .any(|i| i["id"] == "EF-TRUST-ENV-005" || i["id"] == "EF-TRUST-ENV-006"));
}

// --- T052: remote (URL-configured, non-stdio) server partial assessment ---

#[test]
fn remote_server_gets_partial_assessment_per_fr057() {
    let json = detect_json(&fixture_root("trust-home"));
    let server = find_server(&json, "VS Code", "remote-hosted-docs");
    let trust = &server["trustAssessment"];

    assert_eq!(trust["invocation"]["applicable"], false);
    // Every other invocation field is omitted, not present-but-null, when not applicable.
    assert!(trust["invocation"].get("runner").is_none());
    assert!(trust["invocation"].get("shellWrapper").is_none());
    assert_eq!(trust["executablePath"], "not-applicable");
    assert!(trust.get("sha256").is_none());
    assert_eq!(trust["artifactIdentity"], "unknown");

    // Environment-variable assessment still ran (FR-057a).
    let indicators = trust["indicators"].as_array().unwrap();
    assert!(indicators.iter().any(|i| i["id"] == "EF-TRUST-ENV-001"));
    assert_eq!(trust["configurationRisk"], "high-risk");
    assert_eq!(trust["aggregate"], "high-risk");
}

// --- Deny-by-default invariant (SC-006) ---

#[test]
fn recommendation_tier_is_never_allow_regardless_of_trust_assessment() {
    let json = detect_json(&fixture_root("trust-home"));
    for detection in json["detections"].as_array().unwrap() {
        for server in detection["servers"].as_array().unwrap() {
            assert_eq!(server["recommendation"]["tier"], "deny");
        }
    }
}
