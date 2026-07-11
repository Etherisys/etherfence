use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn fixture_root(name: &str) -> PathBuf {
    PathBuf::from(format!(
        "{}/../../tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
}

fn temp_home(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "etherfence-setup-{name}-{}-{nanos}",
        std::process::id()
    ))
}

fn copy_dir_all(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).expect("create temp fixture dir");
    for entry in fs::read_dir(src).expect("read fixture dir") {
        let entry = entry.expect("fixture entry");
        let ty = entry.file_type().expect("fixture file type");
        let dst_path = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_all(&entry.path(), &dst_path);
        } else {
            fs::copy(entry.path(), dst_path).expect("copy fixture file");
        }
    }
}

fn write_file(path: &Path, content: &str) {
    fs::create_dir_all(path.parent().expect("file parent")).expect("create parent dir");
    fs::write(path, content).expect("write file");
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_etherfence"))
        .args(args)
        .output()
        .expect("run etherfence setup")
}

#[test]
fn setup_detect_and_plan_are_redacted_and_read_only() {
    let root = fixture_root("home");
    let root_arg = root.to_str().unwrap();

    let detect = run(&["setup", "detect", "--root", root_arg]);
    assert!(
        detect.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&detect.stderr)
    );
    let detect_stdout = String::from_utf8_lossy(&detect.stdout);
    assert!(detect_stdout.contains("Claude Code [write-supported]"));
    assert!(detect_stdout.contains("Windsurf [advisory-only]"));
    assert!(!detect_stdout.contains("fixture-value"));
    assert!(!detect_stdout.contains("ANTHROPIC_API_KEY"));

    let plan = run(&["setup", "plan", "--root", root_arg]);
    assert!(
        plan.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&plan.stderr)
    );
    let plan_stdout = String::from_utf8_lossy(&plan.stdout);
    assert!(plan_stdout.contains("Claude Code:filesystem -> wrap"));
    assert!(plan_stdout.contains("Windsurf:repo-context -> advisory-only"));
    assert!(!plan_stdout.contains("fixture-value"));
    assert!(!root.join(".etherfence").exists());
}

#[test]
fn setup_detect_json_includes_capabilities_and_recommendation_per_contract() {
    let root = fixture_root("home");
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
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    // v1.3.0 additively bumps this to v0.2 (new trustAssessment field);
    // every v0.1 field below keeps its exact name/meaning (FR-074).
    assert_eq!(json["etherfenceSchemaVersion"], "ef-setup-detect/v0.2");
    assert!(json.get("root").is_some());

    let detections = json["detections"].as_array().expect("detections array");
    assert!(!detections.is_empty());
    let mut saw_filesystem = false;
    let mut saw_shell_needs_review = false;
    for detection in detections {
        assert!(detection.get("agent").is_some());
        assert!(detection.get("configPath").is_some());
        assert!(detection.get("writeSupport").is_some());
        for server in detection["servers"].as_array().expect("servers array") {
            let labels = server["capabilities"]["labels"]
                .as_array()
                .expect("labels array");
            assert!(!labels.is_empty(), "labels must never be empty");
            assert_eq!(server["recommendation"]["tier"], "deny");
            for label in labels {
                let label = label.as_str().unwrap();
                assert_eq!(
                    label,
                    label.to_lowercase(),
                    "labels must be kebab-case tokens"
                );
                assert!(!label.contains(' '), "labels must be kebab-case tokens");
            }
            if labels.iter().any(|l| l == "filesystem") {
                saw_filesystem = true;
            }
            if labels.iter().any(|l| l == "shell-command-execution") {
                assert_eq!(server["recommendation"]["needsReview"], true);
                saw_shell_needs_review = true;
            }
        }
    }
    assert!(
        saw_filesystem,
        "expected at least one filesystem-labeled server"
    );
    assert!(
        saw_shell_needs_review,
        "expected at least one shell-command-execution server flagged needs-review"
    );
}

#[test]
fn setup_detect_human_output_gains_capability_lines_without_removing_existing_ones() {
    let root = fixture_root("home");
    let output = run(&["setup", "detect", "--root", root.to_str().unwrap()]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Pre-existing lines are unchanged.
    assert!(stdout.contains("EtherFence setup detect"));
    assert!(stdout.contains("Claude Code [write-supported]"));
    assert!(stdout.contains("filesystem transport=stdio wrapped=false"));

    // New lines are additive.
    assert!(stdout.contains("capabilities: filesystem"));
    assert!(stdout.contains("recommendation: deny (needs-review="));
}

#[test]
fn setup_plan_and_doctor_output_does_not_leak_capability_fields() {
    let root = fixture_root("home");
    let root_arg = root.to_str().unwrap();

    let plan = run(&["setup", "plan", "--root", root_arg]);
    assert!(plan.status.success());
    let plan_stdout = String::from_utf8_lossy(&plan.stdout);
    assert!(!plan_stdout.contains("capabilities"));
    assert!(!plan_stdout.contains("recommendation:"));
    assert!(!plan_stdout.contains("needs-review"));

    let doctor = run(&["setup", "doctor", "--root", root_arg]);
    assert!(doctor.status.success());
    let doctor_stdout = String::from_utf8_lossy(&doctor.stdout);
    assert!(!doctor_stdout.contains("capabilities"));
    assert!(!doctor_stdout.contains("recommendation:"));
    assert!(!doctor_stdout.contains("needs-review"));
}

#[test]
fn setup_detect_default_format_matches_explicit_human_format() {
    let root = fixture_root("home");
    let root_arg = root.to_str().unwrap();
    let default = run(&["setup", "detect", "--root", root_arg]);
    let explicit = run(&["setup", "detect", "--format", "human", "--root", root_arg]);
    assert_eq!(default.stdout, explicit.stdout);
}

#[test]
fn setup_detect_recommendations_are_deny_by_default_with_correct_needs_review_across_all_fixtures()
{
    let escalating = ["unknown", "shell-command-execution", "identity-auth"];
    let mut saw_any_server = false;
    for fixture in [
        "home",
        "empty-home",
        "windows-home",
        "malformed-home",
        "minimal-home",
        "multi-home",
        "safe-home",
        "multi-path-home",
    ] {
        let root = fixture_root(fixture);
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
            "fixture {fixture} stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let json: Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|e| panic!("fixture {fixture}: invalid JSON: {e}"));
        for detection in json["detections"].as_array().expect("detections array") {
            for server in detection["servers"].as_array().expect("servers array") {
                saw_any_server = true;
                assert_eq!(
                    server["recommendation"]["tier"], "deny",
                    "fixture {fixture} server {:?}: tier must always be deny in v1.2.0",
                    server["name"]
                );
                let labels: Vec<&str> = server["capabilities"]["labels"]
                    .as_array()
                    .expect("labels array")
                    .iter()
                    .map(|l| l.as_str().unwrap())
                    .collect();
                let expected_needs_review = labels.iter().any(|l| escalating.contains(l));
                assert_eq!(
                    server["recommendation"]["needsReview"], expected_needs_review,
                    "fixture {fixture} server {:?} labels={labels:?}: needs_review mismatch",
                    server["name"]
                );
            }
        }
    }
    assert!(
        saw_any_server,
        "expected at least one server across all fixtures"
    );
}

#[test]
fn setup_apply_wraps_supported_clients_and_rollback_restores() {
    let root = temp_home("apply-rollback");
    copy_dir_all(&fixture_root("home"), &root);
    let root_arg = root.to_str().unwrap();

    let apply = run(&["setup", "apply", "--root", root_arg]);
    assert!(
        apply.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&apply.stderr)
    );

    let detect_after_apply = run(&["setup", "detect", "--root", root_arg]);
    assert!(detect_after_apply.status.success());
    let stdout = String::from_utf8_lossy(&detect_after_apply.stdout);
    assert!(stdout.contains("Claude Code [write-supported]"));
    assert!(stdout.contains("filesystem transport=stdio wrapped=true"));
    assert!(stdout.contains("shell-tools transport=stdio wrapped=true"));
    assert!(stdout.contains("browser transport=stdio wrapped=true"));
    assert!(stdout.contains("repo-context transport=stdio wrapped=false"));

    assert!(root.join(".etherfence/backups").exists());
    assert!(root.join(".etherfence/policies/filesystem.toml").is_file());
    assert!(root
        .join(".cursor/.etherfence/policies/shell-tools.toml")
        .is_file());
    assert!(root
        .join(".vscode/.etherfence/policies/browser.toml")
        .is_file());

    let rollback = run(&["setup", "rollback", "--root", root_arg]);
    assert!(
        rollback.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&rollback.stderr)
    );

    let detect_after_rollback = run(&["setup", "detect", "--root", root_arg]);
    assert!(detect_after_rollback.status.success());
    let rollback_stdout = String::from_utf8_lossy(&detect_after_rollback.stdout);
    assert!(rollback_stdout.contains("filesystem transport=stdio wrapped=false"));
    assert!(rollback_stdout.contains("shell-tools transport=stdio wrapped=false"));
    assert!(rollback_stdout.contains("browser transport=stdio wrapped=false"));
    assert!(!root.join(".etherfence/policies/filesystem.toml").exists());

    fs::remove_dir_all(root).ok();
}

#[test]
fn setup_apply_is_idempotent_for_already_wrapped_servers() {
    let root = temp_home("idempotent");
    copy_dir_all(&fixture_root("home"), &root);
    let root_arg = root.to_str().unwrap();

    let first = run(&["setup", "apply", "--root", root_arg]);
    assert!(first.status.success());
    let second = run(&["setup", "apply", "--root", root_arg]);
    assert!(second.status.success());

    let claude = fs::read_to_string(root.join(".claude.json")).expect("read claude config");
    assert_eq!(claude.matches("mcp-proxy").count(), 1);

    fs::remove_dir_all(root).ok();
}

#[test]
fn setup_plan_and_apply_support_vscode_nested_mcp_servers_shape() {
    let root = temp_home("vscode-nested");
    write_file(
        &root.join(".vscode/settings.json"),
        r#"{
  "mcp": {
    "servers": {
      "nested-browser": {
        "command": "node",
        "args": ["playwright-mcp"]
      }
    }
  }
}
"#,
    );
    let root_arg = root.to_str().unwrap();

    let plan = run(&["setup", "plan", "--root", root_arg]);
    assert!(plan.status.success());
    let plan_stdout = String::from_utf8_lossy(&plan.stdout);
    assert!(plan_stdout.contains("VS Code:nested-browser -> wrap"));

    let apply = run(&["setup", "apply", "--root", root_arg]);
    assert!(apply.status.success());
    let detect = run(&["setup", "detect", "--root", root_arg]);
    assert!(detect.status.success());
    let detect_stdout = String::from_utf8_lossy(&detect.stdout);
    assert!(detect_stdout.contains("nested-browser transport=stdio wrapped=true"));

    fs::remove_dir_all(root).ok();
}

#[test]
fn setup_apply_supports_windows_vscode_nested_mcp_servers_shape() {
    let root = temp_home("windows-vscode-nested");
    write_file(
        &root.join("AppData/Roaming/Code/User/settings.json"),
        r#"{
  "mcp": {
    "servers": {
      "windows-browser": {
        "command": "node",
        "args": ["playwright-mcp"]
      }
    }
  }
}
"#,
    );
    let root_arg = root.to_str().unwrap();

    let plan = run(&["setup", "plan", "--root", root_arg]);
    assert!(plan.status.success());
    assert!(String::from_utf8_lossy(&plan.stdout).contains("VS Code:windows-browser -> wrap"));

    let apply = run(&["setup", "apply", "--root", root_arg]);
    assert!(apply.status.success());
    let detect = run(&["setup", "detect", "--root", root_arg]);
    assert!(detect.status.success());
    assert!(String::from_utf8_lossy(&detect.stdout)
        .contains("windows-browser transport=stdio wrapped=true"));

    fs::remove_dir_all(root).ok();
}

#[test]
fn setup_rollback_refuses_to_overwrite_user_edits_after_apply() {
    let root = temp_home("rollback-user-edit");
    copy_dir_all(&fixture_root("home"), &root);
    let root_arg = root.to_str().unwrap();

    assert!(run(&["setup", "apply", "--root", root_arg])
        .status
        .success());
    fs::write(root.join(".claude.json"), "{\"user_edit\": true}\n").expect("edit config");

    let rollback = run(&["setup", "rollback", "--root", root_arg]);
    assert!(!rollback.status.success());
    assert!(String::from_utf8_lossy(&rollback.stderr).contains("refusing to overwrite user edits"));
    assert_eq!(
        fs::read_to_string(root.join(".claude.json")).expect("read edited config"),
        "{\"user_edit\": true}\n"
    );

    fs::remove_dir_all(root).ok();
}

#[test]
fn setup_rollback_rejects_forged_manifest_for_unsupported_original_path() {
    let root = temp_home("forged-manifest");
    copy_dir_all(&fixture_root("home"), &root);
    write_file(
        &root.join(".claude/.etherfence/backups/1/original.json"),
        "{}\n",
    );
    write_file(
        &root.join(".claude/.etherfence/backups/1/manifest.json"),
        r#"{
  "marker": "etherfence-setup-backup/v1",
  "original_path": ".windsurf/mcp.json",
  "backup_path": ".claude/.etherfence/backups/1/original.json",
  "backup_hash": "ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356",
  "post_apply_hash": "ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356",
  "policy_paths": []
}
"#,
    );
    let before = fs::read_to_string(root.join(".windsurf/mcp.json")).expect("read windsurf");
    let rollback = run(&["setup", "rollback", "--root", root.to_str().unwrap()]);
    assert!(!rollback.status.success());
    assert!(String::from_utf8_lossy(&rollback.stderr).contains("does not target a supported"));
    assert_eq!(
        fs::read_to_string(root.join(".windsurf/mcp.json")).expect("read windsurf after"),
        before
    );

    fs::remove_dir_all(root).ok();
}

#[test]
fn setup_rollback_rejects_manifest_with_unexpected_backup_path() {
    let root = temp_home("forged-backup-path");
    copy_dir_all(&fixture_root("home"), &root);
    write_file(&root.join(".etherfence/backups/1/original.json"), "{}\n");
    write_file(
        &root.join(".etherfence/backups/1/not-original.json"),
        "{}\n",
    );
    write_file(
        &root.join(".etherfence/backups/1/manifest.json"),
        r#"{
  "marker": "etherfence-setup-backup/v1",
  "original_path": ".claude.json",
  "backup_path": ".etherfence/backups/1/not-original.json",
  "backup_hash": "ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356",
  "post_apply_hash": "ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356",
  "policy_paths": []
}
"#,
    );

    let rollback = run(&["setup", "rollback", "--root", root.to_str().unwrap()]);
    assert!(!rollback.status.success());
    assert!(String::from_utf8_lossy(&rollback.stderr).contains("backup_path must equal"));

    fs::remove_dir_all(root).ok();
}

#[cfg(unix)]
#[test]
fn setup_apply_restores_completed_configs_when_later_write_fails() {
    use std::os::unix::fs::PermissionsExt;

    let root = temp_home("apply-write-fail-cleanup");
    write_file(
        &root.join(".claude.json"),
        r#"{"mcpServers":{"filesystem":{"command":"npx","args":["server"]}}}"#,
    );
    write_file(
        &root.join(".claude/settings.json"),
        r#"{"mcpServers":{"second":{"command":"node","args":["server"]}}}"#,
    );
    let original = fs::read_to_string(root.join(".claude.json")).expect("read claude");
    let mut readonly = fs::metadata(root.join(".claude"))
        .expect("metadata")
        .permissions();
    readonly.set_mode(0o500);
    fs::set_permissions(root.join(".claude"), readonly).expect("set readonly");

    let apply = run(&["setup", "apply", "--root", root.to_str().unwrap()]);

    let mut writable = fs::metadata(root.join(".claude"))
        .expect("metadata")
        .permissions();
    writable.set_mode(0o700);
    fs::set_permissions(root.join(".claude"), writable).expect("set writable");

    assert!(!apply.status.success());
    assert_eq!(
        fs::read_to_string(root.join(".claude.json")).expect("read claude after"),
        original
    );
    assert!(!root.join(".etherfence").exists());
    assert!(!root.join(".claude/.etherfence").exists());

    fs::remove_dir_all(root).ok();
}

#[test]
fn setup_apply_prepares_all_configs_before_writing_any_state() {
    let root = temp_home("prepare-before-write");
    write_file(
        &root.join(".claude.json"),
        r#"{"mcpServers":{"filesystem":{"command":"npx","args":["server"]}}}"#,
    );
    write_file(
        &root.join("AppData/Roaming/Claude/settings.json"),
        "{not valid json",
    );
    let original = fs::read_to_string(root.join(".claude.json")).expect("read claude");

    let apply = run(&["setup", "apply", "--root", root.to_str().unwrap()]);
    assert!(!apply.status.success());
    assert!(String::from_utf8_lossy(&apply.stderr).contains("parsing supported MCP config JSON"));
    assert_eq!(
        fs::read_to_string(root.join(".claude.json")).expect("read claude after"),
        original
    );
    assert!(!root.join(".etherfence").exists());

    fs::remove_dir_all(root).ok();
}
