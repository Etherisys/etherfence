//! Integration tests for `apply_wizard_plan`: the plan the user confirmed
//! must be exactly what lands on disk. These tests verify resulting files,
//! not just the plan structure.

use etherfence_setup::{
    apply_wizard_plan, build_wizard_plan, detect, PolicyType, WizardSelections,
};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_root(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "etherfence-wizard-apply-{name}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("create temp root");
    dir
}

/// Writes a `.claude.json` with two unwrapped stdio servers.
fn write_claude_config(root: &Path) -> PathBuf {
    let path = root.join(".claude.json");
    fs::write(
        &path,
        r#"{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "--transport", "stdio"]
    },
    "fetcher": {
      "command": "uvx",
      "args": ["web-search-mcp"]
    }
  }
}
"#,
    )
    .expect("write claude config");
    path
}

/// Writes a `.cursor/mcp.json` with one unwrapped stdio server.
fn write_cursor_config(root: &Path) -> PathBuf {
    let dir = root.join(".cursor");
    fs::create_dir_all(&dir).expect("create cursor dir");
    let path = dir.join("mcp.json");
    fs::write(
        &path,
        r#"{
  "mcpServers": {
    "helper": {
      "command": "npx",
      "args": ["helper-mcp"]
    }
  }
}
"#,
    )
    .expect("write cursor config");
    path
}

fn selections_for(keys: &[&str]) -> WizardSelections {
    WizardSelections {
        selected_keys: keys.iter().map(ToString::to_string).collect(),
        version_pins: HashMap::new(),
        policy_types: HashMap::new(),
        trust_overrides: HashMap::new(),
    }
}

fn server_value(config_path: &Path, name: &str) -> Value {
    let content = fs::read_to_string(config_path).expect("read config");
    let value: Value = serde_json::from_str(&content).expect("parse config");
    value["mcpServers"][name].clone()
}

#[test]
fn selecting_one_of_two_servers_modifies_only_that_server() {
    let root = temp_root("select-one");
    let config_path = write_claude_config(&root);
    let fetcher_before = server_value(&config_path, "fetcher");

    let detections = detect(&root);
    let mut selections = selections_for(&["Claude Code:filesystem"]);
    selections
        .version_pins
        .insert("Claude Code:filesystem".to_string(), "1.2.3".to_string());

    let plan = build_wizard_plan(&detections, &selections, &root.display().to_string())
        .expect("build plan");
    apply_wizard_plan(&root, &plan).expect("apply plan");

    // Selected server is wrapped, and the pin lands inside the wrapped
    // invocation with every original argument preserved.
    let filesystem = server_value(&config_path, "filesystem");
    assert_eq!(filesystem["command"], "etherfence");
    let args: Vec<String> = filesystem["args"]
        .as_array()
        .expect("wrapped args")
        .iter()
        .map(|v| v.as_str().expect("string arg").to_string())
        .collect();
    assert_eq!(args[0], "mcp-proxy");
    let separator = args
        .iter()
        .position(|a| a == "--")
        .expect("wrapped invocation separator");
    assert_eq!(
        &args[separator + 1..],
        [
            "npx",
            "-y",
            "@modelcontextprotocol/server-filesystem@1.2.3",
            "--transport",
            "stdio",
        ]
    );

    // The unselected server in the same config is untouched.
    let fetcher_after = server_value(&config_path, "fetcher");
    assert_eq!(fetcher_before, fetcher_after);

    // A backup manifest exists so rollback can undo the change.
    let backups = root.join(".etherfence/backups");
    assert!(backups.is_dir(), "backup dir must exist");
}

#[test]
fn config_without_any_selected_server_stays_byte_identical() {
    let root = temp_root("untouched-config");
    write_claude_config(&root);
    let cursor_path = write_cursor_config(&root);
    let cursor_before = fs::read(&cursor_path).expect("read cursor config");

    let detections = detect(&root);
    let selections = selections_for(&["Claude Code:filesystem"]);
    let plan = build_wizard_plan(&detections, &selections, &root.display().to_string())
        .expect("build plan");
    apply_wizard_plan(&root, &plan).expect("apply plan");

    let cursor_after = fs::read(&cursor_path).expect("re-read cursor config");
    assert_eq!(
        cursor_before, cursor_after,
        "config without selected servers must stay byte-identical"
    );
    assert!(
        !root.join(".cursor/.etherfence/backups").exists(),
        "no backup should be created for an untouched config"
    );
}

#[test]
fn skipping_every_server_changes_nothing() {
    // A high-risk server the user skips is simply never selected; the
    // engine must then leave every file byte-identical.
    let root = temp_root("skip-all");
    let config_path = write_claude_config(&root);
    let before = fs::read(&config_path).expect("read config");

    let detections = detect(&root);
    let selections = selections_for(&[]);
    let plan = build_wizard_plan(&detections, &selections, &root.display().to_string())
        .expect("build plan");
    apply_wizard_plan(&root, &plan).expect("apply plan");

    let after = fs::read(&config_path).expect("re-read config");
    assert_eq!(before, after, "skip must mean no changes at all");
    assert!(!root.join(".etherfence").exists());
}

#[test]
fn custom_allowlist_policy_content_is_written() {
    let root = temp_root("custom-allowlist");
    write_claude_config(&root);

    let detections = detect(&root);
    let mut selections = selections_for(&["Claude Code:filesystem"]);
    selections.policy_types.insert(
        "Claude Code:filesystem".to_string(),
        PolicyType::CustomToolAllowlist(vec!["read_file".to_string(), "list_dir".to_string()]),
    );

    let plan = build_wizard_plan(&detections, &selections, &root.display().to_string())
        .expect("build plan");
    apply_wizard_plan(&root, &plan).expect("apply plan");

    let policy_path = root.join(".etherfence/policies/filesystem.toml");
    let policy = fs::read_to_string(&policy_path).expect("read written policy");
    assert!(
        policy.contains("\"read_file\"") && policy.contains("\"list_dir\""),
        "written policy must contain the custom allowlist, got:\n{policy}"
    );
    assert!(
        policy.contains("tools/call"),
        "custom allowlist policy must allow tools/call:\n{policy}"
    );

    // The written policy is exactly the plan's validated content.
    let planned = plan
        .policies
        .iter()
        .find(|p| p.server_name == "filesystem")
        .expect("plan has filesystem policy");
    assert_eq!(planned.content, policy);
}

#[test]
fn unselected_server_gets_no_policy_file() {
    let root = temp_root("no-policy-for-skipped");
    write_claude_config(&root);

    let detections = detect(&root);
    let selections = selections_for(&["Claude Code:filesystem"]);
    let plan = build_wizard_plan(&detections, &selections, &root.display().to_string())
        .expect("build plan");
    apply_wizard_plan(&root, &plan).expect("apply plan");

    assert!(root.join(".etherfence/policies/filesystem.toml").is_file());
    assert!(
        !root.join(".etherfence/policies/fetcher.toml").exists(),
        "skipped server must not receive a policy file"
    );
}

#[test]
fn previewed_plan_and_applied_changes_correspond() {
    let root = temp_root("plan-correspondence");
    let config_path = write_claude_config(&root);

    let detections = detect(&root);
    let mut selections = selections_for(&["Claude Code:fetcher"]);
    selections
        .version_pins
        .insert("Claude Code:fetcher".to_string(), "0.2.1".to_string());

    let plan = build_wizard_plan(&detections, &selections, &root.display().to_string())
        .expect("build plan");

    // The plan's pinning change is derived from the server's real args.
    let pin = plan
        .pinning_changes
        .iter()
        .find(|c| c.server_name == "fetcher")
        .expect("plan has fetcher pin");
    assert_eq!(pin.pinned_args, vec!["web-search-mcp==0.2.1".to_string()]);

    apply_wizard_plan(&root, &plan).expect("apply plan");

    // The applied config carries exactly the planned pinned args inside
    // the wrapped invocation.
    let fetcher = server_value(&config_path, "fetcher");
    let args: Vec<String> = fetcher["args"]
        .as_array()
        .expect("wrapped args")
        .iter()
        .map(|v| v.as_str().expect("string arg").to_string())
        .collect();
    let separator = args
        .iter()
        .position(|a| a == "--")
        .expect("wrapped invocation separator");
    assert_eq!(args[separator + 1], "uvx");
    assert_eq!(args[separator + 2..], pin.pinned_args[..]);
}

#[test]
fn invalid_version_pin_is_rejected_at_plan_time() {
    let root = temp_root("invalid-pin");
    write_claude_config(&root);

    let detections = detect(&root);
    for bad in ["latest", "^1.2", ">=2", "foo"] {
        let mut selections = selections_for(&["Claude Code:filesystem"]);
        selections
            .version_pins
            .insert("Claude Code:filesystem".to_string(), bad.to_string());
        let result = build_wizard_plan(&detections, &selections, &root.display().to_string());
        assert!(result.is_err(), "version {bad:?} must be rejected as a pin");
    }
}
