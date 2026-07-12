//! Integration tests for `apply_wizard_plan`: the plan the user confirmed
//! must be exactly what lands on disk. These tests verify resulting files,
//! not just the plan structure, and every fail-closed preflight path.

use etherfence_setup::{
    apply_wizard_plan, build_wizard_plan, detect, PolicyType, WizardSelections, WizardServerId,
};
use serde_json::Value;
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

/// Writes a `.claude/settings.json` defining a server named like one in
/// `.claude.json` — the duplicate-name-across-configs scenario.
fn write_claude_settings_config(root: &Path) -> PathBuf {
    let dir = root.join(".claude");
    fs::create_dir_all(&dir).expect("create .claude dir");
    let path = dir.join("settings.json");
    fs::write(
        &path,
        r#"{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["other-package"]
    }
  }
}
"#,
    )
    .expect("write claude settings config");
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

fn claude_id(root: &Path, server_name: &str) -> WizardServerId {
    let _ = root;
    WizardServerId {
        agent: "Claude Code".to_string(),
        config_path: "~/.claude.json".to_string(),
        server_name: server_name.to_string(),
    }
}

fn selections_for(ids: &[WizardServerId]) -> WizardSelections {
    WizardSelections {
        selected: ids.to_vec(),
        ..WizardSelections::default()
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
    let id = claude_id(&root, "filesystem");
    let mut selections = selections_for(std::slice::from_ref(&id));
    selections.version_pins.insert(id, "1.2.3".to_string());

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
fn duplicate_server_name_in_second_config_stays_untouched() {
    // Same agent + same server name in two config files: selecting the
    // server in `.claude.json` must never touch `.claude/settings.json`.
    let root = temp_root("dup-name");
    write_claude_config(&root);
    let settings_path = write_claude_settings_config(&root);
    let settings_before = fs::read(&settings_path).expect("read settings");

    let detections = detect(&root);
    let selections = selections_for(&[claude_id(&root, "filesystem")]);
    let plan = build_wizard_plan(&detections, &selections, &root.display().to_string())
        .expect("build plan");

    // The plan itself must be scoped to one config.
    assert_eq!(plan.selected_servers.len(), 1);
    assert_eq!(plan.selected_servers[0].config_path, "~/.claude.json");
    assert_eq!(plan.policies.len(), 1);

    apply_wizard_plan(&root, &plan).expect("apply plan");

    let settings_after = fs::read(&settings_path).expect("re-read settings");
    assert_eq!(
        settings_before, settings_after,
        "the same-named server in the other config must stay byte-identical"
    );
    let dup = server_value(&settings_path, "filesystem");
    assert_eq!(dup["command"], "npx");
}

#[test]
fn config_without_any_selected_server_stays_byte_identical() {
    let root = temp_root("untouched-config");
    write_claude_config(&root);
    let cursor_path = write_cursor_config(&root);
    let cursor_before = fs::read(&cursor_path).expect("read cursor config");

    let detections = detect(&root);
    let selections = selections_for(&[claude_id(&root, "filesystem")]);
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
    let id = claude_id(&root, "filesystem");
    let mut selections = selections_for(std::slice::from_ref(&id));
    selections.policy_types.insert(
        id,
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
    let selections = selections_for(&[claude_id(&root, "filesystem")]);
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
    let id = claude_id(&root, "fetcher");
    let mut selections = selections_for(std::slice::from_ref(&id));
    selections.version_pins.insert(id, "0.2.1".to_string());

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
    // `latest`/ranges/garbage plus npm partial versions, which are ranges,
    // not exact pins.
    for bad in ["latest", "^1.2", ">=2", "foo", "1", "1.2", "1..2", "1foo"] {
        let id = claude_id(&root, "filesystem");
        let mut selections = selections_for(std::slice::from_ref(&id));
        selections.version_pins.insert(id, bad.to_string());
        let result = build_wizard_plan(&detections, &selections, &root.display().to_string());
        assert!(result.is_err(), "version {bad:?} must be rejected as a pin");
    }
}

#[test]
fn deleted_config_aborts_apply_without_false_success() {
    let root = temp_root("deleted-config");
    let config_path = write_claude_config(&root);

    let detections = detect(&root);
    let selections = selections_for(&[claude_id(&root, "filesystem")]);
    let plan = build_wizard_plan(&detections, &selections, &root.display().to_string())
        .expect("build plan");

    // The reviewed config disappears between preview and confirm.
    fs::remove_file(&config_path).expect("delete config");

    let error = apply_wizard_plan(&root, &plan).expect_err("apply must fail");
    assert!(
        format!("{error:#}").contains("no longer exists"),
        "unexpected error: {error:#}"
    );
    assert!(
        !root.join(".etherfence").exists(),
        "no backup or policy may be written when the apply aborts"
    );
}

#[test]
fn post_preview_invocation_drift_aborts_apply() {
    let root = temp_root("drift");
    let config_path = write_claude_config(&root);

    let detections = detect(&root);
    let selections = selections_for(&[claude_id(&root, "filesystem")]);
    let plan = build_wizard_plan(&detections, &selections, &root.display().to_string())
        .expect("build plan");

    // The invocation is swapped for a different package after preview.
    let content = fs::read_to_string(&config_path).expect("read config");
    let swapped = content.replace(
        "@modelcontextprotocol/server-filesystem",
        "evil-lookalike-package",
    );
    assert_ne!(content, swapped);
    fs::write(&config_path, &swapped).expect("modify config");
    let before = fs::read(&config_path).expect("read modified config");

    let error = apply_wizard_plan(&root, &plan).expect_err("apply must fail");
    assert!(
        format!("{error:#}").contains("changed after the plan was reviewed"),
        "unexpected error: {error:#}"
    );
    // Nothing was written: the modified config is untouched and no
    // EtherFence artifacts exist.
    let after = fs::read(&config_path).expect("re-read config");
    assert_eq!(before, after);
    assert!(!root.join(".etherfence").exists());
}

#[test]
fn root_mismatch_aborts_apply() {
    let root = temp_root("root-mismatch");
    write_claude_config(&root);
    let other_root = temp_root("root-mismatch-other");
    write_claude_config(&other_root);

    let detections = detect(&root);
    let selections = selections_for(&[claude_id(&root, "filesystem")]);
    let plan = build_wizard_plan(&detections, &selections, &root.display().to_string())
        .expect("build plan");

    let error = apply_wizard_plan(&other_root, &plan).expect_err("apply must fail");
    assert!(
        format!("{error:#}").contains("does not match the plan's root"),
        "unexpected error: {error:#}"
    );
    assert!(!other_root.join(".etherfence").exists());
}

#[test]
fn shared_parent_configs_get_distinct_policies_and_backups() {
    // `.vscode/mcp.json` and `.vscode/settings.json` share one parent
    // directory and here define the same server name — policies and
    // backups must not collide.
    let root = temp_root("shared-parent");
    let dir = root.join(".vscode");
    fs::create_dir_all(&dir).expect("create .vscode");
    fs::write(
        dir.join("mcp.json"),
        r#"{"mcpServers": {"shared": {"command": "npx", "args": ["pkg-a"]}}}"#,
    )
    .expect("write mcp.json");
    fs::write(
        dir.join("settings.json"),
        r#"{"mcp": {"servers": {"shared": {"command": "npx", "args": ["pkg-b"]}}}}"#,
    )
    .expect("write settings.json");

    let detections = detect(&root);
    let ids: Vec<WizardServerId> = detections
        .iter()
        .flat_map(|d| {
            d.servers.iter().map(|s| WizardServerId {
                agent: d.agent.clone(),
                config_path: d.config_path.clone(),
                server_name: s.name.clone(),
            })
        })
        .collect();
    assert_eq!(ids.len(), 2, "both shared servers detected: {ids:?}");

    let selections = selections_for(&ids);
    let plan = build_wizard_plan(&detections, &selections, &root.display().to_string())
        .expect("build plan");
    apply_wizard_plan(&root, &plan).expect("apply plan");

    // Two distinct policy files exist.
    let policy_dir = dir.join(".etherfence/policies");
    let policies: Vec<PathBuf> = fs::read_dir(&policy_dir)
        .expect("policy dir")
        .map(|e| e.expect("entry").path())
        .collect();
    assert_eq!(
        policies.len(),
        2,
        "each config's server needs its own policy file: {policies:?}"
    );

    // Two distinct backup directories exist, each with its own manifest.
    let backup_dir = dir.join(".etherfence/backups");
    let backups: Vec<PathBuf> = fs::read_dir(&backup_dir)
        .expect("backup dir")
        .map(|e| e.expect("entry").path())
        .collect();
    assert_eq!(backups.len(), 2, "one backup dir per config: {backups:?}");
    for backup in &backups {
        assert!(backup.join("manifest.json").is_file());
        assert!(backup.join("original.json").is_file());
    }

    // Both servers are wrapped against different policy paths.
    let mcp = server_value(&dir.join("mcp.json"), "shared");
    let settings_content: Value = serde_json::from_str(
        &fs::read_to_string(dir.join("settings.json")).expect("read settings"),
    )
    .expect("parse settings");
    let settings = settings_content["mcp"]["servers"]["shared"].clone();
    let policy_of = |server: &Value| -> String {
        let args = server["args"].as_array().expect("args");
        let idx = args
            .iter()
            .position(|a| a == "--policy")
            .expect("--policy flag");
        args[idx + 1].as_str().expect("policy path").to_string()
    };
    assert_ne!(
        policy_of(&mcp),
        policy_of(&settings),
        "the two wrapped servers must reference different policy files"
    );
}

#[test]
fn sanitized_policy_name_collision_is_disambiguated() {
    // `foo/bar` and `foo?bar` both sanitize to `foo-bar`.
    let root = temp_root("sanitize-collision");
    fs::write(
        root.join(".claude.json"),
        r#"{
  "mcpServers": {
    "foo/bar": {"command": "npx", "args": ["pkg-a"]},
    "foo?bar": {"command": "npx", "args": ["pkg-b"]}
  }
}
"#,
    )
    .expect("write config");

    let detections = detect(&root);
    let selections = selections_for(&[claude_id(&root, "foo/bar"), claude_id(&root, "foo?bar")]);
    let plan = build_wizard_plan(&detections, &selections, &root.display().to_string())
        .expect("build plan");
    apply_wizard_plan(&root, &plan).expect("apply plan");

    let policy_dir = root.join(".etherfence/policies");
    let policies: Vec<String> = fs::read_dir(&policy_dir)
        .expect("policy dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        policies.len(),
        2,
        "colliding sanitized names must produce two distinct policy files: {policies:?}"
    );

    let config: Value =
        serde_json::from_str(&fs::read_to_string(root.join(".claude.json")).expect("read"))
            .expect("parse");
    let policy_of = |name: &str| -> String {
        let args = config["mcpServers"][name]["args"].as_array().expect("args");
        let idx = args
            .iter()
            .position(|a| a == "--policy")
            .expect("--policy flag");
        args[idx + 1].as_str().expect("policy path").to_string()
    };
    assert_ne!(policy_of("foo/bar"), policy_of("foo?bar"));
}

#[test]
fn pre_existing_policy_with_different_content_aborts_apply() {
    let root = temp_root("existing-policy");
    let config_path = write_claude_config(&root);
    let before = fs::read(&config_path).expect("read config");

    // An operator-authored policy already sits at the planned path.
    let policy_dir = root.join(".etherfence/policies");
    fs::create_dir_all(&policy_dir).expect("create policy dir");
    fs::write(
        policy_dir.join("filesystem.toml"),
        "# operator-authored policy — not EtherFence generated\n",
    )
    .expect("write pre-existing policy");

    let detections = detect(&root);
    let selections = selections_for(&[claude_id(&root, "filesystem")]);
    let plan = build_wizard_plan(&detections, &selections, &root.display().to_string())
        .expect("build plan");

    let error = apply_wizard_plan(&root, &plan).expect_err("apply must fail");
    assert!(
        format!("{error:#}").contains("refusing to overwrite"),
        "unexpected error: {error:#}"
    );
    // The config was not modified and the operator's policy is intact.
    let after = fs::read(&config_path).expect("re-read config");
    assert_eq!(before, after);
    let policy = fs::read_to_string(policy_dir.join("filesystem.toml")).expect("read policy");
    assert!(policy.contains("operator-authored"));
}

#[test]
fn plan_with_foreign_policy_entry_is_rejected() {
    // A policy entry that belongs to no selected server means the plan is
    // inconsistent; apply must refuse rather than write extra files.
    let root = temp_root("foreign-policy");
    write_claude_config(&root);

    let detections = detect(&root);
    let selections = selections_for(&[claude_id(&root, "filesystem")]);
    let mut plan = build_wizard_plan(&detections, &selections, &root.display().to_string())
        .expect("build plan");
    let mut foreign = plan.policies[0].clone();
    foreign.server_name = "fetcher".to_string();
    plan.policies.push(foreign);

    let error = apply_wizard_plan(&root, &plan).expect_err("apply must fail");
    assert!(
        format!("{error:#}").contains("unselected server"),
        "unexpected error: {error:#}"
    );
    assert!(!root.join(".etherfence").exists());
}

#[test]
fn post_preview_env_change_aborts_apply() {
    // The drift gate must cover the complete server entry — including
    // `env`, which influences trust findings and can carry credentials —
    // not just command/args/url.
    let root = temp_root("env-drift");
    let config_path = root.join(".claude.json");
    fs::write(
        &config_path,
        r#"{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem"],
      "env": {"FS_ROOT": "/home/user/projects"}
    }
  }
}
"#,
    )
    .expect("write config");

    let detections = detect(&root);
    let selections = selections_for(&[claude_id(&root, "filesystem")]);
    let plan = build_wizard_plan(&detections, &selections, &root.display().to_string())
        .expect("build plan");

    // The environment changes after preview; command/args/url stay put.
    let content = fs::read_to_string(&config_path).expect("read config");
    let swapped = content.replace("/home/user/projects", "/");
    assert_ne!(content, swapped);
    fs::write(&config_path, &swapped).expect("modify config");
    let before = fs::read(&config_path).expect("read modified config");

    let error = apply_wizard_plan(&root, &plan).expect_err("apply must fail");
    assert!(
        format!("{error:#}").contains("changed after the plan was reviewed"),
        "unexpected error: {error:#}"
    );
    let after = fs::read(&config_path).expect("re-read config");
    assert_eq!(before, after, "aborted apply must write nothing");
    assert!(!root.join(".etherfence").exists());
}

#[test]
fn identical_pre_existing_policy_is_never_adopted() {
    // A pre-existing policy file whose content happens to equal the
    // planned content must not be absorbed into the transaction: the
    // backup manifest records every prepared policy path and rollback /
    // failed-apply cleanup delete recorded paths, so adopting the file
    // would make an operator-owned policy deletable. Apply must refuse
    // outright and leave the file untouched.
    let root = temp_root("identical-policy");
    let config_path = write_claude_config(&root);
    let config_before = fs::read(&config_path).expect("read config");

    let policy_dir = root.join(".etherfence/policies");
    fs::create_dir_all(&policy_dir).expect("create policy dir");
    let identical = etherfence_setup::generated_policy_template("filesystem")
        .expect("generate template content");
    fs::write(policy_dir.join("filesystem.toml"), &identical).expect("write identical policy");

    let detections = detect(&root);
    let selections = selections_for(&[claude_id(&root, "filesystem")]);
    let plan = build_wizard_plan(&detections, &selections, &root.display().to_string())
        .expect("build plan");
    assert_eq!(
        plan.policies[0].content, identical,
        "test precondition: pre-existing content equals planned content"
    );

    let error = apply_wizard_plan(&root, &plan).expect_err("apply must fail");
    assert!(
        format!("{error:#}").contains("already exists"),
        "unexpected error: {error:#}"
    );

    // Nothing changed: config untouched, the operator's file survives,
    // and no backup manifest exists that could later delete it.
    let config_after = fs::read(&config_path).expect("re-read config");
    assert_eq!(config_before, config_after);
    let survivor =
        fs::read_to_string(policy_dir.join("filesystem.toml")).expect("read surviving policy");
    assert_eq!(survivor, identical);
    assert!(!root.join(".etherfence/backups").exists());
}

// ── snapshot consistency and bounded read (v1.6.2 hardening) ──────────

/// An oversized config (> 5 MiB) must never receive canonical-entry
/// snapshots. The bounded read rejects it, so `attach_entry_snapshots`
/// returns early and every server in the detection keeps `raw_entry_sha256: None`.
#[test]
fn oversized_supported_config_yields_no_snapshot() {
    let root = temp_root("oversized");
    let config_path = root.join(".claude.json");

    // Build a valid JSON config whose total size exceeds 5 MiB. Write
    // a 5.01 MiB padding value so the file is just past the bound.
    let padding_len = 5 * 1024 * 1024 + 1024; // 5 MiB + 1 KiB
    let padding = "x".repeat(padding_len);
    let config_json = serde_json::json!({
        "mcpServers": {
            "test-server": {
                "command": "npx",
                "args": ["-y", "some-package"],
                "_padding": padding
            }
        }
    });
    fs::write(&config_path, config_json.to_string()).expect("write oversized config");
    assert!(
        config_path.metadata().expect("metadata").len() > 5 * 1024 * 1024,
        "test precondition: config must exceed 5 MiB"
    );

    let detections = detect(&root);
    assert!(
        !detections.is_empty(),
        "must detect the config even if oversized"
    );

    for detection in &detections {
        for server in &detection.servers {
            assert!(
                server.raw_entry_sha256.is_none(),
                "oversized config must never receive snapshot hashes; \
                 server '{}' got one",
                server.name
            );
        }
    }
}

/// A supported config that exists but cannot be read as UTF-8 JSON must
/// never receive canonical-entry snapshots. The bounded read returns an
/// error, so `attach_entry_snapshots` returns early.
#[test]
fn unreadable_supported_config_yields_no_snapshot() {
    let root = temp_root("unreadable-config");

    // Create a `.claude.json` with invalid UTF-8 bytes so
    // `read_bounded_text_file` fails.
    let config_path = root.join(".claude.json");
    let mut bad_bytes = vec![b'{', b'"', b'm', b'c', b'p', b'S'];
    bad_bytes.push(0xFF); // invalid UTF-8 byte
    fs::write(&config_path, &bad_bytes).expect("write unreadable config");

    let detections = detect(&root);

    // The config file exists, so inventory detects it (presence-entry)
    // but parsing fails. It should appear with no servers and no snapshots.
    for detection in &detections {
        if detection.config_path.contains(".claude.json") {
            for server in &detection.servers {
                assert!(
                    server.raw_entry_sha256.is_none(),
                    "unreadable config must never receive snapshot hashes; \
                     server '{}' got one",
                    server.name
                );
            }
        }
    }
}

/// The snapshot hash computed at detection time must match the hash the
/// apply drift gate computes from the same config content. Build a plan,
/// then verify the plan's `expected_entry_sha256` equals what `detect()`
/// assigned to the same server.
#[test]
fn detect_snapshot_consistency_across_detect_and_plan() {
    let root = temp_root("snapshot-consistent");
    write_claude_config(&root);

    let detections = detect(&root);

    // Extract the entry hash detect assigned to "filesystem".
    let claude_detection = detections
        .iter()
        .find(|d| d.config_path == "~/.claude.json")
        .expect("claude config detected");
    let filesystem = claude_detection
        .servers
        .iter()
        .find(|s| s.name == "filesystem")
        .expect("filesystem server found");
    let detect_hash = filesystem
        .raw_entry_sha256
        .as_ref()
        .expect("filesystem must have a snapshot hash");

    // Build a wizard plan; the plan embeds the same hash.
    let selections = selections_for(&[claude_id(&root, "filesystem")]);
    let plan = build_wizard_plan(&detections, &selections, &root.display().to_string())
        .expect("build plan");

    assert_eq!(
        plan.selected_servers[0].expected_entry_sha256, *detect_hash,
        "plan's expected_entry_sha256 must match the snapshot hash from detect()"
    );
}

/// Verify that every stdio server in every writable supported config
/// receives a canonical-entry snapshot during detection, and that the
/// hash is 64 hex chars (SHA-256).
#[test]
fn all_supported_stdio_servers_get_snapshots() {
    let root = temp_root("all-snapshot");
    write_claude_config(&root);
    write_cursor_config(&root);

    let detections = detect(&root);

    for detection in &detections {
        // Only writable supported configs get snapshots.
        let is_supported = detection.agent == "Claude Code" || detection.agent == "Cursor";
        for server in &detection.servers {
            if is_supported {
                let hash = server.raw_entry_sha256.as_ref().unwrap_or_else(|| {
                    panic!(
                        "supported server '{}/{}' must have a snapshot hash",
                        detection.config_path, server.name
                    )
                });
                assert_eq!(
                    hash.len(),
                    64,
                    "snapshot hash for '{}/{}' must be 64 hex chars, got {}",
                    detection.config_path,
                    server.name,
                    hash.len()
                );
                assert!(
                    hash.chars().all(|c| c.is_ascii_hexdigit()),
                    "snapshot hash for '{}/{}' must be hex: {hash}",
                    detection.config_path,
                    server.name
                );
            } else {
                assert!(
                    server.raw_entry_sha256.is_none(),
                    "unsupported/absent config '{}/{}' must not have snapshot",
                    detection.config_path,
                    server.name
                );
            }
        }
    }
}
