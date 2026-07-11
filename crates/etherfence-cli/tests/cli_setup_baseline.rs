use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
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
        "etherfence-baseline-{name}-{}-{nanos}",
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

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_etherfence"))
        .args(args)
        .output()
        .expect("run etherfence")
}

fn write_baseline(root: &Path, output: &Path) -> Output {
    run(&[
        "setup",
        "baseline",
        "write",
        "--root",
        root.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
    ])
}

fn check(root: &Path, baseline: &Path, extra: &[&str]) -> Output {
    let mut args = vec![
        "setup".to_string(),
        "baseline".to_string(),
        "check".to_string(),
        "--root".to_string(),
        root.to_str().unwrap().to_string(),
        "--baseline".to_string(),
        baseline.to_str().unwrap().to_string(),
    ];
    args.extend(extra.iter().map(|s| s.to_string()));
    let args_ref: Vec<&str> = args.iter().map(String::as_str).collect();
    run(&args_ref)
}

fn check_json(root: &Path, baseline: &Path, extra: &[&str]) -> Value {
    let mut all_extra = vec!["--format", "json"];
    all_extra.extend_from_slice(extra);
    let output = check(root, baseline, &all_extra);
    assert!(
        output.status.success() || !extra.is_empty(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("valid JSON")
}

fn entry_by_server<'a>(json: &'a Value, name: &str) -> &'a Value {
    json["entries"]
        .as_array()
        .expect("entries array")
        .iter()
        .find(|e| e["serverName"] == name)
        .unwrap_or_else(|| panic!("missing server {name}"))
}

fn file_hash(path: &Path) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let content = fs::read(path).expect("read file for hashing");
    Sha256::digest(&content).to_vec()
}

// --- T008: write byte-identical / overwrite refusal ---

#[test]
fn write_is_byte_identical_across_repeated_runs_with_no_changes() {
    let root = fixture_root("baseline-home");
    let out_a = temp_home("write-a").join("baseline.json");
    let out_b = temp_home("write-b").join("baseline.json");
    let a = write_baseline(&root, &out_a);
    assert!(
        a.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&a.stderr)
    );
    let b = write_baseline(&root, &out_b);
    assert!(
        b.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&b.stderr)
    );
    assert_eq!(fs::read(&out_a).unwrap(), fs::read(&out_b).unwrap());
}

#[test]
fn write_refuses_overwrite_without_flag_and_overwrites_with_flag() {
    let root = fixture_root("baseline-home");
    let output = temp_home("overwrite").join("baseline.json");
    let first = write_baseline(&root, &output);
    assert!(first.status.success());
    let before_hash = file_hash(&output);

    let refused = write_baseline(&root, &output);
    assert!(!refused.status.success());
    assert_eq!(
        file_hash(&output),
        before_hash,
        "file must be untouched on refusal"
    );

    let overwritten = run(&[
        "setup",
        "baseline",
        "write",
        "--root",
        root.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
        "--overwrite",
    ]);
    assert!(overwritten.status.success());
}

#[test]
fn write_output_declares_schema_version() {
    let root = fixture_root("baseline-home");
    let output = temp_home("schema").join("baseline.json");
    let result = write_baseline(&root, &output);
    assert!(result.status.success());
    let json: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(json["schemaVersion"], "ef-setup-baseline/v0.1");
}

// --- T012: statuses and drift reasons ---

#[test]
fn check_reports_unchanged_when_nothing_changed() {
    let root = fixture_root("baseline-home");
    let output = temp_home("unchanged").join("baseline.json");
    assert!(write_baseline(&root, &output).status.success());
    let json = check_json(&root, &output, &[]);
    for entry in json["entries"].as_array().unwrap() {
        assert_eq!(entry["status"], "unchanged", "entry: {entry}");
    }
}

#[test]
fn check_detects_new_and_missing_servers() {
    let temp = temp_home("new-missing");
    copy_dir_all(&fixture_root("baseline-home"), &temp);
    let baseline_path = temp_home("new-missing-baseline").join("baseline.json");
    assert!(write_baseline(&temp, &baseline_path).status.success());

    // Remove the Cursor config entirely -> its server becomes `missing`.
    fs::remove_file(temp.join(".cursor/mcp.json")).unwrap();
    // Add a brand-new server to Claude Code's config -> `new`.
    write_file(
        &temp.join(".claude.json"),
        r#"{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/example"],
      "env": {"MCP_ENV_NAME": "fixture-value", "OTHER_ENV_NAME": "fixture-value"}
    },
    "docs": {
      "url": "https://example.invalid/mcp",
      "env": {"MCP_ENV_NAME": "fixture-value"}
    },
    "brand-new-server": {
      "command": "npx",
      "args": ["-y", "some-brand-new-package"]
    }
  }
}
"#,
    );

    let json = check_json(&temp, &baseline_path, &[]);
    let entries = json["entries"].as_array().unwrap();
    let missing = entries
        .iter()
        .find(|e| e["serverName"] == "filesystem" && e["configSource"] == "~/.cursor/mcp.json")
        .unwrap();
    assert_eq!(missing["status"], "missing");
    assert_eq!(missing["reasons"], serde_json::json!(["server-removed"]));

    let new_entry = entries
        .iter()
        .find(|e| e["serverName"] == "brand-new-server")
        .unwrap();
    assert_eq!(new_entry["status"], "new");
    assert_eq!(new_entry["reasons"], serde_json::json!(["server-added"]));
}

#[test]
fn check_detects_command_and_arguments_changed() {
    let temp = temp_home("cmd-args");
    copy_dir_all(&fixture_root("baseline-home"), &temp);
    let baseline_path = temp_home("cmd-args-baseline").join("baseline.json");
    assert!(write_baseline(&temp, &baseline_path).status.success());

    write_file(
        &temp.join(".cursor/mcp.json"),
        r#"{"mcpServers":{"filesystem":{"command":"npx","args":["some-other-package==1.0.0"]}}}"#,
    );
    let json = check_json(&temp, &baseline_path, &[]);
    let entry = entry_by_server(&json, "filesystem");
    // Two "filesystem" entries exist (Claude Code + Cursor); find the Cursor one.
    let cursor_entry = json["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["configSource"] == "~/.cursor/mcp.json")
        .unwrap();
    assert_eq!(cursor_entry["status"], "changed");
    assert!(cursor_entry["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r == "command-changed"));
    let _ = entry; // silence unused warning if the first lookup is redundant.
}

#[test]
fn check_detects_package_identity_and_version_changed() {
    let temp = temp_home("pkg-identity");
    copy_dir_all(&fixture_root("baseline-home"), &temp);
    let baseline_path = temp_home("pkg-identity-baseline").join("baseline.json");
    assert!(write_baseline(&temp, &baseline_path).status.success());

    // Baseline has an exactly-pinned version (`==1.0.0`); switch to an
    // omitted version so the *version-expression classification* itself
    // changes (exactly-pinned -> omitted) — a same-classification version
    // bump (e.g. 1.0.0 -> 2.0.0, both exactly-pinned) is intentionally not
    // detectable, since only the classification is persisted, never the
    // raw version text (spec FR-024).
    write_file(
        &temp.join(".cursor/mcp.json"),
        r#"{"mcpServers":{"filesystem":{"command":"uvx","args":["some-other-package"]}}}"#,
    );
    let json = check_json(&temp, &baseline_path, &[]);
    let entry = json["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["configSource"] == "~/.cursor/mcp.json")
        .unwrap();
    assert_eq!(entry["status"], "changed");
    assert!(entry["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r == "package-version-changed"));
}

#[test]
fn check_detects_transport_changed() {
    let temp = temp_home("transport");
    copy_dir_all(&fixture_root("baseline-home"), &temp);
    let baseline_path = temp_home("transport-baseline").join("baseline.json");
    assert!(write_baseline(&temp, &baseline_path).status.success());

    write_file(
        &temp.join(".cursor/mcp.json"),
        r#"{"mcpServers":{"filesystem":{"url":"https://example.invalid/mcp"}}}"#,
    );
    let json = check_json(&temp, &baseline_path, &[]);
    let entry = json["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["configSource"] == "~/.cursor/mcp.json")
        .unwrap();
    assert_eq!(entry["status"], "changed");
    assert!(entry["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r == "transport-changed"));
}

#[test]
fn check_detects_capability_and_trust_indicator_set_changed() {
    let temp = temp_home("capability");
    copy_dir_all(&fixture_root("baseline-home"), &temp);
    let baseline_path = temp_home("capability-baseline").join("baseline.json");
    assert!(write_baseline(&temp, &baseline_path).status.success());

    // Switch the Claude Code filesystem server to a bare shell command,
    // changing both its capability classification and its trust indicators.
    write_file(
        &temp.join(".claude.json"),
        r#"{
  "mcpServers": {
    "filesystem": {
      "command": "bash",
      "args": ["-c", "echo hi"]
    },
    "docs": {
      "url": "https://example.invalid/mcp",
      "env": {"MCP_ENV_NAME": "fixture-value"}
    }
  }
}
"#,
    );
    let json = check_json(&temp, &baseline_path, &[]);
    let entry = json["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["configSource"] == "~/.claude.json" && e["serverName"] == "filesystem")
        .unwrap();
    assert_eq!(entry["status"], "changed");
    let reasons: Vec<&str> = entry["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r.as_str().unwrap())
        .collect();
    assert!(
        reasons.contains(&"capability-set-changed"),
        "reasons: {reasons:?}"
    );
}

#[test]
fn environment_variable_name_set_reordering_causes_no_drift_but_addition_does() {
    let temp = temp_home("env-set");
    copy_dir_all(&fixture_root("baseline-home"), &temp);
    let baseline_path = temp_home("env-set-baseline").join("baseline.json");
    assert!(write_baseline(&temp, &baseline_path).status.success());

    // Reorder env keys only (semantically identical set) -> no drift.
    write_file(
        &temp.join(".claude.json"),
        r#"{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/example"],
      "env": {"OTHER_ENV_NAME": "fixture-value", "MCP_ENV_NAME": "fixture-value"}
    },
    "docs": {
      "url": "https://example.invalid/mcp",
      "env": {"MCP_ENV_NAME": "fixture-value"}
    }
  }
}
"#,
    );
    let json = check_json(&temp, &baseline_path, &[]);
    let entry = json["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["configSource"] == "~/.claude.json" && e["serverName"] == "filesystem")
        .unwrap();
    assert_eq!(entry["status"], "unchanged");

    // Now add a new env var name -> drift.
    write_file(
        &temp.join(".claude.json"),
        r#"{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/example"],
      "env": {"MCP_ENV_NAME": "fixture-value", "OTHER_ENV_NAME": "fixture-value", "THIRD_ENV_NAME": "fixture-value"}
    },
    "docs": {
      "url": "https://example.invalid/mcp",
      "env": {"MCP_ENV_NAME": "fixture-value"}
    }
  }
}
"#,
    );
    let json2 = check_json(&temp, &baseline_path, &[]);
    let entry2 = json2["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["configSource"] == "~/.claude.json" && e["serverName"] == "filesystem")
        .unwrap();
    assert_eq!(entry2["status"], "changed");
    assert!(entry2["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r == "environment-variable-names-changed"));
}

#[test]
fn json_key_reordering_in_config_file_causes_no_drift() {
    let temp = temp_home("key-reorder");
    copy_dir_all(&fixture_root("baseline-home"), &temp);
    let baseline_path = temp_home("key-reorder-baseline").join("baseline.json");
    assert!(write_baseline(&temp, &baseline_path).status.success());

    // Same semantic content, different key order and whitespace.
    write_file(
        &temp.join(".cursor/mcp.json"),
        r#"{ "mcpServers": { "filesystem": { "args": ["some-other-package==1.0.0"], "command": "uvx" } } }"#,
    );
    let json = check_json(&temp, &baseline_path, &[]);
    for entry in json["entries"].as_array().unwrap() {
        assert_eq!(entry["status"], "unchanged", "entry: {entry}");
    }
}

#[test]
fn duplicate_server_names_across_agents_are_never_conflated() {
    let root = fixture_root("baseline-home");
    let output = temp_home("dup-names").join("baseline.json");
    assert!(write_baseline(&root, &output).status.success());
    let json: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    let filesystem_entries: Vec<&Value> = json["servers"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| s["serverName"] == "filesystem")
        .collect();
    assert_eq!(filesystem_entries.len(), 2);
    assert_ne!(
        filesystem_entries[0]["fingerprint"],
        filesystem_entries[1]["fingerprint"]
    );

    let check_result = check_json(&root, &output, &[]);
    let checked: Vec<&Value> = check_result["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["serverName"] == "filesystem")
        .collect();
    assert_eq!(checked.len(), 2);
    assert!(checked.iter().all(|e| e["status"] == "unchanged"));
}

// --- T013: malformed baseline fails closed, never mutates, no secrets ---

#[test]
fn check_fails_closed_on_wrong_schema_version() {
    let root = fixture_root("baseline-home");
    let baseline_path = temp_home("bad-schema").join("baseline.json");
    write_file(
        &baseline_path,
        r#"{"schemaVersion":"ef-setup-baseline/v9.9","root":"x","servers":[]}"#,
    );
    let output = check(&root, &baseline_path, &[]);
    assert!(!output.status.success());
}

#[test]
fn check_fails_closed_on_invalid_json() {
    let root = fixture_root("baseline-home");
    let baseline_path = temp_home("bad-json").join("baseline.json");
    write_file(&baseline_path, "{ this is not valid json ");
    let output = check(&root, &baseline_path, &[]);
    assert!(!output.status.success());
}

#[test]
fn check_never_modifies_the_baseline_file() {
    let root = fixture_root("baseline-home");
    let baseline_path = temp_home("never-mutates").join("baseline.json");
    assert!(write_baseline(&root, &baseline_path).status.success());
    let before = file_hash(&baseline_path);

    for extra in [
        vec![],
        vec!["--format", "json"],
        vec!["--fail-on-drift"],
        vec!["--fail-on-new"],
        vec!["--fail-on-risk-increase"],
    ] {
        let extra_ref: Vec<&str> = extra;
        let _ = check(&root, &baseline_path, &extra_ref);
        assert_eq!(
            file_hash(&baseline_path),
            before,
            "baseline mutated after check {extra_ref:?}"
        );
    }
}

#[test]
fn no_secret_or_env_value_ever_appears_in_baseline_or_check_output() {
    let root = fixture_root("baseline-home");
    let baseline_path = temp_home("no-leak").join("baseline.json");
    assert!(write_baseline(&root, &baseline_path).status.success());
    let baseline_content = fs::read_to_string(&baseline_path).unwrap();
    assert!(!baseline_content.contains("fixture-value"));

    let human = check(&root, &baseline_path, &[]);
    assert!(!String::from_utf8_lossy(&human.stdout).contains("fixture-value"));
    let json = check(&root, &baseline_path, &["--format", "json"]);
    assert!(!String::from_utf8_lossy(&json.stdout).contains("fixture-value"));
}

// --- T016: gate semantics ---

#[test]
fn gate_flag_combinations_produce_expected_exit_codes() {
    let temp = temp_home("gates");
    copy_dir_all(&fixture_root("baseline-home"), &temp);
    let baseline_path = temp_home("gates-baseline").join("baseline.json");
    assert!(write_baseline(&temp, &baseline_path).status.success());

    // Introduce exactly one `new` server; no risk-increase, no missing/changed.
    write_file(
        &temp.join(".cursor/mcp.json"),
        r#"{"mcpServers":{"filesystem":{"command":"uvx","args":["some-other-package==1.0.0"]},"extra":{"command":"npx","args":["-y","extra-pkg"]}}}"#,
    );

    let combinations: [(bool, bool, bool, bool); 8] = [
        (false, false, false, false),
        (true, false, false, true),
        (false, true, false, true),
        (false, false, true, false),
        (true, true, false, true),
        (true, false, true, true),
        (false, true, true, true),
        (true, true, true, true),
    ];
    for (fail_on_drift, fail_on_new, fail_on_risk_increase, expect_fail) in combinations {
        let mut extra = Vec::new();
        if fail_on_drift {
            extra.push("--fail-on-drift");
        }
        if fail_on_new {
            extra.push("--fail-on-new");
        }
        if fail_on_risk_increase {
            extra.push("--fail-on-risk-increase");
        }
        let output = check(&temp, &baseline_path, &extra);
        assert_eq!(
            output.status.success(),
            !expect_fail,
            "combination {extra:?} unexpected exit status"
        );
        // Report must always be rendered, even when the gate triggers.
        assert!(!output.stdout.is_empty(), "report suppressed for {extra:?}");
    }
}

#[test]
fn risk_increase_gate_fires_on_increase_but_not_on_decrease() {
    // Baseline: exactly-pinned known-source package (aggregate=known-source).
    let temp_up = temp_home("risk-up");
    fs::create_dir_all(&temp_up).unwrap();
    write_file(
        &temp_up.join(".claude.json"),
        r#"{"mcpServers":{"filesystem":{"command":"npx","args":["@modelcontextprotocol/server-filesystem@1.2.3"]}}}"#,
    );
    let baseline_path = temp_home("risk-up-baseline").join("baseline.json");
    assert!(write_baseline(&temp_up, &baseline_path).status.success());

    // Current: same package, version omitted -> pinning indicator ->
    // configurationRisk becomes needs-review -> aggregate rank increases.
    write_file(
        &temp_up.join(".claude.json"),
        r#"{"mcpServers":{"filesystem":{"command":"npx","args":["@modelcontextprotocol/server-filesystem"]}}}"#,
    );
    let increased = check_json(&temp_up, &baseline_path, &[]);
    let entry = entry_by_server(&increased, "filesystem");
    assert_eq!(entry["riskDirection"], "increased");
    assert!(entry["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r == "risk-increased"));
    let gated = check(&temp_up, &baseline_path, &["--fail-on-risk-increase"]);
    assert!(!gated.status.success());

    // Reverse scenario: baseline unpinned (needs-review), current pinned
    // (known-source) -> risk decreases; must NOT trigger the gate.
    let temp_down = temp_home("risk-down");
    fs::create_dir_all(&temp_down).unwrap();
    write_file(
        &temp_down.join(".claude.json"),
        r#"{"mcpServers":{"filesystem":{"command":"npx","args":["@modelcontextprotocol/server-filesystem"]}}}"#,
    );
    let baseline_down_path = temp_home("risk-down-baseline").join("baseline.json");
    assert!(write_baseline(&temp_down, &baseline_down_path)
        .status
        .success());
    write_file(
        &temp_down.join(".claude.json"),
        r#"{"mcpServers":{"filesystem":{"command":"npx","args":["@modelcontextprotocol/server-filesystem@1.2.3"]}}}"#,
    );
    let decreased = check_json(&temp_down, &baseline_down_path, &[]);
    let decreased_entry = entry_by_server(&decreased, "filesystem");
    assert_eq!(decreased_entry["riskDirection"], "decreased");
    assert!(!decreased_entry["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r == "risk-increased"));
    assert_eq!(decreased_entry["status"], "changed");
    let not_gated = check(
        &temp_down,
        &baseline_down_path,
        &["--fail-on-risk-increase"],
    );
    assert!(not_gated.status.success());
}

// --- Executable hash drift and unverifiable status ---

fn write_executable(path: &Path, content: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).unwrap();
    }
}

#[test]
fn one_byte_executable_change_produces_hash_drift() {
    let temp = temp_home("hash-drift");
    let bin_path = temp.join("bin").join("sample-tool");
    write_executable(&bin_path, b"original-bytes-0000");
    write_file(
        &temp.join(".claude.json"),
        &format!(
            r#"{{"mcpServers":{{"tool":{{"command":"{}"}}}}}}"#,
            bin_path.display().to_string().replace('\\', "\\\\")
        ),
    );
    let baseline_path = temp_home("hash-drift-baseline").join("baseline.json");
    assert!(write_baseline(&temp, &baseline_path).status.success());
    let baseline_json: Value = serde_json::from_slice(&fs::read(&baseline_path).unwrap()).unwrap();
    assert!(baseline_json["servers"][0]["sha256"].is_string());

    write_executable(&bin_path, b"original-bytes-0001");
    let json = check_json(&temp, &baseline_path, &[]);
    let entry = entry_by_server(&json, "tool");
    assert_eq!(entry["status"], "changed");
    assert!(entry["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r == "executable-hash-changed"));
}

/// A permission-denial hash failure is the "clean" unverifiable case: the
/// executable path classification itself (`absolute-path`) is unaffected
/// (a `stat`-only check succeeds regardless of read permission), so no
/// other independent drift reason (like a new symlink indicator) can also
/// fire alongside it. A symlink swap was considered for this test and
/// rejected: replacing the file with a symlink also changes its
/// `executablePath` classification and raises a *new*, genuinely
/// independent `EF-TRUST-PATH-003` indicator, which correctly demotes that
/// scenario to `changed` rather than `unverifiable` per Decision 8's
/// precedence rule — permission denial isolates the "lost verification"
/// signal from any other observable change.
#[cfg(unix)]
#[test]
fn hash_verified_executable_becoming_unreadable_is_unverifiable() {
    let temp = temp_home("unverifiable");
    let bin_path = temp.join("bin").join("sample-tool");
    write_executable(&bin_path, b"original-bytes-0000");
    write_file(
        &temp.join(".claude.json"),
        &format!(
            r#"{{"mcpServers":{{"tool":{{"command":"{}"}}}}}}"#,
            bin_path.display()
        ),
    );
    let baseline_path = temp_home("unverifiable-baseline").join("baseline.json");
    assert!(write_baseline(&temp, &baseline_path).status.success());
    let baseline_json: Value = serde_json::from_slice(&fs::read(&baseline_path).unwrap()).unwrap();
    assert!(baseline_json["servers"][0]["sha256"].is_string());

    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&bin_path, fs::Permissions::from_mode(0o000)).unwrap();

    let json = check_json(&temp, &baseline_path, &[]);
    let entry = entry_by_server(&json, "tool");
    let reasons: Vec<&str> = entry["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r.as_str().unwrap())
        .collect();
    assert_eq!(entry["status"], "unverifiable", "reasons: {reasons:?}");
    assert!(
        reasons.contains(&"executable-became-unverifiable"),
        "reasons: {reasons:?}"
    );

    // Restore permissions so the temp directory can be cleaned up normally.
    fs::set_permissions(&bin_path, fs::Permissions::from_mode(0o755)).unwrap();
}

// --- Review findings #2/#3: no-follow baseline read, race-safe write ---

#[cfg(unix)]
#[test]
fn check_refuses_a_baseline_path_that_is_a_symlink() {
    let root = fixture_root("baseline-home");
    let real_baseline = temp_home("symlink-target").join("baseline.json");
    assert!(write_baseline(&root, &real_baseline).status.success());

    let link = temp_home("symlink-link-parent").join("baseline.json");
    fs::create_dir_all(link.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&real_baseline, &link).unwrap();

    let output = check(&root, &link, &[]);
    assert!(
        !output.status.success(),
        "check must fail closed when --baseline is a symlink"
    );
}

#[cfg(unix)]
#[test]
fn write_refuses_to_create_through_a_pre_existing_symlink_without_overwrite() {
    let root = fixture_root("baseline-home");
    let real_target = temp_home("write-symlink-target").join("baseline.json");
    fs::create_dir_all(real_target.parent().unwrap()).unwrap();
    fs::write(&real_target, "not a real baseline").unwrap();

    let link = temp_home("write-symlink-link-parent").join("baseline.json");
    fs::create_dir_all(link.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&real_target, &link).unwrap();

    let result = write_baseline(&root, &link);
    assert!(
        !result.status.success(),
        "write without --overwrite must refuse to create through a pre-existing symlink"
    );
    // The symlink's target must be untouched.
    assert_eq!(
        fs::read_to_string(&real_target).unwrap(),
        "not a real baseline"
    );
}

/// Review follow-up: `write --overwrite`'s temp file must be created with
/// an unpredictable name and opened via exclusive creation, never a plain
/// `fs::write` at a guessable path — otherwise an attacker who can write
/// into the same directory could pre-stage a symlink at the anticipated
/// temp path and have EtherFence write through it. Simulates the attack
/// by pre-placing a symlink at the *old*, predictable temp-path pattern
/// (`.{file}.tmp-etherfence-{pid}`) this function used before the fix,
/// and confirms `--overwrite` still succeeds (because the current
/// implementation never reuses that predictable name) and the symlink's
/// target is completely untouched.
#[cfg(unix)]
#[test]
fn write_overwrite_never_writes_through_a_symlink_at_the_anticipated_temp_path() {
    let root = fixture_root("baseline-home");
    let output = temp_home("overwrite-temp-race").join("baseline.json");
    assert!(write_baseline(&root, &output).status.success());

    let attacker_target = output.parent().unwrap().join("attacker-owned-file");
    fs::write(&attacker_target, "attacker file must survive untouched").unwrap();

    // Pre-stage a symlink at every temp path the pre-fix predictable
    // naming scheme could have produced for this process, pointing at a
    // file the test owns and must remain untouched.
    let dir = output.parent().unwrap();
    let file_name = output.file_name().unwrap().to_string_lossy().into_owned();
    let predictable_link = dir.join(format!(
        ".{file_name}.tmp-etherfence-{}",
        std::process::id()
    ));
    std::os::unix::fs::symlink(&attacker_target, &predictable_link).unwrap();

    let overwritten = run(&[
        "setup",
        "baseline",
        "write",
        "--root",
        root.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
        "--overwrite",
    ]);
    assert!(
        overwritten.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&overwritten.stderr)
    );
    assert_eq!(
        fs::read_to_string(&attacker_target).unwrap(),
        "attacker file must survive untouched",
        "write must never write through a symlink at a predictable temp path"
    );
    // The pre-staged symlink itself must also be untouched (still a
    // symlink, still pointing at the same target) — EtherFence's own temp
    // file must have used a different, unpredictable name entirely.
    let link_meta = fs::symlink_metadata(&predictable_link).unwrap();
    assert!(link_meta.file_type().is_symlink());
}

#[test]
fn baseline_entries_carry_a_stable_agent_kind_distinct_from_the_display_name() {
    let root = fixture_root("baseline-home");
    let output = temp_home("agent-kind").join("baseline.json");
    assert!(write_baseline(&root, &output).status.success());
    let json: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    let claude_entry = json["servers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["configSource"] == "~/.claude.json" && s["serverName"] == "filesystem")
        .unwrap();
    assert_eq!(claude_entry["agentKind"], "claude-code");
    assert_eq!(claude_entry["agent"], "Claude Code");
}
