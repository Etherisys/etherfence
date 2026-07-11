use serde_json::Value;
use std::fs;
use std::path::PathBuf;
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
        .expect("run etherfence setup catalog")
}

const EXPECTED_CLIENT_ORDER: [&str; 10] = [
    "claude-style-config",
    "cursor",
    "vs-code",
    "hermes",
    "antigravity",
    "windsurf",
    "gemini-cli",
    "codex-cli",
    "open-code",
    "cline-roo-code",
];

#[test]
fn setup_catalog_human_lists_all_ten_clients_in_fixed_order_for_home_fixture() {
    let root = fixture_root("home");
    let output = run(&["setup", "catalog", "--root", root.to_str().unwrap()]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("Claude-style config"));
    assert!(stdout.contains("fixture-verified"));
    assert!(stdout.contains("Cursor"));
    assert!(stdout.contains("VS Code"));
    assert!(stdout.contains("Hermes"));
    assert!(stdout.contains("Antigravity"));
    assert!(stdout.contains("Windsurf"));
    assert!(stdout.contains("detect-only"));
    assert!(stdout.contains("Gemini CLI"));
    assert!(stdout.contains("Codex CLI"));
    assert!(stdout.contains("OpenCode"));
    assert!(stdout.contains("Cline / Roo Code"));
    assert!(stdout.contains("advisory-only"));

    // Row order: each client name must appear in fixed declared order.
    let names = [
        "Claude-style config",
        "Cursor",
        "VS Code",
        "Hermes",
        "Antigravity",
        "Windsurf",
        "Gemini CLI",
        "Codex CLI",
        "OpenCode",
        "Cline / Roo Code",
    ];
    let mut last_pos = 0usize;
    for name in names {
        let pos = stdout
            .find(name)
            .unwrap_or_else(|| panic!("missing row {name}"));
        assert!(pos >= last_pos, "row {name} out of fixed order");
        last_pos = pos;
    }
}

#[test]
fn setup_catalog_human_reports_all_ten_rows_not_found_for_empty_home() {
    let root = fixture_root("empty-home");
    let output = run(&["setup", "catalog", "--root", root.to_str().unwrap()]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // 10 data rows, each showing "no" as found status with no config path.
    assert_eq!(stdout.matches("no     -").count(), 10);
    for name in [
        "Claude-style config",
        "Cursor",
        "VS Code",
        "Hermes",
        "Antigravity",
        "Windsurf",
        "Gemini CLI",
        "Codex CLI",
        "OpenCode",
        "Cline / Roo Code",
    ] {
        assert!(stdout.contains(name));
    }
}

#[test]
fn setup_catalog_json_matches_ef_setup_catalog_v0_1_shape() {
    let root = fixture_root("home");
    let output = run(&[
        "setup",
        "catalog",
        "--format",
        "json",
        "--root",
        root.to_str().unwrap(),
    ]);
    assert!(output.status.success());
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(json["etherfenceSchemaVersion"], "ef-setup-catalog/v0.1");
    assert!(json.get("root").is_some());

    let clients = json["clients"].as_array().expect("clients array");
    assert_eq!(clients.len(), 10);
    let client_ids: Vec<&str> = clients
        .iter()
        .map(|c| c["client"].as_str().expect("client id"))
        .collect();
    assert_eq!(client_ids, EXPECTED_CLIENT_ORDER);

    for client in clients {
        assert!(client.get("tier").is_some());
        assert!(client.get("foundLocally").is_some());
        // Always present, even when empty (contract: never omitted/null).
        assert!(client["configPaths"].is_array());
    }

    let claude = clients
        .iter()
        .find(|c| c["client"] == "claude-style-config")
        .expect("claude entry");
    assert_eq!(claude["tier"], "fixture-verified");
    assert_eq!(claude["foundLocally"], true);
    assert_eq!(claude["configPaths"][0], "~/.claude.json");
}

#[test]
fn setup_catalog_json_multi_path_home_lists_both_cursor_paths_in_candidates_order() {
    let root = fixture_root("multi-path-home");
    let output = run(&[
        "setup",
        "catalog",
        "--format",
        "json",
        "--root",
        root.to_str().unwrap(),
    ]);
    assert!(output.status.success());
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    let clients = json["clients"].as_array().expect("clients array");
    let cursor = clients
        .iter()
        .find(|c| c["client"] == "cursor")
        .expect("cursor entry");
    let paths: Vec<&str> = cursor["configPaths"]
        .as_array()
        .expect("configPaths array")
        .iter()
        .map(|p| p.as_str().expect("path string"))
        .collect();
    assert_eq!(paths, vec!["~/.cursor/mcp.json", "~/.cursor/settings.json"]);
}

#[test]
fn setup_catalog_repeated_runs_produce_byte_identical_stdout() {
    let root = fixture_root("home");
    let first = run(&["setup", "catalog", "--root", root.to_str().unwrap()]);
    let second = run(&["setup", "catalog", "--root", root.to_str().unwrap()]);
    assert_eq!(first.stdout, second.stdout);

    let first_json = run(&[
        "setup",
        "catalog",
        "--format",
        "json",
        "--root",
        root.to_str().unwrap(),
    ]);
    let second_json = run(&[
        "setup",
        "catalog",
        "--format",
        "json",
        "--root",
        root.to_str().unwrap(),
    ]);
    assert_eq!(first_json.stdout, second_json.stdout);
}

#[test]
fn setup_catalog_is_read_only_and_always_exits_zero() {
    for fixture in [
        "home",
        "empty-home",
        "windows-home",
        "malformed-home",
        "multi-path-home",
        "minimal-home",
    ] {
        let root = fixture_root(fixture);
        let before = snapshot(&root);
        let output = run(&["setup", "catalog", "--root", root.to_str().unwrap()]);
        assert_eq!(
            output.status.code(),
            Some(0),
            "fixture {fixture} did not exit 0"
        );
        let after = snapshot(&root);
        assert_eq!(
            before, after,
            "fixture {fixture} was modified by setup catalog"
        );
        assert!(!root.join(".etherfence").exists());
    }
}

fn snapshot(root: &std::path::Path) -> Vec<(PathBuf, u64)> {
    fn walk(dir: &std::path::Path, out: &mut Vec<(PathBuf, u64)>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if let Ok(metadata) = entry.metadata() {
                out.push((path, metadata.len()));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, &mut out);
    out.sort();
    out
}
