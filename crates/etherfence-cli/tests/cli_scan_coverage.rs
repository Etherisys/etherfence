use serde_json::Value;
use std::process::Command;

fn fixture_root(name: &str) -> String {
    format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn run(args: &[&str]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_etherfence"));
    command.args(args);
    command.output().expect("run etherfence scan")
}

// ── Protection coverage: JSON (primary format for assertions) ────────

#[test]
fn scan_with_policy_shows_coverage_json() {
    let root = fixture_root("coverage-home");
    let policy = format!("{root}/policy.toml");
    let output = run(&[
        "scan", "--root", &root, "--policy", &policy, "--format", "json",
    ]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");

    let coverage = &json["protection_coverage"];
    assert!(coverage.is_object(), "protection_coverage must be present");

    // With 3 Claude + 2 Cursor + 1 VS Code + 2 Hermes + 1 Tirith = 9 servers
    assert_eq!(coverage["total_servers"], 9);
    assert_eq!(coverage["covered"], 3); // Claude: filesystem+memory, Cursor: filesystem
    assert_eq!(coverage["not_covered"], 2); // Claude: github, Cursor: browser-tools
    assert_eq!(coverage["no_policy_for_agent"], 1); // VS Code: lint
    assert_eq!(coverage["empty_allowlist"], 2); // Hermes: calculator+filesystem
    assert_eq!(coverage["not_applicable"], 1); // Tirith

    let servers = coverage["servers"].as_array().expect("servers array");
    assert_eq!(servers.len(), 9);

    // Tirith server present with not_applicable status
    let tirith: Vec<&Value> = servers.iter().filter(|s| s["agent"] == "tirith").collect();
    assert_eq!(tirith.len(), 1, "Tirith server must be present in coverage");
    assert_eq!(tirith[0]["status"], "not_applicable");
    assert_eq!(tirith[0]["server_name"], "tirith");

    // Spot-check: first server is claude-code/filesystem with covered status
    assert_eq!(servers[0]["agent"], "claude-code");
    assert_eq!(servers[0]["server_name"], "filesystem");
    assert_eq!(servers[0]["status"], "covered");
    assert_eq!(servers[0]["config_path"], "~/.claude.json");
}

// ── No policy → no coverage ──────────────────────────────────────────

#[test]
fn scan_without_policy_no_coverage() {
    let root = fixture_root("coverage-home");
    let output = run(&["scan", "--root", &root, "--format", "json"]);
    assert!(output.status.success());
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert!(
        json.get("protection_coverage").is_none(),
        "protection_coverage must not appear without --policy"
    );

    let human = run(&["scan", "--root", &root]);
    let stdout = String::from_utf8_lossy(&human.stdout);
    assert!(
        !stdout.contains("Protection coverage"),
        "human output must not contain protection coverage without --policy"
    );
}

// ── Coverage counts are internally consistent ────────────────────────

#[test]
fn scan_coverage_counts_add_up() {
    let root = fixture_root("coverage-home");
    let policy = format!("{root}/policy.toml");
    let output = run(&[
        "scan", "--root", &root, "--policy", &policy, "--format", "json",
    ]);
    assert!(output.status.success());
    let json: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    let c = &json["protection_coverage"];

    let total = c["total_servers"].as_u64().unwrap() as usize;
    let covered = c["covered"].as_u64().unwrap() as usize;
    let not_covered = c["not_covered"].as_u64().unwrap() as usize;
    let no_policy = c["no_policy_for_agent"].as_u64().unwrap() as usize;
    let empty = c["empty_allowlist"].as_u64().unwrap() as usize;
    let na = c["not_applicable"].as_u64().unwrap() as usize;

    assert_eq!(
        total,
        covered + not_covered + no_policy + empty + na,
        "total_servers must equal sum of all status counts"
    );
    assert_eq!(c["servers"].as_array().unwrap().len(), total);
}

// ── Deterministic order ──────────────────────────────────────────────

#[test]
fn scan_coverage_deterministic_order() {
    let root = fixture_root("coverage-home");
    let policy = format!("{root}/policy.toml");
    let a = run(&[
        "scan", "--root", &root, "--policy", &policy, "--format", "json",
    ]);
    let b = run(&[
        "scan", "--root", &root, "--policy", &policy, "--format", "json",
    ]);
    let ja: Value = serde_json::from_slice(&a.stdout).unwrap();
    let jb: Value = serde_json::from_slice(&b.stdout).unwrap();
    assert_eq!(ja, jb, "JSON output must be deterministic across runs");

    let servers = ja["protection_coverage"]["servers"].as_array().unwrap();
    let names: Vec<String> = servers
        .iter()
        .map(|s| {
            format!(
                "{}/{}/{}",
                s["agent"].as_str().unwrap(),
                s["config_path"].as_str().unwrap(),
                s["server_name"].as_str().unwrap()
            )
        })
        .collect();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(
        names, sorted,
        "servers must be sorted by (agent, config, name)"
    );
}

// ── Human summary shows coverage ─────────────────────────────────────

#[test]
fn scan_with_policy_shows_coverage_human() {
    let root = fixture_root("coverage-home");
    let policy = format!("{root}/policy.toml");
    let output = run(&["scan", "--root", &root, "--policy", &policy]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Protection coverage"),
        "must have coverage section"
    );
    assert!(stdout.contains("✓ covered"), "must show covered marker");
    assert!(
        stdout.contains("✗ not covered"),
        "must show not covered marker"
    );
    assert!(stdout.contains("~ no policy"), "must show no policy marker");
    assert!(
        stdout.contains("— empty allowlist"),
        "must show empty allowlist marker"
    );
}

// ── Markdown shows coverage table ────────────────────────────────────

#[test]
fn scan_with_policy_shows_coverage_markdown() {
    let root = fixture_root("coverage-home");
    let policy = format!("{root}/policy.toml");
    let output = run(&[
        "scan", "--root", &root, "--policy", &policy, "--format", "markdown",
    ]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("## Protection Coverage"));
    assert!(stdout.contains("| Covered |"));
    assert!(stdout.contains("| Not covered |"));
}

// ── SARIF shows coverage ─────────────────────────────────────────────

#[test]
fn scan_with_policy_shows_coverage_sarif() {
    let root = fixture_root("coverage-home");
    let policy = format!("{root}/policy.toml");
    let output = run(&[
        "scan", "--root", &root, "--policy", &policy, "--format", "sarif",
    ]);
    assert!(output.status.success());
    let sarif: Value = serde_json::from_slice(&output.stdout).expect("valid SARIF");
    let props = &sarif["runs"][0]["properties"];
    assert!(
        props["protectionCoverage"].is_object(),
        "SARIF must have protectionCoverage"
    );
}
