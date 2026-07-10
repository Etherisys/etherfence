use serde_json::Value;
use std::collections::HashSet;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

// Keeps docs/ci.md, docs/examples/ci/, and docs/examples/workflows/ from
// silently drifting away from the CLI they document.

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn temp_file(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "etherfence-ci-examples-{name}-{}-{nanos}.json",
        std::process::id()
    ))
}

fn run_in_repo_root(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_etherfence"))
        .current_dir(repo_root())
        .args(args)
        .output()
        .expect("run etherfence")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

const REQUEST_ALLOWED_TOOL_CALL: &str =
    include_str!("../../../docs/examples/ci/requests/allowed-tool-call.json");
const REQUEST_DENIED_TOOL_CALL: &str =
    include_str!("../../../docs/examples/ci/requests/denied-tool-call.json");
const REQUEST_DENIED_PATH_TOOL_CALL: &str =
    include_str!("../../../docs/examples/ci/requests/denied-path-tool-call.json");

const WORKFLOW_FILES: &[(&str, &str)] = &[
    (
        "scan-gate.yml",
        include_str!("../../../docs/examples/workflows/scan-gate.yml"),
    ),
    (
        "scan-baseline.yml",
        include_str!("../../../docs/examples/workflows/scan-baseline.yml"),
    ),
    (
        "scan-sarif-upload.yml",
        include_str!("../../../docs/examples/workflows/scan-sarif-upload.yml"),
    ),
    (
        "mcp-policy-gate.yml",
        include_str!("../../../docs/examples/workflows/mcp-policy-gate.yml"),
    ),
    (
        "pr-security-gate.yml",
        include_str!("../../../docs/examples/workflows/pr-security-gate.yml"),
    ),
];

#[test]
fn ci_example_scan_policy_parses() {
    let content = include_str!("../../../docs/examples/ci/scan-policy.toml");
    let policy = etherfence_policy::parse_policy(content).expect("ci scan policy should parse");
    assert_eq!(policy.schema_version, "ef-policy/v0.1");
    assert_eq!(policy.name, "ci-team-gate");
}

#[test]
fn ci_example_mcp_policy_parses() {
    let content = include_str!("../../../docs/examples/ci/mcp-policy.toml");
    let policy = etherfence_mcp::parse_mcp_policy(content).expect("ci mcp policy should parse");
    assert_eq!(policy.schema_version, "ef-mcp-policy/v0.1");
    assert_eq!(policy.name, "ci-team-gate");
}

#[test]
fn ci_example_json_rpc_requests_are_valid_json() {
    for (name, content) in [
        ("allowed-tool-call", REQUEST_ALLOWED_TOOL_CALL),
        ("denied-tool-call", REQUEST_DENIED_TOOL_CALL),
        ("denied-path-tool-call", REQUEST_DENIED_PATH_TOOL_CALL),
    ] {
        let value: Value = serde_json::from_str(content)
            .unwrap_or_else(|error| panic!("{name} request should be valid JSON: {error}"));
        assert_eq!(value["jsonrpc"], "2.0");
        assert_eq!(value["method"], "tools/call");
    }
}

#[test]
fn ci_mcp_policy_check_examples_produce_documented_decisions() {
    let policy =
        etherfence_mcp::parse_mcp_policy(include_str!("../../../docs/examples/ci/mcp-policy.toml"))
            .expect("ci mcp policy should parse");

    for (name, request, expect_allowed) in [
        ("allowed-tool-call", REQUEST_ALLOWED_TOOL_CALL, true),
        ("denied-tool-call", REQUEST_DENIED_TOOL_CALL, false),
        (
            "denied-path-tool-call",
            REQUEST_DENIED_PATH_TOOL_CALL,
            false,
        ),
    ] {
        let outcome = etherfence_mcp::dry_run_check(
            &policy,
            "default",
            etherfence_mcp::MethodDirection::ClientToServer,
            request,
        );
        assert_eq!(
            outcome.allowed, expect_allowed,
            "unexpected decision for {name}: {outcome:?}"
        );
    }
}

#[test]
fn ci_mcp_policy_cli_commands_from_docs_succeed() {
    let validate =
        run_in_repo_root(&["mcp-policy", "validate", "docs/examples/ci/mcp-policy.toml"]);
    assert!(validate.status.success(), "stderr: {}", stderr(&validate));

    let explain = run_in_repo_root(&["mcp-policy", "explain", "docs/examples/ci/mcp-policy.toml"]);
    assert!(explain.status.success(), "stderr: {}", stderr(&explain));

    let allowed = run_in_repo_root(&[
        "mcp-policy",
        "check",
        "--policy",
        "docs/examples/ci/mcp-policy.toml",
        "--request",
        "docs/examples/ci/requests/allowed-tool-call.json",
    ]);
    assert!(allowed.status.success(), "stderr: {}", stderr(&allowed));
    assert!(stdout(&allowed).contains("Decision: ALLOW"));

    let denied = run_in_repo_root(&[
        "mcp-policy",
        "check",
        "--policy",
        "docs/examples/ci/mcp-policy.toml",
        "--request",
        "docs/examples/ci/requests/denied-tool-call.json",
    ]);
    assert!(denied.status.success(), "stderr: {}", stderr(&denied));
    assert!(stdout(&denied).contains("Decision: DENY"));
}

#[test]
fn ci_scan_gate_cli_command_from_docs_succeeds_on_repo_root() {
    let output = run_in_repo_root(&[
        "scan",
        "--root",
        ".",
        "--policy",
        "docs/examples/ci/scan-policy.toml",
        "--fail-on",
        "high",
        "--format",
        "human",
    ]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
}

#[test]
fn ci_scan_sarif_cli_command_from_docs_produces_sarif() {
    let output = run_in_repo_root(&[
        "scan",
        "--root",
        ".",
        "--policy",
        "docs/examples/ci/scan-policy.toml",
        "--format",
        "sarif",
    ]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let sarif: Value = serde_json::from_str(&stdout(&output)).expect("valid SARIF JSON");
    assert_eq!(sarif["version"], "2.1.0");
}

#[test]
fn ci_example_baseline_matches_freshly_generated_baseline() {
    let fixture_root = repo_root().join("tests/fixtures/home");
    let temp = temp_file("baseline-regen");
    let output = Command::new(env!("CARGO_BIN_EXE_etherfence"))
        .args([
            "scan",
            "--root",
            fixture_root.to_str().unwrap(),
            "--write-baseline",
            temp.to_str().unwrap(),
        ])
        .output()
        .expect("run scan --write-baseline");
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let regenerated: Value =
        serde_json::from_slice(&std::fs::read(&temp).expect("read regenerated baseline"))
            .expect("regenerated baseline is valid JSON");
    let _ = std::fs::remove_file(&temp);

    let committed: Value =
        serde_json::from_str(include_str!("../../../docs/examples/ci/baseline.json"))
            .expect("committed baseline is valid JSON");

    assert_eq!(
        regenerated, committed,
        "docs/examples/ci/baseline.json is stale; regenerate it with \
         `etherfence scan --root tests/fixtures/home --write-baseline docs/examples/ci/baseline.json`"
    );
}

#[test]
fn ci_example_workflows_parse_as_yaml_with_jobs() {
    for (name, content) in WORKFLOW_FILES {
        let value: serde_yaml::Value = serde_yaml::from_str(content)
            .unwrap_or_else(|error| panic!("{name} should parse as YAML: {error}"));
        let mapping = value
            .as_mapping()
            .unwrap_or_else(|| panic!("{name} should be a YAML mapping"));
        assert!(
            mapping.contains_key("jobs"),
            "{name} should define at least one job"
        );
        assert!(
            mapping.contains_key(serde_yaml::Value::String("on".to_string())),
            "{name} should define a trigger"
        );
    }
}

#[test]
fn ci_example_workflows_reference_existing_files() {
    let root = repo_root();
    for (name, content) in WORKFLOW_FILES {
        let referenced: HashSet<&str> = content
            .split_whitespace()
            .map(|token| token.trim_end_matches(['.', ',', ')', ';']))
            .filter(|token| token.starts_with("docs/examples/") || token.starts_with("tests/"))
            .collect();
        assert!(
            !referenced.is_empty(),
            "{name} should reference at least one checked-in example file"
        );
        for path in referenced {
            assert!(
                root.join(path).exists(),
                "{name} references {path}, which does not exist in the repository"
            );
        }
    }
}

fn workflow_content(name: &str) -> &'static str {
    WORKFLOW_FILES
        .iter()
        .find(|(candidate, _)| *candidate == name)
        .map(|(_, content)| *content)
        .unwrap_or_else(|| panic!("{name} missing from WORKFLOW_FILES"))
}

// `mcp-policy check` exits 0 for both an ALLOW and a DENY decision (it is a
// dry-run/inspection command, not a gate by itself). A workflow step that
// only runs `mcp-policy check` without asserting the printed `Decision:`
// line would still pass CI after an expected DENY silently became an ALLOW.
// These example workflows must grep (or equivalent) for the exact expected
// decision so that regression is actually caught.
#[test]
fn ci_example_workflows_assert_mcp_policy_check_decisions() {
    let mcp_gate = workflow_content("mcp-policy-gate.yml");
    assert!(
        mcp_gate.contains("grep -q '^Decision: ALLOW$'"),
        "mcp-policy-gate.yml should assert the allowed request decides ALLOW, \
         not just run `mcp-policy check`"
    );
    assert!(
        mcp_gate.contains("grep -q '^Decision: DENY$'"),
        "mcp-policy-gate.yml should assert the denied request decides DENY, \
         not just run `mcp-policy check`"
    );

    let pr_gate = workflow_content("pr-security-gate.yml");
    assert!(
        pr_gate.contains("grep -q '^Decision: DENY$'"),
        "pr-security-gate.yml should assert the denied request decides DENY, \
         not just run `mcp-policy check`"
    );

    // Every `mcp-policy check` invocation in these two workflows must be
    // followed somewhere in the same file by a matching decision assertion,
    // so a future edit that adds a new unchecked `check` step is also
    // caught.
    for name in ["mcp-policy-gate.yml", "pr-security-gate.yml"] {
        let content = workflow_content(name);
        let check_steps = content.matches("/etherfence mcp-policy check").count();
        let decision_asserts = content.matches("grep -q '^Decision:").count();
        assert_eq!(
            check_steps, decision_asserts,
            "{name} has {check_steps} `mcp-policy check` invocation(s) but \
             {decision_asserts} `Decision:` grep assertion(s); every check \
             step must assert its expected decision"
        );
    }
}

#[test]
fn ci_docs_reference_valid_subcommands_and_flags() {
    let ci_doc = include_str!("../../../docs/ci.md");
    for expected in [
        "etherfence scan",
        "--fail-on",
        "--fail-on-new",
        "--baseline",
        "--write-baseline",
        "--format sarif",
        "etherfence mcp-policy validate",
        "etherfence mcp-policy explain",
        "etherfence mcp-policy check",
        "--policy",
        "--request",
        "exits `0` for both an `ALLOW` and a `DENY` decision",
        "grep -q '^Decision: DENY$'",
    ] {
        assert!(
            ci_doc.contains(expected),
            "docs/ci.md should document `{expected}`"
        );
    }

    let readme = include_str!("../../../README.md");
    assert!(readme.contains("## CI and team workflow integration"));
    assert!(readme.contains("docs/ci.md"));
    assert!(readme.contains("docs/examples/ci/"));
    assert!(readme.contains("docs/examples/workflows/"));
}
