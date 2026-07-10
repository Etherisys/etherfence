use std::collections::HashSet;
use std::path::PathBuf;
use std::process::{Command, Output};

// Keeps docs/mcp-proxy-operator-guide.md from silently drifting away from
// the checked-in example policies/config templates it documents, and keeps
// README.md linked to it.

const README: &str = include_str!("../../../README.md");
const OPERATOR_GUIDE: &str = include_str!("../../../docs/mcp-proxy-operator-guide.md");

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
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

/// Extracts repo-relative path-like tokens referenced in prose/code fences,
/// including `../`-prefixed links (this doc lives under `docs/`), stripping
/// common Markdown punctuation, and returns the unique set normalized to be
/// relative to the repo root.
fn referenced_repo_paths(content: &str) -> HashSet<String> {
    content
        .split(|c: char| c.is_whitespace() || matches!(c, '`' | '(' | ')' | '[' | ']' | '"'))
        .map(|token| token.trim_end_matches(['.', ',', ';', ':']))
        .filter_map(|token| {
            if let Some(rest) = token.strip_prefix("../") {
                if rest.starts_with("docs/") || rest.starts_with("examples/") || rest == "README.md"
                {
                    return Some(rest.to_string());
                }
                return None;
            }
            if token.starts_with("docs/")
                || token.starts_with("examples/")
                || token.starts_with("crates/")
                || token.starts_with("tests/")
            {
                return Some(token.to_string());
            }
            None
        })
        .collect()
}

#[test]
fn operator_guide_referenced_paths_exist() {
    let root = repo_root();
    let referenced = referenced_repo_paths(OPERATOR_GUIDE);
    assert!(
        !referenced.is_empty(),
        "docs/mcp-proxy-operator-guide.md should reference at least one checked-in path"
    );
    for path in &referenced {
        // The guide lives under docs/, so a bare `examples/...`-style token
        // may be a real relative link href resolved against the guide's own
        // directory (e.g. `examples/mcp-client-generic-linux.json` meaning
        // `docs/examples/mcp-client-generic-linux.json`), in addition to the
        // repo-root-relative prose convention used elsewhere in this repo's
        // docs. Accept either resolution.
        let resolves = root.join(path).exists() || root.join("docs").join(path).exists();
        assert!(
            resolves,
            "docs/mcp-proxy-operator-guide.md references {path}, which does not exist \
             at the repo root or under docs/"
        );
    }
}

#[test]
fn operator_guide_config_examples_use_checked_policies() {
    for (name, content) in [
        (
            "filesystem-readonly",
            include_str!("../../../examples/policies/mcp-filesystem-readonly.toml"),
        ),
        (
            "filesystem-project-readonly-hardened",
            include_str!(
                "../../../examples/policies/mcp-filesystem-project-readonly-hardened.toml"
            ),
        ),
        (
            "memory-notes-readonly",
            include_str!("../../../examples/policies/mcp-memory-notes-readonly.toml"),
        ),
    ] {
        let policy = etherfence_mcp::parse_mcp_policy(content).unwrap_or_else(|error| {
            panic!("{name} policy referenced by the operator guide should parse: {error}")
        });
        assert_eq!(policy.schema_version, "ef-mcp-policy/v0.1");
    }
}

#[test]
fn operator_guide_check_examples_produce_documented_decisions() {
    // Mirrors the exact `mcp-policy check` invocations shown in
    // docs/mcp-proxy-operator-guide.md, so the documented output can never
    // silently drift from what the CLI actually decides.
    let allowed_filesystem = run_in_repo_root(&[
        "mcp-policy",
        "check",
        "--policy",
        "examples/policies/mcp-filesystem-readonly.toml",
        "--server-name",
        "filesystem",
        "--request",
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"filesystem.read","arguments":{"path":"/home/user/notes.txt"}}}"#,
    ]);
    assert!(
        allowed_filesystem.status.success(),
        "stderr: {}",
        stderr(&allowed_filesystem)
    );
    let out = stdout(&allowed_filesystem);
    assert!(out.contains("Decision: ALLOW"), "{out}");
    assert!(
        out.contains("tool name is in the server-specific policy allow list for filesystem"),
        "{out}"
    );

    let denied_filesystem = run_in_repo_root(&[
        "mcp-policy",
        "check",
        "--policy",
        "examples/policies/mcp-filesystem-readonly.toml",
        "--server-name",
        "filesystem",
        "--request",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"filesystem.write","arguments":{"path":"/home/user/notes.txt"}}}"#,
    ]);
    assert!(
        denied_filesystem.status.success(),
        "stderr: {}",
        stderr(&denied_filesystem)
    );
    let out = stdout(&denied_filesystem);
    assert!(out.contains("Decision: DENY"), "{out}");
    assert!(
        out.contains("tool name is in the global policy deny list"),
        "{out}"
    );

    let allowed_memory = run_in_repo_root(&[
        "mcp-policy",
        "check",
        "--policy",
        "examples/policies/mcp-memory-notes-readonly.toml",
        "--server-name",
        "memory",
        "--request",
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"memory.read_graph","arguments":{}}}"#,
    ]);
    assert!(
        allowed_memory.status.success(),
        "stderr: {}",
        stderr(&allowed_memory)
    );
    assert!(stdout(&allowed_memory).contains("Decision: ALLOW"));

    let denied_memory = run_in_repo_root(&[
        "mcp-policy",
        "check",
        "--policy",
        "examples/policies/mcp-memory-notes-readonly.toml",
        "--server-name",
        "memory",
        "--request",
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"memory.delete_entities","arguments":{}}}"#,
    ]);
    assert!(
        denied_memory.status.success(),
        "stderr: {}",
        stderr(&denied_memory)
    );
    assert!(stdout(&denied_memory).contains("Decision: DENY"));
}

#[test]
fn operator_guide_policy_error_example_exits_with_documented_code() {
    // Mirrors the "fail closed" failure-mode row in the operator guide and
    // docs/release-checklist.md's smoke check.
    let output = run_in_repo_root(&["mcp-proxy", "--policy", "/nonexistent.toml", "--", "true"]);
    assert_eq!(output.status.code(), Some(2), "stderr: {}", stderr(&output));
}

#[test]
fn readme_links_to_operator_guide() {
    assert!(
        README.contains("docs/mcp-proxy-operator-guide.md"),
        "README.md should link to docs/mcp-proxy-operator-guide.md"
    );
}

#[test]
fn readme_example_policy_count_matches_checked_in_policies() {
    let policies_dir = repo_root().join("examples/policies");
    let mcp_policy_count = std::fs::read_dir(&policies_dir)
        .expect("read examples/policies directory")
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            name.starts_with("mcp-") && name.ends_with(".toml")
        })
        .count();

    let word = match mcp_policy_count {
        10 => "Ten",
        11 => "Eleven",
        12 => "Twelve",
        13 => "Thirteen",
        14 => "Fourteen",
        15 => "Fifteen",
        other => panic!(
            "add a number-word mapping for {other} checked-in MCP example policies, \
             then update README.md's stated count to match"
        ),
    };
    let expected = format!("{word} checked-in example policies");
    assert!(
        README.contains(&expected),
        "README.md should state \"{expected}\" to match the {mcp_policy_count} \
         mcp-*.toml files under examples/policies/ (found: {mcp_policy_count})"
    );
}
