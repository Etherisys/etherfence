use std::collections::HashSet;
use std::path::PathBuf;
use std::process::{Command, Output};

// Keeps README.md and docs/install.md from silently drifting away from the
// CLI, the release artifact names, and the checked-in example files they
// document.

const README: &str = include_str!("../../../README.md");
const INSTALL_DOCS: &str = include_str!("../../../docs/install.md");
const RELEASE_WORKFLOW: &str = include_str!("../../../.github/workflows/release.yml");
const CLI_CARGO_TOML: &str = include_str!("../Cargo.toml");
const CHANGELOG: &str = include_str!("../../../CHANGELOG.md");

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

/// Extracts repo-relative path-like tokens (docs/, examples/, crates/,
/// tests/) referenced in prose/code fences, stripping common Markdown
/// punctuation, and returns the unique set.
fn referenced_repo_paths(content: &str) -> HashSet<String> {
    content
        .split(|c: char| c.is_whitespace() || matches!(c, '`' | '(' | ')' | '[' | ']' | '"'))
        .map(|token| token.trim_end_matches(['.', ',', ';', ':']))
        .filter(|token| {
            token.starts_with("docs/")
                || token.starts_with("examples/")
                || token.starts_with("crates/")
                || token.starts_with("tests/")
        })
        .map(|token| token.to_string())
        .collect()
}

#[test]
fn readme_referenced_paths_exist() {
    let root = repo_root();
    let referenced = referenced_repo_paths(README);
    assert!(
        !referenced.is_empty(),
        "README.md should reference at least one checked-in doc/example path"
    );
    for path in &referenced {
        assert!(
            root.join(path).exists(),
            "README.md references {path}, which does not exist in the repository"
        );
    }
}

#[test]
fn install_docs_referenced_paths_exist() {
    let root = repo_root();
    let referenced = referenced_repo_paths(INSTALL_DOCS);
    assert!(
        !referenced.is_empty(),
        "docs/install.md should reference at least one checked-in path"
    );
    for path in &referenced {
        assert!(
            root.join(path).exists(),
            "docs/install.md references {path}, which does not exist in the repository"
        );
    }
}

#[test]
fn install_docs_artifact_names_match_release_workflow() {
    // The release workflow is the source of truth for artifact/checksum
    // filenames; docs/install.md must reference the exact same names so a
    // future rename in one place is caught by a drift in the other.
    for artifact in [
        "etherfence-linux-x86_64.tar.gz",
        "etherfence-linux-x86_64.tar.gz.sha256",
        "etherfence-windows-x86_64.zip",
        "etherfence-windows-x86_64.zip.sha256",
    ] {
        assert!(
            RELEASE_WORKFLOW.contains(artifact),
            "release.yml should reference artifact {artifact}"
        );
        assert!(
            INSTALL_DOCS.contains(artifact),
            "docs/install.md should document artifact {artifact}"
        );
    }
}

#[test]
fn install_docs_documents_cargo_install_excluding_fixture_binary() {
    assert!(
        INSTALL_DOCS.contains("cargo install --path crates/etherfence-cli --bin etherfence"),
        "docs/install.md should document `cargo install --path crates/etherfence-cli --bin etherfence`"
    );
    // The `--bin etherfence` flag is only meaningful because the crate
    // builds more than one binary; confirm the explicit [[bin]] name still
    // matches and the fake-mcp-server fixture binary still exists.
    assert!(
        CLI_CARGO_TOML.contains("name = \"etherfence\""),
        "crates/etherfence-cli/Cargo.toml should still define a bin named \"etherfence\""
    );
    assert!(
        repo_root()
            .join("crates/etherfence-cli/src/bin/fake-mcp-server.rs")
            .exists(),
        "fake-mcp-server fixture binary should still exist alongside the etherfence bin"
    );
}

#[test]
fn readme_command_snippets_use_valid_subcommands() {
    for expected in [
        "etherfence scan",
        "etherfence policy list",
        "etherfence mcp-policy validate",
        "etherfence mcp-policy explain",
        "etherfence mcp-policy init",
        "etherfence mcp-policy check",
        "etherfence mcp-proxy",
        "--policy-profile",
        "--fail-on",
        "--fail-on-new",
        "--baseline",
        "--format sarif",
        "--server-name",
        "--audit-log",
        "--output",
        "--request",
    ] {
        assert!(
            README.contains(expected),
            "README.md should document `{expected}`"
        );
    }
}

#[test]
fn readme_quickstart_validate_and_check_succeed_with_documented_decision() {
    let validate = run_in_repo_root(&[
        "mcp-policy",
        "validate",
        "examples/policies/mcp-minimal-boundary.toml",
    ]);
    assert!(validate.status.success(), "stderr: {}", stderr(&validate));

    let check = run_in_repo_root(&[
        "mcp-policy",
        "check",
        "--policy",
        "examples/policies/mcp-minimal-boundary.toml",
        "--request",
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"filesystem.read","arguments":{}}}"#,
    ]);
    assert!(check.status.success(), "stderr: {}", stderr(&check));
    assert!(
        stdout(&check).contains("Decision: ALLOW"),
        "README quickstart request should decide ALLOW: {}",
        stdout(&check)
    );
}

#[test]
fn readme_mcp_policy_example_init_validate_explain_check_succeed() {
    let temp = std::env::temp_dir().join(format!(
        "etherfence-install-docs-mcp-boundary-{}.toml",
        std::process::id()
    ));
    let init = run_in_repo_root(&[
        "mcp-policy",
        "init",
        "--profile",
        "filesystem-project-readonly-hardened",
        "--output",
        temp.to_str().unwrap(),
        "--overwrite",
    ]);
    assert!(init.status.success(), "stderr: {}", stderr(&init));

    let validate = run_in_repo_root(&["mcp-policy", "validate", temp.to_str().unwrap()]);
    assert!(validate.status.success(), "stderr: {}", stderr(&validate));

    let explain = run_in_repo_root(&["mcp-policy", "explain", temp.to_str().unwrap()]);
    assert!(explain.status.success(), "stderr: {}", stderr(&explain));

    let check = run_in_repo_root(&[
        "mcp-policy",
        "check",
        "--policy",
        temp.to_str().unwrap(),
        "--request",
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"filesystem.read","arguments":{"path":"/home/user/project/README.md"}}}"#,
    ]);
    let _ = std::fs::remove_file(&temp);
    assert!(check.status.success(), "stderr: {}", stderr(&check));
    assert!(
        stdout(&check).contains("Decision: ALLOW"),
        "README mcp-policy example request should decide ALLOW: {}",
        stdout(&check)
    );
}

#[test]
fn installed_version_matches_workspace_version() {
    let output = run_in_repo_root(&["--version"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let expected = format!("etherfence {}\n", env!("CARGO_PKG_VERSION"));
    assert_eq!(stdout(&output), expected);
}

#[test]
fn changelog_and_install_docs_reference_current_version() {
    let version = env!("CARGO_PKG_VERSION");
    let heading = format!("## [{version}]");
    assert!(
        CHANGELOG.contains(&heading),
        "CHANGELOG.md should have a `{heading}` section matching the workspace version"
    );
    assert!(
        INSTALL_DOCS.contains(version),
        "docs/install.md should reference the current version {version}"
    );
}

#[test]
fn readme_does_not_reference_stale_release_workflow_versions() {
    // Regression guard: earlier README revisions hard-coded example release
    // versions (e.g. 0.2.5) in packaging snippets. The current README no
    // longer duplicates versioned packaging steps, so it should not contain
    // any stale `v0.2.x`-style example version left over from a copy/paste.
    assert!(
        !README.contains("v0.2.5"),
        "README.md should not reference the old v0.2.5 packaging example"
    );
}
