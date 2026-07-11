use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::path::Path;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn demo_workspace() -> PathBuf {
    repo_root().join("demo/workspace")
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_etherfence"))
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

fn temp_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "etherfence-demo-{name}-{}-{nanos}",
        std::process::id()
    ))
}

#[cfg(unix)]
fn install_fake_runner(dir: &Path, name: &str, log_path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let runner = dir.join(name);
    fs::write(
        &runner,
        format!(
            "#!/usr/bin/env sh\necho \"{name} executed\" >> '{}'\nexit 99\n",
            log_path.display()
        ),
    )
    .expect("write fake package runner");
    let mut permissions = fs::metadata(&runner)
        .expect("fake runner metadata")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&runner, permissions).expect("chmod fake runner");
}

#[test]
fn demo_workspace_detects_claude_code_filesystem_server_without_executing_runner() {
    let workspace = demo_workspace();
    let tmp = temp_dir("fake-runner");
    let fake_bin = tmp.join("bin");
    fs::create_dir_all(&fake_bin).expect("create fake bin");
    let exec_log = tmp.join("executed.log");
    fs::write(&exec_log, "").expect("create exec log");

    #[cfg(unix)]
    {
        for runner in ["npx", "uvx", "pipx"] {
            install_fake_runner(&fake_bin, runner, &exec_log);
        }
    }

    let mut command = Command::new(env!("CARGO_BIN_EXE_etherfence"));
    command.args(["setup", "detect", "--root"]);
    command.arg(&workspace);
    #[cfg(unix)]
    {
        let old_path = std::env::var_os("PATH").unwrap_or_default();
        let mut paths = vec![fake_bin.clone()];
        paths.extend(std::env::split_paths(&old_path));
        command.env("PATH", std::env::join_paths(paths).expect("join PATH"));
    }
    let output = command.output().expect("run setup detect");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let text = stdout(&output);

    assert!(text.contains("Claude Code [write-supported]"));
    assert!(text.contains("filesystem-server transport=stdio wrapped=false"));
    assert!(text.contains("capabilities: filesystem"));
    assert!(text.contains("starter policy: deny"));
    assert!(text.contains(
        "trust assessment: artifact-identity=known-source configuration-risk=needs-review aggregate=needs-review review-needed=true"
    ));
    assert!(text.contains("EF-TRUST-PIN-001 [medium] package-pinning: Package version is omitted"));
    // The fixture intentionally has no synthetic DEMO_TOKEN env var
    assert!(!text.contains("DEMO_TOKEN"));
    assert!(!text.contains("secret-like"));

    #[cfg(unix)]
    assert_eq!(
        fs::read_to_string(&exec_log).expect("read exec log"),
        "",
        "setup detect must not execute configured package runners"
    );

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn demo_policy_denies_filesystem_write_request() {
    let workspace = demo_workspace();
    let policy = workspace.join("project-readonly.toml");
    let request = workspace.join("request.json");

    let validate = run(&[
        "mcp-policy",
        "validate",
        policy.to_str().expect("policy path is UTF-8"),
    ]);
    assert!(
        validate.status.success(),
        "validate stderr: {}",
        stderr(&validate)
    );
    let validate_text = stdout(&validate);
    assert!(validate_text.contains("name=\"project-readonly\""));
    assert!(validate_text.contains("schema_version=\"ef-mcp-policy/v0.1\""));

    let check = run(&[
        "mcp-policy",
        "check",
        "--policy",
        policy.to_str().expect("policy path is UTF-8"),
        "--request",
        request.to_str().expect("request path is UTF-8"),
    ]);
    assert!(check.status.success(), "check stderr: {}", stderr(&check));
    let text = stdout(&check);

    assert!(text.contains("Decision: DENY"));
    assert!(text.contains("Would be forwarded: no"));
    assert!(text.contains("Inspected by policy: yes"));
    assert!(text.contains("Category: tool_call_decision"));
    assert!(text.contains("Method: tools/call"));
    assert!(text.contains("Tool: filesystem.write"));
    assert!(text.contains("Reason: tool name is in the global policy deny list"));
    assert!(text.contains("No MCP server was started or contacted and no tool was executed."));
}
