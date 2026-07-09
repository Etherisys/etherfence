use serde_json::Value;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const TEST_POLICY: &str = r#"
schema_version = "ef-mcp-policy/v0.1"
name = "minimal-mcp-boundary"

[tools]
allow = ["github.list_repos", "filesystem.read"]
deny = ["filesystem.read_secret", "shell.run"]
"#;

fn temp_path(name: &str, extension: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "etherfence-mcp-{name}-{}-{nanos}.{extension}",
        std::process::id()
    ))
}

fn write_temp_policy(name: &str, content: &str) -> PathBuf {
    let path = temp_path(name, "toml");
    std::fs::write(&path, content).expect("write temp policy");
    path
}

struct ProxyRun {
    output: std::process::Output,
    server_log: PathBuf,
    audit_log: PathBuf,
}

fn run_proxy_with_input(name: &str, policy_path: &PathBuf, input_lines: &[&str]) -> ProxyRun {
    run_proxy_with_input_for_server(name, policy_path, None, input_lines)
}

fn run_proxy_with_input_for_server(
    name: &str,
    policy_path: &PathBuf,
    server_name: Option<&str>,
    input_lines: &[&str],
) -> ProxyRun {
    let server_log = temp_path(&format!("{name}-server-received"), "jsonl");
    let audit_log = temp_path(&format!("{name}-audit"), "jsonl");
    let mut command = Command::new(env!("CARGO_BIN_EXE_etherfence"));
    command
        .arg("mcp-proxy")
        .arg("--policy")
        .arg(policy_path)
        .arg("--audit-log")
        .arg(&audit_log);
    if let Some(server_name) = server_name {
        command.arg("--server-name").arg(server_name);
    }
    let mut child = command
        .arg("--")
        .arg(env!("CARGO_BIN_EXE_fake-mcp-server"))
        .env("FAKE_MCP_SERVER_LOG", &server_log)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn etherfence mcp-proxy");
    {
        let mut stdin = child.stdin.take().expect("proxy stdin");
        for line in input_lines {
            writeln!(stdin, "{line}").expect("write to proxy stdin");
        }
    }
    let output = child.wait_with_output().expect("wait for proxy");
    ProxyRun {
        output,
        server_log,
        audit_log,
    }
}

fn stdout_json_lines(output: &std::process::Output) -> Vec<Value> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).expect("proxy stdout line is JSON"))
        .collect()
}

fn response_with_id(lines: &[Value], id: u64) -> &Value {
    lines
        .iter()
        .find(|line| line["id"] == id)
        .unwrap_or_else(|| panic!("no response with id {id}"))
}

#[test]
fn proxy_forwards_allowed_calls_and_denies_denied_calls() {
    let policy = write_temp_policy("valid", TEST_POLICY);
    let run = run_proxy_with_input(
        "e2e",
        &policy,
        &[
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"filesystem.read","arguments":{"path":"/home/user/notes.txt"}}}"#,
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"shell.run","arguments":{"command":"env","api_token":"sk-super-secret-value-12345"}}}"#,
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"browser.open","arguments":{}}}"#,
        ],
    );

    assert!(
        run.output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&run.output.stderr)
    );
    let lines = stdout_json_lines(&run.output);

    // Protocol messages that are not tool calls pass through untouched.
    let initialize = response_with_id(&lines, 1);
    assert_eq!(initialize["result"]["echo_method"], "initialize");

    // The allowed tool call reached the server and got a real response.
    let allowed = response_with_id(&lines, 2);
    assert_eq!(allowed["result"]["echo_tool"], "filesystem.read");

    // Denied and default-denied calls got safe JSON-RPC errors from the proxy.
    for (id, tool) in [(3, "shell.run"), (4, "browser.open")] {
        let denied = response_with_id(&lines, id);
        assert_eq!(denied["error"]["code"], -32000);
        assert_eq!(denied["error"]["data"]["tool"], tool);
        assert!(denied.get("result").is_none());
    }

    // The server only ever received the initialize and the allowed call.
    let received = std::fs::read_to_string(&run.server_log).expect("server receive log");
    assert!(received.contains("initialize"));
    assert!(received.contains("filesystem.read"));
    assert!(!received.contains("shell.run"));
    assert!(!received.contains("browser.open"));
    assert!(!received.contains("sk-super-secret-value-12345"));

    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&run.server_log);
    let _ = std::fs::remove_file(&run.audit_log);
}

#[test]
fn proxy_audit_log_records_decisions_without_secret_values() {
    let policy = write_temp_policy("audit", TEST_POLICY);
    let run = run_proxy_with_input(
        "audit",
        &policy,
        &[
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"filesystem.read","arguments":{"path":"/home/user/notes.txt"}}}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"shell.run","arguments":{"api_token":"sk-super-secret-value-12345"}}}"#,
        ],
    );
    assert!(run.output.status.success());

    let audit = std::fs::read_to_string(&run.audit_log).expect("audit log");
    let records: Vec<Value> = audit
        .lines()
        .map(|line| serde_json::from_str(line).expect("audit line is JSON"))
        .collect();
    assert_eq!(records.len(), 2);

    let allow = &records[0];
    assert_eq!(allow["event"], "tool_call_decision");
    assert_eq!(allow["decision"], "allow");
    assert_eq!(allow["tool"], "filesystem.read");
    assert_eq!(allow["policy"], "minimal-mcp-boundary");
    assert_eq!(allow["request_id"], 1);
    assert!(allow["reason"].as_str().unwrap().contains("allow list"));
    assert!(allow["ts"].as_str().unwrap().ends_with('Z'));

    let deny = &records[1];
    assert_eq!(deny["decision"], "deny");
    assert_eq!(deny["tool"], "shell.run");
    assert_eq!(deny["argument_keys"], serde_json::json!(["api_token"]));

    // Argument key names are recorded, argument values never are.
    assert!(audit.contains("api_token"));
    assert!(!audit.contains("sk-super-secret-value-12345"));
    assert!(!audit.contains("/home/user/notes.txt"));

    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&run.server_log);
    let _ = std::fs::remove_file(&run.audit_log);
}

#[test]
fn proxy_filters_tools_list_and_audits_metadata_without_schemas() {
    let policy = write_temp_policy("list-filter", TEST_POLICY);
    let run = run_proxy_with_input(
        "list-filter",
        &policy,
        &[r#"{"jsonrpc":"2.0","id":10,"method":"tools/list","params":{}}"#],
    );
    assert!(
        run.output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&run.output.stderr)
    );

    let lines = stdout_json_lines(&run.output);
    let response = response_with_id(&lines, 10);
    let tools = response["result"]["tools"].as_array().expect("tools array");
    let names: Vec<&str> = tools
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name"))
        .collect();
    assert_eq!(names, vec!["github.list_repos", "filesystem.read"]);
    assert!(!response.to_string().contains("shell.run"));
    assert!(!response.to_string().contains("browser.open"));

    let audit = std::fs::read_to_string(&run.audit_log).expect("audit log");
    let record: Value = serde_json::from_str(audit.lines().next().expect("one audit record"))
        .expect("audit line is JSON");
    assert_eq!(record["event"], "tools_list_filtered");
    assert_eq!(record["server"], "default");
    assert_eq!(record["original_count"], 5);
    assert_eq!(record["filtered_count"], 2);
    assert_eq!(
        record["allowed_tools"],
        serde_json::json!(["filesystem.read", "github.list_repos"])
    );
    assert!(!audit.contains("Secret-bearing schema"));
    assert!(!audit.contains("Run a command"));

    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&run.server_log);
    let _ = std::fs::remove_file(&run.audit_log);
}

#[test]
fn proxy_per_server_policy_changes_tools_list_and_call_decisions() {
    let scoped_policy = r#"
schema_version = "ef-mcp-policy/v0.1"
name = "scoped-mcp-boundary"

[tools]
allow = ["github.list_repos"]

[servers.filesystem.tools]
allow = ["filesystem.read"]
deny = ["github.list_repos"]
"#;
    let policy = write_temp_policy("server-scope", scoped_policy);
    let run = run_proxy_with_input_for_server(
        "server-scope",
        &policy,
        Some("filesystem"),
        &[
            r#"{"jsonrpc":"2.0","id":11,"method":"tools/list","params":{}}"#,
            r#"{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"github.list_repos","arguments":{}}}"#,
            r#"{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"filesystem.read","arguments":{}}}"#,
        ],
    );
    assert!(run.output.status.success());
    let lines = stdout_json_lines(&run.output);
    let list = response_with_id(&lines, 11);
    let tools = list["result"]["tools"].as_array().expect("tools array");
    let names: Vec<&str> = tools
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name"))
        .collect();
    assert_eq!(names, vec!["filesystem.read"]);
    assert_eq!(response_with_id(&lines, 12)["error"]["code"], -32000);
    assert_eq!(
        response_with_id(&lines, 13)["result"]["echo_tool"],
        "filesystem.read"
    );

    let audit = std::fs::read_to_string(&run.audit_log).expect("audit log");
    assert!(audit.contains("\"server\":\"filesystem\""));
    assert!(audit.contains("server-specific policy deny list"));
    assert!(audit.contains("server-specific policy allow list"));

    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&run.server_log);
    let _ = std::fs::remove_file(&run.audit_log);
}

#[test]
fn proxy_denies_json_rpc_batches_without_forwarding() {
    let policy = write_temp_policy("batch", TEST_POLICY);
    let run = run_proxy_with_input(
        "batch",
        &policy,
        &[
            r#"[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"github.list_repos","arguments":{}}}]"#,
        ],
    );
    assert!(
        run.output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&run.output.stderr)
    );

    // The whole batch is answered with a single null-id JSON-RPC error.
    let lines = stdout_json_lines(&run.output);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["id"], Value::Null);
    assert_eq!(lines[0]["error"]["code"], -32000);

    // The batch never reached the server, even though every call inside it
    // names an allow-listed tool.
    let received = std::fs::read_to_string(&run.server_log).unwrap_or_default();
    assert!(!received.contains("github.list_repos"));

    let audit = std::fs::read_to_string(&run.audit_log).expect("audit log");
    let record: Value =
        serde_json::from_str(audit.lines().next().expect("one audit record")).expect("audit JSON");
    assert_eq!(record["event"], "batch_denied");
    assert_eq!(record["decision"], "deny");

    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&run.server_log);
    let _ = std::fs::remove_file(&run.audit_log);
}

#[test]
fn proxy_fails_closed_on_invalid_policy_without_starting_server() {
    let policy = write_temp_policy(
        "invalid",
        &TEST_POLICY.replace("ef-mcp-policy/v0.1", "ef-mcp-policy/v9.9"),
    );
    let run = run_proxy_with_input(
        "invalid",
        &policy,
        &[r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"filesystem.read"}}"#],
    );

    assert_eq!(run.output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&run.output.stderr);
    assert!(stderr.contains("fail closed"), "stderr: {stderr}");
    assert!(stderr.contains("schema_version"), "stderr: {stderr}");
    assert!(run.output.stdout.is_empty());

    // The MCP server was never spawned, so it never received anything.
    assert!(!run.server_log.exists());

    let audit = std::fs::read_to_string(&run.audit_log).expect("audit log");
    let record: Value = serde_json::from_str(audit.lines().next().expect("one audit record"))
        .expect("audit line is JSON");
    assert_eq!(record["event"], "policy_load_error");
    assert_eq!(record["decision"], "policy_error");

    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&run.audit_log);
}

#[test]
fn proxy_fails_closed_on_missing_policy_file() {
    let policy = temp_path("missing-policy", "toml");
    let run = run_proxy_with_input("missing", &policy, &[]);

    assert_eq!(run.output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&run.output.stderr);
    assert!(stderr.contains("fail closed"), "stderr: {stderr}");
    assert!(!run.server_log.exists());

    let _ = std::fs::remove_file(&run.audit_log);
}
