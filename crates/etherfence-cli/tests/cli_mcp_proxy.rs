use serde_json::Value;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const TEST_POLICY: &str = r#"
schema_version = "ef-mcp-policy/v0.1"
name = "minimal-mcp-boundary"

[tools]
allow = ["github.list_repos", "filesystem.read"]
deny = ["filesystem.read_secret", "shell.run"]
"#;

const COMPAT_POLICY: &str = r#"
schema_version = "ef-mcp-policy/v0.1"
name = "compat-mcp-boundary"

[tools]
allow = ["compat.allowed", "compat.server_error"]
deny = ["compat.denied"]
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
    let server_command = vec![env!("CARGO_BIN_EXE_fake-mcp-server").to_string()];
    run_proxy_with_command_for_server(
        policy_path,
        server_name,
        input_lines,
        &server_command,
        Some((&server_log, "FAKE_MCP_SERVER_LOG")),
        &audit_log,
    )
}

fn run_proxy_with_input_delay_before_close(
    name: &str,
    policy_path: &PathBuf,
    input_lines: &[&str],
    delay: Duration,
) -> ProxyRun {
    let server_log = temp_path(&format!("{name}-server-received"), "jsonl");
    let audit_log = temp_path(&format!("{name}-audit"), "jsonl");
    let server_command = vec![env!("CARGO_BIN_EXE_fake-mcp-server").to_string()];
    let mut command = Command::new(env!("CARGO_BIN_EXE_etherfence"));
    command
        .arg("mcp-proxy")
        .arg("--policy")
        .arg(policy_path)
        .arg("--audit-log")
        .arg(&audit_log)
        .env("FAKE_MCP_SERVER_LOG", &server_log)
        .arg("--")
        .args(&server_command);
    let mut child = command
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
        stdin.flush().expect("flush proxy stdin");
        std::thread::sleep(delay);
    }
    let output = child.wait_with_output().expect("wait for proxy");
    ProxyRun {
        output,
        server_log,
        audit_log,
    }
}

fn run_proxy_with_command_for_server(
    policy_path: &PathBuf,
    server_name: Option<&str>,
    input_lines: &[&str],
    server_command: &[String],
    server_log_env: Option<(&PathBuf, &str)>,
    audit_log: &PathBuf,
) -> ProxyRun {
    let server_log = server_log_env
        .map(|(path, _)| path.clone())
        .unwrap_or_else(|| temp_path("real-server-received", "jsonl"));
    let mut command = Command::new(env!("CARGO_BIN_EXE_etherfence"));
    command
        .arg("mcp-proxy")
        .arg("--policy")
        .arg(policy_path)
        .arg("--audit-log")
        .arg(audit_log);
    if let Some(server_name) = server_name {
        command.arg("--server-name").arg(server_name);
    }
    if let Some((path, env_name)) = server_log_env {
        command.env(env_name, path);
    }
    let mut child = command
        .arg("--")
        .args(server_command)
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
        audit_log: audit_log.clone(),
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
    let records: Vec<Value> = audit
        .lines()
        .map(|line| serde_json::from_str(line).expect("audit line is JSON"))
        .collect();
    // v0.3.0: the first audit record is a method_decision (allow tools/list).
    assert_eq!(records[0]["event"], "method_decision");
    assert_eq!(records[0]["method"], "tools/list");
    assert_eq!(records[0]["decision"], "allow");
    // The tools_list_filtered record follows.
    let filter_record = records
        .iter()
        .find(|r| r["event"] == "tools_list_filtered")
        .expect("tools_list_filtered record");
    assert_eq!(filter_record["server"], "default");
    assert_eq!(filter_record["original_count"], 9);
    assert_eq!(filter_record["filtered_count"], 2);
    assert_eq!(
        filter_record["allowed_tools"],
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

#[test]
fn proxy_compatibility_sequence_matches_realistic_mcp_stdio_flow() {
    let policy = write_temp_policy("compat", COMPAT_POLICY);
    let run = run_proxy_with_input(
        "compat",
        &policy,
        &[
            r#"{"jsonrpc":"2.0","id":"init-1","method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"etherfence-test-client","version":"0.0.0"}}}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#,
            r#"{"jsonrpc":"2.0","id":"list-1","method":"tools/list","params":{}}"#,
            r#"{"jsonrpc":"2.0","id":"call-allowed","method":"tools/call","params":{"name":"compat.allowed","arguments":{"path":"/tmp/example.txt"}}}"#,
            r#"{"jsonrpc":"2.0","id":"call-denied","method":"tools/call","params":{"name":"compat.denied","arguments":{"secret":"do-not-log"}}}"#,
            r#"{"jsonrpc":"2.0","id":"call-error","method":"tools/call","params":{"name":"compat.server_error","arguments":{}}}"#,
            r#"[{"jsonrpc":"2.0","id":"batch-1","method":"tools/call","params":{"name":"compat.allowed","arguments":{}}}]"#,
        ],
    );
    assert!(
        run.output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&run.output.stderr)
    );
    let lines = stdout_json_lines(&run.output);

    let initialize = lines
        .iter()
        .find(|line| line["id"] == "init-1")
        .expect("initialize response id preserved");
    assert_eq!(
        initialize["result"]["serverInfo"]["name"],
        "etherfence-compat-fixture"
    );

    let list = lines
        .iter()
        .find(|line| line["id"] == "list-1")
        .expect("tools/list response id preserved");
    let tool_names: Vec<&str> = list["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name"))
        .collect();
    assert_eq!(tool_names, vec!["compat.allowed", "compat.server_error"]);

    assert_eq!(
        lines
            .iter()
            .find(|line| line["id"] == "call-allowed")
            .expect("allowed call response")["result"]["echo_tool"],
        "compat.allowed"
    );
    assert_eq!(
        lines
            .iter()
            .find(|line| line["id"] == "call-denied")
            .expect("denied call response")["error"]["code"],
        -32000
    );
    assert_eq!(
        lines
            .iter()
            .find(|line| line["id"] == "call-error")
            .expect("server error response")["error"]["code"],
        -32042
    );
    assert!(lines.iter().any(|line| line["id"] == Value::Null
        && line["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("batch"))));

    let received = std::fs::read_to_string(&run.server_log).expect("server receive log");
    assert!(received.contains("initialize"));
    assert!(received.contains("notifications/initialized"));
    assert!(received.contains("tools/list"));
    assert!(received.contains("compat.allowed"));
    assert!(received.contains("compat.server_error"));
    assert!(!received.contains("compat.denied"));
    assert!(!received.contains("batch-1"));
    assert!(!received.contains("do-not-log"));

    let audit = std::fs::read_to_string(&run.audit_log).expect("audit log");
    assert!(audit.contains("tools_list_filtered"));
    assert!(audit.contains("compat.allowed"));
    assert!(audit.contains("compat.server_error"));
    assert!(!audit.contains("do-not-log"));

    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&run.server_log);
    let _ = std::fs::remove_file(&run.audit_log);
}

#[test]
fn proxy_passes_through_tracked_tools_list_server_errors() {
    let policy = write_temp_policy("list-error", COMPAT_POLICY);
    let run = run_proxy_with_input(
        "list-error",
        &policy,
        &[
            r#"{"jsonrpc":"2.0","id":"list-error-1","method":"tools/list","params":{"fixture":"error"}}"#,
        ],
    );
    assert!(run.output.status.success());
    let lines = stdout_json_lines(&run.output);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["id"], "list-error-1");
    assert_eq!(lines[0]["error"]["code"], -32603);

    let audit = std::fs::read_to_string(&run.audit_log).unwrap_or_default();
    assert!(!audit.contains("tools_list_filtered"));

    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&run.server_log);
    let _ = std::fs::remove_file(&run.audit_log);
}

#[test]
fn proxy_handles_malformed_tools_list_fixture_fail_safe() {
    let policy = write_temp_policy("list-malformed", COMPAT_POLICY);
    let run = run_proxy_with_input(
        "list-malformed",
        &policy,
        &[
            r#"{"jsonrpc":"2.0","id":"weird-list-1","method":"tools/list","params":{"fixture":"weird"}}"#,
        ],
    );
    assert!(run.output.status.success());
    let lines = stdout_json_lines(&run.output);
    assert_eq!(lines[0]["id"], "weird-list-1");
    assert_eq!(lines[0]["result"]["tools"], serde_json::json!([]));

    let audit = std::fs::read_to_string(&run.audit_log).expect("audit log");
    assert!(audit.contains("fail safe"));

    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&run.server_log);
    let _ = std::fs::remove_file(&run.audit_log);
}

const SERVER_TO_CLIENT_POLICY: &str = r#"
schema_version = "ef-mcp-policy/v0.1"
name = "server-to-client-test"

[methods]
allow = [
  "initialize",
  "tools/list",
  "tools/call",
  "fixture/server_sampling",
  "fixture/server_roots",
  "fixture/server_elicitation_notification",
  "fixture/server_batch",
]
deny = ["sampling/createMessage", "elicitation/create"]

[tools]
allow = ["filesystem.read"]
"#;

const SERVER_TO_CLIENT_ALLOW_ROOTS_POLICY: &str = r#"
schema_version = "ef-mcp-policy/v0.1"
name = "server-to-client-allow-roots"

[methods]
allow = [
  "initialize",
  "fixture/server_roots",
  "roots/list",
]
deny = ["sampling/createMessage", "elicitation/create"]
"#;

const PATH_GUARD_POLICY: &str = r#"
schema_version = "ef-mcp-policy/v0.1"
name = "path-guard-test"

[methods]
allow = ["tools/list", "tools/call", "resources/read"]

[tools]
allow = ["filesystem.read"]

[path_rules.project_readonly]
allow_roots = ["/home/user/project"]
deny_roots = ["/home/user/project/.git", "/home/user/project/secrets"]

[tools."filesystem.read".arguments]
path_keys = ["path"]
path_rule = "project_readonly"

[methods."resources/read".params]
uri_keys = ["uri"]
path_rule = "project_readonly"
"#;

#[test]
fn proxy_denies_server_to_client_sampling_before_client_and_answers_server() {
    let policy = write_temp_policy("server-sampling", SERVER_TO_CLIENT_POLICY);
    let run = run_proxy_with_input_delay_before_close(
        "server-sampling",
        &policy,
        &[
            r#"{"jsonrpc":"2.0","id":1,"method":"fixture/server_sampling","params":{}}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}"#,
        ],
        Duration::from_millis(50),
    );
    assert!(
        run.output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&run.output.stderr)
    );
    let stdout = String::from_utf8_lossy(&run.output.stdout);
    assert!(
        !stdout.contains("sampling/createMessage"),
        "denied server→client sampling must not reach client stdout: {stdout}"
    );
    assert!(!stdout.contains("secret prompt text from server"));

    let received = std::fs::read_to_string(&run.server_log).expect("server log");
    assert!(received.contains("fixture/server_sampling"));
    assert!(
        received.contains("EtherFence MCP proxy denied this method by policy"),
        "server should receive JSON-RPC denial response: {received}"
    );
    assert!(received.contains("server-sampling-1"));
    assert!(!received.contains("secret prompt text from server"));

    let audit = std::fs::read_to_string(&run.audit_log).expect("audit log");
    assert!(audit.contains("\"direction\":\"server_to_client\""));
    assert!(audit.contains("\"sampling/createMessage\""));
    assert!(audit.contains("\"param_keys\":[\"messages\"]"));
    assert!(!audit.contains("secret prompt text from server"));

    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&run.server_log);
    let _ = std::fs::remove_file(&run.audit_log);
}

#[test]
fn proxy_forwards_allowed_server_to_client_roots_request() {
    let policy = write_temp_policy("server-roots", SERVER_TO_CLIENT_ALLOW_ROOTS_POLICY);
    let run = run_proxy_with_input(
        "server-roots",
        &policy,
        &[r#"{"jsonrpc":"2.0","id":1,"method":"fixture/server_roots","params":{}}"#],
    );
    assert!(
        run.output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&run.output.stderr)
    );
    let lines = stdout_json_lines(&run.output);
    assert!(
        lines
            .iter()
            .any(|line| line["id"] == "server-roots-1" && line["method"] == "roots/list"),
        "allowed roots/list request should reach client stdout: {}",
        String::from_utf8_lossy(&run.output.stdout)
    );

    let audit = std::fs::read_to_string(&run.audit_log).expect("audit log");
    assert!(audit.contains("\"direction\":\"server_to_client\""));
    assert!(audit.contains("\"roots/list\""));
    assert!(audit.contains("\"allow\""));
    assert!(!audit.contains("secret cursor"));

    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&run.server_log);
    let _ = std::fs::remove_file(&run.audit_log);
}

#[test]
fn proxy_drops_denied_server_to_client_notification_and_audits() {
    let policy = write_temp_policy("server-notification", SERVER_TO_CLIENT_POLICY);
    let run = run_proxy_with_input(
        "server-notification",
        &policy,
        &[
            r#"{"jsonrpc":"2.0","id":1,"method":"fixture/server_elicitation_notification","params":{}}"#,
        ],
    );
    assert!(
        run.output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&run.output.stderr)
    );
    let stdout = String::from_utf8_lossy(&run.output.stdout);
    assert!(!stdout.contains("elicitation/create"));
    assert!(!stdout.contains("secret notification body"));

    let received = std::fs::read_to_string(&run.server_log).expect("server log");
    assert!(!received.contains("EtherFence MCP proxy denied this method by policy"));

    let audit = std::fs::read_to_string(&run.audit_log).expect("audit log");
    assert!(audit.contains("\"direction\":\"server_to_client\""));
    assert!(audit.contains("\"elicitation/create\""));
    assert!(audit.contains("\"request_id_type\":\"missing\""));
    assert!(audit.contains("\"param_keys\":[\"message\"]"));
    assert!(!audit.contains("secret notification body"));

    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&run.server_log);
    let _ = std::fs::remove_file(&run.audit_log);
}

#[test]
fn proxy_denies_server_to_client_batch_fail_closed() {
    let policy = write_temp_policy("server-batch", SERVER_TO_CLIENT_POLICY);
    let run = run_proxy_with_input(
        "server-batch",
        &policy,
        &[r#"{"jsonrpc":"2.0","id":1,"method":"fixture/server_batch","params":{}}"#],
    );
    assert!(
        run.output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&run.output.stderr)
    );
    let stdout = String::from_utf8_lossy(&run.output.stdout);
    assert!(!stdout.contains("server-batch-1"));
    let audit = std::fs::read_to_string(&run.audit_log).expect("audit log");
    assert!(audit.contains("\"event\":\"batch_denied\""));
    assert!(audit.contains("\"direction\":\"server_to_client\""));

    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&run.server_log);
    let _ = std::fs::remove_file(&run.audit_log);
}

#[test]
fn proxy_path_guard_allows_configured_tool_path_under_root() {
    let policy = write_temp_policy("path-allow", PATH_GUARD_POLICY);
    let run = run_proxy_with_input(
        "path-allow",
        &policy,
        &[
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"filesystem.read","arguments":{"path":"/home/user/project/docs/readme.md"}}}"#,
        ],
    );
    assert!(
        run.output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&run.output.stderr)
    );
    let lines = stdout_json_lines(&run.output);
    assert_eq!(
        response_with_id(&lines, 1)["result"]["echo_tool"],
        "filesystem.read"
    );
    let audit = std::fs::read_to_string(&run.audit_log).expect("audit log");
    assert!(audit.contains("\"path_rule\":\"project_readonly\""));
    assert!(audit.contains("\"path_key\":\"path\""));
    assert!(audit.contains("\"path_classification\":\"inside_allowed_root\""));
    assert!(!audit.contains("/home/user/project"));

    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&run.server_log);
    let _ = std::fs::remove_file(&run.audit_log);
}

#[test]
fn proxy_path_guard_denies_tool_path_outside_root_without_forwarding() {
    let policy = write_temp_policy("path-deny-outside", PATH_GUARD_POLICY);
    let run = run_proxy_with_input(
        "path-deny-outside",
        &policy,
        &[
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"filesystem.read","arguments":{"path":"/home/user/other/secret.txt"}}}"#,
        ],
    );
    assert!(run.output.status.success());
    let lines = stdout_json_lines(&run.output);
    assert_eq!(response_with_id(&lines, 2)["error"]["code"], -32000);
    let received = std::fs::read_to_string(&run.server_log).unwrap_or_default();
    assert!(!received.contains("/home/user/other"));
    let audit = std::fs::read_to_string(&run.audit_log).expect("audit log");
    assert!(audit.contains("outside_allowed_roots"));
    assert!(!audit.contains("/home/user/other"));

    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&run.server_log);
    let _ = std::fs::remove_file(&run.audit_log);
}

#[test]
fn proxy_path_guard_denies_file_uri_under_denied_root_and_non_file_uri() {
    let policy = write_temp_policy("path-uri", PATH_GUARD_POLICY);
    let run = run_proxy_with_input(
        "path-uri",
        &policy,
        &[
            r#"{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"file:///home/user/project/secrets/token.txt"}}"#,
            r#"{"jsonrpc":"2.0","id":4,"method":"resources/read","params":{"uri":"https://example.invalid/resource"}}"#,
        ],
    );
    assert!(run.output.status.success());
    let lines = stdout_json_lines(&run.output);
    assert_eq!(response_with_id(&lines, 3)["error"]["code"], -32000);
    assert_eq!(response_with_id(&lines, 4)["error"]["code"], -32000);
    let received = std::fs::read_to_string(&run.server_log).unwrap_or_default();
    assert!(!received.contains("resources/read"));
    let audit = std::fs::read_to_string(&run.audit_log).expect("audit log");
    assert!(audit.contains("inside_denied_root"));
    assert!(audit.contains("path_parse_error"));
    assert!(audit.contains("\"path_key\":\"uri\""));
    assert!(!audit.contains("file:///home/user/project/secrets"));
    assert!(!audit.contains("https://example.invalid"));

    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&run.server_log);
    let _ = std::fs::remove_file(&run.audit_log);
}

#[test]
fn proxy_path_guard_denies_bidi_or_zero_width_path_without_logging_raw_value() {
    let policy = write_temp_policy("path-unicode", PATH_GUARD_POLICY);
    let zero_width_uri = format!(
        r#"{{"jsonrpc":"2.0","id":6,"method":"resources/read","params":{{"uri":"file:///home/user/project/{}secret.txt"}}}}"#,
        "\u{200B}"
    );
    let run = run_proxy_with_input(
        "path-unicode",
        &policy,
        &[
            r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"filesystem.read","arguments":{"path":"/home/user/project/\u202esecret.txt"}}}"#,
            zero_width_uri.as_str(),
        ],
    );
    assert!(run.output.status.success());
    let lines = stdout_json_lines(&run.output);
    assert_eq!(response_with_id(&lines, 5)["error"]["code"], -32000);
    assert_eq!(response_with_id(&lines, 6)["error"]["code"], -32000);
    let received = std::fs::read_to_string(&run.server_log).unwrap_or_default();
    assert!(!received.contains("secret.txt"));
    let audit = std::fs::read_to_string(&run.audit_log).expect("audit log");
    assert!(audit.contains("unicode_suspicious_path_value"));
    assert!(audit.contains("\"path_key\":\"path\""));
    assert!(audit.contains("\"path_key\":\"uri\""));
    assert!(!audit.contains("/home/user/project"));
    assert!(!audit.contains("file:///home/user/project"));
    assert!(!audit.contains("secret.txt"));

    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&run.server_log);
    let _ = std::fs::remove_file(&run.audit_log);
}

#[test]
fn real_mcp_command_env_var_must_be_json_array() {
    let err = parse_real_mcp_command("npx -y server").expect_err("plain shell string rejected");
    assert!(err.contains("JSON array"));
    let parsed = parse_real_mcp_command(r#"["/usr/bin/env","true"]"#).expect("json argv");
    assert_eq!(parsed, vec!["/usr/bin/env", "true"]);
}

#[test]
fn optional_real_mcp_stdio_smoke_test() {
    let Some(command_json) = std::env::var_os("ETHERFENCE_REAL_MCP_CMD") else {
        eprintln!("skipping real MCP stdio smoke test: ETHERFENCE_REAL_MCP_CMD is not set");
        return;
    };
    let command_json = command_json
        .into_string()
        .expect("ETHERFENCE_REAL_MCP_CMD must be valid UTF-8 JSON");
    let server_command =
        parse_real_mcp_command(&command_json).expect("ETHERFENCE_REAL_MCP_CMD JSON argv array");
    // Optional maintainer-supplied policy path. Falls back to the deterministic
    // compatibility policy used by the fake-server tests so this smoke test
    // does not require a second env var to run. Only the fallback temp file is
    // ever deleted; a maintainer-supplied policy path is left untouched.
    let (policy, temp_policy) = match std::env::var_os("ETHERFENCE_REAL_MCP_POLICY") {
        Some(policy_path) => (PathBuf::from(policy_path), None),
        None => {
            let temp = write_temp_policy("real-server", COMPAT_POLICY);
            (temp.clone(), Some(temp))
        }
    };
    assert!(
        policy.exists(),
        "ETHERFENCE_REAL_MCP_POLICY path does not exist: {}",
        policy.display()
    );
    let audit_log = temp_path("real-server-audit", "jsonl");
    let run = run_proxy_with_command_for_server(
        &policy,
        Some("real-server"),
        &[
            r#"{"jsonrpc":"2.0","id":"real-init-1","method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"etherfence-real-smoke","version":"0.0.0"}}}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#,
            r#"{"jsonrpc":"2.0","id":"real-list-1","method":"tools/list","params":{}}"#,
        ],
        &server_command,
        None,
        &audit_log,
    );
    assert!(
        run.output.status.success(),
        "real MCP smoke test failed; stderr: {}",
        String::from_utf8_lossy(&run.output.stderr)
    );
    let lines = stdout_json_lines(&run.output);
    assert!(
        lines.iter().any(|line| line["id"] == "real-init-1"),
        "real server did not return initialize response; stdout: {}",
        String::from_utf8_lossy(&run.output.stdout)
    );

    if let Some(temp_policy) = temp_policy {
        let _ = std::fs::remove_file(&temp_policy);
    }
    let _ = std::fs::remove_file(&run.audit_log);
}

#[test]
fn proxy_emits_tracking_removed_audit_after_tools_list() {
    let policy = write_temp_policy("tracking-removed", TEST_POLICY);
    let run = run_proxy_with_input(
        "tracking-removed",
        &policy,
        &[r#"{"jsonrpc":"2.0","id":10,"method":"tools/list","params":{}}"#],
    );
    assert!(
        run.output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&run.output.stderr)
    );

    let audit = std::fs::read_to_string(&run.audit_log).expect("audit log");
    let records: Vec<Value> = audit
        .lines()
        .map(|line| serde_json::from_str(line).expect("audit line is JSON"))
        .collect();
    assert!(
        records.iter().any(|r| r["event"] == "tools_list_filtered"),
        "expected tools_list_filtered record"
    );
    let removed = records
        .iter()
        .find(|r| r["event"] == "tools_list_tracking_removed")
        .expect("expected tools_list_tracking_removed record after tracked response");
    assert_eq!(removed["method"], "tools/list");
    assert!(removed["request_id"].is_null());
    assert!(removed["reason"].as_str().unwrap().contains("cleared"));

    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&run.server_log);
    let _ = std::fs::remove_file(&run.audit_log);
}

#[test]
fn proxy_filters_duplicate_in_flight_tools_list_ids() {
    let policy = write_temp_policy("dup-ids", TEST_POLICY);
    // Two tools/list requests reuse the same id before either response is
    // processed. The proxy reference-counts the tracked entry, so both
    // server answers must be filtered (the first must not orphan the second)
    // and, after both are handled, tracking must be empty so a later unrelated
    // result under the same id passes through unchanged (no leak / no reshape).
    let run = run_proxy_with_input(
        "dup-ids",
        &policy,
        &[
            r#"{"jsonrpc":"2.0","id":"dup","method":"tools/list","params":{}}"#,
            r#"{"jsonrpc":"2.0","id":"dup","method":"tools/list","params":{}}"#,
        ],
    );
    assert!(
        run.output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&run.output.stderr)
    );
    let lines = stdout_json_lines(&run.output);
    let responses: Vec<&Value> = lines
        .iter()
        .filter(|line| {
            line.get("id").and_then(Value::as_str) == Some("dup") && line.get("result").is_some()
        })
        .collect();
    assert_eq!(
        responses.len(),
        2,
        "both duplicate-id responses must appear"
    );
    let filtered: Vec<&Value> = responses
        .iter()
        .filter(|line| {
            line.get("result")
                .and_then(|r| r.get("tools"))
                .map(|tools| tools.is_array())
                .unwrap_or(false)
        })
        .copied()
        .collect();
    assert_eq!(
        filtered.len(),
        2,
        "both duplicate-id tool lists are filtered"
    );
    for response in filtered {
        let tools = response["result"]["tools"].as_array().expect("tools array");
        let names: Vec<&str> = tools
            .iter()
            .map(|tool| tool["name"].as_str().expect("tool name"))
            .collect();
        assert!(!names.contains(&"shell.run"));
        assert!(!names.contains(&"browser.open"));
    }

    let audit = std::fs::read_to_string(&run.audit_log).expect("audit log");
    let count = audit
        .lines()
        .filter(|line| line.contains("tools_list_filtered"))
        .count();
    assert_eq!(count, 2, "two tools_list_filtered audit records");

    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&run.server_log);
    let _ = std::fs::remove_file(&run.audit_log);
}

fn parse_real_mcp_command(value: &str) -> Result<Vec<String>, String> {
    let parsed: Vec<String> = serde_json::from_str(value).map_err(|error| {
        format!(
            "expected ETHERFENCE_REAL_MCP_CMD to be a JSON array of argv strings, not a shell command: {error}"
        )
    })?;
    if parsed.is_empty() || parsed.iter().any(|part| part.is_empty()) {
        return Err("expected ETHERFENCE_REAL_MCP_CMD JSON array to contain a command and optional non-empty arguments".to_string());
    }
    Ok(parsed)
}

/// Run the proxy against the fake server in a specific crash/lifecycle mode so
/// we can assert on child-exit, EOF, and early-exit behavior.
fn run_proxy_with_server_mode(
    name: &str,
    policy: &PathBuf,
    input_lines: &[&str],
    mode: &str,
) -> ProxyRun {
    let server_log = temp_path(&format!("{name}-server-received"), "jsonl");
    let audit_log = temp_path(&format!("{name}-audit"), "jsonl");
    let server_command = vec![env!("CARGO_BIN_EXE_fake-mcp-server").to_string()];
    let mut command = Command::new(env!("CARGO_BIN_EXE_etherfence"));
    command
        .arg("mcp-proxy")
        .arg("--policy")
        .arg(policy)
        .arg("--audit-log")
        .arg(&audit_log)
        .env("FAKE_MCP_SERVER_MODE", mode)
        .env("FAKE_MCP_SERVER_LOG", &server_log)
        .arg("--")
        .args(&server_command);
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn etherfence mcp-proxy");
    {
        let mut stdin = child.stdin.take().expect("proxy stdin");
        for line in input_lines {
            if writeln!(stdin, "{line}").is_err() {
                break;
            }
        }
    }
    let output = child.wait_with_output().expect("wait for proxy");
    ProxyRun {
        output,
        server_log,
        audit_log,
    }
}

#[test]
fn proxy_exits_zero_on_clean_client_eof() {
    // The normal happy path: client sends input, closes stdin, proxy forwards,
    // joins the server pump, reaps the child, and exits 0.
    let policy = write_temp_policy("clean-eof", TEST_POLICY);
    let run = run_proxy_with_input(
        "clean-eof",
        &policy,
        &[
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"filesystem.read","arguments":{"path":"/x"}}}"#,
        ],
    );
    assert!(
        run.output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&run.output.stderr)
    );
    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&run.server_log);
    let _ = std::fs::remove_file(&run.audit_log);
}

#[test]
fn proxy_propagates_child_early_exit_code() {
    // The child server exits before producing output. The proxy must detect
    // the closed stdout, stop forwarding, reap the child, and exit with the
    // child's code (0 here) rather than hanging or panicking.
    let policy = write_temp_policy("early-exit", TEST_POLICY);
    let run = run_proxy_with_server_mode(
        "early-exit",
        &policy,
        &[
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"filesystem.read","arguments":{"path":"/x"}}}"#,
        ],
        "immediate-exit",
    );
    assert!(
        run.output.status.code() == Some(0),
        "expected exit 0 from child early exit, got {:?}; stderr: {}",
        run.output.status.code(),
        String::from_utf8_lossy(&run.output.stderr)
    );
    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&run.server_log);
    let _ = std::fs::remove_file(&run.audit_log);
}

#[test]
fn proxy_handles_child_dropping_mid_handshake() {
    // The child reads the first client line then closes stdout without
    // responding. The proxy must not panic, must not forward the remaining
    // lines to a dead server (broken pipe is a clean shutdown), and must exit
    // with the propagated child code.
    let policy = write_temp_policy("drop-mid", TEST_POLICY);
    let run = run_proxy_with_server_mode(
        "drop-mid",
        &policy,
        &[
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"filesystem.read","arguments":{"path":"/x"}}}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"shell.run","arguments":{}}}"#,
        ],
        "read-one-then-drop",
    );
    // The server received exactly one line (the first), proving the proxy did
    // not forward the second after the child dropped.
    let received = std::fs::read_to_string(&run.server_log).unwrap_or_default();
    assert_eq!(
        received.lines().count(),
        1,
        "child should have received only the first line: {received}"
    );
    assert!(
        run.output.status.code() == Some(0),
        "expected exit 0, got {:?}; stderr: {}",
        run.output.status.code(),
        String::from_utf8_lossy(&run.output.stderr)
    );
    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&run.server_log);
    let _ = std::fs::remove_file(&run.audit_log);
}

#[test]
fn proxy_does_not_forward_invalid_client_json() {
    // A client line that is not valid JSON must be dropped by the proxy and
    // never reach the server.
    let policy = write_temp_policy("invalid-client", TEST_POLICY);
    let run = run_proxy_with_input(
        "invalid-client",
        &policy,
        &[
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"filesystem.read","arguments":{"path":"/x"}}}"#,
            "this line is not json {{{",
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"github.list_repos","arguments":{}}}"#,
        ],
    );
    assert!(
        run.output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&run.output.stderr)
    );
    let received = std::fs::read_to_string(&run.server_log).expect("server receive log");
    assert!(
        !received.contains("this line is not json"),
        "invalid client JSON must not reach the server"
    );
    // The two valid calls still made it through.
    assert!(received.contains("filesystem.read"));
    assert!(received.contains("github.list_repos"));
    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&run.server_log);
    let _ = std::fs::remove_file(&run.audit_log);
}

#[test]
fn proxy_fails_closed_when_audit_log_cannot_be_opened() {
    // Pointing the audit log at a non-writable path must fail closed before the
    // server starts, using the documented internal-error exit code (4) rather
    // than starting a server with no audit trail.
    let policy = write_temp_policy("audit-open-fail", TEST_POLICY);
    // Use a non-existent parent that is itself a regular file, so
    // `create_dir_all` cannot create the audit directory and the open fails.
    let blocking_file = temp_path("audit-block", "txt");
    std::fs::write(&blocking_file, b"block").expect("create blocking file");
    let audit_path = blocking_file.join("audit.jsonl"); // parent is a file
    let server_command = vec![env!("CARGO_BIN_EXE_fake-mcp-server").to_string()];
    let output = Command::new(env!("CARGO_BIN_EXE_etherfence"))
        .arg("mcp-proxy")
        .arg("--policy")
        .arg(&policy)
        .arg("--audit-log")
        .arg(&audit_path)
        .arg("--")
        .args(&server_command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn proxy");
    assert_eq!(
        output.status.code(),
        Some(etherfence_mcp::exit_code::INTERNAL_ERROR),
        "audit open failure should exit {} (got {:?}); stderr: {}",
        etherfence_mcp::exit_code::INTERNAL_ERROR,
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&blocking_file);
}

// --- v0.3.0 method-level policy integration tests ---

const METHOD_POLICY: &str = r#"
schema_version = "ef-mcp-policy/v0.1"
name = "method-level-test"

[methods]
allow = ["tools/list", "tools/call", "resources/list", "resources/read", "prompts/list"]
deny = ["sampling/createMessage", "prompts/get"]

[tools]
allow = ["filesystem.read"]
"#;

#[test]
fn proxy_denied_prompts_get_not_forwarded() {
    let policy = write_temp_policy("deny-prompts-get", METHOD_POLICY);
    let run = run_proxy_with_input(
        "deny-prompts-get",
        &policy,
        &[
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"prompts/get","params":{"name":"secret_prompt","arguments":{"user_input":"do not leak this"}}}"#,
        ],
    );
    assert!(
        run.output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&run.output.stderr)
    );
    let lines = stdout_json_lines(&run.output);

    // initialize passed through
    assert!(lines
        .iter()
        .any(|l| l["id"] == 1 && l.get("result").is_some()));

    // prompts/get was denied by policy — should get a proxy error, not a server response
    let denied = lines
        .iter()
        .find(|l| l["id"] == 2)
        .expect("denied prompts/get response");
    assert_eq!(denied["error"]["code"], -32000);
    assert_eq!(denied["error"]["data"]["method"], "prompts/get");
    assert!(!denied.to_string().contains("do not leak this"));

    // The server must never have received prompts/get
    let received = std::fs::read_to_string(&run.server_log).expect("server log");
    assert!(!received.contains("prompts/get"));
    assert!(!received.contains("do not leak this"));
    assert!(received.contains("initialize"));

    // Audit should record the method_decision deny
    let audit = std::fs::read_to_string(&run.audit_log).expect("audit log");
    assert!(audit.contains("\"method_decision\""));
    assert!(audit.contains("\"prompts/get\""));
    assert!(audit.contains("\"deny\""));
    assert!(audit.contains("\"param_keys\":[\"arguments\",\"name\"]"));
    assert!(!audit.contains("do not leak this"));
    assert!(!audit.contains("secret_prompt"));

    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&run.server_log);
    let _ = std::fs::remove_file(&run.audit_log);
}

#[test]
fn proxy_denied_sampling_create_message_not_forwarded() {
    let policy = write_temp_policy("deny-sampling", METHOD_POLICY);
    let run = run_proxy_with_input(
        "deny-sampling",
        &policy,
        &[
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"sampling/createMessage","params":{"messages":[{"role":"user","content":"secret message body"}]}}"#,
        ],
    );
    assert!(
        run.output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&run.output.stderr)
    );
    let lines = stdout_json_lines(&run.output);

    let denied = lines
        .iter()
        .find(|l| l["id"] == 2)
        .expect("denied sampling response");
    assert_eq!(denied["error"]["code"], -32000);
    assert_eq!(denied["error"]["data"]["method"], "sampling/createMessage");
    assert!(!denied.to_string().contains("secret message body"));

    let received = std::fs::read_to_string(&run.server_log).expect("server log");
    assert!(!received.contains("sampling/createMessage"));
    assert!(!received.contains("secret message body"));

    let audit = std::fs::read_to_string(&run.audit_log).expect("audit log");
    assert!(audit.contains("\"sampling/createMessage\""));
    assert!(audit.contains("\"deny\""));
    assert!(audit.contains("\"param_keys\":[\"messages\"]"));
    assert!(!audit.contains("secret message body"));

    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&run.server_log);
    let _ = std::fs::remove_file(&run.audit_log);
}

#[test]
fn proxy_unknown_method_not_forwarded_by_default() {
    // Using TEST_POLICY which has no [methods] section — built-in default
    // allows only tools/list and tools/call.
    let policy = write_temp_policy("unknown-method", TEST_POLICY);
    let run = run_proxy_with_input(
        "unknown-method",
        &policy,
        &[
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"some/unknown/method","params":{"data":"x"}}"#,
        ],
    );
    assert!(
        run.output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&run.output.stderr)
    );
    let lines = stdout_json_lines(&run.output);

    // unknown method denied
    let denied = lines
        .iter()
        .find(|l| l["id"] == 2)
        .expect("denied unknown method response");
    assert_eq!(denied["error"]["code"], -32000);
    assert_eq!(denied["error"]["data"]["method"], "some/unknown/method");

    let received = std::fs::read_to_string(&run.server_log).expect("server log");
    assert!(!received.contains("some/unknown/method"));

    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&run.server_log);
    let _ = std::fs::remove_file(&run.audit_log);
}

#[test]
fn proxy_allowed_resources_read_is_forwarded() {
    let policy = write_temp_policy("allow-res-read", METHOD_POLICY);
    let run = run_proxy_with_input(
        "allow-res-read",
        &policy,
        &[
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"file:///safe/path"}}"#,
        ],
    );
    assert!(
        run.output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&run.output.stderr)
    );
    let lines = stdout_json_lines(&run.output);

    // resources/read reached the server and got a response
    let resp = lines
        .iter()
        .find(|l| l["id"] == 2)
        .expect("resources/read response");
    assert_eq!(resp["result"]["echo_method"], "resources/read");

    let received = std::fs::read_to_string(&run.server_log).expect("server log");
    assert!(received.contains("resources/read"));

    let audit = std::fs::read_to_string(&run.audit_log).expect("audit log");
    assert!(audit.contains("\"resources/read\""));
    assert!(audit.contains("\"allow\""));

    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&run.server_log);
    let _ = std::fs::remove_file(&run.audit_log);
}

#[test]
fn proxy_allowed_resources_list_is_forwarded() {
    let policy = write_temp_policy("allow-res-list", METHOD_POLICY);
    let run = run_proxy_with_input(
        "allow-res-list",
        &policy,
        &[
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"resources/list","params":{}}"#,
        ],
    );
    assert!(
        run.output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&run.output.stderr)
    );
    let lines = stdout_json_lines(&run.output);

    // resources/list reached the server and got a response.
    let resp = lines
        .iter()
        .find(|l| l["id"] == 2)
        .expect("resources/list response");
    assert_eq!(resp["result"]["echo_method"], "resources/list");

    let received = std::fs::read_to_string(&run.server_log).expect("server log");
    assert!(received.contains("resources/list"));

    let audit = std::fs::read_to_string(&run.audit_log).expect("audit log");
    assert!(audit.contains("\"resources/list\""));
    assert!(audit.contains("\"allow\""));

    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&run.server_log);
    let _ = std::fs::remove_file(&run.audit_log);
}

#[test]
fn proxy_denied_resources_list_not_forwarded() {
    // TEST_POLICY has no [methods] section — built-in default allows only
    // tools/list and tools/call, so resources/list is denied by default.
    let policy = write_temp_policy("deny-res-list", TEST_POLICY);
    let run = run_proxy_with_input(
        "deny-res-list",
        &policy,
        &[r#"{"jsonrpc":"2.0","id":1,"method":"resources/list","params":{}}"#],
    );
    assert!(
        run.output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&run.output.stderr)
    );
    let lines = stdout_json_lines(&run.output);
    let denied = lines
        .iter()
        .find(|l| l["id"] == 1)
        .expect("denied resources/list response");
    assert_eq!(denied["error"]["code"], -32000);
    assert_eq!(denied["error"]["data"]["method"], "resources/list");

    let received = std::fs::read_to_string(&run.server_log).unwrap_or_default();
    assert!(!received.contains("resources/list"));

    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&run.server_log);
    let _ = std::fs::remove_file(&run.audit_log);
}

#[test]
fn proxy_method_denied_response_preserves_request_id() {
    let policy = write_temp_policy("id-preserve", METHOD_POLICY);
    let run = run_proxy_with_input(
        "id-preserve",
        &policy,
        &[r#"{"jsonrpc":"2.0","id":"custom-id-99","method":"prompts/get","params":{}}"#],
    );
    assert!(
        run.output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&run.output.stderr)
    );
    let lines = stdout_json_lines(&run.output);
    let denied = lines
        .iter()
        .find(|l| l["id"] == "custom-id-99")
        .expect("denied response with preserved id");
    assert_eq!(denied["error"]["code"], -32000);
    assert_eq!(denied["error"]["data"]["method"], "prompts/get");

    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&run.server_log);
    let _ = std::fs::remove_file(&run.audit_log);
}

#[test]
fn proxy_audit_excludes_sensitive_param_values() {
    let policy = write_temp_policy("audit-safe", METHOD_POLICY);
    let run = run_proxy_with_input(
        "audit-safe",
        &policy,
        &[
            r#"{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"my_prompt","arguments":{"secret_key":"secret_value_123","token":"abc-token-xyz"}}}"#,
        ],
    );
    assert!(
        run.output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&run.output.stderr)
    );
    let audit = std::fs::read_to_string(&run.audit_log).expect("audit log");
    // Param keys are safe metadata
    assert!(audit.contains("\"arguments\""));
    assert!(audit.contains("\"name\""));
    // Sensitive values must not appear
    assert!(!audit.contains("secret_value_123"));
    assert!(!audit.contains("abc-token-xyz"));
    assert!(!audit.contains("my_prompt"));
    // request_id_type should be recorded
    assert!(audit.contains("\"request_id_type\":\"number\""));

    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&run.server_log);
    let _ = std::fs::remove_file(&run.audit_log);
}

#[test]
fn proxy_tools_call_still_works_with_method_policy() {
    let policy = write_temp_policy("tools-call-method", METHOD_POLICY);
    let run = run_proxy_with_input(
        "tools-call-method",
        &policy,
        &[
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"filesystem.read","arguments":{"path":"/x"}}}"#,
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"shell.run","arguments":{}}}"#,
        ],
    );
    assert!(
        run.output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&run.output.stderr)
    );
    let lines = stdout_json_lines(&run.output);
    // Allowed tool call reached server
    assert_eq!(
        lines.iter().find(|l| l["id"] == 2).expect("allowed call")["result"]["echo_tool"],
        "filesystem.read"
    );
    // Denied tool call got proxy error
    assert_eq!(
        lines.iter().find(|l| l["id"] == 3).expect("denied call")["error"]["code"],
        -32000
    );

    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&run.server_log);
    let _ = std::fs::remove_file(&run.audit_log);
}

#[test]
fn proxy_batch_arrays_still_denied_with_method_policy() {
    let policy = write_temp_policy("batch-method", METHOD_POLICY);
    let run = run_proxy_with_input(
        "batch-method",
        &policy,
        &[r#"[{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}]"#],
    );
    assert!(
        run.output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&run.output.stderr)
    );
    let lines = stdout_json_lines(&run.output);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["id"], Value::Null);
    assert_eq!(lines[0]["error"]["code"], -32000);

    let received = std::fs::read_to_string(&run.server_log).unwrap_or_default();
    assert!(!received.contains("tools/list"));

    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&run.server_log);
    let _ = std::fs::remove_file(&run.audit_log);
}

#[test]
fn proxy_default_policy_denies_resources_read() {
    // TEST_POLICY has no [methods] section, so built-in default applies:
    // only tools/list and tools/call are allowed.
    let policy = write_temp_policy("default-deny-res", TEST_POLICY);
    let run = run_proxy_with_input(
        "default-deny-res",
        &policy,
        &[
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"file:///etc/passwd"}}"#,
        ],
    );
    assert!(
        run.output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&run.output.stderr)
    );
    let lines = stdout_json_lines(&run.output);
    // resources/read denied by default
    let denied = lines
        .iter()
        .find(|l| l["id"] == 2)
        .expect("denied resources/read");
    assert_eq!(denied["error"]["code"], -32000);

    let received = std::fs::read_to_string(&run.server_log).expect("server log");
    assert!(!received.contains("resources/read"));

    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&run.server_log);
    let _ = std::fs::remove_file(&run.audit_log);
}
