use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;

use crate::audit::{redacted_argument_keys, AuditLog, AuditRecord};
use crate::policy::{decide_tool_call, Decision, McpPolicyFile};

pub const TOOL_CALL_METHOD: &str = "tools/call";
/// JSON-RPC application error code returned to the client for denied calls.
pub const DENIED_ERROR_CODE: i64 = -32000;

/// What the proxy should do with one line received from the MCP client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientAction {
    /// Forward the original line to the server unchanged.
    Forward,
    /// Do not forward. If the request carried an id, `response` holds the
    /// JSON-RPC error line to send back to the client.
    Deny { response: Option<String> },
}

#[derive(Debug)]
pub struct InspectedLine {
    pub action: ClientAction,
    pub audit: Option<AuditRecord>,
}

/// Inspect one newline-delimited JSON-RPC message from the client.
///
/// Only `tools/call` requests are policy-checked. Every other message —
/// including non-JSON lines the server will reject itself — is forwarded
/// unchanged to preserve protocol behavior. Tool calls without a usable
/// string tool name are denied (fail closed). JSON-RPC batch arrays are
/// not unpacked: they are denied wholesale (fail closed), because a batch
/// could smuggle a denied `tools/call` past per-message inspection.
pub fn inspect_client_line(policy: &McpPolicyFile, line: &str) -> InspectedLine {
    let Ok(message) = serde_json::from_str::<Value>(line) else {
        return InspectedLine {
            action: ClientAction::Forward,
            audit: None,
        };
    };
    if message.is_array() {
        let reason = "fail closed: JSON-RPC batch arrays are not inspected by this proxy";
        return InspectedLine {
            action: ClientAction::Deny {
                response: Some(batch_denied_response(reason)),
            },
            audit: Some(AuditRecord::batch_denied(&policy.name, reason)),
        };
    }
    if message.get("method").and_then(Value::as_str) != Some(TOOL_CALL_METHOD) {
        return InspectedLine {
            action: ClientAction::Forward,
            audit: None,
        };
    }

    let request_id = message.get("id").cloned();
    let params = message.get("params");
    let tool_name = params
        .and_then(|params| params.get("name"))
        .and_then(Value::as_str);
    let argument_keys = redacted_argument_keys(params.and_then(|params| params.get("arguments")));

    let (tool_for_audit, decision, reason) = match tool_name {
        Some(name) => {
            let policy_decision = decide_tool_call(policy, name);
            (Some(name), policy_decision.decision, policy_decision.reason)
        }
        None => (
            None,
            Decision::Deny,
            "fail closed: tool call has a missing or non-string tool name".to_string(),
        ),
    };

    let audit = Some(AuditRecord::tool_call(
        &policy.name,
        TOOL_CALL_METHOD,
        request_id.clone(),
        tool_for_audit,
        argument_keys,
        decision,
        &reason,
    ));

    match decision {
        Decision::Allow => InspectedLine {
            action: ClientAction::Forward,
            audit,
        },
        Decision::Deny | Decision::PolicyError => {
            let response = request_id.filter(|id| !id.is_null()).map(|id| {
                denied_error_response(&id, tool_for_audit.unwrap_or("<unknown>"), &reason)
            });
            InspectedLine {
                action: ClientAction::Deny { response },
                audit,
            }
        }
    }
}

/// JSON-RPC replies to a rejected batch with a single response object whose
/// id is null, so the client gets an explicit error instead of a hang.
fn batch_denied_response(reason: &str) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": Value::Null,
        "error": {
            "code": DENIED_ERROR_CODE,
            "message": "EtherFence MCP proxy denied this JSON-RPC batch by policy",
            "data": {
                "reason": reason,
            },
        },
    })
    .to_string()
}

fn denied_error_response(request_id: &Value, tool_name: &str, reason: &str) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": DENIED_ERROR_CODE,
            "message": "EtherFence MCP proxy denied this tool call by policy",
            "data": {
                "tool": tool_name,
                "reason": reason,
            },
        },
    })
    .to_string()
}

/// Run the stdio boundary proxy until the client closes its input stream,
/// then wait for the server child process and return its exit code.
pub fn run_proxy<ClientIn, ClientOut>(
    client_in: ClientIn,
    client_out: ClientOut,
    server_command: &[String],
    policy: &McpPolicyFile,
    mut audit_log: Option<AuditLog>,
) -> Result<i32>
where
    ClientIn: BufRead,
    ClientOut: Write + Send,
{
    let (command, args) = server_command
        .split_first()
        .context("MCP server command must not be empty")?;
    let mut child = Command::new(command)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawning MCP server command {command:?}"))?;
    let mut server_in = child.stdin.take().context("opening MCP server stdin")?;
    let server_out = child.stdout.take().context("opening MCP server stdout")?;
    let client_out = Mutex::new(client_out);

    let pump_result = std::thread::scope(|scope| -> Result<()> {
        let server_to_client = scope.spawn(|| pump_server_to_client(server_out, &client_out));

        for line in client_in.lines() {
            let line = line.context("reading from MCP client")?;
            let inspected = inspect_client_line(policy, &line);
            if let (Some(log), Some(record)) = (audit_log.as_mut(), inspected.audit.as_ref()) {
                log.write(record)?;
            }
            match inspected.action {
                ClientAction::Forward => {
                    writeln!(server_in, "{line}").context("forwarding to MCP server")?;
                    server_in.flush().context("flushing MCP server stdin")?;
                }
                ClientAction::Deny { response } => {
                    if let Some(response) = response {
                        let mut out = client_out.lock().expect("client output lock");
                        writeln!(out, "{response}").context("responding to MCP client")?;
                        out.flush().context("flushing MCP client output")?;
                    }
                }
            }
        }

        // Client is done: close the server's stdin so it can exit cleanly.
        drop(server_in);
        server_to_client
            .join()
            .expect("server-to-client pump thread")?;
        Ok(())
    });
    let status = wait_for_child(&mut child);
    pump_result?;
    let status = status.context("waiting for MCP server to exit")?;
    Ok(status)
}

fn pump_server_to_client<ClientOut: Write>(
    server_out: std::process::ChildStdout,
    client_out: &Mutex<ClientOut>,
) -> Result<()> {
    let reader = BufReader::new(server_out);
    for line in reader.lines() {
        let line = line.context("reading from MCP server")?;
        let mut out = client_out.lock().expect("client output lock");
        writeln!(out, "{line}").context("forwarding to MCP client")?;
        out.flush().context("flushing MCP client output")?;
    }
    Ok(())
}

fn wait_for_child(child: &mut Child) -> Result<i32> {
    let status = child.wait().context("waiting for MCP server child")?;
    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::parse_mcp_policy;

    fn policy() -> McpPolicyFile {
        parse_mcp_policy(
            r#"
schema_version = "ef-mcp-policy/v0.1"
name = "minimal-mcp-boundary"

[tools]
allow = ["github.list_repos", "filesystem.read"]
deny = ["filesystem.read_secret", "shell.run"]
"#,
        )
        .expect("valid test policy")
    }

    #[test]
    fn non_tool_call_messages_are_forwarded() {
        let inspected = inspect_client_line(
            &policy(),
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        );
        assert_eq!(inspected.action, ClientAction::Forward);
        assert!(inspected.audit.is_none());
    }

    #[test]
    fn non_json_lines_are_forwarded_for_server_side_rejection() {
        let inspected = inspect_client_line(&policy(), "not json at all");
        assert_eq!(inspected.action, ClientAction::Forward);
        assert!(inspected.audit.is_none());
    }

    #[test]
    fn allowed_tool_call_is_forwarded_and_audited() {
        let inspected = inspect_client_line(
            &policy(),
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"filesystem.read","arguments":{"path":"/home/user/notes.txt"}}}"#,
        );
        assert_eq!(inspected.action, ClientAction::Forward);
        let audit = inspected.audit.expect("audit record");
        assert_eq!(audit.decision, "allow");
        assert_eq!(audit.tool.as_deref(), Some("filesystem.read"));
        assert_eq!(audit.argument_keys, vec!["path"]);
    }

    #[test]
    fn denied_tool_call_gets_error_response_and_audit() {
        let inspected = inspect_client_line(
            &policy(),
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"shell.run","arguments":{"command":"env","api_token":"sk-secret"}}}"#,
        );
        let ClientAction::Deny { response } = inspected.action else {
            panic!("expected deny");
        };
        let response = response.expect("error response for request with id");
        let json: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(json["id"], 3);
        assert_eq!(json["error"]["code"], DENIED_ERROR_CODE);
        assert_eq!(json["error"]["data"]["tool"], "shell.run");
        assert!(!response.contains("sk-secret"));
        let audit = inspected.audit.expect("audit record");
        assert_eq!(audit.decision, "deny");
        assert_eq!(audit.argument_keys, vec!["api_token", "command"]);
    }

    #[test]
    fn denied_notification_without_id_is_dropped_silently() {
        let inspected = inspect_client_line(
            &policy(),
            r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"shell.run"}}"#,
        );
        assert_eq!(inspected.action, ClientAction::Deny { response: None });
        assert_eq!(inspected.audit.expect("audit record").decision, "deny");
    }

    #[test]
    fn tool_call_without_tool_name_fails_closed() {
        let inspected = inspect_client_line(
            &policy(),
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"arguments":{}}}"#,
        );
        let ClientAction::Deny { response } = inspected.action else {
            panic!("expected deny");
        };
        let json: Value = serde_json::from_str(&response.expect("error response")).unwrap();
        assert_eq!(json["error"]["code"], DENIED_ERROR_CODE);
        let audit = inspected.audit.expect("audit record");
        assert_eq!(audit.decision, "deny");
        assert!(audit.reason.contains("fail closed"));
    }

    #[test]
    fn json_rpc_batch_arrays_are_denied_fail_closed() {
        let inspected = inspect_client_line(
            &policy(),
            r#"[{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"filesystem.read"}}]"#,
        );
        let ClientAction::Deny { response } = inspected.action else {
            panic!("expected deny");
        };
        let json: Value = serde_json::from_str(&response.expect("batch error response")).unwrap();
        assert_eq!(json["id"], Value::Null);
        assert_eq!(json["error"]["code"], DENIED_ERROR_CODE);
        let audit = inspected.audit.expect("audit record");
        assert_eq!(audit.event, "batch_denied");
        assert_eq!(audit.decision, "deny");
        assert!(audit.reason.contains("fail closed"));
    }

    #[test]
    fn empty_json_array_is_denied_fail_closed() {
        let inspected = inspect_client_line(&policy(), "[]");
        assert!(matches!(inspected.action, ClientAction::Deny { .. }));
        assert_eq!(inspected.audit.expect("audit record").event, "batch_denied");
    }

    #[test]
    fn unlisted_tool_call_is_denied_by_default() {
        let inspected = inspect_client_line(
            &policy(),
            r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"browser.open"}}"#,
        );
        assert!(matches!(inspected.action, ClientAction::Deny { .. }));
        let audit = inspected.audit.expect("audit record");
        assert!(audit.reason.contains("default deny"));
    }
}
