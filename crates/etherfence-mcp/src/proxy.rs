use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};

use crate::audit::{redacted_argument_keys, AuditLog, AuditRecord};
use crate::policy::{decide_tool_call, Decision, McpPolicyFile};

pub const TOOL_CALL_METHOD: &str = "tools/call";
pub const TOOL_LIST_METHOD: &str = "tools/list";
/// JSON-RPC application error code returned to the client for denied calls.
pub const DENIED_ERROR_CODE: i64 = -32000;

/// Process exit codes used by the `mcp-proxy` subcommand. These are distinct
/// from the child server's exit code, which is propagated unchanged when the
/// child exits before the client.
#[allow(dead_code)]
pub mod exit_code {
    /// The proxy shut down cleanly after the client closed its input.
    pub const OK: i32 = 0;
    /// The MCP policy could not be loaded; the proxy failed closed and the
    /// server was never started.
    pub const INVALID_POLICY: i32 = 2;
    /// The MCP server child process could not be spawned.
    pub const SPAWN_FAILED: i32 = 3;
    /// An internal proxy error (I/O on a pipe, audit-log open failure, or a
    /// broken pipe that could not be handled as a clean shutdown).
    pub const INTERNAL_ERROR: i32 = 4;
}

/// An explicit proxy failure carrying the process exit code the CLI should use.
///
/// Every variant maps to a documented exit code so the lifecycle behavior is
/// predictable and testable. The child server is always reaped by the caller
/// regardless of which variant is returned.
#[derive(Debug)]
pub enum ProxyError {
    /// The child server exited on its own before the client closed its input.
    /// Carries the child's own exit code so it can be propagated.
    ChildExited(i32),
    /// The child could not be spawned (fail closed).
    SpawnFailed(String),
    /// A required pipe (child stdin/stdout) could not be opened after spawn.
    PipeOpen(String),
    /// The client input stream failed.
    ClientRead(String),
    /// Writing to the child (forwarding a client request) failed.
    ServerWrite(String),
    /// Reading the child output stream failed.
    ServerRead(String),
    /// Writing to the client (forwarding a server response) failed.
    ClientWrite(String),
    /// The audit log could not be opened before proxying began.
    AuditOpen(String),
}

impl ProxyError {
    /// The process exit code for this error.
    pub fn code(&self) -> i32 {
        match self {
            ProxyError::ChildExited(code) => *code,
            ProxyError::SpawnFailed(_) => exit_code::SPAWN_FAILED,
            ProxyError::PipeOpen(_) => exit_code::INTERNAL_ERROR,
            ProxyError::ClientRead(_) => exit_code::INTERNAL_ERROR,
            ProxyError::ServerWrite(_) => exit_code::INTERNAL_ERROR,
            ProxyError::ServerRead(_) => exit_code::INTERNAL_ERROR,
            ProxyError::ClientWrite(_) => exit_code::INTERNAL_ERROR,
            ProxyError::AuditOpen(_) => exit_code::INTERNAL_ERROR,
        }
    }

    /// A one-line human-readable message for stderr.
    pub fn message(&self) -> String {
        match self {
            ProxyError::ChildExited(code) => {
                format!("MCP server child process exited with code {code}")
            }
            ProxyError::SpawnFailed(msg) => format!("failed to start MCP server: {msg}"),
            ProxyError::PipeOpen(msg) => format!("failed to open MCP server pipe: {msg}"),
            ProxyError::ClientRead(msg) => format!("failed reading from MCP client: {msg}"),
            ProxyError::ServerWrite(msg) => format!("failed forwarding to MCP server: {msg}"),
            ProxyError::ServerRead(msg) => format!("failed reading from MCP server: {msg}"),
            ProxyError::ClientWrite(msg) => format!("failed writing to MCP client: {msg}"),
            ProxyError::AuditOpen(msg) => format!("failed to open audit log: {msg}"),
        }
    }
}

/// What the proxy should do with one line received from the MCP client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientAction {
    /// Forward the original line to the server unchanged.
    Forward,
    /// Do not forward. If the request carried an id, `response` holds the
    /// JSON-RPC error line to send back to the client.
    Deny { response: Option<String> },
}

/// A client request the proxy must track until its response arrives.
///
/// Only messages that need response handling are tracked. Today that is
/// `tools/list`, whose successful responses are filtered. The id is stored as
/// a stable canonical JSON key (see [`request_id_key`]) so that any JSON-RPC
/// id type (null, number, string, bool, array, object) is handled consistently
/// and can be compared against the id returned by the server.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TrackedRequest {
    pub method: &'static str,
    pub id_key: String,
}

/// Set of in-flight client requests the proxy is waiting on, keyed by
/// `(method, id_key)`. A reference count is kept so that a duplicate in-flight
/// id (two identical `tools/list` requests before either response arrives)
/// does not orphan the second request when the first response clears the
/// entry. An entry is removed only when its count returns to zero.
#[derive(Debug, Default)]
pub struct TrackedRequests {
    counts: HashMap<(String, String), usize>,
}

impl TrackedRequests {
    /// Record a new in-flight request. Returns the request so callers can pass
    /// it through `inspect_client_line`. Duplicate ids increment the count.
    pub fn track(&mut self, request: TrackedRequest) -> TrackedRequest {
        *self
            .counts
            .entry((request.method.to_string(), request.id_key.clone()))
            .or_insert(0) += 1;
        request
    }

    /// Remove one in-flight response for `request`. Returns `true` when this
    /// was the last pending response and the tracking entry was cleared, so
    /// the caller can audit the cleanup. Returns `false` if no matching entry
    /// existed (the response is not for a tracked request, or was already
    /// cleared).
    pub fn remove_response(&mut self, request: &TrackedRequest) -> bool {
        let key = (request.method.to_string(), request.id_key.clone());
        match self.counts.get_mut(&key) {
            Some(count) => {
                *count -= 1;
                if *count == 0 {
                    self.counts.remove(&key);
                    true
                } else {
                    false
                }
            }
            None => false,
        }
    }

    /// Whether `request` is currently tracked (any non-zero count).
    pub fn contains(&self, request: &TrackedRequest) -> bool {
        self.counts
            .get(&(request.method.to_string(), request.id_key.clone()))
            .is_some_and(|count| *count > 0)
    }

    /// True when there are no tracked in-flight requests.
    pub fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }
}

#[derive(Debug)]
pub struct InspectedLine {
    pub action: ClientAction,
    pub audit: Option<AuditRecord>,
    pub tools_list_request: Option<TrackedRequest>,
}

#[derive(Debug)]
pub struct InspectedServerLine {
    pub line: String,
    pub audit: Option<AuditRecord>,
    /// Set when this response matched a tracked request and cleared its
    /// tracking entry, so the engine can emit a cleanup audit event.
    pub tracking_cleared: bool,
}

/// Inspect one newline-delimited JSON-RPC message from the client.
///
/// Only `tools/call` requests are policy-checked. Every other message —
/// including non-JSON lines the server will reject itself — is forwarded
/// unchanged to preserve protocol behavior. Tool calls without a usable
/// string tool name are denied (fail closed). JSON-RPC batch arrays are
/// not unpacked: they are denied wholesale (fail closed), because a batch
/// could smuggle a denied `tools/call` past per-message inspection.
pub fn inspect_client_line(policy: &McpPolicyFile, server_name: &str, line: &str) -> InspectedLine {
    let Ok(message) = serde_json::from_str::<Value>(line) else {
        return InspectedLine {
            action: ClientAction::Forward,
            audit: None,
            tools_list_request: None,
        };
    };
    if message.is_array() {
        let reason = "fail closed: JSON-RPC batch arrays are not inspected by this proxy";
        return InspectedLine {
            action: ClientAction::Deny {
                response: Some(batch_denied_response(reason)),
            },
            audit: Some(AuditRecord::batch_denied(&policy.name, server_name, reason)),
            tools_list_request: None,
        };
    }
    if message.get("method").and_then(Value::as_str) == Some(TOOL_LIST_METHOD) {
        // A tools/list notification (no usable id) is not tracked: there will
        // never be a response to match it against. Notifications are forwarded
        // unchanged, exactly like any other message.
        let tools_list_request =
            message
                .get("id")
                .and_then(request_id_key)
                .map(|id_key| TrackedRequest {
                    method: TOOL_LIST_METHOD,
                    id_key,
                });
        return InspectedLine {
            action: ClientAction::Forward,
            audit: None,
            tools_list_request,
        };
    }
    if message.get("method").and_then(Value::as_str) != Some(TOOL_CALL_METHOD) {
        return InspectedLine {
            action: ClientAction::Forward,
            audit: None,
            tools_list_request: None,
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
            let policy_decision = decide_tool_call(policy, server_name, name);
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
        server_name,
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
            tools_list_request: None,
        },
        Decision::Deny | Decision::PolicyError => {
            let response = request_id.filter(|id| !id.is_null()).map(|id| {
                denied_error_response(&id, tool_for_audit.unwrap_or("<unknown>"), &reason)
            });
            InspectedLine {
                action: ClientAction::Deny { response },
                audit,
                tools_list_request: None,
            }
        }
    }
}

pub fn inspect_server_line(
    policy: &McpPolicyFile,
    server_name: &str,
    pending: &mut TrackedRequests,
    line: &str,
) -> InspectedServerLine {
    let Ok(mut message) = serde_json::from_str::<Value>(line) else {
        // Not JSON: forward unchanged. Non-JSON server output is the server's
        // problem to resolve, exactly like any non-JSON client line.
        return InspectedServerLine {
            line: line.to_string(),
            audit: None,
            tracking_cleared: false,
        };
    };

    // Responses without an id (notifications, or bare results) cannot be
    // matched to a tracked request, so they pass through unchanged. This is a
    // documented safe default: the proxy only re-shapes responses it can tie
    // back to a tracked tools/list request.
    let Some(id) = message.get("id") else {
        return InspectedServerLine {
            line: line.to_string(),
            audit: None,
            tracking_cleared: false,
        };
    };
    let Some(id_key) = request_id_key(id) else {
        // A null id (JSON-RPC error/result with id:null) is never tracked.
        return InspectedServerLine {
            line: line.to_string(),
            audit: None,
            tracking_cleared: false,
        };
    };
    let request = TrackedRequest {
        method: TOOL_LIST_METHOD,
        id_key,
    };

    // Only clear and reshape when this response is for a tracked tools/list
    // request. Unknown ids (including responses for other methods that happen
    // to reuse the same id style) pass through unchanged.
    if !pending.contains(&request) {
        return InspectedServerLine {
            line: line.to_string(),
            audit: None,
            tracking_cleared: false,
        };
    }

    // Server error for a tracked tools/list request: pass through unchanged and
    // clear tracking. The error is the server's authoritative answer; the proxy
    // must not fabricate a tool list.
    if message.get("error").is_some() {
        let tracking_cleared = pending.remove_response(&request);
        return InspectedServerLine {
            line: line.to_string(),
            audit: None,
            tracking_cleared,
        };
    }

    let request_id = message.get("id").cloned();

    // Only reshape genuine tool-list results. A tracked-id response whose
    // result is not a JSON object carrying a `tools` field is treated as an
    // unrelated response: pass it through unchanged so the proxy never leaks
    // or fabricates a tool list, and clear tracking so the entry does not leak.
    let is_tool_list = message
        .get("result")
        .and_then(Value::as_object)
        .is_some_and(|o| o.contains_key("tools"));
    if !is_tool_list {
        let tracking_cleared = pending.remove_response(&request);
        return InspectedServerLine {
            line: line.to_string(),
            audit: None,
            tracking_cleared,
        };
    }

    // `result` is an object containing `tools` (verified above).
    let result = message.get_mut("result").expect("result object");
    let tools = result
        .get_mut("tools")
        .expect("result.tools present (checked by is_tool_list)");
    let Some(tool_array) = tools.as_array_mut() else {
        let audit = AuditRecord::tools_list_malformed(
            &policy.name,
            server_name,
            request_id,
            "fail safe: tools/list response tools field was not an array, advertised no tools",
        );
        *tools = json!([]);
        let tracking_cleared = pending.remove_response(&request);
        return InspectedServerLine {
            line: message.to_string(),
            audit: Some(audit),
            tracking_cleared,
        };
    };

    let original_count = tool_array.len();
    let mut allowed_tool_names = Vec::new();
    tool_array.retain(|tool| {
        let Some(name) = tool.get("name").and_then(Value::as_str) else {
            return false;
        };
        if decide_tool_call(policy, server_name, name).decision == Decision::Allow {
            allowed_tool_names.push(name.to_string());
            true
        } else {
            false
        }
    });
    allowed_tool_names.sort();
    let audit = AuditRecord::tools_list_filtered(
        &policy.name,
        server_name,
        request_id,
        original_count,
        allowed_tool_names,
        "filtered tools/list response using MCP proxy policy; denied and default-denied tools were removed",
    );
    let tracking_cleared = pending.remove_response(&request);
    InspectedServerLine {
        line: message.to_string(),
        audit: Some(audit),
        tracking_cleared,
    }
}

fn request_id_key(id: &Value) -> Option<String> {
    if id.is_null() {
        None
    } else {
        serde_json::to_string(id).ok()
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

/// Run the stdio boundary proxy until the client closes its input stream, the
/// child server exits, or a fatal proxy error occurs.
///
/// Lifecycle guarantees:
/// - The child server is spawned before any client traffic is inspected.
/// - On a clean client EOF the proxy closes the server's stdin so the child can
///   exit, joins the server-to-client pump, waits for the child, and returns
///   its exit code (usually 0).
/// - If the child exits first (early exit, crash), the server pump stops, the
///   client's stdin is closed, and `Err(ProxyError::ChildExited(code))` is
///   returned so the caller can propagate the child's code.
/// - Any I/O, spawn, or audit-open failure returns a `ProxyError` with a
///   documented exit code; the caller is responsible for reaping the child.
/// - A broken pipe to the client (the client closed stdout) terminates the
///   proxy cleanly rather than panicking.
pub fn run_proxy<ClientIn, ClientOut>(
    client_in: ClientIn,
    client_out: ClientOut,
    server_command: &[String],
    policy: &McpPolicyFile,
    server_name: &str,
    mut audit_log: Option<AuditLog>,
) -> std::result::Result<i32, ProxyError>
where
    ClientIn: BufRead,
    ClientOut: Write + Send,
{
    let (command, args) = server_command
        .split_first()
        .ok_or_else(|| ProxyError::SpawnFailed("MCP server command must not be empty".into()))?;
    let mut child = Command::new(command)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // Inherit the child's stderr so a chatty or failing server cannot block
        // or deadlock the proxy's own pipes, and so server diagnostics remain
        // visible to the operator.
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| ProxyError::SpawnFailed(format!("{error:?}")))?;
    let mut server_in = child
        .stdin
        .take()
        .ok_or_else(|| ProxyError::PipeOpen("server stdin was not captured".into()))?;
    let server_out = child
        .stdout
        .take()
        .ok_or_else(|| ProxyError::PipeOpen("server stdout was not captured".into()))?;
    let client_out = Mutex::new(client_out);
    let pending_requests = Arc::new(Mutex::new(TrackedRequests::default()));
    let audit_log = Arc::new(Mutex::new(audit_log.take()));

    // Forward one client line to the server, returning false on a clean client
    // EOF (broken pipe) so the caller can shut down without treating it as an
    // error.
    let forward_to_server = |server_in: &mut std::process::ChildStdin,
                             line: &str|
     -> std::result::Result<bool, ProxyError> {
        match writeln!(server_in, "{line}") {
            Ok(()) => server_in
                .flush()
                .map(|()| true)
                .map_err(|error| ProxyError::ServerWrite(format!("{error:?}"))),
            Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(false),
            Err(error) => Err(ProxyError::ServerWrite(format!("{error:?}"))),
        }
    };

    let pump_result = std::thread::scope(|scope| -> std::result::Result<(), ProxyError> {
        let server_to_client = scope.spawn(|| {
            pump_server_to_client(
                server_out,
                &client_out,
                policy,
                server_name,
                &pending_requests,
                &audit_log,
            )
        });

        let mut lines = client_in.lines();
        for line in lines.by_ref() {
            let line = line.map_err(|error| ProxyError::ClientRead(format!("{error:?}")))?;
            // Validate client lines before forwarding: a line that is not valid
            // JSON could mask a protocol error and is not something the server
            // would accept under JSON-RPC. Drop it instead of forwarding it.
            // Requests/responses/notifications that are valid JSON are
            // forwarded unchanged; only parse failures are dropped here.
            if !is_valid_json_line(&line) {
                continue;
            }
            let inspected = inspect_client_line(policy, server_name, &line);
            if let Some(request) = inspected.tools_list_request.as_ref() {
                pending_requests
                    .lock()
                    .expect("tracked request lock")
                    .track(request.clone());
            }
            // Audit is best-effort: a write failure must never weaken a deny or
            // block a forward, so it is logged and ignored.
            if let (Some(log), Some(record)) = (
                audit_log.lock().expect("audit log lock").as_mut(),
                inspected.audit.as_ref(),
            ) {
                if let Err(error) = log.write(record) {
                    eprintln!("etherfence mcp-proxy: audit write failed (continuing): {error:#}");
                }
            }
            match inspected.action {
                ClientAction::Forward => {
                    if !forward_to_server(&mut server_in, &line)? {
                        // Server pipe closed while we were forwarding: stop the
                        // client loop cleanly and let the server pump finish.
                        break;
                    }
                }
                ClientAction::Deny { response } => {
                    if let Some(response) = response {
                        let mut out = client_out.lock().expect("client output lock");
                        match writeln!(out, "{response}") {
                            Ok(()) => {
                                out.flush().map_err(|error| {
                                    ProxyError::ClientWrite(format!("{error:?}"))
                                })?;
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => {
                                // Client closed its output: stop cleanly.
                                break;
                            }
                            Err(error) => {
                                return Err(ProxyError::ClientWrite(format!("{error:?}")))
                            }
                        }
                    }
                }
            }
        }

        // Client is done (EOF or broken pipe): close the server's stdin so the
        // child receives EOF and can exit. Dropping the handle is sufficient.
        drop(server_in);
        server_to_client
            .join()
            .expect("server-to-client pump thread")?;
        Ok(())
    });

    // Reap the child no matter what happened above.
    let child_status = wait_for_child(&mut child);
    pump_result?;
    child_status
}

fn pump_server_to_client<ClientOut: Write>(
    server_out: std::process::ChildStdout,
    client_out: &Mutex<ClientOut>,
    policy: &McpPolicyFile,
    server_name: &str,
    pending_requests: &Arc<Mutex<TrackedRequests>>,
    audit_log: &Arc<Mutex<Option<AuditLog>>>,
) -> std::result::Result<(), ProxyError> {
    let reader = BufReader::new(server_out);
    for line in reader.lines() {
        let line = line.map_err(|error| ProxyError::ServerRead(format!("{error:?}")))?;
        let inspected = inspect_server_line(
            policy,
            server_name,
            &mut pending_requests.lock().expect("tracked request lock"),
            &line,
        );
        // Best-effort audit: failures here never suppress a response or weaken
        // a deny, so log and continue.
        if let (Some(log), Some(record)) = (
            audit_log.lock().expect("audit log lock").as_mut(),
            inspected.audit.as_ref(),
        ) {
            if let Err(error) = log.write(record) {
                eprintln!("etherfence mcp-proxy: audit write failed (continuing): {error:#}");
            }
        }
        if inspected.tracking_cleared {
            let mut log = audit_log.lock().expect("audit log lock");
            if let Some(log) = log.as_mut() {
                if let Err(error) = log.write(&AuditRecord::tools_list_tracking_removed(
                    policy,
                    server_name,
                )) {
                    eprintln!("etherfence mcp-proxy: audit write failed (continuing): {error:#}");
                }
            }
        }
        let mut out = client_out.lock().expect("client output lock");
        match writeln!(out, "{}", inspected.line) {
            Ok(()) => out
                .flush()
                .map_err(|error| ProxyError::ClientWrite(format!("{error:?}")))?,
            // Client closed its output: stop the server pump cleanly.
            Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => return Ok(()),
            Err(error) => return Err(ProxyError::ClientWrite(format!("{error:?}"))),
        }
    }
    Ok(())
}

fn wait_for_child(child: &mut Child) -> std::result::Result<i32, ProxyError> {
    let status = child.wait().map_err(|error| {
        ProxyError::ServerRead(format!("waiting for MCP server child: {error:?}"))
    })?;
    Ok(status.code().unwrap_or(1))
}

/// Whether `line` parses as a JSON value. Used to drop invalid client lines
/// before they reach the server. Invalid server lines are intentionally NOT
/// dropped (see `inspect_server_line`): they are passed through so the client's
/// own parser rejects them and the proxy never fabricates a tool list.
fn is_valid_json_line(line: &str) -> bool {
    serde_json::from_str::<Value>(line).is_ok()
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

    /// Build a TrackedRequests set pre-seeded with one tools/list id.
    fn tracked(id_key: &str) -> TrackedRequests {
        let mut pending = TrackedRequests::default();
        pending.track(TrackedRequest {
            method: TOOL_LIST_METHOD,
            id_key: id_key.to_string(),
        });
        pending
    }

    #[test]
    fn non_tool_call_messages_are_forwarded() {
        let inspected = inspect_client_line(
            &policy(),
            "default",
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        );
        assert_eq!(inspected.action, ClientAction::Forward);
        assert!(inspected.audit.is_none());
    }

    #[test]
    fn non_json_lines_are_forwarded_for_server_side_rejection() {
        let inspected = inspect_client_line(&policy(), "default", "not json at all");
        assert_eq!(inspected.action, ClientAction::Forward);
        assert!(inspected.audit.is_none());
    }

    #[test]
    fn allowed_tool_call_is_forwarded_and_audited() {
        let inspected = inspect_client_line(
            &policy(),
            "default",
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
            "default",
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
            "default",
            r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"shell.run"}}"#,
        );
        assert_eq!(inspected.action, ClientAction::Deny { response: None });
        assert_eq!(inspected.audit.expect("audit record").decision, "deny");
    }

    #[test]
    fn tool_call_without_tool_name_fails_closed() {
        let inspected = inspect_client_line(
            &policy(),
            "default",
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
            "default",
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
        let inspected = inspect_client_line(&policy(), "default", "[]");
        assert!(matches!(inspected.action, ClientAction::Deny { .. }));
        assert_eq!(inspected.audit.expect("audit record").event, "batch_denied");
    }

    #[test]
    fn unlisted_tool_call_is_denied_by_default() {
        let inspected = inspect_client_line(
            &policy(),
            "default",
            r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"browser.open"}}"#,
        );
        assert!(matches!(inspected.action, ClientAction::Deny { .. }));
        let audit = inspected.audit.expect("audit record");
        assert!(audit.reason.contains("default deny"));
    }

    #[test]
    fn tools_list_request_with_string_id_is_tracked() {
        let inspected = inspect_client_line(
            &policy(),
            "default",
            r#"{"jsonrpc":"2.0","id":"list-1","method":"tools/list","params":{}}"#,
        );
        assert_eq!(inspected.action, ClientAction::Forward);
        let request = inspected.tools_list_request.expect("tracked tools/list");
        assert_eq!(request.method, TOOL_LIST_METHOD);
        assert_eq!(request.id_key, "\"list-1\"");
        assert!(inspected.audit.is_none());
    }

    #[test]
    fn tools_list_request_with_numeric_id_is_tracked() {
        let inspected = inspect_client_line(
            &policy(),
            "default",
            r#"{"jsonrpc":"2.0","id":7,"method":"tools/list","params":{}}"#,
        );
        assert_eq!(inspected.action, ClientAction::Forward);
        let request = inspected.tools_list_request.expect("tracked tools/list");
        assert_eq!(request.id_key, "7");
    }

    #[test]
    fn tools_list_notification_without_id_is_not_tracked() {
        let inspected = inspect_client_line(
            &policy(),
            "default",
            r#"{"jsonrpc":"2.0","method":"tools/list","params":{}}"#,
        );
        assert_eq!(inspected.action, ClientAction::Forward);
        assert!(
            inspected.tools_list_request.is_none(),
            "a tools/list notification must not be tracked"
        );
    }

    #[test]
    fn tools_list_request_with_weird_id_types_is_tracked_consistently() {
        // Object and array ids are tracked via their canonical JSON key so the
        // server's response (which echoes the same id) can be matched.
        for (line, expected_key) in [
            (
                r#"{"jsonrpc":"2.0","id":{"tag":"a"},"method":"tools/list","params":{}}"#,
                r#"{"tag":"a"}"#,
            ),
            (
                r#"{"jsonrpc":"2.0","id":[1,2],"method":"tools/list","params":{}}"#,
                "[1,2]",
            ),
            (
                r#"{"jsonrpc":"2.0","id":true,"method":"tools/list","params":{}}"#,
                "true",
            ),
        ] {
            let inspected = inspect_client_line(&policy(), "default", line);
            let request = inspected.tools_list_request.expect("tracked tools/list");
            assert_eq!(request.id_key, expected_key);
        }
    }

    #[test]
    fn duplicate_in_flight_tools_list_id_is_refcounted() {
        let mut pending = TrackedRequests::default();
        let request = TrackedRequest {
            method: TOOL_LIST_METHOD,
            id_key: "dup-1".to_string(),
        };
        pending.track(request.clone());
        pending.track(request.clone());
        assert!(pending.contains(&request));

        // First matching response only decrements; the entry stays tracked.
        assert!(!pending.remove_response(&request));
        assert!(pending.contains(&request));

        // Second matching response clears the entry.
        assert!(pending.remove_response(&request));
        assert!(!pending.contains(&request));

        // A third removal finds nothing and is a clear no-op.
        assert!(!pending.remove_response(&request));
    }

    #[test]
    fn tools_list_response_filters_denied_and_default_denied_tools() {
        let mut pending = tracked("7");
        let inspected = inspect_server_line(
            &policy(),
            "default",
            &mut pending,
            r#"{"jsonrpc":"2.0","id":7,"result":{"tools":[{"name":"filesystem.read","description":"safe"},{"name":"shell.run","description":"secret schema text"},{"name":"browser.open"}]}}"#,
        );
        let json: Value = serde_json::from_str(&inspected.line).unwrap();
        let tools = json["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "filesystem.read");
        let audit = inspected.audit.expect("audit record");
        assert_eq!(audit.event, "tools_list_filtered");
        assert_eq!(audit.original_count, Some(3));
        assert_eq!(audit.filtered_count, Some(1));
        assert_eq!(audit.allowed_tools, vec!["filesystem.read"]);
        assert!(inspected.tracking_cleared);
        assert!(pending.is_empty());
    }

    #[test]
    fn tools_list_response_with_string_id_filters_and_clears() {
        let mut pending = tracked("\"list-1\"");
        let inspected = inspect_server_line(
            &policy(),
            "default",
            &mut pending,
            r#"{"jsonrpc":"2.0","id":"list-1","result":{"tools":[{"name":"github.list_repos"},{"name":"shell.run"}]}}"#,
        );
        let json: Value = serde_json::from_str(&inspected.line).unwrap();
        let tools = json["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "github.list_repos");
        assert!(inspected.tracking_cleared);
    }

    #[test]
    fn tools_list_response_drops_tools_without_string_names() {
        let mut pending = tracked("1");
        let inspected = inspect_server_line(
            &policy(),
            "default",
            &mut pending,
            r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"github.list_repos"},{"name":7},{"description":"missing name"}]}}"#,
        );
        let json: Value = serde_json::from_str(&inspected.line).unwrap();
        let tools = json["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "github.list_repos");
        assert!(inspected.tracking_cleared);
    }

    #[test]
    fn unexpected_tools_list_shape_advertises_no_tools_and_marks_malformed() {
        let mut pending = tracked("2");
        let inspected = inspect_server_line(
            &policy(),
            "default",
            &mut pending,
            r#"{"jsonrpc":"2.0","id":2,"result":{"tools":"not-array"}}"#,
        );
        let json: Value = serde_json::from_str(&inspected.line).unwrap();
        assert_eq!(json["result"]["tools"], serde_json::json!([]));
        let audit = inspected.audit.expect("audit record");
        assert_eq!(audit.event, "tools_list_malformed");
        assert_eq!(audit.original_count, Some(0));
        assert_eq!(audit.filtered_count, Some(0));
        assert!(audit.reason.contains("fail safe"));
        assert!(inspected.tracking_cleared);
    }

    #[test]
    fn tools_list_result_missing_tools_field_passes_through_and_clears() {
        // A tracked-id response whose result object does not carry `tools` is
        // treated as an unrelated result: forwarded unchanged and tracking is
        // cleared (no fabrication of a tool list).
        let mut pending = tracked("2");
        let line = r#"{"jsonrpc":"2.0","id":2,"result":{"other":"value"}}"#;
        let inspected = inspect_server_line(&policy(), "default", &mut pending, line);
        assert_eq!(inspected.line, line);
        assert!(inspected.audit.is_none());
        assert!(inspected.tracking_cleared);
        assert!(pending.is_empty());
    }

    #[test]
    fn unrelated_tracked_id_result_passes_through_and_clears() {
        // id matches a tracked-key style but the result is not a tool list, so
        // it is forwarded unchanged and tracking is cleared (no fabrication).
        let mut pending = tracked("7");
        let line = r#"{"jsonrpc":"2.0","id":7,"result":{"other":"value"}}"#;
        let inspected = inspect_server_line(&policy(), "default", &mut pending, line);
        assert_eq!(inspected.line, line);
        assert!(inspected.audit.is_none());
        assert!(inspected.tracking_cleared);
        assert!(pending.is_empty());
    }

    #[test]
    fn server_error_for_tracked_tools_list_passes_through_and_clears() {
        let mut pending = tracked("\"err-1\"");
        let line = r#"{"jsonrpc":"2.0","id":"err-1","error":{"code":-32603,"message":"boom"}}"#;
        let inspected = inspect_server_line(&policy(), "default", &mut pending, line);
        // Error passes through unchanged.
        assert_eq!(inspected.line, line);
        assert!(inspected.audit.is_none());
        assert!(inspected.tracking_cleared);
        assert!(pending.is_empty());
    }

    #[test]
    fn non_tools_list_response_is_not_modified() {
        let mut pending = TrackedRequests::default();
        let line = r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"shell.run"}]}}"#;
        let inspected = inspect_server_line(&policy(), "default", &mut pending, line);
        assert_eq!(inspected.line, line);
        assert!(inspected.audit.is_none());
        assert!(!inspected.tracking_cleared);
    }

    #[test]
    fn response_without_id_passes_through_unchanged() {
        let mut pending = TrackedRequests::default();
        let line = r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#;
        let inspected = inspect_server_line(&policy(), "default", &mut pending, line);
        assert_eq!(inspected.line, line);
        assert!(inspected.audit.is_none());
        assert!(!inspected.tracking_cleared);
    }

    #[test]
    fn unrelated_method_response_with_same_id_style_is_not_modified() {
        // A tools/call result that reuses an id shape tracked for tools/list
        // must not be reshaped into a tool list, and tracking is cleared so the
        // entry cannot leak or match a later unrelated response.
        let mut pending = tracked("10");
        let line = r#"{"jsonrpc":"2.0","id":10,"result":{"echo_tool":"filesystem.read"}}"#;
        let inspected = inspect_server_line(&policy(), "default", &mut pending, line);
        assert_eq!(inspected.line, line);
        assert!(inspected.audit.is_none());
        assert!(inspected.tracking_cleared);
        assert!(pending.is_empty());
    }

    #[test]
    fn is_valid_json_line_accepts_and_rejects() {
        // Valid JSON (objects, arrays, primitives) is accepted.
        assert!(is_valid_json_line(r#"{"jsonrpc":"2.0","id":1}"#));
        assert!(is_valid_json_line("[1,2,3]"));
        assert!(is_valid_json_line(r#""a string""#));
        assert!(is_valid_json_line("42"));
        // Invalid JSON is rejected so the proxy can drop it before forwarding.
        assert!(!is_valid_json_line("not json at all"));
        assert!(!is_valid_json_line(r#"{"jsonrpc":"2.0","id":1"#)); // truncated
        assert!(!is_valid_json_line(""));
    }

    #[test]
    fn invalid_server_json_passes_through_unchanged() {
        // A malformed server line must reach the client unchanged so the
        // client's own parser rejects it. The proxy must never fabricate or
        // advertise a tool list from a broken server line.
        let mut pending = TrackedRequests::default();
        let line = "this is not json {{{";
        let inspected = inspect_server_line(&policy(), "default", &mut pending, line);
        assert_eq!(inspected.line, line);
        assert!(inspected.audit.is_none());
        assert!(!inspected.tracking_cleared);
    }
}
