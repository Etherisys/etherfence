use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};

use crate::audit::{redacted_argument_keys, redacted_param_keys, AuditLog, AuditRecord};
use crate::policy::{
    decide_method, decide_method_for_direction, decide_method_param_guards,
    decide_method_param_paths, decide_tool_argument_guards, decide_tool_argument_paths,
    decide_tool_call, Decision, GuardPolicyDecision, McpPolicyFile, MethodDirection,
    PathPolicyDecision,
};

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

/// What the proxy should do with one line received from the MCP server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerAction {
    /// Forward `line` to the client unchanged or after safe response filtering.
    Forward { line: String },
    /// Do not forward to the client. If the server request carried an id,
    /// `response_to_server` holds the JSON-RPC error line to send back toward
    /// the MCP server.
    Deny { response_to_server: Option<String> },
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
    pub action: ServerAction,
    pub audit: Option<AuditRecord>,
    /// Set when this response matched a tracked request and cleared its
    /// tracking entry, so the engine can emit a cleanup audit event.
    pub tracking_cleared: bool,
}

/// Inspect one newline-delimited JSON-RPC message from the client.
///
/// v0.3.0 behavior: every client→server JSON-RPC request object is inspected
/// before forwarding. The method-level policy is checked first. If the method
/// is denied, the request is never forwarded. If the method is `tools/call`
/// and is allowed by method policy, the tool-name policy is then checked as
/// before. If the method is `tools/list` and is allowed, the request is
/// tracked for response filtering. Always-allowed methods (initialize,
/// notifications/initialized, ping) bypass method policy entirely.
///
/// JSON-RPC batch arrays are not unpacked: they are denied wholesale (fail
/// closed), because a batch could smuggle a denied request past per-message
/// inspection. Non-JSON lines are forwarded unchanged (the server's parser
/// will reject them) — this preserves existing behavior and is safe because
/// the server rejects them, not the proxy.
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

    // A message without a "method" field is not a JSON-RPC request/notification
    // from the client (it might be a stray response or something else). Forward
    // it unchanged — the proxy only policy-checks client→server requests.
    let Some(method) = message.get("method").and_then(Value::as_str) else {
        return InspectedLine {
            action: ClientAction::Forward,
            audit: None,
            tools_list_request: None,
        };
    };

    let request_id = message.get("id").cloned();
    let params = message.get("params");
    let param_keys = redacted_param_keys(params);

    // --- Method-level policy check ---
    let method_decision = decide_method(policy, server_name, method);
    if method_decision.decision != Decision::Allow {
        let audit = Some(AuditRecord::method_decision(
            &policy.name,
            server_name,
            method,
            request_id.clone(),
            param_keys,
            method_decision.decision,
            &method_decision.reason,
        ));
        let response = request_id
            .filter(|id| !id.is_null())
            .map(|id| method_denied_error_response(&id, method, &method_decision.reason));
        return InspectedLine {
            action: ClientAction::Deny { response },
            audit,
            tools_list_request: None,
        };
    }

    // Method is allowed. Now handle method-specific logic.

    // tools/list: track for response filtering (only if it has a usable id).
    if method == TOOL_LIST_METHOD {
        let tools_list_request =
            message
                .get("id")
                .and_then(request_id_key)
                .map(|id_key| TrackedRequest {
                    method: TOOL_LIST_METHOD,
                    id_key,
                });
        // Audit the method allow decision.
        let audit = Some(AuditRecord::method_decision(
            &policy.name,
            server_name,
            method,
            request_id,
            param_keys,
            Decision::Allow,
            &method_decision.reason,
        ));
        return InspectedLine {
            action: ClientAction::Forward,
            audit,
            tools_list_request,
        };
    }

    // tools/call: proceed to tool-name policy check.
    if method == TOOL_CALL_METHOD {
        let tool_name = params
            .and_then(|params| params.get("name"))
            .and_then(Value::as_str);
        let arguments = params.and_then(|params| params.get("arguments"));
        let argument_keys = redacted_argument_keys(arguments);

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

        let path_decision =
            tool_for_audit.and_then(|tool| decide_tool_argument_paths(policy, tool, arguments));
        let (decision, reason) = apply_path_decision(decision, reason, path_decision.as_ref());

        // Only consult the v0.2 guard when the decision is still Allow: a
        // guard that happens to be satisfied is not a meaningful "allow"
        // signal once the call is already denied for another reason, and
        // computing/auditing it unconditionally produced confusing
        // decision/reason combinations (e.g. `decision: deny` alongside a
        // `guard_reason_category: guard_allowed`).
        let guard_decision = if decision == Decision::Allow {
            tool_for_audit
                .and_then(|tool| decide_tool_argument_guards(policy, server_name, tool, arguments))
        } else {
            None
        };
        let (decision, reason) = apply_guard_decision(decision, reason, guard_decision.as_ref());

        let mut audit = AuditRecord::tool_call(
            &policy.name,
            server_name,
            request_id.clone(),
            tool_for_audit,
            argument_keys,
            decision,
            &reason,
        );
        if let Some(path_decision) = path_decision.as_ref() {
            audit = audit.with_path_metadata(
                &path_decision.rule_name,
                &path_decision.key_name,
                &path_decision.classification,
            );
        }
        if let Some(guard_decision) = guard_decision.as_ref() {
            audit = audit.with_guard_metadata(
                &guard_decision.guard_key,
                &guard_decision.selector,
                &guard_decision.reason_category,
            );
        }
        let audit = Some(audit);

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
    } else {
        // Any other allowed method (resources/list, resources/read, prompts/list,
        // prompts/get, completion/complete, roots/list, sampling/createMessage,
        // or custom methods): forward and audit the method allow decision.
        //
        // The v0.1 path/URI guard remains scoped to resources/read only, exactly
        // as before. The v0.2 params guard (require_keys/forbid_keys/fields) is
        // new capability and applies to any method with a configured guard.
        let path_decision = if method == "resources/read" {
            decide_method_param_paths(policy, method, params)
        } else {
            None
        };
        let (decision, reason) = apply_path_decision(
            Decision::Allow,
            method_decision.reason.clone(),
            path_decision.as_ref(),
        );
        let guard_decision = if decision == Decision::Allow {
            decide_method_param_guards(policy, server_name, method, params)
        } else {
            None
        };
        let (decision, reason) = apply_guard_decision(decision, reason, guard_decision.as_ref());
        let mut audit = AuditRecord::method_decision(
            &policy.name,
            server_name,
            method,
            request_id.clone(),
            param_keys,
            decision,
            &reason,
        );
        if let Some(path_decision) = path_decision.as_ref() {
            audit = audit.with_path_metadata(
                &path_decision.rule_name,
                &path_decision.key_name,
                &path_decision.classification,
            );
        }
        if let Some(guard_decision) = guard_decision.as_ref() {
            audit = audit.with_guard_metadata(
                &guard_decision.guard_key,
                &guard_decision.selector,
                &guard_decision.reason_category,
            );
        }
        match decision {
            Decision::Allow => InspectedLine {
                action: ClientAction::Forward,
                audit: Some(audit),
                tools_list_request: None,
            },
            Decision::Deny | Decision::PolicyError => {
                let response = request_id
                    .filter(|id| !id.is_null())
                    .map(|id| method_denied_error_response(&id, method, &reason));
                InspectedLine {
                    action: ClientAction::Deny { response },
                    audit: Some(audit),
                    tools_list_request: None,
                }
            }
        }
    }
}

fn apply_path_decision(
    base_decision: Decision,
    base_reason: String,
    path_decision: Option<&PathPolicyDecision>,
) -> (Decision, String) {
    match (base_decision, path_decision) {
        (Decision::Allow, Some(path_decision)) => {
            (path_decision.decision, path_decision.reason.clone())
        }
        _ => (base_decision, base_reason),
    }
}

/// v0.2 counterpart to [`apply_path_decision`]: a guard decision can only
/// narrow a still-`Allow` base decision (v0.1 path precedence — see
/// research.md Decision 7). If the base decision is already `Deny` (from
/// the tool/method or v0.1 path guard), the v0.2 guard is not consulted and
/// that decision/reason stands unchanged.
fn apply_guard_decision(
    base_decision: Decision,
    base_reason: String,
    guard_decision: Option<&GuardPolicyDecision>,
) -> (Decision, String) {
    match (base_decision, guard_decision) {
        (Decision::Allow, Some(guard_decision)) => {
            (guard_decision.decision, guard_decision.reason.clone())
        }
        _ => (base_decision, base_reason),
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
            action: ServerAction::Forward {
                line: line.to_string(),
            },
            audit: None,
            tracking_cleared: false,
        };
    };

    if message.is_array() {
        let reason =
            "fail closed: server-to-client JSON-RPC batch arrays are not inspected by this proxy";
        return InspectedServerLine {
            action: ServerAction::Deny {
                response_to_server: Some(batch_denied_response(reason)),
            },
            audit: Some(AuditRecord::batch_denied_with_direction(
                &policy.name,
                server_name,
                MethodDirection::ServerToClient.as_str(),
                reason,
            )),
            tracking_cleared: false,
        };
    }

    // A server output object with a method is a server→client JSON-RPC request
    // or notification. Inspect it before forwarding so client-feature methods
    // such as sampling/createMessage, roots/list, and elicitation/create can be
    // denied before they reach the client.
    if let Some(method) = message.get("method").and_then(Value::as_str) {
        let request_id = message.get("id").cloned();
        let params = message.get("params");
        let param_keys = redacted_param_keys(params);
        let method_decision = decide_method_for_direction(
            policy,
            server_name,
            MethodDirection::ServerToClient,
            method,
        );
        // v0.2 params guard: new, purely additive capability for the
        // server→client direction (v0.1 never guarded params here at all).
        // Only consulted when the method decision is still Allow, matching
        // the same "guards only narrow" precedence used client→server.
        let guard_decision = if method_decision.decision == Decision::Allow {
            decide_method_param_guards(policy, server_name, method, params)
        } else {
            None
        };
        let (decision, reason) = apply_guard_decision(
            method_decision.decision,
            method_decision.reason.clone(),
            guard_decision.as_ref(),
        );
        let mut audit = AuditRecord::method_decision_with_direction(
            &policy.name,
            server_name,
            MethodDirection::ServerToClient.as_str(),
            method,
            request_id.clone(),
            param_keys,
            decision,
            &reason,
        );
        if let Some(guard_decision) = guard_decision.as_ref() {
            audit = audit.with_guard_metadata(
                &guard_decision.guard_key,
                &guard_decision.selector,
                &guard_decision.reason_category,
            );
        }
        let audit = Some(audit);
        if decision != Decision::Allow {
            let response_to_server = request_id
                .filter(|id| !id.is_null())
                .map(|id| method_denied_error_response(&id, method, &reason));
            return InspectedServerLine {
                action: ServerAction::Deny { response_to_server },
                audit,
                tracking_cleared: false,
            };
        }
        return InspectedServerLine {
            action: ServerAction::Forward {
                line: line.to_string(),
            },
            audit,
            tracking_cleared: false,
        };
    }

    // Responses without an id cannot be matched to a tracked request, so they
    // pass through unchanged. This is a documented safe default: the proxy only
    // re-shapes responses it can tie back to a tracked tools/list request.
    let Some(id) = message.get("id") else {
        return InspectedServerLine {
            action: ServerAction::Forward {
                line: line.to_string(),
            },
            audit: None,
            tracking_cleared: false,
        };
    };
    let Some(id_key) = request_id_key(id) else {
        // A null id (JSON-RPC error/result with id:null) is never tracked.
        return InspectedServerLine {
            action: ServerAction::Forward {
                line: line.to_string(),
            },
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
            action: ServerAction::Forward {
                line: line.to_string(),
            },
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
            action: ServerAction::Forward {
                line: line.to_string(),
            },
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
            action: ServerAction::Forward {
                line: line.to_string(),
            },
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
            action: ServerAction::Forward {
                line: message.to_string(),
            },
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
        action: ServerAction::Forward {
            line: message.to_string(),
        },
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
    let tool_name = if reason.starts_with("unicode_") {
        "<unicode-denied-tool>"
    } else {
        tool_name
    };
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

/// JSON-RPC error response for a method denied by method-level policy.
/// The request id is preserved so the client can match the error to its
/// request. The method name and reason are included in `data` for
/// diagnostics.
fn method_denied_error_response(request_id: &Value, method: &str, reason: &str) -> String {
    let method = if reason.starts_with("unicode_") {
        "<unicode-denied-method>"
    } else {
        method
    };
    json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": DENIED_ERROR_CODE,
            "message": "EtherFence MCP proxy denied this method by policy",
            "data": {
                "method": method,
                "reason": reason,
            },
        },
    })
    .to_string()
}

/// Run the stdio boundary proxy until the client closes its input stream, the
/// child server exits, or a fatal proxy error occurs.
///
/// `etherfence-mcp` is a library: it never calls `std::process::exit`, even
/// on a fatal error, because doing so would let a misbehaving MCP server
/// (an oversized frame, invalid UTF-8, a client-output failure) terminate
/// the *entire host process* embedding this crate — including processes
/// that run multiple proxies, need to flush their own logs, or run
/// destructors before exiting. Every fatal condition is instead reported
/// through this function's `Result`.
///
/// Lifecycle guarantees:
/// - The child server is spawned before any client traffic is inspected.
/// - On a clean client EOF the proxy closes the server's stdin so the child can
///   exit, joins the server-to-client pump, waits for the child, and returns
///   its exit code (usually 0).
/// - If the child exits first (early exit, crash), the server pump stops, the
///   client's stdin is closed, and `Err(ProxyError::ChildExited(code))` is
///   returned so the caller can propagate the child's code.
/// - A fatal error in the client→server pump (bad read, hard write failure)
///   always kills the child before the client loop returns, so the
///   server→client pump — which may be blocked reading from a child that is
///   still waiting on stdin — is guaranteed to unblock instead of leaving the
///   proxy's scoped-thread join hanging forever.
/// - A fatal error in the server→client pump (an oversized/invalid server
///   frame, a hard write failure) kills the child and this function returns
///   `Err`. That pump runs on a background thread while the client→server
///   pump may be blocked in a plain blocking read on the client's own input
///   stream with no portable way to interrupt it from another thread, so
///   `run_proxy` cannot always return promptly: it still waits for both
///   pumps to finish, which for a non-interruptible foreground reader (real
///   process stdin, in particular) may not happen until that reader also
///   unblocks on its own. `on_fatal_error`, when supplied, is invoked from
///   the background pump thread *as soon as* such an error occurs — before
///   `run_proxy` itself can return — so a caller that owns the whole
///   process (a CLI) and needs a hard guarantee of immediate termination
///   can act (e.g. `std::process::exit`) from inside that callback instead
///   of waiting on the `Result`. A library embedder that owns an
///   interruptible client reader can instead simply react to the returned
///   `ProxyError` and does not need to supply a callback.
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
    on_fatal_error: Option<&(dyn Fn(&ProxyError) + Sync)>,
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
    let server_in = child
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
    let server_in = Arc::new(Mutex::new(Some(server_in)));
    let child = Arc::new(Mutex::new(child));

    let pump_result = std::thread::scope(|scope| -> std::result::Result<(), ProxyError> {
        let server_to_client = scope.spawn(|| {
            pump_server_to_client(
                server_out,
                &client_out,
                policy,
                server_name,
                &pending_requests,
                &audit_log,
                &server_in,
                &child,
                on_fatal_error,
            )
        });

        let mut client_in = client_in;
        let mut client_frame = Vec::new();
        let mut client_result: std::result::Result<(), ProxyError> = Ok(());
        'client: loop {
            let line = match read_bounded_frame(&mut client_in, &mut client_frame) {
                Ok(Some(line)) => line,
                Ok(None) => break 'client,
                Err(error) => {
                    client_result = Err(ProxyError::ClientRead(format!("{error:?}")));
                    break 'client;
                }
            };
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
                ClientAction::Forward => match write_to_server(&server_in, &line) {
                    Ok(true) => {}
                    Ok(false) => {
                        // Server pipe closed while we were forwarding: stop the
                        // client loop cleanly and let the server pump finish.
                        break 'client;
                    }
                    Err(error) => {
                        client_result = Err(error);
                        break 'client;
                    }
                },
                ClientAction::Deny { response } => {
                    if let Some(response) = response {
                        let mut out = client_out.lock().expect("client output lock");
                        match writeln!(out, "{response}") {
                            Ok(()) => {
                                if let Err(error) = out.flush() {
                                    drop(out);
                                    client_result =
                                        Err(ProxyError::ClientWrite(format!("{error:?}")));
                                    break 'client;
                                }
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => {
                                // Client closed its output: stop cleanly.
                                drop(out);
                                break 'client;
                            }
                            Err(error) => {
                                drop(out);
                                client_result = Err(ProxyError::ClientWrite(format!("{error:?}")));
                                break 'client;
                            }
                        }
                    }
                }
            }
        }

        // The client loop is done, whether by clean EOF, a clean break (server
        // pipe closed), or a fatal error. On a fatal error, do not trust the
        // child to notice stdin EOF and exit on its own: kill it outright so a
        // still-live server cannot leave the server-to-client pump blocked
        // reading from it forever.
        if client_result.is_err() {
            let _ = child.lock().expect("child lock").kill();
        }
        // Close the server's stdin so a well-behaved child receives EOF and can
        // exit. The server pump only borrows this handle briefly when it must
        // answer denied server→client requests, so setting it to None closes
        // the write end and avoids keeping the child alive accidentally.
        *server_in.lock().expect("server input lock") = None;
        let server_result = server_to_client
            .join()
            .expect("server-to-client pump thread");
        client_result?;
        server_result
    });

    // Reap the child no matter what happened above.
    let child_status = wait_for_child(&mut child.lock().expect("child lock"));
    pump_result?;
    child_status
}

/// Handle a fatal server→client pump failure without terminating the process.
///
/// This pump runs on a background thread while the client→server pump may be
/// blocked in a plain blocking read on the client's own input stream (in
/// production, the process's real stdin), which has no portable way to be
/// interrupted from another thread. Killing the child here cannot unblock
/// that read, so `run_proxy` itself may not return until the foreground
/// reader also unblocks on its own — but this function never calls
/// `std::process::exit` to force the issue, because `etherfence-mcp` is a
/// library and doing so would terminate the whole embedding process instead
/// of just this proxy. The child is killed and reaped here so it is never
/// left running while `run_proxy` waits to return, and `on_fatal_error` (if
/// supplied) is invoked immediately so a caller that owns the process — and
/// so can safely decide to terminate it — does not have to wait either.
fn handle_fatal_server_pump_error(
    child: &Arc<Mutex<Child>>,
    on_fatal_error: Option<&(dyn Fn(&ProxyError) + Sync)>,
    error: ProxyError,
) -> ProxyError {
    if let Ok(mut child) = child.lock() {
        let _ = child.kill();
        let _ = child.wait();
    }
    eprintln!("etherfence mcp-proxy: {}", error.message());
    if let Some(on_fatal_error) = on_fatal_error {
        on_fatal_error(&error);
    }
    error
}

#[allow(clippy::too_many_arguments)]
fn pump_server_to_client<ClientOut: Write>(
    server_out: std::process::ChildStdout,
    client_out: &Mutex<ClientOut>,
    policy: &McpPolicyFile,
    server_name: &str,
    pending_requests: &Arc<Mutex<TrackedRequests>>,
    audit_log: &Arc<Mutex<Option<AuditLog>>>,
    server_in: &Arc<Mutex<Option<std::process::ChildStdin>>>,
    child: &Arc<Mutex<Child>>,
    on_fatal_error: Option<&(dyn Fn(&ProxyError) + Sync)>,
) -> std::result::Result<(), ProxyError> {
    let mut reader = BufReader::new(server_out);
    let mut server_frame = Vec::new();
    loop {
        let line = match read_bounded_frame(&mut reader, &mut server_frame) {
            Ok(Some(line)) => line,
            Ok(None) => return Ok(()),
            Err(error) => {
                return Err(handle_fatal_server_pump_error(
                    child,
                    on_fatal_error,
                    ProxyError::ServerRead(format!("{error:?}")),
                ))
            }
        };
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
        match inspected.action {
            ServerAction::Forward { line } => {
                let mut out = client_out.lock().expect("client output lock");
                match writeln!(out, "{line}") {
                    Ok(()) => {
                        if let Err(error) = out.flush() {
                            drop(out);
                            return Err(handle_fatal_server_pump_error(
                                child,
                                on_fatal_error,
                                ProxyError::ClientWrite(format!("{error:?}")),
                            ));
                        }
                    }
                    // Client closed its output: stop the server pump cleanly.
                    Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => return Ok(()),
                    Err(error) => {
                        drop(out);
                        return Err(handle_fatal_server_pump_error(
                            child,
                            on_fatal_error,
                            ProxyError::ClientWrite(format!("{error:?}")),
                        ));
                    }
                }
            }
            ServerAction::Deny { response_to_server } => {
                if let Some(response) = response_to_server {
                    if let Err(error) = write_to_server(server_in, &response) {
                        return Err(handle_fatal_server_pump_error(child, on_fatal_error, error));
                    }
                }
            }
        }
    }
}

fn write_to_server(
    server_in: &Arc<Mutex<Option<std::process::ChildStdin>>>,
    line: &str,
) -> std::result::Result<bool, ProxyError> {
    let mut guard = server_in.lock().expect("server input lock");
    let Some(server_in) = guard.as_mut() else {
        return Ok(false);
    };
    match writeln!(server_in, "{line}") {
        Ok(()) => server_in
            .flush()
            .map(|()| true)
            .map_err(|error| ProxyError::ServerWrite(format!("{error:?}"))),
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(false),
        Err(error) => Err(ProxyError::ServerWrite(format!("{error:?}"))),
    }
}

fn wait_for_child(child: &mut Child) -> std::result::Result<i32, ProxyError> {
    let status = child.wait().map_err(|error| {
        ProxyError::ServerRead(format!("waiting for MCP server child: {error:?}"))
    })?;
    Ok(status.code().unwrap_or(1))
}

/// Maximum size of a single newline-delimited JSON-RPC frame the proxy will
/// buffer from either side of the boundary. A frame larger than this fails
/// closed (the affected pump aborts and the proxy shuts down) instead of
/// letting an untrusted client or wrapped server drive the proxy — the one
/// runtime-enforcement component — to out-of-memory. `BufRead::lines()` /
/// `read_line` grow without bound, so they must not be used on this hot path.
const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

/// Read one newline-delimited frame into `buf`, bounded to `MAX_FRAME_BYTES`.
///
/// Returns `Ok(None)` at EOF, `Ok(Some(line))` for a frame terminated by a
/// newline or by EOF, and an `InvalidData` error (fail closed) when a single
/// frame exceeds the cap or is not strictly valid UTF-8.
///
/// UTF-8 validity is intentionally strict (`String::from_utf8`, not
/// `String::from_utf8_lossy`): lossy replacement rewrites invalid bytes to
/// U+FFFD in place, and an invalid byte inside an otherwise well-formed JSON
/// string does not necessarily make the surrounding message invalid JSON —
/// the rewritten message can still parse and would then be forwarded across
/// the trust boundary with altered content. Rejecting the frame outright
/// keeps the boundary from ever changing bytes it forwards.
fn read_bounded_frame<R: BufRead>(
    reader: &mut R,
    buf: &mut Vec<u8>,
) -> std::io::Result<Option<String>> {
    buf.clear();
    let read = reader
        .by_ref()
        .take(MAX_FRAME_BYTES as u64 + 1)
        .read_until(b'\n', buf)?;
    if read == 0 {
        return Ok(None);
    }
    if buf.len() > MAX_FRAME_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "JSON-RPC frame exceeds maximum size",
        ));
    }
    if buf.last() == Some(&b'\n') {
        buf.pop();
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
    }
    String::from_utf8(std::mem::take(buf))
        .map(Some)
        .map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("JSON-RPC frame contains invalid UTF-8: {error}"),
            )
        })
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

    #[test]
    fn bounded_frame_reads_lines_and_stops_at_eof() {
        let data = b"{\"a\":1}\n{\"b\":2}\n".to_vec();
        let mut reader = std::io::BufReader::new(&data[..]);
        let mut buf = Vec::new();
        assert_eq!(
            read_bounded_frame(&mut reader, &mut buf).unwrap(),
            Some("{\"a\":1}".to_string())
        );
        assert_eq!(
            read_bounded_frame(&mut reader, &mut buf).unwrap(),
            Some("{\"b\":2}".to_string())
        );
        assert_eq!(read_bounded_frame(&mut reader, &mut buf).unwrap(), None);
    }

    #[test]
    fn bounded_frame_trims_crlf() {
        let data = b"hello\r\n".to_vec();
        let mut reader = std::io::BufReader::new(&data[..]);
        let mut buf = Vec::new();
        assert_eq!(
            read_bounded_frame(&mut reader, &mut buf).unwrap(),
            Some("hello".to_string())
        );
    }

    #[test]
    fn bounded_frame_fails_closed_on_oversized_frame() {
        // A single newline-less frame larger than the cap must error rather
        // than allocate without bound (memory-exhaustion DoS on the boundary).
        let data = vec![b'x'; MAX_FRAME_BYTES + 16];
        let mut reader = std::io::BufReader::new(&data[..]);
        let mut buf = Vec::new();
        let err = read_bounded_frame(&mut reader, &mut buf).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn bounded_frame_fails_closed_on_invalid_utf8_inside_json_string() {
        // A single invalid byte planted inside an otherwise well-formed JSON
        // string. Lossy conversion would rewrite it to U+FFFD and the message
        // would still parse as valid JSON, silently changing bytes crossing
        // the trust boundary. Strict UTF-8 must reject the whole frame.
        let mut data =
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"#.to_vec();
        data.push(0xFF);
        data.extend_from_slice(br#""}}"#);
        data.push(b'\n');
        let mut reader = std::io::BufReader::new(&data[..]);
        let mut buf = Vec::new();
        let err = read_bounded_frame(&mut reader, &mut buf).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

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

    fn forwarded_line(inspected: &InspectedServerLine) -> &str {
        match &inspected.action {
            ServerAction::Forward { line } => line,
            ServerAction::Deny { .. } => panic!("expected forwarded server line"),
        }
    }

    #[test]
    fn non_tool_call_messages_are_forwarded() {
        let inspected = inspect_client_line(
            &policy(),
            "default",
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        );
        assert_eq!(inspected.action, ClientAction::Forward);
        // v0.3.0: method decisions are now audited.
        let audit = inspected.audit.expect("method audit for initialize");
        assert_eq!(audit.event, "method_decision");
        assert_eq!(audit.method.as_deref(), Some("initialize"));
        assert_eq!(audit.decision, "allow");
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
    fn client_to_server_non_ascii_method_is_denied_before_matching() {
        let inspected = inspect_client_line(
            &policy(),
            "default",
            r#"{"jsonrpc":"2.0","id":15,"method":"tοols/call","params":{"name":"filesystem.read","pro\u202empt":"value"}}"#,
        );
        let ClientAction::Deny {
            response: Some(response),
        } = inspected.action
        else {
            panic!("expected Unicode method deny");
        };
        let json: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(json["error"]["data"]["method"], "<unicode-denied-method>");
        assert_eq!(json["error"]["data"]["reason"], "unicode_non_ascii_method");
        assert!(!response.contains("tοols/call"));
        let audit = inspected.audit.expect("audit record");
        assert_eq!(audit.reason, "unicode_non_ascii_method");
        assert_eq!(audit.method.as_deref(), Some("<unicode-denied-method>"));
        assert_eq!(audit.param_keys, vec!["<unicode-denied-key>", "name"]);
        let audit_line = serde_json::to_string(&audit).unwrap();
        assert!(!audit_line.contains("pro\u{202E}mpt"));
        assert!(!audit_line.contains("pro\\u202empt"));
    }

    #[test]
    fn tools_call_tool_name_with_zero_width_or_bidi_is_denied() {
        let zero_width_line = format!(
            r#"{{"jsonrpc":"2.0","id":16,"method":"tools/call","params":{{"name":"filesystem.{}read","arguments":{{"sec\u202eret":"value"}}}}}}"#,
            "\u{200B}"
        );
        for (line, reason) in [
            (zero_width_line.as_str(), "unicode_zero_width_detected"),
            (
                r#"{"jsonrpc":"2.0","id":17,"method":"tools/call","params":{"name":"filesystem.\u202eread","arguments":{"sec\u202eret":"value"}}}"#,
                "unicode_bidi_control_detected",
            ),
        ] {
            let inspected = inspect_client_line(&policy(), "default", line);
            let ClientAction::Deny {
                response: Some(response),
            } = inspected.action
            else {
                panic!("expected Unicode tool deny");
            };
            let json: Value = serde_json::from_str(&response).unwrap();
            assert_eq!(json["error"]["data"]["tool"], "<unicode-denied-tool>");
            assert_eq!(json["error"]["data"]["reason"], reason);
            let audit = inspected.audit.expect("audit record");
            assert_eq!(audit.reason, reason);
            assert_eq!(audit.tool.as_deref(), Some("<unicode-denied-tool>"));
            assert_eq!(audit.argument_keys, vec!["<unicode-denied-key>"]);
            let audit_line = serde_json::to_string(&audit).unwrap();
            assert!(!audit_line.contains("sec\u{202E}ret"));
            assert!(!audit_line.contains("sec\\u202eret"));
        }
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
        // v0.3.0: method decisions are now audited.
        let audit = inspected.audit.expect("method audit for tools/list");
        assert_eq!(audit.event, "method_decision");
        assert_eq!(audit.decision, "allow");
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
        let json: Value = serde_json::from_str(forwarded_line(&inspected)).unwrap();
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
        let json: Value = serde_json::from_str(forwarded_line(&inspected)).unwrap();
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
        let json: Value = serde_json::from_str(forwarded_line(&inspected)).unwrap();
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
        let json: Value = serde_json::from_str(forwarded_line(&inspected)).unwrap();
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
        assert_eq!(forwarded_line(&inspected), line);
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
        assert_eq!(forwarded_line(&inspected), line);
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
        assert_eq!(forwarded_line(&inspected), line);
        assert!(inspected.audit.is_none());
        assert!(inspected.tracking_cleared);
        assert!(pending.is_empty());
    }

    #[test]
    fn non_tools_list_response_is_not_modified() {
        let mut pending = TrackedRequests::default();
        let line = r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"shell.run"}]}}"#;
        let inspected = inspect_server_line(&policy(), "default", &mut pending, line);
        assert_eq!(forwarded_line(&inspected), line);
        assert!(inspected.audit.is_none());
        assert!(!inspected.tracking_cleared);
    }

    #[test]
    fn response_without_id_passes_through_unchanged() {
        let mut pending = TrackedRequests::default();
        let line = r#"{"jsonrpc":"2.0","result":{"status":"ok"}}"#;
        let inspected = inspect_server_line(&policy(), "default", &mut pending, line);
        assert_eq!(forwarded_line(&inspected), line);
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
        assert_eq!(forwarded_line(&inspected), line);
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
        assert_eq!(forwarded_line(&inspected), line);
        assert!(inspected.audit.is_none());
        assert!(!inspected.tracking_cleared);
    }

    // --- v0.3.0 method-level policy tests ---

    fn method_policy() -> McpPolicyFile {
        parse_mcp_policy(
            r#"
schema_version = "ef-mcp-policy/v0.1"
name = "method-test"

[methods]
allow = ["tools/list", "tools/call", "resources/list", "resources/read"]
deny = ["sampling/createMessage", "prompts/get"]

[tools]
allow = ["filesystem.read"]
"#,
        )
        .expect("valid method test policy")
    }

    #[test]
    fn denied_method_is_not_forwarded() {
        let inspected = inspect_client_line(
            &method_policy(),
            "default",
            r#"{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","params":{"messages":[{"role":"user","content":"secret prompt text"}]}}"#,
        );
        let ClientAction::Deny { response } = inspected.action else {
            panic!("expected deny for sampling/createMessage");
        };
        let response = response.expect("error response for denied method with id");
        let json: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(json["id"], 1);
        assert_eq!(json["error"]["code"], DENIED_ERROR_CODE);
        assert_eq!(json["error"]["data"]["method"], "sampling/createMessage");
        // Sensitive param content must not appear in the response or audit.
        assert!(!response.contains("secret prompt text"));
        let audit = inspected.audit.expect("audit record");
        assert_eq!(audit.event, "method_decision");
        assert_eq!(audit.decision, "deny");
        assert_eq!(audit.method.as_deref(), Some("sampling/createMessage"));
        // Param keys are safe metadata; values are not logged.
        assert_eq!(audit.param_keys, vec!["messages"]);
        assert!(!audit.reason.contains("secret"));
    }

    #[test]
    fn denied_resources_read_is_not_forwarded_by_default() {
        let inspected = inspect_client_line(
            &policy(), // no [methods] section → built-in default
            "default",
            r#"{"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"file:///etc/passwd"}}"#,
        );
        assert!(matches!(inspected.action, ClientAction::Deny { .. }));
        let audit = inspected.audit.expect("audit record");
        assert_eq!(audit.event, "method_decision");
        assert_eq!(audit.decision, "deny");
        assert_eq!(audit.param_keys, vec!["uri"]);
    }

    #[test]
    fn allowed_resources_read_is_forwarded() {
        let inspected = inspect_client_line(
            &method_policy(),
            "default",
            r#"{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"file:///safe/path"}}"#,
        );
        assert_eq!(inspected.action, ClientAction::Forward);
        let audit = inspected.audit.expect("audit record");
        assert_eq!(audit.event, "method_decision");
        assert_eq!(audit.decision, "allow");
        assert_eq!(audit.param_keys, vec!["uri"]);
        assert!(inspected.tools_list_request.is_none());
    }

    #[test]
    fn denied_prompts_get_is_not_forwarded() {
        let inspected = inspect_client_line(
            &method_policy(),
            "default",
            r#"{"jsonrpc":"2.0","id":4,"method":"prompts/get","params":{"name":"system_prompt","arguments":{"user_input":"secret data"}}}"#,
        );
        assert!(matches!(inspected.action, ClientAction::Deny { .. }));
        let audit = inspected.audit.expect("audit record");
        assert_eq!(audit.decision, "deny");
        assert_eq!(audit.param_keys, vec!["arguments", "name"]);
        // Sensitive content must not leak.
        let response = match inspected.action {
            ClientAction::Deny { response } => response,
            _ => unreachable!(),
        };
        assert!(response.is_some());
        assert!(!response.unwrap().contains("secret data"));
    }

    #[test]
    fn unknown_method_is_not_forwarded_by_default() {
        let inspected = inspect_client_line(
            &policy(),
            "default",
            r#"{"jsonrpc":"2.0","id":5,"method":"some/custom/method","params":{"data":"x"}}"#,
        );
        assert!(matches!(inspected.action, ClientAction::Deny { .. }));
        let audit = inspected.audit.expect("audit record");
        assert_eq!(audit.decision, "deny");
        assert!(audit.reason.contains("built-in default"));
    }

    #[test]
    fn unknown_method_denied_with_explicit_methods_section() {
        let inspected = inspect_client_line(
            &method_policy(),
            "default",
            r#"{"jsonrpc":"2.0","id":6,"method":"unknown/method","params":{}}"#,
        );
        assert!(matches!(inspected.action, ClientAction::Deny { .. }));
        let audit = inspected.audit.expect("audit record");
        assert_eq!(audit.decision, "deny");
        assert!(audit
            .reason
            .contains("not in the server-specific or global"));
    }

    #[test]
    fn denied_method_notification_without_id_has_no_response() {
        let inspected = inspect_client_line(
            &method_policy(),
            "default",
            r#"{"jsonrpc":"2.0","method":"sampling/createMessage","params":{}}"#,
        );
        assert_eq!(inspected.action, ClientAction::Deny { response: None });
        let audit = inspected.audit.expect("audit record");
        assert_eq!(audit.decision, "deny");
        assert_eq!(audit.request_id_type.as_deref(), Some("missing"));
    }

    #[test]
    fn always_allowed_methods_bypass_method_policy() {
        let strict_policy = parse_mcp_policy(
            r#"
schema_version = "ef-mcp-policy/v0.1"
name = "strict"

[methods]
allow = []
deny = ["initialize", "notifications/initialized", "ping"]
"#,
        )
        .unwrap();
        for (method, line) in [
            (
                "initialize",
                r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
            ),
            (
                "notifications/initialized",
                r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#,
            ),
            (
                "ping",
                r#"{"jsonrpc":"2.0","id":2,"method":"ping","params":{}}"#,
            ),
        ] {
            let inspected = inspect_client_line(&strict_policy, "default", line);
            assert_eq!(
                inspected.action,
                ClientAction::Forward,
                "always-allowed {method} should forward"
            );
            let audit = inspected.audit.expect("audit");
            assert_eq!(audit.decision, "allow");
            assert!(audit.reason.contains("always allowed"));
        }
    }

    #[test]
    fn method_denied_response_preserves_request_id() {
        let inspected = inspect_client_line(
            &method_policy(),
            "default",
            r#"{"jsonrpc":"2.0","id":"my-id-42","method":"prompts/get","params":{}}"#,
        );
        let ClientAction::Deny {
            response: Some(response),
        } = inspected.action
        else {
            panic!("expected deny with response");
        };
        let json: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(json["id"], "my-id-42");
        assert_eq!(json["error"]["code"], DENIED_ERROR_CODE);
        assert_eq!(json["error"]["data"]["method"], "prompts/get");
    }

    #[test]
    fn tools_list_filtering_still_works_with_method_policy() {
        let mut pending = tracked("10");
        let inspected = inspect_server_line(
            &method_policy(),
            "default",
            &mut pending,
            r#"{"jsonrpc":"2.0","id":10,"result":{"tools":[{"name":"filesystem.read"},{"name":"shell.run"}]}}"#,
        );
        let json: Value = serde_json::from_str(forwarded_line(&inspected)).unwrap();
        let tools = json["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "filesystem.read");
    }

    #[test]
    fn tools_call_existing_behavior_still_works_with_method_policy() {
        let inspected = inspect_client_line(
            &method_policy(),
            "default",
            r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"filesystem.read","arguments":{"path":"/x"}}}"#,
        );
        assert_eq!(inspected.action, ClientAction::Forward);
        let audit = inspected.audit.expect("audit");
        assert_eq!(audit.event, "tool_call_decision");
        assert_eq!(audit.decision, "allow");
        assert_eq!(audit.tool.as_deref(), Some("filesystem.read"));
    }

    #[test]
    fn tools_call_denied_tool_still_denied_with_method_policy() {
        let inspected = inspect_client_line(
            &method_policy(),
            "default",
            r#"{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"shell.run","arguments":{}}}"#,
        );
        assert!(matches!(inspected.action, ClientAction::Deny { .. }));
        let audit = inspected.audit.expect("audit");
        assert_eq!(audit.event, "tool_call_decision");
        assert_eq!(audit.decision, "deny");
    }

    #[test]
    fn batch_arrays_remain_denied_with_method_policy() {
        let inspected = inspect_client_line(
            &method_policy(),
            "default",
            r#"[{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}]"#,
        );
        assert!(matches!(inspected.action, ClientAction::Deny { .. }));
        let audit = inspected.audit.expect("audit");
        assert_eq!(audit.event, "batch_denied");
    }

    #[test]
    fn wildcard_allow_lets_unknown_method_through() {
        let wildcard_policy = parse_mcp_policy(
            r#"
schema_version = "ef-mcp-policy/v0.1"
name = "wildcard"

[methods]
allow = ["*"]
deny = ["sampling/createMessage"]
"#,
        )
        .unwrap();
        let inspected = inspect_client_line(
            &wildcard_policy,
            "default",
            r#"{"jsonrpc":"2.0","id":9,"method":"custom/method","params":{}}"#,
        );
        assert_eq!(inspected.action, ClientAction::Forward);
        let audit = inspected.audit.expect("audit");
        assert_eq!(audit.decision, "allow");
        assert!(audit.reason.contains("wildcard"));
    }

    #[test]
    fn server_to_client_non_ascii_method_is_denied_before_forwarding() {
        let inspected = inspect_server_line(
            &method_policy(),
            "default",
            &mut TrackedRequests::default(),
            r#"{"jsonrpc":"2.0","id":"srv-unicode","method":"rοots/list","params":{"cursor":"secret cursor"}}"#,
        );
        let ServerAction::Deny {
            response_to_server: Some(response),
        } = inspected.action
        else {
            panic!("expected server-to-client Unicode method denial");
        };
        let json: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(json["error"]["data"]["method"], "<unicode-denied-method>");
        assert_eq!(json["error"]["data"]["reason"], "unicode_non_ascii_method");
        assert!(!response.contains("rοots/list"));
        assert!(!response.contains("secret cursor"));
        let audit = inspected.audit.expect("audit");
        assert_eq!(audit.direction.as_deref(), Some("server_to_client"));
        assert_eq!(audit.method.as_deref(), Some("<unicode-denied-method>"));
        assert_eq!(audit.reason, "unicode_non_ascii_method");
        assert_eq!(audit.param_keys, vec!["cursor"]);
    }

    #[test]
    fn server_to_client_allowed_method_is_forwarded_and_audited_with_direction() {
        let allow_policy = parse_mcp_policy(
            r#"
schema_version = "ef-mcp-policy/v0.1"
name = "allow-roots"

[methods]
allow = ["roots/list"]
"#,
        )
        .unwrap();
        let inspected = inspect_server_line(
            &allow_policy,
            "default",
            &mut TrackedRequests::default(),
            r#"{"jsonrpc":"2.0","id":"roots-1","method":"roots/list","params":{"cursor":"secret-cursor"}}"#,
        );
        assert!(matches!(inspected.action, ServerAction::Forward { .. }));
        let audit = inspected.audit.expect("audit");
        assert_eq!(audit.event, "method_decision");
        assert_eq!(audit.direction.as_deref(), Some("server_to_client"));
        assert_eq!(audit.method.as_deref(), Some("roots/list"));
        assert_eq!(audit.decision, "allow");
        assert_eq!(audit.param_keys, vec!["cursor"]);
    }

    #[test]
    fn server_to_client_denied_method_is_dropped_with_error_to_server() {
        let inspected = inspect_server_line(
            &method_policy(),
            "default",
            &mut TrackedRequests::default(),
            r#"{"jsonrpc":"2.0","id":"sample-1","method":"sampling/createMessage","params":{"messages":[{"role":"user","content":"secret prompt"}]}}"#,
        );
        let ServerAction::Deny {
            response_to_server: Some(response),
        } = inspected.action
        else {
            panic!("expected server-to-client denial response to server");
        };
        let json: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(json["id"], "sample-1");
        assert_eq!(json["error"]["code"], DENIED_ERROR_CODE);
        assert_eq!(json["error"]["data"]["method"], "sampling/createMessage");
        assert!(!response.contains("secret prompt"));
        let audit = inspected.audit.expect("audit");
        assert_eq!(audit.direction.as_deref(), Some("server_to_client"));
        assert_eq!(audit.decision, "deny");
        assert_eq!(audit.param_keys, vec!["messages"]);
    }

    #[test]
    fn server_to_client_denied_notification_is_dropped_and_audited() {
        let inspected = inspect_server_line(
            &method_policy(),
            "default",
            &mut TrackedRequests::default(),
            r#"{"jsonrpc":"2.0","method":"elicitation/create","params":{"message":"secret body"}}"#,
        );
        assert_eq!(
            inspected.action,
            ServerAction::Deny {
                response_to_server: None
            }
        );
        let audit = inspected.audit.expect("audit");
        assert_eq!(audit.direction.as_deref(), Some("server_to_client"));
        assert_eq!(audit.request_id_type.as_deref(), Some("missing"));
        assert_eq!(audit.param_keys, vec!["message"]);
    }

    #[test]
    fn server_to_client_batch_arrays_are_denied_fail_closed() {
        let inspected = inspect_server_line(
            &method_policy(),
            "default",
            &mut TrackedRequests::default(),
            r#"[{"jsonrpc":"2.0","id":"s1","method":"roots/list","params":{}}]"#,
        );
        assert!(matches!(
            inspected.action,
            ServerAction::Deny {
                response_to_server: Some(_)
            }
        ));
        let audit = inspected.audit.expect("audit");
        assert_eq!(audit.event, "batch_denied");
        assert_eq!(audit.direction.as_deref(), Some("server_to_client"));
    }

    // --- v0.2 argument/param guards ---

    fn v2_tool_guard_policy() -> McpPolicyFile {
        parse_mcp_policy(
            r#"
schema_version = "ef-mcp-policy/v0.2"
name = "v2-proxy-guard"

[tools]
allow = ["github.create_issue"]

[tools."github.create_issue".arguments]
require_keys = ["org"]

[tools."github.create_issue".arguments.fields.org]
type = "enum"
values = ["my-org"]
"#,
        )
        .expect("valid v0.2 test policy")
    }

    #[test]
    fn v2_field_guard_denies_tool_call_and_audits_guard_metadata() {
        let inspected = inspect_client_line(
            &v2_tool_guard_policy(),
            "default",
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"github.create_issue","arguments":{"org":"other-org"}}}"#,
        );
        let ClientAction::Deny { response } = inspected.action else {
            panic!("expected deny for out-of-allowlist org");
        };
        assert!(response.is_some());
        let audit = inspected.audit.expect("audit record");
        assert_eq!(audit.decision, "deny");
        assert_eq!(audit.guard_key.as_deref(), Some("github.create_issue"));
        assert_eq!(audit.guard_selector.as_deref(), Some("org"));
        assert_eq!(
            audit.guard_reason_category.as_deref(),
            Some("enum_value_not_allowed")
        );
        // The denied value must never appear in the audit record.
        let serialized = serde_json::to_string(&audit).unwrap();
        assert!(!serialized.contains("other-org"));
    }

    #[test]
    fn v2_field_guard_allows_matching_tool_call() {
        let inspected = inspect_client_line(
            &v2_tool_guard_policy(),
            "default",
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"github.create_issue","arguments":{"org":"my-org"}}}"#,
        );
        assert_eq!(inspected.action, ClientAction::Forward);
        let audit = inspected.audit.expect("audit record");
        assert_eq!(audit.decision, "allow");
    }

    #[test]
    fn v2_guard_metadata_is_absent_when_tool_is_already_denied() {
        // A tool that isn't in the allow list is denied by decide_tool_call
        // before any v0.2 guard is relevant. The guard must not be computed
        // or attached to the audit record in that case: a `deny` decision
        // alongside `guard_reason_category: guard_allowed` would be a
        // confusing, misleading audit combination.
        let policy = parse_mcp_policy(
            r#"
schema_version = "ef-mcp-policy/v0.2"
name = "v2-denied-tool-with-guard"

[tools]
allow = ["other.tool"]

[tools."github.create_issue".arguments.fields.org]
type = "enum"
values = ["my-org"]
"#,
        )
        .expect("valid v0.2 policy");
        let inspected = inspect_client_line(
            &policy,
            "default",
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"github.create_issue","arguments":{"org":"my-org"}}}"#,
        );
        assert!(matches!(inspected.action, ClientAction::Deny { .. }));
        let audit = inspected.audit.expect("audit record");
        assert_eq!(audit.decision, "deny");
        assert!(
            audit.guard_key.is_none(),
            "guard must not be evaluated once the tool is already denied: {audit:?}"
        );
    }

    #[test]
    fn v2_server_scoped_tool_guard_is_enforced_end_to_end() {
        let policy = parse_mcp_policy(
            r#"
schema_version = "ef-mcp-policy/v0.2"
name = "v2-server-scoped-e2e"

[servers.production.tools]
allow = ["github.create_issue"]

[servers.production.tools."github.create_issue".arguments.fields.org]
type = "enum"
values = ["approved-org"]
"#,
        )
        .expect("valid v0.2 policy");

        let denied = inspect_client_line(
            &policy,
            "production",
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"github.create_issue","arguments":{"org":"other-org"}}}"#,
        );
        assert!(matches!(denied.action, ClientAction::Deny { .. }));
        let audit = denied.audit.expect("audit record");
        assert_eq!(audit.guard_key.as_deref(), Some("github.create_issue"));

        let allowed = inspect_client_line(
            &policy,
            "production",
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"github.create_issue","arguments":{"org":"approved-org"}}}"#,
        );
        assert_eq!(allowed.action, ClientAction::Forward);
    }

    #[test]
    fn v1_only_policy_resources_read_path_guard_behavior_is_unchanged() {
        // Regression guard for T018: generalizing the "any other method"
        // branch to call decide_method_param_guards for every method must not
        // change the v0.1 resources/read path-guard-only behavior.
        let policy = parse_mcp_policy(
            r#"
schema_version = "ef-mcp-policy/v0.1"
name = "v1-resources-read"

[tools]
allow = ["filesystem.read"]

[methods]
allow = ["tools/list", "tools/call", "resources/read"]

[path_rules.project_readonly]
allow_roots = ["/home/user/project"]

[methods."resources/read".params]
uri_keys = ["uri"]
path_rule = "project_readonly"
"#,
        )
        .expect("valid v0.1 policy");
        let allowed = inspect_client_line(
            &policy,
            "default",
            r#"{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///home/user/project/readme.md"}}"#,
        );
        assert_eq!(allowed.action, ClientAction::Forward);
        let denied = inspect_client_line(
            &policy,
            "default",
            r#"{"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"file:///etc/passwd"}}"#,
        );
        assert!(matches!(denied.action, ClientAction::Deny { .. }));
    }

    #[test]
    fn v2_param_guard_enforced_for_non_resources_read_method() {
        // T018: a v0.2 params guard on a method other than resources/read is
        // now enforced (new capability; v0.1 never checked this at all).
        let policy = parse_mcp_policy(
            r#"
schema_version = "ef-mcp-policy/v0.2"
name = "v2-custom-method-guard"

[tools]
allow = ["filesystem.read"]

[methods]
allow = ["tools/list", "tools/call", "demo/method"]

[methods."demo/method".params]
require_keys = ["destination"]

[methods."demo/method".params.fields.destination]
type = "enum"
values = ["eng-alerts"]
"#,
        )
        .expect("valid v0.2 policy");
        let allowed = inspect_client_line(
            &policy,
            "default",
            r#"{"jsonrpc":"2.0","id":1,"method":"demo/method","params":{"destination":"eng-alerts"}}"#,
        );
        assert_eq!(allowed.action, ClientAction::Forward);
        let denied = inspect_client_line(
            &policy,
            "default",
            r#"{"jsonrpc":"2.0","id":2,"method":"demo/method","params":{"destination":"random"}}"#,
        );
        assert!(matches!(denied.action, ClientAction::Deny { .. }));
        let audit = denied.audit.expect("audit record");
        assert_eq!(audit.guard_key.as_deref(), Some("demo/method"));
    }

    #[test]
    fn v2_param_guard_denies_server_to_client_method() {
        // T019: purely additive server->client params guard enforcement.
        let policy = parse_mcp_policy(
            r#"
schema_version = "ef-mcp-policy/v0.2"
name = "v2-server-to-client-guard"

[methods]
allow = ["tools/list", "tools/call", "sampling/createMessage"]

[tools]
allow = ["filesystem.read"]

[methods."sampling/createMessage".params]
require_keys = ["operation"]

[methods."sampling/createMessage".params.fields.operation]
type = "enum"
values = ["read"]
"#,
        )
        .expect("valid v0.2 policy");
        let mut pending = TrackedRequests::default();
        let denied = inspect_server_line(
            &policy,
            "default",
            &mut pending,
            r#"{"jsonrpc":"2.0","id":"s1","method":"sampling/createMessage","params":{"operation":"write"}}"#,
        );
        assert!(matches!(
            denied.action,
            ServerAction::Deny {
                response_to_server: Some(_)
            }
        ));
        let audit = denied.audit.expect("audit record");
        assert_eq!(audit.guard_key.as_deref(), Some("sampling/createMessage"));

        let mut pending = TrackedRequests::default();
        let allowed = inspect_server_line(
            &policy,
            "default",
            &mut pending,
            r#"{"jsonrpc":"2.0","id":"s2","method":"sampling/createMessage","params":{"operation":"read"}}"#,
        );
        assert!(matches!(allowed.action, ServerAction::Forward { .. }));
    }
}
