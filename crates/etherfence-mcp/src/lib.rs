//! Experimental MCP stdio boundary proxy for EtherFence v0.2.x/v0.3.x.
//!
//! The proxy sits between an MCP client and an MCP server, forwards
//! newline-delimited JSON-RPC messages, and enforces method-level and
//! tool-level allow/deny policy. It is a prototype: stdio transport only,
//! exact-match tool and method names, no daemon, no shell hooks, and no
//! network interception.

mod audit;
mod policy;
mod policy_ux;
mod proxy;
pub mod unicode;

pub use audit::{redacted_argument_keys, redacted_param_keys, AuditLog, AuditRecord};
pub use policy::{
    decide_method, decide_method_param_guards, decide_method_param_paths,
    decide_tool_argument_guards, decide_tool_argument_paths, decide_tool_call,
    is_always_allowed_method, load_mcp_policy, parse_mcp_policy, ArgumentGuard, Decision,
    FieldGuard, GuardPolicyDecision, McpPolicyFile, MethodDirection, MethodRules,
    PathPolicyDecision, PolicyDecision, ScalarValue, ServerPolicy, ToolRules,
    ALWAYS_ALLOWED_METHODS, DEFAULT_ALLOWED_METHODS, SUPPORTED_MCP_POLICY_SCHEMA_VERSION,
    SUPPORTED_MCP_POLICY_SCHEMA_VERSIONS, SUPPORTED_MCP_POLICY_SCHEMA_VERSION_V2,
};
pub use policy_ux::{
    dry_run_check, explain_policy, ArgumentGuardSummary, CheckOutcome, FieldGuardSummary,
    GuardScope, GuardSummary, MethodPolicySummary, PathRuleSummary, PolicyExplanation,
    ServerScopeSummary, ToolPolicySummary,
};
pub use proxy::exit_code;
pub use proxy::{
    inspect_client_line, inspect_server_line, run_proxy, ClientAction, InspectedLine,
    InspectedServerLine, ProxyError, DENIED_ERROR_CODE, TOOL_CALL_METHOD, TOOL_LIST_METHOD,
};
