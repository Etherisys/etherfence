//! Experimental MCP stdio boundary proxy for EtherFence v0.2.x.
//!
//! The proxy sits between an MCP client and an MCP server, forwards
//! newline-delimited JSON-RPC messages, and enforces a minimal allow/deny
//! tool-call policy. It is a prototype: stdio transport only, exact-match
//! tool names, no daemon, no shell hooks, and no network interception.

mod audit;
mod policy;
mod proxy;

pub use audit::{redacted_argument_keys, AuditLog, AuditRecord};
pub use policy::{
    decide_tool_call, load_mcp_policy, parse_mcp_policy, Decision, McpPolicyFile, PolicyDecision,
    ToolRules, SUPPORTED_MCP_POLICY_SCHEMA_VERSION,
};
pub use proxy::{
    inspect_client_line, run_proxy, ClientAction, InspectedLine, DENIED_ERROR_CODE,
    TOOL_CALL_METHOD,
};
