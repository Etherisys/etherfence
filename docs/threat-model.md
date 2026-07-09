# EtherFence Threat Model

Status: pre-alpha draft, originally for v0.1.0 scan-only posture discovery,
with a v0.2.0 addendum for the experimental MCP boundary proxy.

## Assets

- Local files reachable by AI agents and MCP servers
- Environment variables exposed to MCP subprocesses
- Agent configuration files
- Developer workstations and repositories
- Complementary terminal protections such as Tirith

## Initial threat hypotheses

1. An agent configuration may enable MCP servers with broad filesystem access.
2. An MCP server may expose shell, command execution, browser, or network-capable behavior.
3. Secret-like environment variable names may be passed to MCP servers.
4. Operators may not know which agent/MCP configurations exist on a workstation.

## Trust boundaries

- The scan commands read local configuration files only.
- The scanner does not intercept, proxy, or block agent runtime behavior.
- EtherFence does not inspect live network traffic.
- It does not scan terminal commands; Tirith remains complementary for that class of control.

## v0.1.0 detection limits

The scanner reports conservative hints from known config paths and fixture-backed formats. It may miss custom locations, unsupported schemas, dynamically generated settings, and runtime-only capabilities. A finding indicates review priority, not confirmed compromise.

## v0.2.0 addendum: experimental MCP boundary proxy

`etherfence mcp-proxy` introduces one opt-in, per-invocation runtime
component. Its trust boundary assumptions:

- The proxy only governs the single MCP server it launches over stdio. Any
  MCP server the client talks to directly, or over HTTP/SSE, is outside the
  boundary.
- Enforcement is on `tools/call` request tool names only. Tool results,
  resources, prompts, and `tools/list` traffic pass through unmodified, so a
  cooperative-but-misbehaving server is not constrained beyond which tool
  calls reach it.
- The policy fails closed: if it cannot be loaded and validated, the MCP
  server is never started.
- The audit log records decisions and argument key names only; argument
  values are excluded so secrets do not leak into the log.
- JSON-RPC batch arrays from the client are denied fail closed rather than
  unpacked, so a batch cannot smuggle a denied tool call past per-message
  inspection.
- Audit failures are fail closed: an unopenable audit log stops the proxy
  before the server starts, and a failed audit write stops forwarding.
- The proxy is a prototype and has not had a full adversarial review of MCP
  framing edge cases (for example multi-line or non-standard framing
  variants, or servers whose JSON parsers resolve duplicate keys differently
  from the proxy). It must not be treated as a security guarantee.
