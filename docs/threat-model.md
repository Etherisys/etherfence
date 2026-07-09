# EtherFence Threat Model

Status: pre-alpha draft, originally for v0.1.0 scan-only posture discovery,
with v0.2.x addenda for the experimental MCP boundary proxy.

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

## v0.2.x addendum: experimental MCP boundary proxy

`etherfence mcp-proxy` introduces one opt-in, per-invocation runtime
component. Its trust boundary assumptions:

- The proxy only governs the single MCP server it launches over stdio. Any
  MCP server the client talks to directly, or over HTTP/SSE, is outside the
  boundary.
- Enforcement is on `tools/call` request tool names plus `tools/list`
  advertisement filtering. Tool results, resources, prompts, and sampling
  traffic still pass through unmodified, so a cooperative-but-misbehaving
  server is not constrained beyond which tool calls reach it and which tools
  are advertised through tracked `tools/list` responses.
- v0.2.1 policy scoping is selected explicitly with `--server-name` (default:
  `default`). The proxy does not auto-discover or authenticate server
  identity; the operator must bind the right policy scope to the wrapped MCP
  server command.
- The policy fails closed: if it cannot be loaded and validated, the MCP
  server is never started.
- The audit log records decisions and argument key names only; argument
  values are excluded so secrets do not leak into the log. `tools/list`
  filtering records counts and allowed tool names only, not full tool schemas
  or descriptions.
- JSON-RPC batch arrays from the client are denied fail closed rather than
  unpacked, so a batch cannot smuggle a denied tool call past per-message
  inspection.
- Audit failures are fail closed: an unopenable audit log stops the proxy
  before the server starts, and a failed audit write stops forwarding.
- The proxy is a prototype and has not had a full adversarial review of MCP
  framing edge cases (for example multi-line or non-standard framing
  variants, or servers whose JSON parsers resolve duplicate keys differently
  from the proxy). It must not be treated as a security guarantee.
- v0.2.2 compatibility tests cover deterministic stdio request/response flows
  and an optional maintainer-run real-server smoke test. They improve
  confidence that the proxy can sit in front of real stdio MCP servers, but
  they are not a comprehensive MCP conformance suite.
- v0.2.6 hardened request tracking: the proxy tracks `tools/list` requests by
  `(method, id)` with reference-counted cleanup, so duplicate in-flight ids are
  handled deterministically and tracking entries cannot leak. Notifications and
  responses with unknown/missing/no-id pass through unchanged, server errors
  clear tracking, and tracked-id responses that are not genuine tool lists are
  forwarded unchanged with their entry cleared rather than re-shaped. Tracking
  remains scoped to `tools/list`; the proxy still does not reorder, buffer, or
  correlate responses beyond id matching, and remains experimental/pre-alpha.
