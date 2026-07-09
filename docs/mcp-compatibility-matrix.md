# MCP compatibility matrix

This matrix records MCP stdio compatibility checks for EtherFence's experimental `mcp-proxy`. It is evidence for common JSON-RPC stdio flows, not a conformance suite and not production-readiness evidence.

Scope guard:

- stdio transport only;
- exact tool-name matching only;
- no daemon mode;
- no HTTP/SSE transport;
- no network interception;
- no shell hooks;
- no terminal-command scanning;
- no wildcard, prefix, or regex matching;
- no new enforcement semantics beyond existing `tools/call` decisions and tracked `tools/list` filtering.

## Fields

Each compatibility record must capture:

- server name
- server version
- platform
- command template
- policy used
- tools/list behavior
- allowed `tools/call` result
- denied `tools/call` result
- audit result
- tester/date
- notes/limitations

## Matrix

| Server name | Server version | Platform | Command template | Policy used | `tools/list` behavior | Allowed `tools/call` result | Denied `tools/call` result | Audit result | Tester/date | Notes/limitations |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `etherfence-compat-fixture` fake MCP server | `0.1.0` | Linux and Windows CI via Rust integration tests | `etherfence mcp-proxy --policy <compat-policy.toml> --audit-log <audit.jsonl> --server-name default -- <path-to-fake-mcp-server>` | Integration-test compatibility policy plus checked examples `examples/policies/mcp-minimal-boundary.toml`, `examples/policies/mcp-filesystem-readonly.toml`, and `examples/policies/mcp-github-readonly.toml` | Deterministic `tools/list` response is filtered to exact allowed tool names; denied, default-denied, and malformed unnamed tools are removed; malformed successful list shapes fail safely to `tools: []`; server errors pass through unchanged. | Allowed calls such as `compat.allowed` and `compat.server_error` are forwarded; successful allowed calls return the fake server echo response and the server-error fixture passes through unchanged. | Denied calls such as `compat.denied` are answered by the proxy with a safe JSON-RPC error and are not forwarded to the fake server; JSON-RPC batch arrays are denied fail-closed. | JSONL audit records include policy, server, method, request id, tool name, decision, reason, and argument key names only; argument values and tool schemas are not logged. | EtherFence maintainers / 2026-07-09 | Checked-in deterministic fixture only. This row does not prove compatibility with any external MCP server package or HTTP/SSE transport. Use `docs/mcp-real-server-test-template.md` for optional local real-server records. |

## Adding real-server records

1. Run the optional smoke test with a locally installed stdio MCP server using `ETHERFENCE_REAL_MCP_CMD` as a JSON argv array.
2. Capture the server package/version, OS/platform, exact command template, policy file, and audit-log summary.
3. Add a new row to the matrix without changing proxy enforcement semantics.
4. Keep tool names exact; if a server changes names between versions, create a separate row for each tested version.
