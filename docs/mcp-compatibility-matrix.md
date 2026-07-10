# MCP compatibility matrix

This matrix records MCP stdio compatibility checks for EtherFence's experimental `mcp-proxy`. It is evidence for common JSON-RPC stdio flows, not a conformance suite and not production-readiness evidence.

## What is tested

The checked-in fake MCP server fixture, run through `cargo test --workspace` on every CI run, exercises:

- `initialize` and `notifications/initialized`
- `tools/list` filtering (allowed, denied, and default-denied tools removed)
- `tools/call` allowed (forwarded, response returned)
- `tools/call` denied (safe JSON-RPC error, never forwarded)
- `resources/list` allowed and denied by method policy
- `resources/read` allowed for an in-scope `file://` URI
- `resources/read` denied for a URI outside the configured allow root
- `resources/read` denied for a non-`file://` URI
- server→client `sampling/createMessage` policy denial (id-bearing request answered toward the server, never forwarded to the client)
- server→client `roots/list` policy allow (forwarded to the client)
- server→client `elicitation/create` notification policy denial (dropped, audited)
- malformed successful `tools/list` shapes (fail safe to `tools: []`)
- client→server and server→client JSON-RPC batch arrays (denied fail closed)
- Unicode/homograph-suspicious method, tool, and path/URI values (denied)
- audit log redaction (argument/param values, raw paths/URIs, and secrets never logged)

## What remains untested

- Any MCP transport other than newline-delimited stdio JSON-RPC (no HTTP/SSE).
- Real third-party MCP server packages, beyond whatever maintainers choose to
  run manually via the optional real-server smoke test below. CI does not run
  any external server by default.
- Client-side behavior of specific MCP client applications (Claude Desktop,
  Cursor, VS Code, etc.) beyond the JSON configuration examples in
  `docs/mcp-clients.md`.
- Non-ASCII/internationalized MCP method or tool names (rejected by design,
  see the v0.4.1 Unicode hardening notes).
- Performance, concurrency, or load characteristics of the proxy.
- Any guarantee that a given real server's tool/resource names, schemas, or
  behavior match the fake fixture; exact names must be verified per server
  version.

Passing these tests is evidence that the proxy behaves correctly against a
deterministic, checked-in fixture for the flows listed above. It is **not**
production-readiness certification and does not certify compatibility with
any specific real-world MCP server.

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
| `etherfence-compat-fixture` fake MCP server | `0.1.0` | Linux and Windows CI via Rust integration tests | `etherfence mcp-proxy --policy <compat-policy.toml> --audit-log <audit.jsonl> --server-name default -- <path-to-fake-mcp-server>` | Integration-test compatibility policy plus checked examples `examples/policies/mcp-minimal-boundary.toml`, `examples/policies/mcp-filesystem-readonly.toml`, `examples/policies/mcp-github-readonly.toml`, `examples/policies/mcp-filesystem-project-readonly-hardened.toml`, and `examples/policies/mcp-strict-method-only.toml` | Deterministic `tools/list` response is filtered to exact allowed tool names; denied, default-denied, and malformed unnamed tools are removed; malformed successful list shapes fail safely to `tools: []`; server errors pass through unchanged. | Allowed calls such as `compat.allowed` and `compat.server_error` are forwarded; successful allowed calls return the fake server echo response and the server-error fixture passes through unchanged. Allowed `resources/list` and `resources/read` (in-root `file://`) requests forward the same way. | Denied calls such as `compat.denied` are answered by the proxy with a safe JSON-RPC error and are not forwarded to the fake server; JSON-RPC batch arrays are denied fail-closed. Denied `resources/read` (outside the allow root, or a non-`file://` URI) and denied `resources/list` behave the same way. | JSONL audit records include policy, server, method, request id, tool name, decision, reason, and argument key names only; argument values and tool schemas are not logged. | EtherFence maintainers / 2026-07-10 | Checked-in deterministic fixture only. This row does not prove compatibility with any external MCP server package or HTTP/SSE transport. Use `docs/mcp-real-server-test-template.md` for optional local real-server records. |

## Adding real-server records

1. Run the optional smoke test with a locally installed stdio MCP server using `ETHERFENCE_REAL_MCP_CMD` as a JSON argv array, and optionally `ETHERFENCE_REAL_MCP_POLICY` to point at a specific policy file instead of the built-in compatibility policy.
2. Capture the server package/version, OS/platform, exact command template, policy file, and audit-log summary.
3. Add a new row to the matrix without changing proxy enforcement semantics.
4. Keep tool names exact; if a server changes names between versions, create a separate row for each tested version.
5. Label the row's notes/limitations clearly as compatibility evidence for the tested flows, not production-readiness certification.
