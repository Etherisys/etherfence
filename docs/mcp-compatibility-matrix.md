# MCP compatibility matrix

This matrix records MCP stdio compatibility checks for EtherFence's `mcp-proxy` (CLI surface and `ef-mcp-policy/v0.1` schema are stable as of v1.0.0, and the proxy is production-ready for controlled local-first deployments of its defined scope). `ef-mcp-policy/v0.2` (v1.5.0) adds optional argument/param field guards additively — see `docs/mcp-policy-ux.md` — without changing v0.1 compatibility or the flows recorded here. It is evidence for common JSON-RPC stdio flows, not a conformance suite and not a universal certification for every MCP server.

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
- `prompts/get` denied by method policy
- `completion/complete` denied by method policy (v0.9.0)
- server→client `sampling/createMessage` policy denial (id-bearing request answered toward the server, never forwarded to the client)
- server→client `roots/list` policy allow (forwarded to the client)
- server→client `elicitation/create` notification policy denial (dropped, audited)
- malformed successful `tools/list` shapes (fail safe to `tools: []`)
- client→server and server→client JSON-RPC batch arrays (denied fail closed)
- Unicode/homograph-suspicious method, tool, and path/URI values (denied)
- audit log redaction (argument/param values, raw paths/URIs, and secrets never logged)
- richer `tools/list` schemas with nested `inputSchema` fields (nested object
  properties, an array-of-strings property, a `required` list) preserved
  unchanged for allowed tools after filtering (v0.9.0)
- realistic `resources/list` shapes (`uri`/`name`/`mimeType` entries) and
  `resources/read` shapes (a `contents` array with `uri`/`mimeType`/`text`),
  forwarded unchanged when allowed by method policy (v0.9.0)

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
a universal certification and does not certify compatibility with any
specific real-world MCP server — operators must still test their own
chosen MCP server and policy.

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
| `etherfence-compat-fixture` fake MCP server | `0.1.0` | Linux and Windows CI via Rust integration tests | `etherfence mcp-proxy --policy <compat-policy.toml> --audit-log <audit.jsonl> --server-name default -- <path-to-fake-mcp-server>` | Integration-test compatibility policy plus checked examples `examples/policies/mcp-minimal-boundary.toml`, `examples/policies/mcp-filesystem-readonly.toml`, `examples/policies/mcp-github-readonly.toml`, `examples/policies/mcp-filesystem-project-readonly-hardened.toml`, `examples/policies/mcp-memory-notes-readonly.toml`, and `examples/policies/mcp-strict-method-only.toml` | Deterministic `tools/list` response is filtered to exact allowed tool names; denied, default-denied, and malformed unnamed tools are removed; malformed successful list shapes fail safely to `tools: []`; server errors pass through unchanged. A richer `tools/list` shape with a nested `inputSchema` (nested object property, array-of-strings property, `required` list) is preserved unchanged for the allowed tool after filtering. | Allowed calls such as `compat.allowed` and `compat.server_error` are forwarded; successful allowed calls return the fake server echo response and the server-error fixture passes through unchanged. Allowed `resources/list` and `resources/read` (in-root `file://`) requests forward the same way, including realistic `uri`/`name`/`mimeType` resource entries and a `contents` array with `uri`/`mimeType`/`text`. | Denied calls such as `compat.denied` are answered by the proxy with a safe JSON-RPC error and are not forwarded to the fake server; JSON-RPC batch arrays are denied fail-closed. Denied `resources/read` (outside the allow root, or a non-`file://` URI), denied `resources/list`, denied `prompts/get`, and denied `completion/complete` behave the same way. | JSONL audit records include policy, server, method, request id, tool name, decision, reason, and argument key names only; argument values and tool schemas are not logged. | EtherFence maintainers / 2026-07-10 | Checked-in deterministic fixture only. This row does not prove compatibility with any external MCP server package or HTTP/SSE transport. Use `docs/mcp-real-server-test-template.md` for optional local real-server records. |

## Realistic MCP server categories (compatibility evidence status)

These rows track compatibility evidence for the shapes of real-world MCP
server categories that EtherFence is designed to sit in front of. The fake
fixture row above already exercises the JSON-RPC shapes for each category
(nested tool schemas, resource list/read entries, method-policy denial).
Rows in this table become real-server-backed once a maintainer runs the
optional real-server smoke test in `docs/mcp-real-server-test-template.md`
against an actual installed server and adds a dated row to the main matrix
above. Until then, they document intent and the recommended starting policy,
not a real-server-verified result.

| Server category | Representative real servers (examples, not endorsements) | Recommended starting policy | Compatibility status |
| --- | --- | --- | --- |
| Filesystem-style (local file read/list/search tools) | `@modelcontextprotocol/server-filesystem`-style servers | `examples/policies/mcp-filesystem-readonly.toml`, `examples/policies/mcp-filesystem-project-readonly-hardened.toml` | Fake-fixture shapes only (fixture tools named `filesystem.read`, `filesystem.read_secret`). No real-server row yet — run the real-server smoke test to add one. |
| GitHub/API-style (repo/issue/PR read tools over an authenticated API) | GitHub MCP server-style implementations | `examples/policies/mcp-github-readonly.toml` | Fake-fixture shapes only (fixture tool named `github.list_repos`). No real-server row yet; a real run needs maintainer-supplied API credentials via the server's own configuration, never via EtherFence. |
| Memory/notes-style (local knowledge-graph or notes store) | Memory/knowledge-graph MCP server-style implementations | `examples/policies/mcp-memory-notes-readonly.toml` | Fake-fixture shapes only (generic `tools/list`/`tools/call` coverage; no dedicated fake `memory.*` tool fixture yet). No real-server row yet. |
| Resources/read-capable (servers exposing `resources/list` and `resources/read`) | Any MCP server implementing the resources capability | `examples/policies/mcp-resources-project-only.toml`, `examples/policies/mcp-readonly.toml` | Fixture-backed CI coverage for allowed/denied `resources/list` and `resources/read`, including a realistic `uri`/`name`/`mimeType` list shape and a `contents` array read shape (v0.9.0). No real-server row yet. |
| Server→client feature server (uses `sampling/createMessage`, `roots/list`, and/or `elicitation/create`) | Any MCP server that initiates client-feature requests | `examples/policies/mcp-sampling-denied.toml`, `examples/policies/mcp-strict-method-only.toml` | Fixture-backed CI coverage for server→client `sampling/createMessage` denial, `roots/list` allow, and `elicitation/create` notification denial (v0.3.1/v0.5.0). No real-server row yet. |

## Adding real-server records

1. Run the optional smoke test with a locally installed stdio MCP server using `ETHERFENCE_REAL_MCP_CMD` as a JSON argv array, and optionally `ETHERFENCE_REAL_MCP_POLICY` to point at a specific policy file instead of the built-in compatibility policy.
2. Capture the server package/version, OS/platform, exact command template, policy file, and audit-log summary.
3. Add a new row to the matrix without changing proxy enforcement semantics.
4. Keep tool names exact; if a server changes names between versions, create a separate row for each tested version.
5. Label the row's notes/limitations clearly as compatibility evidence for the tested flows, not a universal certification for that server or any other.
