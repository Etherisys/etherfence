# MCP Boundary Proxy (experimental)

`etherfence mcp-proxy` is the first prototype in the EtherFence v0.2.x
runtime-control line. It is a minimal MCP **stdio** boundary proxy that sits
between an MCP client and an MCP server, audits MCP tool calls, filters tool
advertisements, and allows/denies tool calls deterministically using a small
TOML policy.

Status: **experimental prototype**. It is not production-ready, it is not a
daemon or endpoint agent, and it does not replace the v0.1.x scan-only
posture commands, which are unchanged.

## Usage

```sh
etherfence mcp-proxy --policy <file> [--audit-log <file>] [--server-name <name>] -- <server-command> [args...]
```

`--server-name` selects an optional per-server policy scope. If omitted, the
server name is `default`.

The proxy:

1. Loads the policy file. If the policy cannot be read, parsed, or validated,
   the proxy **fails closed**: it reports the error, optionally writes a
   `policy_error` audit record, exits with code 2, and never starts the MCP
   server.
2. Starts the real MCP server as a child process with piped stdin/stdout
   (stderr is passed through).
3. Forwards newline-delimited JSON-RPC messages between the client (the
   proxy's own stdin/stdout) and the server.
4. Inspects `tools/call` requests before forwarding. Allowed calls are
   forwarded unchanged; denied calls are answered with a safe JSON-RPC error
   and are **not** forwarded to the server.
5. Tracks client `tools/list` requests and filters the matching server
   responses so denied and default-denied tools are not advertised.
6. Leaves unrelated protocol messages untouched.

Example, wrapping a filesystem MCP server:

```sh
etherfence mcp-proxy \
  --policy /home/user/mcp-boundary.toml \
  --audit-log /home/user/etherfence-mcp-audit.jsonl \
  --server-name filesystem \
  -- npx -y @modelcontextprotocol/server-filesystem /home/user/projects
```

In an MCP client configuration this means replacing the server command with
`etherfence` and moving the original command after `--`.

When the client closes its input stream, the proxy closes the server's stdin,
waits for the server to exit, and exits with the server's exit code.

## Policy

Policies use schema `ef-mcp-policy/v0.1`. Legacy v0.2.0 global-only policies
remain valid:

```toml
schema_version = "ef-mcp-policy/v0.1"
name = "minimal-mcp-boundary"

[tools]
allow = ["github.list_repos", "filesystem.read"]
deny = ["filesystem.read_secret", "shell.run"]
```

v0.2.1 adds optional per-server sections keyed by `--server-name`:

```toml
schema_version = "ef-mcp-policy/v0.1"
name = "mcp-boundary"

[tools]
allow = ["github.list_repos"]
deny = ["shell.run"]

[servers.filesystem.tools]
allow = ["filesystem.read"]
deny = ["filesystem.read_secret", "filesystem.write"]
```

Examples live at:

- `examples/policies/mcp-minimal-boundary.toml`
- `examples/policies/mcp-filesystem-readonly.toml`
- `examples/policies/mcp-github-readonly.toml`

Decision rules, in exact order:

1. Tool name in global `[tools].deny` -> **deny**.
2. Tool name in `[servers.<server-name>.tools].deny` -> **deny**.
3. Tool name in `[servers.<server-name>.tools].allow` -> **allow**.
4. Tool name in global `[tools].allow` -> **allow**.
5. Anything else -> **deny** (default deny).

Deny therefore always overrides allow. Tool names are matched exactly. There
are no globs, prefixes, or regular expressions in `ef-mcp-policy/v0.1`.

Fail-closed cases:

- Missing, unreadable, or syntactically invalid policy file -> the proxy exits
  before starting the server (decision `policy_error`).
- Unsupported `schema_version` or empty `name` -> same fail-closed exit.
- A `tools/call` request whose tool name is missing or not a string -> denied.
- A successful `tools/list` response with an unexpected shape -> rewritten to
  advertise an empty `tools` array for that response.

## `tools/list` filtering

The proxy records the id of each forwarded client `tools/list` request. When a
server response with the same id returns successfully, `result.tools` is
filtered with the same policy decision rules used for `tools/call`:

- denied tools are removed;
- default-denied/unlisted tools are removed;
- entries without a string `name` are removed;
- allowed entries remain otherwise unchanged, preserving their normal MCP tool
  structure for the client.

Unrelated server-to-client messages are not modified. Server errors for a
tracked `tools/list` request pass through unchanged. If a tracked successful
`tools/list` response has a missing/non-object `result`, missing `tools`, or a
non-array `tools`, the proxy fails safely for that response by returning a
valid response shape that advertises no tools (`"tools": []`) and writes a
`tools_list_filtered` audit event. This avoids passing an unsafe or ambiguous
tool advertisement through the boundary.

## Denied tool calls

Denied requests receive a JSON-RPC error and never reach the server:

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "error": {
    "code": -32000,
    "message": "EtherFence MCP proxy denied this tool call by policy",
    "data": {
      "tool": "shell.run",
      "reason": "tool name is in the global policy deny list"
    }
  }
}
```

Denied `tools/call` notifications (no `id`) are dropped without a response,
because JSON-RPC forbids replying to notifications; the decision is still
audited.

## Audit log

`--audit-log <file>` appends one JSON object per line (JSONL). Tool-call
example:

```json
{"ts":"2026-07-09T02:04:56Z","event":"tool_call_decision","policy":"minimal-mcp-boundary","server":"filesystem","method":"tools/call","request_id":3,"tool":"shell.run","argument_keys":["api_token","command"],"original_count":null,"filtered_count":null,"allowed_tools":[],"decision":"deny","reason":"tool name is in the global policy deny list"}
```

Tool-list filtering example:

```json
{"ts":"2026-07-09T02:05:01Z","event":"tools_list_filtered","policy":"minimal-mcp-boundary","server":"filesystem","method":"tools/list","request_id":10,"tool":null,"argument_keys":[],"original_count":5,"filtered_count":1,"allowed_tools":["filesystem.read"],"decision":"allow","reason":"filtered tools/list response using MCP proxy policy; denied and default-denied tools were removed"}
```

Fields:

- `ts`: RFC 3339 UTC timestamp
- `event`: `tool_call_decision`, `tools_list_filtered`, `batch_denied`, or
  `policy_load_error`
- `policy`: policy `name` (absent for policy load errors)
- `server`: selected server name when applicable
- `method`: JSON-RPC method (`tools/call` or `tools/list`)
- `request_id`: JSON-RPC request id when present
- `tool`: tool name for tool-call decisions when it could be extracted
- `argument_keys`: sorted tool-call argument **key names only**
- `original_count`: original advertised tool count for `tools_list_filtered`
- `filtered_count`: remaining advertised tool count for `tools_list_filtered`
- `allowed_tools`: allowed tool names retained in a filtered `tools/list`
  response
- `decision`: `allow`, `deny`, or `policy_error`
- `reason`: the policy or fail-safe reason for the decision

Argument values are never written to the audit log, so secret values passed as
tool arguments do not leak into it. Full tool schemas/descriptions are not
written for `tools_list_filtered`; only counts and allowed tool names are
recorded.

Audit failures are fail closed: if the audit log file cannot be opened at
startup, the proxy exits before starting the MCP server; if writing an audit
record fails while the proxy is running, the proxy stops forwarding and exits
with an error instead of continuing unaudited.

## Compatibility test harness

v0.2.4 documents the compatibility matrix workflow in `docs/mcp-compatibility-matrix.md` and optional real-server test records in `docs/mcp-real-server-test-template.md`. v0.2.2 added a deterministic MCP stdio compatibility harness in
`crates/etherfence-cli/tests/cli_mcp_proxy.rs` backed by the checked-in
`fake-mcp-server` test binary. Normal CI remains self-contained: it does not
require internet access, npm, npx, uvx, Docker, or external MCP packages.

The harness sends a realistic client-like sequence through
`etherfence mcp-proxy`:

1. `initialize`
2. `notifications/initialized`
3. `tools/list`
4. an allowed `tools/call`
5. a denied `tools/call`
6. an allowed `tools/call` that returns a server error
7. a JSON-RPC batch array, which remains denied fail closed

The tests verify request/response id preservation, `tools/list` filtering,
server error passthrough, fail-safe malformed `tools/list` handling, and that
denied tool calls and batch arrays are not forwarded to the server fixture.

Maintainers can optionally smoke-test any locally installed real stdio MCP
server by setting `ETHERFENCE_REAL_MCP_CMD` to a JSON argv array. It is not a
shell command and is intentionally not parsed by a shell:

```sh
ETHERFENCE_REAL_MCP_CMD='["/absolute/path/to/server","--arg","value"]' \
  cargo test -p etherfence-cli optional_real_mcp_stdio_smoke_test -- --nocapture
```

If `ETHERFENCE_REAL_MCP_CMD` is absent, the optional test skips with a clear
message. This keeps CI deterministic while allowing maintainers to validate
that EtherFence can sit between a client-like test harness and a real stdio
MCP server.

## Compatibility matrix workflow

`docs/mcp-compatibility-matrix.md` defines the fields required for every compatibility record: server name, server version, platform, command template, policy used, `tools/list` behavior, allowed and denied `tools/call` results, audit result, tester/date, and notes/limitations. The checked-in fake MCP server row is the only deterministic CI-backed record. External server rows should be added only after running the optional real-server template and recording exact tool names and versions.

## Client configuration examples

See `docs/mcp-clients.md` and the checked JSON templates under
`docs/examples/` for generic, Claude-style, Cursor-style, and VS Code-style
client configuration examples. They all use placeholders and must be adjusted
for local paths, server commands, and exact tool names.

## Limitations

- stdio transport only; HTTP/SSE MCP transports are not supported.
- Newline-delimited JSON-RPC framing only; each message must be one line.
- Exact tool-name matching only; no wildcard, prefix, regex, argument-aware, or
  schema-aware rules.
- Per-server scoping is selected explicitly with `--server-name`; the proxy
  does not auto-discover or authenticate MCP server identity.
- The proxy inspects `tools/call` requests and filters tracked `tools/list`
  responses. It does not inspect tool results, resources, prompts, or sampling
  traffic.
- JSON-RPC batch arrays are not unpacked. A batch line from the client is
  denied fail closed — answered with a single null-id JSON-RPC error, audited
  as `batch_denied`, and never forwarded — even if every call inside it names
  an allow-listed tool.
- Non-JSON input lines are forwarded unchanged for the server to reject,
  matching plain JSON-RPC behavior.
- One client, one server, one process; no daemon mode, shell hooks, command
  interception, terminal-command scanning, or network interception — those
  remain out of scope.
