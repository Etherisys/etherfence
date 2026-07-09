# MCP Boundary Proxy (experimental)

`etherfence mcp-proxy` is the first prototype in the EtherFence v0.2.x/
v0.3.x runtime-control line. It is a minimal MCP **stdio** boundary proxy
that sits between an MCP client and an MCP server, inspects every
client→server JSON-RPC method, enforces method-level and tool-level
allow/deny policy, filters tool advertisements, and audits decisions
deterministically using a small TOML policy.

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
   `policy_error` audit record, exits with code `2`, and never starts the MCP
   server.
2. Starts the real MCP server as a child process with piped stdin/stdout. The
   child's stderr is **inherited** (it goes straight to the operator's terminal
   / the proxy's stderr) so a chatty or failing server can never block or
   deadlock the proxy's own pipes.
3. Forwards newline-delimited JSON-RPC messages between the client (the
   proxy's own stdin/stdout) and the server.
4. Inspects every client→server JSON-RPC request before forwarding. The
   method-level policy is checked first (v0.3.0). Denied methods are never
   forwarded and receive a JSON-RPC error. `tools/call` requests that pass
   the method check are then checked against the tool-name policy: allowed
   calls are forwarded unchanged; denied calls are answered with a safe
   JSON-RPC error and are **not** forwarded to the server.
5. Tracks client `tools/list` requests and filters the matching server
   responses so denied and default-denied tools are not advertised.
6. Leaves server→client messages untouched (no response inspection beyond
   tracked `tools/list` filtering).

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
- `examples/policies/mcp-strict-tools-only.toml` (v0.3.0)
- `examples/policies/mcp-readonly.toml` (v0.3.0)
- `examples/policies/mcp-resources-denied.toml` (v0.3.0)
- `examples/policies/mcp-sampling-denied.toml` (v0.3.0)

Decision rules for tool names, in exact order:

1. Tool name in global `[tools].deny` -> **deny**.
2. Tool name in `[servers.<server-name>.tools].deny` -> **deny**.
3. Tool name in `[servers.<server-name>.tools].allow` -> **allow**.
4. Tool name in global `[tools].allow` -> **allow**.
5. Anything else -> **deny** (default deny).

### Method-level policy (v0.3.0 client→server, v0.3.1 server→client)

v0.3.0 added optional `[methods]` and `[servers.<name>.methods]` sections
for client→server JSON-RPC requests. v0.3.1 uses the same exact-match
policy model for server→client request/notification objects with a `method`
field, before they reach the client:

```toml
schema_version = "ef-mcp-policy/v0.1"
name = "mcp-readonly"

[methods]
allow = ["tools/list", "tools/call", "resources/list", "resources/read"]
deny = ["sampling/createMessage", "prompts/get"]

[tools]
allow = ["filesystem.read"]
```

Method decision rules, in exact order:

1. Client→server method is `initialize`, `notifications/initialized`, or
   `ping` -> **always allow** (protocol-required for client→server
   initialization/liveness; bypasses client→server method policy). For
   server→client traffic, only `ping` is always allowed; server-initiated
   client feature methods such as `sampling/createMessage`, `roots/list`, and
   `elicitation/create` must be explicitly allowed or they are denied.
2. Method in global `[methods].deny` -> **deny**.
3. Method in `[servers.<server-name>.methods].deny` -> **deny**.
4. Method in `[servers.<server-name>.methods].allow` -> **allow**.
5. Method in global `[methods].allow` -> **allow**.
6. Global `[methods].allow` contains `"*"` -> **allow** (wildcard).
7. No `[methods]` section at all (global and server) -> **built-in
   default**: allow `tools/list` and `tools/call`, deny everything else.
8. A `[methods]` section exists but the method is not listed -> **deny**
   (default deny for unknown methods).

When no `[methods]` section is present, the built-in default allows
`tools/list` and `tools/call` and denies everything else. This is a
**behavioral hardening from v0.2.x**: in v0.2.x, non-tools methods passed
through the proxy uninspected; in v0.3.0 they are denied by default.
Deployments that need non-tools methods to pass through must add an
explicit `[methods]` allow list or use `allow = ["*"]` for permissive mode.

The `"*"` wildcard in the `allow` list explicitly opts in to permissive
mode: all methods (including unknown ones) are allowed except those in
the `deny` list. Use this with caution.

Per-server method scoping follows the same precedence as tool rules:
global deny, server deny, server allow, global allow, then default deny.

**Direction semantics:** Method policy now applies in both MCP directions, but
the protocol behavior differs by direction. Client→server denials are returned
as JSON-RPC errors to the client and are never forwarded to the server.
Server→client denials are never forwarded to the client; when the denied
server→client message has a non-null `id`, the proxy writes a JSON-RPC error
response back toward the server, and when it is a notification without an `id`,
the proxy drops it and audits the denial. This is intended for server-initiated
client-feature methods such as `sampling/createMessage`, `roots/list`, and
`elicitation/create`.

Fail-closed cases:

- Missing, unreadable, or syntactically invalid policy file -> the proxy exits
  before starting the server (decision `policy_error`).
- Unsupported `schema_version` or empty `name` -> same fail-closed exit.
- A `tools/call` request whose tool name is missing or not a string -> denied.
- A successful `tools/list` response with an unexpected shape -> rewritten to
  advertise an empty `tools` array for that response.
- Client→server or server→client JSON-RPC batch arrays -> denied wholesale
  (fail closed); the proxy does not unpack mixed batches.

## `tools/list` filtering

The proxy records the id of each forwarded client `tools/list` request. When a
server response with the same id returns successfully, `result.tools` is
filtered with the same policy decision rules used for `tools/call`:

- denied tools are removed;
- default-denied/unlisted tools are removed;
- entries without a string `name` are removed;
- allowed entries remain otherwise unchanged, preserving their normal MCP tool
  structure for the client.

Server responses without a `method` field are not method-checked. Server errors for a
tracked `tools/list` request pass through unchanged. If a tracked successful
`tools/list` response has a missing/non-object `result`, missing `tools`, or a
non-array `tools`, the proxy fails safely for that response by returning a
valid response shape that advertises no tools (`"tools": []`) and writes a
`tools_list_filtered` audit event. This avoids passing an unsafe or ambiguous
tool advertisement through the boundary.

## Lifecycle and failure modes

The proxy is hardened for the failure cases an MCP boundary component is most
likely to hit. All of these are covered by the test harness in
`crates/etherfence-cli/tests/cli_mcp_proxy.rs`.

- **Child process cleanup.** The child server is reaped on every exit path
  (clean shutdown, child early exit, or proxy error). On a normal client EOF
  the proxy closes the server's stdin and `wait()`s for the child, so no zombie
  is left behind.
- **Child early exit / server stdout closure.** If the child exits (or closes
  its stdout) before the client is done, the server→client pump ends, the
  proxy stops forwarding, and the proxy exits with the child's own exit code.
- **Client EOF.** Closing the client's stdin is a normal shutdown: the proxy
  closes the server's stdin, joins the server pump, reaps the child, and exits
  `0`.
- **Broken pipe to server.** A write to a child that has already exited is
  treated as a clean shutdown (the client loop stops), not a panic.
- **Broken pipe to client.** A write to a client that has closed its stdout is
  treated as a clean shutdown (the server pump stops), not a panic.
- **Invalid client JSON.** A client line that is not valid JSON is **dropped
  before** it is forwarded; it never reaches the server. (Valid JSON-RPC
  requests, responses, and notifications are still forwarded unchanged — the
  proxy never alters server-originated or client notification traffic.)
- **Invalid server JSON.** A server line that is not valid JSON is passed
  through to the client unchanged, so the client's own parser rejects it. The
  proxy never fabricates or advertises a tool list from a malformed server
  line.
- **Audit write failure (best-effort).** See [Audit log](#audit-log). A failed
  audit write never weakens a deny: the decision response is still returned to
  the client and the proxy continues.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Clean client EOF shutdown; the child server exited normally. |
| `2` | Invalid/unloadable policy. Fail closed; the server is never started. |
| `3` | Child server could not be spawned. Fail closed. |
| `4` | Internal proxy error: a pipe I/O failure, or the audit log could not be opened at startup. |
| child's code | When the child server exits before the client (early exit / crash), its own exit code is propagated. |

A child that ignores a closed stdin and keeps its stdout open will keep the
server pump alive until the proxy process itself is killed. That matches normal
stdio MCP server behavior and is by design, not a defect.

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
- `event`: `tool_call_decision`, `method_decision`, `tools_list_filtered`,
  `batch_denied`, or `policy_load_error`
- `policy`: policy `name` (absent for policy load errors)
- `server`: selected server name when applicable
- `method`: JSON-RPC method (`tools/call`, `tools/list`, or the method
  name for `method_decision` events)
- `request_id`: JSON-RPC request id when present (simple types: number,
  string, bool, null are logged as-is; complex types: object and array
  ids are redacted — only the type is recorded in `request_id_type`)
- `direction`: `client_to_server` or `server_to_client` when applicable
- `request_id_type`: JSON type of the request id (`number`, `string`,
  `bool`, `object`, `array`, `null`, or `missing`) (v0.3.0)
- `tool`: tool name for tool-call decisions when it could be extracted
- `argument_keys`: sorted tool-call argument **key names only**
- `param_keys`: sorted top-level `params` key names for method decisions
  (v0.3.0)
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

Audit failures are best-effort: if the audit log file cannot be opened at
startup, the proxy exits before starting the MCP server (code `4`); if writing
an audit record fails while the proxy is running, the error is logged to stderr
and the proxy continues. A failed audit write never weakens a deny or reverses
a `tools/list` filter already applied — the security-critical decision is
returned to the client regardless of audit state.

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

## Request tracking behavior

The proxy tracks only the client requests it must act on later. Today that is
`tools/list`: the proxy remembers each `tools/list` request so it can filter the
matching response. This tracking is hardened against the protocol edge cases
below.

- **Tracked by method + id.** Each tracked request is keyed by both its
  JSON-RPC `method` and a canonical id key (the id serialized to compact JSON,
  so `1`, `"1"`, `[1]`, `{"a":1}`, and `true` each have a stable, distinct key).
  A response is only filtered when its `(method, id)` matches a tracked request.
  A `tools/call` result (or any other method) that happens to reuse the same id
  style is never re-shaped into a tool list.
- **Notifications are not tracked.** A `tools/list` message with no usable id
  (a notification) is forwarded unchanged and is never added to the tracking
  set, because there is no response to match it against.
- **Deterministic cleanup.** Tracking entries are reference-counted. Tracking a
  duplicate in-flight `tools/list` id increments the count; each matching
  response decrements it, and the entry is removed only when the count reaches
  zero. This means two identical `tools/list` ids in flight are both handled
  unambiguously: the first response does not silently orphan the second.
- **Server errors clear tracking.** A JSON-RPC error response for a tracked
  `tools/list` id passes through unchanged and clears the tracking entry. The
  proxy never fabricates a tool list from an error.
- **Unknown / no-id responses pass through.** A response whose id matches no
  tracked request, or whose id is missing/null, is forwarded unchanged and
  does not affect tracking. A tracked-id response whose `result` is not a tool
  list (no `tools` object) is also forwarded unchanged and its tracking entry
  is cleared, so entries cannot leak and later match an unrelated response.
- **Malformed tool lists fail safe.** A `tools/list` result that is not a valid
  tool list (missing `result`, `result` not an object, missing `tools`, or
  `tools` not an array) is rewritten to `{"tools":[]}` and audited as
  `tools_list_malformed`. Denied and default-denied tools are removed from
  allowed lists as before.

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
- Exact tool-name and method-name matching only; no wildcard (except the
  `"*` method allow wildcard), prefix, regex, argument-aware, or
  schema-aware rules.
- Per-server scoping is selected explicitly with `--server-name`; the proxy
  does not auto-discover or authenticate MCP server identity.
- The proxy inspects every client→server JSON-RPC request method and
  server→client JSON-RPC request/notification method. Tool-name policy still
  applies only to client→server `tools/call`, and `tools/list` filtering still
  applies only to tracked server responses for client `tools/list` requests.
- It does not inspect tool results, resource contents, prompt responses,
  or sampling responses beyond what is needed for `tools/list` response
  filtering.
- No filesystem path-scoped argument policy in this release; argument
  values are never inspected or logged.
- JSON-RPC batch arrays are not unpacked. A batch line in either inspected
  direction is denied fail closed — answered with a single null-id JSON-RPC
  error toward the sender, audited as `batch_denied`, and never forwarded —
  even if every call inside it names an allow-listed method/tool.
- Invalid client JSON input lines are **dropped** before forwarding (they are
  never sent to the server); valid JSON-RPC requests, responses, and
  notifications are forwarded unchanged. Invalid server JSON lines are passed
  through unchanged for the client's own parser to reject.
- Tracking is best-effort and scoped to `tools/list`: a client that never sends
  `tools/list`, or that reuses one id for multiple unrelated methods, may see a
  tracked-id response forwarded unchanged with its tracking entry cleared. The
  proxy does not reorder, buffer, or correlate responses beyond id matching.
- One client, one server, one process; no daemon mode, API server, shell hooks,
  command interception, terminal-command scanning, or network interception —
  those remain out of scope.
