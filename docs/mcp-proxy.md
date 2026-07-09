# MCP Boundary Proxy (experimental)

`etherfence mcp-proxy` is the first prototype in the EtherFence v0.2.x
runtime-control line. It is a minimal MCP **stdio** boundary proxy that sits
between an MCP client and an MCP server, audits MCP tool calls, and
allows/denies them deterministically using a small TOML policy.

Status: **experimental prototype**. It is not production-ready, it is not a
daemon or endpoint agent, and it does not replace the v0.1.x scan-only
posture commands, which are unchanged.

## Usage

```sh
etherfence mcp-proxy --policy <file> [--audit-log <file>] -- <server-command> [args...]
```

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
5. Leaves every other protocol message (`initialize`, `tools/list`,
   responses, notifications, and so on) untouched.

Example, wrapping a filesystem MCP server:

```sh
etherfence mcp-proxy \
  --policy /home/user/mcp-boundary.toml \
  --audit-log /home/user/etherfence-mcp-audit.jsonl \
  -- npx -y @modelcontextprotocol/server-filesystem /home/user/projects
```

In an MCP client configuration this means replacing the server command with
`etherfence` and moving the original command after `--`.

When the client closes its input stream, the proxy closes the server's stdin,
waits for the server to exit, and exits with the server's exit code.

## Policy

Policies use schema `ef-mcp-policy/v0.1`:

```toml
schema_version = "ef-mcp-policy/v0.1"
name = "minimal-mcp-boundary"

[tools]
allow = ["github.list_repos", "filesystem.read"]
deny = ["filesystem.read_secret", "shell.run"]
```

An example lives at `examples/policies/mcp-minimal-boundary.toml`.

Decision rules, in order, all deterministic:

1. Tool name in `deny` → **deny** (deny wins over allow).
2. Tool name in `allow` → **allow**.
3. Anything else → **deny** (default deny).

Tool names are matched exactly. There are no globs, prefixes, or regular
expressions in `ef-mcp-policy/v0.1`.

Fail-closed cases:

- Missing, unreadable, or syntactically invalid policy file → the proxy exits
  before starting the server (decision `policy_error`).
- Unsupported `schema_version` or empty `name` → same fail-closed exit.
- A `tools/call` request whose tool name is missing or not a string → denied.

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
      "reason": "tool name is in the policy deny list"
    }
  }
}
```

Denied `tools/call` notifications (no `id`) are dropped without a response,
because JSON-RPC forbids replying to notifications; the decision is still
audited.

## Audit log

`--audit-log <file>` appends one JSON object per line (JSONL). Example:

```json
{"ts":"2026-07-09T02:04:56Z","event":"tool_call_decision","policy":"minimal-mcp-boundary","method":"tools/call","request_id":3,"tool":"shell.run","argument_keys":["api_token","command"],"decision":"deny","reason":"tool name is in the policy deny list"}
```

Fields:

- `ts`: RFC 3339 UTC timestamp
- `event`: `tool_call_decision` or `policy_load_error`
- `policy`: policy `name` (absent for policy load errors)
- `method`: JSON-RPC method (`tools/call`)
- `request_id`: JSON-RPC request id when present
- `tool`: tool name when it could be extracted
- `argument_keys`: sorted tool-call argument **key names only**
- `decision`: `allow`, `deny`, or `policy_error`
- `reason`: the policy reason for the decision

Argument values are never written to the audit log, so secret values passed
as tool arguments do not leak into it. Only argument key names are recorded.

## Limitations

- stdio transport only; HTTP/SSE MCP transports are not supported.
- Newline-delimited JSON-RPC framing only; each message must be one line.
- Exact tool-name matching only; no wildcard or per-server scoping.
- The proxy inspects `tools/call` requests. It does not inspect tool results,
  resources, prompts, or sampling traffic, and it does not rewrite
  `tools/list` responses, so denied tools may still be listed to the client.
- Non-JSON input lines are forwarded unchanged for the server to reject,
  matching plain JSON-RPC behavior.
- One client, one server, one process; no daemon mode, shell hooks, command
  interception, or network interception — those remain out of scope.
