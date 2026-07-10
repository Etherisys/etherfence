# MCP proxy operator guide

This is the practical, task-oriented guide for putting `etherfence mcp-proxy`
in front of a real MCP server. For the full command reference, policy schema,
and behavior details, see [`docs/mcp-proxy.md`](mcp-proxy.md). For authoring
and dry-running policies without a server, see
[`docs/mcp-policy-ux.md`](mcp-policy-ux.md).

Status: `mcp-proxy` is a local, stdio-only MCP boundary proxy, production-ready
for controlled local-first deployments of its defined scope. It is not a
daemon, not a network service, and not a universal certification for every
MCP server, MCP client, or deployment environment — operators must still
test their chosen MCP servers and policies and monitor audit logs. See
[Security model / non-goals](../README.md#security-model--non-goals) in the
README and [`docs/mcp-compatibility-matrix.md`](mcp-compatibility-matrix.md)
for what is actually tested.

## Before and after

Without EtherFence, an MCP client talks directly to an MCP server over
stdio:

```text
AI client  --stdio-->  MCP server
```

With EtherFence, the client instead launches `etherfence mcp-proxy`, which
launches the real MCP server as its own child process and sits in the
middle of every message:

```text
AI client  --stdio-->  etherfence mcp-proxy  --stdio-->  MCP server
```

Nothing about the MCP server itself changes. You are not modifying the
server; you are changing what the *client* launches. The client still thinks
it is talking to one MCP server — it just happens to be `etherfence`.

## The command shape

```sh
etherfence mcp-proxy \
  --policy <path-to-policy.toml> \
  --server-name <policy-scope-name> \
  --audit-log <path-to-audit.jsonl> \
  -- <original-mcp-server-command> [original args...]
```

The `--` is load-bearing: it splits the command into two halves.

- **Before `--`**: `etherfence`'s own flags (`mcp-proxy`, `--policy`,
  `--server-name`, `--audit-log`). These are consumed by EtherFence and never
  passed to the real server.
- **After `--`**: the exact command you would have run to start the real MCP
  server directly, unchanged — executable, then its own arguments. EtherFence
  spawns this as a child process with piped stdin/stdout and forwards
  JSON-RPC between the client and this child.

If you already have a working MCP client config that runs
`<server-command> [args...]` directly, migrating means: keep that command
exactly as-is, put it after `--`, and put `etherfence mcp-proxy` plus its own
flags before it.

## What each flag does

### `--policy <file>`

Path to an `ef-mcp-policy/v0.1` TOML policy file. This is the only thing that
decides what is allowed. If the file is missing, unreadable, invalid TOML, an
unsupported `schema_version`, or has an empty `name`, the proxy **fails
closed**: it prints an error, optionally writes a `policy_error` audit
record, exits with code `2`, and the real MCP server is **never started**.
There is no "open" or "no policy" mode.

### `--server-name <name>`

Selects an optional per-server policy scope: `[servers.<name>.tools]` and
`[servers.<name>.methods]` sections in the same policy file. If omitted, the
scope is `default`. This lets one policy file carry different rules for
different MCP servers you wrap (for example, tighter rules for a
`filesystem` server than a `github` server), without maintaining separate
files. `--server-name` does not authenticate or verify server identity in
any way — it is purely a lookup key into the policy file you already trust.

### `--audit-log <file>`

Path to a JSONL (one JSON object per line) file that records every
method/tool/path decision the proxy makes: timestamp, policy name, server
name, method, tool name (when applicable), decision, reason, and safe
metadata (argument/param *key names* only). Optional — omit it and the proxy
still enforces policy, it just doesn't leave a trail. Argument values,
param values, full paths, URIs, prompt/message content, and secrets are
**never** written, regardless of what the wrapped server sends. If the audit
log file can't be opened at startup, the proxy fails closed (exit code `4`)
before starting the server; if a single write fails while running, that
failure is logged to stderr and the proxy keeps going — a broken audit log
never weakens a deny.

## How policy sections map to `--server-name`

A single `ef-mcp-policy/v0.1` file can define:

```toml
[tools]                        # global: applies to every --server-name
allow = ["github.list_repos"]
deny = ["shell.run"]

[servers.filesystem.tools]      # only applies when --server-name filesystem
allow = ["filesystem.read"]
deny = ["filesystem.write"]
```

Decision precedence for a tool name, in order, is always:

1. Global `[tools].deny` → **deny** (wins over everything else)
2. `[servers.<name>.tools].deny` → **deny**
3. `[servers.<name>.tools].allow` → **allow**
4. Global `[tools].allow` → **allow**
5. Anything else → **deny** (default deny)

`[methods]` / `[servers.<name>.methods]` follow the identical shape and
precedence for JSON-RPC method names (`tools/list`, `resources/read`,
`sampling/createMessage`, and so on) instead of tool names. If a policy has
no `[methods]` section at all, the built-in default allows only `tools/list`
and `tools/call` and denies everything else — this is the most common
reason a request you expected to pass gets denied.

Practical implication: running the *same* server twice with two different
`--server-name` values against the *same* policy file can produce two
different outcomes for the same tool name, if that name only appears in one
server's scoped section. Global `deny` always wins regardless of
`--server-name`.

## How `tools/list` filtering works

When the client sends `tools/list`, the proxy remembers that request (by
method + id) and lets it reach the server unchanged. When the server's
response comes back with a matching id, the proxy rewrites `result.tools`
before it reaches the client:

- tools in the deny list, or not covered by any allow rule (default deny),
  are removed;
- tool entries without a usable string `name` are removed;
- allowed tools are passed through with their full original structure
  (description, `inputSchema`, everything) unchanged;
- if the server's response has an unexpected shape (missing `result`,
  missing `tools`, `tools` not an array), the proxy fails safe and rewrites
  it to advertise an empty tool list rather than pass through something
  ambiguous.

This means the client only ever sees tool names it is actually allowed to
call — a denied tool is not just blocked at call time, it's invisible in the
client's own tool picker.

## How allowed and denied `tools/call` requests flow

- **Allowed**: the request is forwarded to the real server unchanged, and
  the server's real response (success or its own error) is forwarded back
  to the client unchanged. The proxy does not alter tool arguments or
  results.
- **Denied**: the proxy answers the client itself with a JSON-RPC error and
  the request **never reaches the server**:

  ```json
  {
    "jsonrpc": "2.0",
    "id": 3,
    "error": {
      "code": -32000,
      "message": "EtherFence MCP proxy denied this tool call by policy",
      "data": { "tool": "shell.run", "reason": "tool name is in the global policy deny list" }
    }
  }
  ```

  A denied `tools/call` sent as a JSON-RPC *notification* (no `id`) is
  dropped with no response at all, since JSON-RPC forbids replying to
  notifications — the decision is still written to the audit log.

The same allow/forward, deny/answer-locally pattern applies to every other
policed JSON-RPC method (`resources/read`, `prompts/get`,
`completion/complete`, and so on), and to server→client requests the server
itself initiates (`sampling/createMessage`, `roots/list`,
`elicitation/create`) — denied server→client requests get an error sent back
toward the server instead of reaching the client. See
[`docs/mcp-proxy.md`](mcp-proxy.md#denied-tool-calls) for the full direction
semantics.

## Dry-running policy decisions with `mcp-policy check`

Before wiring a policy into a live proxy run, dry-run it against one
JSON-RPC request — no server is started or contacted, no tool executes, and
nothing is written to disk:

```sh
etherfence mcp-policy check \
  --policy examples/policies/mcp-filesystem-readonly.toml \
  --server-name filesystem \
  --request '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"filesystem.read","arguments":{"path":"/home/user/notes.txt"}}}'
```

```text
Decision: ALLOW
Would be forwarded: yes
Inspected by policy: yes
Category: tool_call_decision
Method: tools/call
Tool: filesystem.read
Reason: tool name is in the server-specific policy allow list for filesystem
Note: this is a local, serverless dry run. No MCP server was started or contacted and no tool was executed.
```

Swap the tool name to something denied and you get:

```sh
etherfence mcp-policy check \
  --policy examples/policies/mcp-filesystem-readonly.toml \
  --server-name filesystem \
  --request '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"filesystem.write","arguments":{"path":"/home/user/notes.txt"}}}'
```

```text
Decision: DENY
Would be forwarded: no
...
Reason: tool name is in the global policy deny list
```

Use `--direction server-to-client` to dry-run a server-initiated method like
`sampling/createMessage`. See [`docs/mcp-policy-ux.md`](mcp-policy-ux.md) for
the full `check` flag reference.

## Inspecting audit logs

The audit log is JSONL — one JSON object per line, safe to `grep`/`jq`:

```sh
# Every deny, across all servers.
jq 'select(.decision == "deny")' etherfence-mcp-audit.jsonl

# Everything the proxy decided for one server scope.
jq 'select(.server == "filesystem")' etherfence-mcp-audit.jsonl

# Confirm no argument/param values ever landed in the log (should print nothing).
jq -r '.argument_keys, .param_keys' etherfence-mcp-audit.jsonl | grep -E '":|password|secret|token' || echo "no value-shaped content found"
```

Each line's `event` field tells you what kind of record it is:
`tool_call_decision`, `method_decision`, `tools_list_filtered`,
`batch_denied`, or `policy_load_error`. See
[`docs/mcp-proxy.md`](mcp-proxy.md#audit-log) for the full field reference —
`argument_keys`/`param_keys` are key names only, never values, and full tool
schemas are never logged for `tools_list_filtered`.

## Common failure modes

| Symptom | What it means | What to do |
| --- | --- | --- |
| Proxy exits immediately with code `2` and a "fail closed" message | The policy file is missing, unreadable, invalid TOML, has an unsupported `schema_version`, or an empty `name`. The server was **never started**. | Run `etherfence mcp-policy validate <policy.toml>` to get the exact parser error. |
| Proxy exits with code `3` | The real MCP server command after `--` could not be spawned (wrong path, not executable, missing interpreter). | Confirm the exact command after `--` runs on its own outside the proxy. |
| Proxy exits with code `4` | Either the audit log file could not be opened at startup, or an internal pipe I/O error occurred. | Check the `--audit-log` path is writable; check stderr for the specific error. |
| Client's tool picker shows fewer tools than the real server advertises | Working as intended: `tools/list` filtering removed denied/default-denied tools. | Run `etherfence mcp-policy explain <policy.toml>` to see the full allow/deny picture, or `mcp-policy check` the exact `tools/call` you expect to work. |
| Every non-`tools/list`/`tools/call` request is denied even though you didn't write a `[methods]` deny rule | No `[methods]` section exists in the policy at all, so the built-in default (`tools/list`+`tools/call` only) applies. | Add an explicit `[methods]` section with the methods you need in `allow`. |
| A tool name works with one `--server-name` but not another, using the same policy file | The tool is only in one server's `[servers.<name>.tools]` scope, or a global deny is masking a server-specific allow. | `mcp-policy explain <policy.toml>` prints every server scope's rules side by side. |
| `resources/read` (or another method) is denied even though you expected it to be allowed | Method policy is bidirectional and separate from tool policy: an allowed `tools/call` does not imply other methods are allowed. | Add the method to `[methods].allow` explicitly, or check with `mcp-policy check --request '{"...","method":"resources/read",...}'`. |
| A tool/method/path name containing unusual characters is denied with a Unicode-related reason | v0.4.1 Unicode/homograph hardening denies bidi controls, zero-width characters, and non-ASCII text in policy-matched names before normal policy matching runs. | This is by design, not a bug — use plain ASCII names in policy and requests. |

## Concrete config examples

Replace the direct MCP server command in your client config with
`etherfence mcp-proxy`, moving the original command and its arguments after
`--`. The examples below use placeholder paths — adjust them for your
machine.

### Generic config: before EtherFence

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "/usr/bin/npx",
      "args": [
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/home/example/projects"
      ]
    }
  }
}
```

### Generic config: after EtherFence

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "/usr/local/bin/etherfence",
      "args": [
        "mcp-proxy",
        "--policy",
        "/home/example/.config/etherfence/mcp-filesystem-readonly.toml",
        "--server-name",
        "filesystem",
        "--audit-log",
        "/home/example/.local/state/etherfence/mcp-audit.jsonl",
        "--",
        "/usr/bin/npx",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/home/example/projects"
      ]
    }
  }
}
```

Everything from `"command"` down through `"/home/example/projects"` in the
original config becomes the tail of `args` after the `"--"` entry. Nothing in
the original server command changes.

This exact shape is also checked in
[`docs/examples/mcp-client-generic-linux.json`](examples/mcp-client-generic-linux.json)
(and its Windows counterpart), so it cannot silently drift from what the
test suite verifies.

### Filesystem server example

Use [`examples/policies/mcp-filesystem-readonly.toml`](../examples/policies/mcp-filesystem-readonly.toml)
with `--server-name filesystem`:

```sh
etherfence mcp-proxy \
  --policy examples/policies/mcp-filesystem-readonly.toml \
  --server-name filesystem \
  --audit-log /home/example/.local/state/etherfence/mcp-audit.jsonl \
  -- npx -y @modelcontextprotocol/server-filesystem /home/example/projects
```

For path-scoped read access restricted to one project root (plus
credential-like paths denied even inside that root), use
[`examples/policies/mcp-filesystem-project-readonly-hardened.toml`](../examples/policies/mcp-filesystem-project-readonly-hardened.toml)
instead.

### Memory/notes server example

Use [`examples/policies/mcp-memory-notes-readonly.toml`](../examples/policies/mcp-memory-notes-readonly.toml)
with `--server-name memory`:

```sh
etherfence mcp-proxy \
  --policy examples/policies/mcp-memory-notes-readonly.toml \
  --server-name memory \
  --audit-log /home/example/.local/state/etherfence/mcp-audit.jsonl \
  -- npx -y @modelcontextprotocol/server-memory
```

This policy allows read/search tools (`memory.read_graph`,
`memory.search_nodes`, `memory.open_nodes`) and denies every
create/delete/mutate tool, both globally and in the `memory` server scope —
adjust the exact tool names to match your server's own `tools/list` output
before relying on it.

### Client-specific notes

EtherFence does not maintain separate wrapping instructions per MCP client
application beyond what is already checked into
[`docs/mcp-clients.md`](mcp-clients.md): Claude-style, Cursor, and VS
Code-style configs all use one of the two JSON shapes above (a top-level
`mcpServers` object, or VS Code's `mcp.servers` nesting). If your client
uses a different config file location or key name (including Windsurf,
Gemini CLI, or Codex CLI configs discovered by `etherfence scan` — see
`etherfence-inventory`'s supported agents), the wrapping pattern is
unchanged: keep the original server `command`/`args` exactly as they were,
move them after `--`, and put `etherfence mcp-proxy` and its own flags in
front. There is no client-specific behavior in `mcp-proxy` itself — it only
ever sees stdio JSON-RPC, never the client's own config file.
