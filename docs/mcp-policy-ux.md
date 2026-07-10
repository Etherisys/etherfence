# MCP policy UX (`etherfence mcp-policy`)

`etherfence mcp-policy` is a set of local, **serverless** commands that help
an operator author, review, and dry-run `ef-mcp-policy/v0.1` policy files used
by `etherfence mcp-proxy`. Every subcommand here only reads a policy file (and,
for `check`, one JSON-RPC request/notification you provide) and reuses the
same parser and decision functions the live proxy uses. None of these commands
start, contact, or assume anything about a running MCP server, and none of
them execute a tool.

Status: as of v1.0.0, this CLI surface is **stable**, same as the rest of
EtherFence. Stable is not a security certification. Warnings emitted by
`explain` are operator guidance, not proof that a policy is exploitable or
safe — they highlight policy shapes worth a second look. Passing `validate`
or `check` is not production-readiness certification.

## Commands

### `etherfence mcp-policy validate <policy.toml>`

Parses and validates a policy file using the exact same loader
`etherfence mcp-proxy --policy` uses. Prints a one-line success message on a
valid policy, or a clear, actionable error (from the existing parser) on
failure — for example: unsupported `schema_version`, empty `name`, a
`path_rules` entry with no `allow_roots`, malformed TOML, or a method/tool
name containing suspicious Unicode (bidi controls, zero-width characters, or
non-ASCII text). Exits non-zero on failure.

```sh
etherfence mcp-policy validate examples/policies/mcp-resources-project-only.toml
```

### `etherfence mcp-policy explain <policy.toml>`

Prints a deterministic, human-readable summary of a policy:

- policy `name` and `schema_version`
- global method allow/deny (or a note that the built-in default applies)
- global tool allow/deny
- every `[servers.<name>]` scope's tool and method rules
- every `[path_rules.<name>]` entry's `allow_roots`/`deny_roots`
- every configured tool/method path guard and the path rule it references
- a fixed statement of the always-on Unicode/homograph hardening posture
  (v0.4.1) and the always-on audit redaction posture (values are never
  logged, regardless of what `--audit-log` records)
- a `Warnings` section

`explain` warns about policy shapes that are easy to get wrong, not about
anything it observed at runtime:

- a global `[methods] allow` list containing the `"*"` wildcard
- no `[methods]` section configured anywhere (global or per-server) — the
  built-in default (`tools/list`, `tools/call` only) silently applies
- no tool allowed anywhere in the policy (every `tools/call` is default-denied)
- a `[path_rules.<name>]` entry that no tool/method guard references
- a guard that references a `path_rule` name that is not defined
- an `allow_roots` entry that is a broad root such as `/`, `C:/`, or a bare
  drive letter
- a `path_rules` entry with an empty `deny_roots` list

These warnings are guidance, not a security verdict: a broad `allow_roots`
warning does not mean the policy is currently being exploited, and no
warnings does not mean the policy is safe for every deployment.

```sh
etherfence mcp-policy explain examples/policies/mcp-filesystem-project-readonly.toml
```

### `etherfence mcp-policy init --profile <name> [--output <file>] [--overwrite]`

Prints (or writes) a starter `ef-mcp-policy/v0.1` policy from a built-in
profile. Without `--output`, the policy TOML is printed to stdout. With
`--output <file>`, the command refuses to overwrite an existing file unless
`--overwrite` is also passed — it never silently clobbers a file.

Supported profiles:

| Profile | Backing example | Posture |
|---|---|---|
| `minimal` | `examples/policies/mcp-minimal-boundary.toml` | Exact-match global + per-server tool allow/deny only. |
| `strict-method-only` | `examples/policies/mcp-strict-method-only.toml` | Explicit `[methods]` allow/deny restricted to `tools/list`/`tools/call`. |
| `filesystem-project-readonly` | `examples/policies/mcp-filesystem-project-readonly.toml` | Project-root read-only filesystem tool with a path guard. |
| `filesystem-project-readonly-hardened` | `examples/policies/mcp-filesystem-project-readonly-hardened.toml` | Same as above with `deny_roots` expanded to common credential-like paths. |
| `resources-project-only` | `examples/policies/mcp-resources-project-only.toml` | Project-root-only `resources/read` over `file://` URIs, plus tool policy. |

```sh
etherfence mcp-policy init --profile filesystem-project-readonly-hardened --output mcp-boundary.toml
```

### `etherfence mcp-policy check --policy <policy.toml> --request <json> [--server-name <name>] [--direction client-to-server|server-to-client]`

Dry-runs exactly one JSON-RPC request/notification against a policy, using
the same `inspect_client_line`/`inspect_server_line` decision functions the
live proxy uses for the chosen `--direction` (default `client-to-server`).
`--request` accepts either inline JSON (starting with `{` or `[`) or a path to
a file containing the JSON.

`check`:

- **never starts or contacts an MCP server** — there is no server-command
  argument, and no process is spawned;
- **never executes a tool** — `tools/call` requests are classified, not run;
- **does not write an audit log** — nothing is appended anywhere by default;
- prints the method decision, the tool decision when the method is
  `tools/call`, the path decision when a path guard applies, the decision
  reason/category, and whether the live proxy would forward the request;
- reports JSON-RPC batch arrays as denied fail-closed, matching the live
  proxy's behavior;
- never prints raw argument/param values, full paths, or URIs — only method
  names, tool names, decisions, reasons, and safe path-rule/path-key/
  classification metadata, the same redaction posture `--audit-log` uses.

```sh
etherfence mcp-policy check \
  --policy mcp-boundary.toml \
  --request '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"filesystem.read","arguments":{"path":"/home/user/project/README.md"}}}'
```

Example output:

```
Decision: ALLOW
Would be forwarded: yes
Inspected by policy: yes
Category: tool_call_decision
Method: tools/call
Tool: filesystem.read
Reason: tool name is in the global policy allow list
Note: this is a local, serverless dry run. No MCP server was started or contacted and no tool was executed.
```

## `validate` vs `explain` vs `init` vs `check`

- `validate` answers: **does this policy file parse and pass schema/Unicode
  checks at all?**
- `explain` answers: **what does this policy actually allow, and what looks
  risky or confusing about its shape?**
- `init` answers: **give me a known-good starting policy for a common
  posture.**
- `check` answers: **what would the live proxy do with this one specific
  request, right now, without running anything?**

All four are local-only and serverless. None of them read from or write to
the network, start an MCP server child process, or execute a tool. `explain`
and `check` never modify the policy file; `init` only writes when `--output`
is given, and never overwrites silently.

## Non-goals

Consistent with the rest of `etherfence mcp-proxy`, this UX layer adds no new
enforcement surface and does not add:

- a daemon, API service, or control plane
- an endpoint agent, shell hook, or terminal-command scanner
- network or TLS interception
- broad URL filtering, content inspection, or DLP
- arbitrary MCP tool execution
- any change to the `ef-mcp-policy/v0.1` schema

See `docs/mcp-proxy.md` for the underlying policy schema and proxy behavior
these commands read and dry-run against, and
[`docs/mcp-proxy-operator-guide.md`](mcp-proxy-operator-guide.md) for a
practical walkthrough of wrapping a real MCP server, including where `check`
fits into that workflow.
