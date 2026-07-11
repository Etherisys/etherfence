# MCP policy UX (`etherfence mcp-policy`)

`etherfence mcp-policy` is a set of local, **serverless** commands that help
an operator author, review, and dry-run `ef-mcp-policy/v0.1`/`ef-mcp-policy/v0.2`
policy files used by `etherfence mcp-proxy`. Every subcommand here only reads a
policy file (and, for `check`, one JSON-RPC request/notification you provide)
and reuses the same parser and decision functions the live proxy uses. None of
these commands start, contact, or assume anything about a running MCP server,
and none of them execute a tool.

Status: as of v1.0.0, this CLI surface is **stable**, part of the same
production-ready-for-defined-scope posture as the rest of EtherFence.
Stable is not a universal certification. Warnings emitted by `explain` are
operator guidance, not proof that a policy is exploitable or safe — they
highlight policy shapes worth a second look. Passing `validate` or `check`
is evidence for that one policy file, not a certification of any specific
MCP server it will eventually be used with.

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
- every configured `ef-mcp-policy/v0.2` argument/param field guard (see
  below), under an `Argument/param field guards:` section
- a fixed statement of the always-on Unicode/homograph hardening posture
  (v0.4.1, extended to v0.2 selector segments) and the always-on audit
  redaction posture (values are never logged, regardless of what
  `--audit-log` records)
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
| `github-scoped-orgs` | `examples/policies/mcp-github-scoped-orgs.toml` | v0.2: GitHub issue tool restricted to a named organization/repository via enum/prefix field guards. |
| `messaging-named-destinations` | `examples/policies/mcp-messaging-named-destinations.toml` | v0.2: Messaging tool restricted to named destinations, with a forbidden `bypass` key. |
| `browser-approved-hosts` | `examples/policies/mcp-browser-approved-hosts.toml` | v0.2: Browser/API tool restricted to approved HTTPS hosts via the URL field guard. |
| `readonly-operation-guard` | `examples/policies/mcp-readonly-operation-guard.toml` | v0.2: General-purpose tool restricted to read-only operations, with numeric and nested-selector field guards. |

```sh
etherfence mcp-policy init --profile filesystem-project-readonly-hardened --output mcp-boundary.toml
etherfence mcp-policy init --profile github-scoped-orgs --output mcp-boundary.toml
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
  `tools/call`, the path decision when a path guard applies, the v0.2 guard
  decision (`Guard decision: key=... selector=... reason_category=...`) when
  an argument/param field guard applies, the decision reason/category, and
  whether the live proxy would forward the request;
- reports JSON-RPC batch arrays as denied fail-closed, matching the live
  proxy's behavior;
- never prints raw argument/param values, full paths, URIs, or guarded field
  values — only method names, tool names, decisions, reasons, and safe
  path-rule/path-key/classification or guard-key/selector/reason-category
  metadata, the same redaction posture `--audit-log` uses.

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

## `ef-mcp-policy/v0.2`: argument/param field guards

As of v1.5.0, a policy may declare `schema_version = "ef-mcp-policy/v0.2"` to
add deterministic, least-privilege constraints on individual fields inside a
tool's `arguments` object or a method's `params` object — on top of, not
instead of, the v0.1 tool/method/path policy above. `ef-mcp-policy/v0.1`
policies are unaffected: they keep parsing and evaluating exactly as before,
and a v0.2-only construct under `schema_version = "ef-mcp-policy/v0.1"` is
rejected at load time (fail closed) with an error naming
`ef-mcp-policy/v0.2`.

The goal is narrow and explicit: **contain** a tool call that is already
allowed, in case the calling agent is mistaken or prompt-injected — not
detect prompt injection, not infer intent, and not a general-purpose policy
language. See `docs/threat-model.md` for the full non-goals list.

Guards attach to the same tables v0.1 already uses for path guards —
`[tools."<tool>".arguments]` / `[methods."<method>".params]` — with three
additional, independently-optional constructs:

- `require_keys = [...]` / `forbid_keys = [...]` — keys that must be present
  or absent on the guarded object, checked regardless of value.
- `[<guard-table>.fields."<selector>"]` — one primitive constraint per
  selector. A selector is a bounded, dotted path (`org`, `filter.status`,
  `items.0.id`) — object keys or, against an array, all-digit indices — up to
  8 segments, with no wildcards and no regular expressions.

Six field-guard primitives are supported via `type = "..."`:

| `type` | Fields | Constrains |
|---|---|---|
| `exact` | `value` | field equals one scalar |
| `enum` | `values` (non-empty) | field equals one of a finite scalar set |
| `string` | `min_length`, `max_length`, `prefix` | string length bounds and a literal prefix |
| `number` | `min`, `max` | numeric bounds (inclusive) |
| `array` | `min_items`, `max_items`, `allowed_elements` | array length bounds and a finite allowed-element set |
| `url` | `schemes`, `hosts`, `ports`, `path_prefixes` | scheme allowlist, normalized-hostname allowlist, effective-port allowlist (explicit port, else `http`→80/`https`→443), and boundary-safe path-prefix allowlist |

Every guard fails closed for its own field: a missing key, a value of the
wrong JSON type, a malformed value (e.g. an unparseable URL, a URL with
userinfo in its authority, or any `%`-encoded URL value — all rejected as
ambiguous rather than decoded), or an unresolvable selector all deny that
guard's decision. A field with no guard configured behaves exactly as it
does today — guards apply only where configured. See
`specs/004-argument-aware-mcp-policy/contracts/ef-mcp-policy-v0.2.md` and
`specs/004-argument-aware-mcp-policy/data-model.md` for the complete field
list, validation rules, and the closed set of machine-readable
`reason_category` strings (e.g. `enum_value_not_allowed`,
`required_key_missing`, `url_host_not_allowed`) `check` and audit logs use.

Precedence: the v0.1 path guard (when configured) is evaluated first and is
unaffected by v0.2; v0.2 field guards are then evaluated only if the
decision so far is still `Allow`, and the first failing guard wins. Both the
live `mcp-proxy` and `mcp-policy check` run through the identical decision
functions — there is exactly one evaluator, never two implementations that
merely happen to agree.

```toml
schema_version = "ef-mcp-policy/v0.2"
name = "github-scoped"

[tools]
allow = ["github.create_issue"]

[tools."github.create_issue".arguments]
require_keys = ["org", "repo"]

[tools."github.create_issue".arguments.fields.org]
type = "enum"
values = ["my-org"]

[tools."github.create_issue".arguments.fields.repo]
type = "string"
prefix = "my-org/"
```

### Migrating a policy from v0.1 to v0.2

Migration is purely additive — there is nothing to rewrite:

1. Change `schema_version` from `"ef-mcp-policy/v0.1"` to `"ef-mcp-policy/v0.2"`.
2. Everything else in the file (tool/method allow/deny, `[path_rules]`,
   `path_keys`/`uri_keys`/`path_rule` guards, `[servers.*]` scopes) keeps its
   exact v0.1 meaning.
3. Add `require_keys`/`forbid_keys`/`fields.*` where you want field-level
   containment; leave any tool/method you don't guard untouched.

You'll know a policy *needs* v0.2 when `etherfence mcp-policy validate`
rejects a `require_keys`/`forbid_keys`/`fields` construct with an error
stating the file's `schema_version` must be `ef-mcp-policy/v0.2` — that is
the only behavior change v0.1 files can ever observe from this feature.

## Non-goals

Consistent with the rest of `etherfence mcp-proxy`, this UX layer adds no new
enforcement surface and does not add:

- a daemon, API service, or control plane
- an endpoint agent, shell hook, or terminal-command scanner
- network or TLS interception
- prompt-injection detection, natural-language analysis, or intent inference
- a general regular-expression, scripting, or expression policy language
- shell-command parsing, SQL analysis, or DLP/content inspection beyond the
  six v0.2 field-guard primitives above
- arbitrary MCP tool execution
- any change to `ef-mcp-policy/v0.1` parsing or evaluation, or any claim that
  a v0.2-guarded tool call makes the wrapped MCP server safe overall

See `docs/mcp-proxy.md` for the underlying policy schema and proxy behavior
these commands read and dry-run against, and
[`docs/mcp-proxy-operator-guide.md`](mcp-proxy-operator-guide.md) for a
practical walkthrough of wrapping a real MCP server, including where `check`
fits into that workflow.
