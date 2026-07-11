# EtherFence Architecture

EtherFence v0.4.1 is a small Rust workspace with scan-only posture discovery
plus an experimental MCP stdio boundary proxy.

## Crates

- `etherfence-cli`: command-line entrypoint and output selection
- `etherfence-core`: shared inventory, finding, and report models
- `etherfence-inventory`: conservative local config discovery and parsing
- `etherfence-detectors`: posture finding heuristics over inventory
- `etherfence-policy`: scan-only TOML posture policy evaluation
- `etherfence-report`: human-readable, JSON, Markdown, and SARIF report rendering
- `etherfence-mcp`: experimental MCP stdio boundary proxy (policy, audit log, proxy engine)
- `etherfence-setup`: local `setup` onboarding command family — client detection/wrapping (`detect`/`plan`/`apply`/`rollback`/`doctor`), the v1.2.0 client catalog (`catalog.rs`), and MCP server capability classification/starter-policy recommendation (`classification.rs`)

## Scan data flow

1. CLI runs `etherfence scan`.
2. Inventory scans conservative paths under the selected root, defaulting to `HOME`.
3. Parsers extract MCP server names, commands, args, URLs, and environment variable names.
4. Detectors emit findings for MCP presence, filesystem breadth, command/network hints, env exposure, secret-looking env names, and Tirith presence.
5. Optional scan-only policy evaluation adds policy findings.
6. Report renders human-readable text, JSON, Markdown, or SARIF.

## MCP proxy data flow (experimental)

1. CLI runs `etherfence mcp-proxy --policy <file> [--server-name <name>] -- <server-command> [args...]`.
2. The proxy loads and validates the `ef-mcp-policy/v0.1` TOML policy. Any load or validation failure fails closed: the MCP server child process is never started.
   Unicode/homograph hygiene is part of policy validation: suspicious Unicode
   in policy names, server scopes, path-rule names, method/tool guard keys, or
   path keys is rejected instead of normalized.
3. The proxy selects the configured server scope (`--server-name`, default `default`) and spawns the MCP server child process.
4. It pumps newline-delimited JSON-RPC lines in both directions.
5. Every client→server JSON-RPC request is first checked against the
   method-level policy (v0.3.0): global deny, server deny, server allow,
   global allow, then default deny. Always-allowed methods (initialize,
   notifications/initialized, ping) bypass method policy. Denied methods
   receive a JSON-RPC error from the proxy and never reach the server.
6. `tools/call` requests that pass the method check are then checked
   against the tool-name policy: global deny, server deny, server allow,
   global allow, then default deny. Allowed calls are forwarded unchanged;
   denied calls receive a JSON-RPC error from the proxy and never reach
   the server.
7. v0.4.1 Unicode/homograph runtime checks deny non-ASCII/bidi/zero-width MCP
   method names and `tools/call` tool names before exact policy matching.
8. Configured v0.4.0 path guards then check selected local path-like tool
   arguments or `resources/read` URI params against explicit allow/deny roots.
   Deny roots win; malformed paths, paths outside allow roots, paths inside
   denied roots, non-`file://` guarded resource URIs, and guarded values with
   bidi/zero-width characters are denied before forwarding. Existing policies
   without path guards behave as before.
9. Client `tools/list` requests are tracked by `(method, id)` with reference
   counted cleanup; matching successful server responses have `result.tools`
   filtered with the same policy so denied/default-denied tools are not
   advertised. Unexpected successful `tools/list` shapes are rewritten to
   advertise an empty tools list. Notifications, unknown/no-id responses, and
   unrelated-method responses that reuse a tracked id style pass through
   unchanged; server errors clear the tracked entry.
10. Server→client JSON-RPC request/notification objects with a `method`
   field are checked against method policy before reaching the client. Denied
   id-bearing requests receive a JSON-RPC error back toward the server; denied
   notifications are dropped and audited. Server responses without a `method`
   continue through the existing response-filtering path.
11. Method decisions, tool-call decisions, path decisions, and tool-list filter decisions
   are optionally appended to a JSONL audit log with timestamp, server
   name, direction, decision, reason, request id type, argument/param key names,
   optional path rule/key/classification metadata only (no values or full paths),
   and count/name metadata only for list filtering.
12. Compatibility tests use a checked-in deterministic stdio MCP fixture
    plus an optional `ETHERFENCE_REAL_MCP_CMD` real-server smoke test that
    is skipped by default.

See `docs/mcp-proxy.md` for details and limitations.

## Client catalog and MCP capability classification (v1.2.0)

`etherfence setup catalog` and the classification extension to
`etherfence setup detect` are new, local-only, read-only components with
no new trust boundary: both read the same local config files
`etherfence_inventory::discover` already reads for `scan`/`setup detect`,
compute their output as pure functions (`etherfence-setup::catalog`,
`etherfence-setup::classification`), and are rendered by `etherfence-cli`.
Neither starts a process, opens a network connection, or invokes any MCP
protocol method — classification matches an already-parsed MCP server's
`command`/`args` against a small curated, checked-in signature table
(exact-match only, no heuristics), never the live server. Starter-policy
recommendations are deny-by-default and describe posture only; they are
not enforced anywhere and do not change `mcp-proxy`'s decision logic.

## Runtime posture

The scan commands remain read-only and fail gracefully when config files are
missing. The MCP proxy is the only runtime component: it is an opt-in,
per-invocation stdio process. EtherFence still has no daemon, shell hooks,
command interception, terminal-command scanning, or network interception.
