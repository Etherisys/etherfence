# EtherFence Architecture

EtherFence v0.2.6 is a small Rust workspace with scan-only posture discovery
plus an experimental MCP stdio boundary proxy.

## Crates

- `etherfence-cli`: command-line entrypoint and output selection
- `etherfence-core`: shared inventory, finding, and report models
- `etherfence-inventory`: conservative local config discovery and parsing
- `etherfence-detectors`: posture finding heuristics over inventory
- `etherfence-policy`: scan-only TOML posture policy evaluation
- `etherfence-report`: human-readable, JSON, Markdown, and SARIF report rendering
- `etherfence-mcp`: experimental MCP stdio boundary proxy (policy, audit log, proxy engine)

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
3. The proxy selects the configured server scope (`--server-name`, default `default`) and spawns the MCP server child process.
4. It pumps newline-delimited JSON-RPC lines in both directions.
5. `tools/call` requests from the client are checked against the policy: global deny, server deny, server allow, global allow, then default deny. Allowed calls are forwarded unchanged; denied calls receive a JSON-RPC error from the proxy and never reach the server.
6. Client `tools/list` requests are tracked by `(method, id)` with reference
   counted cleanup; matching successful server responses have `result.tools`
   filtered with the same policy so denied/default-denied tools are not
   advertised. Unexpected successful `tools/list` shapes are rewritten to
   advertise an empty tools list. Notifications, unknown/no-id responses, and
   unrelated-method responses that reuse a tracked id style pass through
   unchanged; server errors clear the tracked entry.
7. Unrelated protocol messages pass through untouched.
8. Tool-call and tool-list filter decisions are optionally appended to a JSONL audit log with timestamp, server name, decision, reason, argument key names only for calls, and count/name metadata only for list filtering.
9. Compatibility tests use a checked-in deterministic stdio MCP fixture plus
   an optional `ETHERFENCE_REAL_MCP_CMD` real-server smoke test that is skipped
   by default.

See `docs/mcp-proxy.md` for details and limitations.

## Runtime posture

The scan commands remain read-only and fail gracefully when config files are
missing. The MCP proxy is the only runtime component: it is an opt-in,
per-invocation stdio process. EtherFence still has no daemon, shell hooks,
command interception, terminal-command scanning, or network interception.
