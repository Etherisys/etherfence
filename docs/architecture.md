# EtherFence Architecture

EtherFence v0.2.0 is a small Rust workspace with scan-only posture discovery
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

1. CLI runs `etherfence mcp-proxy --policy <file> -- <server-command> [args...]`.
2. The proxy loads and validates the `ef-mcp-policy/v0.1` TOML policy. Any load or validation failure fails closed: the MCP server child process is never started.
3. The proxy spawns the MCP server child process and pumps newline-delimited JSON-RPC lines in both directions.
4. `tools/call` requests from the client are checked against the policy: deny list wins, allow list admits, everything else is denied by default. Allowed calls are forwarded unchanged; denied calls receive a JSON-RPC error from the proxy and never reach the server.
5. All other protocol messages pass through untouched.
6. Each tool-call decision is optionally appended to a JSONL audit log with timestamp, tool name, decision, reason, and argument key names only (never argument values).

See `docs/mcp-proxy.md` for details and limitations.

## Runtime posture

The scan commands remain read-only and fail gracefully when config files are
missing. The MCP proxy is the only runtime component: it is an opt-in,
per-invocation stdio process. EtherFence still has no daemon, shell hooks,
command interception, terminal-command scanning, or network interception.
