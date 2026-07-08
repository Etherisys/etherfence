# EtherFence Architecture

EtherFence v0.1.0 is a small Rust workspace with scan-only posture discovery.

## Crates

- `etherfence-cli`: command-line entrypoint and output selection
- `etherfence-core`: shared inventory, finding, and report models
- `etherfence-inventory`: conservative local config discovery and parsing
- `etherfence-detectors`: posture finding heuristics over inventory
- `etherfence-report`: human-readable and JSON report rendering

## Data flow

1. CLI runs `etherfence scan`.
2. Inventory scans conservative paths under the selected root, defaulting to `HOME`.
3. Parsers extract MCP server names, commands, args, URLs, and environment variable names.
4. Detectors emit findings for MCP presence, filesystem breadth, command/network hints, env exposure, secret-looking env names, and Tirith presence.
5. Report renders either human-readable text or JSON.

## Runtime posture

v0.1.0 has no daemon, proxy, runtime blocking, shell hook, or network interception. It is intentionally read-only and fails gracefully when config files are missing.
