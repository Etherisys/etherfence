# EtherFence

EtherFence is an open-source **AI Agent Security Posture & Runtime Control** project.

One-line idea: **Tirith protects terminal commands; EtherFence governs agent access.**

Status: **pre-alpha**. The current v0.1.0 foundation is scan-only posture discovery. It is not production-ready.

## What v0.1.0 does

`etherfence scan` conservatively discovers local AI agent and MCP configuration files and reports early posture findings:

- MCP server configured
- broad filesystem path access hints
- risky command/shell-capable tool hints
- network-capable tool hints
- MCP environment variables
- secret-looking environment variable names
- Tirith binary/config/lockfile presence when detectable

Initial inventory targets:

- Claude Code
- Cursor
- VS Code
- Windsurf
- Gemini CLI
- Codex CLI
- Tirith

The parser intentionally uses conservative path discovery and fixture-backed config parsing. Missing files are skipped gracefully. Findings are hints, not proof of exploitability.

## Non-goals for v0.1.0

EtherFence v0.1.0 does **not** implement:

- daemon mode
- runtime blocking
- MCP proxying
- network interception
- shell hooks
- terminal command scanning duplicated from Tirith
- homograph, `curl | bash`, paste, or shell-hook detection

Tirith is treated as complementary terminal-command protection.

## Build and run

```sh
cargo build
cargo run -p etherfence-cli -- scan
cargo run -p etherfence-cli -- scan --format json
```

For fixture scans during development:

```sh
cargo run -p etherfence-cli -- scan --root tests/fixtures/home
```

## Development checks

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo build
git diff --check
```

## License

Apache-2.0.
