# EtherFence

EtherFence is an open-source **AI Agent Security Posture & Runtime Control** project.

One-line idea: **Tirith protects terminal commands; EtherFence governs agent access.**

Status: **pre-alpha**. The current v0.1.1 foundation is scan-only posture discovery with remediation guidance. It is not production-ready.

## What v0.1.1 does

`etherfence scan` conservatively discovers local AI agent and MCP configuration files and reports posture risks/hints with rationale, impact, and recommendations:

- MCP server configured
- broad filesystem path access hints
- risky command/shell-capable MCP hints
- network-capable MCP hints
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

The parser intentionally uses conservative path discovery and fixture-backed config parsing. Missing files are skipped gracefully. Findings are posture hints, not proof of exploitability.

## Sample output

```text
EtherFence scan report
======================
Schema: ef-scan-report/v0.1.1
Status: pre-alpha-scan-only
Summary: 7 inventory item(s), 21 finding(s): high=3, medium=7, low=10, info=1

Findings by severity:

HIGH
- EF-MCP-001 Broad filesystem access hint: filesystem [Claude Code / ~/.claude.json]
  Rationale: The MCP server configuration contains values that look like broad filesystem roots or filesystem-capable tooling.
  Recommendation: Restrict MCP filesystem servers to explicit project directories such as /path/to/project, avoid home-directory or root-level grants, and separate sensitive repos where possible.
```

JSON output uses a versioned shape with `schema_version`, `scanned_root`, `inventory`, `findings`, and `summary`. Each finding includes stable fields such as `id`, `title`, `severity`, `agent`, `target`, `rationale`, `impact`, `recommendation`, and `references`.

## Non-goals for v0.1.x

EtherFence v0.1.x does **not** implement:

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
cargo run -p etherfence-cli -- scan --root tests/fixtures/home --format json
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
