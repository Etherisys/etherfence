# EtherFence

EtherFence is an open-source **AI Agent Security Posture & Runtime Control** project.

One-line idea: **Tirith protects terminal commands; EtherFence governs agent access.**

Status: **pre-alpha**. The current v0.1.2 foundation is scan-only posture discovery with remediation guidance, CI posture gates, and review-friendly exports. It is not production-ready.

## What v0.1.2 does

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

## CLI examples

Local scan:

```sh
cargo run -p etherfence-cli -- scan
```

JSON output for automation:

```sh
cargo run -p etherfence-cli -- scan --format json
```

Markdown output for security review notes:

```sh
cargo run -p etherfence-cli -- scan --format markdown
```

Only display high-severity findings:

```sh
cargo run -p etherfence-cli -- scan --severity-threshold high
```

Fail CI when high-severity posture hints are present:

```sh
cargo run -p etherfence-cli -- scan --format json --fail-on high
```

For fixture scans during development:

```sh
cargo run -p etherfence-cli -- scan --root tests/fixtures/home
cargo run -p etherfence-cli -- scan --root tests/fixtures/home --format json
cargo run -p etherfence-cli -- scan --root tests/fixtures/home --format markdown
```

## Sample output

```text
EtherFence scan report
======================
Schema: ef-scan-report/v0.1.1
Status: pre-alpha-scan-only
Summary: 7 inventory item(s), 3 finding(s): high=3, medium=0, low=0, info=0

Findings by severity:

HIGH
- EF-MCP-001 Broad filesystem access hint: filesystem [Claude Code / ~/.claude.json]
  Rationale: The MCP server configuration contains values that look like broad filesystem roots or filesystem-capable tooling.
  Recommendation: Restrict MCP filesystem servers to explicit project directories such as /path/to/project, avoid home-directory or root-level grants, and separate sensitive repos where possible.
```

JSON output uses the documented `ef-scan-report/v0.1.1` shape with `schema_version`, `scanned_root`, `inventory`, `findings`, and `summary`. See `docs/json-schema.md`.

## Non-goals for v0.1.x

EtherFence v0.1.x does **not** implement:

- daemon mode
- runtime blocking
- MCP proxying
- network interception
- shell hooks
- command interception
- terminal command scanning duplicated from Tirith
- homograph, `curl | bash`, paste, or shell-hook detection

Tirith is treated as complementary terminal-command protection.

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
