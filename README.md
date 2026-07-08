# EtherFence

EtherFence is an open-source **AI Agent Security Posture & Runtime Control** project.

One-line idea: **Tirith protects terminal commands; EtherFence governs agent access.**

Status: **pre-alpha**. The current v0.1.5 foundation is scan-only posture discovery with remediation guidance, CI posture gates, baseline/diff support, versioned TOML policy profiles, and built-in example policy profiles. It is not production-ready and does not enforce policy at runtime.

## What v0.1.5 does

`etherfence scan` conservatively discovers local AI agent and MCP configuration files and reports posture risks/hints with rationale, impact, recommendations, fingerprints, optional baseline status, and optional policy status:

- MCP server configured
- broad filesystem path access hints
- risky command/shell-capable MCP hints
- network-capable MCP hints
- MCP environment variables
- secret-looking environment variable names
- Tirith binary/config/lockfile presence when detectable
- scan-only policy violations from a versioned TOML policy profile

Initial inventory targets:

- Claude Code
- Cursor
- VS Code
- Windsurf
- Gemini CLI
- Codex CLI
- Tirith

The parser intentionally uses conservative path discovery and fixture-backed config parsing. Missing files are skipped gracefully. Findings are posture hints, not proof of exploitability.

## Policy profile mode

Policy profile mode is scan-only. `--policy <file>` evaluates scan results against expected posture and emits policy-generated findings. It does not block agents, proxy MCP traffic, intercept commands, install shell hooks, run a daemon, or intercept network traffic.

Policy files use schema `ef-policy/v0.1`:

```toml
schema_version = "ef-policy/v0.1"
name = "developer-laptop"
description = "Balanced scan-only posture policy for local AI coding agents on developer workstations."
require_tirith = false

[agents."Claude Code"]
allowed_mcp_servers = ["filesystem", "github"]

[filesystem]
allowed_path_prefixes = ["/path/to/project"]
denied_paths = ["/", "/home/user", "/Users/example"]

[environment]
allowed_name_patterns = ["^GITHUB_", "^NODE_"]
deny_secret_like_names = true
```

Policy-generated finding IDs:

- `EF-POL-001` unexpected MCP server
- `EF-POL-002` disallowed filesystem path
- `EF-POL-003` disallowed environment variable exposure
- `EF-POL-004` secret-like environment variable exposure
- `EF-POL-005` Tirith not detected when required

Built-in/example profiles:

- `examples/policies/developer-laptop.toml`
- `examples/policies/ci-runner.toml`
- `examples/policies/research-workstation.toml`
- `examples/policies/strict.toml`

Inspect built-in profile metadata/content:

```sh
cargo run -p etherfence-cli -- policy list
cargo run -p etherfence-cli -- policy show developer-laptop
```

See `docs/policy.md` for the full policy schema and profile intent.

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

Scan with each built-in policy profile:

```sh
cargo run -p etherfence-cli -- scan --policy examples/policies/developer-laptop.toml
cargo run -p etherfence-cli -- scan --policy examples/policies/ci-runner.toml
cargo run -p etherfence-cli -- scan --policy examples/policies/research-workstation.toml
```

Fail CI on high-severity policy violations and posture hints using the CI runner profile:

```sh
cargo run -p etherfence-cli -- scan \
  --policy examples/policies/ci-runner.toml \
  --fail-on high \
  --format json
```

Create a baseline from current known findings:

```sh
cargo run -p etherfence-cli -- scan --write-baseline etherfence-baseline.json
```

Scan with a baseline and show new/existing/resolved status:

```sh
cargo run -p etherfence-cli -- scan --baseline etherfence-baseline.json
```

Fail CI only on newly introduced high-severity findings:

```sh
cargo run -p etherfence-cli -- scan \
  --baseline etherfence-baseline.json \
  --fail-on-new high \
  --format json
```

Combine baseline and policy so policy findings participate in `--fail-on-new`:

```sh
cargo run -p etherfence-cli -- scan \
  --policy examples/policies/ci-runner.toml \
  --baseline etherfence-baseline.json \
  --fail-on-new high \
  --format json
```

For fixture scans during development:

```sh
cargo run -p etherfence-cli -- scan --root tests/fixtures/home
cargo run -p etherfence-cli -- scan --root tests/fixtures/home --format json
cargo run -p etherfence-cli -- scan --root tests/fixtures/home --policy examples/policies/developer-laptop.toml
cargo run -p etherfence-cli -- scan --root tests/fixtures/home --format markdown --policy examples/policies/ci-runner.toml
```

## Sample policy output

```text
EtherFence scan report
======================
Schema: ef-scan-report/v0.1.1
Status: pre-alpha-scan-only
Summary: 7 inventory item(s), 24 finding(s): high=12, medium=8, low=4, info=0
Policy: ci-runner (examples/policies/ci-runner.toml, schema=ef-policy/v0.1) checks=17, pass=6, violations=11, not_applicable=0, require_tirith=false

Findings by severity:

HIGH
- EF-POL-001 Unexpected MCP server for agent policy: shell-tools [Claude Code / ~/.claude.json] status=not_applicable policy_status=violation fingerprint=efp1-...
  Rationale: The MCP server is not in the policy allowlist for this agent.
  Recommendation: Remove the MCP server or add it to the agent's allowed_mcp_servers after review.
```

JSON output uses the documented `ef-scan-report/v0.1.1` shape with `schema_version`, `scanned_root`, `inventory`, `findings`, `summary`, optional `policy`, and optional `baseline`. Baseline files use `ef-baseline/v0.1.3`. See `docs/json-schema.md`.

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
