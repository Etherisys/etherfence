# EtherFence

EtherFence is an open-source **AI Agent Security Posture & Runtime Control** project.

One-line idea: **Tirith protects terminal commands; EtherFence governs agent access.**

Status: **pre-alpha**. The current v0.1.8 foundation is scan-only posture discovery with remediation guidance, CI posture gates, baseline/diff support, versioned TOML policy profiles, built-in policy profiles, direct `scan --policy-profile <name>` selection, conservative Linux/Windows discovery helpers, hardened fixture-backed config parsing, SARIF 2.1.0 export, and Linux/Windows release packaging. It is not production-ready and does not enforce policy at runtime.

## What v0.1.8 does

`etherfence scan` conservatively discovers local AI agent and MCP configuration files and reports posture risks/hints with rationale, impact, recommendations, fingerprints, optional baseline status, and optional policy status:

- MCP server configured
- broad filesystem path access hints
- risky command/shell-capable MCP hints
- network-capable MCP hints
- MCP environment variables
- secret-looking environment variable names
- Tirith binary/config/lockfile presence when detectable
- scan-only policy violations from a versioned TOML policy profile
- agent config files that exist but could not be parsed (`EF-CFG-001`)

Initial inventory targets:

- Claude Code
- Cursor
- VS Code
- Windsurf
- Gemini CLI
- Codex CLI
- Tirith

The parser intentionally uses conservative path discovery and fixture-backed config parsing. Missing files are skipped gracefully, malformed JSON/TOML config files are reported instead of aborting the scan, and unknown extra config fields are ignored. Fixture coverage exercises common shapes (minimal configs, multiple MCP servers, no MCP servers, malformed files, Linux- and Windows-style paths), but EtherFence does not claim complete support for every agent config format or install location. Findings are posture hints, not proof of exploitability.


## Linux and Windows usage

EtherFence remains conservative and scan-only on both Linux and Windows. It reads known local AI-agent/MCP configuration files and emits posture findings; it does not install services, intercept commands, proxy MCP traffic, hook shells, or intercept network traffic.

Linux default discovery uses `HOME` and existing Unix-style config paths such as `~/.claude.json`, `~/.cursor/mcp.json`, `~/.config/Code/User/settings.json`, `~/.gemini/settings.json`, and `~/.codex/config.toml`.

```sh
etherfence scan
etherfence scan --format json
etherfence scan --policy-profile developer-laptop
```

Windows default discovery uses `USERPROFILE`, `APPDATA`, and `LOCALAPPDATA` when available, and checks conservative Windows-style paths such as `%APPDATA%\Code\User\settings.json`, `%APPDATA%\Cursor\User\mcp.json`, `%APPDATA%\Windsurf\User\mcp_config.json`, `%APPDATA%\Gemini\settings.json`, and `%APPDATA%\Codex\config.toml`. Missing environment variables are skipped gracefully.

```powershell
.\etherfence.exe scan
.\etherfence.exe scan --format json
.\etherfence.exe scan --policy-profile developer-laptop
```

For deterministic fixture or repository scans on either OS, pass an explicit root:

```sh
etherfence scan --root tests/fixtures/home
etherfence scan --root tests/fixtures/windows-home
```

## Policy profile mode

Policy profile mode is scan-only. `--policy-profile <name>` loads a built-in profile by name, while `--policy <file>` loads a custom TOML policy file. Both evaluate scan results against expected posture and emit policy-generated findings. It does not block agents, proxy MCP traffic, intercept commands, install shell hooks, run a daemon, or intercept network traffic.

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

Built-in profiles selectable with `--policy-profile <name>`:

- `developer-laptop`
- `ci-runner`
- `research-workstation`
- `strict`

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

SARIF 2.1.0 output for code-scanning dashboards and SARIF-aware tooling:

```sh
etherfence scan --format sarif > etherfence.sarif
etherfence scan --policy-profile ci-runner --format sarif > etherfence.sarif
```

SARIF export works with `--policy`, `--policy-profile`, `--baseline`, and `--severity-threshold`; high maps to `error`, medium to `warning`, and low/info to `note`. See `docs/sarif.md` for the full mapping.

Only display high-severity findings:

```sh
cargo run -p etherfence-cli -- scan --severity-threshold high
```

Fail CI when high-severity posture hints are present:

```sh
cargo run -p etherfence-cli -- scan --format json --fail-on high
```

Scan with built-in policy profiles directly:

```sh
etherfence scan --policy-profile developer-laptop
etherfence scan --policy-profile ci-runner --fail-on high
etherfence scan --policy-profile ci-runner --baseline etherfence-baseline.json --fail-on-new high
```

The equivalent Cargo development commands are:

```sh
cargo run -p etherfence-cli -- scan --policy-profile developer-laptop
cargo run -p etherfence-cli -- scan --policy-profile ci-runner --fail-on high
cargo run -p etherfence-cli -- scan --policy-profile ci-runner --baseline etherfence-baseline.json --fail-on-new high
```

Use a custom policy file when you need local rules outside the built-in profiles:

```sh
cargo run -p etherfence-cli -- scan --policy examples/policies/ci-runner.toml
```

Fail CI on high-severity policy violations and posture hints using the CI runner profile:

```sh
cargo run -p etherfence-cli -- scan \
  --policy-profile ci-runner \
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
  --policy-profile ci-runner \
  --baseline etherfence-baseline.json \
  --fail-on-new high \
  --format json
```

For fixture scans during development:

```sh
cargo run -p etherfence-cli -- scan --root tests/fixtures/home
cargo run -p etherfence-cli -- scan --root tests/fixtures/home --format json
cargo run -p etherfence-cli -- scan --root tests/fixtures/home --policy-profile developer-laptop
cargo run -p etherfence-cli -- scan --root tests/fixtures/home --format markdown --policy-profile ci-runner
```

## Sample policy output

```text
EtherFence scan report
======================
Schema: ef-scan-report/v0.1.1
Status: pre-alpha-scan-only
Summary: 7 inventory item(s), 24 finding(s): high=12, medium=8, low=4, info=0
Policy: ci-runner (builtin:ci-runner, source=built-in-profile, schema=ef-policy/v0.1) checks=17, pass=6, violations=11, not_applicable=0, require_tirith=false

Findings by severity:

HIGH
- EF-POL-001 Unexpected MCP server for agent policy: shell-tools [Claude Code / ~/.claude.json] status=not_applicable policy_status=violation fingerprint=efp1-...
  Rationale: The MCP server is not in the policy allowlist for this agent.
  Recommendation: Remove the MCP server or add it to the agent's allowed_mcp_servers after review.
```

JSON output uses the documented `ef-scan-report/v0.1.1` shape with `schema_version`, `scanned_root`, `inventory`, `findings`, `summary`, optional `policy`, and optional `baseline`. Baseline files use `ef-baseline/v0.1.3`. See `docs/json-schema.md`. SARIF output is documented in `docs/sarif.md`.

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


## Local release packaging

Linux:

```sh
cargo build --release -p etherfence-cli
mkdir -p dist/etherfence-v0.1.8-linux-x86_64
cp target/release/etherfence dist/etherfence-v0.1.8-linux-x86_64/
tar -C dist -czf dist/etherfence-linux-x86_64.tar.gz etherfence-v0.1.8-linux-x86_64
```

Windows PowerShell:

```powershell
cargo build --release -p etherfence-cli
New-Item -ItemType Directory -Force -Path dist/etherfence-v0.1.8-windows-x86_64 | Out-Null
Copy-Item target/release/etherfence.exe dist/etherfence-v0.1.8-windows-x86_64/
Compress-Archive -Path dist/etherfence-v0.1.8-windows-x86_64 -DestinationPath dist/etherfence-windows-x86_64.zip -Force
```

GitHub Actions builds and uploads matching Linux `tar.gz` and Windows `zip` artifacts for CI runs.

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
