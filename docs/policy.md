# EtherFence Policy Profiles

Status: pre-alpha, scan-only. Policies evaluate discovered AI agent and MCP posture and emit findings. They do not enforce, block, proxy, hook, intercept commands, or intercept network traffic.

## Policy schema

Current policy schema version: `ef-policy/v0.1`.

A policy is a TOML file with top-level metadata and optional sections:

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

### Top-level fields

| Field | Required | Description |
| --- | --- | --- |
| `schema_version` | yes | Must currently be `ef-policy/v0.1`. Unsupported versions fail with a clear error. |
| `name` | yes | Stable policy profile name used in scan metadata. |
| `description` | no | Human-readable policy intent. |
| `require_tirith` | no | When true, emit `EF-POL-005` if Tirith is not detected. Default is false. |

### Agent allowlists

`[agents."Agent Name"].allowed_mcp_servers` lists MCP servers expected for that agent. If the list is present and non-empty, any other discovered server for that agent emits `EF-POL-001`.

Agent names can use display names such as `Claude Code`, `Cursor`, `VS Code`, `Windsurf`, `Gemini CLI`, and `Codex CLI`.

### Filesystem rules

`[filesystem].allowed_path_prefixes` lists project-scoped prefixes that filesystem-capable MCP servers may expose.

`[filesystem].denied_paths` lists explicitly denied broad paths. EtherFence also treats root and home-directory-wide grants such as `/`, `/home/user`, and `/Users/example` as broad grants.

Prefix and denied-path matching apply lexical path normalization before comparing: `.` segments are dropped and `..` segments are resolved against the path they appear in (a rooted path cannot be walked above its root). This means a discovered path such as `/path/to/project/../secrets` normalizes to `/path/to/secrets` and is correctly evaluated against `allowed_path_prefixes = ["/path/to/project"]` as *not* a child of the project prefix, rather than matching on the raw, unnormalized string. Both `/`-separated and `\`-separated (Windows) paths are handled the same way. This normalization is purely lexical (string-level) — it does not touch the filesystem, does not resolve symlinks, and does not require the path to exist, keeping policy evaluation deterministic and scan-only.

Filesystem policy violations emit `EF-POL-002`.

### Environment rules

`[environment].allowed_name_patterns` is a list of regular expressions for environment variable names allowed to be passed into MCP servers. Names outside those patterns emit `EF-POL-003`.

`deny_secret_like_names = true` emits `EF-POL-004` for names containing secret-looking terms such as token, secret, password, API key, access key, private key, credential, or auth.

## Built-in example profiles

Built-in profiles can be selected directly with `etherfence scan --policy-profile <name>` and inspected with:

```sh
cargo run -p etherfence-cli -- policy list
cargo run -p etherfence-cli -- policy show developer-laptop
```

### developer-laptop

Built-in name: `developer-laptop`

File equivalent: `examples/policies/developer-laptop.toml`

Intent: balanced local developer workstation policy.

- Allows common coding agents.
- Allows expected MCP servers such as `filesystem`, `github`, and selected context/search servers where reasonable.
- Denies root and home-directory-wide filesystem exposure.
- Denies secret-like environment variable names.
- Recommends Tirith conceptually, but does not require it because warning-only Tirith recommendations are not represented as policy findings in v0.1.8.

Example:

```sh
cargo run -p etherfence-cli -- scan --policy-profile developer-laptop
```

### ci-runner

Built-in name: `ci-runner`

File equivalent: `examples/policies/ci-runner.toml`

Intent: stricter CI or ephemeral automation host policy.

- Uses a narrow MCP server allowlist.
- Uses narrow project workspace filesystem prefixes.
- Denies broad filesystem paths.
- Denies secret-like environment variable names.
- Does not require Tirith by default because many CI runners do not provide interactive terminal controls.

Example CI gate:

```sh
cargo run -p etherfence-cli -- scan \
  --policy-profile ci-runner \
  --fail-on high \
  --format json
```

### research-workstation

Built-in name: `research-workstation`

File equivalent: `examples/policies/research-workstation.toml`

Intent: research-friendly workstation policy.

- Allows browser/search/network-capable MCP servers used for literature and web research workflows.
- Still denies broad filesystem access and secret-looking environment variable names.
- Shell-capable MCP tools remain scanner findings and should be reviewed separately; v0.1.8 does not add shell-command scanner logic or enforcement.

Example:

```sh
cargo run -p etherfence-cli -- scan --policy-profile research-workstation
```

## `--policy-profile <name>` vs `--policy <file>`

Use `--policy-profile <name>` when one of the built-in profiles fits your posture target and you want deterministic scans without carrying a policy file path. Supported built-in names are `developer-laptop`, `ci-runner`, `research-workstation`, and `strict`. Unknown names fail clearly and suggest `etherfence policy list`.

Use `--policy <file>` when you maintain a custom TOML policy file for a project, organization, or lab fixture. `--policy` and `--policy-profile` are mutually exclusive in a single scan.

Direct profile examples:

```sh
etherfence scan --policy-profile developer-laptop
etherfence scan --policy-profile ci-runner --fail-on high
etherfence scan --policy-profile ci-runner --baseline etherfence-baseline.json --fail-on-new high
```

## Policy findings and CI gates

Policy findings are regular scan findings after evaluation:

- `--severity-threshold` controls whether they are displayed.
- `--fail-on high` exits non-zero when high-severity policy or scanner findings exist.
- `--write-baseline` records policy findings if `--policy` or `--policy-profile` is used.
- `--baseline` marks policy findings as `new`, `existing`, or `resolved` by fingerprint.
- `--fail-on-new high` exits non-zero only for newly introduced high-severity policy or scanner findings.

Baseline plus policy example:

```sh
cargo run -p etherfence-cli -- scan \
  --policy-profile ci-runner \
  --baseline etherfence-baseline.json \
  --fail-on-new high \
  --format json
```

## Policy-generated finding IDs

| ID | Meaning |
| --- | --- |
| `EF-POL-001` | Unexpected MCP server for an agent allowlist. |
| `EF-POL-002` | Disallowed filesystem path for a filesystem-capable MCP server. |
| `EF-POL-003` | Disallowed environment variable name exposure. |
| `EF-POL-004` | Secret-like environment variable name exposure. |
| `EF-POL-005` | Tirith not detected when `require_tirith = true`. |

## Non-goals

Policy mode does not implement runtime blocking, daemon mode, MCP proxying, shell hooks, command interception, terminal-command scanner logic, or network interception.
