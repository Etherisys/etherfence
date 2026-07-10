# EtherFence v1.1.0 secure agent onboarding

EtherFence v1.1.0 adds a local `setup` command family for safely helping users wrap local stdio MCP servers through `etherfence mcp-proxy`.

This document is the implementation safety contract. It intentionally limits v1.1.0 to local files, local stdio MCP configs, and conservative rewrites. It does not add a daemon, cloud service, network listener, shell hook, model-provider migration, API-key handling, or approval-setting management.

## Command family

| Command | Mutates files? | Purpose |
| --- | --- | --- |
| `etherfence setup detect` | No | Find known AI client MCP configs and classify configured MCP servers. |
| `etherfence setup plan` | No | Show a redacted before/after wrapping proposal. |
| `etherfence setup apply` | Yes | Back up supported configs, generate/validate conservative MCP proxy policies, then rewrite only supported stdio entries. |
| `etherfence setup rollback` | Yes | Restore only EtherFence-created setup backups. |
| `etherfence setup doctor` | No | Check setup health without starting MCP servers. |

## v1.1.0 write targets

Only these targets may be rewritten by `setup apply` in v1.1.0:

| Target | Config shape | Notes |
| --- | --- | --- |
| Claude-style JSON configs | top-level `mcpServers` object | Includes Claude Desktop/Claude Code style local stdio entries. |
| Cursor MCP JSON configs | top-level `mcpServers` object | Global/project Cursor MCP configs. |
| VS Code MCP JSON configs | `servers` object in `mcp.json`; `mcp.servers` in settings JSON | Stdio servers require `type = "stdio"` when present/needed. |

All other catalog entries are detect/advisory-only until their format and safe rewrite semantics are explicitly implemented and tested.

## v1.1.0 advisory catalog

These clients may be detected and described, but `setup apply` must not rewrite them in v1.1.0 unless a later change explicitly promotes them with tests:

- Hermes Agent by Nous Research
- Google Antigravity
- Windsurf
- Gemini CLI
- Codex CLI
- OpenCode
- Cline
- Roo Code
- Aider
- Continue

Unsupported/advisory entries should explain the detected config path and why EtherFence is not rewriting it yet. They must not dump full config content.

## Hard safety invariants

### Read-only commands

- `setup detect`, `setup plan`, and `setup doctor` must not create, modify, or delete config, policy, backup, state, or audit files.
- Read-only commands must not spawn MCP servers, start background processes, contact networks, or create shell hooks.
- Read-only command output must not contain full config dumps, environment values, API keys, or unredacted command argument values.

### Apply

- `setup apply` must build the full plan before any write, including parsing every supported config that exists under the selected root.
- It must validate every generated MCP policy before writing backups, policies, or client configs.
- It must create EtherFence-owned backups for every file it will modify before modifying any config file.
- It must modify only supported MCP server entries, never model providers, API keys, approval settings, non-MCP keys, or unrelated files.
- Unknown fields must be preserved.
- Already-wrapped servers must not be double-wrapped.
- Advisory-only clients must never be rewritten.
- Failed apply must avoid partial state where possible; parse/validation failures must happen before any backup, policy, or config file is written, and write-phase failures must best-effort restore completed config rewrites and remove generated setup state from the failed run.

### Rollback

- `setup rollback` must only use EtherFence-created setup backup manifests from known backup locations derived from supported config paths.
- It must require the manifest `original_path` to match a supported config path.
- It must require the manifest `backup_path` to equal `original.json` beside that manifest.
- It must not restore arbitrary files or user-supplied backup paths that lack the EtherFence manifest marker and valid scoped paths.
- It must refuse unsafe path traversal in backup metadata.
- It must store backup and post-apply hashes, then refuse rollback when the current config no longer matches the post-apply hash so user edits are not silently overwritten.

### Policy generation

- Generated policies must use `schema_version = "ef-mcp-policy/v0.1"`.
- Generated policies must pass `etherfence_mcp::parse_mcp_policy` before apply writes config.
- Generated policies must not include original server env values, API keys, or full command argument lists.
- The v1.1.0 starter policy should be conservative and easy to inspect; stricter user tuning can happen after onboarding.

### Doctor

`setup doctor` may check:

- supported config files parse
- wrapped servers point at `etherfence mcp-proxy`
- wrapped policy paths exist
- policy files validate
- no double-wrap is present
- backup manifests are well-formed
- advisory-only clients are reported as advisory

`setup doctor` must not start the original MCP server or execute tool calls.

## Implementation shape

Prefer a dedicated library crate:

```text
crates/etherfence-setup/
  src/lib.rs
  src/catalog.rs
  src/detect.rs
  src/plan.rs
  src/policy.rs
  src/backup.rs
  src/apply.rs
  src/rollback.rs
  src/doctor.rs
```

The CLI should remain a thin wrapper that maps `setup` subcommands to library calls.

## Test requirements

Minimum release gates for v1.1.0:

- `cargo fmt --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test`
- `cargo build`
- `git diff --check`

Feature tests must cover:

- detect/plan/doctor are read-only against fixture homes
- apply creates backups before rewrites
- generated policies validate before rewrites
- unknown fields and non-MCP fields are preserved
- already-wrapped servers are skipped
- advisory-only clients are never rewritten
- rollback uses only EtherFence manifests
- stdout/stderr do not leak fixture secret values
