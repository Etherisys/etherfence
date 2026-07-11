# EtherFence v1.1.0 secure agent onboarding

EtherFence v1.1.0 adds a local `setup` command family for safely helping users wrap local stdio MCP servers through `etherfence mcp-proxy`.

This document is the implementation safety contract. It intentionally limits v1.1.0 to local files, local stdio MCP configs, and conservative rewrites. It does not add a daemon, cloud service, network listener, shell hook, model-provider migration, API-key handling, or approval-setting management.

## Command family

| Command | Mutates files? | Purpose |
| --- | --- | --- |
| `etherfence setup catalog` | No | Print the fixed 10-client compatibility/catalog matrix (support tier, local presence). |
| `etherfence setup detect` | No | Find known AI client MCP configs, classify configured MCP servers by capability, and recommend a starter policy tier. |
| `etherfence setup plan` | No | Show a redacted before/after wrapping proposal. |
| `etherfence setup apply` | Yes | Back up supported configs, generate/validate conservative MCP proxy policies, then rewrite only supported stdio entries. |
| `etherfence setup rollback` | Yes | Restore only EtherFence-created setup backups. |
| `etherfence setup doctor` | No | Check setup health without starting MCP servers. |

## `etherfence setup catalog` (v1.2.0)

`etherfence setup catalog [--format human|json] [--root <path>]` prints
exactly one row per client in the fixed v1.2.0 client list (10 total,
always in this order): Claude-style config, Cursor, VS Code, Hermes,
Antigravity, Windsurf, Gemini CLI, Codex CLI, OpenCode, Cline / Roo Code.
It is read-only, offline, and always exits `0` (no `--fail-on` flag exists
for this command).

Each row reports one of four support tiers — a statement of *detection
confidence*, not a promise of write support (see "Catalog tier vs. write
support" below):

| Tier | Meaning |
| --- | --- |
| `fixture-verified` | The client has parsing logic backed by a checked-in fixture and a test asserting its exact catalog row. |
| `detect-only` | The client has real detection/parsing logic and existing fixture coverage at the inventory level, but no catalog-row-specific fixture test yet. |
| `advisory-only` | The client is named and its local presence can be detected, but no config/MCP-server parsing is attempted. |
| `unknown` | Reserved for a client whose detection state cannot be determined; not assigned to any of the 10 clients by default. |

At v1.2.0 ship time: Claude-style config, Cursor, and VS Code are
`fixture-verified`; Windsurf, Gemini CLI, and Codex CLI are `detect-only`;
Hermes, Antigravity, OpenCode, and Cline / Roo Code are `advisory-only`.

Each row also reports whether that client's configuration was found
locally on the current run and every discovered configuration path (a
client may have more than one, e.g. a global and a project-level config —
none are ever dropped or reordered).

`etherfence setup detect --format json` additionally carries, per MCP
server, a multi-label static capability classification
(`capabilities.labels`, e.g. `filesystem`, `shell-command-execution`,
`network`, or `unknown` when no curated rule matches) plus a deny-by-default
starter-policy recommendation (`recommendation.tier` is always `deny` in
v1.2.0; `recommendation.needsReview` is `true` when the label set includes
`unknown`, `shell-command-execution`, or `identity-auth`). Classification is
static and local-only: no MCP server is started, no network call is made,
and no MCP protocol method is ever invoked to produce it. See
[`docs/json-schema.md`](json-schema.md) for the full `ef-setup-catalog/v0.1`
and `ef-setup-detect/v0.1` schemas.

### Catalog tier vs. write support

`CatalogSupportTier` (above) and `WriteSupport` (below, used by `setup
apply`) are two independent axes and must not be conflated. Windsurf,
Gemini CLI, and Codex CLI are catalog `detect-only` — their presence and
MCP servers are reliably parsed — while remaining `WriteSupport::AdvisoryOnly`
for `setup apply` (i.e. `setup apply` will not rewrite their configs in
v1.2.0, even though `setup catalog`/`setup detect` can describe them in
detail). A client can be catalog `advisory-only` and `WriteSupport::AdvisoryOnly`
at the same time (e.g. Hermes) without those two facts being the same
claim.

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

This is a list of named-but-not-write-supported clients (`WriteSupport`
scope for `setup apply`), not the same thing as the v1.2.0
`CatalogSupportTier` shown in "`etherfence setup catalog` (v1.2.0)" above —
the two must not be conflated. Windsurf, Gemini CLI, and Codex CLI are
catalog `detect-only` in v1.2.0 (their presence and MCP servers are
reliably parsed) while remaining `WriteSupport::AdvisoryOnly` here; Hermes,
Antigravity, OpenCode, and Cline / Roo Code are catalog `advisory-only`
(local presence only, no parsing) and also `WriteSupport::AdvisoryOnly`.
Aider and Continue are **not** part of the fixed 10-client v1.2.0
`setup catalog` list and have no `AgentKind`/detection logic in this
codebase today; this pre-existing list entry predates v1.2.0's scope and is
retained here only as a statement of future intent, not a current
detection or write-support claim.

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
