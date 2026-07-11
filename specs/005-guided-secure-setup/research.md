# Phase 0 Research: Guided Secure Setup and Complete AI Client Discovery

This records design decisions made while scoping v1.6.0 guided setup. Format: Decision / Rationale / Alternatives considered.

## Decision 1: Client Registry Architecture (not more candidate entries)

**Decision**: Introduce a `ClientAdapter` abstraction that each client implements, rather than adding more entries to the flat `CANDIDATES` array in `etherfence-inventory`.

**Rationale**: The current `CANDIDATES` array is a flat list of (agent, relative_path, format) tuples. Adding more clients would further bloat an already-large const array with single-responsibility violations (one client = one config file). The product requirement calls for separate detection of: installed (PATH), configured (config file exists), MCP-configured (MCP servers parsed), read support, and write support. These are five independent axes that a flat file-presence check cannot express. A trait-based design lets each client declare its own probes, parsers, and writers as a localized module.

**Alternatives considered**:
- Keep the flat `CANDIDATES` array but add PATH/binary probes: rejected — still conflates too many concepts in one data structure.
- External YAML/TOML client definitions: rejected — adds a file-I/O dependency for what should be compile-time verified; fixture-backed Rust code is more testable.

## Decision 2: dialoguer for TTY interaction

**Decision**: Use `dialoguer` crate for guided wizard TTY interaction.

**Rationale**: dialoguer is the most widely-used Rust CLI prompt library (50M+ downloads), actively maintained, supports multi-select, confirm, input, and select prompts, has built-in non-TTY detection (`Term::stderr().is_term()`), and is already used by many Rust CLI tools. Its theme-based rendering works across Linux/macOS/Windows terminals. Alternatives evaluated:

- **inquire**: More visually polished but heavier dependency graph (crossterm + unicode-width + many features), less battle-tested.
- **requestty**: Good API but smaller community, less proven cross-platform.
- **crossterm raw**: Too low-level; would require building our own input handling, cursor management, and rendering — unnecessarily complex for a setup wizard.
- **console**: Good foundation but no high-level prompt widgets; we'd need dialoguer-level abstractions anyway.

**Alternatives considered**: All alternatives evaluated; dialoguer chosen for minimal dependency cost, proven reliability, and adequate feature set.

## Decision 3: Deny-all default policy, not curated profiles for v1.6.0

**Decision**: Generated policies default to deny-all quarantine (`tools.allow = []`, `methods.allow = ["tools/list"]`) rather than attempting fixture-verified curated profiles for every possible MCP server.

**Rationale**: Fixture-verified curated policies require knowing the exact tool names a server exposes. The spec's safety invariant says we MUST NOT start MCP servers or call `tools/list` during setup. Without that information, any curated policy would be a guess. Deny-all is the only safe default that doesn't require runtime server introspection. Users can refine their policy later manually or via future curated-profile expansions.

**Alternatives considered**:
- Ship curated profiles for popular servers: rejected for v1.6.0 — adds scope risk and requires maintenance burden; can be added incrementally in v1.6.1+.
- Allow the user to type tool names during setup: accepted as the "custom allowlist" option.

## Decision 4: Offline-only, no registry lookup for pinning

**Decision**: Version pinning is resolved entirely from user input or existing local evidence. No network registry lookup (npm, PyPI) is performed.

**Rationale**: The safety invariants say setup MUST NOT contact registries by default. Network lookups introduce latency, availability dependencies, potential information leakage, and supply-chain risk (what if the registry itself is compromised?). The user knows what version they want; asking them to provide it is both simpler and safer.

**Alternatives considered**:
- Opt-in `--resolve-versions` flag: deferred to v1.6.1 if demand exists. The flag would need explicit disclosure, safe bounding (timeout, TLS-only, no auth tokens), and easy-disable.

## Decision 5: Client detection signal separation

**Decision**: Detection produces a `ClientDetection` struct with independent fields: `installed` (bool), `configured` (bool), `config_paths` (Vec), `mcp_servers` (Vec), `read_support` (enum), `write_support` (enum). The old `foundLocally` boolean is derived as `installed || configured` for backward compatibility in the catalog but is not the primary signal.

**Rationale**: The product requirement explicitly asks for independent concepts. The current `foundLocally` conflates file presence with installation evidence. A Hermes user with `~/.hermes/config.yaml` present but `hermes` not on PATH should see "configured but binary not found" — that is actionable information during setup.

**Alternatives considered**: None — this is a direct product requirement.

## Decision 6: No new AgentKind variants

**Decision**: Do not add new `AgentKind` variants for v1.6.0. Use the existing 12 variants (ClaudeCode, Cursor, VsCode, Windsurf, GeminiCli, CodexCli, Tirith, Hermes, Antigravity, OpenCode, Cline, RooCode).

**Rationale**: The existing enum already covers all required clients. Adding variants would break the catalog's fixed 10-row matrix contract and require schema migration. The problem is not missing variants but incorrect detection paths for existing ones.

## Decision 7: Incremental apply — guided wizard uses existing `apply` engine

**Decision**: The guided wizard calls the existing `etherfence_setup::apply()` function after building the plan. The wizard is a presentation layer over the same safety-critical engine, not a separate write path.

**Rationale**: The existing apply/rollback engine has been tested and reviewed for safety invariants (backups, atomic writes, double-wrap detection, hash verification). Duplicating this logic in the wizard would create a second, untested write path. The wizard's responsibility ends at plan construction and user confirmation.

## Decision 8: TOML config format support for Hermes

**Decision**: Add YAML parsing for Hermes `config.yaml` via the `serde_yaml` crate (already a dev-dependency in the workspace).

**Rationale**: Hermes config is YAML, not JSON. The inventory crate currently only handles JSON and TOML. Adding YAML support with proper `mcp_servers:` key extraction is essential for Hermes detection. `serde_yaml` is already referenced in the workspace and is a widely-used, maintained crate.

## Decision 9: OpenCode array-command format

**Decision**: Parse OpenCode's `mcp` → `{name}` → `type: "local"` → `command: ["npx", "args..."]` format, converting the array form to the standard `command` + `args` fields for internal McpServer representation.

**Rationale**: OpenCode uses `command` as an array rather than separate `command` + `args` fields. This is a format divergence that must be handled at parse time to produce a consistent internal representation.

## Decision 10: Package version expression parsing

**Decision**: Implement exact version-extraction regex patterns for npx (`@scope/pkg@ver` or `pkg@ver`), uvx (`--from pkg@ver` or `pkg@ver` positional), and pipx run (`--spec pkg==ver` or `pkg==ver`). Reject anything that doesn't match a known exact-pin pattern.

**Rationale**: The trust assessment (v1.3.0) already classifies version expressions but setup doesn't enforce them. Rather than build a full semver parser, we match known exact-pin patterns and reject everything else. This is conservative (fail-closed) and covers the documented acceptable forms.

## Decision 11: Existing subcommand behavior unchanged

**Decision**: `etherfence setup <subcommand>` passes through to the existing handler with no behavioral change. Only bare `etherfence setup` (no subcommand) triggers the wizard.

**Rationale**: CI, scripts, and advanced users rely on the existing subcommands. Changing their behavior would be a breaking change. The wizard is additive.

## Decision 12: Schema version unchanged for v1.6.0

**Decision**: No schema version bump for existing schemas (`ef-mcp-policy/v0.2`, `ef-setup-baseline/v0.1`). The generated policy format changes (allow-all → deny-all) but the schema grammar is identical — a policy with `tools.allow = []` is valid under `ef-mcp-policy/v0.2` already.

**Rationale**: The schema grammar is unchanged. Only the *content* of generated policies changes, which is not a schema-level concern.

## Decision 13: Real Client Path Evidence (from live system inspection, July 2026)

**Decision**: Use live system evidence to correct client detection paths rather than guessing from documentation alone.

**Evidence found**:

| Client | Binary | Config Path | Format | MCP Key |
|---|---|---|---|---|
| Hermes | `~/.local/bin/hermes` (venv) | `~/.hermes/config.yaml` | YAML | `mcp_servers:` |
| OpenCode | `~/.local/bin/opencode` → `~/.opencode/bin/opencode` | `~/.config/opencode/opencode.jsonc` | JSONC | `mcp` → `{name}` → `type:"local"` |
| Antigravity | `~/.local/bin/agy` (172MB binary) | `~/.gemini/config/mcp_config.json` | JSON | `mcpServers` with `serverUrl` |
| Claude Code | `claude` on PATH | `~/.claude.json` | JSON | `mcpServers` |
| Codex | not on PATH | `~/.codex/config.toml` | TOML | `[mcp_servers]` |

**Key findings**:
- Hermes config filename is `config.yaml` (NOT `config.json` as previously hardcoded)
- OpenCode config filename is `opencode.jsonc` (JSONC with comments), not `config.json`
- Antigravity binary is named `agy`, not `antigravity` or `gemini`
- Hermes MCP servers are inline in the main config, not in a separate file

**Rationale**: Documentation-only paths are unreliable — several clients have undocumented or differently-named config files in practice. The only authoritative source is actual filesystem inspection of a real installation.
