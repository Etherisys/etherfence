# Changelog

All notable changes to EtherFence are documented in this file.

EtherFence is pre-alpha and scan-only. Nothing in v0.1.x performs runtime
blocking, MCP proxying, daemon mode, shell hooks, command interception,
terminal-command scanning, or network interception.

## [0.1.8] - 2026-07-08

### Added

- `etherfence scan --format sarif` emitting SARIF 2.1.0 JSON with the tool
  name/version, one SARIF rule per EtherFence finding ID, severity mapping
  (high=`error`, medium=`warning`, low/info=`note`), finding fingerprints as
  `partialFingerprints`, and baseline/policy status in result properties.
  SARIF export works with `--policy`, `--policy-profile`, `--baseline`, and
  `--severity-threshold`. Documented in `docs/sarif.md`.
- Low-severity `EF-CFG-001` finding (`config-parse-error`) when a discovered
  agent config file exists but cannot be parsed, so unscannable configs are
  visible instead of silent.
- Fixture variants for parser coverage: minimal configs, multiple MCP
  servers, no MCP servers, malformed JSON/TOML, unknown extra fields, and
  Linux-/Windows-style paths (`tests/fixtures/minimal-home`,
  `tests/fixtures/multi-home`, `tests/fixtures/malformed-home`).

### Changed

- Parser hardening: malformed JSON/TOML configs no longer abort inventory;
  they produce deterministic single-line `parse-error:` evidence. Non-object
  `mcpServers`, non-table `mcp_servers`, string-typed server entries,
  non-array `args`, and non-object `env` values degrade gracefully with
  inventory warnings.
- MCP extraction consistency: TOML `args` and `env` now stringify/redact
  numbers and booleans the same way JSON does, and MCP servers are sorted by
  name for deterministic report output across config formats.

### Known limitations

- Scan-only: findings are posture hints, not proof of exploitability, and no
  policy is enforced at runtime.
- Fixture-backed parsing covers common config shapes for the supported
  agents; EtherFence does not claim complete support for every agent config
  format or install location.
- SARIF results reference config paths as artifact URIs relative to the
  scanned root (for example `~/.claude.json`); consumers that require
  absolute URIs may need post-processing.

## [0.1.7] - 2026-07-08

### Added

- Conservative Windows config discovery using `USERPROFILE`, `APPDATA`, and
  `LOCALAPPDATA` for known agent config locations (VS Code, Cursor, Windsurf,
  Gemini CLI, Codex CLI, Claude). Missing environment variables are skipped
  gracefully. This is conservative discovery of known config paths, not
  complete Windows endpoint coverage.
- Conservative Linux config discovery via `HOME` and existing Unix-style
  paths such as `~/.claude.json`, `~/.cursor/mcp.json`,
  `~/.config/Code/User/settings.json`, `~/.gemini/settings.json`, and
  `~/.codex/config.toml`.
- Windows-style scan fixtures (`tests/fixtures/windows-home`) for
  deterministic cross-platform testing.
- Path normalization: Windows path separators are normalized (for example
  `C:/Users/example/...`) so evidence and finding fingerprints are stable
  across operating systems.
- GitHub Actions CI matrix on `ubuntu-latest` and `windows-latest` running
  fmt, clippy, test, and debug/release builds on both platforms.
- Release packaging: CI builds and uploads `etherfence-linux-x86_64.tar.gz`
  and `etherfence-windows-x86_64.zip` artifacts; equivalent local packaging
  steps are documented in `docs/release-checklist.md`.

### Known limitations

- Scan-only: findings are posture hints, not proof of exploitability, and no
  policy is enforced at runtime.
- Windows support is conservative config discovery for a fixed set of known
  agent paths; agents installed in non-default locations are not found.
- Discovery reads local config files only; running processes, registries, and
  remote/managed configurations are not inspected.
- CI runs (and produces artifacts) on pushes and pull requests targeting
  `main` only; pushing a tag does not trigger an artifact build.
- Windows artifacts are built and unit-tested in CI, but the packaged zip
  should still be smoke-tested manually on a Windows machine.

## [0.1.6] and earlier

Initial scan-only foundation: posture scanner with remediation guidance,
markdown/JSON reports, CI posture gates (`--fail-on`), baseline/diff support
(`--baseline`, `--write-baseline`, `--fail-on-new`), versioned TOML policy
schema (`ef-policy/v0.1`), built-in policy profiles, and
`scan --policy-profile <name>` selection.
