# Changelog

All notable changes to EtherFence are documented in this file.

EtherFence is pre-alpha and scan-only. Nothing in v0.1.x performs runtime
blocking, MCP proxying, daemon mode, shell hooks, command interception,
terminal-command scanning, or network interception.

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
