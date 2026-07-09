# Changelog

All notable changes to EtherFence are documented in this file.

EtherFence is pre-alpha. The v0.1.x line is scan-only; nothing in v0.1.x
performs runtime blocking, MCP proxying, daemon mode, shell hooks, command
interception, terminal-command scanning, or network interception. v0.2.x adds
one opt-in experimental runtime component: an MCP stdio boundary proxy.
EtherFence still has no daemon mode, shell hooks, command interception,
terminal-command scanning, or network interception.

## [0.2.3] - 2026-07-09

### Changed

- Switched project license metadata and root license text to
  `AGPL-3.0-only`.

### Notes

- No runtime behavior changes.

## [0.2.2] - 2026-07-09

### Added

- Deterministic MCP stdio compatibility harness using the checked-in
  `fake-mcp-server` test fixture. The harness exercises initialize,
  initialized notification passthrough, `tools/list`, allowed `tools/call`,
  denied `tools/call`, server error response passthrough, malformed
  successful `tools/list` handling, and JSON-RPC batch fail-closed denial.
- Optional real-server smoke test gated by `ETHERFENCE_REAL_MCP_CMD`. The env
  var must be a JSON argv array rather than a shell command, and the test
  skips cleanly when the env var is not set.
- Client configuration documentation in `docs/mcp-clients.md` plus checked JSON
  templates under `docs/examples/` for generic, Claude-style, Cursor-style,
  and VS Code-style MCP client wrapping.
- Example exact-name MCP proxy policies:
  `examples/policies/mcp-filesystem-readonly.toml` and
  `examples/policies/mcp-github-readonly.toml`.
- Tests validating the checked client JSON examples and MCP proxy policy
  examples.

### Changed

- Version bumped to 0.2.2. All scan/report behavior remains backward
  compatible; scan reports now carry version `0.2.2`.
- README, MCP proxy docs, architecture, threat model, roadmap, and release
  checklist now document compatibility testing and client configuration
  examples.

### Known limitations

- The MCP proxy remains an experimental stdio-only prototype, not
  production-ready runtime enforcement.
- The compatibility harness improves confidence for common stdio JSON-RPC MCP
  flows but is not a comprehensive MCP conformance suite.
- Exact tool-name matching only; no wildcard, prefix, regex, argument-aware, or
  schema-aware rules.
- No daemon mode, HTTP/SSE transport, network interception, shell hooks,
  command interception, terminal-command scanning, or Tirith behavior
  duplication.

## [0.2.1] - 2026-07-09

### Added

- `etherfence mcp-proxy --server-name <name>` for selecting an optional
  per-server MCP policy scope. If omitted, the server name defaults to
  `default`.
- Backward-compatible `ef-mcp-policy/v0.1` schema extension with optional
  `[servers.<name>.tools] allow` / `deny` sections alongside legacy global
  `[tools]` rules.
- Deterministic MCP proxy decision precedence: global deny, server-specific
  deny, server-specific allow, global allow, then default deny. Deny still
  overrides allow.
- `tools/list` response filtering for tracked client `tools/list` requests:
  denied, default-denied, and malformed unnamed tool entries are removed so
  unavailable tools are not advertised to the client.
- Fail-safe handling for unexpected successful `tools/list` response shapes:
  the proxy rewrites the response to advertise an empty `tools` array instead
  of passing ambiguous tool advertisements through.
- New `tools_list_filtered` JSONL audit event with server name,
  original/filtered counts, allowed tool names, and reason. Full tool schemas,
  descriptions, and argument values are not logged.
- Tests for legacy global-only policy parsing, per-server policy parsing,
  precedence, `tools/list` deny/default-deny filtering, unexpected list shapes,
  per-server decision changes, and audit metadata redaction.

### Changed

- Version bumped to 0.2.1. All scan/report behavior remains backward
  compatible; scan reports now carry version `0.2.1`.
- `examples/policies/mcp-minimal-boundary.toml`, README, MCP proxy docs,
  threat model, architecture, and roadmap now document per-server policy
  scoping and `tools/list` filtering.

### Known limitations

- The MCP proxy remains an experimental prototype, not production-ready.
- stdio transport with newline-delimited JSON-RPC framing only; HTTP/SSE
  transports are not supported.
- Exact tool-name matching only; no wildcard, prefix, regex, argument-aware,
  or schema-aware rules.
- Per-server scoping is operator-selected with `--server-name`; the proxy does
  not auto-discover or authenticate server identity.
- Only `tools/call` requests and tracked `tools/list` responses are handled;
  tool results, resources, prompts, sampling traffic, daemon mode, shell hooks,
  command interception, terminal-command scanning, and network interception
  remain out of scope.

## [0.2.0] - 2026-07-09

### Added

- Experimental `etherfence mcp-proxy --policy <file> [--audit-log <file>] --
  <server-command> [args...]` command: a minimal MCP stdio boundary proxy
  that starts the real MCP server as a child process and forwards
  newline-delimited JSON-RPC messages between the MCP client and server.
- New `etherfence-mcp` crate with the proxy engine, policy loading, and
  audit logging.
- `ef-mcp-policy/v0.1` TOML proxy policy with exact-match tool-name
  `[tools] allow` / `[tools] deny` lists. Decisions are deterministic:
  deny list wins over allow list, allowed tools are forwarded, and unlisted
  tools are denied by default. Example policy at
  `examples/policies/mcp-minimal-boundary.toml`; documented in
  `docs/mcp-proxy.md`.
- Fail-closed policy handling: a missing, unreadable, invalid, or
  unsupported-schema policy stops the proxy with exit code 2 before the MCP
  server is ever started, and is recorded as a `policy_error` audit event.
- Denied `tools/call` requests are answered with a safe JSON-RPC error
  (code `-32000`) and are never forwarded to the server; denied
  notifications are dropped and audited. Tool calls with a missing or
  non-string tool name are denied (fail closed).
- JSON-RPC batch arrays from the client are denied fail closed instead of
  being unpacked: the proxy answers with a single null-id JSON-RPC error,
  audits a `batch_denied` event, and never forwards the batch, so a batch
  cannot smuggle a denied tool call past per-message inspection.
- JSONL audit logging via `--audit-log <file>`: each tool-call decision
  records an RFC 3339 UTC timestamp, policy name, method, request id, tool
  name, decision (`allow`/`deny`/`policy_error`), policy reason, and the
  sorted tool-call argument key names. Argument values are never logged, so
  secret values do not leak into the audit log. Audit failures are fail
  closed: an unopenable audit log stops the proxy before the server starts,
  and a failed audit write stops forwarding.
- Tests: unit tests for policy parsing/matching and allow/deny decisions,
  audit redaction tests, and CLI integration tests against a fake stdio MCP
  server fixture proving allowed calls are forwarded, denied calls are not,
  invalid policies fail closed without starting the server, and the audit
  log contains no secret-like argument values.

### Changed

- Version bumped to 0.2.0. All v0.1.8 scan/report behavior (`scan`,
  `policy`, output formats, CI gates, baselines, scan policies) is
  unchanged and backward compatible; scan reports now carry version
  `0.2.0`.

### Known limitations

- The MCP proxy is an experimental prototype, not production-ready.
- stdio transport with newline-delimited JSON-RPC framing only; HTTP/SSE
  transports are not supported.
- Exact tool-name matching only; no wildcards or per-server scoping.
- Only `tools/call` requests are inspected; tool results, resources,
  prompts, and `tools/list` responses pass through unmodified, so denied
  tools may still appear in tool listings.
- JSON-RPC batch arrays are denied fail closed rather than unpacked.
- No daemon mode, shell hooks, command interception, terminal-command
  scanning, or network interception; Tirith remains complementary
  terminal-command protection.

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
