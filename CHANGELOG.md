# Changelog

All notable changes to EtherFence are documented in this file.

EtherFence is pre-alpha. The v0.1.x line is scan-only; nothing in v0.1.x
performs runtime blocking, MCP proxying, daemon mode, shell hooks, command
interception, terminal-command scanning, or network interception. v0.2.x adds
one opt-in experimental runtime component: an MCP stdio boundary proxy.
EtherFence still has no daemon mode, shell hooks, command interception,
terminal-command scanning, or network interception.

## [0.3.0] - 2026-07-09

### Added

- Method-level MCP/JSON-RPC policy enforcement in `etherfence mcp-proxy`:
  every client→server JSON-RPC request object is now inspected before
  forwarding. The proxy checks the method name against an optional
  `[methods]` allow/deny policy before any method-specific logic runs.
  Unknown or unspecified methods default deny unless explicitly allowed.
- Optional `[methods]` and `[servers.<name>.methods]` sections in
  `ef-mcp-policy/v0.1` TOML policies with exact-match `allow`/`deny` lists
  and a `"*"` wildcard for permissive deployments. When no `[methods]`
  section is present, the built-in default allows only `tools/list` and
  `tools/call` (preserving v0.2.x behavior).
- Always-allowed methods (`initialize`, `notifications/initialized`,
  `ping`) bypass method policy entirely, since they are required for MCP
  protocol initialization and liveness.
- `method_decision` audit event recording server name, method, decision,
  reason, request id presence/type, and safe top-level param key names
  only — no param values, prompt text, resource content, message bodies,
  secrets, tokens, or file contents are ever logged.
- `request_id_type` audit field recording the JSON type of the request id
  (number, string, bool, object, array, null, or missing).
- `param_keys` audit field recording sorted top-level `params` key names
  for method decisions.
- New example MCP proxy policies: `mcp-strict-tools-only.toml`,
  `mcp-readonly.toml`, `mcp-resources-denied.toml`,
  `mcp-sampling-denied.toml`.

### Changed

- `inspect_client_line` now checks method-level policy for every
  client→server JSON-RPC request before forwarding. Denied methods are
  never forwarded to the server and receive a JSON-RPC error response
  with the method name and reason. `tools/call` and `tools/list` behavior
  is preserved: when the method is allowed, the existing tool-name policy
  and response filtering logic runs unchanged.
- The `AuditRecord` struct includes new `request_id_type` and `param_keys`
  fields. Existing audit events (`tool_call_decision`,
  `tools_list_filtered`, `batch_denied`, etc.) include these fields with
  appropriate values (empty arrays where not applicable).
- Version bumped to 0.3.0. All scan/report behavior is unchanged and
  backward compatible.

### Security notes

- Denied methods never reach the child MCP server. This closes the v0.2.x
  gap where `resources/read`, `prompts/get`, `sampling/createMessage`,
  and other methods passed through the proxy uninspected.
- Unknown/custom methods are denied by default, reducing the attack
  surface for novel MCP method names.
- Batch arrays remain denied fail-closed (unchanged).
- Audit records exclude all sensitive values: only key names, method
  names, decision outcomes, and request id type metadata are logged.
- The proxy is still stdio-only, experimental, and does not add daemon
  mode, API server, network interception, shell hooks, terminal-command
  scanning, or filesystem path-scoped argument policy.

### Policy/schema compatibility and behavioral migration

- Schema version remains `ef-mcp-policy/v0.1` (no version bump needed).
  Existing v0.2.x policy files are syntactically valid and require no
  changes to parse or load.
- **Behavioral hardening (not a pure backward-compatible change):** In
  v0.2.x, the proxy only inspected `tools/call` requests and filtered
  tracked `tools/list` responses; every other client→server JSON-RPC
  method (e.g. `resources/read`, `prompts/get`, `completion/complete`)
  passed through to the server uninspected. In v0.3.0, every
  client→server JSON-RPC request is method-checked before forwarding.
  When no `[methods]` section is present, the built-in default allows
  only `tools/list` and `tools/call` and denies all other methods. This
  means deployments that relied on non-tools methods passing through
  uninspected must now add an explicit `[methods]` allow list (or
  `allow = ["*"]` for permissive mode) to restore prior pass-through
  behavior. This is an intentional security hardening, not a regression:
  the v0.2.x pass-through was a documented limitation, not a feature.
- The `[methods]` section is additive: existing policies that only use
  `[tools]` and `[servers.<name>.tools]` continue to work with the
  stricter built-in default. No file edits are required unless the
  deployment needs non-tools methods to pass through.
- Per-server method scoping via `[servers.<name>.methods]` follows the
  same precedence as tool rules: global deny, server deny, server allow,
  global allow, then default deny.
- **Scope limitation:** The proxy inspects client→server requests only.
  Server→client requests such as `sampling/createMessage` and
  `roots/list` (which in the MCP protocol are initiated by the server,
  not the client) are not intercepted by method policy in this release.
  Method policy applies to client→server requests only.

## [0.2.8] - 2026-07-09

### Changed

- policy path traversal hardening via lexical normalization
- expanded filesystem path detection in policy evaluation
- GitHub release workflow input hardening
- bounded file reads for policy/MCP policy/config/baseline files
- true bounded reads using actual read limit, regular-file check, UTF-8 validation
- Semgrep path traversal triage: current CLI paths are trusted local operator inputs, future API/UI/MCP path inputs must be base-dir constrained

## [0.2.7] - 2026-07-09

### Added

- Explicit MCP proxy lifecycle and failure-mode hardening in
  `crates/etherfence-mcp` (stdio-only, experimental/pre-alpha):
  - Child server process is guaranteed to be reaped on proxy exit: the proxy
    now kills the child on any abnormal exit path and waits for it, so a failed
    `mcp-proxy` invocation cannot leave a zombie or orphaned server process.
  - Child server early exit is detected on the server→client pump: when the
    child closes its stdout, the proxy stops forwarding, closes the client's
    stdin, and surfaces the child's exit status as the proxy exit code.
  - Server stderr is detached (inherited) so a chatty or failing child cannot
    block or deadlock the proxy's pipes.
  - Client stdin EOF is handled cleanly: the proxy closes the server's stdin so
    the child can exit, joins the server pump, and returns the child's status.
  - Broken pipe to the server (write after the child exited) is treated as a
    clean shutdown, not a panic.
  - Broken pipe to the client (write after the client closed stdout) is treated
    as a clean shutdown, not a panic.
  - Invalid/non-JSON client lines are validated before forwarding: a line that
    cannot be parsed as JSON is **not** sent to the server and is dropped (the
    server would reject it anyway; forwarding it could mask protocol errors and
    wastes a round trip). A JSON-RPC notification/response that is not a request
    is still forwarded unchanged (the proxy never alters server-originated or
    client notification traffic).
  - Invalid/non-JSON server lines are handled safely: they are passed through to
    the client unchanged (the client's own parser rejects them), so a malformed
    server line can never cause the proxy to advertise or fabricate a tool list.
  - Audit logging is documented as **best-effort**: the proxy records decisions
    and metadata but treats an audit write failure as non-fatal on the
    inspect/forward path. The security-critical enforcement decisions
    (deny / default-deny / batch denial) are not gated on audit success — a
    failed audit write never weakens a deny. A deny response is still returned
    to the client even when its audit record cannot be written; the error is
    logged to stderr and the proxy continues. `tools_list_filtering` audit is
    likewise best-effort; a failure to record it does not reverse the filtering
    already applied to the response.
  - Documented exit codes:
    - `2`: invalid/unloadable policy (fail closed, server never started)
    - `3`: child server spawn failure (fail closed)
    - `4`: internal proxy error (I/O on client/server pipes, audit open failure)
    - child server exit code: propagated when the child exits first
    - `0`: normal client EOF shutdown
  - New unit tests for invalid client/server JSON handling and audit-write
    failure behavior, and new integration tests for child early exit, server
    stdout closure, and client EOF.
  - Keeps `tools/call` deny behavior, `tools/list` filtering, v0.2.6 request
    tracking tests, and JSON-RPC batch fail-closed behavior unchanged.

### Changed

- `run_proxy` now returns `Result<i32, ProxyError>` carrying an explicit exit
  code; the CLI maps `ProxyError` variants to documented exit codes and always
  reaps the child.

### Limitations

- The proxy remains stdio-only, exact-name matching, policy-compatible with
  `ef-mcp-policy/v0.1`, and experimental/pre-alpha. There is still no audit
  write to durable storage beyond the `--audit-log` file, no audit rotation,
  and no fsync beyond the per-write flush.
- A child that ignores a closed stdin and keeps its stdout open will keep the
  proxy's server pump alive until the proxy itself is killed; this matches
  normal stdio MCP server behavior and is documented, not changed.

## [0.2.6] - 2026-07-09

### Added

- MCP proxy request-tracking hardening in `crates/etherfence-mcp`: the proxy
  now tracks each client `tools/list` request by both its JSON-RPC method and
  id, so `tools/list` responses are only filtered when they actually match a
  tracked `tools/list` request (other methods sharing the same id style are no
  longer re-shaped). Tracking entries are reference-counted and removed after
  the matching response is processed, with a deterministic duplicate in-flight
  id policy (see "Changed"), so entries cannot leak indefinitely.
- Explicit, documented behavior for JSON-RPC request/response edge cases:
  numeric and string `tools/list` ids, `tools/list` notifications without an
  id (never tracked), server-error responses for tracked `tools/list` ids
  (pass through and clear tracking), responses whose id matches no tracked
  request (pass through unchanged), malformed successful `tools/list` results
  (still advertised as an empty list), and responses without an id (pass
  through unchanged). All id types (null, number, string, object, array,
  bool) are handled consistently.
- New `tools_list_tracking_removed` audit event emitted when a tracked
  `tools/list` entry is cleared, and a `tools_list_malformed` reason is
  recorded when a successful `tools/list` result is rejected as malformed.

### Changed

- `inspect_client_line` now returns `tools_list_request: Option<TrackedRequest>`
  (method + id key) instead of a bare id string, and the proxy engine tracks
  requests in a `TrackedRequests` set keyed by `(method, id_key)`. A duplicate
  in-flight `tools/list` id increments a reference count rather than replacing
  state; the matching response decrements it and clears the entry only when the
  count reaches zero. This makes cleanup deterministic and prevents the first
  of two identical-id responses from silently orphaning the second.
- Unit tests and integration `cli_mcp_proxy` fixtures cover all the edge cases
  above; the existing `tools/call` deny behavior, batch-array fail-closed
  denial, per-server policy tests, and compatibility matrix docs validation
  continue to pass unchanged.

### Notes

- No new enforcement semantics or transports: the proxy remains stdio-only,
  exact-name-only, experimental, with no daemon, shell hooks, network
  interception, or terminal-command scanning. v0.2.0/v0.2.1 policy
  compatibility is preserved, and scan/report behavior is backward compatible.

## [0.2.5] - 2026-07-09

### Added

- Manual `workflow_dispatch` GitHub Actions release workflow in
  `.github/workflows/release.yml` that becomes the primary safe release
  path: it validates release state (main ref, semver-like version input,
  `Cargo.toml` workspace version match, a matching `CHANGELOG.md` section,
  and that the target tag/GitHub release do not already exist), runs
  `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D
  warnings`, `cargo test`, `cargo build`, and `git diff --check` on
  `ubuntu-latest` and `windows-latest`, builds
  `etherfence-linux-x86_64.tar.gz` and `etherfence-windows-x86_64.zip`
  packaging the CLI binary with `README.md` and `LICENSE`, then creates an
  annotated `v<version>` tag on the dispatched `main` commit and a GitHub
  release with those artifacts and release notes extracted from the
  matching `CHANGELOG.md` section.
- `docs/release-automation.md` documenting the workflow's inputs,
  validation gates, and manual-approval flow.

### Changed

- Version bumped to 0.2.5. All scan/report and MCP proxy behavior is
  unchanged; scan reports now carry version `0.2.5`.
- `docs/release-checklist.md` and README now point to the
  `workflow_dispatch` release workflow as the primary release path, with
  the previous fully manual tag/release steps kept as a documented
  fallback.

### Notes

- No runtime product behavior changes. The release workflow only runs on
  explicit `workflow_dispatch`; it never mutates existing releases,
  replaces existing tags, force-pushes, or releases from a non-`main` ref,
  and fails closed if release state is ambiguous.

## [0.2.4] - 2026-07-09

### Added

- MCP compatibility matrix workflow in `docs/mcp-compatibility-matrix.md`
  with required fields for server/version/platform, command template, policy,
  tools/list behavior, allowed and denied tools/call outcomes, audit result,
  tester/date, and limitations.
- Checked compatibility record for the deterministic fake MCP server fixture.
- Real stdio MCP server smoke-test template in
  `docs/mcp-real-server-test-template.md` for optional maintainer-run
  validation and matrix updates.
- Validation tests that keep the compatibility matrix, checked JSON client
  examples, and example MCP proxy TOML policies parseable and referenced.

### Notes

- No new enforcement semantics. The MCP proxy remains stdio-only,
  experimental/pre-alpha, exact tool-name matching only, and does not add
  daemon mode, HTTP/SSE transport, network interception, shell hooks,
  terminal-command scanning, wildcard/prefix/regex matching, or Tirith
  terminal-security duplication.

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
