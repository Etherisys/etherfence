# EtherFence Roadmap

## v0.1.0 - scan-only foundation

- Rust workspace and CLI
- `etherfence scan` human report
- `etherfence scan --format json` JSON report
- Conservative inventory for Claude Code, Cursor, VS Code, Windsurf, Gemini CLI, Codex CLI, and Tirith
- Fixture-backed parsing and initial posture findings

## v0.1.1 - report quality and remediation guidance

- Versioned JSON report shape with `schema_version`, `summary`, `inventory`, and `findings`
- Stable finding IDs for current MCP, secret, and Tirith posture hints
- Finding rationale, impact, recommendation, target, and references fields
- Human report grouped by severity with concise remediation guidance
- Snapshot-like CLI assertions for JSON schema stability

## v0.1.2 - CI posture gates and exports

- `--severity-threshold` for concise review output
- `--fail-on` for CI posture gates without runtime enforcement
- Markdown report output for security review notes and PR artifacts
- JSON schema documentation for `ef-scan-report/v0.1.1`
- CLI tests for gate behavior and export formats

## v0.1.3 - baseline and diff mode

- Stable finding fingerprints
- `--write-baseline` for recording known findings
- `--baseline` for marking findings as new, existing, or resolved
- `--fail-on-new` for CI gates that fail only on newly introduced findings
- Baseline JSON schema documentation
- CLI tests for baseline write, comparison, resolved findings, and new-finding gates

## v0.1.4 - scan-only policy profile mode

- `etherfence scan --policy <file>` for TOML policy evaluation
- Example strict policy under `examples/policies/strict.toml`
- Agent MCP server allowlists with unexpected-server violations
- Filesystem-capable MCP path prefix checks with broad root/home-directory deny handling
- Environment variable allowed-name patterns and secret-like name denial
- Optional Tirith-required policy check without duplicating Tirith terminal detection
- Policy metadata in JSON output and policy summary sections in human/Markdown output
- Policy-generated findings with stable IDs `EF-POL-001` through `EF-POL-005`
- Policy findings participating in severity filtering, `--fail-on`, baseline comparison, and `--fail-on-new`
- Tests for parser, violation generation, CLI policy output, CI gates, baseline combination, Markdown summary, and JSON metadata

## v0.1.5 - policy schema metadata and built-in profiles

- Versioned policy schema metadata with `schema_version = "ef-policy/v0.1"`, top-level `name`, `description`, and `require_tirith`
- Clear failure for unsupported policy schema versions
- Built-in/example policy profiles: `developer-laptop`, `ci-runner`, and `research-workstation`
- CLI helpers: `etherfence policy list` and `etherfence policy show <profile>`
- `docs/policy.md` covering policy schema, profile intent, CI gates, and baseline behavior
- JSON policy metadata fields for policy schema version and description
- Tests for supported/unsupported schema versions, example profile parsing, CLI scans, deterministic CI-runner findings, and baseline-plus-policy behavior

## v0.1.6 - direct built-in policy profile selection

- `etherfence scan --policy-profile <profile>` for direct built-in profile scans without passing a file path
- Supported built-in scan profiles: `developer-laptop`, `ci-runner`, `research-workstation`, and `strict`
- Clear mutual-exclusion failure when `--policy <file>` and `--policy-profile <name>` are both provided
- Clear unknown-profile failure that points users to `etherfence policy list`
- JSON policy metadata identifies built-in profile source when `--policy-profile` is used
- Existing human and Markdown policy summaries continue to render for file and built-in profile scans
- Policy findings still participate in `--fail-on`, `--baseline`, and `--fail-on-new` without runtime enforcement


## v0.1.7 - Windows/Linux discovery and release packaging

- Conservative OS-aware discovery helpers for Linux `HOME` and Windows `USERPROFILE`, `APPDATA`, and `LOCALAPPDATA` roots
- Windows-style config path candidates for VS Code, Cursor, Windsurf, Gemini CLI, Claude-style settings, and Codex CLI
- Stable path separator normalization for evidence and fingerprints across Unix and Windows-style paths
- Windows fixture coverage under `tests/fixtures/windows-home/` plus explicit Linux fixture coverage
- CLI tests for Windows fixture scans and built-in policy profile scans against Windows-style fixtures
- GitHub Actions matrix for `ubuntu-latest` and `windows-latest` running fmt, clippy, test, and build
- Release artifact packaging: Linux `tar.gz` containing `etherfence`, Windows `zip` containing `etherfence.exe`
- Documentation for Linux usage, Windows usage, release checks, and v0.1.7 smoke tests

## v0.1.8 - parser hardening and SARIF output

- Fixture variants for supported agents: minimal configs, multiple MCP servers, no MCP servers, malformed JSON/TOML, unknown extra fields, and Linux-/Windows-style paths
- Graceful handling of malformed configs: parse failures become inventory evidence and a low-severity `EF-CFG-001` finding instead of aborting the scan
- Structural tolerance: non-object `mcpServers`, non-table `mcp_servers`, string-typed server entries, non-array `args`, and non-object `env` degrade gracefully with deterministic inventory warnings
- MCP extraction consistency between JSON and TOML: numbers and booleans in `args`/`env` are stringified/redacted the same way, and servers are sorted by name for deterministic output
- `etherfence scan --format sarif` emitting SARIF 2.1.0 with tool name/version, one rule per finding ID, high=error / medium=warning / low+info=note severity mapping, fingerprints, and baseline/policy status properties
- SARIF works with `--policy`, `--policy-profile`, `--baseline`, and `--severity-threshold`
- `docs/sarif.md` documenting the SARIF mapping
- Tests for new fixture variants, malformed-config graceful failure, SARIF validity, SARIF rule/result mapping for MCP and policy findings, and fingerprint stability across repeated scans

## v0.2.0 - experimental MCP boundary proxy prototype

- New `etherfence-mcp` crate with policy, audit, and stdio proxy modules
- `etherfence mcp-proxy --policy <file> [--audit-log <file>] -- <server-command> [args...]`
- Minimal MCP stdio proxy: spawns the real MCP server as a child process and forwards newline-delimited JSON-RPC between client and server
- `ef-mcp-policy/v0.1` TOML policy with exact-match tool-name `allow`/`deny` lists
- Deterministic decisions: deny list wins, allow list admits, default deny for unlisted tools
- Fail closed on missing/invalid/unsupported policy: the MCP server is never started
- Denied `tools/call` requests receive a safe JSON-RPC error and are not forwarded
- JSONL audit log (`--audit-log`) with timestamp, tool name, decision, reason, and argument key names only — argument values are never logged
- Tests: policy matching, allow/deny decisions, fail-closed behavior, fake stdio MCP server integration, forwarding assertions, and audit redaction
- v0.1.x scan/report behavior unchanged and backward compatible

## v0.2.1 - MCP tools/list filtering and per-server policy scoping

- `etherfence mcp-proxy --server-name <name>` for selecting an optional per-server MCP policy scope; omitted server name defaults to `default`
- Backward-compatible `ef-mcp-policy/v0.1` schema extension with optional `[servers.<name>.tools] allow` / `deny` sections
- Deterministic decision precedence: global deny, server-specific deny, server-specific allow, global allow, then default deny
- `tools/list` response filtering for tracked `tools/list` requests so denied and default-denied tools are not advertised
- Fail-safe handling for unexpected successful `tools/list` shapes by advertising an empty tool list rather than passing ambiguous tool advertisements through
- `tools_list_filtered` audit events with server name, original/filtered counts, allowed tool names, and no full tool schemas or argument values
- Tests for legacy and per-server policy parsing, precedence, `tools/list` filtering/default deny, unexpected shapes, per-server decisions, and audit metadata
- Scan behavior remains backward compatible; proxy remains stdio-only and experimental

## v0.2.2 - MCP stdio compatibility tests and client examples

- Deterministic MCP stdio compatibility harness using the checked-in fake MCP
  server fixture: initialize, initialized notification, tools/list,
  allowed/denied tools/call, server error passthrough, malformed tools/list,
  and fail-closed batch denial
- Optional maintainer-run real stdio MCP smoke test gated by
  `ETHERFENCE_REAL_MCP_CMD`, skipped by default in CI
- Client configuration templates under `docs/examples/` plus
  `docs/mcp-clients.md` for generic, Claude-style, Cursor-style, and
  VS Code-style wrapping of MCP servers with `etherfence mcp-proxy`
- New example MCP proxy policies for filesystem read-only and GitHub read-only
  exact-name templates
- Scan behavior and v0.2.0/v0.2.1 MCP policy compatibility remain backward
  compatible; proxy remains stdio-only and experimental

## v0.2.3 - AGPL-3.0-only license metadata

- Project license metadata and root license text updated to AGPL-3.0-only
- No runtime behavior changes

## v0.2.4 - MCP compatibility matrix workflow

- `docs/mcp-compatibility-matrix.md` records compatibility evidence fields for MCP stdio server checks
- Checked fake MCP server compatibility row documents deterministic CI-backed behavior
- `docs/mcp-real-server-test-template.md` documents optional maintainer-run real-server smoke tests using `ETHERFENCE_REAL_MCP_CMD` as JSON argv
- Validation tests keep matrix docs, JSON client examples, and example MCP proxy policies checked
- No new enforcement semantics; the proxy remains stdio-only, exact-name-only, and experimental

## v0.2.5 - manual GitHub Actions release workflow

- `.github/workflows/release.yml` adds a manual `workflow_dispatch` release
  path: validates main ref, semver version input, `Cargo.toml`/`CHANGELOG.md`
  match, and tag/release absence; runs fmt/clippy/test/build checks on Linux
  and Windows; builds and attaches release artifacts; tags and creates the
  GitHub release
- `docs/release-automation.md` documents the workflow's validation gates and
  safety guarantees
- No new enforcement semantics or runtime behavior; release creation stays
  explicit and fails closed on ambiguous state

## v0.2.6 - MCP proxy request tracking hardening

- Hardened JSON-RPC request/response tracking in the stdio MCP proxy:
  - Track client `tools/list` requests by `(method, id)` instead of a bare id
  - Reference-counted tracking entries removed after the matching response is
    processed, so duplicate in-flight ids are handled deterministically and
    entries cannot leak
  - Explicit, documented behavior for notifications, unknown/no-id responses,
    server errors for tracked ids, malformed successful `tools/list` results,
    and unrelated-method responses that reuse a tracked id style
  - `tools_list_tracking_removed` audit event and `tools_list_malformed` reason
  - No new enforcement semantics or transports; proxy remains stdio-only,
    exact-name-only, experimental

## v0.2.7 - MCP proxy lifecycle and failure-mode hardening

- Hardened the stdio MCP proxy's child-process lifecycle and failure modes
  (no new enforcement features or transports):
  - Child server is reaped on every exit path (normal client EOF, child early
    exit, or proxy error) — no zombie or orphaned server process
  - Child early exit / server stdout closure is detected and the child's exit
    code is propagated
  - Client EOF closes the server's stdin so the child can exit, then the proxy
    joins the server pump and reaps the child
  - Broken pipe to the server (write after child exited) is a clean shutdown,
    not a panic
  - Broken pipe to the client (write after client closed stdout) is a clean
    shutdown, not a panic
  - Invalid/non-JSON client lines are dropped before forwarding (never reach
    the server); valid JSON-RPC traffic passes through unchanged
  - Invalid/non-JSON server lines are passed through so the client's own parser
    rejects them; the proxy never fabricates or advertises a tool list
  - Audit logging documented as best-effort: a failed audit write never weakens
    a deny or reverses a `tools/list` filter already applied
  - Documented exit codes (0 clean EOF, 2 invalid policy, 3 spawn failure,
    4 internal/audit-open error, child code on early exit)
  - New unit + integration tests for child early exit, server stdout closure,
    client EOF, invalid client/server JSON, and audit-open failure
  - Proxy remains stdio-only, exact-name-only, `ef-mcp-policy/v0.1`-compatible,
    experimental/pre-alpha

## v0.3.0 - MCP proxy method-level policy enforcement

- Method-level MCP/JSON-RPC policy enforcement: every client→server
  JSON-RPC request object is inspected before forwarding
- Optional `[methods]` and `[servers.<name>.methods]` sections in
  `ef-mcp-policy/v0.1` with exact-match allow/deny lists and `"*"` wildcard
- Always-allowed methods (initialize, notifications/initialized, ping)
  bypass method policy
- Built-in default when no `[methods]` section is present: allow
  tools/list and tools/call, deny everything else (preserves v0.2.x)
- Unknown/unspecified methods default deny
- `method_decision` audit event with server name, method, decision,
  reason, request id type, and safe param key names only
- `request_id_type` and `param_keys` audit fields added
- New example policies: strict-tools-only, readonly, resources-denied,
  sampling-denied
- Schema version unchanged (`ef-mcp-policy/v0.1`); `[methods]` is optional
  — existing v0.2.x policies remain syntactically valid but see stricter
  runtime behavior (non-tools methods now denied by default)
- Behavioral hardening: v0.2.x non-tools client→server methods passed
  through uninspected; v0.3.0 denies them by default unless explicitly
  allowed
- Existing tools/list filtering and tools/call allow/deny behavior
  preserved unchanged
- Batch arrays remain denied fail-closed
- Proxy remains stdio-only, exact-match, experimental/pre-alpha

## v0.3.1 - MCP proxy server→client method policy enforcement

- Server→client JSON-RPC request/notification objects with a `method` field
  are inspected before forwarding to the client
- Client-feature methods initiated by the server, including
  `sampling/createMessage`, `roots/list`, and `elicitation/create`, can be
  denied with the existing exact-match `[methods]` policy
- Denied server→client id-bearing requests are dropped before the client and
  receive a JSON-RPC error response back toward the server
- Denied server→client notifications without an id are dropped and audited
- `method_decision` and `batch_denied` audit records include direction
  metadata (`client_to_server` or `server_to_client`) and continue to log only
  safe metadata (`param_keys`, request id type, method, decision, reason)
- Client→server method policy, tools/call policy, tools/list filtering, audit
  redaction, schema `ef-mcp-policy/v0.1`, and fail-closed batch behavior are
  preserved
- No daemon mode, API server, network interception, shell hooks, terminal
  command scanning, endpoint agent behavior, or non-stdio proxying added

## v0.4.0 - MCP proxy local path-aware argument/resource policy

- Optional `path_rules` for the existing `ef-mcp-policy/v0.1` MCP proxy schema
  with explicit `allow_roots` and `deny_roots`
- Per-tool argument guards such as `[tools."filesystem.read".arguments]` with
  configured `path_keys`
- Per-method resource guards such as `[methods."resources/read".params]` with
  configured `uri_keys`
- Deny roots override allow roots; configured malformed, missing, non-string,
  relative, or non-normalizable path-like keys fail closed
- `file://` resource URIs are converted to local paths before comparison;
  guarded non-file URI schemes are denied rather than treated as broad URL
  policy
- Audit records add only safe path metadata (`path_rule`, `path_key`, and
  redacted `path_classification`) and continue to omit full paths, URIs, prompt
  text, message bodies, file/resource contents, secrets, tokens, and full params
- Existing v0.3.1 method policy, tools/call policy, tools/list filtering,
  fail-closed batches, schema compatibility, and stdio-only scope are preserved
- Not in scope: server/control plane, daemon, API service, network interception,
  shell hooks, terminal-command scanning, endpoint agent, generic policy
  language, content inspection, or DLP engine

## v0.2.x ideas

- Expand tested config schemas and platform paths
- Add baseline fingerprint migration notes if needed
- Add richer machine-readable policy checks
- Improve documentation for safe enterprise rollout
- Consider MCP proxy policy evolution (patterns, richer server identity binding) once real-world examples stabilize

## Later

- Broader runtime control design beyond the stdio proxy prototype
- Integration with complementary tools such as Tirith

Any further runtime blocking, proxying, or interception must be designed and threat-modeled before implementation. Daemon mode, shell hooks, command interception, terminal-command scanning, and network interception remain out of scope.
