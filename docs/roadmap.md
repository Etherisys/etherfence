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

## v0.4.1 - MCP proxy Unicode/homograph hardening

- Narrow Unicode hygiene module for the MCP stdio proxy; no broad confusable
  folding or locale-specific path equivalence
- Policy parsing rejects bidi controls, zero-width/invisible format characters,
  and non-ASCII identifier text in policy names, server scopes, path-rule names,
  tool/method guard keys, and path keys
- Method allow/deny entries must be ASCII; runtime client→server and
  server→client method names with non-ASCII, bidi, or zero-width characters are
  denied before exact policy matching
- Runtime `tools/call` tool names with non-ASCII, bidi, or zero-width
  characters are denied before exact tool-policy matching
- Configured path guards deny guarded path/URI values with bidi or zero-width
  characters before lexical normalization and root comparison
- Safe audit/error categories for Unicode denials, with redacted placeholders
  for Unicode-denied method/tool names and no raw paths/URIs
- Existing v0.4.0 path-aware policy behavior, v0.3.1 bidirectional method
  policy, tools/call policy, tools/list filtering, fail-closed batches, schema
  compatibility, and stdio-only scope are preserved
- Not in scope: broad DLP/content inspection, URL filtering, network
  interception, daemon/control plane/API service, shell hooks, terminal-command
  scanning, endpoint agent, cloud dependency, or release tag creation

## v0.5.0 - MCP proxy compatibility and smoke-test release

- Fixture-backed compatibility smoke tests added for `resources/list` allow
  and deny by method policy, alongside existing `initialize`, `tools/list`,
  `tools/call` allow/deny, `resources/read` allow/deny, server→client
  sampling/roots/elicitation policy behavior, and malformed/batch fail-closed
  coverage
- Optional `ETHERFENCE_REAL_MCP_POLICY` environment variable lets maintainers
  point the optional real-server smoke test at a specific policy file instead
  of the built-in compatibility policy; remains read-only and skipped by
  default in CI (gated by `ETHERFENCE_REAL_MCP_CMD`)
- New example policies: `mcp-filesystem-project-readonly-hardened.toml`
  (project-root read-only with `deny_roots` expanded to common
  credential-like paths) and `mcp-strict-method-only.toml` (explicit
  `[methods]` allow/deny restricted to `tools/list` and `tools/call`)
- Validation tests confirming the new example policies parse and enforce as
  documented
- `docs/mcp-compatibility-matrix.md` documents explicitly what MCP stdio
  flows are tested and what remains untested, and states that compatibility
  evidence is not production-readiness certification
- No new enforcement semantics, schema changes, or runtime behavior changes;
  proxy remains stdio-only, exact-match, experimental/pre-alpha

## v0.6.0 - MCP policy UX (validate, explain, init, check)

- New `etherfence mcp-policy` subcommand group, local-only and serverless:
  - `etherfence mcp-policy validate <policy.toml>` parses and validates a
    policy using the existing `ef-mcp-policy/v0.1` loader, with clear errors
    for unsupported schema versions, empty `name`, missing `allow_roots`,
    malformed TOML, and suspicious Unicode
  - `etherfence mcp-policy explain <policy.toml>` prints a deterministic
    human summary of methods, tools, server scopes, path rules, guarded keys,
    Unicode-hardening posture, and audit-redaction posture, plus warnings for
    wildcard method allow, no `[methods]` section, no allowed tool anywhere,
    unused path rules, guards referencing an undefined path rule, broad
    `allow_roots` (e.g. `/`, `C:/`), and empty `deny_roots`
  - `etherfence mcp-policy init --profile <name> [--output <file>]` generates
    a starter policy from one of five built-in profiles (`minimal`,
    `strict-method-only`, `filesystem-project-readonly`,
    `filesystem-project-readonly-hardened`, `resources-project-only`);
    refuses to overwrite an existing `--output` file unless `--overwrite` is
    also passed
  - `etherfence mcp-policy check --policy <policy.toml> --request <json>
    [--server-name <name>] [--direction client-to-server|server-to-client]`
    dry-runs one JSON-RPC request/notification against the exact same
    `inspect_client_line`/`inspect_server_line` decision functions the live
    proxy uses, reporting method/tool/path decisions, reason, and whether the
    request would be forwarded; JSON-RPC batches are reported as denied
    fail-closed; no MCP server is started or contacted and no tool is
    executed
- New `etherfence-mcp::policy_ux` module exposing `explain_policy` and
  `dry_run_check` as small, reusable, serverless helpers built on the
  existing policy parser and proxy decision functions — no proxy internals
  duplicated
- `docs/mcp-policy-ux.md` documents all four commands, the warning semantics,
  and explicit non-goals
- Schema unchanged (`ef-mcp-policy/v0.1`); existing `scan`, `policy`, and
  `mcp-proxy` behavior, v0.5.0 compatibility/smoke tests, v0.4.1 Unicode
  hardening, v0.4.0 path-aware policy, and v0.3.1 bidirectional method
  policy/tools-list filtering/audit redaction/batch fail-closed behavior are
  all preserved unchanged
- Not in scope: daemon/API/control plane, network/TLS interception, shell
  hooks, terminal-command scanning, endpoint agent, DLP/content inspection,
  or arbitrary MCP tool execution

## v0.7.0 - CI and team workflow integration

- `docs/ci.md` documents how to adopt EtherFence in a team/CI pipeline:
  failing a PR on findings with `scan --fail-on`, failing only on new
  findings with `scan --baseline`/`--fail-on-new`, generating and uploading
  a SARIF report, validating MCP proxy policies in CI with `mcp-policy
  validate`, and dry-run-checking MCP policy decisions in CI with
  `mcp-policy check` without starting an MCP server; also documents avoiding
  secrets in checked-in baselines/policies and restates that EtherFence is
  local-first and pre-v1
- New checked example CI input files under `docs/examples/ci/`: a scan-only
  posture policy (`scan-policy.toml`), an MCP proxy policy
  (`mcp-policy.toml`), a baseline generated from `tests/fixtures/home`
  (`baseline.json`), and JSON-RPC request fixtures for `mcp-policy check`
  covering an allowed tool call, a denied tool, and a denied path
  (`requests/`)
- New checked example GitHub Actions workflows under
  `docs/examples/workflows/` (documentation, not active repository
  workflows): a scan posture gate, a scan-with-baseline gate, a SARIF
  generate-and-upload workflow, an MCP policy validate/explain/check gate,
  and a combined PR security gate composing all of the above
- New README "CI and team workflow integration" section pointing at
  `docs/ci.md` and the example files/workflows above
- New tests (`crates/etherfence-cli/tests/ci_examples.rs`) keeping the
  examples honest: example policies parse, example JSON-RPC requests are
  valid JSON, `mcp-policy check` against the example requests produces the
  documented allow/deny decisions, the regenerated baseline matches the
  checked-in one, every example workflow file parses as YAML, and every
  file/command path referenced by the example workflows and `docs/ci.md`
  exists
- No production `mcp-proxy` enforcement behavior changes, no
  `ef-mcp-policy/v0.1` schema changes, no daemon/API/control plane, no
  marketplace GitHub Action, no automatic PR-commenting bot, and no new
  runtime blocking mode; `scan`, `policy`, `mcp-proxy`, and `mcp-policy`
  behavior, v0.6.1 subprocess test hardening, v0.6.0 `mcp-policy`
  validate/explain/init/check, v0.5.0 compatibility smoke tests, and v0.4.1
  Unicode hardening/v0.4.0 path guards are all preserved unchanged

## v0.8.0 - packaging, install docs, and README refresh

- New `docs/install.md`: Linux/Windows release-artifact install flows,
  build-from-source, local `cargo install --path crates/etherfence-cli
  --bin etherfence`, `etherfence --version` verification, a first-scan
  walkthrough, a release-artifact table, SHA-256 checksum verification
  steps for Linux and Windows, and a Linux/Windows smoke-test checklist
- SHA-256 checksum generation added to the manual release workflow
  (`.github/workflows/release.yml`): `.sha256` files for both the Linux
  `tar.gz` and Windows `zip` artifacts, uploaded and attached to the GitHub
  release alongside the existing archives; release creation stays manual,
  explicit, and `workflow_dispatch`-only
- `docs/release-automation.md` and `docs/release-checklist.md` updated to
  document the new checksum artifacts and manual-fallback checksum steps
- README.md restructured for readability (one-line positioning, pre-v1
  status, what it does/does not do, quickstart, install/build, command
  overview table, focused scan/mcp-policy/mcp-proxy examples, CI summary,
  docs-links table, security model/non-goals, development/verification,
  license) with no command, schema, or enforcement content changes
- New tests (`crates/etherfence-cli/tests/install_docs.rs`) keeping
  `docs/install.md` and README install/quickstart content honest: example
  paths exist, `mcp-policy init/validate/check` commands shown in the docs
  succeed end to end, README command snippets use real subcommands, and
  `--version` output matches the workspace version
- Version bumped to 0.8.0
- No production `mcp-proxy` enforcement behavior changes, no
  `ef-mcp-policy/v0.1` schema changes, no daemon/API/control plane, no
  installer/MSI, no package-registry publishing, no auto-update system; all
  prior release behavior, CI/team workflow examples, `mcp-policy` UX, and
  proxy hardening are preserved unchanged; no git tag created or pushed for
  this release

## v0.9.0 - real-world MCP compatibility expansion

- Fixture-backed compatibility tests for more realistic MCP protocol shapes
  against the checked-in fake MCP server: a richer `tools/list` response
  with a nested `inputSchema` (nested object property, array-of-strings
  property, `required` list) preserved unchanged after filtering; realistic
  `resources/list` (`uri`/`name`/`mimeType`) and `resources/read`
  (`contents` array) shapes; `completion/complete` denied by method policy
- New example policy `examples/policies/mcp-memory-notes-readonly.toml` for
  a memory/notes-style MCP server
- `docs/mcp-compatibility-matrix.md` adds a status table for realistic MCP
  server categories (filesystem-style, GitHub/API-style, memory/notes-style,
  resources/read-capable, server→client feature servers), each with a
  recommended starting policy and an honest "no real-server row yet" status
- `docs/mcp-real-server-test-template.md` documents choosing a starting
  policy by server category for the existing optional, env-var-gated
  real-server smoke test
- No `ef-mcp-policy/v0.1` schema changes, no MCP proxy runtime enforcement
  behavior changes, no daemon/API/control plane, no real third-party MCP
  server started by default in CI; compatibility evidence only, not
  production-readiness certification; all prior release behavior preserved
  unchanged; no git tag created or pushed for this release

## v1.0.0 - stable local-first MCP boundary docs and release readiness

- New `docs/mcp-proxy-operator-guide.md`: a practical, task-oriented guide
  covering the before/after wrapping diagram, what goes before/after `--`,
  what `--policy`/`--server-name`/`--audit-log` do, how policy sections map
  to `--server-name`, how `tools/list` filtering works, how allowed/denied
  `tools/call` requests flow, dry-running decisions with `mcp-policy check`,
  inspecting audit logs, common failure modes and exit codes, and concrete
  generic/filesystem/memory-notes config examples
- README adds a short "How `mcp-proxy` fits into your MCP client config"
  pointer to the new operator guide (no duplication of the full guide) and
  updates its status line, `mcp-proxy` description, and example-policy count
  to reflect a stable CLI/schema surface
- `docs/mcp-proxy.md`, `docs/mcp-policy-ux.md`, and
  `docs/mcp-compatibility-matrix.md` cross-link the operator guide and
  reword status language to: EtherFence v1.0.0 is production-ready for
  controlled local-first deployments of its defined scope (scan,
  mcp-policy, and the stdio mcp-proxy boundary), with a stable CLI and
  policy schema — not a universal certification for every MCP server, MCP
  client, or deployment environment; no new compatibility claims and no
  schema changes
- `docs/install.md` and `docs/release-checklist.md` updated for the v1.0.0
  version and the same production-ready-for-defined-scope framing
- New docs-drift tests: operator guide referenced paths exist, its
  documented `mcp-policy check` examples produce the exact ALLOW/DENY
  decisions shown, README links to the operator guide, and the checked-in
  example-policy count matches what README states
- Version bumped to 1.0.0
- No new runtime enforcement semantics, no `ef-mcp-policy/v0.1` schema
  changes, no daemon/API/control plane, no package publishing/auto-update;
  operators must still test their chosen MCP servers and policies and
  monitor audit logs — this is not a universal certification; all prior
  release behavior (v0.9.0 compatibility evidence, v0.8.0 install/release
  docs, v0.7.0 CI examples, v0.6.x policy UX, v0.5.0 smoke tests, v0.4.x
  path/Unicode hardening) preserved unchanged; no git tag created or
  pushed for this release

## v1.0.1 - scan output status wording fix

- Fixed stale v0.1-era `scan` status/note wording left in human, JSON,
  Markdown, and SARIF output after v1.0.0: `status` changes from
  `pre-alpha-scan-only` to `stable-local-scan`, and the note is now scoped
  to the `scan` command ("This scan command is read-only posture
  discovery... Runtime MCP boundary enforcement is available separately
  through `etherfence mcp-proxy`.") instead of describing all of EtherFence
  as pre-alpha and scan-only
- Messaging/status-only patch: no scanner detection logic, finding IDs,
  severities, fingerprints, `ef-scan-report/v0.1.1` schema, or baseline
  comparison changes; no `mcp-proxy` enforcement or `ef-mcp-policy/v0.1`
  changes; no git tag created or pushed for this release

## v1.2.0 - expanded agent integration catalog and MCP server classification

- `etherfence setup catalog` — a new, purely informational, read-only
  command printing a fixed 10-client compatibility matrix (Claude-style
  config, Cursor, VS Code, Hermes, Antigravity, Windsurf, Gemini CLI,
  Codex CLI, OpenCode, Cline / Roo Code) with an honest support tier per
  client (`fixture-verified` / `detect-only` / `advisory-only` /
  `unknown`) and local-presence status; new `ef-setup-catalog/v0.1` schema
- `etherfence setup detect` gains static, local-only, multi-label MCP
  server capability classification (`filesystem`, `network`, `browser`,
  `shell / command execution`, `database`, `SaaS / API`,
  `identity / auth`, `messaging / collaboration`, `security tooling`,
  `unknown`) derived from a small curated command/package signature table
  — no live MCP protocol interaction, no network access, no command
  execution from inspected configs; new `ef-setup-detect/v0.1` schema
  (the first JSON output `setup detect` has ever had)
- Deterministic, deny-by-default starter-policy recommendations per MCP
  server: `tier` is always `deny` in v1.2.0 (`allow` is reserved for a
  future release, gated behind a fixture-verified safe-capability mapping
  that does not exist yet); `needs_review` escalates whenever a server's
  capabilities include `unknown`, `shell / command execution`, or
  `identity / auth`
- Both new commands/flags gain a `--format human|json` flag; `setup
  catalog` has no `--fail-on` flag and always exits `0`
- 5 new `AgentKind` variants (Hermes, Antigravity, OpenCode, Cline, Roo
  Code) with presence-only local detection, mirroring the existing Tirith
  `PresenceOnly` precedent — no config/MCP-server parsing is attempted for
  them
- No new crate, daemon, network access, or runtime-enforcement change;
  `mcp-proxy` and existing `scan`/`setup detect/plan/apply/rollback/doctor`
  behavior are unchanged aside from the additive `setup detect` fields
  above; `setup plan` and `setup doctor` human output is byte-identical to
  their pre-v1.2.0 output

## v1.3.0 - MCP server trust and integrity assessment

- `etherfence setup detect` gains a static, local-only, deterministic
  trust-and-integrity assessment per MCP server, alongside the existing
  v1.2.0 capability classification and starter-policy recommendation;
  new `ef-setup-detect/v0.2` schema (additive over v1.2.0's
  `ef-setup-detect/v0.1` — every existing field keeps its name, type, and
  meaning)
- Package-runner invocation pinning for `npx`, `uvx`, and `pipx run`:
  parses package identity and classifies the version expression as
  exactly pinned, omitted, a mutable tag, a version range, or
  unsupported/ambiguous — no package registry access, installation, or
  execution
- Shell-wrapper detection (`sh -c`, `bash -c`, `cmd.exe /c`,
  `powershell`/`pwsh` `-Command`/`-EncodedCommand`) and a fixed, closed
  set of 5 obscured/download-and-execute launch patterns (downloader
  piped to shell, `certutil -urlcache`, PowerShell web-request piped to
  `Invoke-Expression`, decode-piped-to-shell, encoded PowerShell option),
  detected by bounded structural string matching — no general shell
  parser, no command execution, no decoding
- Executable-path classification (absolute path, relative path,
  bare/PATH-resolved command, missing path, non-regular file, symlink,
  temporary-directory location) with bounded, streamed local SHA-256
  hashing for an eligible absolute regular-file path only; `PATH` is
  never searched and symlinks are never followed or dereferenced
- Narrow Unicode/identity-ambiguity indicators (bidirectional control
  characters, invisible/zero-width characters, a defined mixed-script
  condition, and one curated confusable-identity alias), reusing
  `etherfence-mcp`'s existing bidi/zero-width detection
- Environment-variable name-only risk categories (dynamic loader
  injection, interpreter/runtime path override, package-registry
  override, TLS-verification-disabling, secret-like names); environment
  variable values are never read into evidence
- Artifact Identity Confidence (`verified-local`/`known-source`/`unknown`)
  and Configuration Risk status (`no-known-indicators`/`needs-review`/
  `high-risk`) are reported independently and combined into one
  Aggregate Assessment status by a fixed configuration-risk-first
  precedence rule — a favorable artifact identity never hides a raised
  configuration-risk indicator, and both fields remain visible regardless
  of which one determined the aggregate
- `recommendation.tier` remains `deny` for every server; this feature
  introduces no path to a permissive `allow` recommendation
- Remote (URL-configured, non-stdio) servers still receive
  environment-variable and Unicode/identity-ambiguity assessment;
  invocation/executable-path/local-artifact assessment is explicitly
  reported as not applicable rather than fabricated or silently omitted
- Explicitly not a malware scanner, behavioral security sandbox, endpoint
  protection product, package authenticity/signature verifier,
  package-registry reputation service, universal typosquatting detector,
  universal Unicode confusable detector, or universal MCP server
  certification system
- No new crate, daemon, network access, subprocess execution, or
  runtime-enforcement change; `mcp-proxy`, `ef-mcp-policy/v0.1`, `setup
  catalog`, `scan`, and existing `setup plan/apply/rollback/doctor`
  behavior are unchanged; `setup plan` and `setup doctor` human output is
  byte-identical to their pre-v1.3.0 output

## v1.4.0 - MCP server integrity baseline and drift detection

- `etherfence setup baseline write --root <path> --output <file>
  [--overwrite]`: writes a deterministic, point-in-time MCP server
  integrity baseline (`ef-setup-baseline/v0.1`); refuses to overwrite an
  existing output file unless `--overwrite` is passed
- `etherfence setup baseline check --root <path> --baseline <file>
  [--format human|json] [--fail-on-drift] [--fail-on-new]
  [--fail-on-risk-increase]`: compares current state against a baseline
  and reports drift (`ef-setup-baseline-comparison/v0.1`); strictly
  read-only against `--baseline` — never auto-updates, auto-accepts, or
  rewrites it under any circumstance
- Every server classified as `unchanged`/`new`/`changed`/`missing`/
  `unverifiable`, with a closed, deterministic 14-value drift-reason enum
  (executable hash, command, arguments, package identity/version,
  environment-variable name set, transport, server added/removed,
  capability set, trust-indicator set, artifact identity, a documented
  risk increase, or the executable becoming newly unverifiable)
- Collision-safe identity fingerprint derived from agent, normalized
  config-source path, and server name — never display name alone;
  transport is tracked as a comparable field rather than folded into the
  fingerprint, so a transport change is reported as drift instead of
  making the server unrecognizable across runs
- Fixed monotonic risk ordering over the five trust-assessment aggregate
  values; a risk decrease is always visible as drift but never satisfies
  `--fail-on-risk-increase` by itself
- Reuses v1.3.0's discovery, classification, trust assessment, and local
  artifact hashing exactly as-is — no new discovery/classification/hashing
  engine; every v1.3.0 file-safety invariant (no-follow open, opened-file
  identity re-validation, bounded streamed reads, no symlink following)
  is preserved when re-hashing for comparison
- Persists/emits only safe, normalized fields — identity, command/argument
  *fingerprints* (hashes, never raw text), package identity/version
  classification, executable path/hash, environment variable *names*
  (never values), capability labels, trust-indicator IDs/categories/
  severities, and the v1.3.0 trust/risk vocabulary; never persists or
  emits raw environment values, secrets, credentials, file contents,
  prompts/messages, or MCP protocol traffic
- No new crate, daemon, network access, subprocess execution, malware
  classification, registry/reputation lookup, download/install action,
  signature/provenance verification, or sandboxing; `ef-setup-detect/v0.2`,
  the pre-existing `scan --write-baseline`/`--baseline`
  (`ef-baseline/v0.1.3`), `mcp-proxy`, `ef-mcp-policy/v0.1`, and every
  other existing `setup` subcommand are unchanged

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
