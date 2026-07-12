# Changelog

All notable changes to EtherFence are documented in this file.

EtherFence v1.0.0 is production-ready for controlled local-first
deployments of its defined scope: scan, mcp-policy, and the stdio
mcp-proxy boundary. This is not a security certification for every MCP
server, MCP client, or deployment environment; operators must still
review policies, test their chosen servers, and monitor audit logs. The
v0.1.x line is scan-only; nothing in v0.1.x performs runtime blocking, MCP
proxying, daemon mode, shell hooks, command interception, terminal-command
scanning, or network interception. v0.2.x adds one opt-in runtime
component: an MCP stdio boundary proxy, whose CLI surface and
`ef-mcp-policy/v0.1` policy schema are stable as of v1.0.0. v1.5.0 adds an
optional, additive `ef-mcp-policy/v0.2` schema extension for argument/param
field guards; `ef-mcp-policy/v0.1` policies are unaffected. EtherFence still
has no daemon mode, shell hooks, command interception, terminal-command
scanning, or network interception.

## [1.7.3] - 2026-07-12

### Changed

- **Enhanced startup banner**: added a clean separator and metadata line
  beneath the ASCII art showing the product tagline, version, and scan mode
  (`LOCAL POSTURE ASSESSMENT`). The ASCII art itself is unchanged.
  Compatible with narrow terminals and ANSI-disabled output.
- **Redesigned `scan --verbose` output**: organized by AI client → MCP server
  → findings with consolidated, deduplicated recommended actions. Uses the
  same themed visual system as the default summary.
- **Removed internal implementation noise from verbose output**: schema
  identifiers, internal status strings, and fingerprints no longer appear
  in normal verbose mode.

### Added

- **`--debug` flag on `scan`**: when combined with `--verbose`, includes
  full technical evidence (fingerprints, schema IDs, policy-status,
  baseline-status) in the human output.
- **Unicode/ASCII fallback**: box-drawing characters and Unicode symbols
  automatically fall back to ASCII equivalents when the terminal does not
  support Unicode (detected via TERM=dumb, NO_UNICODE, and C locale).

### Fixed

- All human output now wraps correctly on narrow terminals (≤42 columns).
- ANSI color codes are fully suppressed when NO_COLOR, CI, or dumb
  terminals are detected.

## [1.7.2] - 2026-07-12

### Added

- **Protection coverage in scan output**: when `etherfence scan` is run with
  `--policy` or `--policy-profile`, all output formats now include a
  Protection Coverage section showing which detected MCP servers are
  covered by the active policy and which are not. The coverage data
  maps every MCP server to its coverage status under the policy:
  `covered` (in allowlist), `not_covered` (not in allowlist),
  `no_policy_for_agent` (no agent section in policy), `empty_allowlist`
  (implicit allow-all), or `not_applicable` (Tirith, excluded from MCP
  server coverage). Coverage appears in:
  - Human summary: a "Protection coverage" section between Clients and
    Priority Findings with per-server ✓/✗ markers
  - Human verbose: `[covered]`/`[not covered]` badges on each MCP server
  - Markdown: a "## Protection Coverage" table
  - JSON: a `protection_coverage` field in the report root
  - SARIF: `protectionCoverage` in run.properties
- Additive schema bump: `ef-scan-report/v0.1.1` → `ef-scan-report/v0.1.2`
  (optional `protection_coverage` field; existing consumers unaffected).

## [1.7.1] - 2026-07-12

### Fixed

- **Scan posture presentation**: default and verbose human reports now wrap long titles, targets, impact statements, and recommendations using Unicode display columns with stable continuation indentation. Narrow terminals, `NO_COLOR`, redirected/non-TTY output, and plain terminals remain readable and deterministic without raw ANSI sequences. This is presentation-only: posture calculation, finding selection/order, machine formats, schemas, baselines, policies, exit behavior, SARIF, and MCP runtime enforcement are unchanged.

## [1.7.0] - 2026-07-12

### Added

- **Scan posture experience**: `etherfence scan` now presents a deterministic 0–100 posture score, A–F grade, concise advisory assessment, and up to three priority risks with linked recommended next actions before detailed evidence. The default terminal view extends the existing EtherFence theme and retains the full-evidence path through `--verbose`.
- **Consistent reports**: verbose human and Markdown reports now include the same posture, priority-risk, and action summary before their complete severity-grouped evidence.
- **Additive JSON posture**: `ef-scan-report/v0.1.1` now optionally includes `posture` with deterministic counts, score, grade, priority risks, and recommended actions. Existing fields, schema identifier, SARIF output, baseline files, scan selection, and exit-code behavior remain unchanged.

### Compatibility

- Posture is local, read-only, and advisory. It does not add detectors, alter severities/finding IDs, remediate configurations, prove a host is secure, or change `mcp-proxy` enforcement.
- The score derives from displayed active findings after existing severity filtering and baseline comparison; resolved historical findings remain evidence but do not lower the score or consume a priority slot.

## [1.6.2] - 2026-07-12

### Fixed

- **Detection snapshot consistency**: `attach_entry_snapshots` now uses
  the bounded `read_bounded_text_file` (5 MiB limit) instead of the
  unbounded `fs::read_to_string`, so snapshot derivation, trust assessment,
  and inventory data all respect the same file-size bound. An oversized
  (> 5 MiB) or unreadable supported config never receives a canonical-entry
  snapshot, and the apply drift gate correctly refuses to wrap servers
  without a reviewed snapshot (fail-closed).

## [1.6.1] - 2026-07-12

### Added

- **Interactive selection flow**: the guided setup wizard now walks
  one-decision-per-screen steps — scan, choose AI clients (grouped by
  product with CAN CONFIGURE / DETECT ONLY badges), choose MCP servers
  (risk badges instead of raw trust tokens), resolve trust and pinning
  issues, choose policy posture, review the exact change plan, apply and
  verify. Advisory-only clients are selectable for review with an explicit
  note that EtherFence cannot modify them.
- **Package pinning engine**: unpinned, mutable-tag, or range-based
  `npx`/`uvx`/`pipx run` invocations can be pinned to an exact version
  during the wizard. Pins are computed against the server's real parsed
  invocation (launcher flags and trailing arguments are preserved) and
  validated per runner — only exact npm or PEP 440 versions are accepted;
  `latest`, `^1.2`, `>=2`, and other mutable or range expressions are
  rejected at input time and again at plan time. Resolves
  EF-TRUST-PIN-001 in actual configuration output.
- **Trust gates**: high-risk servers cannot receive a permissive setup —
  the wizard offers skip (recommended) or quarantine-only mode, and
  needs-review/unknown servers are flagged before any decision.
- **Selective wizard apply**: confirming the wizard applies exactly the
  reviewed plan via a new fail-closed engine. Only selected servers are
  pinned, given their planned policy (deny-all quarantine, curated, or
  custom tool allowlist written verbatim), and wrapped; skipped servers
  and configs without selected servers stay byte-identical. If a selected
  server disappeared or a promised pin no longer applies, the apply
  aborts before writing anything.
- **Terminal UI layer**: a semantic theme (restrained colors with meaning:
  green success, yellow review, red high-risk, cyan paths, dim technical
  IDs) shared by the wizard and scan output, degrading to plain text for
  redirected output, `NO_COLOR`, `CLICOLOR=0`, CI, and `TERM=dumb`.
- **Scan executive summary**: `etherfence scan` now defaults to a readable
  posture summary (overall status, clients grouped by product, priority
  findings, next steps). New `--verbose` flag shows the previous full
  evidence view: rationale, recommendation, complete finding list, full
  fingerprints, and schema/status metadata. JSON, Markdown, and SARIF
  outputs are unchanged.
- Integration tests that verify wizard-applied files (not just the plan):
  selective wrapping, pin-in-invocation, custom allowlist content,
  byte-identical skips, and plan/apply correspondence; plus PTY tests
  proving the startup splash is wired into the binary.

### Fixed

- `apply_wizard_plan()` previously ignored the confirmed plan and ran the
  generic apply path: every unwrapped stdio server was wrapped regardless
  of selection, custom allowlists were replaced by deny-all templates,
  and version pins were never written. The apply now executes the
  reviewed plan exactly.
- Choosing "Skip this server" in the wizard previously left the server
  selected (it was committed before the trust/posture decisions); skip
  now truly skips — nothing is committed until every decision for a
  server is complete.
- Pinning plans were previously constructed from a synthetic minimal
  argument list; they are now derived from the server's real parsed
  configuration arguments.
- The terminal splash module existed but was never wired into the binary;
  `command_banner_mode()` now classifies every command (bare
  `etherfence setup` and human-format commands show the splash on an
  interactive color TTY; JSON/Markdown/SARIF, raw policy TOML, and MCP
  proxy protocol traffic never do).
- Wizard selections are now scoped by full server identity
  (`WizardServerId`: agent + config path + server name), never by
  `agent:server_name` alone — selecting a server in `~/.claude.json` no
  longer also selects a same-named server in `~/.claude/settings.json`.
- Apply now runs a complete preflight before creating any backup or
  policy and aborts the whole operation — instead of reporting a false
  "Setup complete" — when the apply root differs from the plan's root, a
  planned configuration no longer exists, a selected server disappeared,
  the plan is internally inconsistent (duplicate selections, missing or
  duplicate policies/pins, entries for unselected servers), or the
  prepared change counts differ from the reviewed plan.
- Post-preview configuration drift is detected: the plan records the
  exact command, argument list, and URL the user reviewed for every
  selected server, and apply aborts if any of them changed — a package
  swapped in after preview is never silently wrapped.
- Already-wrapped and remote servers are no longer selectable in the
  wizard (they are shown as explicit no-action rows), and
  `build_wizard_plan` rejects them — plans can no longer promise policy/
  proxy/backup changes that apply would silently skip.
- npm version pins are validated with a real semver parser: partial
  versions (`1`, `1.2`) and malformed input (`1..2`, `1foo`) are rejected
  along with tags and ranges; only a complete `major.minor.patch` (with
  optional prerelease/build metadata) is accepted.
- Unknown `npx` options before the package token now fail closed instead
  of being treated as the package name and rewritten; version pinning
  refuses to rewrite any invocation whose package position is ambiguous.
- Policy and backup output paths are collision-safe: sanitized policy
  filename collisions (e.g. `foo/bar` vs `foo?bar`) are disambiguated
  with a stable identity hash, backup directories include the config
  file's stem plus a nanosecond timestamp (two configs sharing
  `.vscode/` no longer race), and apply refuses to overwrite an existing
  policy file whose content differs from the planned content.
- The default `scan` view caps priority findings at 10 and points to
  `--verbose` for the rest, keeping the summary scannable on hosts with
  many findings.
- The post-preview drift gate now binds the plan to a canonical SHA-256
  snapshot of each selected server's complete JSON entry, captured at
  detection time — a change to `env` (or any other server-specific
  field) between preview and confirm aborts the apply, not just changes
  to command/args/url. Unrelated edits to unselected servers still do
  not abort.
- Apply refuses every pre-existing file at a planned policy path, even
  when its content is byte-identical to the planned content. Adopting
  such a file would record it in the backup manifest, making an
  operator-owned policy deletable by rollback or failed-apply cleanup;
  now only files the transaction itself creates are ever manifested,
  cleaned up, or removed. The same rule applies to the non-wizard
  `setup apply` path.

## [1.6.0] - 2026-07-11

### Added

- **Guided setup wizard**: `etherfence setup` (no subcommand) now launches an
  interactive guided setup experience on TTYs. The wizard scans for AI clients,
  detects MCP servers, and provides step-by-step guidance toward applying
  setup changes. On non-TTY (CI, pipes, scripts), it prints clear guidance to use
  explicit subcommands.
- **Safe policy generation**: Generated starter policies now default to
  **deny-all quarantine** (`tools.allow = []`, `methods.allow = ["tools/list"]`)
  instead of the previous wildcard `tools.allow = ["*"]`. This is a security
  correction — policies now fail-closed by default. Operators refine the
  allowlist explicitly after setup.
- **Real Hermes config path**: Hermes Agent detection now uses the actual
  `~/.hermes/config.yaml` path (YAML format, `mcp_servers:` key) instead of
  the incorrect `~/.hermes/config.json` guess. Hermes MCP servers are now
  parsed from YAML config.
- **Real OpenCode and Antigravity detection**: OpenCode now probes
  `~/.config/opencode/opencode.{json,jsonc}` and Antigravity probes
  `~/.gemini/config/mcp_config.json` with binary detection for `agy`.
- New core types for client detection granularity: `ReadSupport`, `WriteSupportKind`,
  `ConfigFormat::Yaml`.

### Changed

- `generated_policy_template()` now produces deny-all policies instead of
  wildcard allow-all. Existing policies written by earlier versions are
  unaffected; this only changes new policy generation.
- README Quickstart now leads with `etherfence setup` (guided wizard) and
  documents explicit subcommands as advanced/CI usage.

### Fixed

- Hermes Agent no longer requires the nonexistent `~/.hermes/config.json`
  marker file for detection. The correct `~/.hermes/config.yaml` path is
  used, with YAML format and MCP server parsing.
- OpenCode and Antigravity detection now uses real config paths and binary
  names discovered from live system inspection.

## [1.5.0] - 2026-07-11

### Added

- New versioned MCP proxy policy schema extension `ef-mcp-policy/v0.2`,
  additive over `ef-mcp-policy/v0.1`: every existing v0.1 policy continues
  to parse and evaluate byte-for-byte identically, and a v0.2-only
  construct (`require_keys`/`forbid_keys`/`fields`) under `schema_version =
  "ef-mcp-policy/v0.1"` is rejected at load time with an error naming
  `ef-mcp-policy/v0.2`. Documented in `docs/mcp-policy-ux.md` and
  `specs/004-argument-aware-mcp-policy/contracts/ef-mcp-policy-v0.2.md`.
- **Argument/param field guards**, configurable per guarded `tools/call`
  `arguments` object or method `params` object: object-level `require_keys`/
  `forbid_keys`, plus six per-field primitives addressed through one
  bounded, non-regex selector syntax (dotted object keys / array indices,
  up to 8 segments) — `exact` (one scalar), `enum` (a finite scalar set),
  `string` (length bounds, literal prefix), `number` (inclusive min/max),
  `array` (length bounds, a finite allowed-element set), and `url` (scheme
  allowlist, normalized-hostname allowlist, effective-port allowlist —
  explicit port or the scheme's default, `http`→80/`https`→443 only — and
  boundary-safe path-prefix allowlist). Guards apply only where configured;
  an unguarded field's behavior is unchanged.
- Fail-closed per guard: a missing guarded key, a value of the wrong JSON
  type, a malformed value, or an unresolvable selector all deny that one
  guard's decision. The URL guard specifically rejects, without attempting
  to decode or partially parse them, any value containing `%` (percent
  encoding is how allowlist checks get bypassed), userinfo (`@`) in its
  authority (the classic `trusted.example@evil.example` confusable-host
  attack), or a `.`/`..` path segment (a path-prefix allowlist check on the
  raw string alone would otherwise be bypassable, since a downstream server
  commonly resolves `/api/../admin` to `/admin`). A `number` guard's `min`/
  `max` and any `exact`/`enum`/`allowed_elements` scalar must be finite —
  `NaN`/`+-infinity` are rejected at load time rather than silently
  disabling the bound they appear in (every comparison against `NaN` is
  `false`).
- One shared, pure decision evaluator
  (`decide_tool_argument_guards`/`decide_method_param_guards` in
  `etherfence-mcp::policy`) used by both the live `mcp-proxy`
  (`inspect_client_line`/`inspect_server_line`) and the serverless
  `mcp-policy check` dry run (`policy_ux::dry_run_check`) — no duplicated
  decision logic, so a dry run and a live proxy decision can never
  diverge. v0.2 guards are evaluated only when the existing v0.1
  method/tool/path decision is still `allow`; the v0.1 path guard's own
  precedence and its `resources/read`-only scope are completely unchanged.
  The v0.2 params guard is new, additive capability applicable to any
  method (not just `resources/read`) and, for the first time, to
  server→client method params as well as client→server.
- Argument/param guards may be configured globally
  (`[tools."<tool>".arguments]` / `[methods."<method>".params]`) and/or per
  server (`[servers."<name>".tools."<tool>".arguments]` /
  `[servers."<name>".methods."<method>".params]`); when both are configured
  for the same tool/method, both must pass (guards only narrow, so there is
  no "more specific wins" override). A server-scoped guard never applies
  outside its own server scope.
- `etherfence mcp-policy validate` rejects (fail closed, at load time):
  duplicate/conflicting `require_keys`/`forbid_keys` on the same key,
  invalid or unbounded selectors (empty/too many segments, disallowed
  characters, suspicious Unicode via the existing hardening), invalid URL
  guard schemes/hosts/ports, impossible numeric/length/array ranges
  (`min > max`), empty `enum`/`allowed_elements` lists, unsupported guard
  types, and v0.2-only constructs under a v0.1 `schema_version`.
- `etherfence mcp-policy explain` gains an `Argument/param field guards:`
  section listing every configured v0.2 guard, its scope, and its
  primitive kind. `etherfence mcp-policy check` reports a `Guard decision:
  key=... selector=... reason_category=...` line and structured
  `guard_key`/`guard_selector`/`guard_reason_category` fields when a v0.2
  guard produced the decision, using the same closed-set reason-category
  vocabulary as the audit log (e.g. `enum_value_not_allowed`,
  `required_key_missing`, `forbidden_key_present`, `field_missing`,
  `field_wrong_type`, `string_prefix_mismatch`, `number_below_minimum`,
  `array_element_not_allowed`, `url_host_not_allowed`).
- `etherfence mcp-policy init` gains four new profiles demonstrating v0.2
  guards, each backed by a new checked-in example policy:
  `github-scoped-orgs`, `messaging-named-destinations`,
  `browser-approved-hosts`, `readonly-operation-guard`.
- `AuditRecord` gains three additive fields — `guard_key`, `guard_selector`,
  `guard_reason_category` — mirroring the existing `path_rule`/`path_key`/
  `path_classification` trio. The evaluated field value, the full
  arguments/params object, and any URL (including its query string) are
  never written to the audit log or echoed in a JSON-RPC denial response —
  only safe rule/guard identifiers, selector/key names, decisions, and
  closed-set reason categories.
- No new crate dependency: URL parsing/normalization and selector
  resolution are hand-rolled, deterministic, string-level operations in
  `crates/etherfence-mcp/src/policy.rs`, matching how the v0.4.0 path
  guard's lexical path normalizer is already implemented.
- **Non-goals** (explicitly not implemented): natural-language analysis or
  prompt-injection detection/intent inference; a general regular-expression,
  scripting, or expression policy language; shell-command parsing or
  command-content allowlisting; DLP/content inspection or SQL analysis
  beyond the six structured primitives above; remote MCP proxying; a
  daemon or control plane; automatic policy widening; and no claim that a
  v0.2-guarded/allowed tool call makes the wrapped MCP server safe overall.

## [1.4.0] - 2026-07-11

### Added

- `etherfence setup baseline write --root <path> --output <file>
  [--overwrite]`: writes a deterministic, point-in-time MCP server
  integrity baseline. New `ef-setup-baseline/v0.1` schema, documented in
  `docs/json-schema.md`. Refuses to overwrite an existing output file
  unless `--overwrite` is passed; never mutates any scanned config, MCP
  server, or policy file.
- `etherfence setup baseline check --root <path> --baseline <file>
  [--format human|json] [--fail-on-drift] [--fail-on-new]
  [--fail-on-risk-increase]`: compares current MCP server state against a
  previously written baseline and reports drift. New
  `ef-setup-baseline-comparison/v0.1` schema. Strictly read-only against
  `--baseline` — never auto-updates, auto-accepts, or silently rewrites it
  under any circumstance, including when a gate flag causes a non-zero
  exit; the full report is always printed first.
- Every server is classified as `unchanged`, `new`, `changed`, `missing`,
  or `unverifiable`, with a closed, deterministic 15-value drift-reason
  enum: `executable-hash-changed`, `command-changed`, `arguments-changed`,
  `package-identity-changed`, `package-version-changed`,
  `environment-variable-names-changed`, `transport-changed`,
  `server-added`, `server-removed`, `capability-set-changed`,
  `trust-indicator-set-changed`, `artifact-identity-changed`,
  `configuration-risk-changed`, `risk-increased`,
  `executable-became-unverifiable`.
- Collision-safe identity fingerprint derived from a stable agent-kind
  key (e.g. `"vs-code"`, never the human-facing display name, which is
  persisted separately as `agent` for readability only), normalized
  config-source path, and server name — hashed via a canonical JSON-array
  encoding, not a delimiter-joined string, so no combination of
  operator-controlled command/argument/path text can collide across a
  field boundary. Transport is intentionally tracked as an ordinary
  comparable field rather than folded into the fingerprint, so a server
  switching transport is reported as `changed`/`transport-changed` instead
  of one server vanishing and an unrelated one appearing.
- `check` refuses to read a `--baseline` path that is a symlink (fails
  closed rather than silently following it), and validates a parsed
  baseline's internal consistency (fingerprints match their own identity
  fields, no duplicate fingerprints, well-formed `sha256`, sorted/
  deduplicated set fields, `aggregate` consistent with its own
  `artifactIdentity`/`configurationRisk`) before ever comparing against
  it. `write` without `--overwrite` uses atomic exclusive file creation
  (never a separate existence-check then write), and `write --overwrite`
  writes to a temp file and atomically renames it into place.
- Fixed monotonic risk ordering over the five v1.3.0 aggregate values
  (`verified-local` < `known-source` < `unknown` < `needs-review` <
  `high-risk`). A risk *decrease* is always reported as drift (never
  silently hidden) but never satisfies `--fail-on-risk-increase` by
  itself — only a documented increase does.
- Reuses v1.3.0's discovery (`etherfence_inventory::discover`),
  capability classification, trust assessment, and local artifact hashing
  exactly as-is (zero changes to `trust.rs`/`classification.rs` logic —
  only additive `Deserialize` derives so the baseline round-trips through
  JSON). Every v1.3.0 file-safety invariant (no-follow open, opened-file
  identity re-validation, bounded streamed reads, no symlink following) is
  preserved when re-hashing for comparison; a single-byte change to a
  hashed executable always produces `changed`/`executable-hash-changed`.
- Persists/emits only safe, normalized fields: identity, command/argument
  *fingerprints* (SHA-256 hashes, never raw command/argument text),
  package identity/version classification, executable path/hash,
  environment variable *names* (never values), capability labels,
  trust-indicator IDs/categories/severities, and the v1.3.0 trust/risk
  vocabulary. Never persists or emits raw environment values, secrets,
  credentials, file contents, prompts/messages, or MCP protocol traffic.
- New pure comparison module `crates/etherfence-setup/src/baseline.rs`;
  all CLI argument parsing, file I/O, and rendering lives in
  `etherfence-cli`. No new crate, daemon, network access, subprocess
  execution, malware classification, registry/reputation lookup,
  download/install action, signature/provenance verification, or
  sandboxing.
- `ef-setup-detect/v0.2` and its command are unchanged. The pre-existing,
  unrelated `scan --write-baseline`/`--baseline` findings-baseline feature
  (`ef-baseline/v0.1.3`) is unaffected. `mcp-proxy`, `ef-mcp-policy/v0.1`,
  deny-by-default starter-policy recommendations, and every other existing
  `setup` subcommand (`detect`, `catalog`, `plan`, `apply`, `rollback`,
  `doctor`) are unchanged.

## [1.3.0] - 2026-07-11

### Added

- `etherfence setup detect` gains a static, local-only, deterministic
  **trust and integrity assessment** for every discovered MCP server,
  alongside the existing v1.2.0 capability classification and
  starter-policy recommendation. New `ef-setup-detect/v0.2` JSON schema,
  additive over v1.2.0's `ef-setup-detect/v0.1` (every existing field
  keeps its exact name, type, and meaning); documented in
  `docs/json-schema.md`. Default human output gains two more lines per
  server (`trust: ...`, `trust indicators: ...`) — again additive, not
  byte-identical to pre-v1.3.0 output.
- Package-runner invocation pinning for `npx`, `uvx`, and `pipx run`:
  parses package identity and classifies the version expression as
  exactly pinned, omitted, a mutable tag, a version range, or
  unsupported/ambiguous. No package registry access, installation, or
  execution.
- Shell-wrapper detection (`sh -c`, `bash -c`, `cmd.exe /c`,
  `powershell`/`pwsh` `-Command`/`-EncodedCommand`) and a fixed, closed
  set of 5 obscured/download-and-execute launch patterns, detected by
  bounded structural string matching over already-tokenized arguments —
  no general shell parser, no command execution, no decoding.
- Executable-path classification (absolute path, relative path,
  bare/PATH-resolved command, missing path, non-regular file, symlink,
  temporary-directory location) with bounded, streamed local SHA-256
  hashing for an eligible absolute regular-file path only. `PATH` is
  never searched and symlinks are never followed or dereferenced. File
  metadata is checked immediately before and after the read; any change
  discards the computed hash rather than reporting it.
- Narrow Unicode/identity-ambiguity indicators (bidirectional control
  characters, invisible/zero-width characters, a defined mixed-script
  condition, and one curated confusable-identity alias), reusing
  `etherfence-mcp`'s existing bidi/zero-width detection.
- Environment-variable name-only risk categories (dynamic loader
  injection, interpreter/runtime path override, package-registry
  override, TLS-verification-disabling, secret-like names).
  Environment-variable *values* are never read into evidence, logged, or
  persisted anywhere.
- Artifact Identity Confidence (`verified-local`/`known-source`/`unknown`)
  and Configuration Risk status (`no-known-indicators`/`needs-review`/
  `high-risk`) are reported independently and combined into one
  Aggregate Assessment status by a fixed configuration-risk-first rule.
- Remote (URL-configured, non-stdio) servers still receive
  environment-variable and Unicode/identity-ambiguity assessment;
  invocation/executable-path/local-artifact assessment is explicitly
  reported as not applicable.

### Notes

- `recommendation.tier` remains `deny` for every server; this feature
  introduces no path to a permissive `allow` recommendation. No
  `mcp-proxy` behavior, `ef-mcp-policy/v0.1` schema, `tools/list`
  filtering, `tools/call` enforcement, method policy, path policy, or
  audit behavior changed. `setup catalog` and `scan` behavior are
  unaffected. `setup plan` and `setup doctor` human output is
  byte-identical to their pre-v1.3.0 output — the new `SetupServer`
  field (`trust_assessment`) is additive and only rendered by `setup
  detect`.
- This feature is not a malware scanner, a behavioral security sandbox,
  an endpoint protection product, a package authenticity or
  software-signature verifier, a package-registry reputation service, a
  universal typosquatting detector, a universal Unicode confusable
  detector, or a universal MCP server certification system. It does not
  guarantee that no malicious behavior exists, and it is not a
  replacement for manual review or for `mcp-proxy`'s runtime
  least-privilege policy.
- No new crate, daemon, network access, or subprocess execution was
  introduced.

## [1.2.0] - 2026-07-11

### Added

- New `etherfence setup catalog [--format human|json] [--root <path>]`
  command: a purely informational, read-only, always-exit-0 command
  printing a fixed 10-client compatibility matrix (Claude-style config,
  Cursor, VS Code, Hermes, Antigravity, Windsurf, Gemini CLI, Codex CLI,
  OpenCode, Cline / Roo Code), each row reporting an honest support tier
  (`fixture-verified`, `detect-only`, `advisory-only`, or `unknown`) and
  local-presence status with discovered configuration path(s). New
  `ef-setup-catalog/v0.1` JSON schema, documented in `docs/json-schema.md`.
- `etherfence setup detect` gains a new `--format human|json` flag
  (defaulting to `human`; every pre-v1.2.0 line is preserved unchanged and
  in order, but two new `capabilities`/`recommendation` lines are appended
  per server, so default output is **not** byte-identical to pre-v1.2.0 —
  scripts that need the exact prior shape should use `--format json` or
  match only on pre-existing lines) and static, local-only, multi-label
  MCP server capability classification for every
  detected server: `filesystem`, `network`, `browser`,
  `shell / command execution`, `database`, `SaaS / API`,
  `identity / auth`, `messaging / collaboration`, `security tooling`, or
  `unknown` when no curated rule matches. Classification reads only
  already-parsed local `command`/`args` fields against a small curated,
  checked-in signature table — no live MCP protocol interaction, no
  network access, and no command execution from inspected configs. New
  `ef-setup-detect/v0.1` JSON schema (the first JSON output `setup detect`
  has ever had), documented in `docs/json-schema.md`.
- Deterministic, deny-by-default starter-policy recommendations for every
  classified MCP server: `tier` is always `deny` in v1.2.0 (`allow` is
  reserved in the schema for a future release, pending a fixture-verified
  safe-capability mapping); `needs_review` is `true` whenever a server's
  capabilities include `unknown`, `shell / command execution`, or
  `identity / auth`.
- 5 new `AgentKind` variants with presence-only local detection: Hermes,
  Antigravity, OpenCode, Cline, and Roo Code, mirroring the existing
  Tirith `PresenceOnly` precedent. No config/MCP-server parsing is
  attempted for these clients; they are honestly reported as
  `advisory-only` in the catalog.

### Notes

- No `mcp-proxy` or `scan` behavior changed. `setup plan` and `setup
  doctor` human output is byte-identical to their pre-v1.2.0 output — the
  new `SetupServer` fields (`capabilities`, `recommendation`) are additive
  and only rendered by `setup detect`. No new crate, daemon, network
  access, or runtime-enforcement change was introduced.

## [1.0.1] - 2026-07-10

### Fixed

- Fixed stale v0.1-era `scan` output wording left over from before v1.0.0.
  The human, JSON, Markdown, and SARIF `status` field said
  `pre-alpha-scan-only`, and the human/Markdown note said "EtherFence is
  scan-only pre-alpha posture discovery. It does not block, proxy, hook, or
  intercept runtime activity...", both inaccurate now that v1.0.0 ships a
  stable local-first `mcp-policy` and `mcp-proxy` alongside `scan`. `status`
  is now `stable-local-scan`. The note is now scoped to the `scan` command
  specifically: "This scan command is read-only posture discovery. It does
  not block, proxy, hook, or intercept runtime activity. Runtime MCP
  boundary enforcement is available separately through `etherfence
  mcp-proxy`. Findings are posture risks/hints, not confirmed
  exploitability." Messaging/status-only change: no scanner detection
  logic, finding IDs, severities, fingerprints, `ef-scan-report/v0.1.1`
  JSON schema, baseline comparison behavior, `mcp-proxy` enforcement, or
  `ef-mcp-policy/v0.1` changes. No git tag created or pushed for this
  release.

## [1.0.0] - 2026-07-10

### Added

- New `docs/mcp-proxy-operator-guide.md`: a practical, task-oriented
  operator guide for wrapping a real MCP server with `etherfence mcp-proxy`.
  Covers the before/after wrapping diagram (`AI client -> MCP server` vs.
  `AI client -> etherfence mcp-proxy -> MCP server`), what goes before and
  after `--`, what `--policy`/`--server-name`/`--audit-log` each do, how
  policy sections map to `--server-name`, how `tools/list` filtering works,
  how allowed and denied `tools/call` requests flow, how to dry-run policy
  decisions with `mcp-policy check`, how to inspect audit logs, a table of
  common failure modes and exit codes, and concrete generic/filesystem/
  memory-notes config examples
- README adds a short "How `mcp-proxy` fits into your MCP client config"
  pointer section linking to the new operator guide, without duplicating it
- New docs-drift tests keeping the operator guide honest: every path it
  references exists, its documented `mcp-policy check` examples produce the
  exact `Decision: ALLOW`/`Decision: DENY` output shown, README links to the
  guide, and the checked-in MCP example-policy count matches what README
  states

### Changed

- Stability/wording pass for v1.0.0, with no behavior or schema changes:
  `README.md`, `docs/mcp-proxy.md`, `docs/mcp-policy-ux.md`,
  `docs/mcp-proxy-operator-guide.md`, `docs/mcp-compatibility-matrix.md`,
  `docs/install.md`, `docs/release-checklist.md`, and `docs/roadmap.md`
  reword status language to state that EtherFence v1.0.0 is
  production-ready for controlled local-first deployments of its defined
  scope (scan, mcp-policy, and the stdio mcp-proxy boundary) with a stable
  CLI and policy schema, while making clear this is not a universal
  certification for every MCP server, MCP client, or deployment
  environment — operators must still test their chosen MCP servers and
  policies and monitor audit logs
- README's checked-in example-policy count corrected from ten to twelve
  (it had drifted out of date since v0.9.0 added
  `examples/policies/mcp-memory-notes-readonly.toml`)
- Version bumped to 1.0.0

### Not in scope

- No new runtime enforcement semantics (no failing test surfaced a
  correctness bug requiring one)
- No `ef-mcp-policy/v0.1` schema changes
- No daemon, API service, control plane, endpoint agent, shell hooks,
  terminal-command scanning, network/TLS interception, DLP/content
  inspection, marketplace action, PR bot, package publishing, or auto-update
- Not a universal certification: EtherFence does not protect MCP servers
  that are not wrapped by `mcp-proxy`, does not support HTTP/SSE MCP
  transport, does not intercept network/TLS traffic, and does not perform
  DLP/content inspection or certify any specific third-party MCP server
- All prior release behavior (v0.9.0 compatibility evidence, v0.8.0
  install/release docs, v0.7.0 CI examples, v0.6.x policy UX/test
  hardening, v0.5.0 smoke tests, v0.4.x path/Unicode hardening) preserved
  unchanged
- No git tag created or pushed for this release

## [0.9.0] - 2026-07-10

### Added

- Fixture-backed compatibility tests for more realistic MCP protocol shapes,
  still against the checked-in fake MCP server fixture and with no proxy
  enforcement behavior changes:
  - a richer `tools/list` response with a nested `inputSchema` (nested
    object property, an array-of-strings property, and a `required` list),
    proving the filtered response preserves an allowed tool's schema
    structure unchanged, not just its name
  - realistic `resources/list` entries (`uri`/`name`/`mimeType`) and a
    `resources/read` `contents` array shape (`uri`/`mimeType`/`text`)
  - `completion/complete` denied by method policy (in addition to the
    existing `prompts/get` and `sampling/createMessage` denial coverage)
- New example policy `examples/policies/mcp-memory-notes-readonly.toml` for
  a memory/notes-style (knowledge-graph or notes store) MCP server, using
  the existing global-deny-plus-server-scoped-allow shape
- `docs/mcp-compatibility-matrix.md` adds a "Realistic MCP server categories"
  status table (filesystem-style, GitHub/API-style, memory/notes-style,
  resources/read-capable, and server→client feature servers), each pointing
  at a recommended starting policy and stating plainly that no real-server
  row exists yet for that category
- `docs/mcp-real-server-test-template.md` documents choosing a starting
  policy by server category before running the optional, env-var-gated
  real-server smoke test
- Version bumped to 0.9.0

### Not in scope

- No `ef-mcp-policy/v0.1` schema changes and no MCP proxy runtime
  enforcement behavior changes
- No daemon, API service, control plane, endpoint agent, shell hooks,
  terminal-command scanning, network/TLS interception, DLP/content
  inspection, marketplace action, PR bot, or package publishing
- No real third-party MCP server is started by default in CI; the optional
  real-server smoke test remains skipped unless a maintainer sets
  `ETHERFENCE_REAL_MCP_CMD`
- This release is compatibility evidence for the tested flows and
  categories above; it is **not** production-readiness certification for
  any real-world MCP server
- All prior release behavior (v0.8.0 install/release docs, v0.7.0 CI
  examples, v0.6.x policy UX, v0.5.0 smoke tests, v0.4.x path/Unicode
  hardening) is preserved unchanged
- No git tag created or pushed for this release

## [0.8.0] - 2026-07-10

### Added

- New `docs/install.md`: Linux and Windows release-artifact install flows,
  a build-from-source flow, a local `cargo install --path
  crates/etherfence-cli --bin etherfence` flow, `etherfence --version`
  verification, a first-scan walkthrough, a release artifact table, SHA-256
  checksum verification steps for Linux (`sha256sum -c`) and Windows
  (`Get-FileHash`), and a Linux/Windows release-artifact smoke-test
  checklist covering `--version`, `scan`, `policy list`, `mcp-policy
  init/validate/check`, and an optional `mcp-proxy` fail-closed check.
- SHA-256 checksum generation in the manual release workflow
  (`.github/workflows/release.yml`): the Linux job now produces
  `etherfence-linux-x86_64.tar.gz.sha256` (via `sha256sum`) and the Windows
  job now produces `etherfence-windows-x86_64.zip.sha256` (via
  `Get-FileHash`), both uploaded as build artifacts and attached to the
  GitHub release alongside the existing two archives. Release creation
  remains manual, explicit, and `workflow_dispatch`-only; no change to which
  ref can be released, tag/release validation, or `fail-fast` behavior.
- New CLI integration tests
  (`crates/etherfence-cli/tests/install_docs.rs`) so `docs/install.md` and
  the README's install/quickstart sections cannot silently drift: every
  referenced doc/example path exists, `mcp-policy init --profile minimal`
  followed by `validate` and `check` (with the exact inline JSON request
  shown in the docs) succeeds end to end, `cargo install --path
  crates/etherfence-cli --bin etherfence` is documented with the
  fake-mcp-server-exclusion flag, README command snippets use real `clap`
  subcommands, and `--version` output matches the current workspace
  version.

### Changed

- Version bumped to 0.8.0.
- README.md restructured for readability: one-line positioning, a pre-v1
  status callout, "what it does" / "what it does not do", a quickstart
  (install → first scan → validate an MCP policy → dry-run a decision →
  optionally wrap a server with `mcp-proxy`), an install/build section
  pointing at `docs/install.md`, a command-overview table, then focused
  `scan`/`mcp-policy`/`mcp-proxy` examples, the existing CI/team workflow
  summary, a documentation-links table, security model/non-goals, and
  development/verification, ending with license. No command behavior,
  schema, or enforcement content changed — only structure, tables, and
  prose.
- `docs/release-automation.md` documents the two new `.sha256` checksum
  artifacts and links to the new verification steps in `docs/install.md`.
- `docs/release-checklist.md` documents generating the same checksum files
  locally for the manual fallback release path and attaching all four
  files (two archives, two checksums) to a manually created GitHub release.
- `docs/roadmap.md` records v0.8.0 as a packaging/install/README-polish
  release.

### Notes

- No production `mcp-proxy` enforcement behavior changes and no
  `ef-mcp-policy/v0.1` schema changes.
- No daemon, API service, control plane, endpoint agent, shell hooks,
  terminal-command scanning, network/TLS interception, DLP/content
  inspection, marketplace GitHub Action, PR bot, package-registry
  publishing, installer/MSI, or auto-update system added.
- Release creation stays fully manual and explicit
  (`gh workflow run release.yml --ref main -f version=<x.y.z>`); the only
  change to `.github/workflows/release.yml` is generating and attaching
  SHA-256 checksum files for the two existing artifacts.
- Existing `scan`, `policy`, `mcp-proxy`, and `mcp-policy` behavior; v0.7.0
  CI/team workflow examples; v0.6.1 subprocess test hardening; v0.6.0
  `mcp-policy` validate/explain/init/check; v0.5.0 compatibility smoke
  tests; and v0.4.1 Unicode hardening/v0.4.0 path guards are all preserved
  unchanged.
- No git tag created or pushed for this release.

## [0.7.0] - 2026-07-10

### Added

- `docs/ci.md`: a full walkthrough of CI/team workflow integration —
  failing a PR on findings with `scan --fail-on`, failing only on new
  findings with `scan --baseline`/`--fail-on-new`, generating and uploading
  a SARIF report, validating MCP proxy policies in CI with `mcp-policy
  validate`, dry-run-checking MCP policy decisions in CI with `mcp-policy
  check` without starting an MCP server, avoiding secrets in checked-in
  baselines/policies, and a restatement that EtherFence is local-first and
  pre-v1.
- New checked example CI input files under `docs/examples/ci/`:
  `scan-policy.toml` (scan-only posture policy), `mcp-policy.toml` (MCP
  proxy policy), `baseline.json` (baseline generated from
  `tests/fixtures/home`), and `requests/` (JSON-RPC request fixtures for
  `mcp-policy check` covering an allowed tool call, a denied tool, and a
  denied path).
- New checked example GitHub Actions workflows under
  `docs/examples/workflows/` (documentation, not active repository
  workflows): `scan-gate.yml`, `scan-baseline.yml`,
  `scan-sarif-upload.yml`, `mcp-policy-gate.yml`, and
  `pr-security-gate.yml` (a combined gate composing the other four).
- New README "CI and team workflow integration" section pointing at
  `docs/ci.md` and the example files/workflows above.
- New tests (`crates/etherfence-cli/tests/ci_examples.rs`) so the CI docs
  and examples cannot silently drift: example policies parse; example
  JSON-RPC requests are valid JSON; `mcp-policy check` against the example
  requests produces the documented allow/deny decisions; the checked-in
  example baseline exactly matches a freshly regenerated baseline from
  `tests/fixtures/home`; every example workflow file parses as YAML; and
  every file/command path referenced by the example workflows and
  `docs/ci.md` exists in the repository.

### Notes

- No production `mcp-proxy` enforcement behavior changes and no
  `ef-mcp-policy/v0.1` schema changes.
- No daemon, API service, control plane, endpoint agent, shell hooks,
  terminal-command scanning, network/TLS interception, DLP/content
  inspection, marketplace GitHub Action, central dashboard, remote policy
  service, automatic PR-commenting bot, or arbitrary MCP tool execution
  added.
- Existing `scan`, `policy`, `mcp-proxy`, and `mcp-policy` behavior; v0.6.1
  subprocess test hardening; v0.6.0 `mcp-policy` validate/explain/init/check;
  v0.5.0 compatibility smoke tests; and v0.4.1 Unicode hardening/v0.4.0 path
  guards are all preserved unchanged.
- No git tag created or pushed for this release.

## [0.6.1] - 2026-07-10

### Fixed

- Hardened the previously flaky `cli_mcp_proxy` integration test
  `proxy_denies_server_to_client_sampling_before_client_and_answers_server`.
  The test helper closed the client's stdin after a fixed
  `Duration::from_millis(50)` wait, guessing at how long the proxy needed to
  receive a server→client `sampling/createMessage` request, deny it by
  policy, and write the denial back onto the fake server's stdin before the
  client EOF path closed that same pipe. Under slow child-process startup
  (notably Windows-toolchain `cargo` against a WSL-mounted filesystem), the
  guess could be wrong and the denial write would lose the race, dropping it
  silently and failing the test's assertions on the fake server's receive
  log. The helper now polls the fake server's receive log for the denial
  marker (bounded by a 10-second timeout that fails the test with a clear
  message instead of hanging) and only closes the client's stdin once the
  marker is observed, which proves the race window has already passed. This
  is test-only: MCP proxy policy semantics, JSON-RPC behavior, and audit
  behavior are unchanged.

## [0.6.0] - 2026-07-10

### Added

- New `etherfence mcp-policy` command group: local, serverless MCP policy UX
  that reuses the existing `ef-mcp-policy/v0.1` parser and proxy decision
  functions.
  - `etherfence mcp-policy validate <policy.toml>` parses and validates a
    policy, printing a clear success message or the existing parser's
    actionable error (unsupported schema version, empty name, empty
    `allow_roots`, malformed TOML, suspicious Unicode, etc.).
  - `etherfence mcp-policy explain <policy.toml>` prints a deterministic
    human-readable summary: policy name, schema version, global and
    per-server method/tool allow/deny lists, path rules, guarded tool/method
    keys, the always-on Unicode-hardening and audit-redaction posture, and a
    warnings section for risky or confusing policy shapes (wildcard method
    allow, no `[methods]` section anywhere, no tool allowed anywhere, unused
    path rules, guards referencing an undefined path rule, broad
    `allow_roots` such as `/` or a drive root, and empty `deny_roots`).
  - `etherfence mcp-policy init --profile <name> [--output <file>]
    [--overwrite]` generates a starter policy from one of five built-in
    profiles: `minimal`, `strict-method-only`,
    `filesystem-project-readonly`, `filesystem-project-readonly-hardened`,
    and `resources-project-only`. Prints to stdout by default; refuses to
    overwrite an existing `--output` file unless `--overwrite` is passed.
  - `etherfence mcp-policy check --policy <policy.toml> --request <json>
    [--server-name <name>] [--direction client-to-server|server-to-client]`
    dry-runs one JSON-RPC request/notification through the exact same
    `inspect_client_line`/`inspect_server_line` functions the live proxy
    uses. Reports the method decision, the tool decision for `tools/call`,
    the path decision when a guard applies, the reason/category, and whether
    the request would be forwarded. JSON-RPC batch input is reported as
    denied fail-closed. Never starts or contacts an MCP server, never
    executes a tool, and never writes an audit log; never prints raw
    argument/param values, full paths, or URIs.
- New `etherfence-mcp::policy_ux` module: `explain_policy`/`PolicyExplanation`
  and `dry_run_check`/`CheckOutcome`, small reusable helpers built on the
  existing policy parser and proxy decision functions, with unit test
  coverage for warnings and dry-run outcomes.
- `docs/mcp-policy-ux.md` documents `validate`/`explain`/`init`/`check`, the
  warning semantics, and explicit non-goals (no daemon, no network access, no
  tool execution).
- CLI integration tests (`crates/etherfence-cli/tests/cli_mcp_policy.rs`)
  covering: validation success across all example and generated policies,
  clear validation failures for unsupported schema, malformed TOML, empty
  `allow_roots`, and suspicious Unicode; `explain` warning coverage; `init`
  success for every profile and safe overwrite protection; and `check`
  allow/deny outcomes for tool calls, blocked resource URIs, suspicious
  Unicode, and fail-closed batches.

### Notes

- Schema unchanged: `ef-mcp-policy/v0.1`.
- No changes to `scan`, `policy`, or `mcp-proxy` runtime behavior; v0.5.0
  compatibility/smoke tests, v0.4.1 Unicode hardening, v0.4.0 path-aware
  policy, and v0.3.1 bidirectional method policy/tools-list
  filtering/audit-redaction/batch fail-closed behavior are all preserved.
- No daemon, API service, control plane, endpoint agent, shell hooks,
  terminal-command scanning, network/TLS interception, DLP/content
  inspection, or arbitrary MCP tool execution added.
- No git tag created or pushed for this release.

## [0.5.0] - 2026-07-10

### Added

- Fixture-backed compatibility smoke tests for the experimental MCP stdio
  proxy covering `resources/list` allow and deny by method policy, in
  addition to the existing `initialize`, `tools/list`, `tools/call`
  allow/deny, `resources/read` allow/deny, server→client
  sampling/roots/elicitation policy behavior, and malformed/batch
  fail-closed coverage.
- Optional `ETHERFENCE_REAL_MCP_POLICY` environment variable for the
  maintainer-run real-server smoke test (`optional_real_mcp_stdio_smoke_test`),
  letting a specific policy file be exercised against a real stdio MCP server
  instead of the built-in compatibility policy. Only read, never modified or
  deleted by the test. Remains skipped by default in CI; only
  `ETHERFENCE_REAL_MCP_CMD` gates whether the test runs at all.
- New example policies:
  - `examples/policies/mcp-filesystem-project-readonly-hardened.toml`: the
    existing project-root read-only policy with `deny_roots` expanded to
    cover common credential-like paths (`.env`, `.env.local`, `.ssh`, `.aws`,
    `.npmrc`, `.netrc`, `.pypirc`, `credentials`, `id_rsa`) in addition to
    `.git` and `secrets`.
  - `examples/policies/mcp-strict-method-only.toml`: an explicit `[methods]`
    allow/deny list restricted to `tools/list` and `tools/call`, as an
    auditable alternative to relying on the built-in method-policy default.
- Validation tests confirming the new example policies parse and behave as
  documented (credential-like paths denied, non-tool methods denied).
- `## What is tested` / `## What remains untested` sections in
  `docs/mcp-compatibility-matrix.md` stating explicitly which MCP stdio flows
  are covered by the deterministic fixture-backed CI tests, which are not
  (other transports, real third-party servers, specific client applications,
  internationalized method/tool names, performance/concurrency), and that
  passing these tests is not production-readiness certification.

### Changed

- Version bumped to 0.5.0.
- `docs/mcp-compatibility-matrix.md`, `docs/mcp-real-server-test-template.md`,
  `docs/mcp-clients.md`, `docs/mcp-proxy.md`, and `README.md` updated to
  describe the new smoke tests, new example policies, and
  `ETHERFENCE_REAL_MCP_POLICY`, and to state explicitly that compatibility
  evidence from fixture-backed or optional real-server tests is not
  production-readiness certification.

### Security notes

- No proxy enforcement, policy schema, or audit behavior changed in this
  release. All v0.4.1 Unicode/homograph hardening, v0.4.0 path-aware policy,
  v0.3.1 bidirectional method policy, v0.3.0 method-level policy, `tools/list`
  filtering, request tracking, audit redaction, and fail-closed batch
  behavior are preserved unchanged and continue to be exercised by regression
  tests.
- No raw paths, URIs, prompt text, message bodies, file/resource contents,
  secrets, tokens, full params, argument values, or Unicode-suspicious key
  names are logged by the new tests or example policies.
- No daemon, API service, control plane, endpoint agent, shell hooks,
  terminal-command scanning, network interception, TLS interception, cloud
  dependency, DLP, content inspection, or broad URL filtering was added.
  Arbitrary MCP tool execution was not added.

### Compatibility notes

- Policy schema remains `ef-mcp-policy/v0.1`. Existing valid policies parse
  and behave unchanged; the new example policies use the same schema and
  mechanisms (`path_rules`/`deny_roots`, `[methods]` allow/deny) documented
  since v0.4.0/v0.3.0.
- `docs/mcp-compatibility-matrix.md` now documents explicitly what is tested
  and what remains untested for this release. Compatibility evidence from the
  checked-in fake MCP server fixture or from an optional maintainer-run
  real-server smoke test is not production-readiness certification and does
  not extend to server behavior, tool/resource names, or flows not
  exercised.

### Migration / compatibility

- No schema or runtime behavior changes. Existing policies, CI pipelines, and
  client configurations continue to work unchanged.

## [0.4.1] - 2026-07-09

### Added

- Unicode/homograph hardening for the experimental MCP stdio proxy. Suspicious
  Unicode is rejected during policy parsing or denied at runtime before it can
  confuse exact policy matching, audit review, or operator interpretation.
- Safe Unicode reason categories: `unicode_bidi_control_detected`,
  `unicode_zero_width_detected`, `unicode_non_ascii_method`,
  `unicode_non_ascii_tool`, and `unicode_suspicious_path_value`.

### Changed

- Version bumped to 0.4.1.
- MCP proxy policy parsing now rejects policy names, server scopes, path-rule
  names, tool guard keys, method guard keys, path keys, and referenced path-rule
  names containing bidi controls, zero-width/invisible format characters, or
  non-ASCII identifier text. Method allow/deny entries must be ASCII.
- Runtime method checks deny client→server and server→client method names that
  contain non-ASCII, bidi, or zero-width characters before normal method-policy
  matching.
- Runtime `tools/call` checks deny tool names that contain non-ASCII, bidi, or
  zero-width characters before normal tool-policy matching.
- Configured path guards deny guarded path/URI values containing bidi or
  zero-width characters before lexical path normalization/root comparison.

### Security notes

- Existing v0.4.0 path-aware policy behavior, v0.3.1 bidirectional method
  policy, `tools/call` policy, `tools/list` filtering, audit redaction, and
  fail-closed batch behavior are preserved.
- Audit and JSON-RPC denial diagnostics use safe Unicode reason categories and
  redacted placeholders for Unicode-denied method/tool names and suspicious
  audit-visible argument/param key names. Raw paths, URIs, prompt text, message
  bodies, resource/file contents, secrets, tokens, full params, and
  argument/param values are still not logged.
- EtherFence does not fold Unicode confusables into equivalent ASCII strings,
  does not implement locale-specific path equivalence, and does not add broad
  DLP, content inspection, URL filtering, network interception, a daemon, an API
  service, a control plane, shell hooks, terminal-command scanning, endpoint
  agents, or cloud dependencies.

### Migration / compatibility

- Policy schema remains `ef-mcp-policy/v0.1`. Existing valid ASCII policies
  parse and behave unchanged.
- Policies or runtime messages that previously used non-ASCII MCP method/tool
  names or non-ASCII policy identifiers are now rejected/denied by design. This
  release intentionally does not support internationalized MCP method or tool
  names.

## [0.4.0] - 2026-07-09

### Added

- Local path-aware MCP argument/resource policy in `etherfence mcp-proxy` for
  configured `tools/call` argument keys and `resources/read` URI params.
- Optional `[path_rules.<name>]` sections under `ef-mcp-policy/v0.1` with
  explicit `allow_roots` and `deny_roots`; deny roots take precedence over
  allow roots.
- Optional per-tool guards such as `[tools."filesystem.read".arguments]` with
  `path_keys`, and per-method guards such as
  `[methods."resources/read".params]` with `uri_keys`.
- Redacted path audit metadata: `path_rule`, `path_key`, and
  `path_classification` values such as `inside_allowed_root`,
  `outside_allowed_roots`, `inside_denied_root`, and `path_parse_error`.
- Example policies `mcp-filesystem-project-readonly.toml` and
  `mcp-resources-project-only.toml`.

### Changed

- Version bumped to 0.4.0.
- Requests with configured path-like keys are denied before forwarding when the
  value is malformed, missing, non-string, relative, outside allowed roots,
  under denied roots, or a guarded non-`file://` URI.
- `file://` resource URIs are converted to local paths and lexically normalized
  before root comparison. The proxy does not resolve symlinks or inspect file
  contents.

### Security notes

- Existing v0.3.1 bidirectional method policy, `tools/call` allow/deny policy,
  tracked `tools/list` response filtering, fail-closed batch behavior, and
  audit redaction are preserved.
- Audit continues to omit full paths, URIs, prompt text, message bodies,
  resource/file contents, secrets, tokens, argument values, and full params.
- v0.4.0 remains local-first and stdio-only. It does not add a server/control
  plane, daemon, API service, network interception, shell hooks,
  terminal-command scanning, endpoint agent, cloud dependency, generic policy
  language, content inspection, or DLP engine.

### Migration / compatibility

- Policy schema remains `ef-mcp-policy/v0.1`; existing v0.3.1 policies without
  path guards parse and behave as before.
- Default deny for paths applies only when an operator explicitly configures a
  path guard for that exact tool or method key.

## [0.3.1] - 2026-07-09

### Added

- Server→client MCP/JSON-RPC request inspection in `etherfence mcp-proxy` for
  server-initiated client-feature methods such as `sampling/createMessage`,
  `roots/list`, and `elicitation/create`. A server output object with a
  `method` field is now checked before forwarding to the client.
- Direction metadata on audit records (`client_to_server` or
  `server_to_client`) so method decisions and fail-closed batch denials clearly
  identify which side initiated the message.
- Tests covering allowed and denied server→client methods, denied
  `sampling/createMessage` not reaching the client, JSON-RPC denial responses
  sent back toward the server for id-bearing requests, notification drops,
  audit redaction for params and complex ids, preserved client→server behavior,
  preserved `tools/list` filtering, and server→client batch fail-closed
  behavior.

### Changed

- Denied server→client requests are not forwarded to the client. If the denied
  message has a non-null `id`, the proxy writes a safe JSON-RPC error response
  back toward the MCP server; denied notifications without an `id` are dropped
  and audited.
- `mcp-sampling-denied.toml` now documents that `sampling/createMessage` is
  blocked in either direction by v0.3.1 server→client method enforcement.
- Version bumped to 0.3.1. Existing client→server method policy, `tools/call`
  policy, tracked `tools/list` response filtering, audit redaction, and
  fail-closed posture are preserved.

### Security notes

- Server→client method checks reuse the existing exact-match `[methods]` policy
  model and keep schema `ef-mcp-policy/v0.1`; no regex, prefix, glob, daemon
  mode, API server, network interception, shell hooks, terminal-command
  scanning, or endpoint-agent behavior was added.
- Audit continues to log only safe metadata: method name, direction, decision,
  reason, request id type, and top-level param key names. Prompt text, message
  bodies, resource/file contents, secrets, tokens, and full params are not
  logged.
- Server→client JSON-RPC batch arrays are denied wholesale (fail closed) rather
  than unpacked.

### Migration / compatibility

- Policy schema remains `ef-mcp-policy/v0.1`; no policy file migration is
  required. Deployments that want to allow server-initiated client-feature
  methods must list those exact method names in `[methods].allow` or use the
  existing `"*"` wildcard intentionally.
- Client→server v0.3.0 behavior is unchanged. The new behavior only closes the
  previously documented server→client method-policy gap in the stdio proxy.

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
