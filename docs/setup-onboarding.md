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
and `ef-setup-detect/v0.2` schemas.

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

## `etherfence setup detect` trust and integrity assessment (v1.3.0)

`etherfence setup detect` (both `--format human` and `--format json`)
additionally reports a static, local-only, deterministic **trust and
integrity assessment** for every discovered MCP server, alongside its
v1.2.0 capability classification and starter-policy recommendation. It is
read-only, offline, and starts no process, opens no network connection,
and invokes no MCP protocol method to produce it — exactly the same
posture as v1.2.0's classification. See
[`docs/json-schema.md`](json-schema.md) for the full `ef-setup-detect/v0.2`
field reference.

**What this feature never claims.** The trust-and-integrity assessment never proves a server is safe, trusted, certified, malware-free, benign, or definitively malicious. It is not a malware scanner, a behavioral security
sandbox, an endpoint protection product, a package authenticity or
software-signature verifier, a package-registry reputation service, a
universal typosquatting detector, a universal Unicode confusable detector,
or a universal MCP server certification system. It is not a guarantee that
no malicious behavior exists, and it is not a replacement for manual review
or for `mcp-proxy`'s runtime least-privilege policy.

**Vocabulary and what each value actually means:**

- `artifactIdentity: verified-local` means only that a specific local
  regular file was inspected and SHA-256 hashed under bounded,
  TOCTOU-safe conditions — it does not mean the program is safe.
- `artifactIdentity: known-source` means only an exact match against a
  small curated identity table — it does not prove package
  authenticity, provenance, installation integrity, or safety.
- `configurationRisk: no-known-indicators` means only that no implemented
  v1.3.0 indicator triggered for that server — it does not prove the
  absence of malicious behavior.
- `aggregate` combines the two axes above by a fixed,
  configuration-risk-first rule: a raised configuration-risk indicator is
  never hidden by a favorable artifact identity, and a favorable artifact
  identity still surfaces to the aggregate whenever no configuration-risk
  indicator fired. Both underlying fields are always reported separately,
  regardless of which one determined the aggregate value.

**What it assesses, statically, from already-parsed local configuration:**

- Package-runner invocation pinning for `npx`, `uvx`, and `pipx run` —
  whether the resolved package version is exactly pinned, omitted, a
  mutable tag, a version range, or unsupported/ambiguous. No package
  registry is ever contacted, and no package is ever installed or
  executed.
- Shell-wrapper invocation (`sh -c`, `bash -c`, `cmd.exe /c`,
  `powershell -Command`/`-EncodedCommand`, `pwsh -Command`/
  `-EncodedCommand`) and a fixed, closed set of obscured/download-and-
  execute launch patterns, detected by bounded structural string
  matching — never a general shell parser, and the wrapped command is
  never executed or decoded.
- Executable-path classification (absolute path, relative path,
  bare/PATH-resolved command, missing path, non-regular file, symlink,
  temporary-directory location, or ambiguous/unsupported). A relative
  path, a PATH-resolved command, or a symlink is never silently promoted
  to a verified local artifact — `PATH` is never searched, and symlinks
  are never followed.
- Local artifact hashing for an eligible absolute regular-file path only:
  a bounded, streamed SHA-256 read that refuses to follow a symlink at
  open time (enforced by the kernel on Unix; the opened handle's own
  metadata is additionally checked on every platform) and cross-checks
  filesystem file identity — not just length and modified time, which a
  substituted file can coincidentally match — before, immediately after
  opening, and after the read completes, discarding the hash on any
  mismatch. File contents never appear in any output.
- A narrow set of Unicode/identity-ambiguity indicators (bidirectional
  control characters, invisible/zero-width characters, a defined
  mixed-script condition, and a single curated confusable-identity alias)
  — not a universal confusable or typosquatting detector.
- Environment-variable **names only** (dynamic loader injection,
  interpreter/runtime path override, package-registry override,
  TLS-verification-disabling, and secret-like names). Environment
  variable *values* are never emitted, logged, or included in any
  evidence, in this feature or anywhere else in EtherFence — this feature
  only ever sees the same redacted `<set>`/`<empty>` value hint the
  existing inventory layer has produced since v0.1.x.

**Policy relationship.** `recommendation.tier` remains `"deny"` for every
server regardless of the trust-and-integrity assessment; this feature
introduces no path to an `"allow"` recommendation. A favorable assessment
may be described as indicating a server is ready for manual review, but it
never grants, enables, or implies runtime permission. Existing `mcp-proxy` enforcement behavior, `tools/list` filtering, `tools/call` enforcement, method policy, path policy, and audit behavior are not changed by this feature. The MCP proxy policy schema is not touched either.

## `etherfence setup baseline write` / `check` — integrity baseline and drift detection (v1.4.0)

`etherfence setup baseline write --root <path> --output <file>
[--overwrite]` captures a deterministic, point-in-time snapshot of every
discovered MCP server (schema `ef-setup-baseline/v0.1`). `etherfence setup
baseline check --root <path> --baseline <file> [--format human|json]
[--fail-on-drift] [--fail-on-new] [--fail-on-risk-increase]` compares
current state against that snapshot and reports drift (schema
`ef-setup-baseline-comparison/v0.1`). Both commands reuse v1.3.0's
discovery, capability classification, and trust assessment exactly as-is —
no new discovery, classification, or hashing engine.

**What this feature never does.** `check` is strictly read-only against the
`--baseline` file: it never auto-updates, auto-accepts, or silently
rewrites it under any circumstance, including when drift is found and
including when a gate flag causes a non-zero exit. It also refuses to
follow a symlink at `--baseline` (fails closed rather than silently
comparing against whatever the link happens to point at) and validates a
parsed baseline's internal consistency before ever comparing against it
(see "Safety hardening" below). `write` refuses to overwrite an existing
`--output` file unless `--overwrite` is explicitly passed, using an atomic
exclusive-creation file operation rather than a separate check-then-write
(so a file that appears at that path concurrently can never be silently
overwritten, and a pre-existing symlink there is refused rather than
written through); with `--overwrite`, the new content is written to a temp
file and atomically renamed into place. Neither command starts a process,
opens a network connection, performs a registry/reputation lookup,
downloads or installs anything, verifies a cryptographic signature, or
changes `mcp-proxy` runtime behavior in any way.

**What is persisted or emitted — and what never is.** A baseline entry or
comparison-report entry contains only: a normalized identity fingerprint
(agent, config source, server name — see below) plus transport;
command/argument *fingerprints* (SHA-256 hashes, never the raw command or
argument text); parsed package identity and version-expression
classification; executable path classification and its SHA-256 digest
when available; environment variable **names only**; capability labels;
trust-indicator IDs/categories/severities; and the v1.3.0 trust/risk
vocabulary (`artifactIdentity`/`configurationRisk`/`aggregate`). It never
persists or emits raw environment variable values, secrets, credentials,
file contents, prompts/messages, MCP protocol traffic, or unredacted
command/argument text — the same redaction posture as v1.3.0's trust
assessment.

**Server identity.** A server's identity fingerprint is derived from a
*stable machine identifier* for its agent (e.g. `"vs-code"`), its
normalized config-source path, and its server name — never the
human-facing display name (e.g. `"VS Code"`, which is persisted separately
purely for readability and could be reworded in a future release without
that being a security-relevant change) and never raw command text. The
three inputs are combined via a canonical, structurally unambiguous
encoding before hashing, not a delimiter-joined string, since none of them
is guaranteed to exclude any particular character. Transport is
deliberately *not* part of the fingerprint: it is tracked as an ordinary
comparable field instead, so a server switching between a local command
and a remote URL is reported as `changed` with a `transport-changed`
reason rather than as one server disappearing and an unrelated one
appearing.

**Statuses and drift reasons.** Every server is classified as one of
`unchanged`, `new`, `changed`, `missing`, or `unverifiable`, with a closed,
deterministic set of drift reasons (executable hash, command, arguments,
package identity, package version, environment-variable name set,
transport, server added/removed, capability set, trust-indicator set,
artifact identity, configuration risk, a documented risk increase, or the
executable becoming newly unverifiable). `unverifiable` is reported when a
previously hash-verified executable can no longer be safely hashed (and
nothing independent of that fact also changed) — distinct from a generic
`changed` status, so an operator can immediately tell "we lost the ability
to verify this" apart from "something else about this server changed."

**Safety hardening.** Before ever comparing against a parsed baseline,
`check` validates that it is internally consistent — every entry's
fingerprint matches a fresh recomputation from its own identity fields, no
two entries share a fingerprint, every `sha256` value is well-formed hex,
every sorted/set-like field is actually sorted and deduplicated, and each
entry's aggregate status is consistent with its own artifact-identity and
configuration-risk fields. A hand-edited or corrupted baseline fails
closed (a clear error, no comparison performed) instead of silently
producing a misleading report.

**Risk ordering and gates.** The five trust-assessment aggregate values
have a fixed severity order (`verified-local` < `known-source` < `unknown`
< `needs-review` < `high-risk`). A risk *decrease* is still reported as
drift (never silently hidden) but never satisfies `--fail-on-risk-increase`
by itself — only a documented increase along that order does.
`--fail-on-drift` fails on any non-`unchanged` status; `--fail-on-new`
fails only on `new`; `--fail-on-risk-increase` fails only on a documented
increase. Any combination of gates may be passed together, and the full
report is always printed before the process exits, whether or not a gate
triggers.

**Relationship to the pre-existing `scan --write-baseline`/`--baseline`.**
That feature (findings baseline, schema `ef-baseline/v0.1.3`) is unrelated
and unaffected: it tracks `scan`'s security findings, not MCP server
integrity, and lives under a completely separate flag namespace and schema
family.

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
