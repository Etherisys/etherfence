# Feature Specification: MCP Server Integrity Baseline and Drift Detection

**Feature Branch**: `spec/v1.4.0-mcp-integrity-baseline-drift`

**Created**: 2026-07-11

**Status**: Draft

**Input**: User description: "EtherFence v1.4.0: MCP Server Integrity Baseline and Drift Detection — build on v1.3.0's static MCP server trust-and-integrity assessment by letting operators write a deterministic point-in-time baseline of discovered MCP servers and later compare current state against that baseline to detect drift. New `etherfence setup baseline write`/`check` subcommands, closed drift-reason enum, collision-safe server identity fingerprint, safe-only persisted fields, reused v1.3.0 discovery/trust/hashing logic, monotonic risk ordering, and gate flags for CI use."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Capture a point-in-time integrity baseline (Priority: P1)

An operator who has reviewed their current MCP server configuration wants to
record its exact state — which servers exist, how they're launched, their
package/executable identity, and their v1.3.0 trust assessment — so that any
future change can be detected automatically instead of relying on manual
re-review.

**Why this priority**: Without a baseline there is nothing to compare against;
this is the foundational capability every other story depends on.

**Independent Test**: Run `etherfence setup baseline write --root <path>
--output <file>` against a fixture home directory and confirm a baseline file
is created containing one entry per discovered MCP server, with deterministic
field ordering and no secret-bearing values.

**Acceptance Scenarios**:

1. **Given** a root directory with MCP servers configured across multiple
   clients, **When** the operator runs `setup baseline write --root <path>
   --output <file>`, **Then** a baseline file is written containing a
   normalized, deterministically ordered entry for every discovered server.
2. **Given** an output path that already exists, **When** the operator runs
   `setup baseline write` without `--overwrite`, **Then** the command refuses
   to run and the existing file is left untouched.
3. **Given** an output path that already exists, **When** the operator runs
   `setup baseline write --overwrite`, **Then** the file is replaced with a
   freshly computed baseline.
4. **Given** the same root directory scanned twice with no changes in
   between, **When** the operator writes a baseline both times, **Then** the
   two output files are byte-identical.

---

### User Story 2 - Detect drift against a saved baseline (Priority: P1)

An operator who previously wrote a baseline wants to periodically re-check
their live configuration against it — for example before a release, on a
schedule, or in CI — and get a clear, per-server report of anything that is
new, changed, removed, or newly impossible to verify, without the tool ever
silently accepting the drift or rewriting the baseline itself.

**Why this priority**: Detecting drift is the entire value proposition of
this feature; without it the baseline file is inert data.

**Independent Test**: Modify a fixture MCP server's command after writing a
baseline against it, then run `etherfence setup baseline check --root <path>
--baseline <file>` and confirm the server is reported as `changed` with a
`command-changed` drift reason, while the baseline file itself is unmodified
on disk.

**Acceptance Scenarios**:

1. **Given** a baseline written against a root with no subsequent changes,
   **When** the operator runs `setup baseline check`, **Then** every server
   is reported `unchanged` and the process exits zero.
2. **Given** a baseline, **When** a new MCP server is added to the root that
   was not present at baseline time, **Then** `check` reports it as `new`.
3. **Given** a baseline, **When** a previously present server's config is
   removed entirely, **Then** `check` reports it as `missing`.
4. **Given** a baseline, **When** a previously present server's launch
   command, arguments, package identity/version, environment variable names,
   transport, capability labels, trust indicators, or artifact identity
   change, **Then** `check` reports it as `changed` with the specific closed
   drift reason(s) that fired.
5. **Given** a baseline recording a locally hashed (`verified-local`)
   executable, **When** that same executable can no longer be safely hashed
   (permission denied, replaced by a symlink, disappeared, or exceeds the
   hashing bound) and no other tracked field differs, **Then** `check`
   reports it as `unverifiable`.
6. **Given** any `check` invocation, **Then** the baseline file on disk is
   byte-identical before and after the run.

---

### User Story 3 - Gate automation on drift severity (Priority: P1)

A CI pipeline or pre-release check wants to fail a build when specific kinds
of drift occur — any drift at all, only brand-new servers, or only a
documented increase in risk — while still always seeing the full report, so
a failing gate is never a silent failure with no explanation.

**Why this priority**: This is what makes the feature usable as an automated
guardrail rather than a manual-only report; it is a P1 alongside the other
two because the whole feature is aimed at CI/operator gating use.

**Independent Test**: Run `check` with `--fail-on-new` against a baseline
missing one currently-configured server and confirm the process exits
non-zero while still printing the full report to stdout.

**Acceptance Scenarios**:

1. **Given** at least one server with a non-`unchanged` status, **When**
   `check --fail-on-drift` runs, **Then** the process exits non-zero and the
   full report is still printed.
2. **Given** no non-`unchanged` servers except a `new` one, **When** `check
   --fail-on-new` runs, **Then** the process exits non-zero; running without
   `--fail-on-new` (and without `--fail-on-drift`) against the same input
   exits zero.
3. **Given** a server whose aggregate risk status increased along the
   defined monotonic ordering since the baseline, **When** `check
   --fail-on-risk-increase` runs, **Then** the process exits non-zero.
4. **Given** a server whose aggregate risk status *decreased* since the
   baseline (and nothing else changed), **When** `check
   --fail-on-risk-increase` runs, **Then** the process exits zero on that
   basis alone — the decrease is still reported as `changed` drift, just not
   as a risk-increase gate failure.
5. **Given** no gate flags are passed, **When** `check` finds drift,
   **Then** the process exits zero and the report is informational only.

---

### Edge Cases

- Two distinct servers that happen to share a display name (different
  agents, different config files, or different transports) MUST be
  distinguished by their identity fingerprint and never merged or reported
  as the same server drifting.
- A baseline file that fails to parse, fails its schema-version check, or
  fails size bounds MUST cause `check` to fail closed (non-zero exit, no
  partial report) rather than treating it as an empty baseline.
- Re-ordering keys or servers within a config file (no semantic change)
  MUST NOT produce any drift.
- A server present in the baseline whose *environment variable name set*
  is identical but reordered MUST NOT be reported as drift (set comparison,
  not order comparison).
- A server that was `unknown` artifact identity in the baseline and remains
  `unknown` now, but for a *different* underlying reason (e.g. a different
  unhashable path shape), is still `unchanged` for artifact identity — only
  a value change in the recorded fields drives drift, not the narrative
  rationale text.
- Running `check` against a baseline written by a version whose schema the
  current binary does not support MUST fail closed with a clear error.
- Running `check` with a baseline path that is a directory, a symlink, or
  non-regular file MUST fail closed using the same bounded-file-read
  invariants as every other EtherFence config read.

## Requirements *(mandatory)*

### Functional Requirements

**Baseline write**

- **FR-001**: System MUST provide `etherfence setup baseline write --root
  <path> --output <file> [--overwrite]`, which runs the same read-only
  discovery (`etherfence-inventory::discover`) used by `setup detect`
  against `<path>` and writes a normalized baseline document to `<file>`.
- **FR-002**: `write` MUST refuse to run (non-zero exit, no file written or
  modified) when `<file>` already exists and `--overwrite` is not passed.
- **FR-003**: `write` MUST NOT modify, wrap, back up, or otherwise touch any
  scanned agent config, MCP server, or policy file — it is read-only over
  the scanned root exactly like `setup detect`.
- **FR-004**: Given identical on-disk input, `write` MUST produce
  byte-identical output across repeated runs (stable field order, stable
  server ordering, no timestamps or other non-deterministic content in
  comparable fields).
- **FR-005**: The baseline document MUST declare an explicit schema version
  `ef-setup-baseline/v0.1`.

**Server identity fingerprint**

- **FR-006**: Each baseline entry and each current-state entry MUST carry a
  deterministic identity fingerprint derived from the server's agent kind,
  its normalized config-source identity (the existing `~/...`-normalized
  `config_path` string already produced by `etherfence-inventory::discover`),
  and its server name. Two servers differing in any one of these three
  inputs MUST never produce the same fingerprint. Transport
  (`stdio`/`remote`/`unknown`) is deliberately excluded from the
  fingerprint itself: `server_name` is already a unique JSON object key
  within one `config_source`, and `config_source`+agent are unique per
  discovered config file, so (agent, config_source, server_name) alone is
  already collision-free for every entry the discovery engine can produce —
  folding transport into the fingerprint as well would make a server's
  transport change indistinguishable from that server being removed and a
  different one being added, permanently blocking the closed
  `transport-changed` drift reason (FR-014) from ever being reachable.
  Transport is instead tracked as a normal mutable field on the matched
  identity, compared directly to detect `transport-changed` (FR-014).
- **FR-007**: Server matching between a baseline and current state for the
  purpose of computing status/drift MUST use this fingerprint exclusively —
  never display name alone, and never raw command text alone.
- **FR-008**: The fingerprint algorithm MUST be a pure, versioned function
  with fixture-backed tests proving that varying any one of the three
  inputs changes the fingerprint and that varying none of them (including
  field reordering upstream, or a transport change on an otherwise-identical
  server) does not.

**Comparison statuses and drift reasons**

- **FR-009**: `check` MUST classify every server identity found in the union
  of baseline and current state into exactly one status: `unchanged`,
  `new`, `changed`, `missing`, or `unverifiable`.
- **FR-010**: A fingerprint present only in the current state MUST be
  `new`. A fingerprint present only in the baseline MUST be `missing`.
- **FR-011**: A fingerprint present in both with zero drift reasons detected
  MUST be `unchanged`.
- **FR-012**: A fingerprint present in both where a baseline artifact
  identity of `verified-local` can no longer be safely hashed in the
  current state (open/read failure, path no longer an eligible absolute
  regular file, symlink swap, or size-bound exceeded) MUST be
  `unverifiable`, *provided* every other detected reason is a necessary,
  mechanical side effect of that same fact — specifically
  `artifact-identity-changed` (verified-local's confidence value
  necessarily changes once its hash is gone) and/or `risk-increased` (the
  aggregate rank necessarily reflects the lowered artifact identity). These
  are not independent findings; excluding them from the "any other reason"
  check is what makes `unverifiable` reachable at all for the common case
  of a direct (non-package-runner) executable, whose artifact identity has
  no other source to fall back on. If any *other*, independent drift reason
  is also present (e.g. the path itself became a new symlink, raising its
  own distinct indicator, or the command changed), the status MUST be
  `changed` (not `unverifiable`), carrying every reason that fired.
- **FR-013**: A fingerprint present in both with one or more other drift
  reasons detected MUST be `changed`, listing every drift reason that fired
  (never just the first).
- **FR-014**: The drift-reason enum is closed and MUST contain exactly:
  `executable-hash-changed`, `command-changed`, `arguments-changed`,
  `package-identity-changed`, `package-version-changed`,
  `environment-variable-names-changed`, `transport-changed`,
  `server-added`, `server-removed`, `capability-set-changed`,
  `trust-indicator-set-changed`, `artifact-identity-changed`,
  `risk-increased`, `executable-became-unverifiable`. No other reason may be
  introduced without a schema version bump.
- **FR-015**: A `new` entry's only drift reason MUST be `server-added`; a
  `missing` entry's only drift reason MUST be `server-removed`.
- **FR-016**: Argument-set and environment-variable-name-set comparisons
  MUST be order-independent (compare as sets), while argument *identity*
  (position and value) still participates in the `arguments-changed`
  fingerprint comparison as an ordered sequence — reordering the
  environment block in the source config file MUST NOT itself cause drift.
- **FR-017**: `capability-set-changed` MUST fire when the server's
  classified capability label set (from v1.3.0/v1.2.0 classification)
  differs between baseline and current, compared as a set.
- **FR-018**: `trust-indicator-set-changed` MUST fire when the set of
  trust-indicator IDs raised for the server differs between baseline and
  current, compared as a set of indicator IDs.
- **FR-019**: `artifact-identity-changed` MUST fire when the recorded
  `ArtifactIdentityConfidence` value differs between baseline and current,
  independent of whether the aggregate/risk status also changed.
- **FR-020**: `risk-increased` MUST fire only when the current aggregate
  risk rank (FR-022) is strictly greater than the baseline aggregate risk
  rank for that server; a decrease or no change MUST NOT set this reason.

**Risk ordering**

- **FR-021**: System MUST define a single, total, monotonic ordering over
  the five `AggregateAssessmentStatus` values, from least to most severe:
  `verified-local` < `known-source` < `unknown` < `needs-review` <
  `high-risk`. This ordering is reused directly from the existing v1.3.0
  aggregate vocabulary rather than introducing a second severity scale.
- **FR-022**: Every comparison MUST compute a baseline rank and a current
  rank for each server present in both, using the ordering in FR-021, to
  decide `risk-increased` (FR-020) and to report a human-readable
  risk-direction note (increased/decreased/unchanged) for operator context.
- **FR-023**: A risk *decrease* MUST still be visible in the report (as
  `changed` drift, e.g. via `artifact-identity-changed` and/or a
  configuration-risk field difference) but MUST NOT by itself satisfy
  `--fail-on-risk-increase`.

**Persisted/emitted fields (safety boundary)**

- **FR-024**: A baseline entry and a comparison-report entry MUST only ever
  contain: the identity fingerprint and its four source fields (agent kind,
  normalized config source, server name, transport); a command fingerprint
  (a hash of the command string, never the raw command); an arguments
  fingerprint (a hash of the normalized argument sequence, never raw
  argument values); parsed package identity string and version-expression
  classification (not raw version-range text beyond the closed
  classification); the executable path classification and its SHA-256 hex
  digest when available (never file contents); the sorted set of
  environment variable *names* (never values or value hints); the sorted
  capability label set; the sorted set of trust indicator IDs/categories/
  severities (never the raw command/argument text embedded in an
  indicator's rationale beyond what v1.3.0 already renders as safe,
  structured evidence); artifact identity confidence; configuration risk
  status; aggregate status; and a fixed `review-state` field.
- **FR-025**: System MUST NEVER persist or emit, in either the baseline
  file or `check` output: raw environment variable values or value hints,
  secrets or credentials, full file contents, prompts or chat messages, MCP
  protocol traffic, or raw command/argument text that could carry
  secret-bearing values. Command and argument text is represented only as
  a fingerprint (FR-024).
- **FR-026**: `review-state` MUST be a closed field populated as
  `unreviewed` at write time in v1.4.0; no command in this release provides
  a way to change it (see Non-Goals) — its presence exists solely so a
  future review workflow can extend the schema additively.

**Gate semantics**

- **FR-027**: `--fail-on-drift` MUST cause `check` to exit non-zero if any
  server has status `new`, `changed`, `missing`, or `unverifiable`.
- **FR-028**: `--fail-on-new` MUST cause `check` to exit non-zero if any
  server has status `new`, independent of `--fail-on-drift`.
- **FR-029**: `--fail-on-risk-increase` MUST cause `check` to exit non-zero
  if any server (of status `changed` or `unverifiable`) has `risk-increased`
  in its drift reasons, independent of the other two gates.
- **FR-030**: Any combination of gate flags MAY be passed together; the
  process exits non-zero if *any* passed gate's condition is met.
- **FR-031**: The full report (human or JSON, per `--format`) MUST always be
  rendered in full before the process exits, regardless of whether a gate
  triggers a non-zero exit.

**Read-only / non-mutation guarantees**

- **FR-032**: `check` MUST NOT write, update, rename, or otherwise modify
  the `--baseline` file under any circumstance, including when drift is
  found and including when a gate triggers a failing exit.
- **FR-033**: Neither `write` nor `check` may modify any scanned agent
  config, MCP server definition, policy file, or EtherFence setup backup —
  both commands are read-only over the scanned root, exactly like `setup
  detect`.

**Reuse and safety-invariant preservation**

- **FR-034**: Baseline write and check MUST reuse
  `etherfence_inventory::discover`, v1.3.0's `classify_server`/`recommend`,
  and v1.3.0's `assess_trust` (including its local artifact hashing) as-is
  — no forked or duplicated discovery, classification, or hashing logic.
- **FR-035**: Re-hashing an executable during `check` MUST preserve every
  v1.3.0 file-safety invariant: refuse to follow a symlink at open time,
  re-validate the opened file's identity after the read completes, stream
  the read in bounded chunks capped at the existing size bound, and never
  report a hash for a file that fails any of these checks.
- **FR-036**: A single-byte change to a hashed executable MUST always
  produce a `changed` status with `executable-hash-changed` in its drift
  reasons (assuming no other field also changed, per FR-012's precedence).
- **FR-037**: The existing `ef-setup-detect/v0.2` schema, its command
  (`setup detect`), and every other existing `setup` subcommand (`catalog`,
  `plan`, `apply`, `rollback`, `doctor`) MUST remain unchanged in behavior
  and output.
- **FR-038**: The pre-existing, unrelated findings-baseline feature (`scan
  --write-baseline`/`--baseline`, baseline file schema `ef-baseline/v0.1.3`,
  scan report schema `ef-scan-report/v0.1.1`) MUST continue to work
  unchanged; this feature introduces a separate schema family
  (`ef-setup-baseline/v0.1` and `ef-setup-baseline-comparison/v0.1`) and a
  separate `setup baseline` subcommand namespace, never reusing or
  colliding with the `scan` baseline's file format, flags, or terminology.

**Output format**

- **FR-039**: `check` MUST support `--format human` (default) and `--format
  json`; JSON output MUST declare schema version
  `ef-setup-baseline-comparison/v0.1`.
- **FR-040**: All output ordering (server list, drift-reason list within a
  server, indicator list) MUST be deterministic for a given input, using a
  fixed canonical order (never hash-map iteration order or matched-order).

### Key Entities

- **Baseline Document** (`ef-setup-baseline/v0.1`): schema version, root
  descriptor, and an ordered list of Baseline Server Entries.
- **Baseline Server Entry**: identity fingerprint + source fields, command
  fingerprint, arguments fingerprint, package identity/version
  classification, executable path classification, SHA-256 digest
  (optional), sorted environment variable names, sorted capability labels,
  sorted trust indicator summaries, artifact identity confidence,
  configuration risk status, aggregate status, review state.
- **Comparison Report** (`ef-setup-baseline-comparison/v0.1`): schema
  version, root descriptor, and an ordered list of Comparison Entries.
- **Comparison Entry**: identity fingerprint + source fields, status
  (`unchanged`/`new`/`changed`/`missing`/`unverifiable`), ordered list of
  drift reasons, baseline risk rank and current risk rank (when
  applicable), and a risk-direction note.
- **Drift Reason**: one value from the closed enum in FR-014.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: An operator can capture a baseline and, with zero
  configuration changes, re-run `check` and see 100% of servers reported
  `unchanged` with a zero exit code.
- **SC-002**: A single-character change to any tracked field (command,
  one argument, one environment variable name, executable byte content)
  is detected as drift in 100% of the fixture-covered cases, with the
  correct specific drift reason.
- **SC-003**: Two servers with identical display names but different
  agents, config sources, or transports are never conflated: each is
  independently tracked and reported.
- **SC-004**: Running `check` a hundred times against unchanged input
  never modifies the baseline file (verified by hash comparison of the
  baseline file before/after every run in the test suite).
- **SC-005**: No baseline file or `check` output produced by the test
  fixture suite ever contains a raw environment variable value, a
  fixture "secret-looking" value, or full file contents — verified by an
  automated negative-content test.
- **SC-006**: Each of the three gate flags fails the process in exactly
  the documented cases and only those cases, verified by fixture-backed
  tests covering every status/gate combination.
- **SC-007**: Every documented CLI command, schema, and safety claim in
  README/docs matches the shipped behavior — verified by an automated
  docs-drift test, consistent with this repo's existing pattern.

## Out of Scope

- Any change to `setup detect`'s `ef-setup-detect/v0.2` schema or output.
- Any change to the pre-existing `scan --write-baseline`/`--baseline`
  findings-baseline feature or its `ef-baseline/v0.1.3` schema.
- Any change to `mcp-proxy`, `ef-mcp-policy/v0.1`, or starter-policy
  recommendation logic.
- A new discovery, classification, or hashing engine — this feature is a
  comparison layer over v1.3.0's existing pure functions only.
- An interactive or automatic way to mark drift as reviewed/accepted, or
  to regenerate/update a baseline from `check` itself.

## Explicit Non-Goals

- Malware classification, reputation scoring, or any verdict beyond the
  existing v1.3.0 trust vocabulary.
- Any registry, network, or reputation lookup of any kind.
- Any download or install action.
- Cryptographic signature or provenance verification.
- Sandboxing or subprocess execution of any configured MCP server.
- A daemon, background watcher, or scheduled/triggered automatic
  re-check.
- A control plane, fleet view, or any multi-host aggregation.
- Automatic baseline acceptance, allowlisting, or silent baseline
  mutation of any kind — every baseline change is an explicit, operator-run
  `write --overwrite`.
- Any change to `mcp-proxy` runtime behavior.

## Assumptions

- The four-field identity fingerprint (agent kind, normalized config
  source, server name, transport) is sufficient to disambiguate every
  server this repo's discovery engine can currently produce, since the
  underlying `InventoryItem`/`McpServer` model has no other stable identity
  field; this is documented as a `[NEEDS CLARIFICATION]`-free reasonable
  default because no second server-naming scheme exists anywhere in the
  current codebase to draw from instead.
- `review-state` is included as a forward-compatible, currently-static
  field (always `unreviewed`) rather than an interactive workflow, per the
  explicit non-goal "automatic baseline acceptance" — a future release may
  add an explicit, operator-run acceptance command as its own feature.
- The monotonic risk ordering in FR-021 reuses the existing five-value
  `AggregateAssessmentStatus` enum and its already-established
  configuration-risk-first precedence (v1.3.0 FR-061) rather than
  introducing a second, parallel risk scale — this keeps `--fail-on-risk-
  increase` meaningful without new vocabulary.
- Baseline files are treated as trusted-operator input (an explicit
  `--baseline`/`--output` CLI flag), consistent with this repo's existing
  CLI-trusted-operator-input threat model documented in
  `docs/threat-model.md`; they are still read through the same bounded,
  regular-file-only read helper as every other config file.
