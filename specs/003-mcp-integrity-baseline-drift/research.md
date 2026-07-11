# Phase 0 Research: MCP Server Integrity Baseline and Drift Detection

## Decision 1: Crate placement

**Decision**: All new pure data models and comparison logic live in a single
new module, `crates/etherfence-setup/src/baseline.rs`, mirroring the
existing `trust.rs`/`classification.rs` pattern exactly (pure functions over
already-computed `SetupDetection`/`SetupServer` values, re-exported from
`lib.rs`). All CLI argument parsing, file I/O (read/write/overwrite-guard),
and human/JSON rendering lives in `crates/etherfence-cli/src/main.rs`,
following the exact structure of the existing `setup detect`/`setup
catalog` wiring (`SetupCommand` variant → `run_setup_command` match arm →
`render_*` functions).

**Rationale**: Matches the architecture constraint in the goal prompt
exactly and the precedent set by v1.2.0 (`catalog.rs`) and v1.3.0
(`trust.rs`) — no new crate, no duplicated discovery engine.

**Alternatives considered**: A new `etherfence-baseline` crate was
considered and rejected — the comparison logic is a thin, single-purpose
layer over existing `etherfence-setup` types with no independent reuse
need, so a new crate would only add a dependency-graph node without value
(constitution Principle X, Scope Discipline).

## Decision 2: Zero changes to `trust.rs`/`classification.rs`

**Decision**: `baseline.rs` reuses `etherfence_setup::detect()` (which
already calls `classify_server`/`recommend`/`assess_trust` internally) as
its only integration point. No function signature in `trust.rs` or
`classification.rs` is changed. Sorting helpers needed only for baseline
comparison (e.g. a stable ordering over `CapabilityLabel`) are implemented
locally in `baseline.rs` using the already-`pub` `CapabilityLabel::ALL`
array, rather than exposing a new `pub(crate)` helper from
`classification.rs`.

**Rationale**: The spec requires reusing v1.3.0 discovery/trust/hashing
"exactly as-is" and preserving every file-safety invariant without risking
a regression to already-shipped, fixture-tested code. Keeping this
feature's footprint to purely additive new files minimizes regression risk
to a degree beyond what v1.3.0 itself achieved (v1.3.0 needed one
visibility-only change in `etherfence-mcp`; this feature needs none).

**Alternatives considered**: Adding a `pub(crate) fn canonical_index` export
from `classification.rs` was considered; rejected because the 3-line
lookup is trivial to reimplement locally and avoids widening
`classification.rs`'s public/crate-visible surface for a single
comparison-only concern.

## Decision 3: Identity fingerprint algorithm

**Decision**: `fingerprint(agent_display_name, config_source, server_name)
-> String` is `SHA-256` hex of the three inputs joined with the ASCII
`\u{0001}` (SOH) control character as a field separator:
`format!("{agent}\u{1}{config_source}\u{1}{server_name}")`.
`agent_display_name` reuses the string `SetupDetection.agent` already
carries (itself `AgentKind::display_name()`, which is unique per variant);
`config_source` reuses the string `SetupDetection.config_path` already
carries (itself `etherfence_inventory`'s existing root-relative,
`~/`-prefixed, separator-normalized convention).

Transport is deliberately **not** one of the fingerprint's inputs, despite
the goal prompt naming it as one of four — this was corrected during
implementation after a fixture test (`check_detects_transport_changed`)
demonstrated the original 4-input design made `transport-changed`
unreachable: `server_name` is already a unique JSON object key within one
`config_source` (a JSON object cannot have two keys with the same name),
and `config_source`+agent are unique per discovered config file, so
`(agent, config_source, server_name)` alone is already collision-free for
every entry the discovery engine can produce. Folding transport into the
hash as well means a server's transport flipping (stdio -> remote) changes
the fingerprint itself, which the comparison engine can only see as the
old fingerprint going `missing` and a new fingerprint appearing as `new` —
never as a single `changed` entry with `transport-changed` in its reasons.
Transport is instead carried as a normal field on the identified entry and
compared directly by `drift_reasons_for_pair`, exactly like `command`/
`args`/every other mutable attribute.

**Rationale**: A control character that can never appear in any of the
three inputs (display names, normalized paths, and server names are all
printable-text conventions) makes simple concatenation collision-safe
without needing a length-prefixed encoding. Reusing the two fields already
produced deterministically by existing code (`AgentKind::display_name()`,
inventory's `config_path`) avoids inventing a second identity convention.

**Alternatives considered**: Hashing a JSON-serialized tuple was considered
and rejected as needless complexity — a JSON encoder's own escaping already
prevents ambiguity, but pulls in a serialization round-trip for a value
that is immediately re-hashed, for no safety benefit over a control-
character join.

## Decision 4: Command/argument fingerprints (safety boundary)

**Decision**: `command_fingerprint: Option<String>` = `SHA-256` hex of the
raw `command` string; `arguments_fingerprint: Option<String>` = `SHA-256`
hex of `args` joined with the same `\u{1}` separator. Both are `None`
exactly when invocation is not applicable (remote/URL-configured servers —
mirroring `TrustAssessment::invocation.applicable == false`), and always
`Some` (even hashing an empty argument list to a fixed, well-defined
digest) when a `command` is present.

**Rationale**: This is the mechanism that satisfies FR-024/FR-025 — the
baseline can detect that a command or argument list changed (hash
differs) without ever persisting the raw, possibly secret-bearing text.

**Alternatives considered**: Persisting a truncated/redacted command string
was rejected — any truncation heuristic risks leaking a secret-bearing
prefix/suffix, and offers no comparison benefit a hash doesn't already
provide.

## Decision 5: Reusing trust-assessment fields directly

**Decision**: Package identity/version, executable path classification,
SHA-256 digest, artifact identity confidence, configuration risk status,
and aggregate status are copied verbatim from the already-computed
`SetupServer.trust_assessment`/`.recommendation`/`.capabilities` — no
re-derivation, no re-parsing.

**Rationale**: Directly satisfies "reuse v1.3.0 discovery, trust, and
hashing logic" (goal prompt) and guarantees the baseline can never disagree
with what `setup detect` itself would report for the same input.

## Decision 6: Trust-indicator and capability comparison granularity

**Decision**: Baseline persists trust indicators as a sorted-by-`id`
`Vec<IndicatorSummary { id, category, severity }>` (no `summary`/
`rationale`/`evidence`/`remediation` text — those are human-facing
narrative fields, not needed for set-equality drift detection, and
`evidence` values, while already redacted in v1.3.0, are excluded here on
the "only what's needed" safety-boundary principle). Capability labels are
persisted as a sorted `Vec<CapabilityLabel>` (dedup + sorted using
`CapabilityLabel::ALL` position order). `trust-indicator-set-changed`
fires when the sorted `id` sets differ; `capability-set-changed` fires
when the sorted label sets differ.

**Rationale**: FR-017/FR-018 require set-based (not order-based)
comparison; persisting only IDs/categories/severities (never narrative
text) is the minimum needed for deterministic drift detection while
staying inside the FR-024 safe-field allowlist.

## Decision 7: Risk ordering and rank function

**Decision**: `pub fn risk_rank(status: AggregateAssessmentStatus) -> u8`
lives in `baseline.rs` (not `trust.rs`, to avoid touching that module) and
implements the fixed total order from spec FR-021: `VerifiedLocal(0) <
KnownSource(1) < Unknown(2) < NeedsReview(3) < HighRisk(4)`.
`risk-increased` fires when `risk_rank(current.aggregate) >
risk_rank(baseline.aggregate)` for a server present in both.

**Rationale**: Reuses the existing 5-value enum instead of introducing a
second, parallel severity scale — directly satisfies the goal's "do not
introduce ... unnecessary crate"/economy-of-mechanism framing and
constitution Principle X.

**Alternatives considered**: Deriving risk purely from
`ConfigurationRiskStatus` (ignoring artifact identity) was considered;
rejected because it would make "risk increase" invisible for a server
whose executable identity degrades from `verified-local` to `unknown`
while configuration risk indicators stay empty — exactly the kind of
integrity drift this feature exists to catch.

## Decision 8: Status precedence (`changed` vs `unverifiable`)

**Decision**: A server present (by fingerprint) in both baseline and
current is `unverifiable` if `executable-became-unverifiable` fired
(baseline `artifact_identity == VerifiedLocal`, current `sha256 == None`)
and every *other* reason present, if any, is limited to
`artifact-identity-changed` and/or `risk-increased`. Any reason outside
that set demotes the status to `changed` (still carrying every reason that
fired, including `executable-became-unverifiable`).

**Revised during implementation**: the first version of this rule required
the reason set to contain *only* `executable-became-unverifiable` — no
exceptions. A fixture test
(`hash_verified_executable_replaced_by_symlink_is_unverifiable`, later
renamed) proved this was too strict: `artifact-identity-changed` is not an
independent finding here, it is a **necessary mechanical consequence** of
the same fact `executable-became-unverifiable` reports (once a
`verified-local` hash is gone, `derive_artifact_identity` has nowhere else
to fall back to for a direct, non-package-runner executable, so it always
becomes `Unknown`) — and `risk-increased` is likewise just the aggregate
rank reflecting that same drop. Excluding both from the "any other reason"
check is what makes `unverifiable` reachable at all for the single most
common case (a directly-launched executable with no npx/uvx/pipx package
identity to fall back to as `known-source`). The test suite separately
proved a *genuinely* independent co-occurring reason still correctly
demotes to `changed`: swapping the file for a symlink (instead of merely
revoking read permission) changes `executablePath` from `absolute-path` to
`symlink`, which raises a new, distinct `EF-TRUST-PATH-003` indicator not
present in the baseline — `trust-indicator-set-changed` then fires
alongside, correctly yielding `changed` rather than `unverifiable`. The
final fixture for the clean `unverifiable` case uses `chmod 000` (Unix
permission revocation) instead of a symlink swap for exactly this reason:
`classify_executable_path` only calls `symlink_metadata`/`stat`, which
succeeds regardless of read permission, so the path classification (and
therefore every `EF-TRUST-PATH-*` indicator) is unaffected — only the
actual `open()` inside hashing fails, isolating the "lost verification"
signal from any other observable change.

**Rationale**: Gives operators a distinct, higher-signal status for "we
lost the ability to verify what we previously verified" without losing any
information — every reason that fired still appears in the `reasons`
array regardless of which status it produces.

## Decision 9: Comparison output ordering

**Decision**: `ComparisonEntry` (and `BaselineServerEntry`) lists are
sorted by the tuple `(agent_display_name, config_source, server_name,
transport_token)` — never by the fingerprint hash (which is
intentionally opaque/high-entropy and would produce an unreadable,
effectively-random report order) and never by HashMap iteration order.

**Rationale**: Directly satisfies FR-040 (deterministic output) while
keeping human output readable (grouped by agent/config file, matching
`setup detect`'s existing presentation order).

## Decision 10: Baseline/comparison file I/O

**Decision**: `write` reuses `read_bounded_text_file`'s size-bound sibling
constant `MAX_BASELINE_FILE_BYTES` (already defined in `etherfence-core`,
already used by the pre-existing `scan --baseline` feature) for reading a
baseline in `check`, and a plain `fs::write` (mirroring the existing `scan
--write-baseline`'s `write_baseline()` implementation exactly) for
`write`'s output — no atomic-rename machinery is needed since `write`
already gates on a pre-existence check before ever opening the output path
for writing, and a partially-written baseline is only possible on a
mid-write crash, an existing accepted risk in the `scan --write-baseline`
precedent this feature intentionally mirrors.

**Rationale**: Reuses an existing, already-reviewed constant and I/O
pattern rather than inventing a new one; keeps `write`'s implementation
symmetric with the pre-existing, unrelated `scan --write-baseline` for
consistency of expectations across the codebase.

## Decision 11: Schema versions

**Decision**: `ef-setup-baseline/v0.1` for the file `write` produces;
`ef-setup-baseline-comparison/v0.1` for `check --format json`'s output.
Both are new, additive schema families — no existing schema version
changes.

**Rationale**: Directly specified by the goal prompt; follows constitution
Principle VI (explicit versioning per externally-consumed schema).
