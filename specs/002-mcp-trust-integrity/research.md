# Phase 0 Research: MCP Server Trust and Integrity Assessment

Each entry resolves one required planning decision from the feature brief. Format: Decision / Rationale / Alternatives considered.

## 1. Integration point with `setup detect`

**Decision**: Extend `SetupServer` (in `crates/etherfence-setup/src/lib.rs`) with one new additive field, `trust_assessment: TrustAssessment`, computed inside `server_from_mcp()` alongside the existing `classify_server()`/`recommend()` calls — same function, same additive-field pattern used for `capabilities`/`recommendation` in v1.2.0.

**Rationale**: `server_from_mcp()` already receives the full `&McpServer` (command, args, env, url) needed by every assessment area. Following the exact v1.2.0 precedent means `setup plan`/`setup doctor` (which construct `SetupServer` the same way but read only pre-existing fields) remain byte-identical, satisfying FR-004 with zero extra wiring.

**Alternatives considered**: A separate `setup detect --trust` sub-flag or new command — rejected; the spec's Primary User Outcome explicitly requires the assessment to appear inside plain `etherfence setup detect` output, and a second flag would fragment the FR-020/SC-002 determinism guarantee across two code paths.

## 2. New data types (minimal set)

**Decision**: Nine new enums/structs, all in `crates/etherfence-setup`, following the `CapabilityLabel`-style `kebab-case` `Serialize` + `human_label()` split precedent:

- `ArtifactIdentityConfidence` (3 variants), `ConfigurationRiskStatus` (3), `AggregateAssessmentStatus` (5) — the three vocabulary enums from FR-058–FR-060.
- `PackageRunner` (3: Npx, Uvx, PipxRun), `VersionExpressionKind` (5: ExactlyPinned, Omitted, MutableTag, VersionRange, UnsupportedOrAmbiguous), `ShellWrapperKind` (7, one per FR-021 form), `ObscuredLaunchPattern` (5 — see Decision 4 below), `ExecutablePathClassification` (8, one per FR-030 form plus `NotApplicable`).
- `InvocationAssessment` (struct): `applicable: bool`, `runner: Option<PackageRunner>`, `package_identity: Option<String>`, `version_expression: Option<VersionExpressionKind>`, `malformed_runner_invocation: bool`, `shell_wrapper: Option<ShellWrapperKind>`, `obscured_launch_patterns: Vec<ObscuredLaunchPattern>`.
- `TrustIndicator` (struct): `id: &'static str`, `severity: etherfence_core::Severity` (**reused**, not reinvented — see Decision 3), `category: IndicatorCategory` (new, 7 variants, one per assessment area), `summary: String`, `rationale: String`, `evidence: Vec<EvidenceField>`, `remediation: String`.
- `EvidenceField` (struct): `key: EvidenceKey` (new enum: Runner, PackageIdentity, VersionExpression, WrapperType, ObscuredLaunchPattern, OptionName, PathClassification, EnvironmentVariableName, UnicodeCategory, CuratedRuleId), `value: String`.
- `TrustAssessment` (struct, the field added to `SetupServer`): `artifact_identity`, `configuration_risk`, `aggregate`, `needs_review: bool`, `invocation: InvocationAssessment`, `executable_path: ExecutablePathClassification`, `sha256: Option<String>`, `indicators: Vec<TrustIndicator>`.

**Rationale — why not more**: `LocalArtifactRecord` as a separate struct was considered and rejected — a bare `sha256: Option<String>` on `TrustAssessment`, present only when `artifact_identity == VerifiedLocal`, carries the same information with one fewer type (Decision 7 explains the *why* of that `Option` semantics). `IndicatorSeverity` was considered and rejected in favor of reusing `etherfence_core::Severity` (already `Info`/`Low`/`Medium`/`High`, already kebab-case-serialized) — inventing a parallel severity scale would violate "avoid inventing more than necessary" for no behavioral gain.

**Alternatives considered**: A single large enum-of-enums "Indicator" tagged union instead of `EvidenceField{key,value}` — rejected as harder to keep JSON-stable across future evidence-key additions; the flat key/value shape mirrors the existing audit-log `argument_keys: Vec<String>` redaction precedent in `etherfence-mcp`.

## 3. Severity reuse

**Decision**: `TrustIndicator.severity` reuses `etherfence_core::Severity` (`Info`/`Low`/`Medium`/`High`) unchanged.

**Rationale**: Already exists, already deterministic, already kebab-case-serialized, already used for scan findings — introducing a second severity scale for trust indicators would create two incompatible severity vocabularies in the same tool with no requirement driving that split.

## 4. Package-runner version-expression parsing boundaries

**Decision**: Extend (not replace) the existing `launcher_name()`/`resolve_package_arg()` helpers in `classification.rs` with a new, runner-specific version-splitting step, applied only after the existing exact-match capability rules run:

- **npx**: split the resolved package argument on the *last* `@` when the argument does not start with `@` (scoped packages start with `@scope/name`, so a scoped package's own leading `@` is never treated as the version separator — split on the *second* `@` for scoped names, the *first* `@` for unscoped names). `ExactlyPinned` = a single fully-resolved version token (digits/dots, optional pre-release suffix) with no range operator and not in the curated mutable-tag list (`latest`, `next`, `beta`, `alpha`, `canary`, `rc` — closed, exact-match). `Omitted` = no `@version` suffix at all. `MutableTag` = suffix is an exact curated tag match. `VersionRange` = suffix contains a range operator (`^`, `~`, `>=`, `<=`, `>`, `<`, `x`/`*` wildcard, or a comma-separated set). `UnsupportedOrAmbiguous` = any other non-empty suffix shape.
- **uvx / pipx run**: split on PEP 440-style specifier operators. `ExactlyPinned` = `==<version>` with a single fully-resolved version token. `VersionRange` = any other specifier operator (`>=`, `<=`, `~=`, `!=`, `>`, `<`) or an `--from name==version` form parsed the same way. `Omitted` = bare package name, no specifier. `MutableTag` is not reachable for these two runners (PyPI has no dist-tag convention analogous to npm) — this is a documented, intentional asymmetry, not a gap.
- **Malformed runner invocation** (FR-019): the recognized runner name matches, but the resolved package argument cannot be split into a package-identity token at all (empty, or shaped as an unrecognized flag not in the existing `LAUNCHER_BOOLEAN_FLAGS`/`LAUNCHER_VALUE_FLAGS` tables) — reported as its own indicator, never silently folded into `Unknown`/`Omitted`.

**Rationale**: Reuses the v1.2.0 exact-match, closed-world parsing philosophy (Decision 6 of the historical `research.md`) instead of introducing a general version-range parser; every classification is a bounded string-shape check, matching FR-020's "no registry access, no resolution" requirement.

## 5. Shell-wrapper and obscured-launch structural detection boundaries

**Decision**: Wrapper detection is a two-step exact match: (1) `launcher_name(command)` against the closed set `{sh, bash, cmd, cmd.exe, powershell, powershell.exe, pwsh, pwsh.exe}` (reusing the existing `/`/`\`-splitting, `.exe`/`.cmd`-stripping `launcher_name()` helper unchanged); (2) the first matching argument against the closed set `{-c, /c, -Command, -EncodedCommand}` (case-sensitive exact match — no abbreviation matching, e.g. PowerShell's `-Comm` is intentionally not recognized, keeping detection closed-world per FR-021/FR-023).

Obscured-launch detection operates only on the *literal argument string* passed to a recognized `-c`/`-Command` wrapper (never on unwrapped direct commands), using bounded substring/prefix checks, never a shell tokenizer:

- **`PipeToShellDownloader`** (implements both FR-026 "obvious pipe-to-shell composition" *and* FR-028(a)): the wrapped string contains a `|`, and the tokens immediately before the last `|` start with `curl` or `wget`, and the token immediately after the last `|` matches a recognized shell name (`sh`, `bash`, `zsh`).
- **`EncodedPowerShellOption`** (FR-027/FR-028 original 2): the wrapper itself is `-EncodedCommand` (already detected as part of Decision 5's step 2 — this indicator is a second, obscured-launch-categorized indicator carrying the same evidence, not a re-detection).
- **`WindowsCertutilDownloadPattern`** (FR-028b): `launcher_name(command) == "certutil"` and any argument exactly equals or starts with `-urlcache` (closed, single-flag match).
- **`PowerShellWebRequestToInvokeExpression`** (FR-028c): the wrapper is a recognized PowerShell/`pwsh` `-Command` form, and the wrapped string contains one of `Invoke-WebRequest`/`iwr`/`Invoke-RestMethod`/`irm` followed later in the same string by one of `Invoke-Expression`/`iex`.
- **`DecodeThenExecutePipedToShell`** (FR-028d): the wrapped string contains a `|`, the tokens before the last `|` start with `base64 -d`, `base64 --decode`, or `certutil -decode`, and the token after the last `|` matches a recognized shell name.

**5 distinct `ObscuredLaunchPattern` variants ship in v1.3.0**, not 6: FR-026's generic "obvious pipe-to-shell composition" and FR-028(a)'s curl/wget-specific rule are implemented as the *same* rule (`PipeToShellDownloader`), because Clarification Q2 explicitly rejected a broader, curl/wget-agnostic "any command piped into any shell" rule (Option C) as drifting toward the forbidden general shell parser. Implementing FR-026 more broadly than FR-028(a) would silently reintroduce the rejected option; implementing it identically satisfies both FRs with one auditable rule.

**Rationale**: Every rule is a bounded token/substring match over an already-tokenized argument list (never a full shell grammar), matching FR-023/FR-029's "no general shell parser" boundary.

## 6. Safe structured evidence shape

**Decision**: `EvidenceField { key: EvidenceKey, value: String }`, always populated from a small, closed set of safe tokens: a runner name, a package identity string (not a full command line), a version-expression classification token, a wrapper-type token, an obscured-launch-pattern token, a recognized option name (`-EncodedCommand`, never the encoded payload), a path classification token, a normalized environment-variable name, a Unicode-category token, or a curated-rule identifier. Full command strings, file contents, and environment values are never assigned to any `EvidenceField.value`.

**Rationale**: Directly implements FR-065/FR-066; reuses the same "structured key names only, never raw payloads" philosophy already used by `etherfence-mcp`'s audit log (`argument_keys: Vec<String>`, never argument values).

## 7. Artifact identity vs. configuration-risk aggregation

**Decision** (already resolved in spec.md FR-061/FR-062; restated here as the adopted design): a pure function `fn aggregate(artifact: ArtifactIdentityConfidence, risk: ConfigurationRiskStatus) -> AggregateAssessmentStatus` implementing the configuration-risk-first precedence, and `fn needs_review(aggregate: AggregateAssessmentStatus) -> bool` returning `true` for `NeedsReview`/`HighRisk`/`Unknown` and `false` for `VerifiedLocal`/`KnownSource` — mirroring the existing `recommend()` pure-function precedent in `classification.rs` exactly (same file organization pattern: one pure function per derivation step, table-driven tests over the full input cross-product).

## 8. Eligible local-file hashing behavior

**Decision**: A path is hashing-eligible only when its `ExecutablePathClassification` is a direct absolute path (Unix or Windows-drive form) that, at the moment of inspection, `fs::metadata` confirms is a regular file. `RelativePath`, `PathResolvedCommand` (bare command name), `Symlink`, `NonRegularFile`, and `MissingPath` are never eligible — PATH resolution and symlink dereferencing are never performed to find something to hash (FR-031, FR-034, FR-043). A path additionally classified `TemporaryDirectoryLocation` (an additive flag per FR-035, not a replacement classification) remains hashing-eligible if it is otherwise an eligible absolute regular-file path — the temp-directory location is reported as its own risk indicator alongside a successful hash, not a hashing disqualifier.

## 9. Bounded binary reads and size limit

**Decision**: Hashing streams the file through `sha2::Sha256` in fixed-size chunks (e.g. via `std::io::copy` into the hasher) rather than buffering the whole file, so memory use is O(chunk-size) regardless of file size. A new explicit constant, `MAX_EXECUTABLE_HASH_BYTES = 200 MiB`, bounds the *read itself* (via the same `Read::take(MAX_EXECUTABLE_HASH_BYTES + 1)` "read one byte past the limit, then reject if it was reached" technique already used by `etherfence_core::read_bounded_text_file`) — this bounds worst-case time/I/O against a pathological or special-file target, not memory, since the read is streamed rather than buffered. A file whose read exceeds the limit is reported hashing-ineligible (`needs-review`/`unknown`), never partially hashed.

**Rationale for 200 MiB (vs. the existing 5 MiB config-file / 25 MiB baseline-file limits)**: executables are a fundamentally different size class than structured text config — common legitimate MCP server binaries (bundled Node/Python interpreters, statically linked Rust/Go binaries) commonly range from a few MB to100+ MB; 200 MiB comfortably covers realistic cases while still bounding worst-case pathological input, consistent with the existing "generous but bounded, not unlimited" pattern the config/baseline limits already establish.

**Metadata/TOCTOU handling**: capture `fs::metadata` (file length + modified time) immediately before opening the file, stream-hash while reading, then re-capture `fs::metadata` immediately after the read completes. Any mismatch in length or modified time between the two snapshots discards the computed hash and degrades that server's artifact identity to `needs-review`/`unknown` rather than `verified-local` (FR-042). This extends — it does not replace — the existing `read_bounded_text_file` "check `is_file()` via `fs::metadata` before `File::open`, never trust `stat`-reported length alone" pattern, adding the post-read re-check that config-file reads don't need (a config file's exact byte content isn't asserted as an identity claim; a hash is).

## 10. Symlink, relative-path, PATH-command, missing-file, metadata-change behavior

**Decision**: All five are distinct, mutually exclusive `ExecutablePathClassification` outcomes (Decision 8 covers eligibility; this covers *classification*, which always happens regardless of eligibility):

- **Symlink**: detected via `fs::symlink_metadata` (never followed) *before* any regular-file check; a path that is a symlink is classified `Symlink` and is never hashed, regardless of what it points to (conservative, per spec Assumptions — no default dereferencing).
- **Relative path**: a configured path containing a path separator that is not absolute (Unix: doesn't start with `/`; Windows: doesn't start with a drive letter or UNC prefix) → `RelativePath`.
- **Bare/PATH-resolved command**: no path separator at all → `PathResolvedCommand`; `PATH` is never searched to resolve it.
- **Missing path**: an absolute path that `fs::symlink_metadata` reports does not exist → `MissingPath`.
- **Metadata change during inspection**: not a distinct `ExecutablePathClassification` value (the path classification itself doesn't change mid-read) — instead it degrades only the hashing *outcome* per Decision 9, leaving the path classification (e.g. `AbsolutePath`) intact but `sha256` absent and `artifact_identity = Unknown`.

## 11. Narrow Unicode handling — reuse `etherfence-mcp::unicode`

**Decision**: `etherfence-setup` already depends on `etherfence-mcp` (confirmed: `crates/etherfence-setup/Cargo.toml` already lists `etherfence-mcp = { path = "../etherfence-mcp" }`, used today for `etherfence_mcp::parse_mcp_policy` in `generated_policy_template`). `crates/etherfence-mcp/src/lib.rs` currently declares `mod unicode;` (private) with no `pub use` of its functions. The plan is a **one-line additive visibility change**: `mod unicode;` → `pub mod unicode;` in `etherfence-mcp/src/lib.rs`, with no change to `unicode.rs`'s logic. This makes `etherfence_mcp::unicode::inspect_policy_identifier` and `inspect_path_value` directly callable from the new trust-assessment code for bidi-control and invisible/zero-width detection (FR-046, FR-047), with zero logic duplication and zero new dependency edges.

Mixed-script detection (FR-048) and curated confusable-alias matching (FR-049) are **new** logic (not present in `etherfence-mcp::unicode` today) and live in `etherfence-setup`'s new trust module: mixed-script is defined narrowly as "the identity string contains characters from more than one of a small fixed script set (Latin, Cyrillic, Greek) after excluding ASCII digits/punctuation" — not a general Unicode script-detection library; confusable-alias matching is a small, checked-in exact-match table (see Decision 14).

**Alternatives considered**: Duplicating `inspect_policy_identifier`/`inspect_path_value` logic directly inside `etherfence-setup` — rejected; it would violate the "reuse existing utilities" instruction for no benefit, since the dependency already exists and the only blocker is a private module.

## 12. Environment-variable name-only assessment

**Decision**: Implemented entirely inside the new `etherfence-setup` trust module using small, closed, curated name-pattern lists per category (dynamic loader injection: `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH`; interpreter/runtime path override: `PYTHONPATH`, `NODE_PATH`, `NODE_OPTIONS`, `PATH` when configured as a server-specific override; package-registry override: `NPM_CONFIG_REGISTRY`, `PIP_INDEX_URL`, `PIP_EXTRA_INDEX_URL`, `UV_INDEX_URL`; TLS-verification-disabling: `NODE_TLS_REJECT_UNAUTHORIZED`, `PYTHONHTTPSVERIFY`, `GIT_SSL_NO_VERIFY`, `NPM_CONFIG_STRICT_SSL`; secret-like: a small suffix/substring pattern list (`_TOKEN`, `_SECRET`, `_KEY`, `_PASSWORD`, `_CREDENTIAL`, case-insensitive) — conceptually the same shape as `etherfence-policy`'s existing private `secret_looking_name()` heuristic, but **implemented independently inside `etherfence-setup`**, not called cross-crate.

**Rationale for not reusing `etherfence-policy::secret_looking_name` directly**: that function is private (`fn`, not `pub fn`) and `etherfence-policy` is not currently a dependency of `etherfence-setup`. Promoting it to `pub` and adding a new cross-crate dependency edge for one string-matching helper is a larger, less-contained change than re-stating the same small closed pattern list locally — and this feature's own constitution-driven design already requires every category's exact pattern list to be independently fixture-tested regardless of where the code lives, so there is no fixture-coverage cost to keeping it local. If a future release wants a single shared secret-name-pattern utility, that consolidation can happen then, deliberately, as its own change.

## 13. Deterministic indicator ordering

**Decision**: `IndicatorCategory::ALL` defines one fixed canonical order (mirroring `CapabilityLabel::ALL`): `ObscuredLaunch`, `ShellWrapper`, `PackagePinning`, `ExecutablePath`, `LocalArtifact`, `UnicodeIdentity`, `EnvironmentVariable` (most-actionable/most-restrictive-first, matching the existing `CapabilityLabel` ordering philosophy). Indicators for one server sort by `(category canonical index, indicator ID string)` — a total, deterministic order regardless of the order the underlying rules matched in.

## 14. Curated known-source identities and confusable aliases shipped in v1.3.0

**Decision**: The `known-source` curated identity table for v1.3.0 reuses exactly the three package identities already curated in v1.2.0's `EVIDENCE_RULES` (`@modelcontextprotocol/server-filesystem`, `@modelcontextprotocol/server-devops`, `web-search-mcp`) — no new identities are added; classification-level curation (capability labels) and trust-level curation (known-source identity) intentionally share the same small seed table rather than growing two independent curated lists in the same release. Exactly **one** curated confusable-alias fixture ships in v1.3.0 (a single homoglyph/digit-substitution variant of `@modelcontextprotocol/server-filesystem`, finalized during implementation) — enough to prove the mechanism end-to-end with a real fixture and test per Constitution Principle V/XI, while explicitly deferring a broader alias table (see Deferred Work in plan.md) rather than asserting coverage EtherFence hasn't earned.

## 15. `ef-setup-detect/v0.2` schema evolution

**Decision**: Bump `etherfenceSchemaVersion` from `ef-setup-detect/v0.1` to `ef-setup-detect/v0.2`. Every existing `v0.1` field (`agent`, `configPath`, `writeSupport`, `servers[].name/transport/wrapped/capabilities/recommendation`, `notes`) is unchanged in name, type, and meaning. One new field is added per server: `trustAssessment` (camelCase object, matching the existing `capabilities`/`recommendation` casing convention). Null-vs-omitted: `trustAssessment.sha256` is **omitted** (via `skip_serializing_if = "Option::is_none"`, matching the existing `EnvVar.value_hint`/`CatalogEntry` precedent) whenever no verified hash exists — never emitted as JSON `null`. `trustAssessment.indicators` is **always present**, `[]` when empty (matching `capabilities.labels`'s "never omitted" precedent, not `capabilities.evidence`'s "omit when empty" precedent, because the indicator list is a primary result, not supplementary detail per FR-068). `invocation`'s `Option` fields (`runner`, `packageIdentity`, `versionExpression`) are omitted, not null, when `applicable: false` or when that particular sub-check didn't apply (e.g. no runner detected on a directly-launched executable).

## 16. Fixture and documentation strategy

Covered directly in `plan.md`'s Fixture Strategy and Documentation Updates sections (kept here only as a pointer to avoid duplicating a large table across two files).
