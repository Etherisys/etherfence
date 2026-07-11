# Tasks: MCP Server Trust and Integrity Assessment

**Input**: Design documents from `/specs/002-mcp-trust-integrity/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/setup-detect-trust-assessment.md, quickstart.md (all present)

**Tests**: Included — this repository's constitution (Principle V/XI) requires every curated identity/confusable alias and every structural detection rule to ship with a checked-in fixture and an exact-output test before it may be described as implemented.

**Organization**: Tasks are grouped by user story (spec.md priorities P1/P1/P1/P2/P2) to enable independent implementation and testing of each story.

## Post-implementation review remediation (PR #30)

After all 62 tasks below were completed and PR #30 opened, an external review of the diff found Windows CI failing plus 6 implementation defects. All were fixed in the same PR before merge:

1. **Windows CI failure**: `non_regular_file_is_classified_and_indicated` hardcoded `/tmp` (only a directory on Unix) — rewritten to create a real temporary directory at test time. `eligible_absolute_regular_file_is_hashed_and_verified_local`'s hardcoded SHA-256 assertion mismatched on Windows because the default `core.autocrlf=true` checkout rewrote the checked-in script's LF line endings to CRLF — fixed with a new `.gitattributes` marking that one file `-text`. The checked-in symlink fixture was also replaced with one created at test time (defensive hardening — CI evidence showed it already worked, but it removed a fragile dependency on `core.symlinks` checkout behavior).
2. **Workspace version still 1.2.0**: bumped `Cargo.toml` to `1.3.0`, regenerated `Cargo.lock`, updated the two hardcoded `cli_scan.rs` version assertions, `docs/install.md`'s version references, and regenerated `docs/examples/ci/baseline.json`.
3. **Hashing was not actually TOCTOU/symlink-race safe**: the original implementation checked `symlink_metadata` then called `File::open` — a symlink could be swapped in between and followed, or a replacement file could coincidentally match the original's length/mtime. Fixed with `open_no_follow` (Unix `O_NOFOLLOW`, closing the race atomically at the kernel level) plus `same_file_identity` (device+inode / volume+file-index comparison, not just length/mtime) checked against the *opened handle's own metadata*, both before and after the read.
4. **Secret-variable escalation depended on assessment order**: `assess_environment` ran before `assess_unicode_identity`, so a high-severity Unicode finding arriving *after* the environment check was invisible to the `EF-TRUST-ENV-005`/`006` escalation decision. Fixed by splitting into `assess_environment_categories` (runs anywhere, returns pending secret-like names) and `finalize_secret_like_indicators` (runs only after every other assessment area has already contributed its indicators).
5. **PEP 440 wildcard/compound expressions misclassified as exact**: `package==1.2.*` (version-matching wildcard) and `package===1.2` (arbitrary equality, a distinct operator whose `==`-prefix corrupted the original parse) both incorrectly classified as `ExactlyPinned`. Fixed with explicit `===` detection before the `==` check, and `is_exact_pep440_version` rejecting wildcards/whitespace/etc.
6. **PowerShell download-and-execute false positive**: `has_download && has_exec` matched both tokens appearing anywhere in the command, including when separated by `;` or piped through an unrelated intermediate cmdlet. Fixed with bounded adjacent-pipe-segment matching (mirroring the existing `pipe_to_shell_pattern` design).
7. **Remote artifact-identity rationale absent**: FR-057c requires explicit rationale text for a remote server's `unknown` artifact identity. Added a new, always-present `artifactIdentityRationale` string field to `TrustAssessment`, populated deterministically for every `ArtifactIdentityConfidence` value (not only the remote case, for shape consistency) — `ef-setup-detect/v0.2`'s only post-hoc field addition.

All fixes are covered by new regression tests proving the exact scenario described in each finding. Full release gate (`fmt`/`clippy`/`test`/`build`/`git diff --check`) re-verified green after each fix and once more at the end.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (touches a different file than every other task marked `[P]` in the same subsection, with no dependency on an incomplete task in that subsection)
- **[Story]**: Which user story this task belongs to (US1–US5)
- File paths are exact; where a task depends only on Setup/Foundational (not on a sibling implementation task in the same story), the dependency note says so explicitly

## TDD note for this feature

Almost every implementation task in `crates/etherfence-setup/src/trust.rs` edits the **same file**, so within any one subsection those tasks are sequential, not `[P]`, regardless of logical independence — a same-file conflict overrides a no-logical-dependency rule. Test tasks are listed before their paired implementation tasks per story (standard TDD ordering) and depend only on Foundational (Phase 2) plus their own fixture tasks — they are **expected to fail** (wrong values, not compile errors, since Phase 2 already defines a stub `assess_trust` returning safe defaults) until their story's implementation tasks land later in the same phase.

---

## Phase 1: Setup

**Purpose**: Project initialization for this feature — new module scaffolding and the one cross-crate visibility change research.md identified.

- [X] T001 Create `crates/etherfence-setup/src/trust.rs` with a module doc comment, and add `mod trust;` to `crates/etherfence-setup/src/lib.rs`
- [X] T002 [P] Change `mod unicode;` to `pub mod unicode;` in `crates/etherfence-mcp/src/lib.rs` (additive visibility only — no change to `unicode.rs` logic; research.md Decision 11)

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Shared vocabulary types, the story-agnostic aggregation/ordering math, and a stub `assess_trust` orchestrator that every user story independently extends by replacing exactly one of its own stub calls. No user story work should begin until this phase is complete.

**⚠️ CRITICAL**: No user story work can begin until this phase is complete.

- [X] T003 Define `ArtifactIdentityConfidence`, `ConfigurationRiskStatus`, `AggregateAssessmentStatus` enums (`kebab-case` `Serialize`, mirroring `CapabilityLabel`) in `crates/etherfence-setup/src/trust.rs`
- [X] T004 Define `IndicatorCategory` (+ `IndicatorCategory::ALL` canonical order per research.md Decision 13), `EvidenceKey`, `EvidenceField`, and `TrustIndicator` (reusing `etherfence_core::Severity`, not a new severity type) in `crates/etherfence-setup/src/trust.rs` (after T003)
- [X] T005 Implement pure functions `configuration_risk_from_indicators(&[TrustIndicator]) -> ConfigurationRiskStatus`, `aggregate(ArtifactIdentityConfidence, ConfigurationRiskStatus) -> AggregateAssessmentStatus`, `needs_review(AggregateAssessmentStatus) -> bool`, and `sort_indicators(&mut Vec<TrustIndicator>)` in `crates/etherfence-setup/src/trust.rs` per FR-061/FR-062/FR-067 (after T003, T004)
- [X] T006 Table-driven unit tests in `crates/etherfence-setup/src/trust.rs` covering: the full 3×3 `aggregate()` input cross-product against the documented configuration-risk-first table; all 5 `needs_review()` cases; an indicator-ordering test over a hand-built out-of-order `Vec<TrustIndicator>`; and a synthetic "verified-local artifact identity + hand-constructed high-risk indicator" case proving `aggregate` never lets one axis hide the other (User Story 3's core no-conflation guarantee, provable here without any real parsing) (after T005)
- [X] T007 Define `PackageRunner`, `VersionExpressionKind`, `ShellWrapperKind`, `ObscuredLaunchPattern`, `ExecutablePathClassification`, and `InvocationAssessment` types in `crates/etherfence-setup/src/trust.rs` per data-model.md (after T003)
- [X] T008 Define the `TrustAssessment` struct (`sha256: Option<String>` with `skip_serializing_if`, `indicators: Vec<TrustIndicator>` always-serialized) in `crates/etherfence-setup/src/trust.rs` (after T004, T007)
- [X] T009 Implement `assess_trust(&McpServer) -> TrustAssessment` in `crates/etherfence-setup/src/trust.rs`: detect a remote server (`command.is_none() && url.is_some()`) and set `invocation.applicable = false`, `executable_path = NotApplicable`, `sha256 = None` per FR-057b for that case; for every server (stdio **and** remote) call five stub sub-functions — `assess_invocation_runner` (empty), `assess_shell_wrapper_and_obscured_launch` (empty), `classify_executable_path_and_hash` (returns `NotApplicable`/`None` for remote, `Unknown`-safe stub for stdio), `assess_environment` (empty), `assess_unicode_identity` (empty) — then assemble via T005's `configuration_risk_from_indicators`/`aggregate`/`needs_review`/`sort_indicators` (after T005, T008)
- [X] T010 Add `trust_assessment: TrustAssessment` field to `SetupServer`, call `assess_trust(server)` from `server_from_mcp()`, and re-export the new trust types from `crates/etherfence-setup/src/lib.rs` mirroring the existing `catalog`/`classification` `pub use` pattern (after T009)

**Checkpoint**: `cargo test --workspace` passes; every server's `trust_assessment` is present but returns safe stub defaults (`Unknown`/`NoKnownIndicators`/empty indicators). Each user story below now independently replaces exactly one of T009's five stub calls.

---

## Phase 3: User Story 1 - Judge package-runner invocation risk (Priority: P1)

**Goal**: `assess_invocation_runner` correctly classifies npx/uvx/pipx run package identity and version-pinning shape.

**Independent Test**: Run `etherfence setup detect --format json` against fixtures covering every `VersionExpressionKind` value per runner and assert exact output — no dependency on US2/US3/US4/US5.

### Tests for User Story 1

- [X] T011 [P] [US1] Add npx fixture servers (pinned, omitted, mutable-tag `@latest`, version-range, scoped-package-exact-version, scoped-package-no-version, malformed) to `tests/fixtures/trust-home/.claude.json` — **deviation from plan**: uses a new, fully isolated `trust-home/` fixture root instead of extending `home/.claude.json`, to avoid regressing the many exact-count/exact-list assertions `cli_scan.rs` already makes against `home/` (FR-089 compatibility requirement takes precedence over the literal file path named in planning)
- [X] T012 [P] [US1] Add uvx/pipx run fixture servers (pinned `==`, unpinned, version-range, malformed-flag) to `tests/fixtures/trust-home/.cursor/mcp.json` (same isolation rationale as T011)
- [X] T013 [P] [US1] Malformed-runner-invocation fixture folded into T011 (`npx-malformed`, empty args) — a separate `malformed-home/` addition was dropped for the same regression-risk reason (that fixture's exact server-name-list assertions would break)
- [X] T014 [US1] Unit tests in `crates/etherfence-setup/src/trust.rs` (`user_story_1_tests` module) asserting exact `invocation.runner`/`packageIdentity`/`versionExpression` via `assess_trust` for hand-built `McpServer` values mirroring every T011 npx fixture shape
- [X] T015 [US1] Unit tests in `crates/etherfence-setup/src/trust.rs` asserting exact values for every T012 uvx/pipx shape
- [X] T016 [US1] Unit test in `crates/etherfence-setup/src/trust.rs` asserting `malformed_runner_invocation == true` and no `versionExpression` for the malformed shape

### Implementation for User Story 1

- [X] T017 [US1] Implement npx package-identity/version parsing (curated mutable-tag list; `@`-split rule that skips a leading scope `@`; range-operator/wildcard detection) in `crates/etherfence-setup/src/trust.rs`, reusing `classification::launcher_name`/`resolve_package_arg` (promoted to `pub(crate)`) per research.md Decision 4
- [X] T018 [US1] Implement uvx/pipx run PEP-440-style `==`/range/omitted parsing (`classify_pep440`) in `crates/etherfence-setup/src/trust.rs`
- [X] T019 [US1] Implement `assess_invocation_runner`, replacing T009's stub, adding package-pinning `TrustIndicator`s (`EF-TRUST-PIN-001`..`005`: omitted/mutable-tag/version-range/unsupported-or-ambiguous/malformed, evidence `runner`/`package-identity`/`version-expression`) in `crates/etherfence-setup/src/trust.rs`
- [X] T020 CLI integration test asserting `trustAssessment.invocation` JSON fields for the `trust-home` fixtures — **deferred and consolidated**: written together with all other stories' CLI tests in `crates/etherfence-cli/tests/cli_setup_trust.rs` once US3's JSON rendering (T039) exists, since a CLI-level JSON assertion cannot meaningfully run before the field is rendered at all; tracked as part of the Phase 5 CLI test pass, see T034 note

**Checkpoint**: User Story 1 fully functional and testable independently — T014–T016 and T020 now pass.

---

## Phase 4: User Story 2 - Judge shell-wrapper and obscured-launch risk (Priority: P1)

**Goal**: `assess_shell_wrapper_and_obscured_launch` correctly classifies the 7 wrapper forms and the 5 obscured-launch patterns.

**Independent Test**: Run against wrapper/obscured-launch/negative-control fixtures and assert exact indicator output — no dependency on US1/US3/US4/US5.

### Tests for User Story 2

- [X] T021 [P] [US2] Add fixture servers to `tests/fixtures/trust-home/.windsurf/mcp.json` (isolated fixture root, same rationale as T011) covering all 7 `ShellWrapperKind` forms plus one direct-launch negative control
- [X] T022 [P] [US2] Add fixture servers to `tests/fixtures/trust-home/.gemini/settings.json` covering all 5 `ObscuredLaunchPattern` forms (note: FR-026's generic "pipe-to-shell" and FR-028(a)'s curl/wget rule are the same implemented rule per research.md Decision 5, so one fixture proves both) plus one superficially-similar non-matching negative control
- [X] T023 [US2] Unit tests in `crates/etherfence-setup/src/trust.rs` (`user_story_2_tests`) asserting exact `invocation.shellWrapper` for hand-built values mirroring every T021 shape, plus a fixture-backed test reading the real `trust-home` files through `etherfence_inventory::discover`
- [X] T024 [US2] Unit tests asserting exact `invocation.obscuredLaunchPatterns` for hand-built values mirroring every T022 shape, plus the same fixture-backed read-through test

### Implementation for User Story 2

- [X] T025 [US2] Implement shell-wrapper detection (`launcher_name()` against the 7-command closed set, then exact-flag match against `{-c, /c, -Command, -EncodedCommand}`) in `crates/etherfence-setup/src/trust.rs` per research.md Decision 5
- [X] T026 [US2] Implement the 5 obscured-launch structural rules (`pipe_to_shell_pattern`, `powershell_downloads_and_executes`, standalone `certutil -urlcache` check — bounded substring/token matching over the wrapped argument string only, never a shell tokenizer) in `crates/etherfence-setup/src/trust.rs` per research.md Decision 5
- [X] T027 [US2] Implement `assess_shell_wrapper_and_obscured_launch`, replacing T009's stub, adding shell-wrapper (`EF-TRUST-SHW-001`) and obscured-launch (`EF-TRUST-OBS-001`..`005`) `TrustIndicator`s (evidence `wrapper-type`/`obscured-launch-pattern`) in `crates/etherfence-setup/src/trust.rs`
- [X] T028 CLI integration test for `invocation.shellWrapper`/`obscuredLaunchPatterns` JSON fields — **deferred and consolidated** into the Phase 5 CLI test pass alongside T020, same rationale (rendering doesn't exist until T039)

**Checkpoint**: User Stories 1 AND 2 both independently functional.

---

## Phase 5: User Story 3 - Get one clear, non-conflated trust picture per server (Priority: P1)

**Goal**: Executable-path classification, bounded local-artifact hashing, and full `trustAssessment` rendering (JSON `ef-setup-detect/v0.2` + additive human output) — the story that makes the whole feature visible and delivers the "no conflation" promise end-to-end.

**Independent Test**: Run against path-classification and hashing fixtures, and inspect the full rendered `trustAssessment` shape — no dependency on US1/US2/US4/US5 (T006 already proves the aggregation math independently; this story only needs its own path/hash logic and rendering).

### Tests for User Story 3

- [X] T029 [P] [US3] Add fixture servers to `tests/fixtures/trust-home/.codex/config.toml` (isolated fixture root) covering: relative path, bare/PATH-resolved command, missing path, non-regular file (`/tmp`, portable/always-present on Unix CI, used instead of a checked-in path), and empty/ambiguous command
- [X] T030 [US3] Windows absolute-path *shape* recognition covered by a direct unit test (`windows_absolute_path_shape_is_recognized_as_absolute_not_relative`) rather than a checked-in `windows-home`-style fixture — a Windows-style absolute path cannot resolve to a real file on Linux CI regardless of fixture location, so the honestly-testable property (recognized as absolute, not relative/bare) is asserted directly
- [X] T031 [P] [US3] Added `tests/fixtures/trust-home/bin/sample-tool` (small real executable script) and `tests/fixtures/trust-home/bin/sample-tool-symlink` (relative symlink to it) for SHA-256 hashing and symlink-classification tests; both referenced via a `CARGO_MANIFEST_DIR`-relative path computed at test time (not a static config fixture) since `McpServer.command` requires a literal absolute path — baking one into checked-in JSON/TOML would break on any other clone location. Oversized-file ineligibility exercised via a runtime-generated temp file against a test-only-lowered limit (new `hash_eligible_file_bounded(path, max_bytes)` parameterization), not a checked-in large fixture
- [X] T032 [US3] Unit tests in `crates/etherfence-setup/src/trust.rs` (`user_story_3_tests`) asserting exact `executablePath` classification for every T029 fixture (via `discover()`) plus the Windows-shape and dynamic-path (hash/symlink) cases
- [X] T033 [US3] Unit tests asserting: successful SHA-256 hash matches the expected digest for the T031 fixture; ineligibility for an oversized runtime temp file under a test-only limit; and a TOCTOU snapshot-comparison test proving the same before/after metadata check `hash_eligible_file_bounded` uses would reject a mid-inspection change
- [X] T034 [US3] CLI integration tests in `crates/etherfence-cli/tests/cli_setup_trust.rs` (new file) asserting the full `trustAssessment` JSON object shape against `contracts/setup-detect-trust-assessment.md` — also consolidates the deferred T020/T028 assertions (invocation/runner/wrapper/obscured-launch JSON fields) now that rendering exists
- [X] T035 [US3] CLI integration test in `crates/etherfence-cli/tests/cli_setup_trust.rs` asserting `etherfence setup detect --format json` run twice produces byte-identical stdout

### Implementation for User Story 3

- [X] T036 [US3] Implement `classify_executable_path(command: &str) -> ExecutablePathClassification` — `fs::symlink_metadata` checked before any regular-file check (never followed), no `PATH` resolution performed — in `crates/etherfence-setup/src/trust.rs` per research.md Decisions 8/10
- [X] T037 [US3] Implement bounded, streamed SHA-256 hashing (`hash_eligible_file_bounded`, `MAX_EXECUTABLE_HASH_BYTES = 200 MiB`, manual chunked `Read` loop + running-total bound check, pre/post-read `fs::metadata` TOCTOU comparison) in `crates/etherfence-setup/src/trust.rs` per research.md Decision 9
- [X] T038 [US3] Implement `classify_executable_path_and_hash` (path classification + hashing) and `derive_artifact_identity` (in `assess_trust`, since `KnownSource` needs US1's parsed `invocation.package_identity`), replacing T009's stub: `VerifiedLocal` on successful hash, `KnownSource` on a `KNOWN_SOURCE_IDENTITIES` match, else `Unknown`; `TemporaryDirectoryLocation` reported additively (`EF-TRUST-PATH-004`) alongside the primary classification, plus `EF-TRUST-PATH-001`..`003` for missing/non-regular/symlink, in `crates/etherfence-setup/src/trust.rs`
- [X] T039 [US3] Render `trustAssessment` in `etherfence setup detect --format json` output (automatic via `#[derive(Serialize)]` on the new `SetupServer` field) and bump the `etherfenceSchemaVersion` literal to `"ef-setup-detect/v0.2"` in `crates/etherfence-cli/src/main.rs`; also updated the one existing test asserting the literal `v0.1` string (`cli_setup.rs`) to expect `v0.2` — an intentional, documented schema bump, not a regression
- [X] T040 [US3] Render additive human-readable trust-assessment lines per server (`trust: artifact-identity=... configuration-risk=... aggregate=... needs-review=...` plus an indicator list) via a new `kebab_label()` helper that reuses each type's own `Serialize` JSON token (added `serde.workspace = true` to `etherfence-cli`'s `Cargo.toml` for the trait bound) in `crates/etherfence-cli/src/main.rs`
- [X] T041 [US3] Regression test in `crates/etherfence-cli/tests/cli_setup_trust.rs` asserting `etherfence setup plan`/`etherfence setup doctor` human output contains no `trust:`/`trust indicators` text (byte-identical to pre-v1.3.0 output, confirmed by inspection: neither render function was touched)

**Checkpoint**: User Stories 1, 2, and 3 (the full P1 scope) are independently functional — **suggested MVP scope**.

---

## Phase 6: User Story 4 - See risky environment-variable exposure without ever seeing values (Priority: P2)

**Goal**: `assess_environment` flags the 5 documented name-based risk categories, runs for both stdio and remote servers, and never emits a value.

**Independent Test**: Run against env-var category fixtures and scan all output for configured values — no dependency on US1/US2/US3/US5.

### Tests for User Story 4

- [X] T042 [P] [US4] Add fixture servers to `tests/fixtures/trust-home/.vscode/mcp.json` (isolated fixture root) covering one environment variable per FR-053 category, a dual-match name (`NPM_TOKEN` — legitimately both registry-override and secret-like, added to the registry-override curated list as a realistic entry, not a contrived one), and one benign-name negative control — each with a non-empty configured value (already redacted to `<set>` by the existing v0.1.x inventory layer before it ever reaches this feature's code)
- [X] T043 [US4] Unit tests in `crates/etherfence-setup/src/trust.rs` (`user_story_4_tests`) asserting exact category indicator(s) via `assess_trust` for hand-built values mirroring every T042 shape, plus a fixture-backed read-through test
- [X] T044 [US4] Redaction test in `crates/etherfence-cli/tests/cli_setup_trust.rs` scanning full `etherfence setup detect` stdout (human and JSON) for the fixture's configured value literal, asserting it never appears

### Implementation for User Story 4

- [X] T045 [US4] Implement the 4 curated `ENV_RISK_CATEGORIES` name-pattern lists (`EF-TRUST-ENV-001`..`004`) plus secret-like substring matching (`EF-TRUST-ENV-005`/escalated `-006`) and `assess_environment(&[EnvVar], ArtifactIdentityConfidence, &mut Vec<TrustIndicator>)` (names only, values never read into evidence) in `crates/etherfence-setup/src/trust.rs` per research.md Decision 12 — signature takes `artifact_identity` (not in the original plan sketch) since FR-054's escalation rule needs it, and by call time in `assess_trust` it's already computed
- [X] T046 [US4] Wire `assess_environment`, replacing T009's stub, into `assess_trust` for **both** stdio and remote servers per FR-057a in `crates/etherfence-setup/src/trust.rs`

**Checkpoint**: User Stories 1–4 independently functional.

---

## Phase 7: User Story 5 - Detect identity-ambiguous or spoofed-looking server/package names (Priority: P2)

**Goal**: `assess_unicode_identity` reuses `etherfence_mcp::unicode` for bidi/invisible detection, adds narrow mixed-script and curated confusable-alias matching, and runs for both stdio and remote servers.

**Independent Test**: Run against Unicode/confusable identity fixtures — no dependency on US1/US2/US3/US4.

### Tests for User Story 5

- [X] T047 [P] [US5] Add fixture server/package identities to `tests/fixtures/trust-home/.cursor/mcp.json` (isolated fixture root, extending the US1 file) covering a bidi-control character (U+202E), an invisible/zero-width character (U+200B), a defined mixed-script identity (Latin+Cyrillic), the single curated confusable alias (U+0456, research.md Decision 14), and an ordinary ASCII negative control — verified byte-exact via a Python UTF-8 round-trip check before committing to the test suite, given how easily invisible/bidi characters get mangled in transit
- [X] T048 [US5] Unit tests in `crates/etherfence-setup/src/trust.rs` (`user_story_5_tests`) asserting exact indicator per hand-built value mirroring every T047 shape, a fixture-backed read-through test, plus an explicit negative case proving plain single-script non-ASCII text (no bidi/zero-width/mixed-script/confusable match) raises nothing (FR-050)

### Implementation for User Story 5

- [X] T049 [US5] Define the single-entry `CONFUSABLE_ALIASES` curated table (one Cyrillic-homoglyph variant of `@modelcontextprotocol/server-filesystem`, U+0456) in `crates/etherfence-setup/src/trust.rs` per research.md Decision 14
- [X] T050 [US5] Implement `assess_identity_string`/`assess_unicode_identity` — calling `etherfence_mcp::unicode::inspect_policy_identifier` for bidi/invisible detection (interpreting only its `BidiControl`/`ZeroWidth` variants; its `NonAsciiIdentifier` fallback is deliberately not treated as a risk per FR-050), plus new narrow mixed-script detection (closed Latin/Cyrillic/Greek set) and exact `CONFUSABLE_ALIASES` matching — in `crates/etherfence-setup/src/trust.rs` per research.md Decision 11; evidence never reproduces the raw identity string (FR-051), only a category token
- [X] T051 [US5] Wire `assess_unicode_identity` (applied to server name and, when present, `invocation.package_identity`), replacing T009's stub, into `assess_trust` for **both** stdio and remote servers per FR-057a in `crates/etherfence-setup/src/trust.rs`

**Checkpoint**: All 5 user stories independently functional.

---

## Phase 8: Polish & Cross-Cutting Concerns

**Purpose**: Remote-server end-to-end proof, documentation, and the full release gate.

- [X] T052 [P] Added a new `remote-hosted-docs` URL-only server (with a risky `LD_PRELOAD` environment variable) to `tests/fixtures/trust-home/.vscode/mcp.json` (isolated fixture root, same rationale as T011 — `multi-home/`'s existing `remote-docs` server has index/field-order-sensitive assertions in `etherfence-inventory`'s own tests that a new sibling server would risk disturbing), and a CLI test in `crates/etherfence-cli/tests/cli_setup_trust.rs` asserting `invocation.applicable == false`, `executablePath == "not-applicable"`, `sha256` absent, `artifactIdentity == "unknown"`, and that the environment-variable indicator (`EF-TRUST-ENV-001`) still populates and drives `configurationRisk`/`aggregate` to `high-risk` per FR-057a–FR-057d
- [X] T053 [P] Update `README.md`: Command overview gains a `setup detect` row; `setup catalog` example section extended with a trust-assessment paragraph; docs table entries bumped to `ef-setup-detect/v0.2`
- [X] T054 [P] Update `docs/setup-onboarding.md` with a new `## \`etherfence setup detect\` trust and integrity assessment (v1.3.0)` section
- [X] T055 [P] Update `docs/json-schema.md`: extend the `ef-setup-detect` section to `v0.2` with a full `trustAssessment` field table and example per `contracts/setup-detect-trust-assessment.md`
- [X] T056 [P] Update `docs/architecture.md` with a new `## MCP server trust and integrity assessment (v1.3.0)` section plus a `trust.rs` mention in the crate list
- [X] T057 [P] Update `docs/threat-model.md` with a `## v1.3.0 addendum` explicitly documenting the new bounded local-file-read surface (the one genuinely new I/O surface this feature adds) and restating non-goals
- [X] T058 [P] Update `docs/roadmap.md` with the v1.3.0 entry
- [X] T059 [P] Add a `## [1.3.0]` section to `CHANGELOG.md`
- [X] T060 Documentation-honesty tests in `crates/etherfence-cli/tests/setup_catalog_docs.rs`: extended the existing v1.2.0 sentence-scoped, negation-aware `PROHIBITED_TERMS` (block/intercept/prevent/enforce) checker with a second `TRUST_PROHIBITED_TERMS` checker (is-safe/trusted/certified/malware-free/benign/definitively-malicious) using the identical negation-aware pattern — a naive substring ban immediately false-failed on this doc's own correct disclaimers ("does not mean the program is safe"), the same lesson the v1.2.0 precedent already established; also hit and fixed the same markdown-line-wrap sentence-splitting issue (the test splits on `\n` too) in the new doc prose itself
- [X] T061 Full local release gate: `cargo fmt --check` (fixed 3 files via `cargo fmt`, formatting only), `cargo clippy --all-targets --all-features -- -D warnings` (fixed `sort_indicators(&mut Vec<_>)` → `&mut [_]`, a redundant `is_empty()` guard, a collapsible match, and a `&PathBuf` → `&Path` test-helper parameter), `cargo test --workspace` (391 tests, all passing), `cargo build --workspace`, `git diff --check` (staged+checked+reset, no whitespace errors) — all green
- [X] T062 Walked `quickstart.md` end-to-end against the local debug build. Rewrote it first to reference the actual `trust-home` fixture root (the original draft, written before implementation, still named `home`/`multi-home`). Every one of the 10 sections' commands were actually executed and their real output compared against the documented `# expect:` comments — this caught **two real bugs**: (1) `ObscuredLaunchPattern::PowerShellWebRequestToInvokeExpression` (capital `S` in `Shell`) serialized via serde's kebab-case derive to `power-shell-web-request-to-invoke-expression` (split into two words) instead of the documented `powershell-web-request-to-invoke-expression` — renamed the variant to `PowershellWebRequestToInvokeExpression` (matching `ShellWrapperKind`'s existing lowercase-`s` convention) to fix; no test caught this because tests compared the enum value, never the literal JSON string. (2) The quickstart's own `jq '{artifactIdentity, sha256}'` reconstruction syntax prints `null` for a *missing* key exactly the same as a *present* `null` value, which would have misleadingly suggested `sha256` were present-but-null instead of genuinely omitted — fixed to use `jq '.field, has("key")'` instead. Re-ran the full release gate (fmt/clippy/test) after both fixes — still fully green (391 tests)

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — start immediately.
- **Foundational (Phase 2)**: Depends on Setup — **BLOCKS all user stories**.
- **User Stories (Phase 3–7)**: All depend only on Foundational completion. They do **not** depend on each other — each replaces a different one of T009's five stub calls in the same shared file, so they are logically independent even though they physically serialize on `trust.rs` if worked by one contributor.
- **Polish (Phase 8)**: T052 depends on US4 (T046) and US5 (T051) specifically (it asserts both keep working for remote servers); T053–T059 depend only on Foundational; T060–T062 depend on all prior phases.

### User Story Dependencies

- **US1, US2, US4, US5**: Each can start immediately after Foundational (Phase 2); none depends on another story's implementation.
- **US3**: Can start immediately after Foundational; its "no conflation" proof (T006) is already covered in Foundational using synthetic inputs, so US3 does not need US1/US2/US4/US5 to be complete to be independently demonstrable — it only needs its own path/hashing logic plus the shared `TrustAssessment` shape from Phase 2.

### Within Each User Story

- Fixture tasks (marked `[P]` when they touch different files) before the unit/CLI tests that read them.
- Unit tests before the implementation tasks that make them pass (TDD ordering — see "TDD note" above).
- All tasks touching `crates/etherfence-setup/src/trust.rs` within one story are sequential (same-file conflict), even when logically independent.

### Parallel Opportunities

- T001 and T002 (Setup) touch different crates — parallel.
- Within Foundational, only fixture/doc-adjacent work could run in parallel with `trust.rs` edits, but Phase 2 is entirely `trust.rs`/`lib.rs` — effectively sequential; no `[P]` tasks in Phase 2.
- Once Foundational completes, **US1, US2, US4, and US5's fixture tasks** (T011–T013, T021–T022, T042, T047) can all be authored in parallel by different contributors since they touch different fixture files; their respective implementation tasks in `trust.rs` still serialize against each other if one contributor is doing all of them, but are logically independent if split across contributors working in short-lived branches.
- Documentation tasks T053–T059 are all `[P]` (7 different files).

---

## Parallel Example: Fixture authoring across stories (post-Foundational)

```bash
# With Foundational (Phase 2) complete, these fixture tasks can be done in parallel:
Task: "Add npx fixture servers to tests/fixtures/home/.claude.json"                        # T011 (US1)
Task: "Add wrapper fixture servers to tests/fixtures/home/.windsurf/mcp.json"               # T021 (US2)
Task: "Add env-var category fixture servers to tests/fixtures/home/.claude.json"            # T042 (US4) — NOTE: same file as T011, sequence after it
Task: "Add Unicode/confusable fixture identities to tests/fixtures/home/.cursor/mcp.json"   # T047 (US5)
```

---

## Implementation Strategy

### MVP First (User Stories 1–3 only)

1. Complete Phase 1: Setup.
2. Complete Phase 2: Foundational (critical — blocks all stories).
3. Complete Phase 3 (US1), Phase 4 (US2), Phase 5 (US3) — all three are P1 and together deliver the full "one clear picture, driven by real package/wrapper/path/hash data" outcome.
4. **STOP and VALIDATE**: run `quickstart.md` sections 1–5, 8–10 against this scope.
5. Deploy/demo if ready — env-var (US4) and Unicode (US5) indicators will simply be absent (empty) until their phases land, which is a safe, honest default (`no-known-indicators` for those categories), not a broken state.

### Incremental Delivery

1. Setup + Foundational → foundation ready, `trust_assessment` present but stubbed.
2. Add US1 → package-runner pinning live → test independently.
3. Add US2 → wrapper/obscured-launch live → test independently.
4. Add US3 → path/hashing + full rendering live → **MVP demo-ready** (all P1 stories done).
5. Add US4 → environment-variable indicators live → test independently.
6. Add US5 → Unicode/identity-ambiguity indicators live → test independently.
7. Phase 8 → docs, remote-server proof, full release gate.

### Parallel Team Strategy

1. Team completes Setup + Foundational together (single-file bottleneck — best done by one person or in tight pairing).
2. Once Foundational is done: Developer A takes US1, Developer B takes US2, Developer C takes US3, Developer D takes US4+US5 (P2, lower priority) — all edit the same `trust.rs` file, so coordinate merge order (suggested: US1 → US2 → US3 → US4 → US5) even though the *logic* in each story is independent.
3. Phase 8 documentation tasks (T053–T059) can be split across the whole team in parallel once the relevant behavior exists to document.

---

## Notes

- `[P]` tasks = different files, no dependency on an incomplete sibling task.
- `[Story]` label maps a task to its user story for traceability.
- Every curated identity, confusable alias, and structural rule ships only once its fixture + exact-output test (Constitution Principle V/XI) — see `plan.md`'s Fixture Strategy table for the full mapping.
- No task in this list produces `RecommendationTier::Allow`, starts a subprocess, or performs network access — verified structurally by every implementation task's function signature (pure, `&McpServer`/`&Path`/`&str` in, structured value out).
- Stop at any checkpoint to validate a story independently before continuing.
