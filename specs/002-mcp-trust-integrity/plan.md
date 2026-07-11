# Implementation Plan: MCP Server Trust and Integrity Assessment

**Branch**: `002-mcp-trust-integrity` | **Date**: 2026-07-11 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/002-mcp-trust-integrity/spec.md`

## Summary

Extend `etherfence setup detect` so every discovered MCP server gains a structured, deterministic, local-only trust-and-integrity assessment alongside its existing v1.2.0 capability classification and starter-policy recommendation: package-runner version-pinning analysis (npx/uvx/pipx run), shell-wrapper and a closed set of 5 obscured-launch structural indicators, executable-path classification, bounded local SHA-256 hashing of eligible regular files, narrow Unicode/identity-ambiguity checks (reusing `etherfence-mcp`'s existing bidi/zero-width detection), and environment-variable name-only risk categories. Artifact Identity Confidence and Configuration Risk are computed and reported separately, then combined into one Aggregate Assessment by a fixed configuration-risk-first rule. All new logic is a pure-function extension of the existing `etherfence-setup` classification pattern; the only cross-crate change is making `etherfence-mcp`'s already-depended-on Unicode module public. No new crate, daemon, network access, subprocess execution, or `mcp-proxy`/`recommendation.tier` change is introduced.

## Technical Context

**Language/Version**: Rust (2021 edition), `stable` toolchain — unchanged from v1.2.0.

**Primary Dependencies**: `sha2` (already a workspace dependency of `etherfence-setup`, reused for streaming SHA-256), `etherfence-mcp` (already a dependency of `etherfence-setup`, reused for Unicode bidi/zero-width detection — see research.md Decision 11), `serde`/`serde_json`, `anyhow` — no new dependency is added.

**Storage**: None (local filesystem reads only: existing config discovery plus, newly, bounded reads of eligible local executable files for hashing).

**Testing**: `cargo test --workspace` — `cargo test -p etherfence-setup` for the new trust-assessment unit logic, `cargo test -p etherfence-cli` for CLI integration tests against checked-in fixture homes.

**Target Platform**: Linux and Windows (existing CI matrix, unchanged).

**Project Type**: Single Rust Cargo workspace, CLI tool backed by library crates — unchanged.

**Performance Goals**: Not a distinguishing constraint for parsing/classification (same small local config set as v1.2.0). Local artifact hashing is the one new I/O-bound step; bounded and streamed per research.md Decision 9 so it scales with file size, not memory.

**Constraints**: Fully local, read-only, offline; deterministic output across Linux/Windows (FR-075–FR-079); no subprocess execution, no network access, no MCP protocol calls (FR-081–FR-088); `recommendation.tier` never becomes `allow` (FR-069/FR-070).

**Scale/Scope**: Scales with the number of locally configured MCP servers (single digits to low tens, same as v1.2.0) plus, per eligible server, one bounded local file read up to 200 MiB (research.md Decision 9).

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-checked after Phase 1 design (see "Post-Design Re-Check" below).*

| Principle | Compliance approach |
|---|---|
| I. Security-First, Deny-by-Default | `recommendation.tier` stays `deny` unconditionally (FR-069); no trust-assessment value can ever produce `allow` (FR-070). Any hashing/classification failure degrades to `needs-review`/`unknown`, never a favorable default (FR-044). |
| II. Local-First Operation | No daemon, network call, shell hook, or subprocess. Hashing reads local files already referenced by parsed config — no new process boundary. |
| III. Truth in Claims | `verified-local`/`known-source`/`no-known-indicators` are always paired with their documented limiting language (FR-063, SC-008); docs describe this as "trust and integrity assessment," never "malware scan" or "safety guarantee." |
| IV. Deterministic Output | Fixed indicator ordering (research.md Decision 13), fixed aggregation rule (Decision 7), fixed evidence-key vocabulary (Decision 6); byte-identical JSON for identical input (FR-079). |
| V. Fixture-Backed Findings and Classifications / XI. Catalog Classification Discipline | Every curated known-source identity, confusable alias, and structural rule (runner pinning, wrapper, obscured-launch, path classification, env-var category) ships only with a checked-in fixture and exact-output test — see Fixture Strategy below. The known-source/confusable tables are deliberately small (research.md Decision 14) rather than asserting broad coverage. |
| VI. Schema Compatibility and Explicit Versioning | `ef-setup-detect/v0.1` → `v0.2`, additive only (contracts/setup-detect-trust-assessment.md); documented in `docs/json-schema.md` and `CHANGELOG.md`. |
| VII. Fail-Closed Runtime Proxy Behavior | Not touched — `mcp-proxy` code is untouched (FR-072). |
| VIII. Audit Log Safety | Not applicable — this feature writes no audit log; its own analogous redaction rule (never emit env values, file contents, or full command strings) is enforced by FR-057/FR-066/FR-080 and the `EvidenceField` structured-token design. |
| IX. Complete Release Packaging | Fixtures and CLI tests run on both Linux and Windows via the existing CI matrix; docs/CHANGELOG updated in the same change (Documentation Updates below). |
| X. Scope Discipline | Fixed runner set (npx/uvx/pipx run only), fixed 5-pattern obscured-launch list, fixed 7-form wrapper list, fixed small curated tables, no CI-gate flag added — all bounded explicitly in spec.md Out of Scope and re-affirmed here. |
| XI. Catalog Classification Discipline | Same discipline as v1.2.0's `EVIDENCE_RULES`, applied to the new curated known-source/confusable tables — see Principle V row above. |

No violations requiring justification were identified. Complexity Tracking is intentionally empty.

## Project Structure

### Documentation (this feature)

```text
specs/002-mcp-trust-integrity/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md         # Phase 1 output
├── contracts/
│   └── setup-detect-trust-assessment.md
└── quickstart.md         # Phase 1 output
```
(`tasks.md` is Phase 2 output — not created here.)

### Source Code (repository root)

```text
crates/etherfence-mcp/src/lib.rs         # ONE-LINE visibility change: `mod unicode;` →
                                          # `pub mod unicode;` (research.md Decision 11).
                                          # No logic change to unicode.rs.

crates/etherfence-setup/src/
├── lib.rs                 # server_from_mcp() gains a call into the new trust module
│                           # (new SetupServer field: trust_assessment). detect()/plan()/
│                           # doctor()/apply()/rollback() signatures unchanged.
├── catalog.rs              # unchanged
├── classification.rs       # unchanged (v1.2.0 capability classification untouched;
│                           # trust assessment is a new, separate concern)
└── trust.rs                 # NEW: pure fns — assess_invocation(&McpServer),
                            # classify_executable_path(&McpServer), inspect_local_artifact(&Path),
                            # assess_environment(&[EnvVar]), assess_unicode_identity(&str),
                            # aggregate(ArtifactIdentityConfidence, ConfigurationRiskStatus),
                            # needs_review(AggregateAssessmentStatus). Curated tables
                            # (KNOWN_SOURCE_IDENTITIES, CONFUSABLE_ALIASES, MUTABLE_NPM_TAGS,
                            # ENV_RISK_CATEGORIES) live here, mirroring classification.rs's
                            # EVIDENCE_RULES precedent.

crates/etherfence-cli/src/main.rs        # `SetupOutputFormat::Json` rendering for `setup
                                          # detect` gains `trustAssessment` per server;
                                          # human rendering gains additive lines per server
                                          # (mirroring the v1.2.0 capabilities/recommendation
                                          # line precedent). schema_version literal bumped
                                          # to "ef-setup-detect/v0.2".

crates/etherfence-cli/tests/
├── cli_setup.rs             # Extended with trust-assessment JSON/human assertions,
│                             # or a new cli_setup_trust.rs sibling file.

tests/fixtures/
├── home/, windows-home/     # Extended: pinned/unpinned/mutable-tag/range/malformed
│                             # runner variants, wrapper variants, obscured-launch
│                             # variants, path-classification variants, a locally
│                             # hashable binary fixture, Unicode/confusable fixtures,
│                             # env-var category fixtures — see Fixture Strategy below.
├── malformed-home/          # Extended: malformed runner invocation case.
└── multi-home/              # Extended or reused: remote (URL-configured) server case.
```

**Structure Decision**: Everything is added to the two existing crates that already own this responsibility (`etherfence-setup` for the new trust-assessment logic, `etherfence-cli` for rendering), plus one minimal, additive visibility change in `etherfence-mcp` to unlock reuse of its existing Unicode module rather than duplicating it (research.md Decision 11). No new crate. This mirrors the v1.2.0 structure decision exactly and keeps the same regression-risk profile.

## Fixture Strategy

Every claimed curated identity, confusable alias, and structural rule must have a fixture and a passing exact-output test *before* it is described as implemented (FR-091, Constitution Principle V/XI).

| Area | Fixture additions | Proves |
|---|---|---|
| Package-runner pinning | `home/`: pinned npx, unpinned (omitted) npx, mutable-tag npx (`@latest`), version-range npx, scoped-package-exact-version npx, scoped-package-no-version npx, pinned uvx, unpinned uvx, pipx run pinned/unpinned. `malformed-home/`: unparseable runner argument shape. | FR-011–FR-020, all `VersionExpressionKind` variants reachable, malformed case reported distinctly (not silently folded into another category). |
| Shell wrapper | `home/` or `windows-home/`: one server per wrapper form (`sh -c`, `bash -c`, `cmd.exe /c`, `powershell -Command`, `powershell -EncodedCommand`, `pwsh -Command`, `pwsh -EncodedCommand`), plus a negative-control direct-launch server. | FR-021–FR-025, exactly the 7 forms recognized, no false positive on direct launches. |
| Obscured launch | 5 fixtures, one per `ObscuredLaunchPattern` variant (curl-to-shell, wget-to-shell or combined, `certutil -urlcache`, PowerShell `iwr`→`iex`, base64-decode-to-shell), plus a negative-control superficially-similar-but-non-matching command. | FR-026–FR-029, closed 5-pattern set, no drift toward general shell parsing. |
| Executable-path classification | Linux absolute executable, Windows absolute executable, relative path, bare PATH command, missing path, non-regular file (e.g. a directory given as command), symlink, temp-directory-located executable, one ambiguous/unsupported form. | FR-030–FR-036; relative/PATH/symlink never silently promoted to verified-local. |
| Local artifact hashing | One small real regular-file fixture eligible for hashing (deterministic SHA-256 expected value asserted in test); one fixture exceeding `MAX_EXECUTABLE_HASH_BYTES` (or a fixture that simulates the boundary via a lowered test-only limit) proving graceful ineligibility. | FR-037–FR-045; TOCTOU/degradation behavior covered by a unit test that mutates a temp file between the pre- and post-read metadata snapshots. |
| Unicode / identity ambiguity | Bidi-control server/package identity, invisible-character identity, a defined mixed-script identity, the single curated confusable alias from research.md Decision 14, plus an ordinary ASCII negative control. | FR-046–FR-051; reuse of `etherfence_mcp::unicode` verified by a test asserting the same detection fires as `etherfence-mcp`'s own existing unicode tests. |
| Environment variables | One server per FR-053 category (loader injection, interpreter/path override, registry override, TLS-disabling, secret-like), one server with a name matching two categories at once, one benign-name negative control. | FR-052–FR-057; no value ever appears in output (asserted by a redaction test scanning all output for the fixture's configured values). |
| Aggregation / multi-indicator | A fixture combining `verified-local` artifact identity with a `high-risk` configuration indicator; a fixture combining `known-source` identity with an unpinned version and a risky wrapper. | FR-058–FR-062, User Story 3's "no conflation" requirement, the resolved configuration-risk-first precedence. |
| Remote server scope | A `url`-only (no `command`) server fixture, reused/extended from an existing multi-home-style fixture, with a risky environment-variable name attached. | FR-057a–FR-057d; `invocation.applicable == false`, `executablePath == "not-applicable"`, env/Unicode checks still run. |
| Determinism | Reuse the existing "run twice, diff stdout" CLI test pattern already established for `setup catalog`, extended to `setup detect --format json`. | FR-079, SC-002. |
| Compatibility regression | No new fixtures — existing `cli_setup.rs`/`cli_setup_catalog.rs` tests re-run unmodified. | FR-089, SC-009. |

**Gate**: a structural rule or curated identity may be described as implemented only once its fixture has an accompanying test asserting the exact `TrustAssessment`/indicator output it produces.

## Test Strategy

1. **Unit tests, `crates/etherfence-setup/src/trust.rs`**: table-driven tests over the full `VersionExpressionKind`/`ShellWrapperKind`/`ObscuredLaunchPattern`/`ExecutablePathClassification` value sets; a full 3×3 cross-product test of `aggregate(artifact, risk)` asserting every one of the 9 input combinations maps to the documented output (FR-061); a `needs_review` test over all 5 `AggregateAssessmentStatus` values.
2. **Unit tests, local artifact hashing**: use `std::env::temp_dir()`-based real temporary files (mirroring `etherfence-core`'s existing `write_temp_file` test helper pattern) for regular-file, oversized, and TOCTOU-mutation cases; a Unix-only symlink test (mirroring the existing `/dev/zero` Unix-only precedent in `etherfence-core`).
3. **CLI integration tests, `crates/etherfence-cli/tests/`**: extend `cli_setup.rs` (or add `cli_setup_trust.rs`) following the existing `fixture_root`/`run`/`temp_home` helper pattern: `setup detect --format json` field assertions per `contracts/setup-detect-trust-assessment.md`; a determinism (run-twice-diff) test; an env-value-redaction test scanning full stdout/stderr for every fixture's configured secret value; a `setup plan`/`setup doctor` byte-identical-output regression test (extending the existing pattern already used for the v1.2.0 no-leakage check).
4. **Workspace regression gate**: `cargo test --workspace` must remain fully green — mechanical enforcement of SC-009.
5. **CI platforms**: existing `rust (ubuntu-latest)`/`rust (windows-latest)` matrix; no new CI wiring needed. Windows-specific fixtures (Windows absolute paths, `cmd.exe`/`powershell`/`pwsh` wrappers, `certutil`) are exercised as parsed string data on both platforms (no actual Windows binary execution required, since nothing is executed).

## Documentation Updates

Per Constitution Principle IX, updated in the same change as the code:

- **`README.md`**: extend the existing `setup detect` example/description to mention trust-assessment output; update the schema-version reference to `ef-setup-detect/v0.2`.
- **`docs/setup-onboarding.md`**: new subsection under the existing `etherfence setup detect` documentation describing the trust-and-integrity assessment, its vocabulary, and its explicit limits (mirroring the "Catalog tier vs. write support" honesty-framing precedent).
- **`docs/json-schema.md`**: extend the existing `ef-setup-detect/v0.1` section into `v0.2`, documenting every new field per `contracts/setup-detect-trust-assessment.md`.
- **`docs/architecture.md`**: extend the existing "Client catalog and MCP capability classification (v1.2.0)" section (or add a sibling "Trust and integrity assessment (v1.3.0)" section) stating this adds no new trust boundary — same local config reads, plus bounded local file reads for hashing, still no process start/network call.
- **`docs/threat-model.md`**: extend the existing v1.2.0 addendum (or add a v1.3.0 addendum) documenting the new bounded local-file-read surface (hashing) explicitly, and restating the non-goals (not a malware scanner, no registry/network lookups).
- **`docs/roadmap.md`**: append the v1.3.0 entry.
- **`CHANGELOG.md`**: new `## [1.3.0]` section (Added: trust-and-integrity assessment, `ef-setup-detect/v0.2`; explicit note that no `mcp-proxy`/`recommendation.tier` behavior changed).
- **No changes required**: `docs/mcp-proxy.md`, `docs/mcp-proxy-operator-guide.md`, `docs/mcp-policy-ux.md`, `docs/sarif.md`, `docs/ci.md`, `docs/mcp-compatibility-matrix.md` — none touched by this feature.

## Release Gate Checklist

- [ ] `cargo fmt --check` passes.
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passes.
- [ ] `cargo test --workspace` passes on both Linux and Windows CI runners.
- [ ] `cargo build` succeeds.
- [ ] `git diff --check` passes.
- [ ] Every curated known-source identity, confusable alias, and structural rule has a passing fixture test asserting its exact output (SC-007).
- [ ] No test asserts or observes `recommendation.tier == "allow"` anywhere in v1.3.0 output (SC-006).
- [ ] No test observes an environment-variable value, file content, credential, token, or complete sensitive command string anywhere in output (SC-005).
- [ ] `setup plan`/`setup doctor` human output is byte-identical to pre-v1.3.0 output (FR-004).
- [ ] `setup catalog` (`ef-setup-catalog/v0.1`) behavior is entirely unaffected (FR-090).
- [ ] All documentation files listed above are updated.
- [ ] No documentation or command output claims a server is proven safe/trusted/certified/malware-free/benign, or definitively malicious (SC-008).
- [ ] Spec's Out of Scope / Explicit Non-Goals items re-confirmed absent from the diff: no subprocess execution, no network access, no general shell parser, no universal Unicode confusable engine, no automatic config/policy mutation.

## Complexity Tracking

*No Constitution Check violations were identified; this table is intentionally empty.*

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| — | — | — |

## Post-Design Re-Check

Re-evaluated after Phase 1 (data-model.md, contracts/, quickstart.md):

- **`etherfence-mcp` visibility change** (`mod unicode` → `pub mod unicode`) is the only change outside `etherfence-setup`/`etherfence-cli`; it is purely additive (adds an export, changes no behavior) and does not touch `mcp-proxy`'s policy/audit/proxy modules, so FR-072 (no `mcp-proxy` behavior change) holds by inspection.
- **`SetupServer`'s one new public field** (`trust_assessment`) is additive; no existing external construction site exists outside `etherfence-setup::server_from_mcp`, so `setup plan`/`setup doctor` — which read only the fields they already read — remain unchanged in observable output, satisfying FR-004.
- **New `sha256: Option<String>` field's omission semantics** were the one place a data-model default (`skip_serializing_if`) needed to be checked against the contract rather than assumed — confirmed consistent between `data-model.md` and `contracts/setup-detect-trust-assessment.md` (both specify "omitted, never null").
- No new violations were introduced by the data model or contract; Constitution Check table above still holds.
