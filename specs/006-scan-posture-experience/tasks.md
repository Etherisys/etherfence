# Tasks: Scan Posture Experience

**Input**: Design documents from `/specs/006-scan-posture-experience/`
**Prerequisites**: `plan.md`, `spec.md`, `research.md`, `data-model.md`, `contracts/scan-report-posture.md`, `quickstart.md`
**Tests**: Required by FR-010 and the EtherFence constitution. Write and run focused tests before implementation for each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]** tasks work on separate files without an unfinished dependency.
- Story labels map to independently testable user stories in `spec.md`.

## Phase 1: Setup

**Purpose**: Establish release/spec context without product behavior changes.

- [x] T001 Confirm `specs/006-scan-posture-experience/` contract, score table, and compatibility decisions against the current `origin/main` scan implementation.
- [x] T002 [P] Add the 1.7.0 release section skeleton in `CHANGELOG.md` with only implemented scan-posture scope.
- [x] T003 [P] Update workspace release version from 1.6.2 to 1.7.0 in `Cargo.toml` and align existing version assertions in `crates/etherfence-cli/tests/cli_scan.rs`.

---

## Phase 2: Foundational Derived Posture Model

**Purpose**: Build the one deterministic model used by every renderer; blocks user stories.

- [x] T004 Add failing unit tests for score clamp, A/B/C/D/F boundaries, info-only/no-active behavior, resolved exclusion, tie ordering, and three-item cap in `crates/etherfence-core/src/lib.rs`.
- [x] T005 Implement additive `PostureGrade`, `PostureSummary`, `PostureRisk`, and `RecommendedAction` types plus `PostureSummary::from_findings` in `crates/etherfence-core/src/lib.rs`.
- [x] T006 Add optional additive `posture` to `ScanReport` and update in-repo `ScanReport` fixtures in `crates/etherfence-report/src/lib.rs`.
- [x] T007 Wire posture construction after existing baseline comparison and severity filtering, without moving exit-decision logic, in `crates/etherfence-cli/src/main.rs`.
- [x] T008 Run the focused core model tests and verify the existing baseline/threshold/exit tests in `crates/etherfence-cli/tests/cli_scan.rs` still pass.

**Checkpoint**: A scan report can carry one deterministic optional posture object without changing finding discovery, report selection, or exit behavior.

---

## Phase 3: User Story 1 - Understand Posture Immediately (Priority: P1) 🎯 MVP

**Goal**: Put deterministic score/grade/assessment in the existing first terminal screen.

**Independent Test**: Run the default fixture scan and assert posture score/grade/assessment appear before priority findings; run safe fixture and assert 100/A with the non-proof caution.

- [x] T009 [P] [US1] Add failing default human-summary assertions for score, grade, advisory assessment, and no-active posture in `crates/etherfence-cli/tests/cli_scan.rs`.
- [x] T010 [US1] Extend `render_scan_summary` using existing `UiTheme` sections/key-value helpers to render score, grade, assessment, and active severity context in `crates/etherfence-cli/src/main.rs`.
- [x] T011 [US1] Preserve existing narrow/plain-text behavior and existing default-view scope note in `crates/etherfence-cli/src/main.rs`.
- [x] T012 [US1] Run `cargo test -p etherfence-cli --test cli_scan scan_fixture_human_default_is_executive_summary` and the new posture-summary cases.

**Checkpoint**: Default scan answers “what is my posture?” before the operator must parse evidence.

---

## Phase 4: User Story 2 - Act on Priority Risks (Priority: P1)

**Goal**: Show up to three stable risks, why they matter, and linked actions without replacing current terminal language.

**Independent Test**: Use fixture findings with equal severities and baseline-resolved evidence to prove priority/action selection is stable and excludes resolved findings.

- [x] T013 [P] [US2] Add failing priority-risk/action count, stable-order, `Why this matters`, and resolved-exclusion tests in `crates/etherfence-core/src/lib.rs` and `crates/etherfence-cli/tests/cli_scan.rs`.
- [x] T014 [US2] Render at most three priority risks with existing severity styles, stable IDs/scopes, and `Why this matters` in `crates/etherfence-cli/src/main.rs`.
- [x] T015 [US2] Render one linked existing recommendation per priority risk plus existing verbose/setup cues in the `Next steps` section of `crates/etherfence-cli/src/main.rs`.
- [x] T016 [US2] Verify the default summary still omits full rationale/fingerprint evidence and directs operators to `--verbose` in `crates/etherfence-cli/tests/cli_scan.rs`.

**Checkpoint**: Default output gives a traceable, deterministic first-action list while retaining complete evidence behind `--verbose`.

---

## Phase 5: User Story 3 - Consistent Markdown and Additive JSON (Priority: P2)

**Goal**: Share the same deterministic posture across human, Markdown, and JSON without breaking automation.

**Independent Test**: Compare posture values/order among default human, verbose human, Markdown, and JSON for a fixture; verify SARIF/exit behavior retains its existing structure/status.

- [x] T017 [P] [US3] Add failing report-rendering tests for verbose posture and Markdown posture sections in `crates/etherfence-report/src/lib.rs`.
- [x] T018 [P] [US3] Add failing JSON additive-schema, format-consistency, severity-threshold, baseline-resolved, and unchanged exit-code tests in `crates/etherfence-cli/tests/cli_scan.rs`.
- [x] T019 [US3] Render posture/priority/action sections before complete evidence while preserving severity groups and advisory note in `crates/etherfence-report/src/lib.rs`.
- [x] T020 [US3] Keep `to_json` serde output additive and confirm `to_sarif` is untouched in `crates/etherfence-report/src/lib.rs`.
- [x] T021 [US3] Run focused core/report/CLI tests and manually inspect fixture human, Markdown, JSON, and SARIF outputs.

**Checkpoint**: Operators and compatible JSON consumers receive the same posture interpretation; existing machine interfaces and exit behavior remain intact.

---

## Phase 6: Documentation, Examples, and Release Polish

**Purpose**: Complete release packaging and verify actual behavior.

- [x] T022 [P] Document the optional `posture` object, deterministic score/grade/order, baseline/threshold treatment, and compatibility guarantee in `docs/json-schema.md`.
- [x] T023 [P] Refresh the scan example and explanatory wording for posture, priority risks, next actions, advisory scope, and verbose evidence in `README.md`.
- [x] T024 [P] Update 1.7.0 artifact/version references in `docs/install.md`, `docs/examples/ci/baseline.json`, and release-sensitive tests under `crates/etherfence-cli/tests/`; preserve historical smoke-test records.
- [x] T025 Regenerate the deterministic baseline example with `cargo run -- scan --root tests/fixtures/home --write-baseline docs/examples/ci/baseline.json` and review only expected version/unchanged finding deltas.
- [x] T026 Complete the 1.7.0 changelog section in `CHANGELOG.md` with deterministic posture, rendering, additive JSON, and compatibility language supported by implementation.
- [x] T027 Run all quickstart commands in `specs/006-scan-posture-experience/quickstart.md` and correct docs/examples to match real output.
- [x] T028 Run `cargo fmt --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace`, `cargo build --workspace`, and `git diff --check` from repository root.
- [x] T029 Perform a final spec-to-code convergence review against `specs/006-scan-posture-experience/spec.md`, `plan.md`, and `contracts/scan-report-posture.md`; record only verified residuals.

---

## Dependencies & Execution Order

- Phase 1 sets release context and can begin immediately.
- Phase 2 blocks every story because all output surfaces consume the shared model.
- US1 uses the shared model and can be completed as the MVP executive posture screen.
- US2 extends the same summary after US1’s structure is established.
- US3 uses the completed model independently in report renderers and machine output after Phase 2.
- Documentation/release polish follows all desired stories and is validated by the full gate.

## Parallel Opportunities

- T002/T003 touch independent release files after version scope is confirmed.
- T009 and T017/T018 can be prepared as tests on distinct output surfaces, but T017/T018 must not be considered passing until T005/T006 exist.
- T022/T023/T024 can be drafted in parallel only after actual output names/content are settled; final wording must follow real validation.

## Implementation Strategy

1. Lock down the pure deterministic derivation with failing core tests.
2. Add the model and report field, then prove legacy scan semantics remain unchanged.
3. Deliver the default human posture MVP and test it on fixtures.
4. Add priority/action context, then verbose/Markdown/JSON presentation.
5. Update docs/examples/version only after implementation output is real.
6. Run the full gate, conduct convergence, commit, push, and open a PR without merging.

## Post-PR Review Follow-up: Explicit Posture Scope and Boundary Coverage

**Purpose**: Address review findings without changing scan selection, detectors, exits, SARIF, or enforcement behavior.

- [x] R001 Add additive structured `PostureScope` metadata recording displayed-active selection, effective severity threshold, and resolved-baseline exclusion in `crates/etherfence-core/src/lib.rs`.
- [x] R002 Render the deterministic scope line in default human, verbose human, and Markdown output, and serialize it only under the optional JSON `posture` object.
- [x] R003 Add table-driven grade boundary coverage for 100, 90/89, 75/74, 55/54, 30/29, and 0 plus repeated priority/action ordering coverage.
- [x] R004 Add fixture-backed CLI assertions that scope is visible in default human, verbose human, Markdown, and JSON at an explicit `high` threshold.
- [x] R005 Update README, schema documentation, and feature design artifacts to make clear that posture is scoped to displayed active findings and is not a host-wide score.
