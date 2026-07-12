# Tasks: Scan Posture Presentation Stabilization

**Input**: [spec.md](./spec.md), [plan.md](./plan.md), [human layout contract](./contracts/human-posture-layout.md)

## Phase 1 — Foundation

- [x] T001 Add display-width, terminal-width fallback, and stable wrapping helpers with unit tests in `crates/etherfence-cli/src/ui.rs`.
- [x] T002 Add a reusable styled/unstyled human layout boundary so ANSI styling occurs only after wrapping in `crates/etherfence-cli/src/ui.rs`.

## Phase 2 — User Story 1 (P1): Read constrained posture output

- [x] T003 [US1] Update default executive posture summary to use the existing theme plus the new wrapping helpers in `crates/etherfence-cli/src/main.rs`.
- [x] T004 [US1] Update verbose human posture and full-finding presentation to use stable wrapped labels/bullets in `crates/etherfence-report/src/lib.rs`.
- [x] T005 [US1] Add long Unicode/ASCII, narrow-width, no-findings, informational-only, and high-threshold rendering regression tests in `crates/etherfence-cli/tests/cli_scan.rs` and `crates/etherfence-report/src/lib.rs`.

## Phase 3 — User Story 2 (P1): Preserve deterministic plain text

- [x] T006 [US2] Add `NO_COLOR` and redirected/non-TTY subprocess tests with ANSI-free and repeat-output assertions in `crates/etherfence-cli/tests/cli_scan.rs`.

## Phase 4 — User Story 3 (P2): Release/documentation alignment

- [x] T007 [US3] Update `Cargo.toml`, lockfile, version assertions, release docs, example baseline, and `CHANGELOG.md` to 1.7.1.
- [x] T008 [US3] Add only necessary human-layout terminology notes to `README.md` and `docs/json-schema.md`; retain all machine contract wording.

## Phase 5 — Verification and handoff

- [x] T009 Mark completed work and verify artifact/code traceability in `specs/007-scan-posture-stabilization/tasks.md`.
- [x] T010 Run the full gate, inspect staged scope, commit/push, create an open PR to `main`, and verify PR/check state from `CHANGELOG.md`.

## Dependencies

T001–T002 → T003–T006 → T007–T008 → T009–T010. T005 and T006 may proceed in parallel after the relevant layout boundary exists.
