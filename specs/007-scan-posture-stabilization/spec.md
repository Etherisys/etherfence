# Feature Specification: Scan Posture Presentation Stabilization

**Feature Branch**: `fix/v1.7.1-posture-presentation`  
**Created**: 2026-07-12  
**Status**: Ready for planning

## Clarifications

### Session 2026-07-12

- No critical ambiguity remained: existing terminal theme/layout helpers are reused; the supplied compatibility constraints freeze posture calculation, finding selection/order, machine formats, and exit behavior.

## User Scenarios & Testing

### User Story 1 — Read posture on constrained terminals (Priority: P1)

As an operator, I can read the default and verbose human posture reports at narrow widths even when finding text is unusually long, without losing the association between a priority risk and its action.

**Independent Test**: Render deterministic reports with long Unicode and ASCII text at a very narrow configured width; each physical line stays within the width and continuations use stable indentation.

**Acceptance Scenarios**:

1. **Given** a narrow terminal and long risk fields, **When** scan output is rendered, **Then** labeled content wraps without clipping or horizontal overflow.
2. **Given** a priority risk and its recommendation, **When** either wraps, **Then** the finding ID remains visible before both and continuation lines remain unambiguously nested.

---

### User Story 2 — Preserve dependable plain text (Priority: P1)

As an operator or CI user, I receive readable, byte-deterministic human text when colors are disabled or stdout is redirected.

**Independent Test**: Compare repeated plain-text renders and subprocess output under `NO_COLOR`; verify no ANSI escape sequence appears and output remains deterministic.

**Acceptance Scenarios**:

1. **Given** `NO_COLOR`, a dumb/plain terminal, or redirected stdout, **When** human scan output is rendered, **Then** it contains no raw ANSI escapes and retains the same words, order, and associations.
2. **Given** the same report/options, **When** output is rendered twice, **Then** the result is byte-identical.

---

### User Story 3 — Keep report terminology and contracts stable (Priority: P2)

As an automation or documentation user, I see consistent posture terminology across human, Markdown, and JSON documentation while existing report semantics remain unchanged.

**Independent Test**: Exercise no findings, informational-only findings, and `--severity-threshold high`; assert human terminology and scope remain aligned with the existing Markdown/JSON contract.

## Edge Cases

- Widths below a normal label length must still wrap rather than truncate or emit malformed spacing.
- Unicode display width, including wide glyphs, must be measured as terminal columns; ANSI style bytes must not affect wrapping decisions.
- No findings and informational-only findings retain their existing no-action behavior.
- `--severity-threshold high` changes only the already-defined displayed content, never selection, score, grade, or exit semantics.

## Requirements

### Functional Requirements

- **FR-001**: Default and verbose human scan posture output MUST use the existing theme/layout surface and wrap all long posture, finding, and recommendation fields to the available terminal width with stable continuation indentation.
- **FR-002**: Width calculation MUST be ANSI-aware and Unicode display-width-aware; lines MUST not be clipped or produce avoidable horizontal overflow at narrow widths.
- **FR-003**: Every displayed priority risk and its corresponding recommended action MUST remain visibly linked by the existing finding ID and clear labels after wrapping.
- **FR-004**: Plain-text modes (`NO_COLOR`, non-color/dumb terminals, and redirected output) MUST contain no raw ANSI sequences and preserve deterministic content/order.
- **FR-005**: Default human, verbose human, Markdown, JSON documentation, and examples MUST use the existing canonical posture terminology; Markdown/JSON report fields and semantics remain unchanged.
- **FR-006**: Regression tests MUST cover narrow width, long Unicode/ASCII fields, no findings, informational-only findings, high threshold, plain/non-TTY behavior, and repeat determinism.
- **FR-007**: The release MUST bump only the package release version to `1.7.1` and update the changelog, relevant docs/examples, and Spec Kit artifacts.

## Compatibility / Non-Goals

- Do not change posture weights, grade boundaries, finding selection/priority ordering, IDs, severities, fingerprints, detectors, baselines, policies, `--fail-on`, `--fail-on-new`, exit codes, SARIF, MCP proxy/runtime enforcement, or `ef-scan-report/v0.1.1` fields/semantics.
- Do not introduce a new UI design, a daemon/service, new report format, or unrelated refactoring.

## Success Criteria

- **SC-001**: Fixture-backed tests prove every emitted physical human line is within a deliberately narrow width except an unbreakable token that cannot be split safely.
- **SC-002**: Tests prove repeated output is identical and plain-text output contains no ANSI escape sequences.
- **SC-003**: The full required Rust validation gate passes with no report schema or behavior regressions.
