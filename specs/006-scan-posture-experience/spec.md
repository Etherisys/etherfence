# Feature Specification: Scan Posture Experience

**Feature Branch**: `feat/v1.7.0-scan-posture-experience`
**Created**: 2026-07-12
**Status**: Ready for planning
**Input**: Improve the `etherfence scan` experience so users immediately understand their AI Agent Security Posture, the highest-priority risks, and recommended next actions while preserving the existing EtherFence terminal design and machine-readable compatibility.

## Clarifications

### Session 2026-07-12

- Q: What evidence contributes to the posture calculation? → A: Every finding displayed by the scan after the existing severity filter; resolved baseline findings are excluded because they are historical, while new and existing active findings both contribute. The posture carries structured scope metadata recording `displayed-active-findings`, the effective severity threshold, and resolved-baseline exclusion; it is not an unfiltered host-wide security score.
- Q: How is a deterministic posture score calculated? → A: Start at 100, subtract 25 per high, 10 per medium, and 2 per low active finding; clamp the result to the inclusive 0–100 range; informational findings do not change the score. EtherFence's existing scan severity vocabulary has no critical level, so this release does not introduce one.
- Q: How is the posture grade assigned? → A: A for 90–100, B for 75–89, C for 55–74, D for 30–54, and F for 0–29.
- Q: How are priority and next actions chosen? → A: Active findings sort by severity descending, then stable finding ID, target, agent, and fingerprint; the first three are displayed as priority risks and their per-finding recommendations form the first three next actions in that same stable order.
- Q: What happens when no active scored findings are shown? → A: The posture is 100/A, the executive summary states that no active scored findings were displayed, and it retains the existing caution that this is not proof that the host is secure.
- Q: Which formats receive the new content? → A: The default human summary, verbose human report, Markdown report, and JSON report receive a posture summary; SARIF stays semantically unchanged. JSON adds an optional top-level `posture` object without removing, renaming, or changing existing fields.

## User Scenarios & Testing

### User Story 1 - Understand posture immediately (Priority: P1)

As an operator, I can run the default scan and see an unambiguous overall posture score, grade, concise assessment, and severity distribution before detailed findings so I can decide where to focus.

**Why this priority**: The first screen must communicate overall posture and the most urgent work without requiring the operator to parse every finding.

**Independent Test**: Run the scan against a deterministic fixture with active findings and verify the initial human output contains a stable score, grade, assessment, severity counts, and advisory scope statement.

**Acceptance Scenarios**:

1. **Given** a fixture with active high and medium findings, **When** the operator runs `etherfence scan`, **Then** the first report section presents the deterministic score and grade before the priority-finding list.
2. **Given** a fixture with no active scored findings, **When** the operator runs `etherfence scan`, **Then** the report presents score 100 and grade A while clearly stating that the result is not proof that the host is secure.
3. **Given** the same fixture is scanned repeatedly, **When** the operator compares human output, **Then** the posture score, grade, priority order, and recommendation order are identical.

---

### User Story 2 - Act on the most important risks (Priority: P1)

As an operator, I can see up to three priority risks with a short explanation of why each matters and a corresponding recommended next action, followed by an explicit path to full evidence.

**Why this priority**: A finding list alone does not tell an operator what to do first or why a risk deserves attention.

**Independent Test**: Scan a fixture containing multiple severities and assert that the top three active findings and actions are selected and ordered deterministically, expose the finding ID and scope, and link the default view to `--verbose` for complete evidence.

**Acceptance Scenarios**:

1. **Given** more than three active findings, **When** the operator runs the default scan, **Then** only the first three priority risks and actions appear in the executive view and the report states how to obtain the full evidence.
2. **Given** findings of equal severity, **When** the operator runs the scan, **Then** their priority order is determined by the declared stable tie-break sequence rather than discovery timing.
3. **Given** a priority finding, **When** it is shown in the human or Markdown report, **Then** its explanation uses the finding's existing impact statement as "Why this matters" and its existing recommendation as the next action without claiming scan-time enforcement or remediation.

---

### User Story 3 - Consume posture consistently in reports and automation (Priority: P2)

As an operator or automation author, I can receive the same posture calculation and priority recommendations in Markdown and additive JSON output while existing scan behavior, exit decisions, and existing fields remain usable.

**Why this priority**: Teams need a shareable report and an additive machine-readable posture summary without breaking established automation.

**Independent Test**: Compare JSON, Markdown, human summary, and verbose report for a fixture; assert that their posture values agree and that existing report fields, finding values, exit behavior, and schema identifier remain unchanged.

**Acceptance Scenarios**:

1. **Given** a scan with active findings, **When** the operator selects JSON output, **Then** the existing top-level report fields remain present and a new optional `posture` object provides the score, grade, assessment, counts, priority risks, and recommended actions.
2. **Given** a scan with active findings, **When** the operator selects Markdown output, **Then** the report begins with the same posture summary and next actions before full finding evidence.
3. **Given** existing `--fail-on`, `--fail-on-new`, baseline, severity threshold, and output-format options, **When** the posture feature is used, **Then** their exit status and finding selection semantics are unchanged.

---

### Edge Cases

- Resolved baseline findings remain visible wherever the existing report displays them but do not lower the posture score or appear in priority risks/actions.
- Informational findings remain visible in full evidence but do not lower the posture score or consume a priority slot unless no scored findings exist; no priority risk/action is shown in the latter case.
- A severity threshold may hide active findings; the posture describes only the findings displayed by that invocation and must say so in the assessment context.
- If arithmetic reaches below zero, the score remains exactly zero; no score may be negative or above 100.
- Repeated recommendations are retained per selected finding so each priority action remains traceable to the risk it addresses; no heuristic deduplication may change ordering or evidence.
- Markdown and human text must remain readable on narrow terminals using the current width, indentation, color, and plain-text fallback conventions.

## Requirements

### Functional Requirements

- **FR-001**: The scan report MUST derive one deterministic posture summary from the displayed active findings without adding detectors, modifying finding identities, or altering scan discovery.
- **FR-002**: The posture score MUST use the declared 100-point deduction schedule and inclusive clamp, and the grade MUST use the declared fixed ranges.
- **FR-003**: The default human scan screen MUST put posture, concise executive assessment, priority risks, and next actions before lower-priority report content while reusing EtherFence's existing terminal theme, section rendering, width handling, plain-text fallback, and interaction style.
- **FR-004**: The default human view MUST show at most three priority risks and at most three corresponding next actions, identify each risk by finding ID and scope, and point operators to `etherfence scan --verbose` for complete evidence.
- **FR-005**: Each displayed priority risk MUST include a clearly labeled "Why this matters" explanation drawn from existing finding impact data, and each action MUST use the existing finding recommendation text.
- **FR-006**: The verbose human report and Markdown report MUST include the same posture summary and prioritization while continuing to provide complete finding evidence organized by severity.
- **FR-007**: JSON output MUST retain its current schema identifier and all existing top-level and finding fields unchanged, and MAY add only an optional top-level `posture` object containing deterministic posture values and priority/action entries derived from existing finding data.
- **FR-008**: SARIF output, scan detectors, finding IDs, inventory behavior, policy evaluation, runtime proxy behavior, scan option meanings, baseline behavior, and all exit-code decisions MUST remain unchanged.
- **FR-009**: The posture assessment and all user-facing documentation MUST state that scan results are advisory and local, do not automatically remediate, and do not prove a host is secure.
- **FR-010**: The implementation MUST provide fixture-backed automated coverage for score boundaries, grade boundaries, active-versus-resolved treatment, stable ordering, format consistency, JSON additive compatibility, and unchanged exit behavior.
- **FR-011**: The release MUST update the version, changelog, user documentation, examples, schema documentation, and Spec Kit validation artifacts to match the implemented behavior.

### Key Entities

- **Posture Summary**: A deterministic, derived view of the displayed active findings containing score, grade, assessment context, severity counts, priority risks, and next actions.
- **Priority Risk**: One selected active finding represented by its stable identity, severity, human title, agent/target scope, and existing impact statement.
- **Recommended Action**: The existing recommendation text paired with the selected priority risk it addresses.
- **Posture Counts**: The active finding counts by severity that feed the posture score; resolved and informational findings are represented separately or excluded as declared above.

## Success Criteria

### Measurable Outcomes

- **SC-001**: For every checked-in fixture, repeated scans with the same options produce byte-identical JSON posture content and identical human/Markdown priority ordering.
- **SC-002**: The first visible default human scan section contains the posture score, grade, and at least one clear next-step cue before any full finding evidence.
- **SC-003**: A report with more than three active findings presents exactly three priority risks and exactly three linked recommended actions in the executive view.
- **SC-004**: JSON consumers that read all previously documented top-level fields and finding fields continue to parse the v1.7.0 report unchanged.
- **SC-005**: The full Rust verification gate, focused posture tests, documentation/example validation, and `git diff --check` complete successfully before review.

## Out of Scope

- New detectors, finding IDs, severity reclassification, or scan semantic changes.
- Runtime policy, MCP enforcement, proxy, onboarding, or automatic remediation changes.
- Remote MCP posture, daemon/service behavior, cloud dependencies, or fleet management.
- New exit codes or changed `--fail-on`, `--fail-on-new`, baseline, or severity-threshold semantics.
- Breaking JSON, Markdown, SARIF, baseline, or policy schema changes.
- Replacing the EtherFence terminal design system or unrelated refactoring.

## Assumptions

- Existing findings already contain the rationale, impact, recommendation, stable identity, severity, agent, target, and fingerprint needed to derive posture without new detection data.
- Existing scan report ordering is preserved for full evidence; posture selection introduces only its explicitly declared stable ordering for the derived executive view.
- Version 1.7.0 is a product release version; the existing `ef-scan-report/v0.1` identifier remains compatible because `posture` is additive and optional.
- The default human summary remains a concise executive view, and `--verbose` remains the explicit complete-evidence path.
