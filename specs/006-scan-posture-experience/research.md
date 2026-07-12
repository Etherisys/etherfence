# Research: Scan Posture Experience

## Decision: Derive posture from final displayed findings

**Rationale**: Existing scan logic already applies detector discovery, optional policy evaluation, baseline comparison, resolved-finding inclusion, and severity filtering before constructing `ScanReport`. Deriving posture from `display_findings` after that pipeline preserves all existing selection semantics and makes posture accurately describe the report the operator receives.

**Alternatives considered**:

- Derive before `--severity-threshold`: rejected because an executive score could describe findings intentionally hidden from the emitted report.
- Derive before baseline comparison: rejected because resolved historical findings would be indistinguishable from active evidence.
- Re-run detectors in a posture module: rejected because it duplicates scan semantics and risks drift.

## Decision: Keep the existing scan severity vocabulary

**Rationale**: `Severity` currently has `info`, `low`, `medium`, and `high`. The release scope excludes new findings/severity semantics, so the score schedule uses only these existing tokens. High findings are the highest input; no critical category is invented.

**Alternatives considered**:

- Add `critical`: rejected as a breaking semantic expansion outside scope.
- Map selected high findings to critical: rejected as misleading reclassification.

## Decision: Fixed integer score and grade table

**Rationale**: Integer penalties (25 high, 10 medium, 2 low) and a fixed grade table make score calculation easy to document, test at boundaries, reproduce, and explain. Clamp prevents invalid output while allowing several high findings to communicate an F posture.

**Alternatives considered**:

- Probabilistic or risk-model scoring: rejected as opaque and nondeterministic in practice.
- Detector-specific weights: rejected because it would change the relative meaning of existing detectors and expand scope.
- Baseline/newness weighting: rejected because existing/new status remains a CI workflow concern, not a changed risk severity.

## Decision: One shared core posture model with optional report field

**Rationale**: Core ownership prevents divergent human/Markdown/JSON calculations. `Option<PostureSummary>` makes the JSON field additive and permits existing in-repo manual report fixtures to represent older reports without synthetic data.

**Alternatives considered**:

- Independent renderer calculations: rejected because they can diverge and duplicate sorting/scoring logic.
- Mandatory non-optional report field: rejected because it needlessly breaks programmatic construction and is less visibly additive.
- New schema identifier: rejected because no existing meaning or required field changes.

## Decision: Deterministic top-three priorities

**Rationale**: Sorting active findings by severity, ID, target, agent key, then fingerprint produces a total order independent of discovery/insertion order. Limiting executive sections to three preserves the established concise default view and directs users to verbose evidence.

**Alternatives considered**:

- Discovery order: rejected as not a deliberate priority contract.
- Deduplicating similar recommendations: rejected because hidden grouping logic could obscure traceability and alter ordering.
- More than three items: rejected because it weakens first-screen scanability.

## Decision: Preserve terminal design and SARIF behavior

**Rationale**: The CLI has an established `UiTheme` with semantic styles, 60-column rules, aligned rows, and a plain-text fallback. Existing `Security posture`, `Priority findings`, and `Next steps` headings are the natural extension points. SARIF is a separate established integration contract and is explicitly out of scope.

**Alternatives considered**:

- New TUI/dashboard: rejected as a design-language replacement and scope expansion.
- SARIF posture properties: rejected because additive JSON is required, while SARIF changes are not needed to meet the objective.
