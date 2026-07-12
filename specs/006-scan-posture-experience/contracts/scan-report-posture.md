# Contract: Additive `ef-scan-report/v0.1.1` Posture Object

## Compatibility

- The top-level `schema_version` remains exactly `ef-scan-report/v0.1.1`.
- All pre-v1.7.0 top-level fields and finding fields retain their names, types, and meanings.
- `posture` is an optional new top-level object. Consumers that ignore unknown fields continue to parse existing output.
- v1.7.0 scans populate `posture`; older serialized reports may omit it.
- SARIF and baseline file contracts do not gain posture content.

## Shape

```json
{
  "schema_version": "ef-scan-report/v0.1.1",
  "posture": {
    "scope": {
      "finding_selection": "displayed-active-findings",
      "severity_threshold": "info",
      "resolved_baseline_findings": "excluded"
    },
    "score": 65,
    "grade": "c",
    "assessment": "Meaningful posture risks need review.",
    "active_findings": 5,
    "high": 1,
    "medium": 1,
    "low": 2,
    "info": 1,
    "priority_risks": [
      {
        "finding_id": "EF-MCP-001",
        "severity": "high",
        "title": "Broad filesystem access hint",
        "agent": "claude-code",
        "target": "filesystem",
        "fingerprint": "efp1-example",
        "why_this_matters": "Existing finding impact text."
      }
    ],
    "recommended_actions": [
      {
        "finding_id": "EF-MCP-001",
        "recommendation": "Existing finding recommendation text."
      }
    ]
  }
}
```

## Deterministic rules

- `scope.finding_selection` is always `displayed-active-findings`; `scope.severity_threshold` is the effective `--severity-threshold` for this invocation; and `scope.resolved_baseline_findings` is always `excluded`. This explicitly prevents interpreting posture as an unfiltered host-wide score.
- Active means `baseline_status` is not `resolved`.
- Score: `max(0, 100 - 25*high - 10*medium - 2*low)`; informational findings do not reduce score.
- Grades: A 90–100, B 75–89, C 55–74, D 30–54, F 0–29; serialized lower-case tokens are `a` to `f`.
- Priority ordering: severity descending, then finding ID, target, agent key, and fingerprint ascending.
- At most three priority risks/actions are emitted, linked by `finding_id` in identical order.
- The posture reflects the existing report's displayed-finding selection after `--severity-threshold`; it does not alter detector output, baseline comparison, or exit decisions.

## Safety language

Posture is local, read-only, advisory prioritization. It neither remediates findings nor proves a machine is secure, and it does not change the separately opt-in `mcp-proxy` enforcement boundary.
