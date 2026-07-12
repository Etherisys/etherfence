# Data Model: Scan Posture Experience

## `PostureSummary`

| Field | Type | JSON key | Rules |
|---|---|---|---|
| score | unsigned integer | `score` | Inclusive 0–100; 100 minus active displayed severity deductions, clamped. |
| grade | closed enum | `grade` | `a`, `b`, `c`, `d`, or `f`; fixed score ranges. |
| assessment | string | `assessment` | Deterministic advisory sentence based on grade/no active scored findings. |
| active_findings | unsigned integer | `active_findings` | Active displayed findings, excluding `resolved`; includes info. |
| high | unsigned integer | `high` | Active high count. |
| medium | unsigned integer | `medium` | Active medium count. |
| low | unsigned integer | `low` | Active low count. |
| info | unsigned integer | `info` | Active informational count. |
| priority_risks | array | `priority_risks` | At most three risks selected by the fixed ordering. |
| recommended_actions | array | `recommended_actions` | One action per priority risk, same order. |

## `PostureGrade`

| Grade | Score range | Human framing |
|---|---:|---|
| `a` | 90–100 | Stronger posture; still advisory and incomplete coverage. |
| `b` | 75–89 | Review findings to improve posture. |
| `c` | 55–74 | Meaningful posture risks need review. |
| `d` | 30–54 | High-priority posture risks need prompt review. |
| `f` | 0–29 | Multiple significant posture risks need prompt review. |

## `PostureRisk`

| Field | Source | Privacy/safety rule |
|---|---|---|
| finding_id | `Finding.id` | Stable existing identifier. |
| severity | `Finding.severity` | Existing token; no remapping. |
| title | `Finding.title` | Existing human title. |
| agent | `Finding.agent` | Existing agent token/display representation. |
| target | `Finding.target` | Existing target. |
| fingerprint | `Finding.fingerprint` | Existing stable fingerprint. |
| why_this_matters | `Finding.impact` | Existing safe impact text; no raw evidence, content, env values, or credentials. |

## `RecommendedAction`

| Field | Source | Rule |
|---|---|---|
| finding_id | selected `Finding.id` | Links action to its priority risk. |
| recommendation | `Finding.recommendation` | Existing advisory next-step text, unchanged. |

## Relationships and derivation

1. Existing scan creates `display_findings` after current detector/policy/baseline/threshold flow.
2. `PostureSummary` filters active items (`baseline_status != resolved`) from that same vector.
3. Counts and score are calculated from active items; resolved items remain in `ScanReport.findings` but not posture.
4. Priority risks sort by severity descending, then finding ID, target, agent key, fingerprint; first three are retained.
5. Recommended actions map one-to-one to those risks in the same order.
6. `ScanReport.posture` is optional/additive in serialized JSON but populated by v1.7.0 scans.
