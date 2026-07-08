# EtherFence JSON Report and Baseline Schemas

Status: pre-alpha. This document describes the current scan report and baseline JSON contracts for automation and review tooling.

## Scan report schema version

Current report schema: `ef-scan-report/v0.1.1`

EtherFence v0.1.3 keeps the v0.1.1 report shape and adds optional baseline comparison metadata plus finding-level `fingerprint` and `baseline_status` fields. These additions are backward-compatible for consumers that ignore unknown fields.

CLI filtering with `--severity-threshold` changes which findings are included in the emitted report and recomputes `summary` for the displayed findings, but it does not change field names or object layout.

## Top-level report fields

| Field | Type | Stability | Description |
| --- | --- | --- | --- |
| `schema_version` | string | stable within v0.1.x | Versioned report shape identifier. |
| `tool` | string | stable | Tool name, currently `etherfence`. |
| `version` | string | stable | EtherFence package version. |
| `status` | string | stable | Product status, currently `pre-alpha-scan-only`. |
| `scanned_root` | string | stable | Root used for conservative config discovery. |
| `inventory` | array | additive | Discovered agent config inventory. |
| `findings` | array | additive | Displayed findings after severity threshold and optional baseline comparison. |
| `summary` | object | stable | Counts for displayed findings and inventory items. |
| `baseline` | object/null | optional | Baseline comparison metadata when `--baseline` is used. |

## Finding

| Field | Type | Description |
| --- | --- | --- |
| `id` | string | Stable finding ID, for example `EF-MCP-001`. |
| `title` | string | Human-readable finding title. |
| `severity` | string | `info`, `low`, `medium`, or `high`. |
| `kind` | string | Machine-oriented finding kind. |
| `agent` | string | Agent associated with the finding. |
| `target` | string | MCP server or component name the finding refers to. |
| `config_path` | string | Config source used as evidence. |
| `rationale` | string | Why EtherFence emitted the posture hint. |
| `impact` | string | Why the condition may matter. |
| `recommendation` | string | Suggested review/remediation step. |
| `references` | array | Reserved for future references; currently empty. |
| `fingerprint` | string | Deterministic finding fingerprint with `efp1-` prefix. |
| `baseline_status` | string | `new`, `existing`, `resolved`, or `not_applicable`. |
| `evidence` | array | Supporting strings from configuration. |

## Fingerprint stability

Fingerprints are deterministic over stable posture inputs: finding ID, agent, config path, target, kind, and normalized sorted evidence. They intentionally do not include timestamps, report version, rationale text, impact text, or recommendations.

Fingerprints are intended to support baseline/diff workflows across repeated scans of the same repository or workstation config. They may change if a config path, MCP server name, finding ID, finding kind, or evidence changes.

## Baseline comparison metadata

When `--baseline <file>` is used, the report includes:

| Field | Type | Description |
| --- | --- | --- |
| `baseline_path` | string | Baseline file path used for comparison. |
| `new` | integer | Current findings absent from the baseline. |
| `existing` | integer | Current findings present in the baseline. |
| `resolved` | integer | Baseline findings absent from the current scan. |

Resolved baseline findings are included in human and Markdown output, and in JSON `findings`, with `baseline_status: "resolved"` when they pass the displayed severity threshold.

## Baseline file schema

Baseline files are written with schema: `ef-baseline/v0.1.3`.

| Field | Type | Description |
| --- | --- | --- |
| `schema_version` | string | `ef-baseline/v0.1.3`. |
| `tool` | string | `etherfence`. |
| `version` | string | EtherFence version that wrote the baseline. |
| `created_at` | string/null | Optional timestamp; currently omitted/null for deterministic output. |
| `findings` | array | Current scan findings with fingerprints. |

## Stability expectations

- v0.1.x may add optional fields, new finding IDs, and new agent kinds.
- v0.1.x should not remove the documented top-level report fields without a schema version bump.
- Finding IDs and fingerprints are intended to be stable for automation when the underlying issue is unchanged.
- Findings are posture risks/hints, not confirmed exploitability.
- Baseline and report JSON are scan-only outputs and do not imply runtime blocking or enforcement.
