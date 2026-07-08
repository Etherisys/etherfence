# EtherFence JSON Report and Baseline Schemas

Status: pre-alpha. This document describes the current scan report and baseline JSON contracts for automation and review tooling.

## Scan report schema version

Current report schema: `ef-scan-report/v0.1.1`

EtherFence v0.1.8 keeps the v0.1.1 report shape unchanged. New finding IDs (such as `EF-CFG-001` for unparseable config files) and SARIF output are additive and do not alter the JSON report schema. Policy schema/source metadata appears in scan output when `--policy` or `--policy-profile` is used. These additions are backward-compatible for consumers that ignore unknown fields.

CLI filtering with `--severity-threshold` changes which findings are included in the emitted report and recomputes `summary` for the displayed findings, but it does not change field names or object layout. Policy findings are ordinary findings for filtering, `--fail-on`, baseline comparison, and `--fail-on-new`.

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
| `policy` | object/null | optional | Policy evaluation metadata when `--policy` or `--policy-profile` is used. |
| `baseline` | object/null | optional | Baseline comparison metadata when `--baseline` is used. |

## Finding

| Field | Type | Description |
| --- | --- | --- |
| `id` | string | Stable finding ID, for example `EF-MCP-001` or `EF-POL-001`. |
| `title` | string | Human-readable finding title. |
| `severity` | string | `info`, `low`, `medium`, or `high`. |
| `kind` | string | Machine-oriented finding kind. |
| `agent` | string | Agent associated with the finding. |
| `target` | string | MCP server or component name the finding refers to. |
| `config_path` | string | Config source used as evidence. Policy-only checks may use `policy`. |
| `rationale` | string | Why EtherFence emitted the posture hint. |
| `impact` | string | Why the condition may matter. |
| `recommendation` | string | Suggested review/remediation step. |
| `references` | array | Reserved for future references; currently empty. |
| `fingerprint` | string | Deterministic finding fingerprint with `efp1-` prefix. |
| `baseline_status` | string | `new`, `existing`, `resolved`, or `not_applicable`. |
| `policy_status` | string | `pass`, `violation`, or `not_applicable`. Existing non-policy findings use `not_applicable`; policy-generated findings use `violation`. |
| `policy_id` | string/null | Short machine policy check identifier for policy-generated findings. Omitted for non-policy findings. |
| `evidence` | array | Supporting strings from configuration or policy evaluation. |

## Policy file schema metadata

Policy files use top-level TOML metadata:

| Field | Type | Description |
| --- | --- | --- |
| `schema_version` | string | Required. Must currently be `ef-policy/v0.1`; unsupported versions fail before scanning completes. |
| `name` | string | Required stable policy name. |
| `description` | string | Optional human-readable policy intent. |
| `require_tirith` | boolean | Optional; when true, emits `EF-POL-005` if Tirith is not detected. |

See `docs/policy.md` for complete policy file documentation.

## Policy metadata in scan output

When `--policy <file>` or `--policy-profile <name>` is used, the report includes:

| Field | Type | Description |
| --- | --- | --- |
| `policy_path` | string | Policy file path used for evaluation. |
| `policy_schema_version` | string | Policy file schema version, currently `ef-policy/v0.1`. |
| `policy_name` | string | Policy display name from top-level `name`. |
| `policy_description` | string | Policy description from top-level `description`; omitted when empty. |
| `require_tirith` | boolean | Whether the policy required Tirith detection. |
| `checks_total` | integer | Number of policy checks evaluated. |
| `pass` | integer | Number of policy checks that passed. |
| `violation` | integer | Number of policy-generated violation findings. |
| `not_applicable` | integer | Number of checks skipped as not applicable. |

Policy-generated IDs in v0.1.8:

| ID | Meaning |
| --- | --- |
| `EF-POL-001` | Unexpected MCP server for an agent allowlist. |
| `EF-POL-002` | Disallowed filesystem path for a filesystem-capable MCP server. |
| `EF-POL-003` | Environment variable name not allowed by configured name patterns. |
| `EF-POL-004` | Secret-like environment variable name exposed while `deny_secret_like_names = true`. |
| `EF-POL-005` | Tirith not detected while `require_tirith = true`. |

## Fingerprint stability

Fingerprints are deterministic over stable posture inputs: finding ID, agent, config path, target, kind, and normalized sorted evidence. They intentionally do not include timestamps, report version, rationale text, impact text, recommendations, baseline status, policy status, or policy metadata.

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
| `findings` | array | Current scan findings with fingerprints. If `--policy` or `--policy-profile` is also used, policy findings are included. |

## Stability expectations

- v0.1.x may add optional fields, new finding IDs, and new agent kinds.
- v0.1.x should not remove the documented top-level report fields without a schema version bump.
- Finding IDs and fingerprints are intended to be stable for automation when the underlying issue is unchanged.
- Findings are posture risks/hints, not confirmed exploitability.
- Policy, baseline, and report JSON are scan-only outputs and do not imply runtime blocking or enforcement.
