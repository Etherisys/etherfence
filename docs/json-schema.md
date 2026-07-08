# EtherFence JSON Report Schema

Status: pre-alpha. This document describes the current scan report JSON contract for automation and review tooling.

## Schema version

Current schema: `ef-scan-report/v0.1.1`

EtherFence v0.1.2 keeps the v0.1.1 JSON shape. CLI filtering with `--severity-threshold` changes which findings are included in the emitted report and recomputes `summary` for the displayed findings, but it does not change field names or object layout.

## Top-level fields

| Field | Type | Stability | Description |
| --- | --- | --- | --- |
| `schema_version` | string | stable within v0.1.x | Versioned report shape identifier. |
| `tool` | string | stable | Tool name, currently `etherfence`. |
| `version` | string | stable | EtherFence package version. |
| `status` | string | stable | Product status, currently `pre-alpha-scan-only`. |
| `scanned_root` | string | stable | Root used for conservative config discovery. |
| `inventory` | array | additive | Discovered agent config inventory. |
| `findings` | array | additive | Displayed findings after any severity threshold filtering. |
| `summary` | object | stable | Counts for displayed findings and inventory items. |

## Inventory item

| Field | Type | Description |
| --- | --- | --- |
| `agent` | string | Agent kind such as `claude-code`, `cursor`, `vs-code`, `windsurf`, `gemini-cli`, `codex-cli`, or `tirith`. |
| `config_path` | string | Generic/display path for the config source. |
| `mcp_servers` | array | Parsed MCP servers when present. Omitted or empty when not applicable. |
| `evidence` | array | Parse or presence evidence. Omitted or empty when not applicable. |

## MCP server

| Field | Type | Description |
| --- | --- | --- |
| `name` | string | MCP server name from config. |
| `command` | string/null | Command when detected. |
| `args` | array | Command arguments when detected. |
| `env` | array | Environment variable names and redacted value hints. |
| `url` | string/null | URL when detected. |

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
| `evidence` | array | Supporting strings from configuration. |

## Summary

| Field | Type | Description |
| --- | --- | --- |
| `inventory_items` | integer | Number of discovered inventory items. |
| `findings_total` | integer | Number of displayed findings. |
| `high` | integer | Displayed high-severity finding count. |
| `medium` | integer | Displayed medium-severity finding count. |
| `low` | integer | Displayed low-severity finding count. |
| `info` | integer | Displayed info-severity finding count. |

## Stability expectations

- v0.1.x may add optional fields, new finding IDs, and new agent kinds.
- v0.1.x should not remove the documented top-level fields without a schema version bump.
- Finding IDs are intended to be stable for automation.
- Findings are posture risks/hints, not confirmed exploitability.
- The JSON report is scan-only output and does not imply runtime blocking or enforcement.
