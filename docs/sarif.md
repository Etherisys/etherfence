# EtherFence SARIF Output

Status: pre-alpha, scan-only. `etherfence scan --format sarif` emits a SARIF
2.1.0 log so scan results can be uploaded to code-scanning dashboards (for
example GitHub code scanning) or consumed by other SARIF-aware tooling.

SARIF output is a rendering of the same scan results as the human, JSON, and
Markdown formats. It works with normal scans and with `--policy`,
`--policy-profile`, `--baseline`, and `--severity-threshold`. It does not
change scan behavior and does not imply runtime enforcement.

## Usage

```sh
etherfence scan --format sarif > etherfence.sarif
etherfence scan --policy-profile ci-runner --format sarif > etherfence.sarif
etherfence scan --baseline etherfence-baseline.json --format sarif
etherfence scan --severity-threshold high --format sarif
```

## Document shape

- `$schema`: `https://json.schemastore.org/sarif-2.1.0.json`
- `version`: `2.1.0`
- One run with `tool.driver.name = "etherfence"` and the EtherFence package
  version in `tool.driver.version`.

## Rules

Each distinct EtherFence finding ID (for example `EF-MCP-001`, `EF-SEC-001`,
`EF-POL-001`, `EF-CFG-001`) present in the report becomes one SARIF rule:

| SARIF rule field | EtherFence source |
| --- | --- |
| `id` | Finding ID. |
| `name` | PascalCase form of the finding kind. |
| `shortDescription.text` | Finding title. |
| `fullDescription.text` | Finding rationale. |
| `help.text` | Finding impact and recommendation. |
| `defaultConfiguration.level` | Severity mapping below. |

## Severity mapping

| EtherFence severity | SARIF level |
| --- | --- |
| `high` | `error` |
| `medium` | `warning` |
| `low` | `note` |
| `info` | `note` |

## Results

Each displayed finding becomes one SARIF result:

- `ruleId` and `level` follow the finding ID and severity mapping.
- `message.text` combines the finding title, rationale, impact, and
  recommendation.
- `locations[0].physicalLocation.artifactLocation.uri` is the config path the
  finding refers to.
- `locations[0].logicalLocations[0]` names the target (for example the MCP
  server name) and a `agent::target` fully qualified name.
- `partialFingerprints["etherfenceFingerprint/v1"]` carries the deterministic
  EtherFence fingerprint used by baseline/diff mode.
- `properties` carries `agent`, `target`, `configPath`, `etherfenceSeverity`,
  `etherfenceCategory` (`inventory`, `informational`, or `risk`; v1.7.4+ —
  independent of severity, see `docs/json-schema.md`), `baselineStatus`,
  `policyStatus`, `policyId` (policy findings only), and `evidence` (each
  entry a `field=value` string, e.g. `command=bash`, `env=API_KEY`; v1.7.4+
  format, never a secret value).

## Run properties

The run-level `properties` bag carries `etherfenceSchemaVersion`, `status`,
`scannedRoot`, and the report `summary`. When `--policy` or `--policy-profile`
is used, the policy metadata object is included as `policy`; when `--baseline`
is used, the baseline comparison object is included as `baseline`.

## Interaction with other flags

- `--severity-threshold` filters findings before SARIF rendering, so only the
  displayed findings appear as results.
- `--baseline` sets `properties.baselineStatus` on every result (`new`,
  `existing`, or `resolved`) and adds run-level baseline metadata.
- `--policy` / `--policy-profile` add `EF-POL-*` rules/results with
  `properties.policyStatus = "violation"` and `properties.policyId`, plus
  run-level policy metadata.
- `--fail-on` and `--fail-on-new` still control the exit code; the SARIF
  document is printed either way.

Findings are posture risks/hints, not confirmed exploitability.
