# Contract: `etherfence setup detect` trust-assessment extension (`ef-setup-detect/v0.2`)

Extends the `ef-setup-detect/v0.1` contract from `specs/001-agent-catalog-classification/contracts/setup-detect-classification.md` (historical, unmodified). This document covers only the additive `v0.2` delta.

## Schema version

`etherfenceSchemaVersion` changes from `"ef-setup-detect/v0.1"` to `"ef-setup-detect/v0.2"`. This is an additive evolution: every `v0.1` field keeps its name, type, and meaning (FR-074). A consumer that ignores unknown fields continues to work unmodified against `v0.2` output except for the version-string change itself.

## New per-server field: `trustAssessment`

Added alongside the existing `capabilities` and `recommendation` fields on each `servers[]` entry:

```json
{
  "name": "filesystem",
  "transport": "stdio",
  "wrapped": false,
  "capabilities": { "...": "unchanged from v0.1" },
  "recommendation": { "...": "unchanged from v0.1" },
  "trustAssessment": {
    "artifactIdentity": "verified-local",
    "configurationRisk": "no-known-indicators",
    "aggregate": "verified-local",
    "needsReview": false,
    "invocation": {
      "applicable": true,
      "runner": "npx",
      "packageIdentity": "@modelcontextprotocol/server-filesystem",
      "versionExpression": "exactly-pinned",
      "malformedRunnerInvocation": false
    },
    "executablePath": "absolute-path",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "indicators": []
  }
}
```

| Field | Type | Description |
| --- | --- | --- |
| `trustAssessment.artifactIdentity` | string | `verified-local`, `known-source`, or `unknown`. |
| `trustAssessment.configurationRisk` | string | `no-known-indicators`, `needs-review`, or `high-risk`. |
| `trustAssessment.aggregate` | string | `verified-local`, `known-source`, `needs-review`, `high-risk`, or `unknown` — derived per the configuration-risk-first rule (FR-061). |
| `trustAssessment.needsReview` | boolean | `true` iff `aggregate` is `needs-review`, `high-risk`, or `unknown` (FR-062). |
| `trustAssessment.invocation.applicable` | boolean | `false` only for remote/URL-configured servers (FR-057b); all other `invocation` sub-fields are omitted when `false`. |
| `trustAssessment.invocation.runner` | string, omitted if absent | `npx`, `uvx`, or `pipx-run`, when a supported package-runner invocation is recognized. |
| `trustAssessment.invocation.packageIdentity` | string, omitted if absent | Parsed package identity (no version suffix). |
| `trustAssessment.invocation.versionExpression` | string, omitted if absent | `exactly-pinned`, `omitted`, `mutable-tag`, `version-range`, or `unsupported-or-ambiguous`. |
| `trustAssessment.invocation.malformedRunnerInvocation` | boolean | `true` when a recognized runner's argument shape could not be parsed into a package identity at all (FR-019). |
| `trustAssessment.invocation.shellWrapper` | string, omitted if absent | One of the 7 `ShellWrapperKind` tokens (e.g. `bash-c`, `powershell-encoded-command`). |
| `trustAssessment.invocation.obscuredLaunchPatterns` | array of string, omitted/empty if none | Zero or more of the 5 `ObscuredLaunchPattern` tokens. |
| `trustAssessment.executablePath` | string | One of 9 `ExecutablePathClassification` tokens (see data-model.md); `not-applicable` for remote servers. |
| `trustAssessment.sha256` | string, omitted if absent | Present **only** when `artifactIdentity == "verified-local"`; a lowercase hex SHA-256 digest of the inspected executable. Never present otherwise — omitted, never `null`. |
| `trustAssessment.indicators` | array | **Always present**, `[]` when no indicator fired (FR-068) — never omitted, unlike `capabilities.evidence`. |

### Indicator object shape

```json
{
  "id": "EF-TRUST-PIN-002",
  "severity": "medium",
  "category": "package-pinning",
  "summary": "npx package version is omitted",
  "rationale": "The npx invocation for '@modelcontextprotocol/server-filesystem' does not pin an exact version, so the resolved package may change on a future run.",
  "evidence": [
    { "key": "runner", "value": "npx" },
    { "key": "package-identity", "value": "@modelcontextprotocol/server-filesystem" },
    { "key": "version-expression", "value": "omitted" }
  ],
  "remediation": "Pin an exact version, e.g. '@modelcontextprotocol/server-filesystem@<version>'."
}
```

| Field | Type | Description |
| --- | --- | --- |
| `id` | string | Stable indicator ID, e.g. `EF-TRUST-PIN-002`. |
| `severity` | string | `info`, `low`, `medium`, or `high` — reuses the existing `ef-scan-report` severity vocabulary (`etherfence_core::Severity`), not a new scale. |
| `category` | string | One of the 7 `IndicatorCategory` tokens. |
| `summary` | string | Concise human-readable finding statement. |
| `rationale` | string | Why this was flagged. |
| `evidence` | array, omitted/empty if none | `EvidenceField{key, value}` pairs — structured, safe tokens only (never raw command strings, env values, or file content). |
| `remediation` | string | Suggested review/remediation step. |

### Remote (non-stdio) server example

```json
{
  "name": "hosted-docs",
  "transport": "remote",
  "wrapped": false,
  "capabilities": { "labels": ["unknown"] },
  "recommendation": { "tier": "deny", "needsReview": true, "rationale": "..." },
  "trustAssessment": {
    "artifactIdentity": "unknown",
    "configurationRisk": "no-known-indicators",
    "aggregate": "unknown",
    "needsReview": true,
    "invocation": { "applicable": false },
    "executablePath": "not-applicable",
    "indicators": []
  }
}
```

Note `sha256` is omitted (never `null`), `invocation` carries only `applicable: false` (every other `invocation` field omitted), and `executablePath` is the explicit `not-applicable` token — never `unknown`, which is reserved for "a local path was assessed and nothing could be established."

## Determinism (FR-075–FR-079)

- Server ordering and indicator ordering within a server are both unchanged/newly-deterministic respectively — servers keep their existing v0.1 ordering; indicators sort per the fixed `(category, id)` order in research.md Decision 13.
- Given identical local input state and an unchanged EtherFence version, repeated `etherfence setup detect --format json` output is byte-identical, including `trustAssessment`.
- All new enum values use the same kebab-case `Serialize` token convention already established by `CapabilityLabel` — verified by the same style of exact-string assertion test used in `classification.rs`'s `json_labels_are_kebab_case_and_human_label_is_friendly_phrasing` test.

## Compatibility

- `capabilities` and `recommendation` objects are byte-for-byte unchanged from `v0.1` (FR-074).
- `etherfence setup catalog` (`ef-setup-catalog/v0.1`) is entirely unaffected (FR-090).
- `setup plan`/`setup doctor` human output is unchanged (FR-004/FR-089).
- Human-readable `etherfence setup detect` (no `--format json`) output gains additive lines per server (mirroring the v1.2.0 `capabilities:`/`recommendation:` line precedent) — existing lines are preserved unchanged and in order; this is **not** byte-identical to `v0.2`'s predecessor human output for the same reason `v0.1` wasn't byte-identical to pre-v1.2.0 output (documented honestly, not claimed as unchanged).
