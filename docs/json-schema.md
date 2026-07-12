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
| `status` | string | stable | Scan command status, currently `stable-local-scan`. |
| `scanned_root` | string | stable | Root used for conservative config discovery. |
| `inventory` | array | additive | Discovered agent config inventory. |
| `findings` | array | additive | Displayed findings after severity threshold and optional baseline comparison. |
| `summary` | object | stable | Counts for displayed findings and inventory items. |
| `posture` | object/null | optional, additive | Deterministic advisory score, grade, assessment, active counts, up to three priority risks, and linked next actions derived from displayed active findings. |
| `policy` | object/null | optional | Policy evaluation metadata when `--policy` or `--policy-profile` is used. |
| `baseline` | object/null | optional | Baseline comparison metadata when `--baseline` is used. |

## Additive posture summary (v1.7.0)

`posture` is an optional additive object in the unchanged `ef-scan-report/v0.1.1` contract. v1.7.0 scans populate it; consumers that read the pre-v1.7.0 fields remain compatible by ignoring it. It is local, read-only, advisory prioritization: it neither remediates findings nor proves that a host is secure.

| Field | Type | Description |
| --- | --- | --- |
| `score` | integer | Inclusive 0–100 score: `max(0, 100 - 25*high - 10*medium - 2*low)` over active displayed findings. Info findings do not reduce the score. |
| `grade` | string | `a`, `b`, `c`, `d`, or `f`: 90–100, 75–89, 55–74, 30–54, and 0–29 respectively. |
| `assessment` | string | Deterministic advisory interpretation of the score/grade. |
| `active_findings`, `high`, `medium`, `low`, `info` | integer | Counts after excluding `baseline_status: "resolved"`. These counts use the same displayed-finding selection as the report. |
| `priority_risks` | array | At most three active risks, sorted by severity descending, then finding ID, target, agent key, and fingerprint. Each has `finding_id`, `severity`, `title`, `agent`, `target`, `fingerprint`, and `why_this_matters` (the finding's existing impact text). |
| `recommended_actions` | array | One existing recommendation per priority risk, in the same order, with `finding_id` and `recommendation`. |

Resolved baseline entries remain in the existing report evidence but never lower `score` or consume a priority/action slot. `--severity-threshold` continues to define which findings are displayed; posture describes that output and does not affect detector behavior, baselines, `--fail-on`, `--fail-on-new`, or exit codes. SARIF and baseline-file schemas are unchanged.

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

## `etherfence setup catalog` schema (`ef-setup-catalog/v0.1`)

`etherfence setup catalog --format json` (v1.2.0) emits the fixed 10-client
compatibility/catalog matrix. It is read-only, local-only, and always
exits `0`.

| Field | Type | Description |
| --- | --- | --- |
| `etherfenceSchemaVersion` | string | `ef-setup-catalog/v0.1`. |
| `root` | string | Root directory used for local presence detection. |
| `clients` | array | Always exactly 10 entries, in the fixed declared order below. Never re-sorted by tier, name, or presence. |

Each `clients[]` entry:

| Field | Type | Description |
| --- | --- | --- |
| `client` | string | One of: `claude-style-config`, `cursor`, `vs-code`, `hermes`, `antigravity`, `windsurf`, `gemini-cli`, `codex-cli`, `open-code`, `cline-roo-code` (this is also the fixed row order). |
| `tier` | string | `fixture-verified`, `detect-only`, `advisory-only`, or `unknown`. A statement of detection confidence, distinct from the `WriteSupport` enum used by `setup apply` — see `docs/setup-onboarding.md` "Catalog tier vs. write support". |
| `foundLocally` | boolean | Whether this client's configuration was found on the current run. |
| `configPaths` | array of string | Always present, even when empty (`[]`, never omitted or `null`) when `foundLocally` is `false`. One entry per discovered configuration path, in `etherfence_inventory::discover()`'s existing declared order — never re-sorted. |

Example:

```json
{
  "etherfenceSchemaVersion": "ef-setup-catalog/v0.1",
  "root": "/home/user",
  "clients": [
    {
      "client": "claude-style-config",
      "tier": "fixture-verified",
      "foundLocally": true,
      "configPaths": ["~/.claude.json"]
    },
    {
      "client": "cursor",
      "tier": "fixture-verified",
      "foundLocally": false,
      "configPaths": []
    }
  ]
}
```

## `etherfence setup detect` schema (`ef-setup-detect/v0.2`)

`etherfence setup detect --format json` (v1.2.0) is the first JSON output
`setup detect` has ever had — an additive new schema, not a change to an
existing one. Omitting `--format` is **not** byte-identical to pre-v1.2.0
human-text output: every pre-v1.2.0 line is preserved unchanged and in the
same order (nothing removed or reworded), and two new lines
(`capabilities: ...`, `starter policy: ...`) are appended per server —
scripts matching on specific pre-existing lines are unaffected, but the
total output is longer than before. `setup plan` and `setup doctor`
remain byte-identical to their pre-v1.2.0 output; only `setup detect`'s
default human output gained lines.

v1.3.0 additively bumps this schema to `ef-setup-detect/v0.2`: every
`capabilities`/`recommendation` field above keeps its exact name, type,
and meaning, and one new field, `trustAssessment`, is added per server
(see "Trust and integrity assessment" below). Human output gains two more
lines per server (`trust assessment: ...`, `trust indicators: ...`), appended after
the existing `starter policy:` line — again additive, not
byte-identical to pre-v1.3.0 output.

| Field | Type | Description |
| --- | --- | --- |
| `etherfenceSchemaVersion` | string | `ef-setup-detect/v0.2`. |
| `root` | string | Root directory used for detection. |
| `detections` | array | One entry per detected client config. |

Each `detections[]` entry:

| Field | Type | Description |
| --- | --- | --- |
| `agent` | string | Agent display name, e.g. `Claude Code`. |
| `configPath` | string | Discovered configuration path. |
| `writeSupport` | string | `supported` or `advisory-only` (unchanged from pre-v1.2.0 `setup detect`). |
| `servers` | array | MCP servers configured for this client. |
| `notes` | array of string | Additional context; omitted when empty. |

Each `servers[]` entry:

| Field | Type | Description |
| --- | --- | --- |
| `name` | string | MCP server name. |
| `transport` | string | `stdio`, `remote`, or `unknown` (unchanged). |
| `wrapped` | boolean | Whether the server is already wrapped by `etherfence mcp-proxy` (unchanged). |
| `capabilities.labels` | array of string | Never empty. `kebab-case` capability tokens from the fixed taxonomy — `unknown`, `shell-command-execution`, `identity-auth`, `security-tooling`, `database`, `messaging-collaboration`, `saas-api`, `network`, `browser`, `filesystem` — derived purely from static, local server `command`/`args` matching a small curated signature table (no network access, no process start, no MCP protocol call). Exactly `["unknown"]` when no curated rule matches. |
| `capabilities.evidence` | array of string | One human-readable note per matched rule; omitted/empty when `labels` is `["unknown"]`. |
| `recommendation.tier` | string | Always `"deny"` in v1.2.0. `"allow"` is reserved in the schema for a future release and never appears in v1.2.0 output. |
| `recommendation.needsReview` | boolean | `true` when `capabilities.labels` contains `unknown`, `shell-command-execution`, or `identity-auth`; `false` otherwise. |
| `recommendation.rationale` | string | Short, deterministic, generated explanation naming the label(s) that drove the decision. |

### `servers[].trustAssessment` (v1.3.0)

Static, local-only trust-and-integrity assessment. It never proves a server is safe, trusted, certified, malware-free, benign, or definitively malicious — see `docs/setup-onboarding.md` for the full limiting
language. `recommendation.tier` above stays `"deny"` regardless of any
value here; this feature never produces an `"allow"` recommendation.

| Field | Type | Description |
| --- | --- | --- |
| `trustAssessment.artifactIdentity` | string | `verified-local` (a specific local regular file was hashed under bounded, race-safe conditions), `known-source` (an exact curated identity match — not proof of authenticity/provenance/safety), or `unknown`. |
| `trustAssessment.artifactIdentityRationale` | string | **Always present.** Deterministic explanation of why `artifactIdentity` holds its value. For a remote/URL-configured server this explicitly states "no local invocation to assess," distinct from a stdio server's `unknown`, which means a local inspection ran but was inconclusive. |
| `trustAssessment.configurationRisk` | string | `no-known-indicators` (no implemented indicator triggered — not an absence-of-risk guarantee), `needs-review`, or `high-risk`. |
| `trustAssessment.aggregate` | string | `verified-local`, `known-source`, `needs-review`, `high-risk`, or `unknown` — derived by the configuration-risk-first rule: `configurationRisk` of `high-risk`/`needs-review` always wins; `artifactIdentity` only surfaces to the aggregate when `configurationRisk` is `no-known-indicators`. Both underlying fields are always reported separately regardless of which one determined the aggregate. |
| `trustAssessment.needsReview` | boolean | `true` iff `aggregate` is `needs-review`, `high-risk`, or `unknown`. |
| `trustAssessment.invocation.applicable` | boolean | `false` only for remote/URL-configured servers, which have no local invocation to assess; every other `invocation` field is then omitted. |
| `trustAssessment.invocation.runner` | string, omitted if absent | `npx`, `uvx`, or `pipx-run`, when recognized. |
| `trustAssessment.invocation.packageIdentity` / `.versionExpression` | string, omitted if absent | Parsed package identity and its pinning classification (`exactly-pinned`, `omitted`, `mutable-tag`, `version-range`, or `unsupported-or-ambiguous`). |
| `trustAssessment.invocation.malformedRunnerInvocation` | boolean | `true` when a recognized runner's arguments could not be parsed into a package identity at all. |
| `trustAssessment.invocation.shellWrapper` | string, omitted if absent | One of `sh-c`, `bash-c`, `cmd-c`, `powershell-command`, `powershell-encoded-command`, `pwsh-command`, `pwsh-encoded-command`. |
| `trustAssessment.invocation.obscuredLaunchPatterns` | array of string, omitted/empty if none | Zero or more of `pipe-to-shell-downloader`, `encoded-powershell-option`, `windows-certutil-download-pattern`, `powershell-web-request-to-invoke-expression`, `decode-then-execute-piped-to-shell` — a fixed, closed set. |
| `trustAssessment.executablePath` | string | `absolute-path`, `relative-path`, `path-resolved-command`, `missing-path`, `non-regular-file`, `symlink`, `ambiguous-or-unsupported`, or `not-applicable` (remote servers). A path may also carry a separate `temporary-directory-location` indicator (see below) alongside its primary classification. |
| `trustAssessment.sha256` | string, omitted if absent | Lowercase hex SHA-256 digest. Present **only** when `artifactIdentity == "verified-local"` — omitted, never `null`, otherwise. |
| `trustAssessment.indicators` | array | **Always present**, `[]` when empty — unlike `capabilities.evidence`, this is never omitted. |

Each `indicators[]` entry: `id` (stable, e.g. `EF-TRUST-PIN-001`), `severity` (`info`/`low`/`medium`/`high`, reusing the same scale as `ef-scan-report` findings), `category` (one of `obscured-launch`, `shell-wrapper`, `package-pinning`, `executable-path`, `local-artifact`, `unicode-identity`, `environment-variable`), `summary`, `rationale`, `evidence` (array of `{key, value}` safe structured tokens — never raw command strings, environment values, or file content), and `remediation`. Indicators are sorted deterministically by `(category, id)`.

Example:

```json
{
  "etherfenceSchemaVersion": "ef-setup-detect/v0.2",
  "root": "/home/user",
  "detections": [
    {
      "agent": "Claude Code",
      "configPath": "~/.claude.json",
      "writeSupport": "supported",
      "servers": [
        {
          "name": "filesystem",
          "transport": "stdio",
          "wrapped": false,
          "capabilities": {
            "labels": ["filesystem"],
            "evidence": [
              "command 'npx' arg '@modelcontextprotocol/server-filesystem' matched filesystem rule"
            ]
          },
          "recommendation": {
            "tier": "deny",
            "needsReview": false,
            "rationale": "denied by default; no fixture-verified allow rule exists for this capability set"
          },
          "trustAssessment": {
            "artifactIdentity": "known-source",
            "artifactIdentityRationale": "This server's parsed package identity is an exact match against a small curated known-source table. This does not prove package authenticity, provenance, installation integrity, or safety.",
            "configurationRisk": "no-known-indicators",
            "aggregate": "known-source",
            "needsReview": false,
            "invocation": {
              "applicable": true,
              "runner": "npx",
              "packageIdentity": "@modelcontextprotocol/server-filesystem",
              "versionExpression": "exactly-pinned",
              "malformedRunnerInvocation": false
            },
            "executablePath": "path-resolved-command",
            "indicators": []
          }
        }
      ],
      "notes": []
    }
  ]
}
```

`ef-setup-catalog/v0.1` and `ef-setup-detect/v0.2` are posture/
classification/starter-policy/trust-assessment guidance only — they never
imply runtime blocking, interception, or enforcement, and no `--fail-on`
flag exists for either command.

## `etherfence setup baseline write` schema (`ef-setup-baseline/v0.1`)

New, additive schema (v1.4.0) — does not change `ef-setup-detect/v0.2`.
Written by `setup baseline write`, read (never written) by `setup baseline
check`. See `docs/setup-onboarding.md` for the full safety boundary.

| Field | Type | Description |
| --- | --- | --- |
| `schemaVersion` | string | `ef-setup-baseline/v0.1`. |
| `root` | string | Root directory scanned to produce this baseline. |
| `servers` | array | One entry per discovered MCP server, sorted by `(agentKind, configSource, serverName, transport)`. |

Each `servers[]` entry:

| Field | Type | Description |
| --- | --- | --- |
| `fingerprint` | string | SHA-256 hex identity fingerprint. Derived from a canonical JSON-array encoding of `agentKind`+`configSource`+`serverName` (never a delimiter-joined string — see below), and never transport (see below), and never the human-facing `agent` display name. |
| `agentKind` | string | Stable machine identifier for the client (`AgentKind::key()`, e.g. `"vs-code"`, `"claude-code"`) — this, not `agent`, is one of the fingerprint's three inputs, so a future rewording of the display name can never change identity or produce spurious `new`/`missing` drift. |
| `agent` | string | Human-facing display name (e.g. `"VS Code"`). Presentation only — never used for identity, matching, or fingerprinting. |
| `configSource` | string | Normalized config-source path (same convention as `setup detect`'s `configPath`). |
| `serverName` | string | MCP server name. |
| `transport` | string | `stdio`, `remote`, or `unknown`. Deliberately excluded from the fingerprint so a transport change is reported as `transport-changed` drift rather than making the server unrecognizable across runs. |
| `commandFingerprint` / `argumentsFingerprint` | string, omitted if not applicable | SHA-256 hex of the raw command string / a canonical JSON-array encoding of the argument list — **never the raw text itself**. The argument fingerprint hashes a JSON array (`serde_json::to_vec`), not a delimiter-joined string: a plain join cannot distinguish `[]` from `[""]`, or `["a","b"]` from a single element containing a separator character, since arguments are arbitrary operator-controlled strings with no excluded characters. Omitted for remote/URL-configured servers. |
| `packageIdentity` / `packageVersionExpression` | string, omitted if absent | Same parsed package identity/version-expression classification as `ef-setup-detect/v0.2`'s `trustAssessment.invocation` fields — never the raw version text. |
| `executablePath` | string | Same classification as `ef-setup-detect/v0.2`'s `trustAssessment.executablePath`. |
| `sha256` | string, omitted if absent | Same as `ef-setup-detect/v0.2`'s `trustAssessment.sha256`. |
| `environmentVariableNames` | array of string | Sorted, deduplicated variable **names only** — values are never persisted. |
| `capabilityLabels` | array of string | Sorted, deduplicated `capabilities.labels` tokens. |
| `trustIndicators` | array | Sorted by `id`. Each entry: `id`, `category`, `severity` only — no narrative `summary`/`rationale`/`evidence`/`remediation` text. |
| `artifactIdentity` / `configurationRisk` / `aggregate` | string | Same vocabulary as `ef-setup-detect/v0.2`'s `trustAssessment` fields. |
| `reviewState` | string | Always `unreviewed` in v1.4.0 — no command changes this field; present for forward-compatible extension only. |

## `etherfence setup baseline check` schema (`ef-setup-baseline-comparison/v0.1`)

New, additive schema (v1.4.0). Produced by `setup baseline check --format
json`; the same information is rendered as human text by default.

| Field | Type | Description |
| --- | --- | --- |
| `schemaVersion` | string | `ef-setup-baseline-comparison/v0.1`. |
| `root` | string | Root directory scanned for the current comparison. |
| `entries` | array | One entry per server identity found in the union of baseline and current state, sorted by `(agentKind, configSource, serverName, transport)`. |

Each `entries[]` entry:

| Field | Type | Description |
| --- | --- | --- |
| `fingerprint` / `agentKind` / `agent` / `configSource` / `serverName` / `transport` | — | Same meaning as the baseline schema above. |
| `status` | string | `unchanged`, `new`, `changed`, `missing`, or `unverifiable`. |
| `reasons` | array of string | Closed, deterministic drift-reason set (see below), sorted by a fixed canonical order — never insertion order. `["server-added"]` for `new`, `["server-removed"]` for `missing`, `[]` for `unchanged`. |
| `baselineRisk` / `currentRisk` | string, omitted if not applicable | The `aggregate` value from the baseline/current side respectively. Omitted for `new` (`baselineRisk`) or `missing` (`currentRisk`). |
| `riskDirection` | string | `increased`, `decreased`, `unchanged`, or `not-applicable` (for `new`/`missing` entries). |

The closed drift-reason enum: `executable-hash-changed`, `command-changed`,
`arguments-changed`, `package-identity-changed`, `package-version-changed`,
`environment-variable-names-changed`, `transport-changed`, `server-added`,
`server-removed`, `capability-set-changed`, `trust-indicator-set-changed`,
`artifact-identity-changed`, `configuration-risk-changed`, `risk-increased`,
`executable-became-unverifiable`. No other value may appear without a
schema version bump. `configuration-risk-changed` fires whenever
`configurationRisk` itself differs between baseline and current, in either
direction — a defense-in-depth signal independent of the `trustIndicators`
comparison (which itself compares the full `(id, category, severity)`
tuple, not id alone) and of `risk-increased` (which only fires on an
*increase* in the aggregate rank); this guarantees a configuration-risk
change is never silently folded into `unchanged`.

`--fail-on-drift`/`--fail-on-new`/`--fail-on-risk-increase` gate the
process exit code only — they never change the rendered report, which is
always printed in full first. A risk *decrease* is always visible in
`reasons`/`riskDirection` but never satisfies `--fail-on-risk-increase` by
itself. `check` never writes to `--baseline` under any circumstance: it
opens the file with symlink-following refused (a pre-open `symlink_metadata`
check plus, on Unix, `O_NOFOLLOW` at the actual open, closing the race
between the two) and validates the parsed document's internal consistency
(fingerprints match their own identity fields, no duplicate fingerprints,
well-formed `sha256` values, sorted/deduplicated set fields, and
`aggregate` consistent with `artifactIdentity`/`configurationRisk`) before
ever comparing against it — a hand-edited or corrupted baseline fails
closed rather than producing a misleading comparison. `write` without
`--overwrite` uses atomic exclusive file creation (never a separate
existence-check-then-write), so a file that appears at `--output` between
two operations can never be silently overwritten, and a pre-existing
symlink at that path is refused rather than written through.

## Stability expectations

- v0.1.x may add optional fields, new finding IDs, and new agent kinds.
- v0.1.x should not remove the documented top-level report fields without a schema version bump.
- Finding IDs and fingerprints are intended to be stable for automation when the underlying issue is unchanged.
- Findings are posture risks/hints, not confirmed exploitability.
- Policy, baseline, and report JSON are scan-only outputs and do not imply runtime blocking or enforcement.
- `ef-setup-catalog/v0.1` and `ef-setup-detect/v0.2` are additive, independently versioned schemas for the `setup` command family and do not alter the `ef-scan-report`/`ef-baseline`/`ef-mcp-policy` schemas above.
- `ef-setup-detect/v0.2`'s `trustAssessment` fields never imply a server is proven safe, trusted, certified, malware-free, benign, or that it has no malicious behavior — see `docs/setup-onboarding.md` for the full limiting language.
