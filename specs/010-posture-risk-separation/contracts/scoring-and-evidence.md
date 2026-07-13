# Contract: Posture Scoring, Finding Category, and Evidence

## Scoring gate

The posture score, grade, and `PostureSummary.{active_findings,high,medium,low,info,priority_risks,recommended_actions}` are computed **only** over active (non-baseline-resolved) findings whose `category == "risk"`. Findings with `category == "inventory"` or `category == "informational"` are never counted, regardless of their `severity`.

Score formula is unchanged: `score = clamp(100 - 25*count(high) - 10*count(medium) - 2*count(low), 0, 100)`, computed over the risk-category population above. `Info`-severity findings never contribute regardless of category (weight 0 in the formula).

## Finding category assignment (fixed for existing finding IDs)

| Finding ID | `category` | `severity` |
|---|---|---|
| `EF-CFG-001` | `risk` | `low` |
| `EF-MCP-000` | `inventory` | `info` |
| `EF-MCP-001` | `risk` | `high` |
| `EF-MCP-002` | `risk` | `medium` |
| `EF-MCP-003` | `risk` | `medium` |
| `EF-MCP-004` | `inventory` | `info` |
| `EF-SEC-001` | `risk` | `medium` |
| `EF-TIRITH-001` | `informational` | `info` |
| `EF-TIRITH-002` | `informational` | `info` |
| `EF-POL-001` | `risk` | `high` |
| `EF-POL-002` | `risk` | `high` |
| `EF-POL-003` | `risk` | `medium` |
| `EF-POL-004` | `risk` | `high` |
| `EF-POL-005` | `risk` | `high` |

This table is the fixture-backed contract (Principle V): any test asserting a finding's category/severity for these IDs must match this table exactly, and any future new finding ID must be added here before it is described as scoring or non-scoring.

## Evidence format

Every evidence entry (`Finding.evidence: Vec<String>`) is a `field=value` string:

| Field label | Meaning |
|---|---|
| `server=<name>` | The MCP server's configured name matched. |
| `command=<value>` | The server's `command` field matched. |
| `args[<i>]=<value>` | The `i`-th (0-indexed) entry of the server's `args` array matched. |
| `url=<value>` | The server's `url` field matched. |
| `env=<name>` | An environment variable **name** matched (never its value). |

Constraints:
- Evidence never contains a secret/credential *value* — only names and matched patterns/paths. Environment variable values remain redacted to `<set>`/`<empty>` before they ever reach a `Finding` (unchanged, enforced in `etherfence-inventory`).
- Evidence entries are sorted and deduplicated before fingerprinting (unchanged, `finding_fingerprint()`); evidence content changes for `EF-MCP-001/002/003/004` and `EF-SEC-001` change those findings' fingerprints relative to pre-v1.7.4 scans (see Compatibility below).
- Evidence ordering within a single finding is deterministic for identical input (same server, same detector logic → same evidence vector, same order, every run).

## Compatibility

- `ef-scan-report`: `v0.1.2` → `v0.1.3`. Additive `category` field on every `Finding`; severity changes for `EF-MCP-000`/`EF-MCP-004`; evidence format changes for `EF-MCP-001/002/003/004` and `EF-SEC-001`.
- `ef-baseline`: `v0.1.3` → `v0.1.4`. `BaselineFile.findings` embeds full `Finding` structs, so the same shape change applies. `etherfence scan --baseline <old-file>` fails closed with an explicit "unsupported schema_version... regenerate it with `--write-baseline`" error (existing mechanism, unchanged code path) rather than silently mismatching fingerprints.
- JSON consumers that only read fields present before this change (score, grade, severity, evidence-as-strings) continue to work — `category` is additive and evidence stays `Vec<String>`, just with new label content.
- SARIF gains one additive `properties.etherfenceCategory` string per result. SARIF `level` (`error`/`warning`/`note`) mapping is unchanged and remains purely severity-derived.
