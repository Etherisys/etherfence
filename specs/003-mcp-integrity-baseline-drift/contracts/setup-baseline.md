# Contract: `etherfence setup baseline write` / `check`

## CLI surface

```text
etherfence setup baseline write --root <path> --output <file> [--overwrite]
etherfence setup baseline check --root <path> --baseline <file>
    [--format human|json]
    [--fail-on-drift]
    [--fail-on-new]
    [--fail-on-risk-increase]
```

- `--root` (hidden, like every other `setup` subcommand's `--root`):
  defaults to the same platform-appropriate scan root as `setup detect`.
- `write --output` is required; `write` fails (non-zero exit, no file
  written) if `<file>` exists and `--overwrite` is absent.
- `check --baseline` is required; `check` never writes to `<file>`.
- `check --format` defaults to `human`.
- Gate flags default to off; any combination may be passed together.
- Exit code: `0` unless a passed gate's condition is met (see spec
  FR-027–FR-030), in which case the process exits non-zero **after**
  printing the full report.

## `ef-setup-baseline/v0.1` (file written by `write`, read by `check`)

```json
{
  "schemaVersion": "ef-setup-baseline/v0.1",
  "root": "/home/user",
  "servers": [
    {
      "fingerprint": "9f2c...",
      "agent": "Claude Code",
      "configSource": "~/.claude.json",
      "serverName": "filesystem",
      "transport": "stdio",
      "commandFingerprint": "a1b2...",
      "argumentsFingerprint": "c3d4...",
      "packageIdentity": "@modelcontextprotocol/server-filesystem",
      "packageVersionExpression": "exactly-pinned",
      "executablePath": "path-resolved-command",
      "environmentVariableNames": ["NODE_ENV"],
      "capabilityLabels": ["filesystem"],
      "trustIndicators": [],
      "artifactIdentity": "known-source",
      "configurationRisk": "no-known-indicators",
      "aggregate": "known-source",
      "reviewState": "unreviewed"
    }
  ]
}
```

`sha256` is present only when computed (omitted, never `null`, matching
the v1.3.0 `TrustAssessment.sha256` convention).

## `ef-setup-baseline-comparison/v0.1` (`check --format json` output)

```json
{
  "schemaVersion": "ef-setup-baseline-comparison/v0.1",
  "root": "/home/user",
  "entries": [
    {
      "fingerprint": "9f2c...",
      "agent": "Claude Code",
      "configSource": "~/.claude.json",
      "serverName": "filesystem",
      "transport": "stdio",
      "status": "changed",
      "reasons": ["command-changed"],
      "baselineRisk": "known-source",
      "currentRisk": "known-source",
      "riskDirection": "unchanged"
    }
  ]
}
```

`baselineRisk`/`currentRisk` are omitted-not-null (`skip_serializing_if =
"Option::is_none"`) for `new`/`missing` entries respectively, matching the
existing repo convention for optional fields.

## Human output (`check`, default format)

```text
EtherFence setup baseline check
Root: /home/user
Baseline: /home/user/baseline.json
Mode: read-only; the baseline file was not modified.

- Claude Code:filesystem [changed] at ~/.claude.json
  transport=stdio
  reasons: command-changed
  risk: known-source -> known-source (unchanged)

Summary: 1 unchanged, 1 changed, 0 new, 0 missing, 0 unverifiable
```

The trailing summary line is always printed, even when zero servers are
present or when every server is `unchanged`, and even when a gate causes a
non-zero exit (FR-031).

## Human output (`write`)

```text
EtherFence setup baseline write
Root: /home/user
Mode: read-only over the scanned root; wrote a new baseline file.
Wrote baseline (3 servers) to /home/user/baseline.json
```

## Compatibility

- `ef-setup-detect/v0.2` and its command are unchanged by this contract.
- `ef-baseline/v0.1.3` and `ef-scan-report/v0.1.1` (the pre-existing `scan
  --write-baseline`/`--baseline` findings-baseline feature) are unchanged
  and unrelated to this schema family.
- `ef-mcp-policy/v0.1` and `mcp-proxy` behavior are unchanged.
