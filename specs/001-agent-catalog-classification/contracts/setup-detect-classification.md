# Contract: `etherfence setup detect` (extended with classification)

## CLI surface

```text
etherfence setup detect [--format human|json] [--root <path>]
```

- `--format` (**new** optional flag, default `human`): `human` or `json`.
  Omitting it is **not** byte-identical to pre-v1.2.0 output: every
  pre-v1.2.0 line is preserved unchanged (none removed, none reworded,
  none reordered), and two new lines (`capabilities: ...`,
  `recommendation: ...`) are appended per server. A script that consumes
  `setup detect`'s human output by looking for specific pre-existing lines
  is unaffected; a script that assumes the *total* line count or exact
  byte length of output per server is not preserved MUST switch to
  `--format json` (constraint: "Preserve existing CLI behavior" means
  "do not remove or change existing lines," not "emit identical bytes").
- `--root`: unchanged, existing hidden flag.
- Read-only, no network access: unchanged existing guarantees.

## JSON schema: `ef-setup-detect/v0.1`

This is the **first** JSON output `setup detect` has ever had (previously
human-text-only), so it is an additive new schema, not a breaking change
to an existing one.

```json
{
  "etherfenceSchemaVersion": "ef-setup-detect/v0.1",
  "root": "/home/user",
  "detections": [
    {
      "agent": "Claude Code",
      "configPath": "/home/user/.claude.json",
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
          }
        },
        {
          "name": "shell-tools",
          "transport": "stdio",
          "wrapped": false,
          "capabilities": {
            "labels": ["shell-command-execution"],
            "evidence": [
              "command 'shell-mcp-server' matched shell / command execution rule"
            ]
          },
          "recommendation": {
            "tier": "deny",
            "needsReview": true,
            "rationale": "denied by default; flagged for review because capability includes shell / command execution"
          }
        }
      ],
      "notes": []
    }
  ]
}
```

**Field notes**:
- `detections[].servers[].capabilities.labels` is never empty; contains
  exactly `["unknown"]` when no curated rule matched (FR-013). Label
  values are always the `kebab-case` `Serialize` token (e.g.
  `"shell-command-execution"`, `"identity-auth"`, `"saas-api"`) — see
  data-model.md `CapabilityLabel` "JSON vs. human representation." Free-
  text fields (`evidence`, `rationale`) may use the friendlier spec-
  taxonomy phrasing (e.g. "shell / command execution") since they are
  human-readable prose, not machine-matched enum values.
- `detections[].servers[].recommendation.tier` is always `"deny"` in
  v1.2.0 (research.md Decision 3); the `"allow"` value is reserved in the
  schema for a future release and MUST NOT appear in v1.2.0 output —
  covered by a negative test (see quickstart.md).
- All pre-existing fields (`agent`, `configPath`, `writeSupport`,
  `servers[].name/transport/wrapped`, `notes`) are unchanged in name,
  type, and meaning from the existing `SetupDetection`/`SetupServer`
  structs; this is a pure additive extension.

## Human output (illustrative; additive lines only)

Existing lines (unchanged):

```text
EtherFence setup detect
Root: /home/user
Mode: read-only; no configs, policies, backups, or state were modified.
- Claude Code [write-supported] at /home/user/.claude.json
  - filesystem transport=stdio wrapped=false
```

New lines appended per server (does not alter any existing line). Human
output uses `CapabilityLabel::human_label()` (friendly phrasing), never
the JSON `kebab-case` token:

```text
    capabilities: filesystem
    starter policy: deny — denied by default; no
      fixture-verified allow rule exists for this capability set
```

```text
    capabilities: shell / command execution
    starter policy: deny — denied by default;
      flagged for review because capability includes shell / command
      execution
```

v1.5.0 renamed the human-output labels without changing semantics:
`recommendation:` became `starter policy:` (dropping the separate
`needs-review` field from the recommendation line — the recommendation
tier is always `deny`, and the rationale explains why), and the trust
assessment line uses `review-needed` instead of `needs-review` to avoid
confusion with the capability-label-based review flag. JSON schemas are
unaffected.

## Contract test obligations (see quickstart.md for runnable steps)

1. Running `setup detect` with no `--format` flag on an existing fixture
   home produces every pre-v1.2.0 line unchanged, in the same order, with
   two new lines (`capabilities: ...`, `starter policy: ...`) appended per
   server — never a removed or reordered pre-existing line. The overall
   output is **not** byte-identical to the pre-v1.2.0 baseline (it is
   strictly longer); only `setup plan`/`setup doctor` (item 3 below) are
   byte-identical.
2. `setup detect --format json` output validates against the field shape
   above; `recommendation.tier` is `"deny"` for every server in every
   checked-in fixture.
3. `setup plan` and `setup doctor` output (both human-only, unchanged) is
   byte-identical to their pre-v1.2.0 fixtures — proving the additive
   `SetupServer` fields do not leak into commands that don't render them.
