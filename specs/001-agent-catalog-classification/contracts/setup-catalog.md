# Contract: `etherfence setup catalog`

## CLI surface

```text
etherfence setup catalog [--format human|json] [--root <path>]
```

- `--format` (optional, default `human`): `human` or `json`.
- `--root` (hidden, existing convention shared with `detect`/`plan`/
  `apply`/`rollback`/`doctor`): overrides the scan root; intended for
  tests and controlled onboarding, defaults to `HOME`.
- Read-only: never creates, modifies, or deletes any file (FR-005).
- Never performs network access (FR-006).
- Always exits `0` on success; no `--fail-on` flag exists in v1.2.0
  (FR-006a).

## JSON schema: `ef-setup-catalog/v0.1`

```json
{
  "etherfenceSchemaVersion": "ef-setup-catalog/v0.1",
  "root": "/home/user",
  "clients": [
    {
      "client": "claude-style-config",
      "tier": "fixture-verified",
      "foundLocally": true,
      "configPaths": ["/home/user/.claude.json"]
    },
    {
      "client": "cursor",
      "tier": "fixture-verified",
      "foundLocally": false,
      "configPaths": []
    },
    {
      "client": "vs-code",
      "tier": "fixture-verified",
      "foundLocally": false,
      "configPaths": []
    },
    {
      "client": "hermes",
      "tier": "advisory-only",
      "foundLocally": false,
      "configPaths": []
    },
    {
      "client": "antigravity",
      "tier": "advisory-only",
      "foundLocally": false,
      "configPaths": []
    },
    {
      "client": "windsurf",
      "tier": "detect-only",
      "foundLocally": false,
      "configPaths": []
    },
    {
      "client": "gemini-cli",
      "tier": "detect-only",
      "foundLocally": false,
      "configPaths": []
    },
    {
      "client": "codex-cli",
      "tier": "detect-only",
      "foundLocally": false,
      "configPaths": []
    },
    {
      "client": "open-code",
      "tier": "advisory-only",
      "foundLocally": false,
      "configPaths": []
    },
    {
      "client": "cline-roo-code",
      "tier": "advisory-only",
      "foundLocally": false,
      "configPaths": []
    }
  ]
}
```

**Field notes**:
- `clients` always has exactly 10 entries, in the fixed order shown above
  (FR-001, FR-004) — this array order is itself part of the contract and
  MUST NOT be re-sorted by tier, name, or presence.
- `client`, `tier` values are the `kebab-case`-serialized enum variants
  from data-model.md.
- `configPaths` is an empty array (not omitted, not `null`) when
  `foundLocally` is `false`; contains one entry per discovered
  configuration path when `true` (a client may have more than one, e.g.
  a global and a project-level config — see spec Edge Cases). When more
  than one path is found, they are listed in `etherfence_inventory
  ::discover()`'s existing order (the fixed `CANDIDATES` table
  declaration order for that agent) — never re-sorted alphabetically or
  by filesystem-returned order. See `tests/fixtures/multi-path-home/`
  (a Cursor config present at both `.cursor/mcp.json` and
  `.cursor/settings.json`) and data-model.md `CatalogEntry` "Multi-path
  ordering."
- Determinism: for an unchanged local input, every field and array order
  above is byte-identical across repeated runs and across Linux/Windows
  (FR-020). Path *values* are platform-native (`Path::display()`); only
  their use as a *sort key* is normalized (research.md Decision 4) — so
  `configPaths` entries are OS-native strings, not forced to one
  separator style.

## Human output (illustrative shape, not a byte-for-byte contract)

```text
EtherFence setup catalog
Root: /home/user
Mode: read-only; no configs, policies, backups, or state were modified.

Client                Tier               Found  Config path(s)
Claude-style config    fixture-verified   yes    /home/user/.claude.json
Cursor                 fixture-verified   no     -
VS Code                fixture-verified   no     -
Hermes                 advisory-only      no     -
Antigravity            advisory-only      no     -
Windsurf               detect-only        no     -
Gemini CLI              detect-only        no     -
Codex CLI               detect-only        no     -
OpenCode                advisory-only      no     -
Cline / Roo Code        advisory-only      no     -
```

The human format's exact column widths/spacing are not contractually
fixed (unlike the JSON schema); its *row set, row order, and field
values* are (SC-002 applies to both formats via FR-020a).
