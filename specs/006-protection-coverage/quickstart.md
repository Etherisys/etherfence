# Quickstart: Protection Coverage (v1.7.2)

## Using protection coverage

Run a scan with an active policy to see protection coverage:

```bash
# With a policy file
etherfence scan --policy examples/policies/strict.toml

# With a built-in profile
etherfence scan --policy-profile developer-laptop

# JSON output for CI
etherfence scan --policy ci-policy.toml --format json | jq .protection_coverage
```

## What you'll see

The human summary adds a "Protection coverage" section:

```
Security posture
────────────────
Scanned       /home/user
AI clients    3 detected
MCP servers   8 configured
Findings      HIGH: 2 | MEDIUM: 1 | LOW: 1 | INFO: 2
Policy        strict — checks=12, pass=8, violations=2

Clients
───────
✓ Claude Code           3 MCP servers
✓ Cursor                2 MCP servers
✓ VS Code               1 MCP server

Protection coverage
───────────────────
✓ protected    claude-code / filesystem         (~/.claude.json)
✓ protected    claude-code / memory             (~/.claude.json)
✗ unprotected  claude-code / github             (~/.claude.json)
✓ protected    cursor / filesystem              (~/.cursor/mcp.json)
✗ unprotected  cursor / browser-tools           (~/.cursor/mcp.json)
~ no policy    vscode / lint                    (~/.vscode/mcp.json)

Priority findings
─────────────────
...
```

The JSON output includes:

```json
{
  "protection_coverage": {
    "total_servers": 6,
    "protected": 4,
    "unprotected": 2,
    "no_policy_for_agent": 0,
    "empty_allowlist": 0,
    "not_applicable": 0,
    "servers": [...]
  }
}
```

## When coverage is absent

When no `--policy` or `--policy-profile` is provided, the `protection_coverage`
field is absent from all output formats. The scan output is byte-identical to
v1.6.x.

## Coverage status meanings

| Status | Meaning | What to do |
|---|---|---|
| `protected` | Server is in the policy allowlist | No action needed |
| `unprotected` | Server is NOT in the policy allowlist | Review and either add to allowlist or remove the server |
| `no_policy_for_agent` | No policy section for this AI client | Add a `[agents.<name>]` section to your policy |
| `empty_allowlist` | Agent section exists but allowlist is empty | Add specific server names to `allowed_mcp_servers` |
| `not_applicable` | Coverage not applicable (e.g., Tirith) | N/A |

## CI integration

```yaml
# Example: fail CI if any server is unprotected
- name: Scan with coverage
  run: |
    etherfence scan --policy ci-policy.toml --format json > scan.json
    unprotected=$(jq '.protection_coverage.unprotected' scan.json)
    if [ "$unprotected" -gt 0 ]; then
      echo "ERROR: $unprotected unprotected MCP servers found"
      jq '.protection_coverage.servers[] | select(.status == "unprotected")' scan.json
      exit 1
    fi
```
