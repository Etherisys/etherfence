# Quickstart: Guided Setup

## For new users

Run the guided setup wizard:

```bash
etherfence setup
```

The wizard will:
1. **Scan** your system for installed AI clients (Claude Code, Cursor, VS Code, Hermes, OpenCode, Antigravity, etc.)
2. **Show** what was found — which clients are installed, configured, and have MCP servers
3. **Let you select** which clients and MCP servers to protect
4. **Flag issues** — missing package versions, high-risk launch patterns
5. **Help you resolve** blockers before proceeding
6. **Generate safe policies** — deny-by-default, never wildcard allow-all
7. **Preview** every change before writing
8. **Apply** with one explicit confirmation

After setup, your MCP servers are wrapped through `etherfence mcp-proxy` with safe starter policies. You can refine policies later with `etherfence mcp-policy`.

## For CI and scripting

The guided wizard needs a terminal. For non-interactive use, the existing subcommands remain available:

```bash
# Discover what's installed
etherfence setup detect
etherfence setup catalog

# Plan changes without applying
etherfence setup plan

# Apply wrapping
etherfence setup apply

# Check health
etherfence setup doctor

# Manage integrity baselines
etherfence setup baseline write --output baseline.json
etherfence setup baseline check --baseline baseline.json
```

## What setup does NOT do

- ❌ Start MCP servers or AI clients
- ❌ Install or download packages
- ❌ Contact registries (npm, PyPI) by default
- ❌ Expose secrets, API keys, or env values
- ❌ Modify unsupported client configs
- ❌ Overwrite user edits during rollback

## What version pinning means

Package-runner MCP servers (npx, uvx, pipx run) must have exact versions. The wizard flags and helps you pin:

| ❌ Blocked | ✅ Accepted |
|---|---|
| `npx -y some-package` | `npx -y some-package@1.2.3` |
| `npx @scope/pkg@latest` | `npx @scope/pkg@1.2.3` |
| `uvx some-package` | `uvx --from some-package@1.2.3` |
| `pipx run some-package` | `pipx run --spec some-package==1.2.3` |

## Generated policies

Setup generates policies that start **deny-by-default**:

```toml
schema_version = "ef-mcp-policy/v0.2"
name = "etherfence-setup-server-name"

[methods]
allow = ["tools/list"]
deny = []

[tools]
allow = []
deny = []
```

This blocks all tool calls. You refine the policy to allow specific tools:

```bash
etherfence mcp-policy explain .etherfence/policies/server-name.toml
# Edit the file to add allowed tools
etherfence mcp-policy validate .etherfence/policies/server-name.toml
```

## Rollback

To undo all EtherFence setup changes:

```bash
etherfence setup rollback
```

This restores original config files and removes generated policies. Rollback refuses to overwrite configs that were edited after setup (protecting your manual changes).
