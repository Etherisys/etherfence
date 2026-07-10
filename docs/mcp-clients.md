# MCP client configuration examples

These examples are templates for wrapping a local stdio MCP server with the experimental EtherFence MCP proxy. Adjust every path, executable location, server command, server arguments, and exact tool-name policy for your machine and MCP server version.

EtherFence remains pre-alpha. The proxy is stdio-only and experimental. It does not add daemon mode, HTTP/SSE transport, network interception, shell hooks, terminal-command scanning, or wildcard tool matching.

## Wrapping pattern

Replace the original MCP server command with `etherfence`, then move the original server command and args after `--`:

```text
etherfence mcp-proxy \
  --policy <path-to-ef-mcp-policy.toml> \
  --server-name <policy-scope-name> \
  --audit-log <path-to-jsonl-audit-log> \
  -- <original-mcp-server-command> [original args...]
```

Use `--server-name` to select a matching `[servers.<name>.tools]` section in the policy. If omitted, EtherFence uses `default`.

## Checked JSON templates

The JSON templates in `docs/examples/` are parsed by the test suite so they remain syntactically valid:

- `docs/examples/mcp-client-generic-linux.json`
- `docs/examples/mcp-client-generic-windows.json`
- `docs/examples/claude-desktop-filesystem-linux.json`
- `docs/examples/cursor-mcp-filesystem-linux.json`
- `docs/examples/vscode-mcp-filesystem-linux.json`

They intentionally use placeholder paths such as `/home/example/...` and `C:\Users\example\...`.

## Generic Linux shape

Use this shape for clients that accept a top-level `mcpServers` object:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "/usr/local/bin/etherfence",
      "args": [
        "mcp-proxy",
        "--policy",
        "/home/example/.config/etherfence/mcp-filesystem-readonly.toml",
        "--server-name",
        "filesystem",
        "--audit-log",
        "/home/example/.local/state/etherfence/mcp-audit.jsonl",
        "--",
        "/usr/bin/npx",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/home/example/projects"
      ]
    }
  }
}
```

## Generic Windows shape

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "C:\\Program Files\\EtherFence\\etherfence.exe",
      "args": [
        "mcp-proxy",
        "--policy",
        "C:\\Users\\example\\.config\\etherfence\\mcp-filesystem-readonly.toml",
        "--server-name",
        "filesystem",
        "--audit-log",
        "C:\\Users\\example\\AppData\\Local\\EtherFence\\mcp-audit.jsonl",
        "--",
        "C:\\Program Files\\nodejs\\npx.cmd",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "C:\\Users\\example\\projects"
      ]
    }
  }
}
```

## Claude-style config

Claude-style MCP configs commonly use the same top-level `mcpServers` shape. Start from `docs/examples/claude-desktop-filesystem-linux.json` and adjust the config file location for your Claude client and OS.

## Cursor config

Cursor MCP JSON examples in this repository use a top-level `mcpServers` shape. Start from `docs/examples/cursor-mcp-filesystem-linux.json`, then adjust paths and the wrapped MCP server command.

## VS Code-style config

VS Code MCP settings may be nested under `mcp.servers`. Start from `docs/examples/vscode-mcp-filesystem-linux.json` when your client expects that shape.

## Example policies

- `examples/policies/mcp-filesystem-readonly.toml` demonstrates global deny plus `--server-name filesystem` server-scoped read-only allow rules.
- `examples/policies/mcp-github-readonly.toml` demonstrates global deny plus `--server-name github` server-scoped read-only allow rules. GitHub MCP tool names vary; treat this as a template and verify exact names with your server's `tools/list` output.
- `examples/policies/mcp-filesystem-project-readonly.toml` and `examples/policies/mcp-filesystem-project-readonly-hardened.toml` demonstrate path-aware, project-root-scoped read access; the hardened variant adds `deny_roots` entries for common credential-like paths (`.git`, `.env`, `secrets`, `.ssh`, `.aws`, `.npmrc`, `.netrc`, `.pypirc`, `credentials`, `id_rsa`).
- `examples/policies/mcp-resources-project-only.toml` demonstrates a project-root-scoped `resources/read` guard for `file://` URIs.
- `examples/policies/mcp-strict-method-only.toml` demonstrates an explicit `[methods]` allow/deny list that only allows `tools/list` and `tools/call`, as an auditable alternative to relying on the built-in default.

## Optional real-server smoke test

Normal CI uses the checked-in fake stdio MCP server and does not require internet access, npm, npx, uvx, Docker, or external MCP packages.

Maintainers can run an optional smoke test against any locally installed real stdio MCP server by setting `ETHERFENCE_REAL_MCP_CMD` to a JSON argv array, not a shell string:

```sh
ETHERFENCE_REAL_MCP_CMD='["/absolute/path/to/server","--arg","value"]' \
  cargo test -p etherfence-cli optional_real_mcp_stdio_smoke_test -- --nocapture
```

Using a JSON array avoids shell parsing inside the test harness. Do not include shell metacharacters expecting them to be interpreted; pass each argument as its own JSON string.

Optionally set `ETHERFENCE_REAL_MCP_POLICY` to a policy file path (for example, one of the example policies above) to exercise that policy against the real server instead of the built-in compatibility policy. See `docs/mcp-real-server-test-template.md` for the full walkthrough. Both env vars are optional and this test is skipped by default in CI; passing it is compatibility evidence for the exercised server/policy combination, not production-readiness certification.

## Compatibility matrix

Use `docs/mcp-compatibility-matrix.md` to record tested server/version/platform combinations. Use `docs/mcp-real-server-test-template.md` when collecting optional real-server evidence. Matrix entries must keep exact tool names and must not imply HTTP/SSE, daemon, shell-hook, network-interception, wildcard, prefix, or regex support.
