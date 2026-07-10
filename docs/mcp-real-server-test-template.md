# Real MCP server smoke-test template

Use this template when you want to add a real stdio MCP server row to `docs/mcp-compatibility-matrix.md`.

This is optional maintainer validation. Normal CI remains deterministic and uses only the checked-in fake MCP server fixture. Do not use this workflow to add daemon mode, HTTP/SSE transport, network interception, shell hooks, terminal-command scanning, wildcard/prefix/regex matching, or new enforcement semantics.

Running this test successfully is compatibility evidence for the specific
server/version/flow you exercised. It is **not** production-readiness
certification, and it does not extend to server behavior, tool/resource names,
or flows you did not exercise. See `docs/mcp-compatibility-matrix.md` for the
full list of flows covered by the deterministic fixture-backed CI tests.

## 1. Install or locate a stdio MCP server

Record the server name and version using the server's own version command or package manager. Keep the command as an argv list, not a shell pipeline.

Example argv shape:

```json
["/absolute/path/to/server", "--arg", "value"]
```

## 2. Set `ETHERFENCE_REAL_MCP_CMD`

Linux/macOS shell:

```sh
export ETHERFENCE_REAL_MCP_CMD='["/absolute/path/to/server","--arg","value"]'
```

Windows PowerShell:

```powershell
$env:ETHERFENCE_REAL_MCP_CMD = '["C:\\Path\\To\\server.exe","--arg","value"]'
```

The value must be JSON argv. It is not a shell command; shell metacharacters are not interpreted.

## 2b. Optionally set `ETHERFENCE_REAL_MCP_POLICY`

By default the smoke test uses the same deterministic compatibility policy as
the fake-server tests. To exercise a specific policy (for example, one of the
example policies under `examples/policies/`) against the real server instead,
point `ETHERFENCE_REAL_MCP_POLICY` at its file path:

```sh
export ETHERFENCE_REAL_MCP_POLICY=/absolute/path/to/examples/policies/mcp-filesystem-project-readonly-hardened.toml
```

This is optional. A maintainer-supplied policy path is only read, never
modified or deleted, by the test.

## 3. Run the optional smoke test

```sh
cargo test -p etherfence-cli optional_real_mcp_stdio_smoke_test -- --nocapture
```

The test sends a minimal initialize / initialized notification / tools-list sequence through `etherfence mcp-proxy`. If `ETHERFENCE_REAL_MCP_CMD` is unset, the test skips with a clear message and does not run in normal CI.

## 4. Collect audit output

For a manual record, run `etherfence mcp-proxy` with an explicit policy and audit log:

```sh
etherfence mcp-proxy \
  --policy /home/example/.config/etherfence/mcp-policy.toml \
  --audit-log /home/example/.local/state/etherfence/mcp-audit.jsonl \
  --server-name <server-scope> \
  -- <server-command> [server args...]
```

Then inspect the JSONL audit log for:

- `tool_call_decision` records for allowed and denied calls;
- `tools_list_filtered` records for advertised tool filtering;
- no argument values or secrets in audit output;
- expected `server`, `policy`, `decision`, `reason`, and `allowed_tools` metadata.

Do not paste secrets, access tokens, private paths, or full argument values into the matrix.

## 5. Record the result

Add a row to `docs/mcp-compatibility-matrix.md` with:

- server name;
- server version;
- platform;
- command template;
- policy used;
- `tools/list` behavior;
- allowed `tools/call` result;
- denied `tools/call` result;
- audit result;
- tester/date;
- notes/limitations.

Keep rows version-specific. If an external MCP server changes tool names or behavior, add a new row instead of rewriting old evidence.
