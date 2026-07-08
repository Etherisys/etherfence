# EtherFence Threat Model

Status: pre-alpha draft for v0.1.0 scan-only posture discovery.

## Assets

- Local files reachable by AI agents and MCP servers
- Environment variables exposed to MCP subprocesses
- Agent configuration files
- Developer workstations and repositories
- Complementary terminal protections such as Tirith

## Initial threat hypotheses

1. An agent configuration may enable MCP servers with broad filesystem access.
2. An MCP server may expose shell, command execution, browser, or network-capable behavior.
3. Secret-like environment variable names may be passed to MCP servers.
4. Operators may not know which agent/MCP configurations exist on a workstation.

## Trust boundaries

- EtherFence v0.1.0 reads local configuration files only.
- It does not intercept, proxy, or block agent runtime behavior.
- It does not inspect live network traffic.
- It does not scan terminal commands; Tirith remains complementary for that class of control.

## v0.1.0 detection limits

The scanner reports conservative hints from known config paths and fixture-backed formats. It may miss custom locations, unsupported schemas, dynamically generated settings, and runtime-only capabilities. A finding indicates review priority, not confirmed compromise.
