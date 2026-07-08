# EtherFence

**Secure AI agents before they act.**

EtherFence is an open-source project for **AI Agent Runtime Protection**: protecting local AI agents, MCP-connected tools, coding agents, self-hosted assistants, and multi-agent workflows before unsafe actions happen.

## Status

EtherFence is currently in design / pre-alpha. It is not production-ready and should not be used as a security control for critical environments yet.

## Why EtherFence exists

AI agents can read files, call tools, run shell commands, access networks, and coordinate with other agents. As agent workflows become more autonomous, security needs to move closer to runtime decisions: what an agent is allowed to see, call, write, execute, send, or schedule.

EtherFence is intended to provide a practical control layer for agentic systems: discover risky configurations, enforce action boundaries, protect secrets, require approvals, and keep an auditable record of sensitive agent activity.

## Product category

**AI Agent Runtime Protection**

EtherFence is not just an MCP scanner, and it is not branded as a firewall. The goal is runtime protection and policy enforcement for local and self-hosted agent environments.

## Target environments

EtherFence is intended to support or integrate with:

- Claude Code
- Cursor
- VS Code agent workflows
- Windsurf
- Gemini CLI
- Codex CLI
- Hermes Agent
- OpenClaw
- MCP servers
- custom local agents

## Threats targeted

EtherFence is being designed to help reduce risk from:

- indirect prompt injection
- MCP tool poisoning
- malicious or changed tool descriptions
- unsafe MCP configs
- over-permissive agent profiles
- secret exposure
- unsafe file reads/writes
- shell command misuse
- network exfiltration
- unsafe scheduled or multi-agent automation

## Planned capabilities

Planned capabilities include:

- agent and MCP discovery
- MCP risk scanning
- runtime policy enforcement
- secret protection
- file boundary control
- network boundary control
- approval workflow
- audit logging

## Roadmap

- **v0.1:** Agent and MCP risk scanner
- **v0.2:** MCP proxy and policy enforcement
- **v0.3:** Secret and output protection
- **v0.4:** File/network boundary control
- **v0.5:** Developer and multi-agent workflow hardening

## Non-goals

EtherFence is not intended to be:

- an EDR replacement
- a malware scanner
- a general network firewall
- a jailbreak-proofing tool
- a guarantee that prompt injection cannot happen

## Development

The planned implementation language is Rust.

Contributions and design feedback will be welcome as the project moves from design into early implementation.
