# EtherFence Roadmap

## v0.1.0 - scan-only foundation

- Rust workspace and CLI
- `etherfence scan` human report
- `etherfence scan --format json` JSON report
- Conservative inventory for Claude Code, Cursor, VS Code, Windsurf, Gemini CLI, Codex CLI, and Tirith
- Fixture-backed parsing and initial posture findings

## v0.2 ideas

- Expand tested config schemas and platform paths
- Add severity rationale and remediation text
- Add baseline/diff mode for posture drift
- Add machine-readable policy checks without enforcement
- Improve documentation for safe enterprise rollout

## Later, not v0.1

- Runtime control design
- MCP proxy experiments
- Explicit allow/deny policy enforcement
- Integration with complementary tools such as Tirith

Any runtime blocking, proxying, or interception must be designed and threat-modeled before implementation.
