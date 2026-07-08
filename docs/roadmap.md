# EtherFence Roadmap

## v0.1.0 - scan-only foundation

- Rust workspace and CLI
- `etherfence scan` human report
- `etherfence scan --format json` JSON report
- Conservative inventory for Claude Code, Cursor, VS Code, Windsurf, Gemini CLI, Codex CLI, and Tirith
- Fixture-backed parsing and initial posture findings

## v0.1.1 - report quality and remediation guidance

- Versioned JSON report shape with `schema_version`, `summary`, `inventory`, and `findings`
- Stable finding IDs for current MCP, secret, and Tirith posture hints
- Finding rationale, impact, recommendation, target, and references fields
- Human report grouped by severity with concise remediation guidance
- Snapshot-like CLI assertions for JSON schema stability

## v0.1.2 - CI posture gates and exports

- `--severity-threshold` for concise review output
- `--fail-on` for CI posture gates without runtime enforcement
- Markdown report output for security review notes and PR artifacts
- JSON schema documentation for `ef-scan-report/v0.1.1`
- CLI tests for gate behavior and export formats

## v0.2 ideas

- Expand tested config schemas and platform paths
- Add baseline/diff mode for posture drift
- Add machine-readable policy checks without enforcement
- Improve documentation for safe enterprise rollout

## Later, not v0.1

- Runtime control design
- MCP proxy experiments
- Explicit allow/deny policy enforcement
- Integration with complementary tools such as Tirith

Any runtime blocking, proxying, or interception must be designed and threat-modeled before implementation.
