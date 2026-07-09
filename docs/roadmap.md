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

## v0.1.3 - baseline and diff mode

- Stable finding fingerprints
- `--write-baseline` for recording known findings
- `--baseline` for marking findings as new, existing, or resolved
- `--fail-on-new` for CI gates that fail only on newly introduced findings
- Baseline JSON schema documentation
- CLI tests for baseline write, comparison, resolved findings, and new-finding gates

## v0.1.4 - scan-only policy profile mode

- `etherfence scan --policy <file>` for TOML policy evaluation
- Example strict policy under `examples/policies/strict.toml`
- Agent MCP server allowlists with unexpected-server violations
- Filesystem-capable MCP path prefix checks with broad root/home-directory deny handling
- Environment variable allowed-name patterns and secret-like name denial
- Optional Tirith-required policy check without duplicating Tirith terminal detection
- Policy metadata in JSON output and policy summary sections in human/Markdown output
- Policy-generated findings with stable IDs `EF-POL-001` through `EF-POL-005`
- Policy findings participating in severity filtering, `--fail-on`, baseline comparison, and `--fail-on-new`
- Tests for parser, violation generation, CLI policy output, CI gates, baseline combination, Markdown summary, and JSON metadata

## v0.1.5 - policy schema metadata and built-in profiles

- Versioned policy schema metadata with `schema_version = "ef-policy/v0.1"`, top-level `name`, `description`, and `require_tirith`
- Clear failure for unsupported policy schema versions
- Built-in/example policy profiles: `developer-laptop`, `ci-runner`, and `research-workstation`
- CLI helpers: `etherfence policy list` and `etherfence policy show <profile>`
- `docs/policy.md` covering policy schema, profile intent, CI gates, and baseline behavior
- JSON policy metadata fields for policy schema version and description
- Tests for supported/unsupported schema versions, example profile parsing, CLI scans, deterministic CI-runner findings, and baseline-plus-policy behavior

## v0.1.6 - direct built-in policy profile selection

- `etherfence scan --policy-profile <profile>` for direct built-in profile scans without passing a file path
- Supported built-in scan profiles: `developer-laptop`, `ci-runner`, `research-workstation`, and `strict`
- Clear mutual-exclusion failure when `--policy <file>` and `--policy-profile <name>` are both provided
- Clear unknown-profile failure that points users to `etherfence policy list`
- JSON policy metadata identifies built-in profile source when `--policy-profile` is used
- Existing human and Markdown policy summaries continue to render for file and built-in profile scans
- Policy findings still participate in `--fail-on`, `--baseline`, and `--fail-on-new` without runtime enforcement


## v0.1.7 - Windows/Linux discovery and release packaging

- Conservative OS-aware discovery helpers for Linux `HOME` and Windows `USERPROFILE`, `APPDATA`, and `LOCALAPPDATA` roots
- Windows-style config path candidates for VS Code, Cursor, Windsurf, Gemini CLI, Claude-style settings, and Codex CLI
- Stable path separator normalization for evidence and fingerprints across Unix and Windows-style paths
- Windows fixture coverage under `tests/fixtures/windows-home/` plus explicit Linux fixture coverage
- CLI tests for Windows fixture scans and built-in policy profile scans against Windows-style fixtures
- GitHub Actions matrix for `ubuntu-latest` and `windows-latest` running fmt, clippy, test, and build
- Release artifact packaging: Linux `tar.gz` containing `etherfence`, Windows `zip` containing `etherfence.exe`
- Documentation for Linux usage, Windows usage, release checks, and v0.1.7 smoke tests

## v0.1.8 - parser hardening and SARIF output

- Fixture variants for supported agents: minimal configs, multiple MCP servers, no MCP servers, malformed JSON/TOML, unknown extra fields, and Linux-/Windows-style paths
- Graceful handling of malformed configs: parse failures become inventory evidence and a low-severity `EF-CFG-001` finding instead of aborting the scan
- Structural tolerance: non-object `mcpServers`, non-table `mcp_servers`, string-typed server entries, non-array `args`, and non-object `env` degrade gracefully with deterministic inventory warnings
- MCP extraction consistency between JSON and TOML: numbers and booleans in `args`/`env` are stringified/redacted the same way, and servers are sorted by name for deterministic output
- `etherfence scan --format sarif` emitting SARIF 2.1.0 with tool name/version, one rule per finding ID, high=error / medium=warning / low+info=note severity mapping, fingerprints, and baseline/policy status properties
- SARIF works with `--policy`, `--policy-profile`, `--baseline`, and `--severity-threshold`
- `docs/sarif.md` documenting the SARIF mapping
- Tests for new fixture variants, malformed-config graceful failure, SARIF validity, SARIF rule/result mapping for MCP and policy findings, and fingerprint stability across repeated scans

## v0.2 ideas

- Expand tested config schemas and platform paths
- Add baseline fingerprint migration notes if needed
- Add richer machine-readable policy checks without enforcement
- Improve documentation for safe enterprise rollout
- Consider policy schema evolution once real-world policy examples stabilize

## Later, not v0.1

- Runtime control design
- MCP proxy experiments
- Explicit allow/deny policy enforcement
- Integration with complementary tools such as Tirith

Any runtime blocking, proxying, or interception must be designed and threat-modeled before implementation.
