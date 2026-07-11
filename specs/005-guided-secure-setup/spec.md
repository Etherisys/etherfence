# Feature Specification: Guided Secure Setup and Complete AI Client Discovery

**Feature Branch**: `feature/v1.6.0-guided-secure-setup`
**Spec Directory**: `specs/005-guided-secure-setup/`
**Created**: 2026-07-11
**Status**: Draft

## Problem Statement

EtherFence's `setup` command family works for advanced users who understand the internal subcommand workflow (`catalog`, `detect`, `plan`, `apply`, `doctor`, `baseline write/check`), but presents critical gaps:

1. **No guided onboarding**: Bare `etherfence setup` is an error because a subcommand is required. New users must discover the subcommand sequence on their own.
2. **Incomplete client detection**: Detection is based on hard-coded candidate config file paths. Clients like Hermes, OpenCode, and Antigravity may be installed but go undetected when the guessed marker path does not exist. The current `PresenceOnly` format for these clients provides no MCP server parsing.
3. **No package version enforcement**: Setup-generated wrapping proceeds even when a package-runner MCP server has an omitted, mutable, ranged, or ambiguous version (e.g., `npx -y some-package` with no `@version`, `npm@latest`, or `^1.2.0`). This is flagged by trust assessment but not enforced during guided setup.
4. **Unsafe generated policies**: The current `generated_policy_template()` produces `tools.allow = ["*"]` — a wildcard allow-all starter policy that violates Principle I (Security-First, Deny-by-Default).
5. **Trust findings are display-only**: The trust assessment (v1.3.0) and classification (v1.2.0) produce rich structured output but the setup flow does not gate on trust status — high-risk servers proceed to wrapping with the same permissive defaults as verified-local ones.

## User Scenarios

### User Story 1 - First-time user runs `etherfence setup` (Priority: P1)

A developer has installed EtherFence and heard it can protect their MCP-boundary. They run `etherfence setup` expecting a guided flow.

**Why this priority**: This is the entry point for every new user. Without it, EtherFence setup is inaccessible to anyone who hasn't read the internal subcommand docs.

**Independent Test**: Run `etherfence setup` on a real TTY; verify the guided wizard launches, scans, presents detected clients and servers, and allows the user to complete onboarding.

**Acceptance Scenarios**:
1. **Given** EtherFence is installed and the terminal is a TTY, **When** the user runs `etherfence setup`, **Then** the guided wizard launches immediately (no subcommand required).
2. **Given** no TTY (CI, pipe, script), **When** the user runs `etherfence setup`, **Then** an error message is printed explaining that the guided wizard needs a TTY and listing explicit subcommands (`catalog`, `detect`, `plan`, `apply`, `doctor`, `baseline`).
3. **Given** the wizard is running, **When** the user presses Ctrl+C at any step before confirmation, **Then** no files are modified.

### User Story 2 - Hermes user discovers protection (Priority: P1)

A developer uses Hermes Agent daily with several MCP servers configured. They run `etherfence setup` and expect EtherFence to detect their Hermes configuration.

**Why this priority**: The real-world Hermes config path (`~/.hermes/config.yaml`) is different from the current hardcoded `~/.hermes/config.json` guess. This means Hermes is effectively undetectable, which blocks the most common user of EtherFence itself.

**Independent Test**: Create a test fixture with a real Hermes `config.yaml` containing `mcp_servers:` entries; verify detection finds it and correctly parses the MCP servers.

**Acceptance Scenarios**:
1. **Given** a Hermes installation with `~/.hermes/config.yaml` containing `mcp_servers:` entries, **When** the guided setup scans, **Then** Hermes appears as a detected client with its MCP servers listed.
2. **Given** a Hermes installation with the config file present but no `mcp_servers:` section, **When** scanned, **Then** Hermes is detected as installed+configured but with no MCP servers (distinct from "not found at all").
3. **Given** the Hermes binary is on PATH but `~/.hermes/config.yaml` does not exist, **When** scanned, **Then** Hermes is detected as installed but not configured (binary evidence, no config evidence).

### User Story 3 - Package version chaos is caught (Priority: P1)

A developer has an MCP server defined as `npx -y @modelcontextprotocol/server-filesystem` (no version pin). They run guided setup expecting EtherFence to flag this.

**Why this priority**: Omitted versions are the most common configuration error and directly enable supply-chain risk (runner resolves to whatever the registry returns today).

**Independent Test**: Create a fixture with an MCP server using `npx -y some-package` (no version); run guided setup; verify the wizard flags this and requires resolution before proceeding.

**Acceptance Scenarios**:
1. **Given** an MCP server `command: "npx", args: ["-y", "some-package"]` (no version), **When** the wizard processes it, **Then** it is flagged as needing version pinning and cannot silently complete setup.
2. **Given** `npx -y some-package@latest`, **When** processed, **Then** flagged as mutable tag.
3. **Given** `uvx some-package` (no version), **When** processed, **Then** flagged as omitted.
4. **Given** `npx -y @scope/package@1.2.3`, **When** processed, **Then** accepted as an exact pin.
5. **Given** a flagged package, **When** the user selects "enter exact version", **Then** the wizard shows the exact args change before writing.

### User Story 4 - High-risk server blocked (Priority: P2)

A developer has an MCP server configured with `command: "bash", args: ["-c", "curl ... | sh"]`. The guided setup must block this.

**Why this priority**: Trust assessment already detects this pattern; the gap is that setup doesn't act on the finding.

**Independent Test**: Create fixture with a downloader-to-shell MCP server; verify the guided setup blocks normal onboarding and only offers skip or deny-all quarantine.

**Acceptance Scenarios**:
1. **Given** an MCP server classified as `HighRisk` by trust assessment, **When** the wizard processes it, **Then** it cannot receive a normal permissive policy — only skip or deny-all quarantine are offered.
2. **Given** `NeedsReview` trust status, **When** processed, **Then** the wizard requires review but may proceed after issue resolution.

### User Story 5 - Policy never starts as allow-all (Priority: P1)

The current starter policy `tools.allow = ["*"]` is rewritten to a safe default.

**Independent Test**: Run the complete guided setup flow; verify no generated policy file contains `tools.allow = ["*"]`.

**Acceptance Scenarios**:
1. **Given** a server with no fixture-verified curated policy, **When** setup generates its policy, **Then** the policy is `tools.allow = []` (deny-all quarantine), not `["*"]`.
2. **Given** a server with a fixture-verified curated policy mapping, **When** setup generates its policy, **Then** the curated policy is used (explicit tool allowlist).
3. **Given** the user selects "custom allowlist", **When** setup generates the policy, **Then** the user's explicit tool names are used and validated.

## Functional Requirements

### FR-001: Guided Wizard Entry Point
Bare `etherfence setup` (no subcommand) on a TTY MUST launch the interactive guided setup wizard. On a non-TTY, it MUST print a clear error with guidance to use explicit subcommands.

### FR-002: Client Detection Architecture
Detection MUST distinguish these independent concepts:
- **Installed**: executable on PATH or known installation directory
- **Configured**: known config file exists (even if empty or without MCP section)
- **MCP-configured**: config file parsed and MCP servers extracted
- **Read support**: EtherFence can parse MCP config from this client's format
- **Write support**: EtherFence can safely rewrite this client's MCP config

Do not collapse all states into a single `foundLocally` boolean.

### FR-003: Real Path Detection for Hermes
Hermes detection MUST check `~/.hermes/config.yaml` (YAML format, `mcp_servers:` root key), not the current `~/.hermes/config.json`. Binary detection via `hermes` on PATH.

### FR-004: Real Path Detection for OpenCode
OpenCode detection MUST check `~/.config/opencode/config.json` (JSON format, `mcp` root key with `type: "local"` entries, `command` as array).

### FR-005: Real Path Detection for Antigravity
Antigravity detection MUST check `~/.gemini/config/mcp_config.json` and `.agents/mcp_config.json` (JSON format, `mcpServers` root key).

### FR-006: Package Version Pinning Enforcement
For package-runner MCP servers (npx, uvx, pipx run), the following MUST NOT silently pass normal guided setup:
- Omitted version (no `@version`, `==version`, or equivalent)
- Mutable tags (`@latest`, `@next`, `@beta`, etc.)
- Version ranges (`^1.2.0`, `~1.2.0`, `>=1.2`, wildcards)
- Ambiguous or malformed package specifications

The wizard MUST offer: keep existing exact pin, enter exact version manually, or skip the server.

### FR-007: Safe Generated Policies
No generated starter policy MUST contain `tools.allow = ["*"]`. Generated policies MUST be one of:
- Deny-all quarantine: `tools.allow = []`, `methods.allow = ["tools/list"]`
- Fixture-verified curated policy (explicit tool names with known safe profile)
- User-selected explicit tool allowlist

### FR-008: Trust-Gated Onboarding
Trust assessment status MUST influence the guided flow:
- `verified-local`: continue to policy selection (but never auto-allow)
- `known-source`: continue after package/version review
- `unknown`: require review, skip, or deny-all quarantine
- `needs-review`: require issue resolution, skip, or deny-all quarantine
- `high-risk`: block normal onboarding; offer skip or deny-all quarantine only

### FR-009: Existing Subcommands Preserved
All existing subcommands MUST remain available with identical semantics:
`setup catalog`, `setup detect`, `setup plan`, `setup apply`, `setup rollback`, `setup doctor`, `setup baseline write`, `setup baseline check`.

### FR-010: Non-TTY Safety
Non-TTY execution MUST never hang waiting for interactive input. Machine-readable output (JSON) MUST remain deterministic and banner-free.

## Safety Invariants

The wizard and all read-only stages MUST NOT:
- Start MCP servers or AI clients
- Execute package runners
- Install or download packages
- Contact registries by default
- Emit environment-variable values or secrets
- Dump complete configs

Apply MUST:
- Build and validate the complete plan before any write
- Validate every generated policy before writing
- Create backups before changing configs
- Preserve unknown and unrelated config fields
- Avoid double wrapping
- Never rewrite unsupported/untargeted clients
- Clean up best-effort after write failures

## Success Criteria

1. `etherfence setup` launches guided wizard on TTY
2. User can select detected AI clients
3. Hermes detected from real `config.yaml` evidence
4. OpenCode detected from real `config.json` evidence
5. Antigravity detected from real `mcp_config.json` evidence
6. Detection distinguishes installed / configured / MCP-configured / read-support / write-support
7. Omitted package versions blocked during guided setup
8. Mutable tags and ranges blocked
9. Exact pin changes previewed before writing
10. No generated policy contains `tools.allow = ["*"]`
11. High-risk servers cannot receive normal permissive setup
12. Wizard does not start MCP servers or AI clients
13. Non-TTY never hangs
14. All existing subcommands preserved
15. JSON output banner-free and deterministic
16. Apply/rollback safety guarantees intact
17. All tests, linting, builds pass
