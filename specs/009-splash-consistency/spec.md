# Feature Specification: Terminal Splash Consistency

**Feature Branch**: `fix/splash-consistency`

**Created**: 2026-07-13

**Status**: Draft

**Input**: User description: "Fix EtherFence terminal splash consistency on latest `main`. Observed failures: `etherfence`, `etherfence help`, `etherfence --help`, `etherfence policy`, `etherfence policy --help`, `etherfence mcp-proxy`, `etherfence mcp-proxy --help` skip the splash because `Cli::parse()` exits inside Clap before `print_startup_banner()` runs."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Splash appears on every human-facing invocation (Priority: P1)

As a practitioner running `etherfence` interactively, I want the startup splash to appear consistently — whether I ask for help, mistype a command, omit a required subcommand, or run a fully valid command — so the tool's identity and version are always visible before I read its output, instead of only on some code paths.

**Why this priority**: This is the entire defect being fixed. Every other requirement supports this outcome.

**Independent Test**: On an interactive, color-capable terminal, run each of `etherfence`, `etherfence help`, `etherfence --help`, `etherfence policy`, `etherfence policy --help`, `etherfence mcp-proxy`, `etherfence mcp-proxy --help`, and a normal successful command (e.g. `etherfence policy list`). The splash must appear before the command's own output in every case.

**Acceptance Scenarios**:

1. **Given** an interactive, color-capable terminal, **When** the user runs `etherfence` with no arguments, **Then** the splash appears, followed by Clap's usage/error text.
2. **Given** an interactive, color-capable terminal, **When** the user runs `etherfence --help` or `etherfence help`, **Then** the splash appears, followed by the help text.
3. **Given** an interactive, color-capable terminal, **When** the user runs `etherfence policy` (no subcommand) or `etherfence policy --help`, **Then** the splash appears, followed by the corresponding usage/help text.
4. **Given** an interactive, color-capable terminal, **When** the user runs `etherfence mcp-proxy` (missing required arguments) or `etherfence mcp-proxy --help`, **Then** the splash appears, followed by the corresponding usage/help text.
5. **Given** an interactive, color-capable terminal, **When** the user runs `etherfence policy list`, **Then** the splash appears, followed by the list of built-in policy profiles.

---

### User Story 2 - Splash lands on the same stream as the content it precedes (Priority: P1)

As a practitioner piping or redirecting `etherfence` output, I want the splash to travel on the same stream as the text it introduces — stdout for help/version/successful output, stderr for usage and argument errors — so that redirecting one stream never separates the splash from its content or leaks it onto the wrong stream.

**Why this priority**: Without correct stream routing, fixing User Story 1 naively (e.g. always printing to stdout) would corrupt scriptable output or split the splash from the error text it's meant to precede.

**Independent Test**: This requires *split-stream* terminals — one standard stream attached to a real interactive terminal, the other piped/non-interactive — because fully redirecting both streams makes neither eligible for the splash at all (see User Story 3 and FR-006), which would not exercise stream selection. Concretely: (a) attach only stdout to a terminal and pipe stderr, run `etherfence --help`, and confirm the splash and help text both appear on the terminal-attached stdout while the piped stderr stays empty; (b) attach only stderr to a terminal and pipe stdout, run `etherfence mcp-proxy` (missing required args), and confirm the splash and usage error both appear on the terminal-attached stderr while the piped stdout stays empty; (c) as an inverse check, attach only stdout to a terminal (pipe stderr) and run the *error* case, or attach only stderr to a terminal (pipe stdout) and run the *help* case, and confirm the splash never appears at all — proving suppression follows the actual destination stream's interactivity, not merely "some stream is a terminal."

**Acceptance Scenarios**:

1. **Given** a terminal attached to stdout only (stderr piped), **When** the user runs a command that Clap resolves to help or version output, **Then** both the splash and the content are written to stdout, and stderr stays empty.
2. **Given** a terminal attached to stderr only (stdout piped), **When** the user runs a command that Clap rejects (missing subcommand, missing required argument, invalid argument), **Then** both the splash and the error content are written to stderr, and stdout stays empty.
3. **Given** a terminal attached to stdout only (stderr piped), **When** the user runs a command that Clap rejects (its content destined for stderr), **Then** the splash does not appear anywhere, because its destination stream (stderr) is not the terminal-attached one.
4. **Given** a terminal attached to stderr only (stdout piped), **When** the user runs a command that Clap resolves to help or version output (its content destined for stdout), **Then** the splash does not appear anywhere, because its destination stream (stdout) is not the terminal-attached one.

---

### User Story 3 - Machine and protocol output stay pristine (Priority: P1)

As an operator scripting against `etherfence` or wiring it into an MCP client as `mcp-proxy`, I need machine-readable formats and the live MCP protocol stream to remain byte-for-byte free of any splash or decorative text, in every environment (TTY or not, colors enabled or not), so automation and protocol parsing never break.

**Why this priority**: This is a safety guarantee that must never regress while fixing the splash's visibility elsewhere; a violation would be a functional regression in a security-relevant runtime-enforcement component.

**Independent Test**: Run `etherfence scan --format json`, `--format markdown`, `--format sarif`, `etherfence setup detect --format json`, `etherfence policy show <profile>`, `etherfence mcp-policy init --profile <profile>`, and a successful `etherfence mcp-proxy ... -- <server>` session, on both a PTY and redirected/piped output, with and without `NO_COLOR`/`CI`/`CLICOLOR=0`/`TERM=dumb` set. None of these may ever contain splash text, on any stream, under any of those conditions.

**Acceptance Scenarios**:

1. **Given** any terminal or redirection state, **When** the user requests a machine format (JSON, Markdown, SARIF) or raw-TOML output (`policy show`, `mcp-policy init` without `--output`), **Then** no splash text appears anywhere in that command's output.
2. **Given** any terminal or redirection state, **When** a successfully parsed `mcp-proxy` invocation starts running the boundary proxy, **Then** protocol stdout never receives a splash or any other decorative text, matching current behavior.
3. **Given** a redirected (non-interactive) stream, or an environment with `NO_COLOR`, `CI`, `CLICOLOR=0`, or `TERM=dumb` set, **When** the user runs any otherwise splash-eligible human command, **Then** the splash is suppressed exactly as it is today.

---

### Edge Cases

- What happens when stdout is redirected but stderr is still an interactive terminal (or vice versa) for a command that produces a Clap error? The splash decision is made per destination stream, so it should follow the interactivity of the stream actually receiving the content, not the process as a whole.
- What happens for `etherfence setup` (bare, launches the interactive wizard) — already shows the splash today via the existing successful-parse path, and must continue to do so unchanged; it is not one of the previously-broken paths.
- What happens for a fully valid but unknown subcommand or flag typo (e.g. `etherfence scn`)? Same as other Clap argument errors: splash to stderr before the error, when stderr is an eligible interactive terminal.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST show the startup splash before Clap-produced help, version, missing-subcommand, and invalid-argument output whenever the destination stream for that output is an eligible interactive terminal (the same eligibility rules already applied today: interactive, colors enabled, not `NO_COLOR`, not `CI`, not `CLICOLOR=0`, not `TERM=dumb`).
- **FR-002**: The system MUST route the splash to the same stream Clap itself uses for the content that follows it: stdout for help and version output, stderr for usage and argument errors.
- **FR-003**: The system MUST base the interactivity/eligibility check for the splash on the actual stream it is about to write to (stdout or stderr), not unconditionally on stdout.
- **FR-004**: The system MUST continue to suppress the splash entirely for a successfully parsed and running `mcp-proxy` invocation, on protocol stdout, regardless of terminal state.
- **FR-005**: The system MUST continue to suppress the splash entirely for machine-readable formats (JSON, Markdown, SARIF), setup JSON output, and raw TOML output (`policy show`, `mcp-policy init` without `--output`), regardless of terminal state.
- **FR-006**: The system MUST continue to suppress the splash under redirected output, `CI`, `NO_COLOR`, `CLICOLOR=0`, and `TERM=dumb`, exactly as it does today.
- **FR-007**: The system MUST treat `policy list` as human terminal output eligible for the splash on an interactive terminal.
- **FR-008**: The system MUST keep `policy show` splash-free, since it emits raw TOML intended for piping.
- **FR-009**: The system MUST NOT duplicate splash-printing calls across individual command handlers; invocation classification and Clap error/help rendering must be centralized in one place.
- **FR-010**: The system MUST NOT change the splash's visual design, colors, wording, or any command's functional behavior or exit codes — this is a display-plumbing fix only.

### Key Entities

- **Startup splash**: The decorative banner (product name, tagline, version, optional mode label) shown once per invocation on eligible interactive terminals.
- **Invocation outcome**: The classification of how a given `etherfence` run resolves — successful human command, successful machine/protocol command, or a Clap-produced help/version/error exit — which determines whether the splash shows and on which stream.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: All seven previously-reported invocations (`etherfence`, `etherfence help`, `etherfence --help`, `etherfence policy`, `etherfence policy --help`, `etherfence mcp-proxy`, `etherfence mcp-proxy --help`) show the splash before their content when run on an interactive, color-capable terminal.
- **SC-002**: 100% of existing machine-format, protocol, and suppression regression tests continue to pass unmodified in behavior (only reclassifying `policy list`).
- **SC-003**: In split-stream terminal tests (one of stdout/stderr attached to a real terminal, the other piped) covering both the help/version→stdout and error→stderr cases and their inverses, the splash appears only on its correct destination stream when that stream is the terminal-attached one, and never appears at all — on either stream — when its destination stream is the piped one, even if the other stream happens to be a terminal.
- **SC-004**: `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test` all pass on the change with no new warnings or failures.

## Assumptions

- "Eligible interactive terminal" reuses the existing suppression rule set (`NO_COLOR`, `CI`, `CLICOLOR=0`, `TERM=dumb`, non-TTY, ANSI-unsupported) already implemented in `banner.rs`, just generalized to whichever stream is being checked.
- The `etherfence setup` bare-wizard path is out of scope: it already shows the splash via the successful-parse path today and is not one of the reported failures.
- Windows behavior mirrors Unix for this change (stream selection and terminal detection are already cross-platform via existing crates); no new Windows-specific code paths are introduced.
- No new configuration or CLI flags are introduced; this is purely internal control-flow and stream-routing plumbing.
