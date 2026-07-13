# Tasks: Terminal Splash Consistency

**Input**: Design documents from `/specs/009-splash-consistency/`
**Prerequisites**: plan.md, research.md, data-model.md, contracts/cli-splash-routing.md, quickstart.md

**Tests**: Included — the spec's acceptance scenarios are directly testable via PTY/process-output integration tests, and `cli_banner.rs` already establishes this project's convention of testing the banner at the integration level.

**Organization**: Grouped by user story from spec.md (US1: splash appears on every human-facing invocation; US2: splash lands on the same stream as its content; US3: machine/protocol output stays pristine). All three stories are P1 and share one small, cohesive code change (`main.rs` + `banner.rs`), so the Foundational phase carries the core refactor and each story phase adds its specific verification.

## Phase 1: Setup

- [X] T001 Confirm workspace builds clean before changes: `cargo build` and `cargo test -p etherfence-cli --test cli_banner` from repo root (baseline, no file changes)

## Phase 2: Foundational (blocking prerequisites)

**Purpose**: Generalize the banner module to be stream-aware; this is required by every user story before any of them can be verified.

- [X] T002 In `crates/etherfence-cli/src/banner.rs`, add a `pub(crate) enum Stream { Stdout, Stderr }` with methods `is_terminal(&self) -> bool`, `terminal_width(&self) -> Option<u16>`, `ansi_supported(&self) -> bool`, and `write(&self, bytes: &[u8])` (via `anstream::stdout()`/`anstream::stderr()`), each matching on the variant to call the `io::stdout()`/`io::stderr()` equivalent of the existing stdout-only helpers
- [X] T003 In `crates/etherfence-cli/src/banner.rs`, change `TerminalEnvironment` to store which `Stream` it was built for (rename `stdout_is_terminal` → `stream_is_terminal`) and change `TerminalEnvironment::current()` to `TerminalEnvironment::current(stream: Stream)`, sourcing `stream_is_terminal`, `columns`, and `ansi_supported` from the new `Stream` methods (T002) instead of hardcoded `io::stdout()`
- [X] T004 In `crates/etherfence-cli/src/banner.rs`, change `print_startup_banner(mode: OutputMode, mode_label: Option<&str>)` to `print_startup_banner(stream: Stream, mode: OutputMode, mode_label: Option<&str>)`, passing `stream` into `TerminalEnvironment::current` and writing the rendered output via `stream.write(...)` instead of always `anstream::stdout()`
- [X] T005 Update the `banner.rs` unit tests' local `env(...)` helper and any direct `TerminalEnvironment { .. }` literals to match the renamed/generalized struct fields from T003 so `cargo test -p etherfence-cli --lib` (banner unit tests) compiles and passes unchanged in behavior

**Checkpoint**: `banner.rs` compiles standalone with the new `Stream`-parameterized API; `main.rs` does not compile yet (call sites still use the old signature) — expected until Phase 3.

## Phase 3: User Story 1 - Splash appears on every human-facing invocation (Priority: P1)

**Goal**: The splash prints before Clap help/version/missing-subcommand/invalid-argument output, and before `policy list`'s output, on an eligible interactive terminal.

**Independent Test**: On a PTY, run each of `etherfence`, `etherfence help`, `etherfence --help`, `etherfence policy`, `etherfence policy --help`, `etherfence mcp-proxy`, `etherfence mcp-proxy --help`, `etherfence policy list` and confirm the splash tagline appears in the captured output for every one of them.

- [X] T006 [US1] In `crates/etherfence-cli/src/main.rs`, replace `let cli = Cli::parse();` in `fn main()` with a `match Cli::try_parse() { Ok(cli) => cli, Err(err) => { ...; err.exit() } }` block; in the `Err` arm, select `banner::Stream::Stdout` when `!err.use_stderr()` else `banner::Stream::Stderr`, call `banner::print_startup_banner(stream, banner::OutputMode::Human, None)`, then call `err.exit()`
- [X] T007 [US1] In `crates/etherfence-cli/src/main.rs`, update the existing successful-parse call site to `banner::print_startup_banner(banner::Stream::Stdout, banner_mode, banner_label.as_deref())` (stream is always stdout here — every human command's own content already targets stdout, per research.md Decision 3)
- [X] T008 [US1] In `crates/etherfence-cli/src/main.rs`, change `command_banner_mode`'s `Command::Policy { .. } => (banner::OutputMode::Machine, None)` arm to match on `command: &PolicyCommand` and return `(banner::OutputMode::Human, None)` for `PolicyCommand::List` and `(banner::OutputMode::Machine, None)` for `PolicyCommand::Show { .. }`
- [X] T009 [US1] In `crates/etherfence-cli/tests/cli_banner.rs`, add a table-driven PTY test (using the existing `run_in_pty` helper) that runs each reported command — `[]` (bare), `["help"]`, `["--help"]`, `["policy"]`, `["policy", "--help"]`, `["policy", "list"]`, `["mcp-proxy"]`, `["mcp-proxy", "--help"]` — with no `--root`/temp-root needed for these, and asserts `BANNER_TAGLINE` is present in each captured output (note: `["mcp-proxy"]` and bare `[]`/`["policy"]` exit non-zero — the PTY helper's `assert!(status.success())` must be relaxed or a variant helper added for expected-nonzero-exit cases)

**Checkpoint**: All previously-reported commands show the splash on an interactive terminal; workspace compiles.

## Phase 4: User Story 2 - Splash lands on the same stream as its content (Priority: P1)

**Goal**: The splash and the content it precedes are always on the same stream; redirecting one stream never splits them or leaks the splash onto the wrong stream.

**Independent Test**: `etherfence --help > out.txt 2> err.txt` on a terminal-attached process shows splash+help in `out.txt` only; `etherfence mcp-proxy > out.txt 2> err.txt` (missing args) shows splash+error in `err.txt` only.

- [X] T010 [US2] In `crates/etherfence-cli/tests/cli_banner.rs`, add non-PTY `Command::output()` tests asserting stream separation for help/version content: run `etherfence --help` and `etherfence help`, assert `stdout` is non-empty and contains expected help text while `stderr` is empty
- [X] T011 [US2] In `crates/etherfence-cli/tests/cli_banner.rs`, add non-PTY `Command::output()` tests asserting stream separation for usage/argument errors: run `etherfence` (bare), `etherfence policy` (no subcommand), and `etherfence mcp-proxy` (missing required args), assert `stderr` is non-empty and `status.success()` is false while `stdout` is empty
- [X] T012 [US2] In `crates/etherfence-cli/tests/cli_banner.rs`, extend the T009 PTY table-driven test (or add a companion assertion) to verify ordering: for each command, the byte index of `BANNER_TAGLINE` in the captured PTY output is strictly less than the byte index of a command-specific content marker (e.g. `"Usage:"` for errors, `"AI Agent Security Posture"`-adjacent help boilerplate, or the specific subcommand list text for help)

**Checkpoint**: Stream routing is verified both for interactive ordering (Phase 3/4 PTY tests) and strict non-TTY separation (T010/T011).

## Phase 5: User Story 3 - Machine and protocol output stay pristine (Priority: P1)

**Goal**: No regression in existing splash-suppression guarantees for machine formats, raw TOML, protocol stdout, redirected output, or `NO_COLOR`/`CI`/`CLICOLOR=0`/`TERM=dumb`.

**Independent Test**: Run the full existing suppression matrix (JSON/Markdown/SARIF/setup-JSON/raw-TOML, redirected, CI-like env vars) plus a live `mcp-proxy` session, on both PTY and non-PTY, and confirm zero splash bytes anywhere in any of them.

- [X] T013 [P] [US3] In `crates/etherfence-cli/tests/cli_banner.rs`, add a PTY test asserting `etherfence policy show <profile>` (pick any `BUILT_IN_POLICIES` name, e.g. `strict`) never contains `BANNER_TAGLINE`, proving the T008 reclassification did not accidentally include `Show`
- [X] T014 [P] [US3] In `crates/etherfence-cli/tests/cli_banner.rs`, add a PTY test asserting `etherfence mcp-policy init --profile minimal` (or another built-in profile, no `--output`) never contains `BANNER_TAGLINE`, matching existing `McpPolicyCommand::Init` → `OutputMode::Machine` classification
- [X] T015 [P] [US3] In `crates/etherfence-cli/tests/cli_banner.rs`, add PTY tests asserting `etherfence scan --format markdown --root <temp-fixture-root>` and `etherfence scan --format sarif --root <temp-fixture-root>` never contain `BANNER_TAGLINE` (the existing `json_format_suppresses_banner_on_pty` test already covers `--format json` for `setup detect`; add the scan-command equivalents for markdown/sarif since `Command::Scan`'s classification is untouched but was previously only unit-tested, not PTY-tested)
- [X] T016 [US3] In `crates/etherfence-cli/tests/cli_banner.rs`, add environment-suppression PTY regression tests (reusing `run_in_pty` but overriding one env var at a time) confirming `CI=1`, `NO_COLOR=1`, `CLICOLOR=0`, and `TERM=dumb` each suppress the splash for one of the newly-splash-eligible commands (e.g. `["--help"]`), since these were previously only exercised for successfully-parsed commands
- [X] T017 [US3] In `crates/etherfence-cli/tests/cli_mcp_proxy.rs`, extend an existing successful proxy-run test (or add a small new one) to assert the captured proxy stdout/JSON-RPC output never contains the literal string `"ETHERFENCE"` or the banner tagline, confirming `OutputMode::Protocol` still unconditionally suppresses the splash after the T006/T007 refactor

**Checkpoint**: Every existing suppression guarantee is explicitly re-verified at the integration-test level under the new code path.

## Phase 6: Polish & Cross-Cutting Concerns

- [X] T018 Run `cargo fmt` and `cargo clippy --all-targets --all-features -- -D warnings` from repo root and fix any findings introduced by this change
- [X] T019 Run `cargo test` (full workspace) and `cargo build` from repo root; confirm ubuntu-equivalent local pass (Windows PTY tests are `cfg(unix)`-gated and validated by CI per `CLAUDE.md`)
- [X] T020 Add a `CHANGELOG.md` entry (new "Unreleased" or next-patch section per existing convention — do not rename an existing version heading) describing the splash-consistency fix in user-facing terms
- [X] T021 [P] Update `docs/` (grep for existing splash/banner mentions, e.g. any CLI reference doc describing when the banner shows) to reflect that the splash now also appears on help/version/error/`policy list` output, if such docs exist and describe this behavior — **N/A**: grepped `docs/` for "banner"/"splash"/"ETHERFENCE"; no doc describes *when* the splash shows (only `docs/roadmap.md`'s historical note that v1.7.3 added the banner feature), so there is nothing to update
- [X] T022 Run `git diff --check` to confirm no stray whitespace errors, then review the full diff for scope creep against `contracts/cli-splash-routing.md`'s invariants (no visual change, no behavioral/exit-code change)

## Dependencies & Execution Order

- **Phase 2 (Foundational)** blocks all of Phase 3–5: the `Stream`-aware `banner.rs` API (T002–T005) must exist before `main.rs` can be updated (T006–T008) or before any new/updated test can compile.
- **T006, T007, T008** are sequential within `main.rs` (same file, same function region) — do not parallelize.
- **Phase 3 (US1)** must land before Phase 4/5 test tasks that exercise the new error-path banner (T010–T017 assume T006–T008 are done), but US2/US3 test tasks are otherwise independent of each other.
- **T013–T015** are marked `[P]` — independent PTY test additions to the same file but non-overlapping test functions; safe to write in any order, though as edits to one file they should still be applied serially in practice.
- **T021** is marked `[P]` relative to T018–T020/T022 — a docs-only change with no code dependency.
- Polish phase (T018–T022) runs last, after all story phases.

## Implementation Strategy

This fix is small enough that MVP = full scope: Phase 2 (Foundational) plus Phase 3 (US1) already delivers the entire user-visible fix (splash shows everywhere it should, correct stream). Phase 4 and 5 are verification-only phases that harden the change with regression coverage before opening the PR — they should not be skipped given this project's "gotchas" around exact-count fixtures and protocol-purity invariants, but they add tests, not behavior.

Recommended order: T001 → T002–T005 (Foundational) → T006–T009 (US1, code + first test) → build/test checkpoint → T010–T017 (US2/US3 verification, can interleave) → T018–T022 (polish, changelog, PR).
