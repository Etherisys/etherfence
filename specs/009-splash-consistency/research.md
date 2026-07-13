# Phase 0 Research: Terminal Splash Consistency

No `[NEEDS CLARIFICATION]` markers remain in the spec; the technical context was
resolved directly by reading `crates/etherfence-cli/src/main.rs`, `banner.rs`,
`ui.rs`, and the existing `clap` 4.6 dependency rather than via external research
agents (small, self-contained change in a codebase already loaded in context).

## Decision 1: Replace `Cli::parse()` with `Cli::try_parse()` + manual `Err` handling

**Decision**: Change `main()` from `let cli = Cli::parse();` to a `match Cli::try_parse() { Ok(cli) => cli, Err(err) => { ...print splash...; err.exit() } }`.

**Rationale**: `Parser::parse()` is defined (via clap's derive) as `Self::try_parse().unwrap_or_else(|e| e.exit())` — i.e. it already does exactly this, just without a chance to intervene before `e.exit()`. Swapping in `try_parse()` and reproducing the same `err.exit()` tail call preserves clap's existing exit-code and rendering behavior exactly, while giving us one place to print the splash first.

**Alternatives considered**:
- Overriding Clap's help/error templates to inject the banner text directly into clap's own rendering — rejected: couples banner content/styling to clap's template engine, harder to keep pixel-identical to the existing hand-rendered banner, and violates FR-010 ("do not change splash design").
- Wrapping `main` in a subprocess/pre-check that runs `--help` detection via raw `env::args()` before invoking clap — rejected: reimplements clap's own parsing/short-flag/subcommand-alias logic (e.g. `-h`, `help <subcmd>`), fragile and duplicative.

## Decision 2: Stream selection via `clap::Error::use_stderr()`

**Decision**: Use `err.use_stderr(): bool` (public API on `clap::error::Error` since clap 4) to choose the destination stream: `false` → stdout (this is true for `ErrorKind::DisplayHelp` and `ErrorKind::DisplayVersion`), `true` → stderr (every other kind, including `MissingSubcommand` and `MissingRequiredArgument`, which is what bare `etherfence`, `etherfence policy`, and `etherfence mcp-proxy` produce).

**Rationale**: This is the exact same predicate clap's own `Error::print()`/`Error::exit()` use internally (`stream()` matches `DisplayHelp | DisplayVersion => Stdout, _ => Stderr`), so our routing is guaranteed to agree with clap's, satisfying FR-002 without duplicating clap's internal `ErrorKind` matrix.

**Alternatives considered**: Matching on `err.kind()` ourselves — rejected: duplicates clap's internal stream-selection logic and can drift if clap adds new `ErrorKind` variants; `use_stderr()` is the stable, intended public accessor for exactly this decision.

## Decision 3: Generalize `banner::TerminalEnvironment`/`print_startup_banner` over an explicit `Stream`

**Decision**: Add a `pub(crate) enum Stream { Stdout, Stderr }` to `banner.rs` with stream-specific `is_terminal()`, `ansi_supported()`, and `terminal_width()` helpers (mirroring the existing stdout-only helpers). `TerminalEnvironment::current()` takes a `Stream` and uses it for every stream-dependent check. `print_startup_banner()` takes a `Stream` parameter and writes through `anstream::stdout()`/`anstream::stderr()` accordingly.

**Rationale**: Directly satisfies FR-003 ("base the eligibility check on the actual stream, not unconditionally on stdout") with the smallest possible change — the decision logic (`should_show`, `banner_style`, width/rule computation) is untouched; only the *source* of the environment facts becomes stream-parameterized. The existing successful-parse call site (`command_banner_mode` → `print_startup_banner`) keeps calling with `Stream::Stdout`, since every human command's own content already goes to stdout (verified: `println!`/`print!` throughout `run_policy_command`, `run_setup_command`, scan rendering; the one exception, the interactive wizard's `eprintln!` prompts, is out of scope per spec Assumptions).

**Alternatives considered**: Passing a raw `&dyn IsTerminal` / boxed writer — rejected: `anstream`'s `AutoStream::choice` and `terminal_size_of` need the concrete `io::Stdout`/`io::Stderr` handle, so a two-variant enum with explicit match arms is simpler and avoids trait-object overhead in a rarely-called startup path.

## Decision 4: `policy list` vs `policy show` classification

**Decision**: In `command_banner_mode`, match on `PolicyCommand` inside `Command::Policy { command }` instead of collapsing both to `Machine`: `PolicyCommand::List => Human` (no mode label, consistent with other unlabeled human commands like `setup plan`/`doctor`), `PolicyCommand::Show { .. } => Machine`.

**Rationale**: `PolicyCommand::List` prints a human-readable `name\tdescription` table (`run_policy_command`, `main.rs:2263-2267`) intended for interactive browsing, matching FR-007. `PolicyCommand::Show` prints the profile's raw TOML verbatim (`main.rs:2269-2276`) for piping into a file (`etherfence policy show strict > policy.toml`), matching FR-008 — a splash line would corrupt that TOML.

**Alternatives considered**: None — this is a direct, unambiguous reclassification named explicitly in the spec.

## Decision 5: Test strategy for stream-routing regressions

**Decision**: Extend `crates/etherfence-cli/tests/cli_banner.rs` with:
1. A table-driven PTY test (existing `run_in_pty` helper, all three std fds attached to one pseudo-terminal) asserting the splash's *banner-only* markers (see Decision 6) appear, and appear *before*, the command's own recognizable content, for each of the seven reported commands plus `policy list` and `--version`.
2. Non-PTY `Command::output()` tests (existing `redirected_stdout_suppresses_banner` pattern) asserting stdout/stderr separation under full redirection: help/version content lands only in `stdout` with `stderr` empty; usage/argument-error content lands only in `stderr` with `stdout` empty. This proves Clap's own stream routing (unconditional, independent of TTY state) but — because full redirection makes the splash ineligible on *either* stream (FR-006) — it cannot by itself prove the splash follows the correct stream *when it is shown*.
3. **Split-stream** PTY tests: a custom harness opens a real pseudo-terminal via `libc::openpty` and attaches it to exactly one of the child's stdout/stderr (via `Stdio::from(File)`), leaving the other as a normal `Stdio::piped()`. Four cases cover: help→stdout-is-the-terminal (splash+help on the terminal stream, piped stderr empty); error→stderr-is-the-terminal (splash+error on the terminal stream, piped stdout empty); and their inverses — help while *stderr* is the terminal and stdout is piped, and error while *stdout* is the terminal and stderr is piped — asserting the splash appears **nowhere** in the inverse cases. The inverse cases are what actually exercises FR-003 ("checks the actual destination stream, not unconditionally stdout"): a regression that reverted to always checking `io::stdout()` would incorrectly show the splash in the error-inverse case (stdout is the terminal, but the error's destination is the piped stderr).
4. Regression re-assertions (already-passing behavior, re-verified after refactor): JSON/Markdown/SARIF/setup-JSON/raw-TOML stay banner-free on a PTY; redirected output, `CI`, `NO_COLOR`, `CLICOLOR=0`, `TERM=dumb` stay suppressed; a running `mcp-proxy` session's stdout stays pristine (existing `cli_mcp_proxy.rs` coverage already asserts this — extended with an explicit banner-string absence check).

**Rationale**: `portable-pty` 0.9's `CommandBuilder` (the existing unix-only dev-dependency) does not expose separate stdout/stderr redirection — its `spawn_command` always wires all three child fds to the same pty slave. But `std::process::Command` itself *does* support per-stream `Stdio` values, including an arbitrary open file/fd (`Stdio::from(File)`) for exactly one of stdout/stderr while the other uses `Stdio::piped()` — no `dup2`/`pre_exec` needed. Combined with `libc::openpty` (already a transitive dependency via `portable-pty`, whose own `unix.rs` backend calls this exact same C function, so linking is already proven to work in this repo's CI) to obtain the pty pair directly, a genuinely split-stream harness is a modest, self-contained addition (~60 lines, one new unix-only dev-dependency: `libc`), not the large unsafe undertaking the original draft of this decision assumed.

**Alternatives considered** (superseded): An earlier draft of this decision deferred the split-stream harness as disproportionate scaffolding and relied only on items 1–2 above. Review feedback correctly identified that this left FR-003's core "correct destination stream" behavior — and the exact `stdout`-tty/`stderr`-piped (or inverse) edge case named in the spec — unverified by any automated test, so the split-stream harness (item 3) was added rather than deferred.

## Decision 6: Splash-only markers for the PTY ordering table

**Decision**: The table-driven PTY test (Decision 5, item 1) must not use the banner tagline (`"AI Agent Security Posture & Runtime Control"`) alone to detect the splash for any command whose Clap output includes that same text as its `about` string (`help`, `--help`, `policy --help`, `mcp-proxy --help`, and by extension `--version`'s sibling help text) — Clap prints that string in its own help body regardless of whether the splash printed, so a regression that removed the splash entirely could still pass such a check. Instead, the test asserts presence and ordering of two markers that only the rendered splash footer ever produces: the version line (`concat!("v", env!("CARGO_PKG_VERSION"))`) and, since the fixed 120-column test environment always selects the Unicode block-art `Standard` banner style, a literal fragment of that block art (`"███"`). Both must appear, and both must appear before the command's own content marker.

**Rationale**: `BANNER_TAGLINE` remains a safe, sufficient check for commands whose output has no Clap `about` text at all (e.g. `policy list`, `policy show`, `mcp-policy init`, `scan --format markdown/sarif` — none of these render Clap's top-level help), so those existing checks are unchanged. The ordering table specifically covers commands that *do* share text with Clap's `about` string, so it needs markers Clap never emits on its own.

**Alternatives considered**: Force a narrow terminal width in the ordering table so the compact banner's literal `"ETHERFENCE"` wordmark could serve as the product-name marker — rejected: it would diverge the ordering table's terminal environment from every other PTY test in the file (all fixed at 120 columns), for no accuracy benefit over the block-art fragment, which already proves the same thing at the width already in use everywhere else.
