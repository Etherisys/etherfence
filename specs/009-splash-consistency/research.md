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
1. A table-driven PTY test (existing `run_in_pty` helper, all three std fds attached to one pseudo-terminal) asserting the splash tagline appears, and appears *before*, the command's own recognizable content, for each of the seven reported commands plus `policy list`.
2. Non-PTY `Command::output()` tests (existing `redirected_stdout_suppresses_banner` pattern) asserting stdout/stderr separation: help/version content lands only in `stdout` with `stderr` empty; usage/argument-error content lands only in `stderr` with `stdout` empty — proving FR-002's routing without needing split-stream PTY plumbing.
3. Regression re-assertions (already-passing behavior, re-verified after refactor): JSON/Markdown/SARIF/setup-JSON/raw-TOML stay banner-free on a PTY; redirected output, `CI`, `NO_COLOR`, `CLICOLOR=0`, `TERM=dumb` stay suppressed; a running `mcp-proxy` session's stdout stays pristine (existing `cli_mcp_proxy.rs` coverage already asserts this — extended with an explicit banner-string absence check).

**Rationale**: `portable-pty` 0.9's `CommandBuilder` (the existing unix-only dev-dependency) does not expose separate stdout/stderr redirection — a PTY is inherently one merged stream for all three standard fds of the child. Building genuinely separate stdout-is-tty/stderr-is-pipe fixtures would require dropping to raw `libc::openpty` + manual `dup2`, a disproportionate amount of new low-level unsafe test scaffolding for a fix this narrowly scoped (spec explicitly limits scope to `crates/etherfence-cli`). The chosen two-pronged strategy still directly exercises both required properties: PTY tests prove content+splash ordering and presence on an interactive terminal; plain-pipe `Command::output()` tests prove strict stream separation (nothing leaks to the wrong stream) using the same well-established assertion style already used elsewhere in this file.

**Alternatives considered**: Add `libc` as a unix-only dev-dependency and hand-roll a split-stream PTY harness — deferred as unnecessary given Decision 5's two-pronged approach already covers every acceptance scenario in the spec; can be revisited if a future regression specifically needs a mixed tty/non-tty stream test.
