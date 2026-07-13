# Phase 1 Data Model: Terminal Splash Consistency

This feature has no persisted data, schema, or storage entities. The "entities"
here are in-process control-flow types in `crates/etherfence-cli/src/banner.rs`
and `main.rs`, documented for design-record purposes only.

## `banner::Stream`

Which of the two standard output streams a given splash print targets.

| Value  | Meaning |
|--------|---------|
| `Stdout` | Splash and content both go to stdout — successful human commands, and Clap `DisplayHelp`/`DisplayVersion` errors. |
| `Stderr` | Splash and content both go to stderr — Clap errors other than help/version (missing subcommand, missing required argument, invalid argument/value). |

Derived from `clap::error::Error::use_stderr()` on the parse-error path; hardcoded
to `Stdout` on the successful-parse path (every human command's own output already
targets stdout).

## `banner::TerminalEnvironment` (revised)

Existing struct, now constructed per-`Stream` instead of always reading `io::stdout()`.

| Field | Before | After |
|-------|--------|-------|
| `stdout_is_terminal` → `stream_is_terminal` | `io::stdout().is_terminal()` | `stream.is_terminal()` (matches `io::stdout()` or `io::stderr()`) |
| `columns` | `terminal_size_of(io::stdout())` | `terminal_size_of` on the matching stream, `terminal_size_of` has no stderr accessor in `terminal_size` crate — see note below |
| `ansi_supported` | `AutoStream::choice(&io::stdout())` | `AutoStream::choice(&io::stdout())` or `&io::stderr())` |
| `no_color`, `ci`, `clicolor_disabled`, `term`, `unicode` | env-based, stream-independent | unchanged |

Note: the `terminal_size` crate's `terminal_size_of` takes any `AsFd`/handle, so it
extends to `io::stderr()` the same way it already works for `io::stdout()` — no
new dependency needed.

## `Command::Policy` banner classification (revised)

| Subcommand | Before | After |
|------------|--------|-------|
| `PolicyCommand::List` | `OutputMode::Machine` | `OutputMode::Human` (no mode label) |
| `PolicyCommand::Show { profile }` | `OutputMode::Machine` | `OutputMode::Machine` (unchanged) |

## Invocation outcome (conceptual, not a new type)

Every `etherfence` process run resolves to exactly one of:

1. **Clap parse failure** (help, version, missing subcommand, invalid argument) — new: splash printed to the stream `err.use_stderr()` selects, then `err.exit()`.
2. **Successful parse, human command** — unchanged: splash printed to stdout via `command_banner_mode`, then the command runs.
3. **Successful parse, machine/protocol command** — unchanged: no splash, command runs.
