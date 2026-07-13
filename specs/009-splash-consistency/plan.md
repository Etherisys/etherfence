# Implementation Plan: Terminal Splash Consistency

**Branch**: `fix/splash-consistency` | **Date**: 2026-07-13 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/009-splash-consistency/spec.md`

## Summary

`Cli::parse()` in `crates/etherfence-cli/src/main.rs` exits the process from inside Clap (help, version, missing-subcommand, invalid-argument) before `print_startup_banner()` ever runs, so seven human-facing invocations skip the splash. Fix: parse with `Cli::try_parse()`, and on `Err`, print the splash to whichever stream Clap will use for that error (stdout for help/version via `err.use_stderr() == false`, stderr otherwise) before calling `err.exit()`. Generalize `banner.rs`'s terminal/eligibility check to take an explicit `Stream` (stdout or stderr) instead of hardcoding stdout, and reuse that same generalized check for the existing successful-parse banner call. Reclassify `policy list` as human (splash-eligible) while keeping `policy show` machine (splash-free). No change to banner visuals, command behavior, or exit codes.

## Technical Context

**Language/Version**: Rust (workspace edition/toolchain as pinned in `Cargo.toml` / `rust-toolchain`)

**Primary Dependencies**: `clap` 4.6 (derive), `anstream`, `terminal_size`, existing in-crate `banner.rs`/`ui.rs`

**Storage**: N/A

**Testing**: `cargo test` — `crates/etherfence-cli/tests/cli_banner.rs` (unix PTY integration tests via `portable-pty`, dev-dependency) plus `banner.rs` unit tests

**Target Platform**: CLI binary, CI matrix ubuntu-latest + windows-latest (PTY tests are unix-only, matching existing `cli_banner.rs` convention)

**Project Type**: Single Rust workspace, CLI crate (`etherfence-cli`)

**Performance Goals**: N/A (display/control-flow only; no measurable perf target)

**Constraints**: Must not change banner design/colors/wording; must not change any command's functional behavior or exit codes; must not introduce a daemon/network/new dependency (constitution Principles I–II, X); `mcp-proxy` protocol stdout must stay pristine in all cases (Principle VII).

**Scale/Scope**: Two source files (`main.rs`, `banner.rs`) in one crate, plus their tests, `CHANGELOG.md`, and `docs/` mentions of the splash if any.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **I. Security-First, Deny-by-Default**: N/A to this display-only change; no policy/config parsing touched. The one adjacent safety property (mcp-proxy protocol stdout purity) is preserved unchanged, not weakened. **PASS**
- **II. Local-First Operation**: No daemon, network, or new external dependency introduced. **PASS**
- **III. Truth in Claims**: No claims language changed. **PASS**
- **IV. Deterministic Output**: Splash content itself is unchanged; only *when/where* it's printed changes, and that is now more consistent (deterministic) across invocations, not less. **PASS**
- **V. Fixture-Backed Findings and Classifications**: N/A — no findings/classifications involved. **PASS**
- **VI. Schema Compatibility**: No schema (`ef-*`) output touched; JSON/Markdown/SARIF/setup-JSON/raw-TOML remain byte-identical (explicit requirement FR-005). **PASS**
- **VII. Fail-Closed Runtime Proxy Behavior**: `mcp-proxy`'s successful-run protocol stdout purity is an explicit invariant of this change (FR-004) and is tested. The *parse-error* path for `mcp-proxy` (missing args, `--help`) is pre-execution — the proxy never starts — so splash-before-error there does not touch protocol stdout. **PASS**
- **VIII. Audit Log Safety**: Not touched. **PASS**
- **IX. Complete Release Packaging**: No release-workflow changes. **PASS**
- **X. Scope Discipline**: This is exactly the kind of narrowly-scoped display/control-flow fix scope discipline calls for — no daemon/hook/interception added, confined to `etherfence-cli`. **PASS**
- **XI. Catalog Classification Discipline**: N/A. **PASS**

No violations. Complexity Tracking table not needed.

## Project Structure

### Documentation (this feature)

```text
specs/009-splash-consistency/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/
│   └── cli-splash-routing.md
└── tasks.md              # Phase 2 output (/speckit-tasks)
```

### Source Code (repository root)

**Structure Decision**: Existing single-crate CLI layout; no new crates or directories. All production changes live in `crates/etherfence-cli/src/`:

```text
crates/etherfence-cli/
├── src/
│   ├── main.rs      # Cli::try_parse() flow, command_banner_mode, run_policy_command
│   └── banner.rs    # Stream-aware TerminalEnvironment / print_startup_banner
└── tests/
    └── cli_banner.rs  # Extended table-driven PTY coverage for the reported commands
```

## Complexity Tracking

Not applicable — no Constitution Check violations.
