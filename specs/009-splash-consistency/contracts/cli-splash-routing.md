# Contract: CLI Splash Visibility & Stream Routing

This documents the observable contract for `etherfence`'s startup splash — the
behavior external users, scripts, and tests may rely on. This is a CLI, so the
"contract" is the table below rather than a schema/API document.

## Splash visibility matrix

| Invocation | Destination stream | Splash on interactive+color terminal | Splash under redirect / CI / NO_COLOR / CLICOLOR=0 / TERM=dumb |
|---|---|---|---|
| `etherfence` (no args) | stderr | Yes, before usage error | No |
| `etherfence help` | stdout | Yes, before help text | No |
| `etherfence --help` / `-h` | stdout | Yes, before help text | No |
| `etherfence --version` / `-V` | stdout | Yes, before version text | No |
| `etherfence policy` (no subcommand) | stderr | Yes, before usage error | No |
| `etherfence policy --help` | stdout | Yes, before help text | No |
| `etherfence policy list` | stdout | Yes, before profile table | No |
| `etherfence policy show <profile>` | stdout | **No** (raw TOML, must stay pipeable) | No |
| `etherfence mcp-proxy` (missing required args) | stderr | Yes, before usage error | No |
| `etherfence mcp-proxy --help` | stdout | Yes, before help text | No |
| `etherfence mcp-proxy --policy P -- server...` (successfully running) | stdout | **No, ever** (protocol stream) | No |
| `etherfence scan` (human format) | stdout | Yes (existing behavior, unchanged) | No |
| `etherfence scan --format json\|markdown\|sarif` | stdout | **No** (machine format) | No |
| `etherfence setup detect --format json`, `setup baseline check --format json`, etc. | stdout | **No** (machine format) | No |
| `etherfence mcp-policy init --profile P` (no `--output`) | stdout | **No** (raw TOML) | No |
| `etherfence setup` (bare, interactive wizard) | stdout (splash); wizard prompts on stderr | Yes (existing behavior, unchanged) | No |
| Any invalid/unknown subcommand or flag | stderr | Yes, before usage error | No |

## Invariants

1. **Ordering**: whenever the splash appears, it appears strictly before the content it precedes, on the same write sequence.
2. **Stream fidelity**: the splash never appears on a stream other than the one that will receive the content it precedes. Redirecting the *other* stream must not affect whether/where the splash shows.
3. **Byte-for-byte machine safety**: any output whose format is JSON, Markdown, SARIF, raw TOML, or the live MCP JSON-RPC protocol stream is never prefixed, interleaved with, or otherwise touched by splash bytes, under any terminal/env condition.
4. **No visual change**: when the splash does appear, its glyphs, colors, wording, and width-responsive layout are unchanged from current `main` behavior.
5. **No behavioral change**: exit codes, which stream carries which content, and all non-splash output are unchanged from current `main` behavior.
