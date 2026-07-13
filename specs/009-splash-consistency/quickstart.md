# Quickstart: Validating Terminal Splash Consistency

## Prerequisites

- Built binary: `cargo build`
- A real terminal (PTY) for the visibility checks — an SSH session or local
  terminal emulator, not a CI log viewer that itself pipes output.

## Manual validation (interactive terminal)

Run each of the following in an interactive, color-capable terminal (unset
`NO_COLOR`/`CI`, `TERM` not `dumb`) and confirm the splash (cyan/purple
"ETHERFENCE" wordmark + tagline/version rule) appears before the listed content:

```sh
./target/debug/etherfence                      # splash, then usage error (stderr)
./target/debug/etherfence help                  # splash, then help (stdout)
./target/debug/etherfence --help                # splash, then help (stdout)
./target/debug/etherfence policy                # splash, then usage error (stderr)
./target/debug/etherfence policy --help          # splash, then help (stdout)
./target/debug/etherfence policy list            # splash, then profile table (stdout)
./target/debug/etherfence policy show strict     # NO splash — raw TOML only
./target/debug/etherfence mcp-proxy              # splash, then usage error (stderr)
./target/debug/etherfence mcp-proxy --help       # splash, then help (stdout)
```

## Automated validation

```sh
cargo test -p etherfence-cli --test cli_banner
```

Covers, per [contracts/cli-splash-routing.md](./contracts/cli-splash-routing.md):

- Splash presence + ordering for all commands in the table above, on a PTY.
- Stream separation for non-PTY runs: help/version content only ever appears
  on captured stdout with stderr empty; usage/argument-error content only
  ever appears on captured stderr with stdout empty.
- Machine-format and raw-TOML outputs (JSON/Markdown/SARIF/setup-JSON,
  `policy show`, `mcp-policy init`) stay splash-free on a PTY.
- Redirected output, `CI=1`, `NO_COLOR=1`, `CLICOLOR=0`, `TERM=dumb` all
  continue to suppress the splash.

## Protocol-safety validation

```sh
cargo test -p etherfence-cli --test cli_mcp_proxy
```

Confirms a successfully-started `mcp-proxy` session's stdout carries only
JSON-RPC protocol bytes — no splash, on a PTY or otherwise.

## Full pre-PR gate

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo build
git diff --check
```
