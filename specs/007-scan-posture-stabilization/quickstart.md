# Validation Quickstart

From the feature worktree:

```sh
cargo test -p etherfence-cli --test cli_scan scan_fixture_human
cargo test --workspace
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo build --workspace
git diff --check
```

Manual smoke checks use fixtures, not `$HOME`:

```sh
NO_COLOR=1 cargo run -- scan --root tests/fixtures/home
cargo run -- scan --root tests/fixtures/home --verbose --severity-threshold high
cargo run -- scan --root tests/fixtures/safe-home
```

Expected: readable default/verbose human reports; no ANSI sequences in the first command; unchanged machine report contract.
