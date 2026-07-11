# Quickstart: Validating Argument-Aware MCP Runtime Policy

Prerequisites: workspace built (`cargo build`), a shell in the repo root.

## 1. Generate the new example profile

```sh
cargo run -p etherfence-cli -- mcp-policy init --profile github-scoped-orgs
```

Expect TOML output declaring `schema_version = "ef-mcp-policy/v0.2"`, an allowed
`github.create_issue` tool, and an `arguments.fields."org"` enum guard.

## 2. Validate it

```sh
cargo run -p etherfence-cli -- mcp-policy init --profile github-scoped-orgs --output /tmp/policy.toml
cargo run -p etherfence-cli -- mcp-policy validate /tmp/policy.toml
```

Expect: `OK: ... is a valid MCP proxy policy ...`.

## 3. Explain it

```sh
cargo run -p etherfence-cli -- mcp-policy explain /tmp/policy.toml
```

Expect a `Guarded keys:`-style section (or a new dedicated section) listing the `org` field guard,
its scope, and its enum values, alongside the existing tool/method/path-rule summary.

## 4. Dry-run an allowed and a denied call

```sh
cargo run -p etherfence-cli -- mcp-policy check --policy /tmp/policy.toml --request \
  '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"github.create_issue","arguments":{"org":"my-org","repo":"my-org/svc","title":"x"}}}'

cargo run -p etherfence-cli -- mcp-policy check --policy /tmp/policy.toml --request \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"github.create_issue","arguments":{"org":"other-org","repo":"other-org/svc","title":"x"}}}'
```

Expect the first `allowed: true`, the second `allowed: false` with a reason category naming an
enum mismatch on `org` — and neither output line contains the literal string `other-org`'s sibling
denied context beyond the key name (spot-check: `grep` the output for the guarded values only where
the fixture intentionally expects an echo of an *allowed* value, never a denied one beyond its
key).

## 5. Confirm proxy/check equivalence

```sh
cargo test -p etherfence-mcp
```

The `policy_ux.rs` test module includes `check_*` tests that assert `dry_run_check` and
`inspect_client_line`/`inspect_server_line` agree; new v0.2 tests follow the same pattern (see
`tasks.md`).

## 6. Full verification gate

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
cargo build
git diff --check
```

All five must pass before the feature is considered done (constitution Development Workflow gate).
