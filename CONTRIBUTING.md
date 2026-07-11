# Contributing to EtherFence

Thanks for helping improve EtherFence. This project is a local-first AI-agent
security tool, so changes should preserve its safety boundaries: read-only scan
behavior by default, explicit opt-in runtime enforcement, fail-closed MCP policy
handling, and no cloud control plane.

## Before opening a PR

Run the standard local checks:

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
cargo build
```

For documentation-only changes, also run:

```sh
git diff --check
```

## Contribution guidelines

- Keep security claims precise and scoped to tested behavior.
- Do not add network services, telemetry, cloud dependencies, or daemon behavior
  without an explicit design discussion.
- Prefer fixture-backed tests for scanner, setup, and MCP policy behavior.
- Keep examples free of real secrets, tokens, private paths, and personal data.
- Update relevant docs when changing CLI behavior, policy schema, output schema,
  or supported MCP client/server workflows.

## Useful references

- Install/build: [`docs/install.md`](docs/install.md)
- Threat model: [`docs/threat-model.md`](docs/threat-model.md)
- MCP proxy operator guide: [`docs/mcp-proxy-operator-guide.md`](docs/mcp-proxy-operator-guide.md)
- Roadmap: [`docs/roadmap.md`](docs/roadmap.md)
