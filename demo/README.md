# EtherFence terminal demo

This directory contains the reproducible terminal demo used near the top of the repository README.

The demo shows the current product story without faking CLI output:

1. `etherfence setup detect --root .` (from `demo/workspace`) inspects a repository-owned Claude Code MCP configuration fixture.
2. The fixture describes a filesystem MCP server launched through `npx`, with an omitted package version and a secret-looking environment variable name.
3. `etherfence mcp-policy check --policy project-readonly.toml --request request.json` evaluates a JSON-RPC `tools/call` request for `filesystem.write`.
4. The read-only policy denies the write request locally, without starting or contacting any MCP server.

## Files

- `workspace/.claude.json` — supported Claude Code-style MCP configuration fixture.
- `workspace/project/` — harmless repository-local project directory referenced by the fixture.
- `workspace/project-readonly.toml` — valid `ef-mcp-policy/v0.1` read-only MCP proxy policy.
- `workspace/request.json` — valid JSON-RPC `tools/call` request for `filesystem.write`.
- `etherfence.tape` — VHS tape for `docs/assets/etherfence-demo.gif`.
- `run-demo.sh` — builds the release binary, renders the GIF with VHS, optimises with ffmpeg palette pass, and generates an HD MP4.
- `verify-demo.sh` — builds the release binary and semantically verifies the demo behavior without VHS.

## Behavioral verification

Run this on any development machine with Rust installed:

```sh
./demo/verify-demo.sh
```

The verification intentionally prepends fake `npx`, `uvx`, and `pipx` executables to `PATH` and fails if any configured package runner is launched. `setup detect` must only parse the fixture; it must not execute configured MCP commands, install packages, or contact the network. `mcp-policy check` is serverless and evaluates the request with the same policy decision helpers used by the live stdio proxy.

## Recording generation

Rendering the GIF additionally requires Charmbracelet VHS and its runtime
dependencies, including `ttyd` 1.7.2 or newer, `ffmpeg`, and the
**DejaVu Sans Mono** font:

```sh
./demo/run-demo.sh
```

`run-demo.sh` builds `target/release/etherfence`, puts that real binary on `PATH` for the tape, and writes both `docs/assets/etherfence-demo.gif` (optimized with ffmpeg palette pass) and `docs/assets/etherfence-demo.mp4` (HD h264). The tape suppresses the interactive startup banner with the standard `CI=1` environment so the short README recording focuses on command output. The commands still run against the real EtherFence binary and work outside VHS.

Depending on the local VHS/browser setup, the first render may download a
headless Chromium runtime. The underlying EtherFence demo commands themselves
do not require internet access and are covered by `verify-demo.sh`.

VHS generation is primarily a Linux/macOS workflow. Windows users can run `demo/verify-demo.sh` from Git Bash/WSL or rely on the Rust integration test for cross-platform fixture validation.

## Tape specifications

| Setting | Value |
|---|---|
| Canvas | 1280 × 760 px |
| Font | DejaVu Sans Mono, 26 px |
| Framerate | 10 fps |
| Theme | Builtin Dark (high-contrast) |
| Typing speed | 30 ms per character |
| Duration | ~18 seconds |

The recording uses two clear scenes separated by a terminal clear (`Ctrl+L`):

1. Posture discovery (`setup detect --root .` from `demo/workspace`)
2. Policy enforcement (`mcp-policy check` with shortened relative paths)

## Accessibility

The tape uses a 1280×760 canvas, a near-black high-contrast theme (Builtin Dark),
and 26 px DejaVu Sans Mono text so the GIF remains readable in the GitHub README.
README alt text describes the security outcome for users who cannot view the
animation. A higher-quality MP4 is also generated at `docs/assets/etherfence-demo.mp4`.
