# EtherFence terminal demo

This directory contains the reproducible terminal demo used near the top of the repository README.

The demo shows the complete product story without faking CLI output:

1. **Identity + posture scan** — `etherfence scan --root .` prints the real
   colored ETHERFENCE splash, then discovers local AI agent risks
2. **MCP setup assessment** — `etherfence setup detect --root .` assesses
   MCP server capability, trust, and starter-policy recommendation
3. **Runtime policy enforcement** — `etherfence mcp-policy check` denies an
   unauthorized `filesystem.write` with a multiline shell command

All three scenes use real compiled EtherFence binary output. The demo
workspace fixture describes a Claude Code filesystem MCP server with an
unpinned `npx` package reference. The fixture contains no synthetic or
staged findings — every displayed risk is naturally produced by the real
detection and scan engines.

## Files

- `workspace/.claude.json` — supported Claude Code-style MCP configuration fixture (no synthetic env vars).
- `workspace/project/` — harmless repository-local project directory referenced by the fixture.
- `workspace/project-readonly.toml` — valid `ef-mcp-policy/v0.1` read-only MCP proxy policy.
- `workspace/request.json` — valid JSON-RPC `tools/call` request for `filesystem.write`.
- `etherfence.tape` — VHS tape for the demo recording.
- `run-demo.sh` — builds the release binary, renders an HD MP4 directly from VHS, then generates an optimized GIF from the MP4 source.
- `verify-demo.sh` — builds the release binary and semantically verifies all three demo stages without VHS.

## Behavioral verification

Run this on any development machine with Rust installed:

```sh
./demo/verify-demo.sh
```

The verification:
- Prevents `npx`, `uvx`, and `pipx` from executing via fake PATH entries.
- Asserts `scan --root demo/workspace` produces expected inventory and real findings.
- Asserts `setup detect --root demo/workspace` produces expected MCP analysis.
- Asserts `mcp-policy check` returns the expected DENY decision.
- Confirms no configured package runner was launched during any command.
- Confirms the EtherFence tagline appears in help output.

## Recording generation

Rendering the assets additionally requires Charmbracelet VHS and its runtime
dependencies, including `ttyd` 1.7.2 or newer, `ffmpeg`, and the
**DejaVu Sans Mono** font:

```sh
./demo/run-demo.sh
```

`run-demo.sh`:
1. Verifies font availability through `fc-list` (fontconfig required).
2. Validates `ttyd >= 1.7.2` with portable version parsing.
3. Builds `target/release/etherfence`.
4. Renders `docs/assets/etherfence-demo.mp4` directly from VHS (high-quality h264 source).
5. Converts the MP4 to `docs/assets/etherfence-demo.gif` using ffmpeg with a 256-color palette and Sierra Lite dithering for sharp terminal text.

The tape runs without `CI=1` so the real colored EtherFence splash appears.
The commands still run against the real EtherFence binary and work outside VHS.

VHS generation is primarily a Linux workflow (requires fontconfig, ttyd, and
headless Chromium). macOS users may need to adapt font detection. Windows users
can run `demo/verify-demo.sh` from Git Bash/WSL or rely on the Rust integration
test (`cargo test --test cli_demo`) for cross-platform fixture validation.

## Tape specifications

| Setting | Value |
|---|---|
| Canvas | 1280 × 760 px |
| Font | DejaVu Sans Mono, 26 px |
| Framerate | 10 fps |
| Theme | Builtin Dark (near-black, high-contrast) |
| Typing speed | 30 ms per character |
| Duration | ~25 seconds |

### Scene flow

| Time | Scene | Command |
|---|---|---|
| 0–7s | Identity + scan | `etherfence scan --root .` (splash auto-printed before scan output) |
| 7–15s | Setup assessment | `etherfence setup detect --root .` |
| 15–23s | Policy decision preview | `etherfence mcp-policy check` (multiline) |

## Accessibility

The tape uses a 1280×760 canvas, a near-black high-contrast theme (Builtin Dark),
and 26 px DejaVu Sans Mono text so the GIF remains readable in the GitHub README.
README alt text describes the security outcome for users who cannot view the
animation. A higher-quality MP4 direct source is also available at
`docs/assets/etherfence-demo.mp4`.
