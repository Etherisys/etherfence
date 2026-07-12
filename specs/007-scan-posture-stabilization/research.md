# Research: Scan Posture Presentation Stabilization

| Decision | Rationale | Alternative rejected |
|---|---|---|
| Extend `etherfence-cli/src/ui.rs` | It is the established terminal theme/layout layer and already supports color fallback. | A separate renderer/UI system would violate narrow scope. |
| Use terminal display columns and style after wrapping | ANSI bytes and wide Unicode must not affect line length. | Character/byte counts misalign colored or wide text. |
| Inject width in unit-level rendering helpers | Makes narrow-width tests deterministic without depending on the CI terminal. | Only subprocess terminal detection cannot reliably force width. |
| Keep machine renderers unchanged | JSON/Markdown/SARIF are compatibility contracts; this release is human presentation stabilization. | Reformatting them adds unnecessary compatibility risk. |
