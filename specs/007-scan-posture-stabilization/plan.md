# Implementation Plan: Scan Posture Presentation Stabilization

**Branch**: `fix/v1.7.1-posture-presentation` | **Date**: 2026-07-12 | **Spec**: [spec.md](./spec.md)

## Summary

Stabilize only human scan presentation by centralizing terminal-width-aware wrapping in the existing CLI UI layer, then use it for default executive posture output and the verbose report renderer. Markdown, JSON, SARIF, posture derivation, and scan control flow remain unchanged.

## Technical Context

- **Language**: Rust 2021 workspace.
- **Existing dependencies**: `console` (through `dialoguer`) and transitive `unicode-width`; `terminal_size` is already used by the banner.
- **Approach**: Add a small reusable plain-text layout helper in `etherfence-report` and consume it from the existing CLI UI layer; terminal width detection remains in the existing `etherfence-cli/src/ui.rs`.
- **Tests**: report unit tests for verbose layout plus CLI/unit tests for summary layout, no-color/non-TTY behavior, fixed width, long Unicode/ASCII content, empty/info/high-threshold cases, and determinism.

## Constitution Check

| Principle | Decision | Status |
|---|---|---|
| I, II, VII, VIII | No policy, runtime, I/O, audit, or network behavior changes. | PASS |
| III | Retain advisory/read-only wording. | PASS |
| IV | Width choice is environment-derived; given the same explicit width/report, output order and text are deterministic. | PASS |
| V | Use fixture-backed regression tests; no detector/catalog change. | PASS |
| VI | Human-only rendering; JSON/Markdown/SARIF/schema are untouched. | PASS |
| IX | Version, changelog, docs, examples, Spec Kit artifacts, and full gate are included. | PASS |
| X, XI | Fixed presentation-only scope; no catalog work. | PASS |

## Design

1. Keep `UiTheme` as the only styling source. Add a shared plain-text wrapper in `etherfence-report`; the existing CLI UI layer derives terminal/fallback width and consumes that helper.
2. Use display-column measurement (not byte/character count) and wrap at whitespace when possible. Preserve unbreakable tokens only when unavoidable, indent continuations under their label/bullet, and style text only after layout so escape bytes cannot distort alignment.
3. Make default summary and verbose report call the helper for long key/value values and priority/action blocks. Preserve existing section titles, labels, ordering, and full-evidence semantics.
4. Leave Markdown, JSON, SARIF, report model, scan filtering, and exit handling unchanged. Update only terminology/documentation that describes the human posture view.

## Project Structure

```text
crates/etherfence-cli/src/ui.rs             # existing theme + terminal/fallback width
crates/etherfence-cli/src/main.rs           # default human posture summary use
crates/etherfence-report/src/human_layout.rs # shared Unicode-width wrapper
crates/etherfence-report/src/lib.rs         # verbose human posture/full finding use
crates/etherfence-cli/tests/cli_scan.rs     # subprocess plain/non-TTY + compatibility coverage
crates/etherfence-report/src/lib.rs tests   # long-content, Unicode, width layout regression tests
Cargo.toml / Cargo.lock                      # 1.7.1 package version
CHANGELOG.md, README.md, docs/install.md,
docs/json-schema.md, docs/examples/ci/baseline.json
specs/007-scan-posture-stabilization/        # Spec Kit lifecycle artifacts
```

## Validation

Run the required full workspace gate and focused human-format fixture scans. Verify `git diff --check`, stage only feature scope, then create an open PR to `main`.

## Complexity Tracking

No constitutional exception.
