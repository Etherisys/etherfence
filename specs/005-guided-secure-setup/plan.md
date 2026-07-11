# Implementation Plan: Guided Secure Setup and Complete AI Client Discovery

**Branch**: `feature/v1.6.0-guided-secure-setup` | **Date**: 2026-07-11 | **Spec**: [spec.md](./spec.md)

## Summary

Add a guided TTY setup wizard entry point (`etherfence setup` bare), refactor client detection to a trait-based adapter architecture with real-path probes for Hermes/OpenCode/Antigravity, enforce package version pinning in guided setup, replace the wildcard allow-all generated policy with deny-all quarantine, and gate setup decisions on trust assessment status — all while preserving existing subcommands, CI compatibility, and safety invariants.

## Technical Context

**Language/Version**: Rust 1.75+ (workspace `edition = "2021"`)
**Primary Dependencies**: `dialoguer` (new — TTY prompts), `serde_yaml` (promoted from dev to workspace dep — Hermes YAML config)
**Storage**: Local config files (JSON/YAML/TOML) read/written via existing bounded-read helpers
**Testing**: `cargo test --workspace` + new fixture directories + PTY-based wizard tests
**Target Platform**: Linux (primary), Windows (supported), macOS (supported) — TTY behavior must degrade gracefully on all

## Constitution Check

| Principle | Check | Status |
|---|---|---|
| I. Security-First, Deny-by-Default | Generated policies are deny-all by default; high-risk servers blocked; omitted versions blocked | PASS |
| II. Local-First Operation | No network calls added; package pinning is user-provided; registry lookups opt-in only (deferred) | PASS |
| III. Fail-Closed | Deny-all quarantine for unknown/malformed; pinning rejects ambiguous expressions; non-TTY fails with guidance | PASS |
| IV. Determinism & Audit Trail | Existing subcommands remain deterministic; JSON output deterministic; guided flow deterministic given same inputs | PASS |
| V. Fixture-Backed & Testable | New fixture directories for each client; PTY tests for wizard; existing test patterns extended | PASS |
| VI. Read-Only by Default | detect/plan/doctor remain read-only; apply only after explicit confirmation | PASS |
| VII. Explicit Boundaries | ClientAdapter trait cleanly separates detection/parsing/writing; wizard is presentation over existing engine | PASS |
| VIII. Progressive Disclosure | Guided wizard progressively reveals complexity; advanced subcommands remain accessible | PASS |
| IX. Cross-Platform | dialoguer supports Linux/macOS/Windows; non-TTY fallback explicit | PASS |
| X. Scope Discipline | No general content inspection; no MCP server execution; no network calls | PASS |

## Implementation Phases

### Phase 1: Client Detection Architecture (FR-002 through FR-005)
1. Define `ClientAdapter` trait in `etherfence-inventory`
2. Define `ClientDetection`, `ReadSupport`, `ConfigProbe`, `McpKey` types
3. Implement adapters for all 12 AgentKind variants (initial: Hermes, OpenCode, Antigravity with real paths; others with migration from existing CANDIDATES)
4. Wire PATH binary detection for all clients
5. Add YAML parsing for Hermes config
6. Add OpenCode array-command format parsing
7. Update `discover()` to use adapters
8. Update `catalog()` for backward-compatible `found_locally` derivation
9. Add fixture directories and unit tests

### Phase 2: Package Version Pinning (FR-006)
1. Define `PackageVersionStatus` enum
2. Implement extraction from npx/uvx/pipx args
3. Add pinning resolution logic (no network)
4. Add `PinningChange` struct
5. Wire into trust assessment as config risk indicator
6. Add fixture and unit tests

### Phase 3: Safe Policy Generation (FR-007)
1. Rewrite `generated_policy_template()` — deny-all default
2. Add `PolicyType` enum for curated/custom/deny-all
3. Validate all generated policies before writing
4. Update existing tests expecting `tools.allow = ["*"]`

### Phase 4: Trust-Gated Flow (FR-008)
1. Implement `GuidedStep` state machine
2. Gate step transitions on trust aggregate status
3. Block high-risk servers from normal policy selection
4. Integrate package version status into trust flow

### Phase 5: Guided TTY Wizard (FR-001, FR-010)
1. Add `dialoguer` dependency
2. Implement GuidedStep rendering with dialoguer widgets
3. Wire bare `etherfence setup` to wizard on TTY
4. Non-TTY detection and error message
5. PTY-based integration tests

### Phase 6: Apply/Rollback Integration (FR-009)
1. Wizard produces `SetupPlan` → calls existing `apply()`
2. Verify existing safety invariants preserved
3. Add wizard-apply integration tests

### Phase 7: Tests, Fixtures, and Gates
1. Unit tests per phase
2. Integration/CLI tests for full flow
3. PTY tests for wizard interaction
4. Fixture updates for all new detection paths
5. Run full repository gate

### Phase 8: Documentation
1. Update README.md (lead with `etherfence setup`)
2. Create docs/setup-onboarding.md (guided flow)
3. Update CHANGELOG.md
4. Update CLI examples

## Files Changed (predicted)

| Crate | Files | Change |
|---|---|---|
| etherfence-core | `lib.rs` | Add `ReadSupport` enum |
| etherfence-inventory | `lib.rs` | Add `ClientAdapter`, `ClientDetection`, refactor `discover()` |
| etherfence-inventory | `adapters/` (new) | Per-client adapter modules |
| etherfence-setup | `lib.rs` | New `SetupWizardPlan`, pinning logic, safe policy gen |
| etherfence-setup | `wizard.rs` (new) | Guided wizard state machine |
| etherfence-cli | `main.rs` | Wire bare `setup` to wizard |
| etherfence-cli | `wizard_render.rs` (new) | dialoguer rendering |
| Cargo.toml | Workspace | Add `dialoguer`, promote `serde_yaml` |
| tests/fixtures/ | New dirs | hermes-config, opencode-config, antigravity-config, pinning-fixtures |
| tests/ | New files | PTY wizard tests, pinning tests |
