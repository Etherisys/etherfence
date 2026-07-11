# Tasks: Guided Secure Setup v1.6.0

Tasks are ordered by dependency. Each task is independently testable.

## Phase 1: Client Detection Architecture

### T1.1: Define ClientAdapter trait and supporting types
- **Files**: `crates/etherfence-core/src/lib.rs` (ReadSupport, ConfigFormat::Yaml), `crates/etherfence-inventory/src/lib.rs` (ClientAdapter trait, ClientDetection, ConfigProbe, McpKey)
- **Test**: Unit test that trait can be implemented
- **AC**: FR-002 (independent concepts), FR-009 (no breakage)

### T1.2: Implement PATH binary detection
- **Files**: `crates/etherfence-inventory/src/lib.rs` (probe_binary function)
- **Test**: Binary on PATH → detected; not on PATH → not detected; mockable
- **AC**: FR-002 installation evidence

### T1.3: Implement Hermes adapter with real config paths
- **Files**: `crates/etherfence-inventory/src/adapters/hermes.rs` (new)
- **Test**: 
  - `~/.hermes/config.yaml` with `mcp_servers:` entries → full detection
  - Config exists but no `mcp_servers:` → configured but no MCP
  - No config but `hermes` on PATH → installed, not configured
  - Neither → not found
- **AC**: FR-003

### T1.4: Implement OpenCode adapter with real config paths
- **Files**: `crates/etherfence-inventory/src/adapters/opencode.rs` (new)
- **Test**:
  - `~/.config/opencode/config.json` with `mcp` entries → full detection
  - Array-command format properly parsed to command+args
  - OpenCode binary on PATH detection
- **AC**: FR-004

### T1.5: Implement Antigravity adapter with real config paths
- **Files**: `crates/etherfence-inventory/src/adapters/antigravity.rs` (new)
- **Test**:
  - `~/.gemini/config/mcp_config.json` → full detection
  - `.agents/mcp_config.json` project config → full detection
  - `serverUrl` remote servers parsed correctly
- **AC**: FR-005

### T1.6: Migrate existing clients to adapter pattern
- **Files**: `crates/etherfence-inventory/src/adapters/claude.rs`, `cursor.rs`, `vscode.rs`, `windsurf.rs`, `gemini_cli.rs`, `codex_cli.rs`, `cline.rs`, `roocode.rs` (new)
- **Test**: Existing catalog tests pass unchanged (backward compat)
- **AC**: FR-009 (existing behavior preserved)

### T1.7: Wire adapter-based discovery
- **Files**: `crates/etherfence-inventory/src/lib.rs` (refactor `discover()`)
- **Test**: All existing fixture tests pass; new fixtures for Hermes/OpenCode/Antigravity
- **AC**: FR-002, FR-009

### T1.8: Backward-compatible catalog output
- **Files**: `crates/etherfence-setup/src/catalog.rs`
- **Test**: 10-row matrix unchanged; `found_locally` derived from `installed || configured`
- **AC**: FR-009

### T1.9: Add fixture directories for new clients
- **Files**: `tests/fixtures/hermes-home/`, `tests/fixtures/opencode-home/`, `tests/fixtures/antigravity-home/`, `tests/fixtures/mixed-home/`
- **Test**: Each fixture contains synthetic config files; tests verify detection
- **AC**: FR-003, FR-004, FR-005

## Phase 2: Package Version Pinning

### T2.1: Define PackageVersionStatus and extraction logic
- **Files**: `crates/etherfence-setup/src/pinning.rs` (new)
- **Test**:
  - `npx -y pkg@1.2.3` → ExactPin
  - `npx -y @scope/pkg@1.2.3` → ExactPin
  - `npx -y pkg` → Omitted
  - `npx -y pkg@latest` → MutableTag
  - `uvx pkg@1.2.3` → ExactPin (uvx positional)
  - `uvx --from pkg@1.2.3` → ExactPin
  - `uvx pkg` → Omitted
  - `pipx run --spec pkg==1.2.3` → ExactPin
  - `pipx run pkg` → Omitted
  - `node server.js` → NotApplicable
- **AC**: FR-006

### T2.2: Pinning resolution logic
- **Files**: `crates/etherfence-setup/src/pinning.rs`
- **Test**: Pin change preserves unrelated args; scoped npm packages handled; npx launcher flags preserved; uvx `--from` handled; pipx `--spec` handled
- **AC**: FR-006 (pinning mutation requirements)

### T2.3: Wire pinning into trust assessment
- **Files**: `crates/etherfence-setup/src/trust.rs` (extend indicators)
- **Test**: Omitted version → HighRisk indicator; mutable tag → HighRisk; range → HighRisk; exact pin → no indicator
- **AC**: FR-008 (trust integration)

## Phase 3: Safe Policy Generation

### T3.1: Rewrite generated_policy_template to deny-all
- **Files**: `crates/etherfence-setup/src/lib.rs` (modify `generated_policy_template()`)
- **Test**: Generated policy validates; contains `allow = []` not `["*"]`; methods still `["tools/list"]`
- **AC**: FR-007

### T3.2: Add PolicyType enum and curated policy support
- **Files**: `crates/etherfence-setup/src/lib.rs`
- **Test**: DenyAllQuarantine generates quarantined policy; CustomToolAllowlist generates with user names
- **AC**: FR-007

### T3.3: Validate policies before writing
- **Files**: `crates/etherfence-setup/src/lib.rs`
- **Test**: Invalid tool names rejected at generation time; policy parse failure blocks apply
- **AC**: FR-007, safety invariant

## Phase 4: Trust-Gated Flow

### T4.1: Define GuidedStep state machine
- **Files**: `crates/etherfence-setup/src/wizard.rs` (new)
- **Test**: All step transitions valid; no invalid transitions possible
- **AC**: FR-008

### T4.2: Gate server eligibility on trust aggregate
- **Files**: `crates/etherfence-setup/src/wizard.rs`
- **Test**:
  - verified-local → can proceed to policy selection
  - known-source → can proceed after version review
  - unknown → require review/skip/quarantine
  - needs-review → require resolution
  - high-risk → only skip or deny-all quarantine
- **AC**: FR-008

### T4.3: Integrate pinning into trust flow
- **Files**: `crates/etherfence-setup/src/wizard.rs`
- **Test**: Omitted version flagged as blocker; resolved version proceeds
- **AC**: FR-008

## Phase 5: Guided TTY Wizard

### T5.1: Add dialoguer dependency
- **Files**: `Cargo.toml` (workspace), `crates/etherfence-cli/Cargo.toml`
- **Test**: Build succeeds with new dependency
- **AC**: FR-001 (dependency available)

### T5.2: Implement Scan step rendering
- **Files**: `crates/etherfence-cli/src/wizard_render.rs` (new)
- **Test**: Scan shows detected clients with installation/config/MCP evidence
- **AC**: FR-001

### T5.3: Implement SelectClients step (multi-select)
- **Files**: `crates/etherfence-cli/src/wizard_render.rs`
- **Test**: User can select/deselect clients; keyboard navigation works
- **AC**: FR-001

### T5.4: Implement SelectServers step
- **Files**: `crates/etherfence-cli/src/wizard_render.rs`
- **Test**: Shows servers per selected client with transport/trust/package status
- **AC**: FR-001

### T5.5: Implement ResolveBlockers step
- **Files**: `crates/etherfence-cli/src/wizard_render.rs`
- **Test**: Version pinning prompt; high-risk warning; skip option
- **AC**: FR-006, FR-008

### T5.6: Implement SelectPosture step
- **Files**: `crates/etherfence-cli/src/wizard_render.rs`
- **Test**: Deny-all / custom allowlist / skip options
- **AC**: FR-007

### T5.7: Implement Preview step
- **Files**: `crates/etherfence-cli/src/wizard_render.rs`
- **Test**: Shows all pending changes; policy locations; backup locations; pinning diffs
- **AC**: FR-001 (UX requirements)

### T5.8: Implement Confirm step
- **Files**: `crates/etherfence-cli/src/wizard_render.rs`
- **Test**: Confirmation proceeds to apply; decline performs no writes
- **AC**: FR-001

### T5.9: Wire bare `setup` to wizard on TTY
- **Files**: `crates/etherfence-cli/src/main.rs`
- **Test**: TTY → wizard; non-TTY → error with subcommand guidance
- **AC**: FR-001, FR-010

### T5.10: Ctrl+C cancellation
- **Files**: `crates/etherfence-cli/src/main.rs`
- **Test**: Ctrl+C at any step before confirm → no writes; clean exit
- **AC**: FR-001 (acceptance scenario 3)

## Phase 6: Apply/Rollback Integration

### T6.1: Wizard → apply() integration
- **Files**: `crates/etherfence-setup/src/wizard.rs`, `crates/etherfence-cli/src/main.rs`
- **Test**: Wizard plan feeds into existing apply; atomic writes; backup creation
- **AC**: FR-009, safety invariants

### T6.2: Verify existing safety invariants
- **Files**: Run existing setup tests
- **Test**: All existing setup tests pass; rollback still works; double-wrap still detected
- **AC**: FR-009, safety invariants

## Phase 7: Tests, Fixtures, and Gates

### T7.1: Adapter unit tests
- **Test**: Each adapter tested for: binary presence/absence, config presence/absence, MCP parse success/failure, format errors
- **AC**: All acceptance criteria for FR-002-FR-005

### T7.2: Pinning unit tests
- **Test**: All version expression patterns; all runner types; arg preservation
- **AC**: FR-006

### T7.3: Policy generation tests
- **Test**: Deny-all validates; curated validates; custom validates; never contains `["*"]`
- **AC**: FR-007

### T7.4: Trust gating tests
- **Test**: All aggregate status → wizard behavior mappings
- **AC**: FR-008

### T7.5: CLI integration tests (non-TTY)
- **Test**: `setup detect`, `setup catalog`, `setup plan`, `setup apply` still work; JSON output valid and banner-free
- **AC**: FR-009, FR-010

### T7.6: Wizard PTY tests
- **Test**: Full guided flow with simulated input; cancellation; malformed input handling
- **AC**: FR-001

### T7.7: Non-TTY guard test
- **Test**: `etherfence setup` without TTY → error message, exit non-zero, no hang
- **AC**: FR-010

### T7.8: Apply/rollback safety tests
- **Test**: Full plan validates before write; backups created; unknown fields preserved; rollback after user edit rejected
- **AC**: Safety invariants

### T7.9: Output leakage tests
- **Test**: No secret in stdout/stderr; env values redacted; JSON deterministic; suspicious payloads not echoed
- **AC**: Safety invariants

### T7.10: Run full repository gate
- **Commands**: `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test`, `cargo build`, `git diff --check`
- **AC**: All gates pass

## Phase 8: Documentation

### T8.1: Update README.md
- **Files**: `README.md`
- **Change**: Lead with `etherfence setup`; document subcommands as advanced usage
- **AC**: Documentation requirement

### T8.2: Create docs/setup-onboarding.md
- **Files**: `docs/setup-onboarding.md` (new)
- **Content**: Full guided setup flow; detection methodology; pinning explained; policy refinement; rollback guarantees; what setup never does
- **AC**: Documentation requirement

### T8.3: Update CHANGELOG.md
- **Files**: `CHANGELOG.md`
- **Content**: v1.6.0 entry with problem statement, user-visible changes, architecture summary
- **AC**: Documentation requirement

### T8.4: Update CLI examples and demo scripts
- **Files**: `docs/`, `examples/`
- **Content**: Guided setup example; non-interactive CI example
- **AC**: Documentation requirement
