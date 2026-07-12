# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What EtherFence is

A local-first Rust CLI (`etherfence`) for AI-agent security posture and MCP runtime control. Three surfaces: read-only posture scanning (`scan`), MCP onboarding/assessment (`setup …`), and the only runtime-enforcement component — a fail-closed MCP stdio boundary proxy (`mcp-proxy`). There is deliberately **no daemon, no shell/browser/kernel hook, no network interception, and no cloud dependency**; introducing any of those is a constitutional change, not a feature (see `.specify/memory/constitution.md`).

## Commands

```sh
cargo build
cargo test                                    # full workspace suite
cargo test -p etherfence-setup                # one crate
cargo test -p etherfence-setup --test wizard_apply        # one integration-test file
cargo test -p etherfence-cli --test cli_scan scan_fixture # tests matching a name
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
```

CI (`.github/workflows/ci.yml`) runs fmt-check, clippy `-D warnings`, and `cargo test` on **ubuntu-latest and windows-latest**. The expected pre-PR gate is: `cargo fmt --check`, clippy as above, `cargo test`, `cargo build`, `git diff --check` — all must be clean.

Run the binary against a fixture instead of your real home:

```sh
cargo run -- scan --root tests/fixtures/home
cargo run -- setup detect --root tests/fixtures/trust-home --format json
```

`--root` is a hidden flag on `scan` and every `setup` subcommand; it defaults to `$HOME`. The interactive wizard (`etherfence setup` with no subcommand) requires a TTY and always uses the real home — don't try to drive it in tests; test the engine (`build_wizard_plan`/`apply_wizard_plan`) directly instead.

Releases are cut by manually dispatching `.github/workflows/release.yml` (validates version/CHANGELOG/tag, builds Linux+Windows artifacts, creates the tag and GitHub release). Never dispatch it without being asked. Version bumps happen inside the feature branch (workspace `version` in `Cargo.toml`, version assertions in `crates/etherfence-cli/tests/cli_scan.rs`, `docs/install.md`, and the regenerated `docs/examples/ci/baseline.json`).

## Workspace architecture

Dependency direction (all crates in `crates/`):

- **etherfence-core** — shared vocabulary: `AgentKind`, `McpServer`, `Finding`, `Severity`, `ScanReport`, bounded file readers (`read_bounded_text_file`, `…_no_follow`). Everything depends on this.
- **etherfence-inventory** — discovers agent config files under a scan root (`CANDIDATES` declaration order = output order) and parses them into `InventoryItem`s. `config_path` in all downstream output is a **tilde display path** (`~/.claude.json`), not a filesystem path.
- **etherfence-detectors** — turns inventory into scan `Finding`s (EF-MCP-*, EF-SEC-*, …) with stable fingerprints.
- **etherfence-policy** — scan-only posture policy (`ef-policy/v0.1`), evaluated during `scan --policy`.
- **etherfence-mcp** — the MCP proxy engine: `ef-mcp-policy/v0.1 + v0.2` parsing/validation, the shared decision evaluator used identically by the live proxy and `mcp-policy check` dry runs, Unicode/homograph hardening (`unicode.rs`), redacting audit log.
- **etherfence-setup** — everything under `etherfence setup`: detection (`lib.rs`), capability classification (`classification.rs`), trust/integrity assessment (`trust.rs`), integrity baselines (`baseline.rs`), client catalog (`catalog.rs`), and the wizard plan/apply engine (`wizard.rs` + the apply machinery in `lib.rs`).
- **etherfence-report** — renders `ScanReport` to full human text, Markdown, JSON, SARIF.
- **etherfence-cli** — the `etherfence` binary (`main.rs`), startup splash (`banner.rs`, gated by `command_banner_mode()`), terminal theme (`ui.rs`), the interactive wizard UI, and nearly all integration tests (`crates/etherfence-cli/tests/`).

### The wizard plan/apply engine (the most invariant-dense area)

`etherfence setup` (wizard) flows: `detect()` → user selections → `build_wizard_plan()` → preview → `apply_wizard_plan()` → `apply_selected()` in `etherfence-setup/src/lib.rs`. The governing invariant is **"the confirmed plan is exactly what lands on disk"**, enforced fail-closed:

- Server identity is always the full triple `WizardServerId { agent, config_path, server_name }` — never `agent:server_name` (two configs of one client can define the same server name).
- Only servers in writable `SUPPORTED_CONFIGS` (in `lib.rs`) can be planned; wrapped/remote/advisory-only selections are rejected at plan time, never silently skipped at apply time. Display paths map to configs by suffix matching (`display_path_matches`).
- The plan binds each selected server to its reviewed state: expected command/args/url **plus** a canonical SHA-256 of the complete JSON entry (`SetupServer.raw_entry_sha256`, captured in `detect()`); apply preflight re-reads and aborts on any drift, missing config, root mismatch, or internally inconsistent plan **before writing anything**.
- Apply never adopts pre-existing policy files (even byte-identical ones) — backup manifests, failed-apply cleanup, and rollback delete recorded policy paths unconditionally, so only transaction-created files may be recorded.
- Raw invocation data (`command`/`args`/`url`, entry hashes) lives on structs as `#[serde(skip)]` fields: in memory for the engine, never in JSON output — the `ef-setup-detect` schema and CI baselines must not change when these fields do.
- Version pins are validated per runner (npm via the `semver` crate — full `major.minor.patch` only; uvx/pipx via PEP 440 exact); unknown pre-package `npx` flags fail closed in both the resolver and the pin rewriters.

Integration tests for all of this: `crates/etherfence-setup/tests/wizard_apply.rs` — extend it when touching the engine.

### Human vs machine output

`scan` human output defaults to an executive summary (`render_scan_summary` in `main.rs`, themed via `ui.rs`); full evidence is behind `scan --verbose` (`etherfence_report::to_human`). JSON/Markdown/SARIF and every `ef-*` schema are versioned contracts — changes there require a schema version bump, CHANGELOG entry, and doc updates in the same change. Human output renders enum tokens through `kebab_label()` (serde token) or dedicated human labels — never hand-maintain a second label table.

## Non-negotiable project rules

The constitution (`.specify/memory/constitution.md`, 11 principles) governs all work. The ones that most often shape code review here:

- **Deny-by-default / fail-closed everywhere**: missing/ambiguous/malformed policy or config ⇒ refuse, never allow. The proxy must not start its wrapped server if the policy can't load.
- **Truth in claims**: never describe scan/setup/advisory features with blocking/enforcement language, and never claim support for a client/server category without fixture-backed tests (Principles III, V, XI).
- **Deterministic output**: unstable ordering or wall-clock values in comparable output is a defect.
- **Audit redaction**: logs record decisions and names, never argument values, file contents, paths beyond safe classification, or credentials.

## Gotchas that repeatedly bite

- **Shared fixtures have exact-count assertions.** `tests/fixtures/home`, `windows-home`, `malformed-home` are asserted by count/ID in `cli_scan.rs`, catalog and inventory tests, and the checked-in `docs/examples/ci/baseline.json`. Adding any file there shifts counts and requires regenerating the baseline (`cargo run -- scan --root tests/fixtures/home --write-baseline docs/examples/ci/baseline.json`). New features should create their own isolated fixture dir (precedent: `trust-home/`, `baseline-home/`).
- **Docs-honesty tests** (`setup_catalog_docs.rs` and friends) ban enforcement/safety vocabulary in docs using sentence-scoped, negation-aware checks. Legitimate disclaimers ("does not block…") pass, but only if the negation word and the banned term are on the same source line — mind Markdown line wrapping.
- **Windows is CI-only.** `cfg(windows)` code cannot be compile-checked in a Linux sandbox; prefer established cross-platform crates (e.g. `same-file`) over hand-rolled `std::os::windows` calls, avoid hardcoded `/tmp`, and watch CRLF on checked-in fixtures (`.gitattributes`).
- **GitHub Actions inputs**: never interpolate `${{ github.event.inputs.* }}` (or any user-influenced expression) directly into a `run:` block — pass it through `env:` first (established after a script-injection finding in `release.yml`).
- **PTY/banner tests** (`cli_banner.rs`) are unix-only (`portable-pty` dev-dep) and must `env_remove("CI")`/`NO_COLOR` because GitHub Actions sets `CI=1`, which suppresses the splash.
- **CLI paths are trusted-operator inputs** (documented in `docs/threat-model.md`): path-traversal containment is not the fix for `--flag`-provided paths, but reads must stay bounded (`read_bounded_text_file`) and symlink-sensitive reads fail closed (`…_no_follow`).

## Feature workflow

Features are developed spec-first under `specs/NNN-name/` (spec.md → plan.md → tasks.md, via the spec-kit skills) on a branch, with the version bump, CHANGELOG section, doc updates, and fixtures landing in the same PR. `CHANGELOG.md` keeps one distinct section per version — never rename an existing version heading. PR bodies do not carry a "Generated with Claude Code" footer; commit messages keep the `Co-Authored-By` trailer.
