# Tasks: Argument-Aware MCP Runtime Policy

**Input**: Design documents from `/specs/004-argument-aware-mcp-policy/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/ef-mcp-policy-v0.2.md, quickstart.md

**Tests**: Included — the constitution (Principle V, Fixture-Backed Findings) requires every guard
primitive to ship with an automated allow-case and fail-closed-deny-case test; spec SC-002 and
SC-004 make this mandatory, not optional, for this feature.

**Organization**: Phase 2 (Foundational) contains the schema/evaluator/audit/CLI-plumbing work all
four user stories depend on, because every story exercises the same shared evaluator (FR-020) and
the same CLI commands (FR-023–FR-026) — there is no way to make the evaluator itself "belong" to
one story. Phases 3–6 then add one example policy + its story-specific tests per user story, which
*are* independently completable/testable once Phase 2 lands.

## Phase 1: Setup

- [x] T001 Create feature branch `spec/v1.5.0-argument-aware-mcp-policy` from `origin/main` (done at session start)
- [x] T002 Confirm workspace builds clean on `origin/main` baseline: `cargo build && cargo test --workspace` before making changes

## Phase 2: Foundational (schema, evaluator, audit, CLI plumbing — blocks all user stories)

### Schema types and validation

- [x] T003 Add `SUPPORTED_MCP_POLICY_SCHEMA_VERSIONS: &[&str]` (`["ef-mcp-policy/v0.1", "ef-mcp-policy/v0.2"]`) alongside the existing `SUPPORTED_MCP_POLICY_SCHEMA_VERSION` in `crates/etherfence-mcp/src/policy.rs`, and update `parse_mcp_policy`'s version check to accept either, denying anything else (fail closed) exactly as today
- [x] T004 [P] Add `ScalarValue` enum (`Bool`/`Int`/`Float`/`Str`, `#[serde(untagged)]`) and a `scalar_eq(&ScalarValue, &serde_json::Value) -> bool` helper in `crates/etherfence-mcp/src/policy.rs`
- [x] T005 [P] Add `FieldGuard` tagged enum (`#[serde(tag = "type", rename_all = "snake_case")]`, variants `Exact`, `Enum`, `String`, `Number`, `Array`, `Url` per data-model.md) in `crates/etherfence-mcp/src/policy.rs`
- [x] T006 Extend the existing `PathKeyGuard` struct in `crates/etherfence-mcp/src/policy.rs`: make `path_rule` `Option<String>`, add `require_keys: Vec<String>` (default empty), `forbid_keys: Vec<String>` (default empty), `fields: BTreeMap<String, FieldGuard>` (default empty)
- [x] T007 Add selector syntax validation function (`.`-separated segments, `[A-Za-z0-9_-]+`, max 8 segments, each segment run through the existing `inspect_policy_identifier` Unicode-hygiene check) in `crates/etherfence-mcp/src/policy.rs`
- [x] T008 Add selector resolution function (walk a `&serde_json::Value` by segment: object key or all-digits array index; return `None` on any mismatch/missing/out-of-range) in `crates/etherfence-mcp/src/policy.rs`
- [x] T009 Add hand-rolled URL guard parser/normalizer in `crates/etherfence-mcp/src/policy.rs`: scheme extraction, authority parsing that fail-closed-rejects `@`-bearing (userinfo) authorities and any `%` anywhere in the value, host lowercase-normalization (ASCII-only, reject non-ASCII), effective-port derivation (explicit port, else `http`→80/`https`→443), and path extraction, per research.md Decisions 1–4
- [x] T010 Extend `validate_policy_unicode_hygiene`/`validate_tool_rules`/`validate_method_rules`/`validate_path_key_guard` in `crates/etherfence-mcp/src/policy.rs` to: validate every `fields` selector (T007), validate `require_keys`/`forbid_keys` don't overlap, validate each `FieldGuard`'s internal bounds (`min <= max`, non-empty enum/allowed-elements, valid URL guard scheme/host/port lists per data-model.md), and reject any v0.2-only construct (`require_keys`/`forbid_keys`/non-empty `fields`) when `schema_version` is `ef-mcp-policy/v0.1`
- [x] T011 [P] Add unit tests in `crates/etherfence-mcp/src/policy.rs` `mod tests` for T003/T010 validation: v0.2 construct rejected under v0.1 schema, duplicate/overlapping require+forbid key rejected, empty enum/allowed-elements rejected, `min > max` rejected, invalid selector (empty segment, >8 segments, bad character, bidi/zero-width) rejected, invalid URL guard scheme/host/port rejected, unknown `type` rejected

### Decision evaluator

- [x] T012 Add `GuardPolicyDecision` struct (`decision`, `reason`, `guard_key`, `selector`, `reason_category`) in `crates/etherfence-mcp/src/policy.rs`, mirroring `PathPolicyDecision`
- [x] T013 Implement field-guard evaluation (`evaluate_field_guard(&FieldGuard, Option<&serde_json::Value>) -> (bool, &'static str)` reason-category) covering all six variants per data-model.md's reason-category table, fail-closed on missing/wrong-type/malformed in `crates/etherfence-mcp/src/policy.rs`
- [x] T014 Implement `decide_tool_argument_guards(policy, tool_name, arguments) -> Option<GuardPolicyDecision>` (checks `require_keys`, then `forbid_keys`, then `fields` in `BTreeMap` iteration order, first failure wins) in `crates/etherfence-mcp/src/policy.rs`
- [x] T015 Implement `decide_method_param_guards(policy, method, params) -> Option<GuardPolicyDecision>` with the same logic as T014 but reading `MethodPathGuard`/method-scoped guard tables, applying to **any** method with a configured guard (not restricted to `resources/read`) in `crates/etherfence-mcp/src/policy.rs`
- [x] T016 [P] Add unit tests in `crates/etherfence-mcp/src/policy.rs` `mod tests` for T013–T015: one allow + one fail-closed-deny test per `FieldGuard` variant (exact, enum, string length, string prefix, number bounds, array length, array allowed-elements, url scheme, url host, url port, url path-prefix, url userinfo-rejected, url percent-encoding-rejected), plus `require_keys`/`forbid_keys` allow+deny, plus nested-selector resolution allow+deny (missing segment, wrong container type, out-of-range index)

### Proxy wiring (shared evaluator call sites)

- [x] T017 In `crates/etherfence-mcp/src/proxy.rs` `inspect_client_line`'s `tools/call` branch, call `decide_tool_argument_guards` after the existing path decision (T014), combining via the same `apply_path_decision`-style "only overrides when still Allow" pattern, and attach guard metadata to the `AuditRecord` (depends on T021)
- [x] T018 In `crates/etherfence-mcp/src/proxy.rs` `inspect_client_line`'s "any other allowed method" branch, replace the hardcoded `if method == "resources/read"` path-guard-only check with: keep the existing v0.1 `resources/read`-only path-guard call unchanged, and additionally call `decide_method_param_guards` (T015) for **every** method, attaching guard metadata to the audit record when it fires
- [x] T019 In `crates/etherfence-mcp/src/proxy.rs` `inspect_server_line`'s server→client method-request branch, call `decide_method_param_guards` (T015) after the existing method-allow decision, denying server→client when a guard fires (new capability, purely additive per research.md Decision 7)
- [x] T020 [P] Add integration-style tests in `crates/etherfence-mcp/src/proxy.rs` `mod tests` (reusing the existing test-policy/test-request fixture pattern) proving: a `tools/call` request is denied by a v0.2 field guard while an otherwise-identical allowed request passes; a v0.1-only policy's `resources/read` path-guard behavior is byte-identical to before T018; a non-`resources/read` method with a configured v0.2 params guard is now enforced; a server→client method with a configured v0.2 params guard is denied

### Audit redaction

- [x] T021 Add `guard_key: Option<String>`, `guard_selector: Option<String>`, `guard_reason_category: Option<String>` fields to `AuditRecord` and a `with_guard_metadata(&self, guard_key, selector, reason_category)` builder (mirroring `with_path_metadata`) in `crates/etherfence-mcp/src/audit.rs`
- [x] T022 [P] Add redaction tests in `crates/etherfence-mcp/src/audit.rs` `mod tests` proving a denied field-guard value never appears in the serialized `AuditRecord` JSON line, only `guard_key`/`guard_selector`/`guard_reason_category`

### Serverless CLI-summary wiring (`explain`/`check` shared logic)

- [x] T023 Extend `GuardSummary`/`PolicyExplanation`-family types and `explain_policy` in `crates/etherfence-mcp/src/policy_ux.rs` to also collect v0.2 guards (`require_keys`, `forbid_keys`, each `fields` selector with its `FieldGuard` kind) alongside the existing v0.1 path-guard collection, plus a warning for a `fields` selector with no path-rule/guard actually reachable (parity with existing unused-path-rule warnings) if applicable
- [x] T024 Extend `CheckOutcome` in `crates/etherfence-mcp/src/policy_ux.rs` with `guard_key: Option<String>`, `guard_selector: Option<String>`, `guard_reason_category: Option<String>`, populated from `AuditRecord`'s new fields (T021) in `outcome_from_audit`
- [x] T025 [P] Add tests in `crates/etherfence-mcp/src/policy_ux.rs` `mod tests`: `explain_policy` lists a v0.2 field guard; `dry_run_check` surfaces `guard_reason_category` for a v0.2-denied request; and an explicit proxy/check-equivalence test that runs the same v0.2-guard-triggering request through both `inspect_client_line` directly and `dry_run_check` and asserts identical `decision`/`reason_category` (SC-004)
- [x] T026 Update crate-root re-exports in `crates/etherfence-mcp/src/lib.rs` for any newly-public types needed by `crates/etherfence-cli` (e.g. `GuardPolicyDecision` if the CLI needs the type name, `FieldGuard` if `explain` rendering needs to match on it)

### CLI surface

- [x] T027 Update `render_mcp_policy_explanation` in `crates/etherfence-cli/src/main.rs` to print the v0.2 guard summaries from T023 (require/forbid keys, field guards with kind and bounds) in a new `Argument/param field guards:` section, deterministically ordered
- [x] T028 Update `render_mcp_check_outcome` (or equivalent) in `crates/etherfence-cli/src/main.rs` to print `guard_key`/`guard_selector`/`guard_reason_category` from T024 when present
- [x] T029 Update the `McpPolicyCommand::Validate`/`run_mcp_policy_validate` error surfacing in `crates/etherfence-cli/src/main.rs` if needed so T010's validation error messages reach the operator unchanged (likely no code change — `anyhow` error propagation already covers this; confirm with a test in T034)

## Phase 3: User Story 1 - GitHub org/repo enum guard (P1) 🎯 MVP

**Goal**: `github.create_issue`-style tool restricted to a named enum of organizations via a v0.2
field guard, with `require_keys` proving the object-level primitive too.

**Independent Test**: `mcp-policy check` against the new example policy allows an in-allowlist org
and denies an out-of-allowlist org and a request missing `org` entirely, with identical live-proxy
behavior.

- [x] T030 [P] [US1] Create `examples/policies/mcp-github-scoped-orgs.toml` (`schema_version = "ef-mcp-policy/v0.2"`, allows `github.create_issue`, `require_keys = ["org", "repo"]`, `fields."org"` enum of one org name, `fields."repo"` string-prefix guard on `"<org>/"`)
- [x] T031 [US1] Register the new profile in `MCP_POLICY_PROFILES` in `crates/etherfence-cli/src/main.rs`
- [x] T032 [US1] Add CLI integration tests in `crates/etherfence-cli/tests/cli_mcp_policy.rs`: `mcp-policy init --profile github-scoped-orgs` prints/writes valid TOML; `validate` passes; `explain` lists the `org`/`repo` guards; `check` allows an in-allowlist request and denies an out-of-allowlist one and a missing-`org` one with the expected reason categories

## Phase 4: User Story 2 - Messaging destination enum + forbidden key (P1)

**Goal**: `messaging.send`-style tool restricted to a named destination enum, with a `forbid_keys`
escape-hatch key denied outright.

**Independent Test**: `mcp-policy check` allows a request to an allowlisted destination without the
forbidden key, and denies both an out-of-allowlist destination and any request carrying the
forbidden key regardless of its value.

- [x] T033 [P] [US2] Create `examples/policies/mcp-messaging-named-destinations.toml` (allows `messaging.send`, `fields."destination"` enum of named destinations, `forbid_keys = ["bypass"]`)
- [x] T034 [US2] Register the new profile in `MCP_POLICY_PROFILES` in `crates/etherfence-cli/src/main.rs`
- [x] T035 [US2] Add CLI integration tests in `crates/etherfence-cli/tests/cli_mcp_policy.rs` for allow/deny/forbidden-key-present cases against the new profile, mirroring T032's structure

## Phase 5: User Story 3 - Browser/API approved-HTTPS-hosts URL guard (P2)

**Goal**: A `browser.fetch`-style tool restricted via the URL guard: `https`-only, a host
allowlist, and a path-prefix allowlist.

**Independent Test**: `mcp-policy check` allows an in-allowlist HTTPS URL under the allowed path
prefix, and denies (each with the correct reason category, never echoing the URL) a wrong-scheme
URL, an unlisted-host URL, a userinfo-bearing URL, and an out-of-prefix path.

- [x] T036 [P] [US3] Create `examples/policies/mcp-browser-approved-hosts.toml` (allows a `browser.fetch` tool, `fields."url"` URL guard with `schemes = ["https"]`, one allowed host, `path_prefixes = ["/v1/"]`)
- [x] T037 [US3] Register the new profile in `MCP_POLICY_PROFILES` in `crates/etherfence-cli/src/main.rs`
- [x] T038 [US3] Add CLI integration tests in `crates/etherfence-cli/tests/cli_mcp_policy.rs` covering scheme/host/path-prefix denial and confirming the raw denied URL string never appears in `check` output for any denied case

## Phase 6: User Story 4 - Read-only operation enum + numeric/array bounds + nested selector (P2)

**Goal**: A general-purpose tool with `operation` locked to a read-only enum, `limit` numerically
bounded, and a nested `filter.status` selector guard, demonstrating the selector primitive and
multi-guard composition on one tool.

**Independent Test**: `mcp-policy check` allows a fully-compliant request and denies, with distinct
reason categories, an out-of-enum `operation`, an out-of-range `limit`, a wrong-type `limit`, and a
missing/malformed nested `filter.status`.

- [x] T039 [P] [US4] Create `examples/policies/mcp-readonly-operation-guard.toml` (allows a general-purpose tool, `fields."operation"` enum `["read","list","get"]`, `fields."limit"` number guard 1–100, `fields."filter.status"` enum guard)
- [x] T040 [US4] Register the new profile in `MCP_POLICY_PROFILES` in `crates/etherfence-cli/src/main.rs`
- [x] T041 [US4] Add CLI integration tests in `crates/etherfence-cli/tests/cli_mcp_policy.rs` covering the allow case and each distinct deny case (enum, numeric bound, wrong type, nested-selector missing/malformed)

## Phase 7: Polish & Cross-Cutting

- [x] T042 [P] Update `docs/mcp-policy-ux.md` with the v0.2 guard syntax (mirroring contracts/ef-mcp-policy-v0.2.md), `explain`/`check` output changes, and the four new example profiles
- [x] T043 [P] Update `docs/mcp-proxy.md` and `docs/mcp-proxy-operator-guide.md` describing argument/param guards as a defense-in-depth narrowing layer (explicitly not a prompt-injection detector — Truth in Claims)
- [x] T044 [P] Update `docs/architecture.md` to describe the shared-evaluator data flow for v0.2 guards (one evaluator, two call sites: proxy and `mcp-policy check`)
- [x] T045 [P] Update `docs/threat-model.md` with the new guard primitives' coverage and explicit non-goals (FR-028–FR-030)
- [x] T046 [P] Update `docs/roadmap.md` to move argument-aware policy from planned to shipped, scoped exactly to what's implemented
- [x] T047 [P] Update `docs/mcp-compatibility-matrix.md` if it enumerates policy schema capabilities
- [x] T048 [P] Add/extend a v0.2 fixture in `docs/examples/ci/mcp-policy.toml` and confirm `docs/ci.md`'s CI recipe still matches (add a v0.2 example if the recipe demonstrates policy authoring)
- [x] T049 Update `CHANGELOG.md` with a `1.5.0` entry describing the v0.2 schema, guard primitives, compatibility guarantee, and non-goals
- [x] T050 Add a schema/migration note (new doc section or extend `docs/mcp-policy-ux.md`) explaining v0.1→v0.2 migration is purely additive (bump `schema_version`, existing tables unchanged) and how to detect if a policy needs it
- [x] T051 Bump `workspace.package.version` in `Cargo.toml` to `1.5.0` and update any hardcoded version assertions in docs/tests that pin the previous version number
- [x] T052 Run `cargo fmt`, then `cargo fmt --check`
- [x] T053 Run `cargo clippy --all-targets --all-features -- -D warnings` and fix all findings without weakening tests
- [x] T054 Run `cargo test --workspace` and confirm 100% pass, including every pre-existing v0.1 test unchanged (SC-003)
- [x] T055 Run `cargo build` (release-shape sanity) and `git diff --check` (no whitespace errors)
- [x] T056 Re-run the Constitution Check table in `plan.md` against the final diff and update any `PASS (tracked in tasks)` rows to `PASS`

## Dependencies

- Phase 2 (Foundational) blocks Phases 3–6 entirely — no user story can be tested until the schema,
  evaluator, audit fields, and CLI plumbing exist.
- Phases 3, 4, 5, 6 are independent of each other once Phase 2 lands (each adds one example policy
  + its own tests, touching no shared file except the additive `MCP_POLICY_PROFILES` array in
  `main.rs`, where each story's registration task is a small independent insertion).
- Phase 7 depends on Phases 2–6 being functionally complete (docs describe shipped behavior; the
  verification gate runs against the full diff).

## Parallel Execution Examples

- Within Phase 2: T004, T005 can run in parallel (independent new types); T011 and T016 and T022
  and T025 (all `[P]` test-writing tasks) can run in parallel once their respective implementation
  tasks land.
- Once Phase 2 is merged/complete: T030, T033, T036, T039 (the four example-policy files) can all
  be authored in parallel — they touch four different new files and four independent doc sections
  of `MCP_POLICY_PROFILES`.
- Phase 7 doc tasks T042–T048 can all run in parallel (independent files); T051–T056 are sequential
  (version bump before the verification gate; each gate command depends on the previous succeeding).

## Implementation Strategy

**MVP = Phase 2 + Phase 3 (User Story 1)**: this alone proves the schema, the shared evaluator, the
fail-closed semantics, and the CLI surface end-to-end with one real-world-shaped example (GitHub
org/repo restriction). Phases 4–6 then each add one more primitive-combination and one more
documented example without touching Phase 2/3 code, so they can land as independent follow-up
commits within the same branch/PR if useful for review, or all together — this feature ships as one
release (v1.5.0) regardless, per the `/goal` directive's single-PR instruction.
