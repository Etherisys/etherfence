# Quickstart: MCP Server Trust and Integrity Assessment (v1.3.0)

Manual end-to-end validation against the local debug build (`cargo build`). All
v1.3.0-specific fixtures live under `tests/fixtures/trust-home/` — a new,
isolated fixture root (not `tests/fixtures/home/`), added deliberately to avoid
regressing the many exact-count/exact-list assertions `cli_scan.rs` and other
existing tests already make against `home/`, `windows-home/`, and
`malformed-home/`. Run every command below from the repository root.

## 1. Baseline: v1.2.0 fields still present

```sh
cargo run -q -p etherfence-cli --bin etherfence -- setup detect --format json --root tests/fixtures/trust-home | jq '.etherfenceSchemaVersion'
# expect: "ef-setup-detect/v0.2"

cargo run -q -p etherfence-cli --bin etherfence -- setup detect --format json --root tests/fixtures/trust-home \
  | jq '.detections[].servers[] | {capabilities, recommendation}' | head -20
# expect: capabilities/recommendation objects in the same v0.1 shape, unchanged
```

## 2. Package-runner pinning

```sh
cargo run -q -p etherfence-cli --bin etherfence -- setup detect --format json --root tests/fixtures/trust-home \
  | jq '.detections[] | select(.agent == "Claude Code") | .servers[] | {name, invocation: .trustAssessment.invocation}'
# expect: npx-pinned -> versionExpression "exactly-pinned", no package-pinning indicator
#         npx-omitted -> versionExpression "omitted", indicator EF-TRUST-PIN-001
#         npx-mutable-tag -> versionExpression "mutable-tag", indicator EF-TRUST-PIN-002
#         npx-version-range -> versionExpression "version-range", indicator EF-TRUST-PIN-003
#         npx-malformed -> malformedRunnerInvocation: true, indicator EF-TRUST-PIN-005
```

## 3. Shell wrapper and obscured launch

```sh
cargo run -q -p etherfence-cli --bin etherfence -- setup detect --format json --root tests/fixtures/trust-home \
  | jq '.detections[] | select(.agent == "Windsurf") | .servers[] | {name, shellWrapper: .trustAssessment.invocation.shellWrapper}'
# expect: one row per wrapper fixture (wrap-sh-c -> "sh-c", wrap-bash-c -> "bash-c", ...),
#         direct-negative-control -> null (field omitted)

cargo run -q -p etherfence-cli --bin etherfence -- setup detect --format json --root tests/fixtures/trust-home \
  | jq '.detections[] | select(.agent == "Gemini CLI") | .servers[] | {name, patterns: .trustAssessment.invocation.obscuredLaunchPatterns}'
# expect: obs-pipe-to-shell-downloader -> ["pipe-to-shell-downloader"], etc.; no shell command is
#         ever executed (no std::process::Command exists in this code path — verified by inspection)
```

## 4. Aggregate precedence (configuration-risk-first)

```sh
cargo run -q -p etherfence-cli --bin etherfence -- setup detect --format json --root tests/fixtures/trust-home \
  | jq '.detections[] | select(.agent == "Gemini CLI") | .servers[] | select(.name == "obs-pipe-to-shell-downloader") | .trustAssessment | {configurationRisk, aggregate, needsReview}'
# expect: configurationRisk "high-risk", aggregate "high-risk", needsReview true (FR-061)
```

## 5. Local artifact hashing and degradation

```sh
cargo run -q -p etherfence-cli --bin etherfence -- setup detect --format json --root tests/fixtures/trust-home \
  | jq '.detections[] | select(.agent == "Claude Code") | .servers[] | select(.name == "npx-pinned") | .trustAssessment | .artifactIdentity, has("sha256")'
# expect: "known-source" (curated identity match), then `false` — sha256 is genuinely omitted
#         (not present-as-null; `has()` proves the key itself is absent), since npx-pinned's
#         command is "npx", a PATH-resolved command, never hashed. NOTE: jq's `{sha256}` object-
#         construction syntax shows `null` for a MISSING key too, which reads misleadingly as if
#         the field were present-but-null — use `has()` to check omission, not object reconstruction.
```

Symlink/relative-path/PATH-resolved-command/missing-path/non-regular-file
classification is exercised by `crates/etherfence-setup/src/trust.rs`'s
`user_story_3_tests` module directly (dynamic paths computed at test time
against `tests/fixtures/trust-home/bin/sample-tool` and its symlink — a
static checked-in fixture can't portably encode an absolute path).

## 6. Environment-variable and Unicode indicators without leaking values

```sh
cargo run -q -p etherfence-cli --bin etherfence -- setup detect --format json --root tests/fixtures/trust-home > /tmp/trust-detect.json
jq '[.. | strings] | any(test("fixture-secret-value"))' /tmp/trust-detect.json
# expect: false — no configured environment value ever appears in output

jq '.detections[] | select(.agent == "VS Code") | .servers[] | select(.name == "env-dual-match") | .trustAssessment.indicators' /tmp/trust-detect.json
# expect: EF-TRUST-ENV-003 (registry-override) and EF-TRUST-ENV-005/006 (secret-like) both present

jq '.detections[] | select(.agent == "Cursor") | .servers[] | select(.name == "confusable-alias-server") | .trustAssessment.indicators' /tmp/trust-detect.json
# expect: EF-TRUST-UNI-004 (curated confusable alias)
```

## 7. Remote server partial assessment

```sh
jq '.detections[] | select(.agent == "VS Code") | .servers[] | select(.name == "remote-hosted-docs") | .trustAssessment' /tmp/trust-detect.json
# expect: invocation.applicable == false, executablePath == "not-applicable", sha256 absent,
#         but indicators still include EF-TRUST-ENV-001 (env checks still run per FR-057a)
```

## 8. Determinism

```sh
diff <(cargo run -q -p etherfence-cli --bin etherfence -- setup detect --format json --root tests/fixtures/trust-home) \
     <(cargo run -q -p etherfence-cli --bin etherfence -- setup detect --format json --root tests/fixtures/trust-home)
# expect: no diff (byte-identical, FR-079)
```

## 9. Compatibility

```sh
cargo test --workspace
# expect: all pre-existing scan/setup catalog/setup plan/setup apply/setup rollback/setup doctor/
#         mcp-policy/mcp-proxy tests still pass unmodified (FR-089)

cargo run -q -p etherfence-cli --bin etherfence -- setup plan --root tests/fixtures/home | grep -c "trust:"
cargo run -q -p etherfence-cli --bin etherfence -- setup doctor --root tests/fixtures/home | grep -c "trust:"
# expect: 0 for both — human output for setup plan/doctor is unchanged (FR-004)
```

## 10. Deny-by-default invariant

```sh
cargo run -q -p etherfence-cli --bin etherfence -- setup detect --format json --root tests/fixtures/trust-home \
  | jq '[.detections[].servers[].recommendation.tier] | unique'
# expect: ["deny"] — no server, regardless of trust-assessment outcome, ever shows "allow" (FR-069/SC-006)
```
