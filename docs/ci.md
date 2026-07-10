# CI and team workflow integration

Status: **v1.0.0, local-first**, same as the rest of EtherFence. Everything
in this document runs `etherfence scan` or `etherfence mcp-policy
validate/explain/check` — local, read-only, scan-only or serverless-dry-run
commands. Nothing here starts `etherfence mcp-proxy`, spawns or contacts an
MCP server, executes a tool, installs a daemon, or intercepts network or
terminal activity. EtherFence v1.0.0 is production-ready for controlled
local-first deployments of its defined scope, but these examples are not a
universal certification that a policy or scan result is safe; they are
checks worth running before merging.

This page documents how to wire EtherFence into a CI pipeline or a team
workflow: failing a PR on posture findings, failing only on *new* findings,
generating and uploading a SARIF report, and validating/dry-run-checking MCP
proxy policies without starting a server. Checked example files live under
[`docs/examples/ci/`](examples/ci) and checked example workflows live under
[`docs/examples/workflows/`](examples/workflows); both are covered by tests
(`crates/etherfence-cli/tests/ci_examples.rs`) so they cannot silently drift
out of sync with the CLI.

## Failing a PR on findings: `--fail-on`

`etherfence scan --fail-on <severity>` exits non-zero when any finding at or
above the given severity (`info`, `low`, `medium`, `high`) exists. Combine it
with `--policy`/`--policy-profile` to also fail on posture-policy violations
(`EF-POL-*`), not only the built-in scan-only findings:

```sh
etherfence scan --root . --policy docs/examples/ci/scan-policy.toml --fail-on high
```

See [`docs/examples/workflows/scan-gate.yml`](examples/workflows/scan-gate.yml)
for a full GitHub Actions example.

## Failing only on new findings: `--baseline` and `--fail-on-new`

A raw `--fail-on` gate re-fails on every already-known/accepted finding on
every PR. To gate only on *new* findings:

1. Generate a baseline once, and commit it:

   ```sh
   etherfence scan --root . --write-baseline docs/examples/ci/baseline.json
   ```

2. In CI, compare against that baseline and fail only when a *new* finding at
   or above a chosen severity appears:

   ```sh
   etherfence scan --root . --baseline docs/examples/ci/baseline.json --fail-on-new high
   ```

`--fail-on-new` requires `--baseline`. Findings already present in the
baseline are marked `existing` and do not fail the job; findings absent from
the current scan are marked `resolved`; only findings not present in the
baseline are marked `new` and count toward `--fail-on-new`.

When a team intentionally accepts new findings (for example, a newly added
MCP server that has been reviewed), regenerate and commit an updated
baseline, and review the diff before committing it — see
[Avoiding secrets in baselines and policies](#avoiding-secrets-in-baselines-and-policies)
below.

See
[`docs/examples/workflows/scan-baseline.yml`](examples/workflows/scan-baseline.yml)
for a full example. [`docs/examples/ci/baseline.json`](examples/ci/baseline.json)
is a real baseline generated from `tests/fixtures/home`, checked in so the
example workflow has a concrete file to reference; regenerate your own from
your own repository rather than reusing this one.

## Generating and uploading SARIF

`etherfence scan --format sarif` renders the same scan results as a SARIF
2.1.0 log, so they can be uploaded to GitHub code scanning (or any other
SARIF-aware tool). SARIF rendering does not change scan behavior and does not
imply runtime enforcement; see [`docs/sarif.md`](sarif.md) for the full
document shape and severity mapping.

```sh
etherfence scan --root . --policy docs/examples/ci/scan-policy.toml --format sarif > etherfence.sarif
```

Upload it with the standard `github/codeql-action/upload-sarif` action (see
[`docs/examples/workflows/scan-sarif-upload.yml`](examples/workflows/scan-sarif-upload.yml)
for the full workflow). `--format sarif` does not itself fail the job; add
`--fail-on`/`--fail-on-new` in the same or a separate step if you also want
the job to fail on findings.

## Validating MCP policies in CI

`etherfence mcp-policy validate <policy.toml>` parses and validates an
`ef-mcp-policy/v0.1` file using the exact same loader `etherfence mcp-proxy
--policy` uses, and exits non-zero with a clear, actionable error on failure
(unsupported schema version, empty `name`, a `path_rules` entry with no
`allow_roots`, malformed TOML, or suspicious Unicode):

```sh
etherfence mcp-policy validate docs/examples/ci/mcp-policy.toml
```

`etherfence mcp-policy explain <policy.toml>` prints a deterministic summary
of what the policy actually allows and a warnings section for risky or
confusing shapes (wildcard method allow, no `[methods]` section, no tool
allowed anywhere, unused path rules, broad `allow_roots`, empty
`deny_roots`, and more). It always exits `0`; it is meant for a human
reviewer or as informational CI log output, not a pass/fail gate by itself.

See [`docs/mcp-policy-ux.md`](mcp-policy-ux.md) for the full command
reference and [`docs/examples/workflows/mcp-policy-gate.yml`](examples/workflows/mcp-policy-gate.yml)
for a full example.

## Dry-running MCP policy decisions in CI without starting an MCP server

`etherfence mcp-policy check --policy <policy.toml> --request <json>` dry-runs
exactly one JSON-RPC request/notification against a policy, using the same
decision functions the live proxy uses, and prints the method/tool/path
decision, the reason, and whether the live proxy would forward the request.
It never starts or contacts an MCP server, never executes a tool, and never
writes an audit log:

```sh
etherfence mcp-policy check \
  --policy docs/examples/ci/mcp-policy.toml \
  --request docs/examples/ci/requests/allowed-tool-call.json
# Decision: ALLOW

etherfence mcp-policy check \
  --policy docs/examples/ci/mcp-policy.toml \
  --request docs/examples/ci/requests/denied-tool-call.json
# Decision: DENY
```

**`mcp-policy check` exits `0` for both an `ALLOW` and a `DENY` decision** —
it is a dry-run/inspection command, not a pass/fail gate by itself. Checking
its exit code alone in CI proves nothing about which decision was made; a
policy edit that accidentally turns an expected `DENY` into an `ALLOW` would
still exit `0` and pass a CI step that only checks the exit code.

To use `check` as an actual CI gate, capture its stdout and assert the
printed `Decision:` line matches what you expect, for example with `tee` and
`grep`:

```sh
./target/release/etherfence mcp-policy check \
  --policy docs/examples/ci/mcp-policy.toml \
  --request docs/examples/ci/requests/denied-tool-call.json \
  | tee /tmp/etherfence-mcp-check-denied.txt
grep -q '^Decision: DENY$' /tmp/etherfence-mcp-check-denied.txt
```

`tee` keeps the full dry-run output visible in CI logs for a human reviewer,
while `grep -q` (as the last command in the step) is what actually fails the
job when the decision does not match — not the `mcp-policy check` invocation
itself. This is useful as a regression check: commit one or more JSON-RPC
request fixtures that represent requests you expect to be allowed or denied,
and assert the `Decision:` line in CI, with `grep` or equivalent, so a policy
edit that accidentally widens or narrows access is caught before it reaches
`etherfence mcp-proxy`. See
[`docs/examples/workflows/mcp-policy-gate.yml`](examples/workflows/mcp-policy-gate.yml)
and
[`docs/examples/workflows/pr-security-gate.yml`](examples/workflows/pr-security-gate.yml)
for full examples using this pattern. The example requests under
[`docs/examples/ci/requests/`](examples/ci/requests) are covered by an
automated test asserting their expected decision
(`crates/etherfence-cli/tests/ci_examples.rs`); mirror that pattern for your
own request fixtures and CI assertions.

## Avoiding secrets in baselines and policies

- Baseline files (`ef-baseline/v0.1.3`) and scan JSON/Markdown/SARIF output
  record finding metadata (IDs, severities, config paths, evidence
  fingerprints, agent/target names) — never raw environment variable
  *values*, tokens, or secrets. Scan-only findings only ever report that an
  environment variable name *looks* secret-like; they do not read or record
  values.
- `etherfence mcp-proxy --audit-log` and `etherfence mcp-policy check` follow
  the same redaction posture: only decisions, reasons, method/tool names,
  safe path classifications, and argument/param *key* names are ever
  recorded — never argument/param values, full paths, or URIs.
- Even so, review any baseline or policy file before committing it, the same
  way you would review any other checked-in config: confirm `config_path`
  values and MCP server names in a baseline do not reveal anything sensitive
  about your environment, and confirm `allow_roots`/`deny_roots` in an MCP
  policy point at generic project paths, not private absolute paths specific
  to one machine or user.
- Never hard-code a token, password, or API key into a scan policy,
  MCP policy, or JSON-RPC request fixture used in CI. These files are meant
  to describe *posture and policy shape*, not to carry secrets.

## EtherFence is still local-first and pre-v1

Every command referenced in this document — `etherfence scan`, `etherfence
mcp-policy validate/explain/check` — runs entirely locally against files on
disk. None of them call out to a remote service, and none of them require
credentials beyond whatever your CI runner already has. `etherfence
mcp-proxy` is a separate, opt-in, experimental stdio-only component; nothing
in this document changes its enforcement behavior. EtherFence remains
pre-alpha/pre-v1: treat every gate documented here as a useful check to catch
regressions and risky changes early, not as a production-readiness or
security certification.

## Non-goals

Consistent with the rest of EtherFence, none of the CI integration patterns
in this document add or require:

- a daemon, API service, control plane, or endpoint agent
- a marketplace GitHub Action, central dashboard, or remote policy service
- an automatic PR-commenting bot
- shell hooks, terminal-command scanning, or network/TLS interception
- DLP or content inspection
- arbitrary MCP tool execution
- any change to `ef-mcp-policy/v0.1` or to `mcp-proxy` runtime enforcement
