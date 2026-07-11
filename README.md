# EtherFence

**Local-first AI agent security posture and MCP runtime control.**

One-line idea: **Tirith protects terminal commands; EtherFence governs agent
access.**

> **Status: v1.0.0 — production-ready for controlled local-first
> deployments of its defined scope: `scan`, `mcp-policy`, and the stdio
> `mcp-proxy` boundary.** This is not a security certification for every MCP
> server, MCP client, or deployment environment; operators must still
> review policies, test their chosen servers, and monitor audit logs.
> `etherfence scan` is conservative, read-only posture discovery.
> `etherfence mcp-proxy` is an opt-in local MCP stdio boundary proxy built
> on the stable `ef-mcp-policy/v0.1` schema. `etherfence mcp-policy` is a
> local, serverless policy-authoring/dry-run tool. See
> [Security model / non-goals](#security-model--non-goals) below for what is
> explicitly out of scope.

## Who this is for

Developers and teams running AI coding agents (Claude Code, Cursor, VS Code,
Windsurf, Gemini CLI, Codex CLI) or MCP servers locally, who want visibility
into what those agents/configs expose, and an optional local boundary around
one MCP server's traffic — without adopting a daemon, a cloud service, or a
new terminal workflow.

## What EtherFence does

Three local commands, each with a distinct job:

- **`etherfence scan`** — posture discovery and a CI gate. Conservatively
  discovers local AI-agent/MCP configuration files and reports risk hints
  (broad filesystem access, shell-capable MCP servers, network-capable MCP
  servers, secret-looking environment variables, and more) with rationale,
  impact, and remediation guidance. Supports baselines, TOML policy
  profiles, `--fail-on`/`--fail-on-new` CI gates, and JSON/Markdown/SARIF
  output.
- **`etherfence mcp-proxy`** — a local MCP runtime boundary. A stdio proxy
  that sits between an MCP client and one MCP server, enforces
  method-level, tool-level, and path-aware allow/deny policy, and audits
  decisions. Fails closed on any policy problem. See the
  [operator guide](docs/mcp-proxy-operator-guide.md) for how to wrap a real
  server with it.
- **`etherfence mcp-policy`** — policy authoring, validation, explanation,
  and dry-run. `validate`/`explain`/`init`/`check` read and reason about an
  `mcp-proxy` policy file without ever starting or contacting an MCP server.

## What EtherFence protects — and does not

| Area | EtherFence today |
| --- | --- |
| AI-agent/MCP config posture on this machine | **Protects** — `scan` discovers config files and reports risk hints |
| MCP stdio traffic to a server explicitly wrapped with `mcp-proxy` | **Protects** — method/tool/path allow-deny enforcement, fail-closed on policy errors |
| MCP proxy policy authoring and review | **Protects** — `mcp-policy` validates, explains, and dry-runs policies locally |
| MCP servers *not* wrapped by `mcp-proxy` | **Not protected** — traffic passes through however the server/client normally talk |
| Non-stdio MCP transports (HTTP/SSE) | **Not supported** |
| Terminal commands | **Out of scope** — pairs with [Tirith](https://github.com/Etherisys-id) as complementary terminal-command protection |
| Network or TLS traffic | **Never intercepted** |
| File, prompt, or tool-result content | **Never inspected** — no DLP or content-inspection engine |
| Running processes, registries, remote/managed configs | **Not read** — `scan` only reads known local config files |

No daemon mode, API service, control plane, endpoint agent, shell hooks,
terminal-command scanning, network/TLS interception, DLP/content inspection,
or cloud dependency exists anywhere in EtherFence today.

## Quickstart

Five steps, all local:

```sh
# 1. Install or build (see docs/install.md for release artifacts).
cargo build --release -p etherfence-cli
alias etherfence=./target/release/etherfence   # or put it on PATH

# 2. Run your first scan.
etherfence scan --root tests/fixtures/home     # or omit --root to scan your real machine

# 3. Validate an MCP proxy policy.
etherfence mcp-policy validate examples/policies/mcp-minimal-boundary.toml

# 4. Dry-run a policy decision — no MCP server started or contacted.
etherfence mcp-policy check \
  --policy examples/policies/mcp-minimal-boundary.toml \
  --request '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"filesystem.read","arguments":{}}}'

# 5. Optional: wrap a real MCP server with the runtime boundary proxy.
etherfence mcp-proxy \
  --policy examples/policies/mcp-minimal-boundary.toml \
  --server-name filesystem \
  -- npx -y @modelcontextprotocol/server-filesystem /home/user/projects
```

## Install / build

Full Linux/Windows release-artifact instructions, `cargo install --path`,
and checksum verification live in **[`docs/install.md`](docs/install.md)**.
Short version:

```sh
# From a release artifact (see docs/install.md for checksum verification):
tar -xzf etherfence-linux-x86_64.tar.gz    # Linux
# or: Expand-Archive etherfence-windows-x86_64.zip -DestinationPath .   (Windows)

# From source:
cargo build --release -p etherfence-cli
./target/release/etherfence --version
```

## Command overview

| Command | Purpose | Mode |
| --- | --- | --- |
| `etherfence scan` | Posture discovery / CI gate | Local, read-only, scan-only |
| `etherfence policy list` / `show <name>` | Inspect built-in scan-only policy profiles | Local, read-only |
| `etherfence mcp-policy validate/explain/init/check` | Author, validate, explain, and dry-run MCP proxy policies | Local, serverless |
| `etherfence mcp-proxy` | MCP stdio boundary proxy | Opt-in, local runtime |
| `etherfence setup catalog` | Fixed 10-client compatibility/catalog matrix (support tier, local presence) | Local, read-only |

## `scan` example

```sh
etherfence scan --format json
etherfence scan --policy-profile ci-runner --fail-on high
etherfence scan --baseline etherfence-baseline.json --fail-on-new high
etherfence scan --format sarif > etherfence.sarif
```

```text
EtherFence scan report
======================
Schema: ef-scan-report/v0.1.1
Status: stable-local-scan
Summary: 7 inventory item(s), 24 finding(s): high=12, medium=8, low=4, info=0

HIGH
- EF-POL-001 Unexpected MCP server for agent policy: shell-tools [Claude Code / ~/.claude.json]
  Rationale: The MCP server is not in the policy allowlist for this agent.
  Recommendation: Remove the MCP server or add it to the agent's allowed_mcp_servers after review.
```

`--policy <file>` or `--policy-profile <name>` (built-ins: `developer-laptop`,
`ci-runner`, `research-workstation`, `strict`) evaluates results against a
versioned `ef-policy/v0.1` TOML policy — see
[`docs/policy.md`](docs/policy.md) for the full schema, and
[`docs/json-schema.md`](docs/json-schema.md)/[`docs/sarif.md`](docs/sarif.md)
for output shapes.

## `mcp-policy` example

```sh
etherfence mcp-policy init --profile filesystem-project-readonly-hardened --output mcp-boundary.toml
etherfence mcp-policy validate mcp-boundary.toml
etherfence mcp-policy explain mcp-boundary.toml
etherfence mcp-policy check \
  --policy mcp-boundary.toml \
  --request '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"filesystem.read","arguments":{"path":"/home/user/project/README.md"}}}'
```

`explain` prints a deterministic summary plus warnings for risky or
confusing policy shapes; `check` dry-runs one JSON-RPC request through the
exact decision functions the live proxy uses and never starts a server,
executes a tool, or writes an audit log. See
[`docs/mcp-policy-ux.md`](docs/mcp-policy-ux.md) for the full reference.

## `mcp-proxy` example

```sh
etherfence mcp-proxy \
  --policy /home/user/mcp-boundary.toml \
  --audit-log /home/user/etherfence-mcp-audit.jsonl \
  --server-name filesystem \
  -- npx -y @modelcontextprotocol/server-filesystem /home/user/projects
```

**How `mcp-proxy` fits into your MCP client config:** replace the server
command in your client's config with `etherfence mcp-proxy` plus its flags,
then move the original server command and args after `--` — nothing about
the wrapped server itself changes. See
**[`docs/mcp-proxy-operator-guide.md`](docs/mcp-proxy-operator-guide.md)**
for the full before/after diagram, flag reference, `tools/list`
filtering/allow-deny flow, dry-run and audit-log walkthroughs, common
failure modes, and filesystem/memory-notes config examples.

Policies use schema `ef-mcp-policy/v0.1`:

```toml
schema_version = "ef-mcp-policy/v0.1"
name = "minimal-mcp-boundary"

[tools]
allow = ["github.list_repos", "filesystem.read"]
deny = ["filesystem.read_secret", "shell.run"]

[path_rules.project_readonly]
allow_roots = ["/home/user/project"]
deny_roots = ["/home/user/project/.git", "/home/user/project/secrets"]

[tools."filesystem.read".arguments]
path_keys = ["path"]
path_rule = "project_readonly"
```

The proxy inspects every client→server and server→client JSON-RPC method,
enforces method/tool/path policy, filters `tools/list` advertisements, and
**fails closed**: a missing or invalid policy means the MCP server is never
started. Twelve checked-in example policies live under
[`examples/policies/`](examples/policies). Full behavior, the Unicode/
homograph hardening added in v0.4.1, and current compatibility evidence are
documented in [`docs/mcp-proxy.md`](docs/mcp-proxy.md),
[`docs/mcp-proxy-operator-guide.md`](docs/mcp-proxy-operator-guide.md)
(practical wrapping walkthrough), [`docs/mcp-clients.md`](docs/mcp-clients.md)
(client configuration templates), and
[`docs/mcp-compatibility-matrix.md`](docs/mcp-compatibility-matrix.md).

## `setup catalog` example

```sh
etherfence setup catalog
etherfence setup catalog --format json
```

```text
EtherFence setup catalog
Root: /home/user
Mode: read-only; no configs, policies, backups, or state were modified.

Client                  Tier               Found  Config path(s)
Claude-style config     fixture-verified   yes    ~/.claude.json
Cursor                  fixture-verified   no     -
VS Code                 fixture-verified   no     -
Hermes                  advisory-only      no     -
Antigravity             advisory-only      no     -
Windsurf                detect-only        no     -
Gemini CLI              detect-only        no     -
Codex CLI               detect-only        no     -
OpenCode                advisory-only      no     -
Cline / Roo Code        advisory-only      no     -
```

Prints all 10 fixed clients every run, each labeled honestly by detection
confidence (`fixture-verified` / `detect-only` / `advisory-only`) rather than
a single "supported" claim. `etherfence setup detect --format json` also
carries this release's new, deny-by-default MCP server capability
classification (`ef-setup-detect/v0.1`) — see
[`docs/setup-onboarding.md`](docs/setup-onboarding.md) and
[`docs/json-schema.md`](docs/json-schema.md) for the full schemas.

## CI and team workflow integration

EtherFence is designed to be easy to drop into a team's CI: every command
below is local, read-only scan-only or a serverless MCP-policy dry-run, with
no daemon, no external service, and no change to `mcp-proxy` enforcement.

```sh
# Fail a PR on any high-severity posture finding.
etherfence scan --root . --policy docs/examples/ci/scan-policy.toml --fail-on high

# Fail a PR only on *new* findings versus a checked-in baseline.
etherfence scan --root . --baseline docs/examples/ci/baseline.json --fail-on-new high

# Generate a SARIF report for code-scanning upload.
etherfence scan --root . --format sarif > etherfence.sarif

# Validate an MCP proxy policy, and dry-run one request against it, without
# starting or contacting an MCP server.
etherfence mcp-policy validate docs/examples/ci/mcp-policy.toml
etherfence mcp-policy check \
  --policy docs/examples/ci/mcp-policy.toml \
  --request docs/examples/ci/requests/allowed-tool-call.json
```

See [`docs/ci.md`](docs/ci.md) for the full walkthrough (including how to
avoid committing secrets in baselines/policies), checked example CI input
files under [`docs/examples/ci/`](docs/examples/ci/), and checked example
GitHub Actions workflows under
[`docs/examples/workflows/`](docs/examples/workflows/) (scan posture gate,
scan-with-baseline, SARIF upload, MCP policy validate/explain/check gate,
and a combined PR security gate). These are documentation examples, not
active repository workflows — copy the one(s) you want into your own
`.github/workflows/`.

## Documentation

| Doc | Covers |
| --- | --- |
| [`docs/install.md`](docs/install.md) | Install from a release artifact, build from source, checksum verification, smoke tests |
| [`docs/ci.md`](docs/ci.md) | CI/team workflow integration in full |
| [`docs/policy.md`](docs/policy.md) | `ef-policy/v0.1` scan-only policy schema and built-in profiles |
| [`docs/mcp-proxy.md`](docs/mcp-proxy.md) | `mcp-proxy` behavior, `ef-mcp-policy/v0.1` schema, limitations |
| [`docs/mcp-proxy-operator-guide.md`](docs/mcp-proxy-operator-guide.md) | Practical operator walkthrough: before/after, flags, policy/`--server-name` mapping, dry-run and audit-log usage, failure modes, config examples |
| [`docs/mcp-policy-ux.md`](docs/mcp-policy-ux.md) | `mcp-policy validate/explain/init/check` reference |
| [`docs/setup-onboarding.md`](docs/setup-onboarding.md) | `setup` onboarding command family safety contract, including `setup catalog` (`ef-setup-catalog/v0.1`) and `setup detect`'s MCP capability classification (`ef-setup-detect/v0.1`) |
| [`docs/mcp-clients.md`](docs/mcp-clients.md) | Client configuration templates for wrapping a server with `mcp-proxy` |
| [`docs/mcp-compatibility-matrix.md`](docs/mcp-compatibility-matrix.md) | What MCP stdio behavior is tested vs. untested |
| [`docs/json-schema.md`](docs/json-schema.md) / [`docs/sarif.md`](docs/sarif.md) | `scan` JSON and SARIF output shapes, plus `ef-setup-catalog/v0.1` (`setup catalog`) and `ef-setup-detect/v0.1` (`setup detect`) |
| [`docs/threat-model.md`](docs/threat-model.md) / [`docs/architecture.md`](docs/architecture.md) | Threat model and architecture notes |
| [`docs/roadmap.md`](docs/roadmap.md) | Release-by-release history and scope |
| [`docs/release-automation.md`](docs/release-automation.md) / [`docs/release-checklist.md`](docs/release-checklist.md) | How releases are cut |
| [`CHANGELOG.md`](CHANGELOG.md) | Full per-release change history |

## Security model / non-goals

EtherFence v0.1.x is scan-only. The MCP stdio boundary proxy (v0.2.x+, built
on the stable `ef-mcp-policy/v0.1` schema as of v1.0.0) adds method-level,
tool-level, and path-aware policy enforcement for exactly one wrapped server
at a time; v0.4.1 adds narrow Unicode/homograph hygiene inside policy/runtime
names and guarded path-like values. `mcp-policy` (v0.6.0+) adds local,
serverless policy UX with no new enforcement behavior. EtherFence v1.0.0 is
production-ready for controlled local-first deployments of its defined
scope — `scan`, `mcp-policy`, and the stdio `mcp-proxy` boundary — with a
stable CLI and policy schema. This is not a universal certification for
every MCP server, MCP client, or deployment environment: operators must
still test their chosen MCP servers and policies and monitor audit logs —
see [`docs/mcp-compatibility-matrix.md`](docs/mcp-compatibility-matrix.md)
for exactly what is tested. EtherFence does **not** implement:

- daemon mode, an API service, a control plane, or an endpoint agent
- network or TLS interception
- shell hooks or command interception
- terminal-command scanning duplicated from Tirith
- broad Unicode confusable folding, locale-specific path equivalence,
  `curl | bash`/paste detection, or shell-hook detection
- DLP, content inspection, or arbitrary MCP tool execution
- a marketplace GitHub Action, central dashboard, remote policy service, or
  automatic PR-commenting bot
- package-registry publishing, an auto-update system, or central/fleet
  management
- certification of any specific third-party MCP server, MCP client, or
  deployment environment

Tirith is treated as complementary terminal-command protection. See
[`docs/threat-model.md`](docs/threat-model.md) for the full threat model.

## Development / verification

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
cargo build
git diff --check
```

Releases are cut with a manual `workflow_dispatch` GitHub Actions workflow
(`.github/workflows/release.yml`), never automatically:

```sh
gh workflow run release.yml --ref main -f version=1.0.0
```

It re-runs the checks above on Linux and Windows, builds and checksums both
release artifacts, and creates the tag and GitHub release only after every
validation gate passes. See
[`docs/release-automation.md`](docs/release-automation.md) for the full
workflow and [`docs/release-checklist.md`](docs/release-checklist.md) for
the manual fallback process.

## License

AGPL-3.0-only.
