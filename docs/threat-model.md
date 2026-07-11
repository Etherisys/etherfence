# EtherFence Threat Model

Status: pre-alpha draft, originally for v0.1.0 scan-only posture discovery,
with v0.2.x addenda for the experimental MCP boundary proxy.

## Assets

- Local files reachable by AI agents and MCP servers
- Environment variables exposed to MCP subprocesses
- Agent configuration files
- Developer workstations and repositories
- Complementary terminal protections such as Tirith

## Initial threat hypotheses

1. An agent configuration may enable MCP servers with broad filesystem access.
2. An MCP server may expose shell, command execution, browser, or network-capable behavior.
3. Secret-like environment variable names may be passed to MCP servers.
4. Operators may not know which agent/MCP configurations exist on a workstation.

## Trust boundaries

- The scan commands read local configuration files only.
- The scanner does not intercept, proxy, or block agent runtime behavior.
- EtherFence does not inspect live network traffic.
- It does not scan terminal commands; Tirith remains complementary for that class of control.

## v0.1.0 detection limits

The scanner reports conservative hints from known config paths and fixture-backed formats. It may miss custom locations, unsupported schemas, dynamically generated settings, and runtime-only capabilities. A finding indicates review priority, not confirmed compromise.

## v0.2.x addendum: experimental MCP boundary proxy

`etherfence mcp-proxy` introduces one opt-in, per-invocation runtime
component. Its trust boundary assumptions:

- The proxy only governs the single MCP server it launches over stdio. Any
  MCP server the client talks to directly, or over HTTP/SSE, is outside the
  boundary.
- Enforcement is on `tools/call` request tool names plus `tools/list`
  advertisement filtering. Tool results, resources, prompts, and sampling
  traffic still pass through unmodified, so a cooperative-but-misbehaving
  server is not constrained beyond which tool calls reach it and which tools
  are advertised through tracked `tools/list` responses.
- v0.2.1 policy scoping is selected explicitly with `--server-name` (default:
  `default`). The proxy does not auto-discover or authenticate server
  identity; the operator must bind the right policy scope to the wrapped MCP
  server command.
- The policy fails closed: if it cannot be loaded and validated, the MCP
  server is never started.
- The audit log records decisions and argument key names only; argument
  values are excluded so secrets do not leak into the log. `tools/list`
  filtering records counts and allowed tool names only, not full tool schemas
  or descriptions.
- JSON-RPC batch arrays from the client are denied fail closed rather than
  unpacked, so a batch cannot smuggle a denied tool call past per-message
  inspection.
- Audit failures are fail closed: an unopenable audit log stops the proxy
  before the server starts, and a failed audit write stops forwarding.
- The proxy is a prototype and has not had a full adversarial review of MCP
  framing edge cases (for example multi-line or non-standard framing
  variants, or servers whose JSON parsers resolve duplicate keys differently
  from the proxy). It must not be treated as a security guarantee.
- v0.2.2 compatibility tests cover deterministic stdio request/response flows
  and an optional maintainer-run real-server smoke test. They improve
  confidence that the proxy can sit in front of real stdio MCP servers, but
  they are not a comprehensive MCP conformance suite.
- v0.2.6 hardened request tracking: the proxy tracks `tools/list` requests by
  `(method, id)` with reference-counted cleanup, so duplicate in-flight ids are
  handled deterministically and tracking entries cannot leak. Notifications and
  responses with unknown/missing/no-id pass through unchanged, server errors
  clear tracking, and tracked-id responses that are not genuine tool lists are
  forwarded unchanged with their entry cleared rather than re-shaped. Tracking
  remains scoped to `tools/list`; the proxy still does not reorder, buffer, or
  correlate responses beyond id matching, and remains experimental/pre-alpha.
- v0.2.7 hardened the MCP proxy lifecycle and failure modes: the child server
  is reaped on every exit path (no zombie on normal shutdown, child early exit,
  or proxy error); child early exit / server stdout closure is detected and the
  child's exit code is propagated; client EOF closes the server's stdin and
  reaps the child; broken pipes to either side are treated as clean shutdowns
  rather than panics; invalid client JSON is dropped before forwarding (never
  reaching the server) while valid JSON-RPC traffic passes through unchanged;
  invalid server JSON is passed through for the client's own parser to reject,
  so the proxy can never fabricate or advertise a tool list from a malformed
  server line; and audit logging is explicitly best-effort — a failed audit
  write never weakens a deny or reverses a `tools/list` filter already applied.
  The proxy remains stdio-only, exact-match, policy-compatible with
  `ef-mcp-policy/v0.1`, and experimental/pre-alpha. It still does not perform
  audit rotation or durable fsync beyond the per-write flush, and a child that
  ignores a closed stdin while keeping its stdout open will keep the server
  pump alive until the proxy is killed (matching normal stdio MCP behavior).
- v0.3.0 hardened the MCP proxy from tool-call-only enforcement into
  method-level MCP/JSON-RPC policy enforcement. Every client→server
  JSON-RPC request object is now inspected before forwarding: the method
  name is checked against an optional `[methods]` allow/deny policy.
  Unknown or unspecified methods default deny. Always-allowed methods
  (initialize, notifications/initialized, ping) bypass method policy.
  Existing tools/list filtering and tools/call allow/deny behavior is
  preserved. This is a behavioral hardening from v0.2.x: non-tools
  client→server methods that previously passed through uninspected are
  now denied by default. Deployments needing prior pass-through behavior
  must add an explicit `[methods]` allow list. v0.3.1 extends the same exact-match method policy to server→client
  request/notification objects with a `method` field, covering server-initiated
  client features such as sampling/createMessage, roots/list, and
  elicitation/create before they reach the client. A `method_decision` audit
  event records server name, direction, method, decision,
  reason, request id type, and safe param key names only — no param
  values, prompt text, resource content, message bodies, or secrets are
  logged. The proxy remains stdio-only, exact-match,
  `ef-mcp-policy/v0.1`-compatible, and experimental/pre-alpha. The
  `[methods]` section is optional; existing v0.2.x policies remain
  syntactically valid but will see stricter runtime behavior.
- v0.4.0 adds local path-aware argument/resource guards for the stdio proxy.
  Operators can bind exact tool argument keys or `resources/read` URI param
  keys to named allow/deny root rules. The check is lexical and local-first:
  `.`/`..` segments are collapsed before comparison, deny roots override allow
  roots, malformed or relative configured path-like values fail closed, and
  guarded non-`file://` URIs are denied. The proxy still does not inspect file
  contents, resource contents, prompt/message bodies, terminal commands, shell
  commands, network traffic, or arbitrary URLs. Audit records only safe
  metadata: decision, reason category, method/direction/tool name, key names,
  path rule name, and redacted path classification. Full paths and URIs are not
  logged.
- v0.4.1 adds narrow Unicode/homograph hardening for MCP policy/runtime names
  and guarded path-like values. Policy parsing rejects suspicious Unicode in
  policy names, server scopes, path-rule names, tool/method guard keys, and
  path keys. Runtime checks deny non-ASCII/bidi/zero-width MCP method names,
  non-ASCII/bidi/zero-width `tools/call` tool names, and bidi/zero-width
  guarded path/URI values before matching or path comparison. Audit uses safe
  categories such as `unicode_bidi_control_detected`,
  `unicode_zero_width_detected`, `unicode_non_ascii_method`,
  `unicode_non_ascii_tool`, and `unicode_suspicious_path_value`, with redacted
  placeholders for Unicode-denied method/tool names and suspicious
  audit-visible argument/param key names. The proxy does not fold Unicode
  confusables into ASCII equivalents, does not implement
  locale-specific path equivalence, and does not add content inspection, DLP,
  URL filtering, network interception, a daemon, or a control plane.

## v1.2.0 addendum: client catalog and MCP capability classification

`etherfence setup catalog` and the classification extension to
`etherfence setup detect` add no new trust boundary. They read the same
local configuration files already covered by the "Trust boundaries"
section above (via `etherfence_inventory::discover`), never intercept,
proxy, or block agent runtime behavior, and never inspect live network
traffic or start an MCP server process. Capability classification and the
resulting starter-policy recommendations are static, local-only, and
computed purely from already-parsed `command`/`args` fields against a
small curated signature table — they describe posture, not a runtime
enforcement decision, and `recommendation.tier` is always `deny` in
v1.2.0 (no fixture-verified `allow` rule exists yet, so nothing is ever
recommended permissive by default). An unrecognized MCP server, or one
whose config could not be parsed, is labeled `unknown` and its
recommendation is never permissive.

## v1.3.0 addendum: MCP server trust and integrity assessment

The trust-and-integrity assessment extension to `etherfence setup detect`
adds one new, narrow, local-only surface not present before v1.3.0: a
bounded read of a directly configured local executable file for SHA-256
hashing. This section documents that surface explicitly rather than
folding it silently into the "no new trust boundary" framing above.

- **What's read.** Only a statically configured executable path that
  resolves, via `fs::symlink_metadata` (never followed through a
  symlink), to a regular file at an absolute path is eligible. The read
  is streamed and capped at an explicit size limit; a file exceeding the
  limit is never fully read. File metadata is snapshotted immediately
  before and immediately after the read, and any mismatch discards the
  computed hash rather than reporting it — an operator running `setup
  detect` repeatedly against a workstation whose binaries change between
  runs will see this degrade gracefully, not silently succeed with a
  stale identity.
- **What's never read.** File contents never appear in any output. A
  relative path, a bare/PATH-resolved command, or a symlink is never
  hashed — `PATH` is never searched and symlinks are never dereferenced.
  Remote (URL-configured) servers have no local executable to read at
  all.
- **No new process or network surface.** Hashing is a local file read
  only; it never starts the executable, never contacts a package
  registry or any other network endpoint, and never invokes an MCP
  protocol method. This is the same "no new trust boundary" posture as
  v1.2.0's classification, extended by exactly one narrowly bounded local
  file read.
- **Static structural detection only.** Package-runner version-pinning
  parsing, shell-wrapper recognition, and the fixed set of obscured-launch
  patterns are all closed-world string/token matching over already-parsed
  `command`/`args` fields — never a general shell parser, never command
  execution, and never decoding of an encoded payload.
- **Explicit non-goals.** This feature is not a malware scanner, a
  behavioral security sandbox, an endpoint protection product, a package
  authenticity or software-signature verifier, a package-registry
  reputation service, a universal typosquatting detector, or a universal
  Unicode confusable detector. `artifactIdentity: verified-local` and
  `artifactIdentity: known-source` never imply the underlying program is
  safe; `configurationRisk: no-known-indicators` never implies an absence
  of malicious behavior. `recommendation.tier` remains `deny` for every
  server regardless of this assessment's output — this feature introduces
  no path to a permissive default.

## Path handling and Semgrep path-traversal triage

Static analysis (Semgrep) flags file-path handling across EtherFence as a
generic path-traversal pattern (a path string reaching an `fs::` read call).
This section records how those findings were triaged and what changed.

**Current CLI path model: trusted local operator.** EtherFence today is a
local CLI. Every path it reads — `scan --policy`, `--baseline`,
`--write-baseline`, `mcp-proxy --policy`, `--audit-log`, and the fixed set of
per-agent config file locations under a scanned root — is either an explicit
flag value chosen by the person invoking the CLI, or a filename EtherFence
itself appends to a scanned root the operator selected. There is no remote
caller and no untrusted input reaching these paths, so the security boundary
is "the operator chose this path," not filesystem containment. Consistent
with that, EtherFence does not restrict these CLI paths to a base directory
and does not reject `..` in them — doing so would break documented,
intentional CLI behavior (for example, running `etherfence scan --policy
../shared/team-policy.toml` from a subdirectory).

**What changed as a result of the Semgrep triage:**

- **Policy path prefix/traversal fix.** `crates/etherfence-policy` previously
  compared `allowed_path_prefixes` against filesystem-capable MCP server
  paths using a plain string-prefix check, so a discovered path like
  `/path/to/project/../secrets` would satisfy a naive `starts_with` check
  against the prefix `/path/to/project` even though it lexically resolves
  outside it. Path comparisons (`allowed_path_prefixes` containment and
  `denied_paths` equality) now go through a lexical normalizer that collapses
  `.` and `..` components (without touching the filesystem or requiring the
  path to exist) before comparing, and treat `/`- and `\`-separated paths the
  same way. See `docs/policy.md` for details and examples.
- **Broader filesystem-path detection.** `looks_like_path()` now also
  recognizes relative (`.`, `..`, `./x`, `../x`), home-relative (`~/x`),
  and environment-variable-style (`$HOME/x`, `${HOME}/x`, `%USERPROFILE%\x`)
  filesystem grants, plus common broad Unix directories (`/etc`, `/var`,
  `/tmp`) and any Windows drive path (`C:\`, `D:\data`), so these are
  evaluated against policy instead of silently skipped.
- **Bounded reads.** Policy, MCP proxy policy, and scanned agent config
  files are read through a shared `read_bounded_text_file` helper
  (`crates/etherfence-core`) that rejects files over 5 MiB before reading
  them fully into memory; baseline files use the same helper with a 25 MiB
  ceiling. This bounds worst-case memory/time on an oversized or corrupted
  file; it is a resource-exhaustion guard, not an access-control boundary.

**Future API rule.** EtherFence has no network-facing API today. If one is
ever added, it must never pass an untrusted path string directly to an
`fs::` operation. Any path originating from a remote caller, a UI, or an
MCP-exposed tool must be resolved against and constrained under an explicit
base directory, with traversal (`..` escaping that base) rejected, before
any filesystem access — the trusted-operator model above applies only to
today's local CLI surface.
