# EtherFence Roadmap

EtherFence is **AI Agent Security Posture and Runtime Control** for local-first
developer environments.

This document describes product direction and priorities. The detailed,
release-by-release history is maintained in [`CHANGELOG.md`](../CHANGELOG.md).
Planned release scopes are proposals until their Spec Kit specification,
threat-model review, implementation plan, and acceptance tests are complete.

## Product mission

AI agents are probabilistic and can be mistaken, hallucinate, or be influenced
by untrusted content. MCP tools and servers are deterministic software with real
authority over files, commands, APIs, credentials, and infrastructure.

EtherFence assumes:

- the agent may be wrong or prompt-injected;
- a legitimate tool may be overprivileged;
- tool descriptions and schemas may be misleading or may change;
- an MCP server may be replaced, reconfigured, or compromised;
- model-level guardrails are useful but are not a deterministic security
  boundary.

EtherFence therefore aims to:

1. **Discover** which agents, MCP servers, and relevant configurations exist.
2. **Explain** capabilities, trust indicators, effective exposure, and change.
3. **Recommend** conservative least-privilege controls in understandable terms.
4. **Protect** the MCP boundary with deterministic runtime policy.
5. **Verify** configuration, policy, and integrity state over time.
6. **Recover** safely through preview, validation, backups, and rollback.

Posture finds the risk. Runtime control limits the consequence.

## Product principles

- Local-first and offline by default.
- Deterministic controls must not depend on the model correctly policing itself.
- Default deny for unknown runtime authority.
- Explain before enforcing; never describe drift as confirmed malware.
- No silent trust, automatic baseline acceptance, or hidden policy widening.
- Configuration-changing workflows must preview, validate, back up, and support
  rollback.
- Avoid approval queues for normal configuration protection. Explicit commands
  are the operator's authorization.
- Strict or disruptive enforcement must be an explicit opt-in.
- Security claims must be narrow, testable, and honest about boundaries.

## Current capability: v1.4.0

### Security posture

EtherFence can:

- discover fixture-backed local AI-agent and MCP configuration;
- report support confidence through the fixed client catalog;
- classify MCP server capabilities using local static evidence;
- assess package pinning, shell wrappers, obscured launch patterns,
  executable-path state, bounded executable hashes, Unicode ambiguity, and
  environment-variable name risks;
- distinguish artifact identity from configuration risk;
- write deterministic MCP integrity baselines;
- report new, changed, missing, unchanged, and unverifiable servers;
- gate CI on drift, new servers, or documented risk increases.

### Runtime control

For explicitly wrapped local stdio MCP servers, `mcp-proxy` can:

- enforce bidirectional MCP/JSON-RPC method policy;
- enforce tool-name allow and deny policy;
- filter `tools/list` advertisements;
- restrict configured filesystem paths and `file://` resources;
- reject malformed, ambiguous, batch, and suspicious-Unicode cases
  conservatively;
- apply the same decision functions through `mcp-policy check`.

### Safe setup and policy UX

EtherFence already provides:

- `setup detect`, `plan`, `apply`, `rollback`, and `doctor`;
- backup-first rewriting for supported client configurations;
- conservative policy generation and validation;
- `mcp-policy init`, `validate`, `explain`, and `check`.

These capabilities should be improved rather than replaced with a separate
approval workflow.

## Remaining product gaps

| Gap | Why it matters | Planned response |
| --- | --- | --- |
| Tool-name policy is too coarse | An allowed tool can still perform an unsafe operation using dangerous arguments | v1.5.0 argument-aware MCP runtime policy |
| Remote MCP posture is shallow | Users cannot clearly assess remote endpoint identity, transport, or configuration risk | v1.6.0 remote MCP posture |
| Tool definitions may change | A server can retain a tool name while changing its schema, description, or annotations | v1.7.0 tool-manifest integrity |
| Guided protection is not yet the primary user journey | Existing setup capabilities are safer than manual editing but need clearer intent-based policy generation | v1.8.0 guided protection maturation |
| Client and real-server evidence remains uneven | Unsupported formats and untested servers reduce practical coverage | Continuous compatibility track |
| MCP policy cannot constrain actions outside the protocol | A malicious server process can access the OS directly | Long-term isolation research |
| Product documents can lag implementation | Stale status and threat-model wording weakens user trust | Continuous documentation-honesty track |

## v1.5.0 — Argument-aware MCP runtime policy

**Priority: next.**

### User outcome

> An allowed tool may run only with arguments that match the operator's
> least-privilege policy.

This release should strengthen consequence containment when an agent is
mistaken or prompt-injected. It should not attempt to detect prompt injection or
infer natural-language intent.

### Proposed scope

- Introduce a versioned argument-policy extension, expected to become
  `ef-mcp-policy/v0.2`, while continuing to support existing
  `ef-mcp-policy/v0.1` policies.
- Add deterministic, closed-world guards for selected tool arguments and method
  parameters:
  - required and forbidden keys;
  - exact-value and finite-enum allowlists;
  - string length limits and narrow prefix rules;
  - numeric minimum and maximum bounds;
  - array length limits and finite allowed-element sets;
  - URL scheme, normalized hostname, port, and path-prefix allowlists;
  - bounded nested selectors with an explicit syntax.
- Missing guarded keys, wrong types, ambiguous selectors, and malformed values
  fail closed only where a guard is explicitly configured.
- Use the exact same evaluator for live `mcp-proxy` decisions and serverless
  `mcp-policy check`.
- Extend `mcp-policy explain`, validation, examples, and CI fixtures.
- Audit only safe metadata such as rule identifiers, key names, decision, and
  reason categories. Do not log protected values.
- Add task-oriented examples such as:
  - GitHub operations restricted to named organizations and repositories;
  - messaging operations restricted to named destinations;
  - browser or API operations restricted to approved HTTPS hosts;
  - tools with an explicit operation field restricted to read-only enum values.

### Explicit non-goals

- No natural-language or semantic-intent analysis.
- No general regex or executable policy language.
- No prompt, message, tool-result, file-content, or raw SQL inspection.
- No general shell parser or command-content allowlisting.
- No claim that an allowed argument makes the underlying server safe.
- No new daemon, control plane, or network interception.

### Acceptance direction

- Existing v0.1 policies remain behaviorally compatible.
- Configured guards are deterministic on Linux and Windows.
- Unknown or malformed guarded values cannot bypass a rule.
- Dry-run and live decisions are byte-for-byte equivalent in their decision
  semantics.
- Denials provide a concise reason and remediation without exposing argument
  values.

## v1.6.0 — Remote MCP posture

**Priority: planned after v1.5.0.**

### User outcome

> Users can understand which remote MCP endpoints are configured, how they are
> addressed, what configuration risks exist, and whether those endpoints
> changed after review.

This release is posture-only. It must not silently become a remote MCP proxy.

### Proposed scope

- Expand fixture-verified discovery of remote MCP configurations across
  supported clients.
- Normalize remote endpoint identity using safe components:
  scheme, normalized host, effective port, and path identity.
- Never emit embedded credentials, query secrets, fragments, bearer tokens, or
  environment-variable values.
- Add static risk indicators for:
  - plaintext or unsupported transport schemes;
  - credentials or secret-like material embedded in a URL;
  - loopback, private, link-local, and public endpoint classes;
  - suspicious Unicode, bidirectional, zero-width, or hostname ambiguity;
  - unusual ports and malformed endpoint shapes;
  - missing or ambiguous authentication configuration, using names and
    categories only.
- Integrate normalized endpoint identity and risk with `setup detect` and the
  v1.4.0 baseline/check workflow so endpoint changes become explicit drift.
- Provide human and JSON output with precise remediation guidance.
- Add Linux/Windows fixtures, malformed-config behavior, deterministic sorting,
  and negative tests proving secret values never appear.

### Explicit non-goals

- No connection to the configured endpoint.
- No token validation, TLS handshake, certificate inspection, DNS lookup,
  redirect following, or reputation query.
- No HTTP/SSE/Streamable HTTP interception or runtime enforcement.
- No statement that HTTPS, a familiar hostname, or configured authentication
  proves the server is trustworthy.

## v1.7.0 — Tool-manifest integrity and capability drift

### User outcome

> Users can see when a server's advertised tools, schemas, descriptions,
> annotations, or capabilities changed after review.

### Direction

- Design a separately threat-modelled, explicit inspection command because live
  tool discovery starts or contacts an MCP server and therefore creates a new
  trust boundary.
- Capture deterministic fingerprints for tool names, input schemas,
  descriptions, annotations, and declared server capabilities.
- Compare manifests and report added, removed, or changed tool definitions.
- Never call a tool during inspection.
- Report change, not maliciousness.
- Do not make runtime blocking the default; strict behavior, if added later,
  must be opt-in and explainable.

## v1.8.0 — Guided protection maturation

### User outcome

> A user can move from a detected MCP server to a useful least-privilege policy
> without manually understanding the full policy schema.

### Direction

Build on the existing `setup plan/apply/rollback/doctor` safety model:

- intent-based profiles that request only necessary user inputs;
- explicit project roots, repositories, hosts, and destinations;
- redacted before/after plans;
- argument-aware policy generation using the v1.5.0 primitives;
- validation before any write;
- backup-first, atomic configuration changes;
- clear verification and rollback commands;
- no automatic permissive policy for unknown capabilities;
- no approval queue or repeated interactive confirmation;
- promotion of additional clients to write support only with fixture-backed,
  format-preserving tests.

## Continuous compatibility tracks

These tracks should progress alongside feature releases without weakening scope
discipline.

### Client coverage

- Promote advisory-only clients to fixture-verified parsing one at a time.
- Keep detection support and safe write support as separate claims.
- Prioritize Hermes and OpenCode, followed by other clients with documented,
  stable configuration formats.
- Preserve unknown fields and refuse ambiguous rewrites.

### Real-server compatibility

- Add controlled evidence for representative filesystem, GitHub/API, database,
  browser, messaging, memory, and security-tooling servers.
- Keep third-party servers out of default CI unless the fixture is pinned,
  deterministic, credential-free, and safe to execute.
- Compatibility evidence is not server certification.

### Security and documentation honesty

Every release should keep these aligned:

- README version, status, and command overview;
- architecture and threat-model status;
- roadmap current and planned scopes;
- changelog release entry;
- schema and example documentation;
- docs-drift tests for public claims and commands.

### Cross-platform hardening

- Preserve deterministic Linux and Windows behavior.
- Continue no-follow, bounded-read, atomic-write, path-normalization, Unicode,
  malformed-input, and secret-redaction regression coverage.
- Treat review findings as design feedback and document meaningful corrections
  in the relevant Spec Kit research artifacts.

## Long-term research

The following areas require new threat models and should not be added as small
extensions to the current stdio proxy:

- remote MCP runtime mediation for HTTP/SSE/Streamable HTTP;
- optional MCP server process confinement and filesystem isolation;
- network egress restrictions for MCP server processes;
- cross-tool sensitive-data flow and exfiltration controls;
- signed provenance and software identity verification;
- central or fleet posture management.

## Explicit non-goals for the current roadmap

Unless a future threat model explicitly changes the boundary, EtherFence does
not claim to provide:

- universal prompt-injection prevention;
- malware detection or endpoint protection;
- behavioral sandboxing;
- DLP or general content inspection;
- automatic trust, baseline approval, or policy widening;
- terminal-command interception already covered by complementary tools;
- transparent network or TLS interception;
- certification of an MCP server, client, package, or deployment.

## Completed milestones

- **v0.1.x:** local posture inventory, findings, policies, baselines, CI gates,
  SARIF, parser hardening, Windows/Linux support, and release packaging.
- **v0.2.0–v0.4.1:** local stdio MCP boundary, tool and method policy,
  bidirectional enforcement, request tracking, lifecycle hardening, path-aware
  rules, and Unicode hygiene.
- **v0.5.0–v1.0.1:** compatibility evidence, policy UX, CI integration,
  installation and release hardening, and a stable local-first CLI/policy
  surface for the defined scope.
- **v1.1.0:** secure setup onboarding with detect, plan, apply, rollback, and
  doctor; backup-first supported-client rewriting.
- **v1.2.0:** expanded client catalog, capability classification, and
  deny-by-default recommendations.
- **v1.3.0:** static MCP server trust and executable-integrity assessment.
- **v1.4.0:** deterministic MCP server integrity baselines, drift reasons, and
  CI gates for drift, new servers, and risk increases.

See [`CHANGELOG.md`](../CHANGELOG.md) for the detailed release history.
