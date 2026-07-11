# Feature Specification: Expanded Agent Integration Catalog and MCP Server Classification

**Feature Branch**: `spec/v1.2.0-expanded-agent-integration-catalog`

**Created**: 2026-07-10

**Status**: Draft

**Input**: User description: "EtherFence v1.2.0: Expanded Agent Integration Catalog and MCP Server Classification. Add `etherfence setup catalog` showing a compatibility/catalog matrix for a fixed 10-client list (Claude-style config, Cursor, VS Code, Hermes, Antigravity, Windsurf, Gemini CLI, Codex CLI, OpenCode, Cline / Roo Code), distinguishing fixture-verified / detect-only / advisory-only / unknown support. Add static, local-only, multi-label MCP server capability classification (filesystem, network, browser, shell/command execution, database, SaaS/API, identity/auth, messaging/collaboration, security tooling, unknown) with deterministic starter policy recommendations that are deny-by-default and never permissive for unverified or unknown servers. Must stay local-first, read-only, and honestly documented as posture/classification guidance rather than enforcement."

## Clarifications

### Session 2026-07-10

- Q: Where should MCP server capability classification and starter-policy
  recommendations be surfaced? → A: Extend the existing `etherfence setup
  detect` command with capability labels and starter-policy recommendation
  output; `etherfence setup catalog` stays scoped to the client
  compatibility matrix only.
- Q: Should catalog and classification output include a machine-readable
  (JSON) format in v1.2.0, given the determinism requirement? → A: Yes —
  both a human-readable table and a structured JSON output, mirroring
  existing `scan`/`mcp-policy` conventions.
- Q: Should `etherfence setup catalog` support a CI-style fail-on/exit-code
  gate, or stay purely informational? → A: Purely informational — always
  exits 0 on success regardless of support tiers found; no `--fail-on`
  flag in v1.2.0.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - See client detection support level at a glance (Priority: P1)

An operator who runs one or more AI coding clients wants a single command
that lists every client EtherFence claims to know about for this release,
and tells them honestly how much to trust that claim: is it actually
verified against test fixtures, only detected without verification, only
advisory guidance, or unrecognized?

**Why this priority**: This is the explicitly requested entry point for the
release (`etherfence setup catalog`). Without it, there is no single, honest
place for an operator to see EtherFence's real coverage versus its
aspirational client list, and every other capability in this release has no
discoverable home.

**Independent Test**: Run `etherfence setup catalog` against fixture home
directories that include each of the 10 fixed clients in both a present and
an absent state, and verify every row reports the correct support tier and
local presence — independent of any MCP server classification behavior.

**Acceptance Scenarios**:

1. **Given** a machine with a fixture-verified client's configuration
   present, **When** the operator runs `etherfence setup catalog`, **Then**
   that client's row is labeled fixture-verified and shows the discovered
   configuration path.
2. **Given** a machine with an advisory-only client's configuration present,
   **When** the operator runs `etherfence setup catalog`, **Then** that
   client's row is labeled advisory-only and does not claim verified
   support.
3. **Given** a machine with none of the 10 fixed clients configured,
   **When** the operator runs `etherfence setup catalog`, **Then** all 10
   rows still print with their support tier and an explicit "not found
   locally" presence indicator.
4. **Given** an unchanged machine state, **When** the operator runs
   `etherfence setup catalog` twice in a row, **Then** both runs produce
   byte-identical, identically ordered output.

---

### User Story 2 - Understand what a locally configured MCP server can do (Priority: P1)

An operator who has one or more MCP servers configured in a detected client
wants to see, for each server, which broad capability areas (filesystem,
network, shell access, and so on) it appears to need — derived purely from
reading local configuration — so they can judge risk before trusting or
wrapping that server, without EtherFence ever starting it, contacting it, or
touching the network.

**Why this priority**: This is the core new detection value of the release
and a direct prerequisite for the starter-policy recommendation in User
Story 3. It is equally foundational to User Story 1 — both are named,
required behaviors of this release.

**Independent Test**: Run classification against fixture MCP server
configurations whose command/argument shapes are constructed to match each
taxonomy label (individually and in combination), and verify the exact
expected label set is produced for each fixture, with no network access or
external process ever started during the test.

**Acceptance Scenarios**:

1. **Given** an MCP server configuration whose command/arguments match a
   known filesystem-tool pattern, **When** classification runs, **Then**
   the server's output includes the `filesystem` label.
2. **Given** an MCP server configuration matching both a shell-execution
   pattern and a network-access pattern, **When** classification runs,
   **Then** the server's output includes both the `shell / command
   execution` and `network` labels.
3. **Given** an MCP server configuration that matches none of the
   documented evidence patterns, **When** classification runs, **Then**
   the server is labeled `unknown` rather than omitted or left blank.
4. **Given** any classification run, **When** its behavior is observed,
   **Then** no outbound network connection is opened, no MCP server
   process is started, and no MCP protocol method (including `tools/list`)
   is ever invoked.

---

### User Story 3 - Get a safer starting policy than "allow everything" (Priority: P2)

An operator new to policy authoring wants EtherFence to propose a
conservative starter policy recommendation for each classified server,
defaulting to deny and flagging anything uncertain for manual review, so
they never accidentally start from a fully permissive configuration.

**Why this priority**: Builds directly on User Story 2's classification
output and delivers the release's safety payoff, but it is one step removed
from the raw catalog/classification data itself, so it follows P1 work.

**Independent Test**: Feed a set of already-classified fixture servers
(including servers with an `unknown` label and servers that are fully
fixture-verified) through the recommendation step and verify recommendations
default to deny/needs-review and are never permissive for any server
carrying an `unknown` label or an unverified classification.

**Acceptance Scenarios**:

1. **Given** a server classified only with capabilities that are not
   fixture-verified as safe to recommend allowing, **When** a starter
   recommendation is generated, **Then** the recommendation is deny or
   needs-review, never allow.
2. **Given** a server carrying the `unknown` label, **When** a starter
   recommendation is generated, **Then** the recommendation is never
   permissive.
3. **Given** identical classified server data, **When** recommendations
   are generated on Linux and on Windows, **Then** the recommendation
   values and their ordering are identical on both platforms.

---

### Edge Cases

- What happens when zero of the 10 fixed clients are detected locally? The
  catalog still prints all 10 rows with their support tier and a "not
  found" presence indicator; it never shrinks the list to only what is
  present.
- What happens when a single client has more than one configuration path on
  the same machine (for example, both a global and a project-level
  configuration)? Each discovered path is represented without collapsing or
  silently dropping any of them.
- What happens when one MCP server's configuration matches evidence for
  several capability labels at once (for example, a server that both reads
  files and shells out)? All matching labels are attached to that server;
  none are dropped in favor of a single "primary" label.
- What happens when an MCP server's configuration matches no documented
  evidence pattern at all? It is labeled `unknown`, and its starter
  recommendation is never permissive.
- What happens when a configuration file is malformed or unreadable? The
  affected entry is reported as unreadable/`unknown` rather than causing the
  command to crash or silently skip that entry.
- What happens when path casing or separators differ between Linux and
  Windows for otherwise-identical configurations? Output ordering and
  labels are still identical between platforms once platform-specific path
  spelling is normalized for comparison.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST provide a `etherfence setup catalog` command
  that prints a matrix with exactly one row per client in the fixed
  v1.2.0 client list: Claude-style config, Cursor, VS Code, Hermes,
  Antigravity, Windsurf, Gemini CLI, Codex CLI, OpenCode, and Cline / Roo
  Code (10 rows total).
- **FR-002**: Each catalog row MUST report exactly one support tier:
  fixture-verified, detect-only, advisory-only, or unknown/unsupported.
- **FR-003**: Each catalog row MUST also report whether that client's
  configuration was found on the local machine during the current run, and
  the discovered configuration path(s) if found.
- **FR-004**: The catalog list MUST be fixed to exactly the 10 named
  clients for v1.2.0; the system MUST NOT silently add other client names
  to the catalog output without a corresponding specification and
  constitution-compliant amendment.
- **FR-005**: The `etherfence setup catalog` command MUST be read-only: it
  MUST NOT create, modify, or delete any configuration, backup, policy,
  audit, or state file.
- **FR-006**: The `etherfence setup catalog` command MUST NOT perform any
  network access.
- **FR-006a**: The `etherfence setup catalog` command MUST remain purely
  informational in v1.2.0: it MUST always exit successfully (exit code 0)
  regardless of which support tiers are present, and MUST NOT provide a
  CI-gating flag (e.g., a `--fail-on`-style option). CI/CD gating on
  posture findings remains the responsibility of the existing `scan
  --fail-on`/`--fail-on-new` behavior.
- **FR-007**: The system MUST classify each locally detected MCP server
  configuration using static inspection of already-read local configuration
  data only, surfaced through the existing `etherfence setup detect`
  command (extended with capability labels and starter-policy
  recommendation output) rather than a new top-level command; `etherfence
  setup catalog` remains scoped to the client compatibility matrix defined
  in FR-001 through FR-004.
- **FR-008**: Classification MUST NOT connect to, start, execute, or
  otherwise interact with any MCP server process.
- **FR-009**: Classification MUST NOT invoke `tools/list` or any other MCP
  protocol method against any server.
- **FR-010**: Classification MUST NOT perform any network access.
- **FR-011**: Classification MUST NOT execute any command referenced inside
  an inspected configuration file.
- **FR-012**: Classification MUST assign zero or more capability labels to
  each server from the fixed taxonomy — filesystem, network, browser,
  shell / command execution, database, SaaS / API, identity / auth,
  messaging / collaboration, security tooling, unknown — as a set (multi-
  label), never forcing a single label per server.
- **FR-013**: A server that matches none of the documented, evidence-backed
  capability rules MUST be labeled `unknown` rather than left unlabeled or
  omitted from output.
- **FR-014**: Every capability label assignment MUST be backed by an
  explicit, documented, deterministic rule (for example: a matched command
  name, argument pattern, or package/tool identifier). No non-reproducible
  heuristic may contribute a label.
- **FR-015**: The system MUST derive exactly one starter-policy
  recommendation tier per server from that server's assigned capability
  label set, using a single fixed, documented precedence/merge order over
  the taxonomy, such that an identical label set always yields an identical
  recommendation regardless of the order labels were discovered in.
- **FR-016**: A server carrying the `unknown` label, the `shell / command
  execution` label, or the `identity / auth` label MUST each independently
  force the most restrictive recommendation (deny plus needs-review) for
  that server, regardless of what other labels are also present.
- **FR-017**: Starter-policy recommendations MUST default to deny for every
  capability unless that specific capability, on that specific classified
  server, is fixture-verified as safe to recommend allowing.
- **FR-018**: The system MUST NOT produce a permissive (allow) starter
  policy recommendation for any server whose overall classification
  includes the `unknown` label or is not backed by a fixture-verified
  client/config source.
- **FR-019**: Every client catalog status of fixture-verified, and every
  classification rule that contributes a capability label, MUST have at
  least one corresponding checked-in fixture and automated test asserting
  its exact expected output before it may be described as
  supported/verified in documentation or command output.
- **FR-020**: Catalog and classification output (ordering, labels, support
  tiers, recommendations, and any identifiers/fingerprints) MUST be
  deterministic: identical local input state MUST produce byte-identical
  output on repeated runs and across Linux and Windows.
- **FR-020a**: Both `etherfence setup catalog` and the classification/
  starter-policy output of `etherfence setup detect` MUST support a
  human-readable format and a structured, machine-readable (JSON) format,
  consistent with existing `scan`/`mcp-policy` output conventions; the
  determinism guarantee in FR-020 applies to both formats.
- **FR-021**: The feature MUST NOT introduce a daemon process, background
  service, telemetry collection, or any new network listener.
- **FR-022**: The feature MUST NOT change existing `mcp-proxy` runtime
  interception/enforcement behavior.
- **FR-023**: The feature MUST NOT perform live or runtime MCP server
  probing of any kind.
- **FR-024**: The feature MUST NOT add any shell hook, browser hook, or
  kernel hook.
- **FR-025**: The feature MUST NOT automatically modify any user
  configuration file as part of catalog display or classification; all
  behavior in this feature is read-only.
- **FR-026**: Documentation and command output for this feature MUST
  describe catalog, classification, and starter-policy behavior as local
  posture/classification/starter-policy guidance, and MUST NOT describe it
  as enforcement or blocking. Enforcement claims MUST be limited to cases
  where the existing `mcp-proxy` is explicitly used.
- **FR-027**: Existing `scan`, `setup` (`detect`/`plan`/`apply`/`rollback`/
  `doctor`), `mcp-policy`, and `mcp-proxy` behaviors MUST continue to
  function and pass their existing test suites unmodified by this feature.

### Key Entities

- **Client Catalog Entry**: One of the 10 fixed v1.2.0 clients. Attributes:
  client name/id, support tier (fixture-verified / detect-only /
  advisory-only / unknown-unsupported), local presence (found/not found),
  discovered configuration path(s) if found.
- **MCP Server Record**: One MCP server configuration discovered under a
  detected client. Attributes: server name, owning client/configuration
  source, assigned capability label set (zero or more of the fixed
  taxonomy), and the evidence rule(s) that produced each label.
- **Capability Label**: One entry from the fixed taxonomy (filesystem,
  network, browser, shell / command execution, database, SaaS / API,
  identity / auth, messaging / collaboration, security tooling, unknown).
  A server may carry any number of labels simultaneously.
- **Starter Policy Recommendation**: A per-server recommendation (deny,
  needs-review, or a fixture-verified allow) derived deterministically from
  that server's capability label set and classification confidence, plus
  the rationale for the recommendation.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: For every one of the 10 fixed clients, a user can determine
  its support tier (fixture-verified, detect-only, advisory-only, or
  unknown) from a single command's output, without reading source code.
- **SC-002**: Running the catalog and classification commands twice in a
  row against an unchanged local configuration set produces identical
  ordered output, and produces identical ordered output when run on Linux
  versus Windows against equivalent configuration state.
- **SC-003**: 100% of locally detected MCP servers receive at least one
  capability label in output; none are left unlabeled, and servers with no
  positively identified capability show `unknown` rather than being
  omitted.
- **SC-004**: 100% of starter-policy recommendations for servers carrying
  an `unknown` label, or classified from a non-fixture-verified source,
  are deny or needs-review — never an unqualified allow.
- **SC-005**: Every client marked fixture-verified in the catalog, and
  every capability-label rule exercised in this release, has at least one
  passing automated fixture test proving that exact status/output, checked
  as a release gate before the version ships.
- **SC-006**: A documentation-honesty check confirms that catalog,
  classification, and starter-policy documentation and command output use
  posture/classification/guidance language, not enforcement or blocking
  language, except where `mcp-proxy` is explicitly named as the enforcement
  mechanism.
- **SC-007**: All pre-existing `scan`, `setup`, `mcp-policy`, and
  `mcp-proxy` automated tests continue to pass unmodified after this
  feature ships, confirming no regression.

## Out of Scope

- Live or runtime MCP server inspection of any kind (connecting to a
  server, starting a server, calling `tools/list`, or any other MCP
  protocol interaction) — deferred to a future release, if ever pursued.
- Any client not in the fixed 10-client list. Adding further clients is
  explicitly out of scope for this release and must not occur as an
  incidental side effect of implementation.
- Automatic rewriting, migration, or mutation of any configuration file
  discovered by the catalog or classification behavior in this release.
- Any change to `mcp-proxy` runtime enforcement semantics, the
  `ef-mcp-policy` schema's enforcement behavior, or existing `scan`
  finding/severity behavior.
- Network-sourced threat intelligence, reputation scoring, or any
  capability requiring outbound network access.
- A CI-gating flag (e.g., `--fail-on`) on `etherfence setup catalog`.
  CI/CD gating on posture findings remains the responsibility of the
  existing `scan --fail-on`/`--fail-on-new` behavior.

## Assumptions

- "Cline / Roo Code" is treated as a single catalog entry (one matrix row)
  per the user-provided fixed client list, which paired them together.
- The exact ranked precedence order used to resolve a server's final
  starter-policy tier from a multi-label set (beyond the fixed rule that
  `unknown`, `shell / command execution`, and `identity / auth` always
  force the most restrictive tier, per FR-016) is a deterministic ordering
  to be finalized and documented during implementation planning, not
  prescribed at the specification level.
- "Fixture-verified" for a client means EtherFence has both explicit
  detection/parsing logic for that client's configuration shape and a
  checked-in fixture plus automated test proving the catalog reports that
  client correctly; "detect-only" means detection logic exists without a
  fixture-backed test of the exact catalog status; "advisory-only" means
  the client is named and described but has no dedicated detection logic
  beyond generic/manual guidance.
