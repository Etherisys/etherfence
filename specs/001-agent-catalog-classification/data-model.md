# Phase 1 Data Model: Expanded Agent Integration Catalog and MCP Server Classification

All new types are Rust types added to `crates/etherfence-core` (shared,
cross-crate types) and `crates/etherfence-setup` (feature-specific
types), following the existing `#[derive(Debug, Clone, Serialize)]` /
`#[serde(rename_all = "kebab-case")]` conventions already used throughout
the workspace (see `SetupDetection`, `WriteSupport`, `DoctorStatus`).

## AgentKind (extended, `etherfence-core`)

Existing enum, extended with 5 new variants. No existing variant is
renamed or removed (additive only).

```text
pub enum AgentKind {
    ClaudeCode, Cursor, VsCode, Windsurf, GeminiCli, CodexCli, Tirith, // existing
    Hermes, Antigravity, OpenCode, Cline, RooCode,                    // new (v1.2.0)
}
```

- `display_name()` and `key()` gain matching arms for the 5 new variants
  (compiler-enforced exhaustiveness — see plan.md Post-Design Re-Check).
- `write_support_for_agent` in `etherfence-setup` requires **no code
  change**: its existing wildcard arm (`_ => WriteSupport::AdvisoryOnly`)
  already covers the new variants correctly (they must never be
  write-supported — see spec Out of Scope).

## CatalogClient (new, `etherfence-setup::catalog`)

Represents one row of the fixed v1.2.0 client matrix. Distinct from
`AgentKind` because two `AgentKind` variants (`Cline`, `RooCode`) collapse
into a single catalog row per spec Assumption ("Cline / Roo Code" is one
matrix row), and because catalog membership is fixed at exactly 10
entries regardless of future `AgentKind` growth (FR-004).

```text
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CatalogClient {
    ClaudeStyleConfig,
    Cursor,
    VsCode,
    Hermes,
    Antigravity,
    Windsurf,
    GeminiCli,
    CodexCli,
    OpenCode,
    ClineRooCode,
}
```

- Fixed, exhaustive, declaration-order == catalog display order (Decision 4).
- `CatalogClient::ALL: [CatalogClient; 10]` constant enumerates them in
  matrix-row order for FR-001's "exactly one row per client."
- Mapping to underlying `AgentKind` presence: `ClineRooCode` maps to
  `AgentKind::Cline` **or** `AgentKind::RooCode` (found if either is
  present; both paths recorded if both are present — see `CatalogEntry.config_paths`).

## CatalogSupportTier (new, `etherfence-setup::catalog`)

```text
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CatalogSupportTier {
    FixtureVerified,
    DetectOnly,
    AdvisoryOnly,
    Unknown,
}
```

Assigned per `CatalogClient` from a fixed, checked-in static table (not
computed at runtime from heuristics) — see research.md Decision 2 for the
v1.2.0 ship-time assignment. `Unknown` exists for forward-compatibility
(e.g. a future corrupted/ambiguous detection state) and is not assigned to
any of the 10 clients by default.

## CatalogEntry (new, `etherfence-setup::catalog`)

One row of `etherfence setup catalog` output.

```text
#[derive(Debug, Clone, Serialize)]
pub struct CatalogEntry {
    pub client: CatalogClient,
    pub tier: CatalogSupportTier,
    pub found_locally: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub config_paths: Vec<String>,   // empty iff found_locally == false
}
```

**Validation rules**:
- `config_paths.is_empty() == !found_locally` (never both found and empty,
  never not-found with paths) — enforced by construction, asserted by
  unit tests.
- Exactly 10 `CatalogEntry` values are produced per `catalog()` call, one
  per `CatalogClient::ALL`, in that fixed order (FR-001, FR-004).
- **Multi-path ordering** (spec Edge Case 2, FR-003, FR-020): when a
  client has more than one discovered configuration path (e.g. both a
  global and a project-level Cursor config), `config_paths` lists them in
  the same order `etherfence_inventory::discover()` already returns its
  `InventoryItem`s — which is itself the fixed, declared order of that
  agent's entries in the `CANDIDATES` table in
  `crates/etherfence-inventory/src/lib.rs`. `catalog()` MUST NOT re-sort
  `config_paths` by any other key (alphabetical, filesystem-returned
  order, etc.) — it simply collects paths in `discover()`'s existing
  deterministic order. This requires no new sorting logic and no
  path-normalization step, since `CANDIDATES` declaration order is
  already identical on Linux and Windows.

## CapabilityLabel (new, `etherfence-setup::classification`)

```text
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CapabilityLabel {
    Unknown,
    ShellCommandExecution,
    IdentityAuth,
    SecurityTooling,
    Database,
    MessagingCollaboration,
    SaasApi,
    Network,
    Browser,
    Filesystem,
}
```

- Declaration order is the canonical, most-restrictive-first order used
  both for output ordering and for the `needs_review` merge rule
  (Decision 4) — one order serves both purposes, so there is exactly one
  place this ordering is defined.
- `CapabilityLabel::ALL: [CapabilityLabel; 10]` enumerates the full fixed
  taxonomy (satisfies spec requirement "capability taxonomy must include
  at least" these 10 — this release implements exactly these 10, no more).
- **JSON vs. human representation**: `Serialize` (`kebab-case`) is the
  *only* machine-readable form and MUST be used for every JSON field
  value — e.g. `ShellCommandExecution` serializes to
  `"shell-command-execution"`, `IdentityAuth` to `"identity-auth"`,
  `SecurityTooling` to `"security-tooling"`, `MessagingCollaboration` to
  `"messaging-collaboration"`, `SaasApi` to `"saas-api"`. For human-facing
  CLI text (and evidence/rationale strings), a separate
  `pub fn human_label(self) -> &'static str` returns the friendlier
  spec-taxonomy phrasing (`"shell / command execution"`,
  `"identity / auth"`, `"security tooling"`, `"messaging / collaboration"`,
  `"SaaS / API"`), mirroring the existing `AgentKind::display_name()` vs.
  `AgentKind::key()` split in `etherfence-core`. The two representations
  MUST NOT be conflated in either direction — JSON output always uses the
  `Serialize` token; human/text output always uses `human_label()`.

## ClassifiedCapabilities (new, `etherfence-setup::classification`)

```text
#[derive(Debug, Clone, Serialize)]
pub struct ClassifiedCapabilities {
    pub labels: Vec<CapabilityLabel>,       // non-empty; sorted per the canonical order;
                                              // contains exactly [Unknown] when no curated
                                              // rule matched (FR-013)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,               // one human-readable note per matched rule,
                                              // e.g. "command 'npx' arg '@modelcontextprotocol/server-filesystem' matched filesystem rule"
}
```

**Validation rules**: `labels` is never empty (FR-013 — always at least
`[Unknown]`). `labels` contains no duplicates. `evidence.len() ==
labels.len()` when `labels != [Unknown]`; `evidence` is empty when
`labels == [Unknown]` (nothing matched, so there is nothing to cite).

## StarterPolicyRecommendation (new, `etherfence-setup::classification`)

```text
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecommendationTier {
    Deny,
    Allow,   // reserved; never produced by any v1.2.0 curated rule — see research.md Decision 3
}

#[derive(Debug, Clone, Serialize)]
pub struct StarterPolicyRecommendation {
    pub tier: RecommendationTier,
    pub needs_review: bool,
    pub rationale: String,
}
```

**Derivation rule** (pure function of `ClassifiedCapabilities.labels`,
FR-015/FR-016/FR-017/FR-018):
1. `tier = RecommendationTier::Deny` always, in v1.2.0 (no curated rule
   sets `Allow` — Decision 3).
2. `needs_review = labels.contains(Unknown) || labels.contains(ShellCommandExecution) || labels.contains(IdentityAuth)`.
3. `rationale` is a short, deterministic, generated string naming which
   label(s) drove the decision (e.g., "denied by default; flagged for
   review because capability includes shell / command execution").

This is a total function over any label set the classifier can produce —
no unreachable/undefined case exists.

## SetupServer (extended, `etherfence-setup`, existing struct)

```text
pub struct SetupServer {
    pub name: String,
    pub transport: ServerTransport,
    pub wrapped: bool,
    pub capabilities: ClassifiedCapabilities,          // NEW
    pub recommendation: StarterPolicyRecommendation,    // NEW
}
```

Additive-only change. Populated inside `server_from_mcp` (which already
receives the full `&McpServer`, including `command`/`args`, needed by the
classifier). `setup plan` and `setup doctor` rendering code is untouched
and continues to read only the fields it already reads — their observable
output does not change (plan.md Post-Design Re-Check).

## Relationships

```text
CatalogClient  --(static table)-->  CatalogSupportTier
CatalogClient  --(local presence lookup via AgentKind)-->  CatalogEntry

McpServer (existing, etherfence-core)
   --(classify_server)-->  ClassifiedCapabilities
   --(recommend)------->  StarterPolicyRecommendation

SetupDetection (existing)
   .servers: Vec<SetupServer>   // each now carries capabilities + recommendation
```

No entity in this feature is persisted (no database, no state file); all
types are computed fresh on every command invocation from local config
files already read by existing `etherfence_inventory::discover`.
