# Phase 1 Data Model: MCP Server Trust and Integrity Assessment

All new types are Rust types added to `crates/etherfence-setup` (feature-specific logic) and reuse `etherfence_core::Severity` unchanged (see research.md Decision 3). All follow the existing `#[derive(Debug, Clone, Serialize)]` / `#[serde(rename_all = "kebab-case")]` (enums) or `#[serde(rename_all = "camelCase")]` (structs) conventions already used by `CapabilityLabel`/`ClassifiedCapabilities`/`StarterPolicyRecommendation`.

## ArtifactIdentityConfidence (new)

```text
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactIdentityConfidence {
    VerifiedLocal,
    KnownSource,
    Unknown,
}
```

- `VerifiedLocal`: a specific local regular file was inspected and SHA-256 hashed under the conditions in research.md Decisions 8–10 (never implies safety).
- `KnownSource`: an exact curated identity match (research.md Decision 14) against the package identity or executable name (never implies authenticity/provenance/safety).
- `Unknown`: neither of the above — including, for remote servers, "not applicable" (see FR-057c: reported as `Unknown` with rationale text stating no local invocation exists).

## ConfigurationRiskStatus (new)

```text
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigurationRiskStatus {
    NoKnownIndicators,
    NeedsReview,
    HighRisk,
}
```

Derived from the raised `TrustIndicator` set for a server: `HighRisk` if any indicator has `Severity::High`; else `NeedsReview` if any indicator exists at all; else `NoKnownIndicators`.

## AggregateAssessmentStatus (new)

```text
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AggregateAssessmentStatus {
    VerifiedLocal,
    KnownSource,
    NeedsReview,
    HighRisk,
    Unknown,
}
```

Derived by `aggregate(artifact, risk)` (research.md Decision 7 / spec FR-061): `risk == HighRisk` → `HighRisk`; else `risk == NeedsReview` → `NeedsReview`; else → `artifact` value directly (`VerifiedLocal`/`KnownSource`/`Unknown`).

## PackageRunner (new)

```text
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PackageRunner { Npx, Uvx, PipxRun }
```

## VersionExpressionKind (new)

```text
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum VersionExpressionKind {
    ExactlyPinned,
    Omitted,
    MutableTag,
    VersionRange,
    UnsupportedOrAmbiguous,
}
```

Classification rules per runner are in research.md Decision 4. `human_label()` provides friendlier phrasing for rationale text (e.g. "mutable tag" vs. the JSON token `mutable-tag`), mirroring `CapabilityLabel`'s split.

## ShellWrapperKind (new)

```text
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ShellWrapperKind {
    ShC, BashC, CmdC,
    PowershellCommand, PowershellEncodedCommand,
    PwshCommand, PwshEncodedCommand,
}
```

One variant per FR-021 form. Detection rule in research.md Decision 5.

## ObscuredLaunchPattern (new)

```text
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObscuredLaunchPattern {
    PipeToShellDownloader,
    EncodedPowerShellOption,
    WindowsCertutilDownloadPattern,
    PowerShellWebRequestToInvokeExpression,
    DecodeThenExecutePipedToShell,
}
```

Exactly 5 variants (research.md Decision 5 explains why FR-026 and FR-028(a) collapse into `PipeToShellDownloader` rather than shipping 6).

## ExecutablePathClassification (new)

```text
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutablePathClassification {
    AbsolutePath,
    RelativePath,
    PathResolvedCommand,
    MissingPath,
    NonRegularFile,
    Symlink,
    TemporaryDirectoryLocation,
    AmbiguousOrUnsupported,
    NotApplicable,
}
```

`TemporaryDirectoryLocation` is reported *in addition to* `AbsolutePath`/`RelativePath` via a dedicated `TrustIndicator` (research.md Decision 8/10) — the enum value itself represents the single primary classification, and temp-directory-ness is evidence on an indicator, not a mutually exclusive enum arm, avoiding a combinatorial explosion of variants. `NotApplicable` is used only for remote/URL-configured servers (FR-057b).

## InvocationAssessment (new)

```text
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvocationAssessment {
    pub applicable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runner: Option<PackageRunner>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_identity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_expression: Option<VersionExpressionKind>,
    pub malformed_runner_invocation: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shell_wrapper: Option<ShellWrapperKind>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub obscured_launch_patterns: Vec<ObscuredLaunchPattern>,
}
```

`applicable = false` only for remote servers (FR-057b); every other field is then omitted/default. For a stdio server with a direct (non-runner, non-wrapper) executable, `applicable = true` but `runner`/`shell_wrapper` are both `None` and `obscured_launch_patterns` is empty — a fully "clean" invocation, distinct from "not applicable."

## EvidenceKey / EvidenceField (new)

```text
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceKey {
    Runner, PackageIdentity, VersionExpression, WrapperType,
    ObscuredLaunchPattern, OptionName, PathClassification,
    EnvironmentVariableName, UnicodeCategory, CuratedRuleId,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceField {
    pub key: EvidenceKey,
    pub value: String,
}
```

`value` is always a safe structured token (research.md Decision 6) — never a raw command line, environment value, or file content.

## TrustIndicator (new)

```text
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustIndicator {
    pub id: String,                 // stable, e.g. "EF-TRUST-PIN-001"
    pub severity: etherfence_core::Severity,   // reused, not reinvented
    pub category: IndicatorCategory,
    pub summary: String,
    pub rationale: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<EvidenceField>,
    pub remediation: String,
}
```

## IndicatorCategory (new)

```text
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum IndicatorCategory {
    ObscuredLaunch,
    ShellWrapper,
    PackagePinning,
    ExecutablePath,
    LocalArtifact,
    UnicodeIdentity,
    EnvironmentVariable,
}
```

`IndicatorCategory::ALL` fixes canonical order for FR-067 (research.md Decision 13).

## TrustAssessment (new — the field added to `SetupServer`)

```text
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustAssessment {
    pub artifact_identity: ArtifactIdentityConfidence,
    pub configuration_risk: ConfigurationRiskStatus,
    pub aggregate: AggregateAssessmentStatus,
    pub needs_review: bool,
    pub invocation: InvocationAssessment,
    pub executable_path: ExecutablePathClassification,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default)]
    pub indicators: Vec<TrustIndicator>,   // NOT skip_serializing_if — always present, `[]` when empty (FR-068)
}
```

**Validation rules**:
- `sha256.is_some()` implies `artifact_identity == VerifiedLocal`; the converse is not required (a server could theoretically be `VerifiedLocal` only via the hash — in practice `sha256` is the *only* mechanism that produces `VerifiedLocal` in v1.3.0, so in effect they are equivalent, but the field is not derived *from* the enum to keep the two independently testable).
- `indicators` sorted per research.md Decision 13; never reordered downstream.
- `needs_review == (aggregate ∈ {NeedsReview, HighRisk, Unknown})` (FR-062), enforced by construction via `needs_review(aggregate)`.
- For a remote server (`invocation.applicable == false`): `executable_path == NotApplicable`, `sha256 == None`, `artifact_identity == Unknown`; `configuration_risk`/`aggregate`/`needs_review`/`indicators` are still fully populated from environment-variable and Unicode/identity-ambiguity checks only (FR-057a/FR-057d).

## SetupServer (extended, existing struct)

```text
pub struct SetupServer {
    pub name: String,
    pub transport: ServerTransport,
    pub wrapped: bool,
    pub capabilities: ClassifiedCapabilities,          // v1.2.0, unchanged
    pub recommendation: StarterPolicyRecommendation,    // v1.2.0, unchanged
    pub trust_assessment: TrustAssessment,              // NEW (v1.3.0)
}
```

Additive-only, populated inside `server_from_mcp` alongside the existing `classify_server`/`recommend` calls (research.md Decision 1). `setup plan`/`setup doctor` rendering reads only the fields it already reads — unchanged output (FR-004).

## Curated tables (new, checked-in constant data in the trust module)

- **`KNOWN_SOURCE_IDENTITIES`**: the 3 package identities already curated in v1.2.0's `EVIDENCE_RULES` (research.md Decision 14) — no new identities in v1.3.0.
- **`CONFUSABLE_ALIASES`**: exactly 1 curated alias entry in v1.3.0 (research.md Decision 14), mapping one exact confusable string to the known identity it impersonates.
- **`MUTABLE_NPM_TAGS`**: `latest`, `next`, `beta`, `alpha`, `canary`, `rc` (research.md Decision 4).
- **`ENV_RISK_CATEGORIES`**: 5 fixed name-pattern lists, one per FR-053 category (research.md Decision 12).

## Relationships

```text
McpServer (existing, etherfence-core)
   --(runner/wrapper/obscured-launch parsing)-->  InvocationAssessment
   --(path classification + eligible hashing)-->  ExecutablePathClassification, sha256
   --(env var name matching)-->                   TrustIndicator[] (EnvironmentVariable category)
   --(server/package identity string)-->          TrustIndicator[] (UnicodeIdentity category, via etherfence_mcp::unicode reuse)

InvocationAssessment + ExecutablePathClassification + sha256 + curated tables
   --(assess_artifact_identity)-->  ArtifactIdentityConfidence

All raised TrustIndicator
   --(configuration_risk)-->  ConfigurationRiskStatus

ArtifactIdentityConfidence + ConfigurationRiskStatus
   --(aggregate, FR-061)-->  AggregateAssessmentStatus
   --(needs_review, FR-062)-->  bool

SetupServer.trust_assessment: TrustAssessment   // all of the above, assembled
```

No entity in this feature is persisted (no database, no state file); everything is computed fresh on every invocation from local config already read by `etherfence_inventory::discover`, plus, for eligible executable paths, a bounded local file read (research.md Decisions 8–10).
