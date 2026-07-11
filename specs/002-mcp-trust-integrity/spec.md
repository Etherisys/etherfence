# Feature Specification: MCP Server Trust and Integrity Assessment

**Feature Branch**: `002-mcp-trust-integrity`

**Created**: 2026-07-11

**Status**: Draft

**Input**: User description: "EtherFence v1.3.0: MCP Server Trust and Integrity Assessment — build on v1.2.0's static MCP server capability classification by assessing concrete launch, identity, package, environment, and local-artifact risk indicators for each discovered MCP server, surfaced as a structured, explainable, deterministic trust-and-integrity assessment inside `etherfence setup detect`. Must remain read-only, local-first, deterministic, fixture-backed, and honest about its limits; must never claim a server is proven safe, trusted, certified, malware-free, benign, or definitively malicious."

## Clarifications

### Session 2026-07-11

- Q1: When a server's Artifact Identity Confidence and Configuration Risk Indicators point in different directions (for example, a locally hashed/verified executable that also carries a high-risk configuration indicator, or a curated known-source package identity launched through a risky shell wrapper), how should the single Aggregate Assessment Status be derived? → A: Configuration-risk-first — `high-risk` Configuration Risk always yields `high-risk` Aggregate; `needs-review` Configuration Risk always yields `needs-review` Aggregate; only when Configuration Risk is `no-known-indicators` does Artifact Identity Confidence (`verified-local` / `known-source` / `unknown`) determine the Aggregate value. Artifact Identity Confidence is never hidden by this rule — it remains separately reported per FR-006/FR-058 regardless of what the Aggregate shows.
- Q2: Beyond "obvious pipe-to-shell composition" and "encoded PowerShell launch options," what is the complete, closed set of obscured/download-and-execute launch indicators in scope for v1.3.0? → A: Add a small, explicitly named set now: (1) a recognized Unix downloader (`curl`/`wget`) writing to standard output composed via a shell pipe into a recognized shell interpreter; (2) a Windows `certutil` invocation using a recognized download-cache flag in a known download-and-execute pattern; (3) a PowerShell/`pwsh` invocation piping `Invoke-WebRequest`/`iwr`/`Invoke-RestMethod`/`irm` into `Invoke-Expression`/`iex` within the same command string; (4) a recognized base64-decode utility composed via a shell pipe into a recognized shell interpreter. This is a closed, fixed list for v1.3.0 (see FR-028); extending it requires a future specification change.
- Q3: Do remote (URL-configured, non-stdio) MCP servers receive any trust-and-integrity assessment in v1.3.0, and if so, which parts of it? → A: Yes, partially. Environment-variable assessment and Unicode/identity-ambiguity assessment (applied to the server name) still run for remote servers. Invocation Identity/Form, Executable Path Classification, and Local Artifact inspection are explicitly not applicable to remote servers and are reported as such, not silently omitted or reported as `unknown`-by-failure (see new "Remote (non-stdio) server scope" requirements below).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Judge package-runner invocation risk before trusting a server (Priority: P1)

An operator has one or more MCP servers configured that are launched through a package runner such as `npx`, `uvx`, or `pipx run`. Before deciding whether to trust or wrap a server, the operator wants to know, for each one: what package identity is being launched, whether the version is exactly pinned or could silently change on the next run (a mutable tag like `latest`, an omitted version, or a version range), and whether the invocation itself is well-formed enough for EtherFence to have understood it at all — all derived from already-read local configuration, with no package registry contacted and no package ever installed or executed.

**Why this priority**: This is the highest-value, most common real-world MCP server shape (most fixture-verified example servers in this repository are already `npx`-launched), and version-pinning ambiguity is one of the most concrete, explainable, and actionable trust signals an operator can act on immediately (pin the version, or don't run it).

**Independent Test**: Run the assessment against fixture MCP server configurations built to cover each supported runner (`npx`, `uvx`, `pipx run`) crossed with each version-expression shape (exact version, omitted version, mutable tag, version range, malformed/unsupported expression), and verify the exact expected package-identity, version-expression, and indicator output for each fixture — independent of any other assessment area.

**Acceptance Scenarios**:

1. **Given** an MCP server launched via a supported runner with an exactly pinned package version, **When** `etherfence setup detect` runs, **Then** the server's assessment records the parsed package identity and version, and does not raise a version-pinning risk indicator for that server.
2. **Given** an MCP server launched via a supported runner with the version omitted or expressed as a mutable tag (such as `latest`) or a version range, **When** the assessment runs, **Then** it raises a version-pinning risk indicator naming the specific unpinned form observed, without contacting any package registry.
3. **Given** an MCP server whose runner invocation does not match any recognized supported-runner shape at all, **When** the assessment runs, **Then** it is reported as an unrecognized/malformed runner invocation rather than silently treated as pinned, unpinned, or omitted from output.
4. **Given** the same fixture configuration, **When** the assessment is run twice in a row, or once each on a Linux-shaped and an equivalent Windows-shaped fixture, **Then** both runs produce identical package-identity, version-expression, and indicator output.

---

### User Story 2 - Judge shell-wrapper and obscured-launch risk before trusting a server (Priority: P1)

An operator has one or more MCP servers configured whose launch command routes through a shell interpreter (`sh -c`, `bash -c`, `cmd.exe /c`, `powershell -Command`/`-EncodedCommand`, `pwsh -Command`/`-EncodedCommand`) rather than launching a tool directly. The operator wants EtherFence to flag that indirection, and to flag a narrow set of specifically defined obscured-launch patterns (such as an obvious pipe-to-shell composition or an encoded PowerShell command), without EtherFence attempting to fully parse, decode, or execute the wrapped command.

**Why this priority**: Shell-wrapper indirection is a concrete, well-understood way a launch command can obscure what actually executes, and it is directly actionable (an operator can decide the added indirection isn't worth the risk) using only static string-shape inspection — no execution or decoding required.

**Independent Test**: Run the assessment against fixture MCP server configurations covering each supported wrapper form (positive cases), non-wrapper commands that must not be misclassified as wrappers (negative cases), malformed/ambiguous wrapper-like commands, and the boundary between "recognized obscured-launch pattern" and "not recognized" — verify the exact expected wrapper-type and indicator output for each.

**Acceptance Scenarios**:

1. **Given** an MCP server launched through a recognized shell-wrapper form, **When** the assessment runs, **Then** it records the wrapper type as structured evidence and raises a shell-wrapper risk indicator, without attempting to parse or evaluate the wrapped command text itself.
2. **Given** an MCP server launched directly (no shell wrapper), **When** the assessment runs, **Then** no shell-wrapper indicator is raised for that server.
3. **Given** an MCP server launch matching one of the explicitly enumerated obscured-launch patterns, **When** the assessment runs, **Then** it raises a distinctly named obscured-launch indicator, separate from the general shell-wrapper indicator.
4. **Given** an MCP server launch that superficially resembles a wrapper or obscured-launch pattern but does not exactly match any documented rule, **When** the assessment runs, **Then** it is not misreported as matching that rule; at most it may contribute to a generic unrecognized-invocation signal.

---

### User Story 3 - Get one clear, non-conflated trust-and-integrity picture per server (Priority: P1)

An operator viewing `etherfence setup detect` output for a server wants a single place that shows, without being reduced to one boolean: what EtherFence could establish about the identity of the thing being launched (a locally hashed executable file, a curated known package/source identity, or neither), separately from what configuration risk indicators were raised (pinning, wrappers, obscured launches, risky paths, risky environment variables, identity-ambiguous characters), and a combined, explainable bottom line that never overstates confidence and never implies a safe/trusted/certified guarantee.

**Why this priority**: This is the structural promise of the whole feature — every other user story only has value if its output is presented honestly, without conflating "we could identify this artifact" with "this artifact's configuration is safe." Getting this separation right is a P1 prerequisite for every other story being trustworthy.

**Independent Test**: Feed a set of already-classified fixture servers through the assessment step, including at least one server that has strong artifact identity confidence but also high-risk configuration indicators, and one server with a curated known-source package identity that is also launched through a risky wrapper — verify that identity confidence and configuration risk are reported as distinct fields that do not silently overwrite or hide one another, and that the resulting aggregate status and rationale are internally consistent with both underlying fields.

**Acceptance Scenarios**:

1. **Given** a server whose local executable was successfully hashed (verified-local artifact identity) but which also carries at least one high-risk configuration indicator, **When** the assessment runs, **Then** the output shows both the verified-local artifact identity and the high-risk configuration indicator(s) side by side, the Aggregate Assessment status is `high-risk` (per the configuration-risk-first precedence rule), and the human- and machine-readable rationale explicitly names both facts rather than presenting only the Aggregate value.
2. **Given** a server matching a curated known package/source identity but launched through a risky wrapper or with an unpinned version, **When** the assessment runs, **Then** the known-source identity match and the configuration risk indicator(s) are both reported, and neither field is dropped in favor of the other.
3. **Given** any assessed server, **When** its output is inspected, **Then** there is no single boolean field anywhere in the output (human or JSON) that purports to answer "is this server safe/trusted/malicious" on its own.
4. **Given** any assessed server, **When** its aggregate assessment and needs-review flag are inspected, **Then** they are derived by a single, fixed, documented rule from the server's artifact identity confidence and configuration risk indicators, so that identical underlying facts always yield an identical aggregate result.

---

### User Story 4 - See risky environment-variable exposure without ever seeing values (Priority: P2)

An operator has an MCP server configured with environment variables whose *names* suggest elevated risk (for example, names associated with dynamic loader injection, interpreter/runtime path overrides, package-registry overrides, TLS verification disabling, or secret-like naming patterns exposed to a server EtherFence could not otherwise identify). The operator wants these flagged by name-based category, with an absolute guarantee that no environment variable *value* — secret or otherwise — ever appears anywhere in EtherFence's output.

**Why this priority**: Environment-variable name inspection is cheap, deterministic, and already partially precedented by v1.2.0/v0.1.x env-name posture checks, but it is P2 rather than P1 because it is additive risk signal rather than the core invocation/identity story this release is primarily about.

**Independent Test**: Run the assessment against fixture servers with environment variable names covering each documented risk category, plus ordinary/benign variable names, plus secret-like names — verify the exact expected category indicators fire, and verify by direct inspection of all produced output (human text, JSON, evidence, rationale, error paths) that no configured environment variable *value* ever appears, even when the underlying fixture sets a non-empty value.

**Acceptance Scenarios**:

1. **Given** a server with an environment variable name matching a documented risk category, **When** the assessment runs, **Then** a category-specific indicator is raised whose evidence names only the variable name, never its value.
2. **Given** a server with an environment variable that has a secret-like name and belongs to a server whose overall identity is `unknown` or otherwise high-risk, **When** the assessment runs, **Then** a secret-exposure-style indicator is raised reflecting that combination.
3. **Given** any assessed server with any environment variables configured, **When** all human and JSON output is inspected, **Then** no environment variable value appears anywhere, including in error messages, evidence strings, or rationale text.
4. **Given** a remote (URL-configured, non-stdio) server with an environment variable name matching a documented risk category, **When** the assessment runs, **Then** the same category indicator fires as it would for a stdio server, even though that server's Invocation Identity/Form, Executable Path Classification, and Local Artifact inspection are all reported as not applicable.

---

### User Story 5 - Detect identity-ambiguous or spoofed-looking server/package names (Priority: P2)

An operator wants to be warned when a configured server or package identity contains characters that could visually or structurally impersonate a trusted identity — bidirectional-control characters, invisible/default-ignorable characters, a reliably-mixed script within a single identity, or an exact match against a small curated list of known confusable aliases for well-known server/package names — without EtherFence claiming to catch every possible spoofing technique.

**Why this priority**: Identity-spoofing indicators are a narrow but high-value defensive signal precedented by EtherFence's existing MCP proxy Unicode/homograph hardening; it is P2 because it is a comparatively rare configuration shape relative to the P1 stories.

**Independent Test**: Run the assessment against fixture server/package identities containing bidi control characters, invisible characters, a defined mixed-script case, and an exact curated confusable alias, plus clean ASCII identities as negative controls — verify the exact expected indicator fires for each positive fixture and that no indicator fires for the negative controls.

**Acceptance Scenarios**:

1. **Given** a server or package identity containing a bidirectional control character, **When** the assessment runs, **Then** a bidi-control indicator is raised naming that category, without echoing the raw suspicious identity string in a way that could itself be visually confusing.
2. **Given** a server or package identity that exactly matches a curated confusable alias for a known identity, **When** the assessment runs, **Then** an identity-confusable indicator is raised citing the curated rule that matched.
3. **Given** an ordinary ASCII server or package identity with no curated confusable relationship to anything, **When** the assessment runs, **Then** no Unicode/identity-ambiguity indicator is raised for it.
4. **Given** a remote (URL-configured, non-stdio) server whose name contains a bidirectional control character or matches a curated confusable alias, **When** the assessment runs, **Then** the same indicator fires as it would for a stdio server's package/server identity, even though that server's invocation-based assessment areas are reported as not applicable.

---

### Edge Cases

- What happens when an MCP server has no command at all (a remote/URL-configured server)? Per Clarification Q3 (see "Remote (non-stdio) server scope"), Invocation Identity/Form, Executable Path Classification, and Local Artifact inspection are reported as explicitly not applicable rather than fabricated or silently omitted; environment-variable and Unicode/identity-ambiguity checks still run against the server's name and configured environment variables.
- What happens when a server's executable path does not exist on disk at assessment time? It must be reported as a missing-path indicator, not silently skipped and not misreported as verified.
- What happens when a configured executable path resolves to a non-regular file (a directory, device, FIFO, or similar)? It must be reported as a non-regular-path indicator and must never be read for hashing.
- What happens when a configured executable path is a symlink? The assessment must represent the symlink explicitly (as its own path classification) rather than silently resolving through it and reporting the symlink target as if it were the configured path.
- What happens when a configured executable path points into a temporary-directory location? It must be reported as a distinct path-classification indicator.
- What happens when a locally referenced executable file is larger than the defined hashing size limit? It must degrade to a documented "hashing-ineligible" outcome (not `verified-local`), not attempt an unbounded read.
- What happens when the file at a configured path changes (or its identity becomes ambiguous, such as being replaced) between the time its metadata is read and the time it is hashed? The assessment must not report `verified-local` for that read; it must degrade conservatively.
- What happens when a server's command is a bare or PATH-resolved name (no path separator at all)? It must never be silently promoted to a verified local artifact; PATH resolution itself must not be performed as part of establishing artifact identity.
- What happens when a server matches a curated known package/source identity but is also launched through a risky wrapper, has an unpinned version, or carries other high-risk configuration indicators? Both the known-source identity and every applicable configuration risk indicator must be reported; the presence of one must never suppress or override the other (see User Story 3).
- What happens when a server triggers multiple simultaneous indicators across different assessment areas (for example, an unpinned package, a shell wrapper, and a risky environment variable name, all on the same server)? All applicable indicators must be reported in the same deterministic order, none dropped or coalesced into a single generic indicator.
- What happens when a server's configuration is malformed or unreadable (already degraded upstream by existing v1.2.0/v0.1.x parsing)? The already-established "degrade to unknown, never crash" behavior must extend to this feature's assessment, not regress it.
- What happens when path casing or separator conventions differ between an equivalent Linux and Windows fixture? Assessment output (indicators, classifications, ordering) must be identical once platform-specific path spelling is normalized for comparison, matching the v1.2.0 precedent.
- What happens when an environment variable name matches more than one documented risk category at once? Every matching category must be represented; none may be silently dropped in favor of another.
- What happens when a package-runner invocation uses a recognized runner name but an unsupported or ambiguous version-expression syntax that isn't cleanly "omitted," "mutable tag," or "range"? It must be reported as its own distinct unsupported/ambiguous-expression indicator rather than forced into one of the other categories.

## Requirements *(mandatory)*

### Functional Requirements

**Integration with existing `setup detect` output**

- **FR-001**: The system MUST attach a structured trust-and-integrity assessment to every MCP server entry already produced by `etherfence setup detect`, for both human-readable and JSON output formats.
- **FR-002**: The trust-and-integrity assessment MUST be presented alongside, and MUST NOT replace, remove, or change the meaning of, each server's existing v1.2.0 capability classification (`capabilities`) and starter-policy recommendation (`recommendation`) fields.
- **FR-003**: `etherfence setup catalog`, `etherfence scan`, `etherfence setup plan`, `etherfence setup apply`, `etherfence setup rollback`, `etherfence mcp-policy`, and `etherfence mcp-proxy` output and behavior MUST be unaffected by this feature; only `etherfence setup detect` output changes.
- **FR-004**: `etherfence setup doctor` human output MUST remain unchanged unless this specification (after clarification) explicitly requires a change; no change is currently in scope.
- **FR-005**: The trust-and-integrity assessment MUST be computed using only already-read local configuration data (the same data already available to v1.2.0 classification) plus, where explicitly permitted below, bounded local filesystem metadata/content reads of a directly configured executable path — no other new input source is introduced.

**Conceptual separation**

- **FR-006**: The system MUST report Artifact Identity Confidence as a value distinct from, and never overwritten by, Configuration Risk Indicators for the same server.
- **FR-007**: The system MUST report Configuration Risk Indicators as a value distinct from, and never overwritten by, Artifact Identity Confidence for the same server.
- **FR-008**: The system MUST report a distinct Aggregate Assessment value derived from, but not identical in meaning to, either Artifact Identity Confidence or Configuration Risk Indicators alone.
- **FR-009**: The system MUST report a distinct needs-review boolean (or equivalent) indicating whether manual review is warranted, computed from a single documented rule.
- **FR-010**: The system MUST NOT expose any single boolean field (such as an `is_safe`, `is_trusted`, or `is_malicious`-shaped field) anywhere in human or JSON output as the sole representation of a server's trustworthiness.

**Package-runner invocation assessment**

- **FR-011**: The system MUST statically parse the configured command and arguments of a server launched via a supported package runner (`npx`, `uvx`, `pipx run`) to identify, where parseable: the package identity, and the version expression (if any) associated with that package identity.
- **FR-012**: A version expression MUST be classified into exactly one of: exactly pinned, omitted, mutable tag, version range, or unsupported/ambiguous expression.
- **FR-013**: "Exactly pinned" for an `npx`-style invocation MUST mean the package argument specifies a single, fully-resolved version identifier with no range operators, no wildcard/partial version, and not a known mutable tag name (such as `latest`, `next`, or similar reserved dist-tag conventions); scoped packages (`@scope/name@version`) MUST be supported using the same rule.
- **FR-014**: "Exactly pinned" for a `uvx`-style invocation MUST mean the package argument specifies a single exact version identifier with no range operators and no mutable extra/tag qualifier that leaves the resolved version ambiguous.
- **FR-015**: "Exactly pinned" for a `pipx run`-style invocation MUST mean the package argument specifies a single exact version identifier with no range operators and no mutable qualifier that leaves the resolved version ambiguous.
- **FR-016**: An omitted version (a package identity given with no version qualifier at all) MUST be classified as omitted, not as pinned and not as an error.
- **FR-017**: A recognized mutable tag (such as `latest`) MUST be classified as a mutable tag, distinct from an omitted version, even though both leave the resolved version non-deterministic.
- **FR-018**: A version expression using a range/comparator syntax (for example, prefix/caret/tilde ranges or explicit comparator operators) MUST be classified as a version range, distinct from a mutable tag.
- **FR-019**: A runner invocation that does not match any recognized supported-runner shape (unrecognized launcher name, or a recognized launcher name with an argument shape the system cannot parse into a package identity at all) MUST be classified as an unrecognized/malformed runner invocation, and MUST NOT be silently treated as any of the pinned/omitted/tag/range categories.
- **FR-020**: Package-runner assessment MUST NOT require, perform, or simulate package registry access, package installation, package dependency resolution, or package execution of any kind.

**Shell-wrapper invocation assessment**

- **FR-021**: The system MUST statically recognize, by exact structural pattern, at minimum the following wrapper forms when they are the configured launch command: `sh -c`, `bash -c`, `cmd.exe /c`, `powershell -Command`, `powershell -EncodedCommand`, `pwsh -Command`, `pwsh -EncodedCommand`.
- **FR-022**: A recognized shell-wrapper invocation MUST produce a shell-wrapper risk indicator whose structured evidence names the wrapper type, without including the full wrapped command text as raw evidence.
- **FR-023**: The system MUST NOT implement a general-purpose shell command-line parser, MUST NOT execute or simulate execution of any wrapped command, and MUST NOT expand shell variables or otherwise interpret shell semantics beyond recognizing the bounded set of wrapper forms in FR-021.
- **FR-024**: A launch command that does not match any recognized wrapper form MUST NOT raise a shell-wrapper indicator.
- **FR-025**: An `-EncodedCommand` (or equivalent encoded-option) invocation MUST be recognized as its own distinct evidence detail (an encoded-launch-option indicator) separate from the general shell-wrapper indicator for that same command, without the system decoding the encoded payload.

**Obscured/download-and-execute launch indicators**

- **FR-026**: The system MUST detect an "obvious pipe-to-shell composition" pattern (a narrowly and explicitly defined static structural pattern, finalized during clarification) as a distinct indicator from the general shell-wrapper indicator.
- **FR-027**: The system MUST detect an encoded PowerShell launch option (`-EncodedCommand` or equivalent) as a distinct obscured-launch indicator (see FR-025), without decoding the encoded content.
- **FR-028**: In addition to FR-026/FR-027, the system MUST detect the following fixed, closed set of additional obscured-launch patterns, each as its own distinct indicator, using only static structural matching:
  - **(a) Unix downloader piped to shell**: a recognized downloader (`curl` or `wget`) invoked with arguments that write to standard output (for example, `curl` without a file-writing output flag, or `wget -O -`/`wget -O-`) composed via a shell pipe into a recognized shell interpreter (`sh`, `bash`, or an equivalent recognized POSIX shell).
  - **(b) Windows `certutil` download pattern**: a `certutil` invocation containing a recognized download-cache flag (for example `-urlcache`) used in a documented download-and-execute argument shape.
  - **(c) PowerShell download-and-execute pattern**: a `powershell`/`pwsh` invocation whose `-Command` argument string contains a recognized web-request cmdlet or alias (`Invoke-WebRequest`, `iwr`, `Invoke-RestMethod`, `irm`) piped into a recognized expression-execution cmdlet or alias (`Invoke-Expression`, `iex`) within that same command string.
  - **(d) Decode-then-execute pattern**: a recognized base64-decode utility invocation (for example `base64 -d`, `base64 --decode`, or `certutil -decode`) composed via a shell pipe into a recognized shell interpreter; this is distinct from, and does not overlap with, the PowerShell `-EncodedCommand` indicator in FR-025/FR-027.

  This is a fixed, closed list for v1.3.0. No other pipe/download/decode composition is detected in this release; extending this list requires a future specification change, not a silent addition.
- **FR-029**: Obscured-launch detection MUST NOT require arbitrary decoding, command emulation, recursive interpretation of nested commands, or any form of behavioral analysis; every implemented rule (FR-026, FR-027, FR-028a–d) MUST be a bounded, static, structural pattern match.

**Executable-path assessment**

- **FR-030**: The system MUST classify a server's statically configured executable identity into exactly one of: direct absolute path, relative path, bare/PATH-resolved command, missing path, non-regular file, symlink, temporary-directory location, or ambiguous/unsupported path form.
- **FR-031**: A relative path or a bare/PATH-resolved command MUST NOT, by itself, be treated as, or promoted to, a verified local artifact; PATH resolution MUST NOT be performed to locate or read a file on behalf of establishing artifact identity.
- **FR-032**: A configured path that does not exist on disk at assessment time MUST be classified as missing, and MUST NOT be eligible for local artifact inspection.
- **FR-033**: A configured path that resolves to something other than a regular file (directory, device file, FIFO, socket, or similar) MUST be classified as non-regular, and MUST NOT be eligible for local artifact inspection.
- **FR-034**: A configured path that is a symlink MUST be classified explicitly as a symlink (a distinct path classification), and its treatment for local artifact inspection MUST be governed by the same eligibility rules as any other path classification — a symlink MUST NOT be silently followed and then reported as though the configured path itself were a verified regular file without that fact being recorded.
- **FR-035**: A configured path located under a recognized temporary-directory location MUST be classified as a distinct temporary-directory-location indicator in addition to (not instead of) its underlying path-form classification.
- **FR-036**: Path classification MUST be computed using only local filesystem metadata already available to a conservative, bounded local inspection — no network access and no execution of the path.

**Local artifact inspection**

- **FR-037**: For a directly referenced executable path classified as an eligible regular file (per FR-032–FR-034), the system MUST support computing and recording a SHA-256 identity for that file as part of establishing Artifact Identity Confidence.
- **FR-038**: Only an eligible regular file, verified as such immediately before the read used to compute its identity, MAY receive a `verified-local` artifact identity outcome.
- **FR-039**: File reads performed to compute a local artifact identity MUST be bounded by, or safely streamed under, an explicit, documented size limit; a file exceeding that limit MUST NOT be read in full and MUST NOT receive a `verified-local` outcome.
- **FR-040**: Local artifact inspection MUST support binary executable files without requiring UTF-8 decoding or any text interpretation of file contents.
- **FR-041**: File contents (or any excerpt of them) MUST NEVER appear in any human or JSON output, evidence, log, or diagnostic produced by this feature.
- **FR-042**: If file metadata observed immediately before and immediately after the read used to compute a file's identity is inconsistent (indicating the file may have changed or been replaced during inspection), the assessment MUST NOT report `verified-local` for that read.
- **FR-043**: Symlink handling during local artifact inspection MUST be explicit and documented (whether a symlink is ever eligible for inspection, and if so, exactly what is inspected) — silent, undocumented symlink-following behavior is prohibited.
- **FR-044**: Any failure during local artifact inspection (permission error, I/O error, metadata ambiguity, oversized file, non-regular file, missing file) MUST degrade conservatively to a `needs-review` or `unknown` outcome for that server's artifact identity — it MUST NEVER be treated as equivalent to a successful `verified-local` outcome.
- **FR-045**: Local artifact inspection MUST NOT execute, load, map for execution, or otherwise run the inspected file.

**Unicode and identity ambiguity**

- **FR-046**: The system MUST detect bidirectional control characters in a server's package/server identity strings and raise a distinct bidi-control indicator when found, consistent with EtherFence's existing MCP proxy Unicode-hygiene precedent (detection without confusable-folding or normalization).
- **FR-047**: The system MUST detect invisible or default-ignorable characters in a server's package/server identity strings and raise a distinct invisible-character indicator when found.
- **FR-048**: The system MUST detect a reliably-defined mixed-script condition within a single identity string and raise a distinct mixed-script indicator when found, using only a narrowly and explicitly documented definition of "reliably defined" (no broad linguistic/script-detection heuristic).
- **FR-049**: The system MUST support a small, checked-in, curated table of exact confusable aliases for known server/package identities, and MUST raise a distinct identity-confusable indicator only on an exact match against that table.
- **FR-050**: The system MUST NOT implement or claim a universal Unicode confusable-detection engine and MUST NOT implement or claim a universal typosquatting detector; detection is limited to FR-046–FR-049.
- **FR-051**: When a Unicode/identity-ambiguity indicator fires, its evidence MUST describe the category of the finding (for example, which code point range or which curated rule matched) without reproducing the raw suspicious identity string in a way that itself could visually mislead a reader.

**Environment-variable assessment**

- **FR-052**: The system MUST inspect only environment-variable *names* configured for a server, never values, when producing environment-related indicators.
- **FR-053**: The system MUST recognize, by exact or documented deterministic name-matching rules, at minimum these environment-variable risk categories: dynamic loader injection variables, interpreter/runtime path override variables, package-registry override variables, TLS-verification-disabling variables, and secret-like variable names.
- **FR-054**: A secret-like environment-variable name MUST additionally be evaluated in combination with that server's overall identity/risk state, and MUST raise a distinct, more specific indicator when the server is `unknown` or otherwise classified as high-risk.
- **FR-055**: Environment-variable evidence MUST contain only the normalized variable name, never the configured value, regardless of whether the value is present, empty, or absent.
- **FR-056**: An environment-variable name matching more than one documented risk category MUST raise an indicator for every matching category; none may be dropped in favor of another.
- **FR-057**: Environment-variable values MUST NEVER be emitted, logged, persisted, included in evidence, included in snapshots, included in error messages, or included in any other diagnostic output produced by this feature.

**Remote (non-stdio) server scope**

- **FR-057a**: For a server discovered with a remote/URL configuration and no local launch command (`ServerTransport::Remote`), Environment-Variable Assessment (FR-052–FR-057) and Unicode/Identity-Ambiguity Assessment (FR-046–FR-051, applied to the server's name) MUST still be performed.
- **FR-057b**: For such a server, Invocation Identity and Form (package-runner and shell-wrapper/obscured-launch assessment, FR-011–FR-029), Executable Path Classification (FR-030–FR-036), and Local Artifact inspection (FR-037–FR-045) MUST each be reported as explicitly not applicable, distinct from any value that would be reported for a stdio server that was assessed and yielded no findings — a remote server's assessment output MUST make clear these areas were skipped by design, not attempted and inconclusive.
- **FR-057c**: For such a server, Artifact Identity Confidence MUST be reported as `unknown`, with rationale text that explicitly states this reflects "no local invocation to assess" rather than a failed or inconclusive local inspection.
- **FR-057d**: Configuration Risk status and Aggregate Assessment status for a remote server MUST still be computed from whatever indicators FR-057a produces (environment-variable and Unicode/identity-ambiguity indicators only), using the same rules as any other server (FR-059, FR-061); a remote server with zero triggered indicators reports Configuration Risk status `no-known-indicators` and, per FR-061 rule 3, Aggregate Assessment status `unknown`.

**Assessment vocabulary and aggregation**

- **FR-058**: The system MUST report an Artifact Identity Confidence value for each server, using at minimum the values `verified-local`, `known-source`, and `unknown`, with `verified-local` meaning only that a specific local regular file was inspected and hashed under the conditions in FR-037–FR-045, and `known-source` meaning only an exact curated identity match per FR-049 (or an equivalent curated package/server identity table) — neither value may be described or documented as proving authenticity, provenance, installation integrity, or safety.
- **FR-059**: The system MUST report a Configuration Risk status for each server, using at minimum the values `no-known-indicators`, `needs-review`, and `high-risk`, where `no-known-indicators` MUST be documented as meaning only that no implemented v1.3.0 indicator triggered for that server, not as an absence-of-risk guarantee.
- **FR-060**: The system MUST report an Aggregate Assessment status for each server, using at minimum the values `verified-local`, `known-source`, `needs-review`, `high-risk`, and `unknown`.
- **FR-061**: Aggregate Assessment status MUST be derived from Artifact Identity Confidence and Configuration Risk status by the following fixed, configuration-risk-first precedence rule, applied in order:
  1. If Configuration Risk status is `high-risk`, Aggregate Assessment status MUST be `high-risk`, regardless of Artifact Identity Confidence.
  2. Otherwise, if Configuration Risk status is `needs-review`, Aggregate Assessment status MUST be `needs-review`, regardless of Artifact Identity Confidence.
  3. Otherwise (Configuration Risk status is `no-known-indicators`), Aggregate Assessment status MUST equal Artifact Identity Confidence directly (`verified-local`, `known-source`, or `unknown`).

  This rule ensures a raised configuration risk indicator is never hidden by a favorable artifact identity result, while a favorable artifact identity result is still visible in the Aggregate whenever no configuration risk indicator fired. Artifact Identity Confidence and Configuration Risk status MUST both continue to be reported in full alongside the Aggregate per FR-006/FR-007, regardless of which one determined the Aggregate value.
- **FR-062**: The needs-review boolean MUST be `true` whenever Aggregate Assessment status is `needs-review`, `high-risk`, or `unknown`, and MUST be `false` whenever Aggregate Assessment status is `verified-local` or `known-source` — a single rule derived directly from FR-061's output, such that identical underlying facts always yield an identical needs-review value.
- **FR-063**: Every occurrence of `known-source`, `verified-local`, and `no-known-indicators` in human-readable output MUST be accompanied by, or documented alongside, the exact limiting language specified in this feature's product context (no proof of authenticity/provenance/safety; no proof of absence of malicious behavior).

**Indicators**

- **FR-064**: Every reported indicator MUST include: a stable indicator ID, a severity, a category, a concise human-readable summary, a rationale, structured redacted evidence, and a remediation suggestion.
- **FR-065**: Indicator evidence MUST use structured fields (for example: runner, package identity, version expression, wrapper type, option name, path classification, environment-variable name) rather than an arbitrary raw configuration payload.
- **FR-066**: Indicator evidence MUST NEVER contain: environment-variable values, credentials, tokens, secrets, file contents, a complete sensitive command string, or an arbitrary raw configuration payload.
- **FR-067**: All indicators for a given server MUST be emitted in one fixed, documented, deterministic order (for example, a canonical category/severity order analogous to the existing v1.2.0 `CapabilityLabel` canonical-order precedent), independent of the order in which the underlying rules happened to match.
- **FR-068**: A server that triggers zero indicators MUST still report a complete, well-formed assessment (Artifact Identity Confidence, Configuration Risk status, Aggregate Assessment, needs-review) with an empty indicator list — indicators are additive evidence, not a substitute for the base assessment fields.

**Policy relationship**

- **FR-069**: The existing v1.2.0 deny-by-default starter-policy recommendation behavior MUST remain unchanged: `recommendation.tier` MUST continue to be `deny` for every server in v1.3.0 output; this feature MUST NOT introduce any code path that produces an `allow` starter-policy recommendation.
- **FR-070**: No value or combination of values produced by this feature's trust-and-integrity assessment (including `verified-local`, `known-source`, or `no-known-indicators`) MUST be used, by itself or in combination, to change `recommendation.tier` away from `deny`.
- **FR-071**: A favorable trust-and-integrity assessment MAY be described in human-readable rationale as indicating the server is ready for manual review, but MUST NOT be described, implied, or rendered as granting, enabling, or recommending runtime permission.
- **FR-072**: This feature MUST NOT change `etherfence mcp-proxy` enforcement behavior, the `ef-mcp-policy/v0.1` schema or its enforcement semantics, `tools/list` filtering, `tools/call` enforcement, method policy, path policy, or audit-log behavior in any way.

**Machine-readable output**

- **FR-073**: `etherfence setup detect --format json` MUST evolve its schema version from `ef-setup-detect/v0.1` to a new, explicitly named version (expected `ef-setup-detect/v0.2` unless a later planning phase documents and justifies a different explicit version identifier); the version identifier change itself MUST be documented as reflecting an additive schema evolution, not a breaking change to existing v1.2.0 fields.
- **FR-074**: Every existing v1.2.0 JSON field under a server's `capabilities` and `recommendation` objects MUST retain its existing meaning, type, and serialization in v1.3.0 output.
- **FR-075**: Server ordering within `etherfence setup detect` JSON and human output MUST remain deterministic and MUST NOT be reordered by this feature's additions.
- **FR-076**: Indicator ordering within a server's trust-and-integrity assessment MUST be deterministic per FR-067, in both JSON and human output.
- **FR-077**: Every new enum-shaped value introduced by this feature (Artifact Identity Confidence, Configuration Risk status, Aggregate Assessment status, indicator severity, indicator category, path classification, version-expression classification, wrapper type) MUST serialize deterministically and MUST use the same JSON-token-vs-human-phrasing separation already established by the v1.2.0 `CapabilityLabel`/`human_label()` precedent.
- **FR-078**: The specification's (and downstream contract's) treatment of an optional field being `null` versus omitted entirely MUST be explicitly documented and MUST be consistent across all new fields.
- **FR-079**: Given identical local input state and an unchanged EtherFence version, repeated `etherfence setup detect --format json` invocations MUST produce byte-identical output.
- **FR-080**: All new JSON evidence fields introduced by this feature MUST carry only the safe, structured, redacted evidence described in FR-065–FR-066 — no field may carry raw configuration payloads, secret values, or file contents.

**Required security boundaries**

- **FR-081**: This feature MUST NOT execute, spawn, or otherwise run any inspected MCP server, any inspected command, or any subprocess derived from inspected configuration, for any purpose including probing.
- **FR-082**: This feature MUST NOT perform any shell expansion, variable expansion, or command emulation of inspected configuration.
- **FR-083**: This feature MUST NOT communicate with any MCP server using the MCP protocol (including but not limited to `tools/list`) as part of producing an assessment.
- **FR-084**: This feature MUST NOT perform any network access, DNS lookup, package-registry lookup, package installation, package download, or remote hash-reputation lookup as part of producing an assessment.
- **FR-085**: This feature MUST NOT implement or invoke a behavioral sandbox of any kind.
- **FR-086**: This feature MUST NOT automatically modify any client configuration file, any MCP proxy policy file, or any allowlist, and MUST NOT introduce any new automatic-allowlisting behavior.
- **FR-087**: This feature MUST NOT introduce a daemon process, a background monitor, a filesystem watcher, or any other persistent/long-running component; assessment MUST be computed synchronously, once per invocation, like all other `setup` subcommands.
- **FR-088**: This feature MUST NOT implement or claim a complete filesystem ACL, ownership, or permissions-analysis engine; any permission-adjacent observation (if any is implemented) MUST be scoped to the narrow local-artifact-eligibility checks in FR-032–FR-044.

**Compatibility**

- **FR-089**: `etherfence scan`, `etherfence setup catalog`, `etherfence setup plan`, `etherfence setup apply`, `etherfence setup rollback`, `etherfence setup doctor`, `etherfence mcp-policy`, and `etherfence mcp-proxy` MUST continue to function and pass their existing automated test suites unmodified by this feature.
- **FR-090**: The v1.2.0 `ef-setup-catalog/v0.1` schema and `etherfence setup catalog` behavior MUST be entirely unaffected by this feature.
- **FR-091**: Every claimed curated known-source identity, every claimed curated confusable alias, and every structural invocation rule (package-runner pinning classification, shell-wrapper recognition, obscured-launch pattern, path classification, environment-variable category) MUST have at least one corresponding checked-in fixture and an automated test asserting its exact expected output before it may be described as implemented/supported in documentation or command output, per the project constitution's Fixture-Backed Findings and Catalog Classification Discipline principles.

### Key Entities

- **Trust and Integrity Assessment**: The full structured assessment attached to one MCP server entry. Attributes: Invocation Identity and Form, Artifact Identity Confidence, Configuration Risk status, Aggregate Assessment status, needs-review flag, and an ordered list of Indicators.
- **Invocation Identity and Form**: The classified shape of how a server is launched — which supported package runner (if any), parsed package identity and version-expression classification, whether a shell-wrapper form is present and which one, and whether an obscured-launch pattern matched.
- **Executable Path Classification**: The classified shape of a server's statically configured executable location (absolute, relative, bare/PATH-resolved, missing, non-regular, symlink, temporary-directory, or ambiguous/unsupported).
- **Local Artifact Record**: The result of local artifact inspection for an eligible regular file, including its SHA-256 identity when successfully computed under the defined conditions, or a documented degraded outcome when inspection is ineligible or fails.
- **Curated Known Identity / Confusable Alias Table**: A small, checked-in table of exact server/package identities and their exact confusable aliases, used only for exact-match `known-source` and identity-confusable determinations.
- **Environment-Variable Indicator Category**: One of the fixed, documented name-based risk categories (dynamic loader injection, interpreter/runtime path override, package-registry override, TLS-verification-disabling, secret-like) that a configured environment-variable *name* may match.
- **Indicator**: One raised finding within an assessment. Attributes: stable indicator ID, severity, category, concise summary, rationale, structured redacted evidence, remediation suggestion.
- **Aggregate Assessment Status**: The single combined status derived from Artifact Identity Confidence and Configuration Risk status by one fixed, documented rule (see Clarification Q1).

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: For every MCP server that `etherfence setup detect` discovers, an operator can determine that server's Artifact Identity Confidence, Configuration Risk status, Aggregate Assessment status, and whether manual review is required, from a single command's output, without reading source code.
- **SC-002**: Running the assessment twice in a row against an unchanged local configuration set produces byte-identical JSON output, and produces identical ordered output when run against equivalent Linux and Windows fixture configurations.
- **SC-003**: 100% of MCP servers assessed by this feature receive a complete assessment (Artifact Identity Confidence, Configuration Risk status, Aggregate Assessment status, needs-review flag) — none are left with a missing or partial assessment.
- **SC-004**: 100% of indicators reported anywhere in output include all six required fields (stable ID, severity, category, summary, rationale, structured evidence) and a remediation suggestion.
- **SC-005**: 0% of automated test runs observe any environment-variable value, file content, credential, token, or complete sensitive command string anywhere in produced output (human text, JSON, evidence, error messages).
- **SC-006**: 0% of automated test runs observe `recommendation.tier` set to anything other than `deny` anywhere in v1.3.0 output.
- **SC-007**: Every claimed curated known-source identity, curated confusable alias, and structural invocation rule exercised in this release has at least one passing automated fixture test proving that exact status/output, checked as a release gate before the version ships.
- **SC-008**: A documentation-honesty check confirms that trust-and-integrity output and documentation never claim a server is proven safe, trusted, certified, malware-free, benign, or definitively malicious, and that `known-source`/`verified-local`/`no-known-indicators` are always accompanied by their documented limiting language.
- **SC-009**: All pre-existing `scan`, `setup catalog`, `setup plan`, `setup apply`, `setup rollback`, `setup doctor`, `mcp-policy`, and `mcp-proxy` automated tests continue to pass unmodified after this feature ships, confirming no regression.
- **SC-010**: An operator presented with a server that has strong Artifact Identity Confidence but high-risk Configuration Risk indicators (or vice versa) can identify both facts from the output without either one being hidden or overwritten by the other.

## Out of Scope

- Live or runtime MCP server inspection of any kind (connecting to, starting, or communicating with a server) — this feature is a static, local-only extension of `setup detect`, not a runtime capability.
- Package registry access, package installation, package dependency resolution, or package execution of any kind.
- Network access, DNS lookups, remote hash-reputation lookups, or any cloud-dependent signal.
- A general-purpose shell command-line parser, shell variable expansion, or full shell-semantics interpretation.
- Arbitrary decoding, command emulation, recursive interpretation, or behavioral analysis of any inspected command.
- A universal Unicode confusable-detection engine or a universal typosquatting detector; only the narrowly enumerated indicators in FR-046–FR-051 are in scope.
- A complete filesystem ACL, ownership, or permissions-analysis engine.
- Automatic modification of any client configuration file, MCP proxy policy file, or allowlist; automatic-allowlisting behavior of any kind.
- A daemon process, background monitor, or filesystem watcher.
- Any change to `mcp-proxy` runtime enforcement semantics, the `ef-mcp-policy/v0.1` schema's enforcement behavior, or existing `scan`/`setup catalog`/`setup plan`/`setup apply`/`setup rollback`/`setup doctor` finding/behavior.
- Any automatic `allow` starter-policy recommendation; v1.3.0 introduces no new path to `recommendation.tier = allow`.

## Explicit Non-Goals

EtherFence v1.3.0's trust-and-integrity assessment is explicitly **not**:

- a malware scanner
- a behavioral security sandbox
- an endpoint protection product
- a package authenticity verifier
- a software-signature verifier
- a package-registry reputation service
- a universal typosquatting detector
- a universal Unicode confusable detector
- a universal MCP server certification system
- a guarantee that no malicious behavior exists for any assessed server
- a replacement for manual review or for runtime least-privilege policy (`mcp-proxy` / `ef-mcp-policy`)

## Assumptions

- "Exactly pinned" for `npx`/`uvx`/`pipx run` invocations is defined per FR-013–FR-015 using standard package-manager version-identifier conventions (a single fully-resolved version, no range operators, no known mutable dist-tag); this is treated as a reasonable industry-standard default rather than requiring clarification, consistent with existing package-manager semantics.
- The supported package-runner set for v1.3.0 is fixed to exactly `npx`, `uvx`, and `pipx run`; other launchers (for example a bare `node`, `python`, or container-runtime invocation) are assessed only through the general Executable-Path Assessment and Shell-Wrapper Assessment areas, not through runner-specific package/version parsing, unless a future release explicitly extends the supported-runner set.
- The curated known-source identity table and the curated confusable-alias table are small, hand-maintained, checked-in data (mirroring the v1.2.0 `EVIDENCE_RULES` precedent), not a generated or externally sourced dataset.
- The explicit local-artifact file-size limit for hashing eligibility (FR-039) will reuse or closely mirror the existing `MAX_CONFIG_FILE_BYTES`-style bounded-read precedent already established in this codebase, with the exact numeric limit finalized during planning.
- This feature operates only on MCP servers already discovered by the existing v1.2.0/v0.1.x local configuration discovery; it does not expand the set of local configuration file locations or client kinds EtherFence looks for.
- Symlink handling (FR-034, FR-043) defaults to conservative non-following: a symlink is classified explicitly and is not, by default, dereferenced and hashed as though it were the configured path, unless clarification/planning explicitly documents a safe, bounded exception.
- Remote (URL-configured) MCP servers receive a partial assessment per Clarification Q3 / FR-057a–FR-057d: environment-variable and Unicode/identity-ambiguity checks run, while invocation-identity, executable-path, and local-artifact assessment are explicitly not applicable, since those areas presuppose a local, stdio-launched process.
- The four named obscured-launch patterns in FR-028 (Unix downloader-to-shell, Windows `certutil` download pattern, PowerShell download-and-execute, decode-then-execute) are treated as a fixed, closed v1.3.0 list per Clarification Q2; broader or more general download/decode detection is deferred to a future release.
- The configuration-risk-first Aggregate Assessment precedence in FR-061 (Clarification Q1) is treated as the single governing rule for all servers, including the remote-server case in FR-057d.
