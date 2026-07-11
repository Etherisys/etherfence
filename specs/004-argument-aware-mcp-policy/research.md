# Phase 0 Research: Argument-Aware MCP Runtime Policy

All Technical Context fields in `plan.md` were already fully determined by the `/goal` input; no
`NEEDS CLARIFICATION` markers remain. This document records the design decisions made while
turning that fixed context into a concrete schema/evaluator shape, in the same
Decision/Rationale/Alternatives format used so reviewers can see what was rejected and why.

## Decision 1: Hand-rolled URL parsing, no `url` crate

**Decision**: Parse the URL guard's scheme/host/port/path by hand (scheme up to `://`, authority
up to the next `/`, `?`, or `#`, path from there), rejecting anything ambiguous rather than trying
to fully implement WHATWG URL parsing.

**Rationale**: The existing v0.1 path guard already hand-rolls its own path normalizer
(`LexicalPath`) instead of depending on `std::path` or a crate, specifically because policy
evaluation needs to be a pure, deterministic, string-level operation with no filesystem or
platform-specific behavior. The URL guard has the identical requirement — deterministic, testable,
no I/O — and pulling in a general-purpose URL crate would add a dependency whose own parsing
edge cases (IDNA, unicode normalization tables, WHATWG's error-recovery-heavy grammar) are outside
this feature's threat model and would work against Principle X (Scope Discipline: no general
content-inspection machinery for its own sake). A minimal hand-rolled parser can be exhaustively
fail-closed: anything it does not confidently understand is denied rather than guessed at.

**Alternatives considered**:
- The `url` crate (WHATWG-compliant): rejected — new dependency, permissive-by-design parser
  (browsers must render almost anything), which is the wrong default for a security allowlist that
  wants to reject ambiguity, not tolerate it.
- Regex-based extraction: rejected outright by the spec's non-goals (FR-029: no general regex
  policy language) and also less auditable than explicit character-class scanning.

## Decision 2: Reject any URL with userinfo (`user:pass@host`) in the authority

**Decision**: A URL guard value containing `@` in its authority section is denied fail-closed as
malformed, never parsed into "userinfo + host".

**Rationale**: `scheme://trusted.example@evil.example/...` is a well-known confusable-authority
attack: naive parsers extract `trusted.example` as "the host" when it is actually userinfo, and the
real host is `evil.example`. Refusing to parse userinfo entirely closes this class of bypass
without needing any heuristic, and matches the "never log credential-bearing URLs" privacy
requirement (FR-027) — a URL with embedded credentials should never reach a decision path that
might normalize/echo it.

**Alternatives considered**: Parse userinfo and discard it before host extraction — rejected,
because it re-opens the confusable-host bypass above; correctness of that split depends on exact
WHATWG-grade parsing, which Decision 1 already ruled out.

## Decision 3: Reject any `%` in a guarded URL value

**Decision**: Any percent sign anywhere in a URL-guarded field's value is treated as malformed
(fail closed), rather than percent-decoding.

**Rationale**: Percent-encoding is exactly how path-prefix and host allowlist checks get bypassed
(`%2e%2e`, `%68ost`, mixed-encoding host confusables). The existing v0.1 `file://` URI handling in
`extract_file_uri_path` already takes this same stance (rejects `%` in the URI's path). Extending
the identical rule to the new URL guard keeps one consistent, auditable policy instead of a second,
subtly different decoding implementation — and avoids re-implementing a decoder whose correctness
would itself need to be verified against every allowlist check.

**Alternatives considered**: Decode-then-normalize — rejected as unnecessary complexity and a new
source of parser-differential bugs; operators can configure allowlists using unencoded values, and
a request that requires percent-encoding to reach an allowed host/path is not a case this feature
needs to support.

## Decision 4: Effective port = explicit port, else scheme default (http→80, https→443 only)

**Decision**: The URL guard computes "effective port" as the URL's explicit `:port` if present,
otherwise the well-known default for `http`/`https`. No other scheme gets an implicit default; a
port allowlist configured against a URL guard whose scheme has no known default and no explicit
port fails closed.

**Rationale**: Spec Assumptions explicitly scope this to `http`/`80` and `https`/`443`, matching
the browser/API-host example (User Story 3), which is the only documented use case needing port
semantics at all. Guessing defaults for arbitrary schemes would be unverifiable/untested
(Principle V) and is unnecessary scope.

**Alternatives considered**: Require an explicit port always (no defaulting) — rejected as
needlessly operator-hostile for the primary `https` use case, where omitting `:443` is completely
standard.

## Decision 5: Selector syntax — dotted segments, `[A-Za-z0-9_-]+` only, fixed max depth

**Decision**: A selector is a `.`-separated sequence of segments, each matching
`[A-Za-z0-9_-]+`, with a fixed maximum of 8 segments enforced at policy-load time. At evaluation
time, a segment is resolved as an object key if the current container is a JSON object, or as an
array index if the container is an array and the segment is all-digits; any other combination
(wrong container type, missing key, out-of-range index) is a guard-level deny, not a policy error.

**Rationale**: This mirrors the existing tool/method/path-rule identifier character class already
enforced elsewhere in `policy.rs`/`unicode.rs`, keeping one consistent "what characters are legal
in a policy identifier" rule across the whole schema instead of inventing a second one. A fixed
small depth bound satisfies FR-012's "bounded" requirement and every documented example (at most
one level of nesting, e.g. `filter.status`) with headroom, while remaining trivially reviewable —
no recursion budget, no cycle risk (JSON has no cycles), no unbounded work per request.

**Alternatives considered**: JSON Pointer (RFC 6901): rejected — its `~0`/`~1` escaping and
leading-slash syntax is a second, unfamiliar syntax next to the rest of the schema's plain
identifiers, working against FR-012's "one explicit syntax" requirement being *simple*, not merely
*a* syntax. A tiny expression/query language (JSONPath-like, wildcards, filters): rejected outright
by FR-029 (no general expression language) and by the depth/ambiguity concerns FR-016 requires
rejecting.

## Decision 6: v0.1/v0.2 gating is a policy-load validation rule, not two parser code paths

**Decision**: The Rust `struct`/`enum` types for guards accept the v0.2 fields unconditionally
(serde does not know about `schema_version`), and a single post-deserialize validation pass in
`parse_mcp_policy` walks the parsed policy and rejects any v0.2-only construct when
`schema_version != "ef-mcp-policy/v0.2"`.

**Rationale**: This is exactly the existing pattern for every other schema-hygiene rule in
`policy.rs` (empty path-rule names, missing `allow_roots`, Unicode hygiene) — one parse function,
one post-parse validation pass, fail closed with a specific message. Introducing a second
`McpPolicyFileV1`/`McpPolicyFileV2` type pair would duplicate the entire tool/method/path-rule
schema and violate FR-020's "one shared evaluator" spirit one layer up (schema, not just decision
logic). It also keeps `SUPPORTED_MCP_POLICY_SCHEMA_VERSION` trivially extensible to a third version
later without a breaking type-level change.

**Alternatives considered**: Separate top-level struct per schema version — rejected as
duplicative and harder to keep in lockstep; a serde `#[serde(deny_unknown_fields)]`-based approach
— rejected because it would also reject legitimate *future* unknown fields ambiguously rather than
naming the specific offending v0.2 construct, and does not exist on v0.1 today (adding it now would
itself be a v0.1 behavior change, which FR-002 forbids).

## Decision 7: Guard-vs-path-guard precedence: v0.1 path decision first, v0.2 guard second, single deny wins

**Decision**: When both a v0.1 `path_keys`/`uri_keys` guard and v0.2 `fields`/`require_keys`/
`forbid_keys` guards are configured on the same tool/method, evaluate the v0.1 path decision first
(exactly as today); only if it is still `Allow` do the v0.2 guards run, and the first guard to deny
wins (require/forbid keys checked before per-field guards, fields evaluated in a fixed
deterministic order).

**Rationale**: This is the only ordering that leaves 100% of existing v0.1 behavior byte-identical
(SC-003) — the v0.1 code path is literally unmodified, v0.2 is purely an additional narrowing step
that can only turn an `Allow` into a `Deny`, never the reverse. This satisfies FR-021 and FR-022
directly and needs no new precedence concept beyond "guards only narrow, and are applied in a fixed
order."

**Alternatives considered**: Evaluate v0.2 guards first — rejected, no functional difference in
outcome (deny-wins either way) but changes which *reason* is reported for a request that fails both
guards, which is an unnecessary, untested-by-existing-fixtures behavior change to pin down.
