# Feature Specification: Argument-Aware MCP Runtime Policy

**Feature Branch**: `spec/v1.5.0-argument-aware-mcp-policy`

**Created**: 2026-07-11

**Status**: Draft

**Input**: User description: "EtherFence v1.5.0: Argument-aware MCP runtime policy — contain
consequences when an agent is mistaken or prompt-injected by constraining selected `tools/call`
arguments and MCP method params with deterministic least-privilege rules, on top of the existing
`ef-mcp-policy/v0.1` method/tool/path engine. New versioned schema `ef-mcp-policy/v0.2` adds
required/forbidden key guards, exact-value/enum allowlists, string length/prefix rules, numeric
bounds, array length/allowed-element sets, URL scheme/host/port/path-prefix allowlists, and bounded
nested selectors — all evaluated by one shared evaluator used by both the live proxy and the
serverless `mcp-policy check` command, fail-closed per guard, with redacted audit output."

## User Scenarios & Testing *(mandatory)*

An EtherFence operator has already wrapped a local MCP server with `etherfence mcp-proxy` (or
plans to) and has an `ef-mcp-policy/v0.1` file that allows a tool by name (e.g.
`github.create_issue`, `messaging.send`, `browser.fetch`). Today the policy can only allow or deny
the *whole* tool call, or (for `resources/read`) constrain a single URI parameter to a path root.
The operator wants to keep the tool allowed but narrow *which arguments* it may be called with, so
that a mistaken or prompt-injected call is contained to a safe subset of the tool's real
capability, without inventing a new scripting language and without breaking any policy file they
already have in production.

### User Story 1 - Restrict a GitHub-style tool to named organizations/repositories (Priority: P1)

An operator allows `github.create_issue` for an agent but wants to guarantee the call can only
target their own organization's repositories, never an arbitrary org/repo the agent might be
tricked into targeting.

**Why this priority**: This is the canonical "contain a mistaken or hijacked tool call" scenario
the whole feature exists for, and it only needs the enum/exact-value primitive, making it the
smallest possible slice that proves the feature end-to-end (schema, evaluator, CLI, audit).

**Independent Test**: Write an `ef-mcp-policy/v0.2` policy that allows `github.create_issue` and
guards its `arguments.org` field to an enum of one allowed organization name. Run
`etherfence mcp-policy check` with a `tools/call` request targeting the allowed org (allowed) and
a different org (denied), and confirm the live proxy (`inspect_client_line`) produces the
identical decision for both.

**Acceptance Scenarios**:

1. **Given** a policy allowing `github.create_issue` with an `org` field guard enumerating
   `["my-org"]`, **When** a `tools/call` request supplies `arguments.org = "my-org"`, **Then** the
   call is allowed and the audit record's reason names the guard's allow classification.
2. **Given** the same policy, **When** a request supplies `arguments.org = "other-org"`, **Then**
   the call is denied with a reason category identifying an enum-allowlist mismatch, and the
   denied value is never present in the audit record or the JSON-RPC error response.
3. **Given** the same policy, **When** a request omits `arguments.org` entirely, **Then** the call
   is denied fail-closed with a "missing guarded key" reason category.

---

### User Story 2 - Restrict a messaging tool to named destinations (Priority: P1)

An operator allows `messaging.send` but wants delivery limited to a small, named set of
destinations (channels/addresses), so a hijacked call cannot exfiltrate data to an arbitrary
destination.

**Why this priority**: Proves the enum primitive generalizes across tools/fields (not special-cased
to GitHub) and exercises the "forbidden keys" primitive (denying an `override_destination` escape
hatch some messaging tools expose).

**Independent Test**: Write a policy guarding `messaging.send`'s `destination` field to a finite
enum and forbidding a `bypass` key on the same call; check both an allowed and a denied request via
`mcp-policy check` and confirm identical proxy behavior.

**Acceptance Scenarios**:

1. **Given** a policy enumerating allowed `destination` values and forbidding the `bypass` key,
   **When** a request targets an allowed destination without `bypass`, **Then** the call is
   allowed.
2. **Given** the same policy, **When** a request includes a `bypass` key at all (any value),
   **Then** the call is denied with a "forbidden key present" reason category.

---

### User Story 3 - Restrict a browser/API tool to approved HTTPS hosts (Priority: P2)

An operator allows a `browser.fetch`-style tool but wants outbound requests limited to a named set
of HTTPS hosts, rejecting other schemes, unlisted hosts, non-standard ports, and paths outside an
approved prefix.

**Why this priority**: Exercises the most complex primitive (URL guard: scheme + normalized host +
effective port + path prefix) and the credential-URL privacy requirement (a denied URL, which may
carry query secrets, must never be echoed).

**Independent Test**: Write a policy guarding a tool's `url` field with `schemes = ["https"]`,
`hosts = ["api.example.invalid"]`, and `path_prefixes = ["/v1/"]`; check requests that vary scheme,
host, port, and path, and confirm every denial reason is a safe category string with no URL
fragment in the output.

**Acceptance Scenarios**:

1. **Given** the URL guard above, **When** a request's `url` is
   `https://api.example.invalid/v1/search?q=x`, **Then** the call is allowed.
2. **Given** the same guard, **When** the URL uses `http://` instead of `https://`, **Then** the
   call is denied with a scheme-mismatch reason category.
3. **Given** the same guard, **When** the URL host is not in the allowlist (including a
   confusable/userinfo-bearing authority such as
   `https://api.example.invalid@evil.example/v1/x`), **Then** the call is denied fail-closed, and
   the raw URL never appears in the audit record or CLI output.
4. **Given** the same guard, **When** the URL path is `/v2/search` (outside the allowed prefix),
   **Then** the call is denied with a path-prefix-mismatch reason category.

---

### User Story 4 - Restrict an operation/mode field to read-only values (Priority: P2)

An operator allows a general-purpose tool (e.g. a database or file-management tool) but wants an
`operation`/`mode` field locked to read-only values, plus a numeric/array bound on a related field
(e.g. a `limit` field bounded 1-100, or a `fields` array bounded to an allowed column set).

**Why this priority**: Exercises the remaining primitives (numeric bounds, string length/prefix,
array length + allowed-element set) together in one realistic policy, and the nested-selector
syntax for a field one level inside the guarded object.

**Independent Test**: Write a policy guarding `operation` (enum `["read", "list", "get"]`), `limit`
(numeric bounds 1-100), and a nested `filter.status` selector (enum). Check requests that satisfy
all guards, violate one guard, and use a malformed/out-of-range value for each primitive kind.

**Acceptance Scenarios**:

1. **Given** the policy above, **When** a request sets `operation = "read"`, `limit = 10`, and
   `filter.status = "open"`, **Then** the call is allowed.
2. **Given** the same policy, **When** `operation = "delete"`, **Then** the call is denied with an
   enum-allowlist reason category.
3. **Given** the same policy, **When** `limit = 1000` or `limit = "10"` (wrong type), **Then** the
   call is denied fail-closed with a numeric-bound or wrong-type reason category respectively.
4. **Given** the same policy, **When** `filter` is present but `filter.status` is missing or
   `filter` is not an object, **Then** the call is denied fail-closed with a selector-resolution
   reason category.

---

### Edge Cases

- A `tools/call` or method request whose guarded field is present but has the wrong JSON type
  (e.g. a number where a string is guarded) must deny fail-closed, never coerce.
- A URL value with percent-encoding, userinfo (`user:pass@host`), a missing host, or an
  unparseable authority must deny fail-closed as malformed, never partially parsed.
- A nested selector referencing an array index beyond the array's bounds, or indexing into a
  non-array/non-object at any segment, must deny fail-closed as an unresolved selector.
- A policy that declares two guards for the same key/selector on the same tool/method, or a guard
  with `min > max`, an empty enum/allowed-element list, or an unknown guard type, must fail to
  load (parse/validation error), never silently pick one or ignore the conflict.
- An `ef-mcp-policy/v0.1`-declared policy file that happens to contain v0.2-only guard syntax must
  fail to load with an explicit "requires schema_version ef-mcp-policy/v0.2" error, never silently
  ignore the guard or silently upgrade.
- Every existing `ef-mcp-policy/v0.1` fixture and example policy in the repository must continue to
  parse and evaluate identically (byte-for-byte same decisions) after this change.
- A guard configured on a tool/method that a request never exercises does not change that
  request's decision at all ("unconfigured arguments retain current behavior").
- Batch JSON-RPC arrays, non-JSON lines, and messages without a `method` field are unaffected by
  argument guards and keep exactly their current v0.1 handling.

## Requirements *(mandatory)*

### Functional Requirements

**Schema & compatibility**

- **FR-001**: The system MUST introduce a new policy schema identifier `ef-mcp-policy/v0.2` that a
  policy file declares via its existing `schema_version` field.
- **FR-002**: The system MUST continue to accept and evaluate `ef-mcp-policy/v0.1` files exactly as
  today; no existing v0.1 test, fixture, or example policy's parsed structure or decision output may
  change.
- **FR-003**: The system MUST reject, at load time, any policy that declares `schema_version =
  "ef-mcp-policy/v0.1"` but contains any v0.2-only guard construct (see FR-010 through FR-018),
  with an error naming the offending construct and the required schema version.

**Guard primitives (each configurable on a guarded tool-call `arguments` object or a guarded
method `params` object; each primitive applies only where explicitly configured)**

- **FR-004**: The system MUST support a required-keys guard: the guarded object must contain every
  listed key, or the call is denied.
- **FR-005**: The system MUST support a forbidden-keys guard: if the guarded object contains any
  listed key, regardless of that key's value, the call is denied.
- **FR-006**: The system MUST support an exact-value guard on a field: the field's value must equal
  one configured scalar (string, number, or boolean), or the call is denied.
- **FR-007**: The system MUST support a finite-enum guard on a field: the field's value must equal
  one of a configured, non-empty list of scalars, or the call is denied.
- **FR-008**: The system MUST support a string guard on a field with an optional minimum length,
  optional maximum length, and an optional single literal prefix requirement; violating any
  configured bound denies the call.
- **FR-009**: The system MUST support a numeric guard on a field with an optional minimum and
  optional maximum (inclusive); violating either bound, or the field not being a JSON number,
  denies the call.
- **FR-010**: The system MUST support an array guard on a field with an optional minimum length,
  optional maximum length, and an optional finite allowed-element set (every element must be a
  scalar present in the set); violating any configured bound denies the call.
- **FR-011**: The system MUST support a URL guard on a field with an optional scheme allowlist, an
  optional normalized-hostname allowlist, an optional effective-port allowlist (explicit port or
  the scheme's default), and an optional path-prefix allowlist; the field's value must parse as a
  well-formed URL and satisfy every configured element, or the call is denied.
- **FR-012**: The system MUST support targeting a guard at a field nested inside the guarded
  object via one bounded, explicit selector syntax (dotted object-key / numeric array-index
  segments, no wildcards, no regular expressions, a fixed maximum depth) rather than only
  top-level fields.

**Fail-closed semantics**

- **FR-013**: For any single configured guard, the system MUST deny (not allow, not skip) when: the
  guarded key/selector is absent from the request, the value has the wrong JSON type for that
  guard, the value is malformed (e.g. an unparseable URL), the selector cannot be fully resolved
  against the actual request shape, or a value fails to normalize (e.g. an unnormalizable host).
- **FR-014**: A tool-call or method-params object with no guard configured for a given key/selector
  MUST behave exactly as it does today (no new implicit denial).

**Validation**

- **FR-015**: Policy loading MUST reject a policy that declares two guards for the same key or
  selector on the same tool/method scope.
- **FR-016**: Policy loading MUST reject a selector that is empty, exceeds the maximum depth, has a
  disallowed-character segment, or fails the existing Unicode-hygiene checks (bidi controls,
  zero-width/invisible characters, non-ASCII) already applied to other policy identifiers.
- **FR-017**: Policy loading MUST reject a URL guard with an invalid scheme, invalid/empty
  hostname entry, out-of-range port, or an empty scheme/host/port/path-prefix list where the guard
  requires at least one entry to be meaningful.
- **FR-018**: Policy loading MUST reject a numeric, string-length, or array-length guard whose
  configured minimum exceeds its configured maximum, and any enum/allowed-element-set guard
  declared with zero elements.
- **FR-019**: Policy loading MUST reject an unrecognized/unsupported guard type name.

**Shared evaluator & preserved behavior**

- **FR-020**: There MUST be exactly one decision function set that evaluates v0.2 argument/param
  guards, and both the live `mcp-proxy` request path and the serverless `mcp-policy check` dry-run
  path MUST call it — no second, divergent implementation of guard evaluation may exist.
- **FR-021**: Existing method-then-tool-then-path decision precedence, `tools/list` response
  filtering, bidirectional (client-to-server and server-to-client) method enforcement, JSON-RPC
  batch fail-closed denial, in-flight request tracking, and proxy lifecycle/exit-code behavior MUST
  be unchanged for any request that does not trigger a v0.2 guard.
- **FR-022**: When both a v0.1 path guard and a v0.2 field guard are configured on the same
  tool/method, the system MUST apply a single documented, deterministic precedence between them
  (this feature keeps the v0.1 path guard's existing decision authoritative when it denies, and
  evaluates v0.2 field guards only when the v0.1 path guard — if any — allows).

**CLI surface**

- **FR-023**: `etherfence mcp-policy validate` MUST accept a valid v0.2 policy and reject an invalid
  one with a message identifying the specific validation failure from FR-015 through FR-019.
- **FR-024**: `etherfence mcp-policy explain` MUST list every configured v0.2 guard per tool/method
  key or selector, together with its primitive kind, in the same deterministic listing style used
  for v0.1 path guards today.
- **FR-025**: `etherfence mcp-policy init` MUST offer at least one built-in profile that
  demonstrates v0.2 guards.
- **FR-026**: `etherfence mcp-policy check` MUST report, for a request that triggers a v0.2 guard,
  the same decision/reason shape used today, extended with the triggered guard's key/selector and a
  stable, closed-set reason-category string.

**Privacy & audit**

- **FR-027**: No audit record, CLI output, or JSON-RPC denial response MAY contain a guarded field's
  actual value, a full arguments/params object, a URL's credentials/query string, or any other
  protected content; only safe rule/guard identifiers, key/selector names (subject to the existing
  Unicode-based key redaction), decisions, and reason-category strings MAY be recorded.

**Non-goals (explicitly out of scope for this feature)**

- **FR-028**: The system MUST NOT perform natural-language analysis or infer intent to detect
  prompt injection; guards are purely deterministic, declarative constraints on argument shape and
  value.
- **FR-029**: The system MUST NOT introduce a general regular-expression, scripting, or expression
  policy language, shell-command parsing, SQL analysis, or content-inspection/DLP capability beyond
  the primitives in FR-004 through FR-012.
- **FR-030**: The system MUST NOT claim, in documentation or CLI output, that a v0.2-guarded tool
  call makes the wrapped MCP server safe overall; claims remain scoped to the specific configured
  guards.

### Key Entities

- **Argument Guard**: A named set of constraints attached to one tool's `arguments` object (or one
  method's `params` object), composed of zero or more of: required keys, forbidden keys, and
  per-selector field guards.
- **Field Guard**: One constraint of a single kind (exact, enum, string, number, array, or URL)
  bound to one selector within a guarded object.
- **Selector**: A bounded, explicit path (top-level key, or dotted/indexed path into a nested
  object/array) identifying which value within the guarded object a field guard evaluates.
- **Guard Decision**: The outcome (allow/deny), the closed-set reason category, and the
  rule/guard/selector identifiers describing why — never the evaluated value itself.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: For each of the four documented example policies (GitHub org/repo, messaging
  destination, browser/API host, read-only operation), an operator can express the intended
  restriction using only the built-in guard primitives, with no example requiring a regex or
  scripting workaround.
- **SC-002**: Every one of the guard primitives (required/forbidden keys, exact value, enum,
  string length/prefix, numeric bounds, array length/allowed-elements, URL scheme/host/port/path,
  nested selector) has at least one automated test proving an allow case and at least one proving a
  fail-closed deny case.
- **SC-003**: 100% of pre-existing `ef-mcp-policy/v0.1` fixtures, example policies, and tests
  continue to pass unmodified after this change ships.
- **SC-004**: For every test request exercised against both the live proxy path and the
  `mcp-policy check` dry-run path, the two report the identical decision and reason category (exact
  semantic equivalence).
- **SC-005**: No test asserting on audit-log or CLI-denial output ever finds a guarded value,
  credential, token, URL query string, or full arguments/params object in that output.
- **SC-006**: A policy author can run `etherfence mcp-policy explain` on any v0.2 policy and see
  every configured guard listed without needing to read the TOML source.

## Assumptions

- "Argument" and "param" refer to the JSON value already present in a parsed `tools/call`
  `arguments` object or a JSON-RPC method's `params` object; this feature does not introduce any
  new transport, encoding, or protocol extension.
- The existing v0.1 path/URI guard (`path_keys`/`uri_keys`/`path_rule`) remains the dedicated
  mechanism for filesystem-root containment; the new URL guard is a distinct, general-purpose
  primitive for non-filesystem URLs (HTTP/HTTPS endpoints) and does not replace or duplicate the
  path guard's role.
- "Effective port" means the URL's explicit port when present, otherwise the scheme's registered
  default port (80 for `http`, 443 for `https`); no other scheme's default port needs to be
  supported for this feature's documented use cases.
- Selector depth is bounded to a small fixed constant (on the order of a handful of segments),
  sufficient for the documented examples (e.g. one level of nesting such as `filter.status`)
  without needing to support arbitrarily deep structures.
- This feature only changes the local stdio `mcp-proxy` and the serverless `mcp-policy` CLI family;
  no daemon, remote proxy, or new network surface is introduced, consistent with the project
  constitution.
