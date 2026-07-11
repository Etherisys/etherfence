# Contract: `ef-mcp-policy/v0.2` TOML schema (additive over v0.1)

This is the policy-author-facing contract for the new guard tables. It is the source the checked-in
docs (`docs/mcp-policy-ux.md`, `docs/mcp-proxy.md`) get expanded from during implementation; see
`data-model.md` for the exact in-memory types and validation rules.

## Declaring v0.2

```toml
schema_version = "ef-mcp-policy/v0.2"
name = "example"
```

Everything legal under `ef-mcp-policy/v0.1` remains legal and behaves identically under
`ef-mcp-policy/v0.2` — v0.2 is additive, not a breaking rewrite. A v0.1-declared file that uses any
construct below fails to load.

## Guard table shape

Guards attach to the same tables v0.1 already uses for path guards:

```toml
[tools."<tool-name>".arguments]
require_keys = ["org", "repo"]
forbid_keys = ["admin_override"]

[tools."<tool-name>".arguments.fields."org"]
type = "enum"
values = ["my-org"]

[tools."<tool-name>".arguments.fields."repo"]
type = "string"
prefix = "my-org/"

[methods."<method-name>".params]
require_keys = ["destination"]

[methods."<method-name>".params.fields."destination"]
type = "enum"
values = ["#eng-alerts", "#on-call"]
```

A nested selector uses `.` between segments, e.g. `fields."filter.status"` targets
`arguments.filter.status`; `fields."items.0.id"` targets index `0` of array `items`.

## Field guard variants

```toml
# exact value
[tools."t".arguments.fields."mode"]
type = "exact"
value = "read"

# finite enum
[tools."t".arguments.fields."mode"]
type = "enum"
values = ["read", "list", "get"]

# string length / prefix
[tools."t".arguments.fields."name"]
type = "string"
min_length = 1
max_length = 64
prefix = "proj-"

# numeric bounds
[tools."t".arguments.fields."limit"]
type = "number"
min = 1
max = 100

# array length / allowed elements
[tools."t".arguments.fields."fields"]
type = "array"
min_items = 1
max_items = 5
allowed_elements = ["id", "title", "status"]

# URL scheme / host / port / path-prefix
[tools."t".arguments.fields."url"]
type = "url"
schemes = ["https"]
hosts = ["api.example.invalid"]
ports = [443]
path_prefixes = ["/v1/"]
```

## Validation contract (`etherfence mcp-policy validate`)

| Input | Outcome |
|---|---|
| Valid v0.2 policy | `validate` exits 0, prints schema/name summary (same as today). |
| v0.1 file containing any `require_keys`/`forbid_keys`/`fields` construct | `validate` fails with an error naming the construct and `ef-mcp-policy/v0.2` as required. |
| `min > max` on any bound | `validate` fails, error names the field/guard. |
| `enum.values` or `array.allowed_elements` empty | `validate` fails. |
| Unknown `type` value | `validate` fails (TOML/serde tag mismatch, surfaced as a policy parse error). |
| Selector with an empty segment, >8 segments, or a disallowed/suspicious-Unicode character | `validate` fails, naming the selector. |
| `url` guard with an invalid scheme (not `http`/`https`), empty host entry, or out-of-range port | `validate` fails. |
| A key present in both `require_keys` and `forbid_keys` | `validate` fails. |

## Explain contract (`etherfence mcp-policy explain`)

For each configured v0.2 guard, `explain` lists: the owning scope (global tool / global method /
server tool / server method — same `GuardScope` enum already used for path guards), the tool/method
key, the guard kind (`require_keys` / `forbid_keys` / a `fields` selector with its primitive type),
and — for `fields` — the primitive's configured bounds/allowlist size (never the allowlist values
themselves are required to be hidden; enum/allowlist *values* configured by the operator are their
own policy source, not runtime secrets, so `explain` may print them, matching how v0.1 `explain`
already prints `tools.allow`/`deny` lists verbatim). Only *runtime request values* are redacted
(`FR-027` concerns decision-time data, not the policy source itself).

## Check contract (`etherfence mcp-policy check`)

Extends today's `CheckOutcome` output with, when a v0.2 guard produced the decision: the guard's
key/selector and its `reason_category`. Decision/allowed/forwarded fields are unchanged in shape.
The exact same output must be producible by tracing the identical decision path the live proxy
takes — this is verified by the SC-004 equivalence tests, not by a separate code path.
