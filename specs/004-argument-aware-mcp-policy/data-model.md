# Phase 1 Data Model: Argument-Aware MCP Runtime Policy

This extends the existing `ef-mcp-policy` in-memory model (`crates/etherfence-mcp/src/policy.rs`).
Only new/changed shapes are described; everything not mentioned here (`McpPolicyFile`, `ToolRules`,
`MethodRules`, `PathRule`, `Decision`, `PolicyDecision`) is unchanged.

## ArgumentGuard (extends today's `PathKeyGuard`)

The table reachable at `[tools."<tool>".arguments]` / `[methods."<method>".params]`.

| Field | Type | Schema | Notes |
|---|---|---|---|
| `path_keys` | `Vec<String>` | v0.1 | Unchanged. |
| `uri_keys` | `Vec<String>` | v0.1 | Unchanged. |
| `path_rule` | `Option<String>` | v0.1 (now optional at the type level) | Validation still requires `Some` whenever `path_keys`/`uri_keys` is non-empty — v0.1 files that set it (all of them, since it was previously mandatory) are unaffected. |
| `require_keys` | `Vec<String>` (default empty) | v0.2 | Top-level keys that must be present in the guarded object. |
| `forbid_keys` | `Vec<String>` (default empty) | v0.2 | Top-level keys that must be absent from the guarded object. |
| `fields` | `BTreeMap<String, FieldGuard>` (default empty) | v0.2 | Keyed by **selector** (see below); `BTreeMap` for deterministic iteration order (Principle IV). |

**Validation rules** (all at `parse_mcp_policy` time, fail closed):
- If `schema_version` is `ef-mcp-policy/v0.1` and `require_keys`, `forbid_keys`, or `fields` is
  non-empty anywhere in the policy → reject with the offending construct named.
- Every selector key in `fields` must pass selector-syntax validation (below).
- `require_keys` and `forbid_keys` must not share an entry (a key required and forbidden at once is
  a self-contradiction — reject).
- No two guard tables may target the same tool/method+key combination twice (this falls out of TOML
  itself: `fields` is a map, so a duplicate TOML key is already a `toml` crate parse error; the
  requirement is satisfied structurally, not by extra code).

## Selector

A `String` key of `ArgumentGuard.fields`, syntactically: one or more `.`-separated segments, each
matching `[A-Za-z0-9_-]+`, maximum 8 segments, each segment additionally passing the existing
`inspect_policy_identifier` Unicode-hygiene check (bidi/zero-width/non-ASCII rejected).

**Resolution** (at decision time, against the actual `arguments`/`params` JSON value): walk
segments left to right starting at the guarded object.
- If the current container is a JSON object: the segment is an object key; missing key → guard
  denies (`selector_key_missing`).
- If the current container is a JSON array: the segment must be all-digits and in bounds; anything
  else → guard denies (`selector_index_invalid` / `selector_index_out_of_range`).
- If the current container is neither (a scalar reached before the selector is exhausted) → guard
  denies (`selector_container_mismatch`).
- After the last segment, the resolved JSON value is handed to the field guard's evaluation.

## FieldGuard

A tagged union (`type` field), one variant per primitive. All variants share: the value at a
resolved selector must be present and of the expected JSON kind, or the guard denies
(`field_missing` / `field_wrong_type`).

| Variant (`type =`) | Fields | Semantics | Deny reason categories |
|---|---|---|---|
| `"exact"` | `value: ScalarValue` | resolved value must equal `value` | `exact_value_mismatch` |
| `"enum"` | `values: Vec<ScalarValue>` (non-empty) | resolved value must equal one entry | `enum_value_not_allowed` |
| `"string"` | `min_length: Option<usize>`, `max_length: Option<usize>`, `prefix: Option<String>` | resolved value must be a JSON string; length (char count) within bounds; if `prefix` set, value must start with it (byte-exact) | `string_too_short`, `string_too_long`, `string_prefix_mismatch` |
| `"number"` | `min: Option<f64>`, `max: Option<f64>` | resolved value must be a JSON number; within inclusive bounds | `number_below_minimum`, `number_above_maximum` |
| `"array"` | `min_items: Option<usize>`, `max_items: Option<usize>`, `allowed_elements: Option<Vec<ScalarValue>>` | resolved value must be a JSON array; length within bounds; if `allowed_elements` set, every element must be a scalar present in the set | `array_too_short`, `array_too_long`, `array_element_not_allowed` |
| `"url"` | `schemes: Vec<String>`, `hosts: Vec<String>`, `ports: Vec<u16>`, `path_prefixes: Vec<String>` (each list optional/omittable; empty = unconstrained for that dimension) | resolved value must be a JSON string that parses as a well-formed URL (Decision 1-3 in research.md); each non-empty list constrains its dimension | `url_malformed`, `url_scheme_not_allowed`, `url_host_not_allowed`, `url_port_not_allowed`, `url_path_prefix_not_allowed` |

**Validation rules**:
- `enum.values` and `array.allowed_elements` (when present) must be non-empty.
- `string`/`number`/`array` bounds: if both min and max are set, `min <= max`, else reject
  (`impossible_range`).
- `url.schemes` entries must be `http`/`https` (the only schemes with defined effective-port
  semantics — see research.md Decision 4); `url.hosts` entries must be non-empty, ASCII, lowercase
  after normalization comparison, no embedded `@`/`/`/whitespace; `url.ports` entries must be valid
  `u16` (TOML integer range already enforces this at deserialize time); unrecognized `type` values
  are a hard parse error.

## ScalarValue

```text
ScalarValue = Bool(bool) | Int(i64) | Float(f64) | Str(String)
```

TOML-native scalar, used by `exact.value`, `enum.values`, and `array.allowed_elements`. Comparison
against a `serde_json::Value` is type-and-value equality (a `ScalarValue::Int(5)` does not match
JSON `5.0` loosely beyond what `serde_json::Value` itself considers equal — no cross-type
coercion).

## GuardPolicyDecision

Sibling of the existing `PathPolicyDecision`, returned by the new `decide_tool_argument_guards` /
`decide_method_param_guards` functions:

| Field | Type | Notes |
|---|---|---|
| `decision` | `Decision` | `Allow` or `Deny` (guards never produce `PolicyError`). |
| `reason` | `String` | Human-readable, built only from safe identifiers (never the evaluated value). |
| `guard_key` | `String` | The tool/method name the guard is attached to. |
| `selector` | `String` | The selector or `require_keys`/`forbid_keys` marker that triggered the decision. |
| `reason_category` | `String` | One of the closed-set strings in the FieldGuard table above, or `"required_key_missing"` / `"forbidden_key_present"` / `"guard_allowed"`. |

## AuditRecord (extends existing `crates/etherfence-mcp/src/audit.rs`)

Three new optional fields, additive only, mirroring the existing `path_rule`/`path_key`/
`path_classification` trio:

| Field | Type | Notes |
|---|---|---|
| `guard_key` | `Option<String>` | Present only when a v0.2 guard decision fired. |
| `guard_selector` | `Option<String>` | Selector or key-list marker; never a value. |
| `guard_reason_category` | `Option<String>` | Closed-set category string. |

No new field ever carries request/response *content* — only identifiers already validated safe by
`unicode.rs` hygiene checks (selector segments, tool/method names) or fixed-string category labels
baked into the Rust source.
