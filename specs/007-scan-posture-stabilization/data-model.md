# Data Model

No serialized or persisted data model changes.

## Presentation-only values

- **Layout width**: terminal column budget or deterministic non-TTY fallback; never serialized.
- **Wrapped line**: existing human text split at word boundaries with a stable prefix and continuation indentation.
- **Styled segment**: semantic style applied after the wrapped plain segment is computed; may collapse to plain text.

`ScanReport`, posture fields, `ef-scan-report/v0.1.1`, baseline files, and SARIF remain unchanged.
