use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::policy::Decision;
use crate::policy::McpPolicyFile;
use crate::unicode::inspect_policy_identifier;

/// One JSONL audit record. Request metadata is redacted before it gets here:
/// only tool-call argument key names and top-level params key names are
/// recorded, never argument or param values.
#[derive(Debug, Clone, Serialize)]
pub struct AuditRecord {
    pub ts: String,
    pub event: String,
    pub policy: Option<String>,
    pub server: Option<String>,
    pub direction: Option<String>,
    pub method: Option<String>,
    pub request_id: Option<Value>,
    pub request_id_type: Option<String>,
    pub tool: Option<String>,
    pub argument_keys: Vec<String>,
    pub param_keys: Vec<String>,
    pub original_count: Option<usize>,
    pub filtered_count: Option<usize>,
    pub allowed_tools: Vec<String>,
    pub path_rule: Option<String>,
    pub path_key: Option<String>,
    pub path_classification: Option<String>,
    pub decision: String,
    pub reason: String,
}

impl AuditRecord {
    pub fn tool_call(
        policy_name: &str,
        server_name: &str,
        request_id: Option<Value>,
        tool: Option<&str>,
        argument_keys: Vec<String>,
        decision: Decision,
        reason: &str,
    ) -> Self {
        let (request_id, request_id_type) = split_request_id(request_id);
        AuditRecord {
            ts: rfc3339_utc_now(),
            event: "tool_call_decision".to_string(),
            policy: Some(policy_name.to_string()),
            server: Some(server_name.to_string()),
            direction: Some("client_to_server".to_string()),
            method: Some("tools/call".to_string()),
            request_id,
            request_id_type,
            tool: if reason.starts_with("unicode_") {
                Some("<unicode-denied-tool>".to_string())
            } else {
                tool.map(str::to_string)
            },
            argument_keys,
            param_keys: Vec::new(),
            original_count: None,
            filtered_count: None,
            allowed_tools: Vec::new(),
            path_rule: None,
            path_key: None,
            path_classification: None,
            decision: decision.as_str().to_string(),
            reason: reason.to_string(),
        }
    }

    pub fn method_decision(
        policy_name: &str,
        server_name: &str,
        method: &str,
        request_id: Option<Value>,
        param_keys: Vec<String>,
        decision: Decision,
        reason: &str,
    ) -> Self {
        Self::method_decision_with_direction(
            policy_name,
            server_name,
            "client_to_server",
            method,
            request_id,
            param_keys,
            decision,
            reason,
        )
    }

    pub fn with_path_metadata(
        mut self,
        path_rule: &str,
        path_key: &str,
        path_classification: &str,
    ) -> Self {
        self.path_rule = Some(path_rule.to_string());
        self.path_key = Some(path_key.to_string());
        self.path_classification = Some(path_classification.to_string());
        self
    }

    #[allow(clippy::too_many_arguments)]
    pub fn method_decision_with_direction(
        policy_name: &str,
        server_name: &str,
        direction: &str,
        method: &str,
        request_id: Option<Value>,
        param_keys: Vec<String>,
        decision: Decision,
        reason: &str,
    ) -> Self {
        let (request_id, request_id_type) = split_request_id(request_id);
        AuditRecord {
            ts: rfc3339_utc_now(),
            event: "method_decision".to_string(),
            policy: Some(policy_name.to_string()),
            server: Some(server_name.to_string()),
            direction: Some(direction.to_string()),
            method: Some(if reason.starts_with("unicode_") {
                "<unicode-denied-method>".to_string()
            } else {
                method.to_string()
            }),
            request_id,
            request_id_type,
            tool: None,
            argument_keys: Vec::new(),
            param_keys,
            original_count: None,
            filtered_count: None,
            allowed_tools: Vec::new(),
            path_rule: None,
            path_key: None,
            path_classification: None,
            decision: decision.as_str().to_string(),
            reason: reason.to_string(),
        }
    }

    pub fn batch_denied(policy_name: &str, server_name: &str, reason: &str) -> Self {
        Self::batch_denied_with_direction(policy_name, server_name, "client_to_server", reason)
    }

    pub fn batch_denied_with_direction(
        policy_name: &str,
        server_name: &str,
        direction: &str,
        reason: &str,
    ) -> Self {
        AuditRecord {
            ts: rfc3339_utc_now(),
            event: "batch_denied".to_string(),
            policy: Some(policy_name.to_string()),
            server: Some(server_name.to_string()),
            direction: Some(direction.to_string()),
            method: None,
            request_id: None,
            request_id_type: None,
            tool: None,
            argument_keys: Vec::new(),
            param_keys: Vec::new(),
            original_count: None,
            filtered_count: None,
            allowed_tools: Vec::new(),
            path_rule: None,
            path_key: None,
            path_classification: None,
            decision: Decision::Deny.as_str().to_string(),
            reason: reason.to_string(),
        }
    }

    pub fn tools_list_filtered(
        policy_name: &str,
        server_name: &str,
        request_id: Option<Value>,
        original_count: usize,
        allowed_tools: Vec<String>,
        reason: &str,
    ) -> Self {
        let (request_id, request_id_type) = split_request_id(request_id);
        AuditRecord {
            ts: rfc3339_utc_now(),
            event: "tools_list_filtered".to_string(),
            policy: Some(policy_name.to_string()),
            server: Some(server_name.to_string()),
            direction: Some("server_to_client".to_string()),
            method: Some("tools/list".to_string()),
            request_id,
            request_id_type,
            tool: None,
            argument_keys: Vec::new(),
            param_keys: Vec::new(),
            original_count: Some(original_count),
            filtered_count: Some(allowed_tools.len()),
            allowed_tools,
            path_rule: None,
            path_key: None,
            path_classification: None,
            decision: Decision::Allow.as_str().to_string(),
            reason: reason.to_string(),
        }
    }

    pub fn tools_list_malformed(
        policy_name: &str,
        server_name: &str,
        request_id: Option<Value>,
        reason: &str,
    ) -> Self {
        let (request_id, request_id_type) = split_request_id(request_id);
        AuditRecord {
            ts: rfc3339_utc_now(),
            event: "tools_list_malformed".to_string(),
            policy: Some(policy_name.to_string()),
            server: Some(server_name.to_string()),
            direction: Some("server_to_client".to_string()),
            method: Some("tools/list".to_string()),
            request_id,
            request_id_type,
            tool: None,
            argument_keys: Vec::new(),
            param_keys: Vec::new(),
            original_count: Some(0),
            filtered_count: Some(0),
            allowed_tools: Vec::new(),
            path_rule: None,
            path_key: None,
            path_classification: None,
            decision: Decision::Allow.as_str().to_string(),
            reason: reason.to_string(),
        }
    }

    pub fn tools_list_tracking_removed(policy_name: &McpPolicyFile, server_name: &str) -> Self {
        AuditRecord {
            ts: rfc3339_utc_now(),
            event: "tools_list_tracking_removed".to_string(),
            policy: Some(policy_name.name.clone()),
            server: Some(server_name.to_string()),
            direction: Some("server_to_client".to_string()),
            method: Some("tools/list".to_string()),
            request_id: None,
            request_id_type: None,
            tool: None,
            argument_keys: Vec::new(),
            param_keys: Vec::new(),
            original_count: None,
            filtered_count: None,
            allowed_tools: Vec::new(),
            path_rule: None,
            path_key: None,
            path_classification: None,
            decision: Decision::Allow.as_str().to_string(),
            reason: "tracked tools/list response handled; request tracking entry cleared"
                .to_string(),
        }
    }

    pub fn policy_error(reason: &str) -> Self {
        AuditRecord {
            ts: rfc3339_utc_now(),
            event: "policy_load_error".to_string(),
            policy: None,
            server: None,
            direction: None,
            method: None,
            request_id: None,
            request_id_type: None,
            tool: None,
            argument_keys: Vec::new(),
            param_keys: Vec::new(),
            original_count: None,
            filtered_count: None,
            allowed_tools: Vec::new(),
            path_rule: None,
            path_key: None,
            path_classification: None,
            decision: Decision::PolicyError.as_str().to_string(),
            reason: reason.to_string(),
        }
    }
}

/// Split a JSON-RPC request id into a safe-to-log value and a type tag.
///
/// The type tag is one of: "number", "string", "bool", "object", "array",
/// "null", or "missing" (when the id field is absent).
///
/// Simple id types (number, string, bool, null) are logged as-is because
/// they are client-visible metadata used for request correlation and are
/// not sensitive. Complex id types (object, array) are redacted to just
/// their type tag — the raw object/array content is not logged, to match
/// the "no sensitive values" audit posture. A malicious or unusual id
/// object could carry arbitrary data, and logging its raw form would
/// violate the principle that only safe metadata reaches the audit log.
fn split_request_id(request_id: Option<Value>) -> (Option<Value>, Option<String>) {
    match request_id {
        None => (None, Some("missing".to_string())),
        Some(Value::Null) => (Some(Value::Null), Some("null".to_string())),
        Some(v @ Value::Number(_)) => (Some(v), Some("number".to_string())),
        Some(v @ Value::String(_)) => (Some(v), Some("string".to_string())),
        Some(v @ Value::Bool(_)) => (Some(v), Some("bool".to_string())),
        // Complex ids are redacted: only the type tag is logged, not the
        // raw object/array content.
        Some(Value::Object(_)) => (None, Some("object".to_string())),
        Some(Value::Array(_)) => (None, Some("array".to_string())),
    }
}

/// Append-only JSONL audit log writer.
pub struct AuditLog {
    file: File,
}

impl AuditLog {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!("creating audit log directory {}", parent.display())
                })?;
            }
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("opening audit log file {}", path.display()))?;
        Ok(AuditLog { file })
    }

    pub fn write(&mut self, record: &AuditRecord) -> Result<()> {
        let line = serde_json::to_string(record).context("serializing audit record")?;
        writeln!(self.file, "{line}").context("writing audit record")?;
        self.file.flush().context("flushing audit log")
    }
}

/// Extract only the argument key names from a tool-call `arguments` object.
/// Values are intentionally dropped so secrets never reach the audit log.
pub fn redacted_argument_keys(arguments: Option<&Value>) -> Vec<String> {
    match arguments {
        Some(Value::Object(map)) => {
            let mut keys: Vec<String> = map.keys().map(|key| redacted_audit_key(key)).collect();
            keys.sort();
            keys
        }
        _ => Vec::new(),
    }
}

/// Extract only the top-level key names from a JSON-RPC `params` object.
/// Values are intentionally dropped so sensitive param content (prompt text,
/// resource URIs, message bodies, file contents, secrets) never reaches the
/// audit log.
pub fn redacted_param_keys(params: Option<&Value>) -> Vec<String> {
    match params {
        Some(Value::Object(map)) => {
            let mut keys: Vec<String> = map.keys().map(|key| redacted_audit_key(key)).collect();
            keys.sort();
            keys
        }
        _ => Vec::new(),
    }
}

fn redacted_audit_key(key: &str) -> String {
    if inspect_policy_identifier(key).is_some() {
        "<unicode-denied-key>".to_string()
    } else {
        key.to_string()
    }
}

fn rfc3339_utc_now() -> String {
    let unix_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    rfc3339_utc_from_unix(unix_seconds)
}

/// Format unix seconds as RFC 3339 UTC without external date dependencies,
/// using the standard civil-from-days conversion.
fn rfc3339_utc_from_unix(unix_seconds: u64) -> String {
    let days = unix_seconds / 86_400;
    let second_of_day = unix_seconds % 86_400;
    let (year, month, day) = civil_from_days(days as i64);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        second_of_day / 3600,
        (second_of_day % 3600) / 60,
        second_of_day % 60
    )
}

fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn formats_known_unix_timestamps() {
        assert_eq!(rfc3339_utc_from_unix(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc_from_unix(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339_utc_from_unix(1_767_225_599), "2025-12-31T23:59:59Z");
        assert_eq!(rfc3339_utc_from_unix(1_783_000_000), "2026-07-02T13:46:40Z");
    }

    #[test]
    fn argument_keys_drop_values() {
        let arguments = json!({
            "path": "/home/user/notes.txt",
            "api_token": "«redacted:sk-…»",
        });
        let keys = redacted_argument_keys(Some(&arguments));
        assert_eq!(keys, vec!["api_token", "path"]);
    }

    #[test]
    fn argument_keys_redact_unicode_key_names() {
        let bidi_key = "sec\u{202E}ret";
        let zero_width_key = format!("pa{}th", "\u{200B}");
        let non_ascii_key = "secre\u{0442}";
        let arguments = json!({
            "path": "/home/user/notes.txt",
            bidi_key: "bidi",
            zero_width_key.as_str(): "zero-width",
            non_ascii_key: "non-ascii",
        });

        let keys = redacted_argument_keys(Some(&arguments));
        assert_eq!(
            keys,
            vec![
                "<unicode-denied-key>",
                "<unicode-denied-key>",
                "<unicode-denied-key>",
                "path",
            ]
        );
        let line = serde_json::to_string(&keys).unwrap();
        assert!(!line.contains(bidi_key));
        assert!(!line.contains(&zero_width_key));
        assert!(!line.contains(non_ascii_key));
        assert!(!line.contains("sec\\u202eret"));
        assert!(!line.contains("pa\\u200bth"));
    }

    #[test]
    fn argument_keys_handle_missing_or_non_object() {
        assert!(redacted_argument_keys(None).is_empty());
        assert!(redacted_argument_keys(Some(&json!("string"))).is_empty());
        assert!(redacted_argument_keys(Some(&json!(["a", "b"]))).is_empty());
    }

    #[test]
    fn param_keys_drop_values() {
        let params = json!({
            "uri": "file:///etc/passwd",
            "prompt": "system prompt text here",
        });
        let keys = redacted_param_keys(Some(&params));
        assert_eq!(keys, vec!["prompt", "uri"]);
    }

    #[test]
    fn param_keys_redact_unicode_key_names() {
        let bidi_key = "pro\u{202E}mpt";
        let zero_width_key = format!("u{}ri", "\u{200B}");
        let non_ascii_key = "ur\u{0456}";
        let params = json!({
            "uri": "file:///etc/passwd",
            bidi_key: "bidi",
            zero_width_key.as_str(): "zero-width",
            non_ascii_key: "non-ascii",
        });

        let keys = redacted_param_keys(Some(&params));
        assert_eq!(
            keys,
            vec![
                "<unicode-denied-key>",
                "<unicode-denied-key>",
                "<unicode-denied-key>",
                "uri",
            ]
        );
        let line = serde_json::to_string(&keys).unwrap();
        assert!(!line.contains(bidi_key));
        assert!(!line.contains(&zero_width_key));
        assert!(!line.contains(non_ascii_key));
        assert!(!line.contains("pro\\u202empt"));
        assert!(!line.contains("u\\u200bri"));
    }

    #[test]
    fn param_keys_handle_missing_or_non_object() {
        assert!(redacted_param_keys(None).is_empty());
        assert!(redacted_param_keys(Some(&json!(42))).is_empty());
        assert!(redacted_param_keys(Some(&json!([1]))).is_empty());
    }

    #[test]
    fn audit_record_serializes_without_argument_values() {
        let record = AuditRecord::tool_call(
            "minimal-mcp-boundary",
            "default",
            Some(json!(7)),
            Some("filesystem.read"),
            vec!["api_token".to_string(), "path".to_string()],
            Decision::Deny,
            "tool name is in the policy deny list",
        );
        let line = serde_json::to_string(&record).unwrap();
        assert!(line.contains("\"decision\":\"deny\""));
        assert!(line.contains("\"tool\":\"filesystem.read\""));
        assert!(line.contains("\"api_token\""));
        assert!(!line.contains("«redacted:sk-…»"));
    }

    #[test]
    fn audit_record_serializes_without_param_values() {
        let record = AuditRecord::method_decision(
            "test-policy",
            "default",
            "resources/read",
            Some(json!("req-1")),
            vec!["uri".to_string()],
            Decision::Deny,
            "method is not allowed by policy",
        );
        let line = serde_json::to_string(&record).unwrap();
        assert!(line.contains("\"event\":\"method_decision\""));
        assert!(line.contains("\"method\":\"resources/read\""));
        assert!(line.contains("\"request_id_type\":\"string\""));
        assert!(line.contains("\"param_keys\":[\"uri\"]"));
        assert!(!line.contains("file:///etc/passwd"));
        assert!(!line.contains("system prompt text"));
    }

    #[test]
    fn request_id_type_is_correct() {
        for (id, expected_value, expected_type) in [
            (None, None, "missing"),
            (Some(Value::Null), Some(Value::Null), "null"),
            (Some(json!(42)), Some(json!(42)), "number"),
            (Some(json!("abc")), Some(json!("abc")), "string"),
            (Some(json!(true)), Some(json!(true)), "bool"),
            // Complex ids are redacted: type is logged but value is not.
            (Some(json!({"k": 1})), None, "object"),
            (Some(json!([1, 2])), None, "array"),
        ] {
            let (value, id_type) = split_request_id(id);
            assert_eq!(value, expected_value);
            assert_eq!(id_type.as_deref(), Some(expected_type));
        }
    }
}
