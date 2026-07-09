use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::policy::Decision;

/// One JSONL audit record. Request metadata is redacted before it gets here:
/// only tool-call argument key names are recorded, never argument values.
#[derive(Debug, Clone, Serialize)]
pub struct AuditRecord {
    pub ts: String,
    pub event: String,
    pub policy: Option<String>,
    pub method: Option<String>,
    pub request_id: Option<Value>,
    pub tool: Option<String>,
    pub argument_keys: Vec<String>,
    pub decision: String,
    pub reason: String,
}

impl AuditRecord {
    pub fn tool_call(
        policy_name: &str,
        method: &str,
        request_id: Option<Value>,
        tool: Option<&str>,
        argument_keys: Vec<String>,
        decision: Decision,
        reason: &str,
    ) -> Self {
        AuditRecord {
            ts: rfc3339_utc_now(),
            event: "tool_call_decision".to_string(),
            policy: Some(policy_name.to_string()),
            method: Some(method.to_string()),
            request_id,
            tool: tool.map(str::to_string),
            argument_keys,
            decision: decision.as_str().to_string(),
            reason: reason.to_string(),
        }
    }

    pub fn policy_error(reason: &str) -> Self {
        AuditRecord {
            ts: rfc3339_utc_now(),
            event: "policy_load_error".to_string(),
            policy: None,
            method: None,
            request_id: None,
            tool: None,
            argument_keys: Vec::new(),
            decision: Decision::PolicyError.as_str().to_string(),
            reason: reason.to_string(),
        }
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
            let mut keys: Vec<String> = map.keys().cloned().collect();
            keys.sort();
            keys
        }
        _ => Vec::new(),
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
            "api_token": "sk-super-secret-value",
        });
        let keys = redacted_argument_keys(Some(&arguments));
        assert_eq!(keys, vec!["api_token", "path"]);
    }

    #[test]
    fn argument_keys_handle_missing_or_non_object() {
        assert!(redacted_argument_keys(None).is_empty());
        assert!(redacted_argument_keys(Some(&json!("string"))).is_empty());
        assert!(redacted_argument_keys(Some(&json!(["a", "b"]))).is_empty());
    }

    #[test]
    fn audit_record_serializes_without_argument_values() {
        let record = AuditRecord::tool_call(
            "minimal-mcp-boundary",
            "tools/call",
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
        assert!(!line.contains("sk-super-secret-value"));
    }
}
