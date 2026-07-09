use anyhow::{Context, Result};
use etherfence_core::{
    read_bounded_text_file, AgentKind, EnvVar, InventoryItem, McpServer, MAX_CONFIG_FILE_BYTES,
    PARSE_ERROR_EVIDENCE_PREFIX,
};
use serde_json::Value as JsonValue;
use std::env;
use std::path::{Path, PathBuf};
use toml::Value as TomlValue;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfigFormat {
    Json,
    Toml,
    PresenceOnly,
}

#[derive(Debug, Clone, Copy)]
struct Candidate {
    agent: AgentKind,
    relative_path: &'static str,
    format: ConfigFormat,
}

const CANDIDATES: &[Candidate] = &[
    Candidate {
        agent: AgentKind::ClaudeCode,
        relative_path: ".claude.json",
        format: ConfigFormat::Json,
    },
    Candidate {
        agent: AgentKind::ClaudeCode,
        relative_path: ".claude/settings.json",
        format: ConfigFormat::Json,
    },
    Candidate {
        agent: AgentKind::ClaudeCode,
        relative_path: "AppData/Roaming/Claude/settings.json",
        format: ConfigFormat::Json,
    },
    Candidate {
        agent: AgentKind::ClaudeCode,
        relative_path: "Claude/settings.json",
        format: ConfigFormat::Json,
    },
    Candidate {
        agent: AgentKind::Cursor,
        relative_path: ".cursor/mcp.json",
        format: ConfigFormat::Json,
    },
    Candidate {
        agent: AgentKind::Cursor,
        relative_path: ".cursor/settings.json",
        format: ConfigFormat::Json,
    },
    Candidate {
        agent: AgentKind::Cursor,
        relative_path: "AppData/Roaming/Cursor/User/mcp.json",
        format: ConfigFormat::Json,
    },
    Candidate {
        agent: AgentKind::Cursor,
        relative_path: "Cursor/User/mcp.json",
        format: ConfigFormat::Json,
    },
    Candidate {
        agent: AgentKind::VsCode,
        relative_path: ".vscode/mcp.json",
        format: ConfigFormat::Json,
    },
    Candidate {
        agent: AgentKind::VsCode,
        relative_path: ".vscode/settings.json",
        format: ConfigFormat::Json,
    },
    Candidate {
        agent: AgentKind::VsCode,
        relative_path: ".config/Code/User/settings.json",
        format: ConfigFormat::Json,
    },
    Candidate {
        agent: AgentKind::VsCode,
        relative_path: "AppData/Roaming/Code/User/settings.json",
        format: ConfigFormat::Json,
    },
    Candidate {
        agent: AgentKind::VsCode,
        relative_path: "Code/User/settings.json",
        format: ConfigFormat::Json,
    },
    Candidate {
        agent: AgentKind::Windsurf,
        relative_path: ".windsurf/mcp.json",
        format: ConfigFormat::Json,
    },
    Candidate {
        agent: AgentKind::Windsurf,
        relative_path: ".codeium/windsurf/mcp_config.json",
        format: ConfigFormat::Json,
    },
    Candidate {
        agent: AgentKind::Windsurf,
        relative_path: "AppData/Roaming/Windsurf/User/mcp_config.json",
        format: ConfigFormat::Json,
    },
    Candidate {
        agent: AgentKind::Windsurf,
        relative_path: "Windsurf/User/mcp_config.json",
        format: ConfigFormat::Json,
    },
    Candidate {
        agent: AgentKind::GeminiCli,
        relative_path: ".gemini/settings.json",
        format: ConfigFormat::Json,
    },
    Candidate {
        agent: AgentKind::GeminiCli,
        relative_path: "AppData/Roaming/Gemini/settings.json",
        format: ConfigFormat::Json,
    },
    Candidate {
        agent: AgentKind::GeminiCli,
        relative_path: "Gemini/settings.json",
        format: ConfigFormat::Json,
    },
    Candidate {
        agent: AgentKind::CodexCli,
        relative_path: ".codex/config.toml",
        format: ConfigFormat::Toml,
    },
    Candidate {
        agent: AgentKind::CodexCli,
        relative_path: "AppData/Roaming/Codex/config.toml",
        format: ConfigFormat::Toml,
    },
    Candidate {
        agent: AgentKind::CodexCli,
        relative_path: "Codex/config.toml",
        format: ConfigFormat::Toml,
    },
    Candidate {
        agent: AgentKind::Tirith,
        relative_path: ".tirith/config.toml",
        format: ConfigFormat::PresenceOnly,
    },
    Candidate {
        agent: AgentKind::Tirith,
        relative_path: ".tirith/lockfile.json",
        format: ConfigFormat::PresenceOnly,
    },
];

pub fn default_scan_root() -> PathBuf {
    default_scan_roots()
        .into_iter()
        .next()
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn default_scan_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    push_env_path(&mut roots, "HOME");
    push_env_path(&mut roots, "USERPROFILE");
    push_env_path(&mut roots, "APPDATA");
    push_env_path(&mut roots, "LOCALAPPDATA");
    if roots.is_empty() {
        roots.push(PathBuf::from("."));
    }
    roots
}

fn push_env_path(roots: &mut Vec<PathBuf>, name: &str) {
    let Some(value) = env::var_os(name) else {
        return;
    };
    if value.is_empty() {
        return;
    }
    let path = PathBuf::from(value);
    if !roots.iter().any(|existing| existing == &path) {
        roots.push(path);
    }
}

pub fn discover(root: &Path) -> Vec<InventoryItem> {
    let mut items = discover_candidates(root);
    append_tirith_binary(&mut items);
    items
}

pub fn discover_roots(roots: &[PathBuf]) -> Vec<InventoryItem> {
    let mut items = Vec::new();
    for root in roots {
        items.extend(discover_candidates(root));
    }
    append_tirith_binary(&mut items);
    items
}

fn discover_candidates(root: &Path) -> Vec<InventoryItem> {
    let mut items = Vec::new();
    for candidate in CANDIDATES {
        let path = root.join(candidate.relative_path);
        if !path.is_file() {
            continue;
        }
        match parse_candidate(root, &path, *candidate) {
            Ok(item) => items.push(item),
            Err(err) => items.push(InventoryItem {
                agent: candidate.agent,
                config_path: display_path(root, &path),
                mcp_servers: Vec::new(),
                evidence: vec![parse_error_evidence(&err)],
            }),
        }
    }
    items
}

fn append_tirith_binary(items: &mut Vec<InventoryItem>) {
    if tirith_binary_present() {
        items.push(InventoryItem {
            agent: AgentKind::Tirith,
            config_path: "PATH:tirith".to_string(),
            mcp_servers: Vec::new(),
            evidence: vec!["tirith binary found on PATH".to_string()],
        });
    }
}

// `path` is derived from a known, fixed set of agent config file locations
// under the scanned root (a trusted-operator-provided directory), not from
// an untrusted caller; see the doc comment on `read_bounded_text_file` for
// the CLI-vs-future-API path trust model this crate follows.
fn parse_candidate(root: &Path, path: &Path, candidate: Candidate) -> Result<InventoryItem> {
    let content = read_bounded_text_file(path, MAX_CONFIG_FILE_BYTES)
        .with_context(|| format!("reading {}", path.display()))?;
    let mut item = InventoryItem {
        agent: candidate.agent,
        config_path: display_path(root, path),
        mcp_servers: Vec::new(),
        evidence: Vec::new(),
    };
    match candidate.format {
        ConfigFormat::Json => {
            let value: JsonValue = serde_json::from_str(&content).context("parsing JSON")?;
            let parsed = parse_json_mcp_servers(&value);
            item.mcp_servers = parsed.servers;
            item.evidence.extend(parsed.warnings);
        }
        ConfigFormat::Toml => {
            let value: TomlValue = content.parse::<TomlValue>().context("parsing TOML")?;
            let parsed = parse_toml_mcp_servers(&value);
            item.mcp_servers = parsed.servers;
            item.evidence.extend(parsed.warnings);
        }
        ConfigFormat::PresenceOnly => item.evidence.push("Tirith file present".to_string()),
    }
    item.mcp_servers.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(item)
}

/// Deterministic, single-line parse-error evidence. TOML errors in particular
/// render as multi-line spans, so whitespace is collapsed and the message capped.
fn parse_error_evidence(err: &anyhow::Error) -> String {
    let mut message = format!("{err:#}")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    const MAX_LEN: usize = 200;
    if message.len() > MAX_LEN {
        let mut end = MAX_LEN;
        while !message.is_char_boundary(end) {
            end -= 1;
        }
        message.truncate(end);
        message.push_str("...");
    }
    format!("{PARSE_ERROR_EVIDENCE_PREFIX} {message}")
}

fn display_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .map(|p| format!("~/{}", normalize_path_string(&p.display().to_string())))
        .unwrap_or_else(|_| normalize_path_string(&path.display().to_string()))
}

fn normalize_path_string(path: &str) -> String {
    path.replace('\\', "/")
}

#[derive(Debug, Default)]
struct ParsedServers {
    servers: Vec<McpServer>,
    warnings: Vec<String>,
}

fn parse_json_mcp_servers(value: &JsonValue) -> ParsedServers {
    let mut parsed = ParsedServers::default();
    match find_json_key(value, "mcpServers") {
        Some(JsonValue::Object(map)) => {
            for (name, server) in map {
                if !server.is_object() {
                    parsed.warnings.push(format!(
                        "mcpServers entry {name:?} is not a JSON object; recorded name only"
                    ));
                }
                parsed.servers.push(json_server(name, server));
            }
        }
        Some(JsonValue::Null) | None => {}
        Some(_) => parsed
            .warnings
            .push("mcpServers present but not a JSON object; ignored".to_string()),
    }
    parsed
}

fn find_json_key<'a>(value: &'a JsonValue, key: &str) -> Option<&'a JsonValue> {
    match value {
        JsonValue::Object(map) => {
            if let Some(found) = map.get(key) {
                return Some(found);
            }
            map.values().find_map(|child| find_json_key(child, key))
        }
        JsonValue::Array(values) => values.iter().find_map(|child| find_json_key(child, key)),
        _ => None,
    }
}

fn json_server(name: &str, value: &JsonValue) -> McpServer {
    let command = string_field(value, "command");
    let url = string_field(value, "url");
    let args = value
        .get("args")
        .and_then(JsonValue::as_array)
        .map(|values| values.iter().filter_map(json_to_string).collect())
        .unwrap_or_default();
    let env = value
        .get("env")
        .and_then(JsonValue::as_object)
        .map(|env| {
            env.iter()
                .map(|(name, value)| EnvVar {
                    name: name.clone(),
                    value_hint: json_to_string(value).map(redact_env_value),
                })
                .collect()
        })
        .unwrap_or_default();
    McpServer {
        name: name.to_string(),
        command,
        args,
        env,
        url,
    }
}

fn string_field(value: &JsonValue, key: &str) -> Option<String> {
    value.get(key).and_then(json_to_string)
}

fn json_to_string(value: &JsonValue) -> Option<String> {
    value.as_str().map(ToOwned::to_owned).or_else(|| {
        if value.is_number() || value.is_boolean() {
            Some(value.to_string())
        } else {
            None
        }
    })
}

fn parse_toml_mcp_servers(value: &TomlValue) -> ParsedServers {
    let mut parsed = ParsedServers::default();
    match value.get("mcp_servers") {
        Some(TomlValue::Table(table)) => {
            for (name, server) in table {
                if !server.is_table() {
                    parsed.warnings.push(format!(
                        "mcp_servers entry {name:?} is not a TOML table; recorded name only"
                    ));
                }
                parsed.servers.push(toml_server(name, server));
            }
        }
        None => {}
        Some(_) => parsed
            .warnings
            .push("mcp_servers present but not a TOML table; ignored".to_string()),
    }
    parsed
}

fn toml_server(name: &str, value: &TomlValue) -> McpServer {
    let command = value.get("command").and_then(toml_to_string);
    let url = value.get("url").and_then(toml_to_string);
    let args = value
        .get("args")
        .and_then(TomlValue::as_array)
        .map(|values| values.iter().filter_map(toml_to_string).collect())
        .unwrap_or_default();
    let env = value
        .get("env")
        .and_then(TomlValue::as_table)
        .map(|env| {
            env.iter()
                .map(|(name, value)| EnvVar {
                    name: name.clone(),
                    value_hint: toml_to_string(value).map(redact_env_value),
                })
                .collect()
        })
        .unwrap_or_default();
    McpServer {
        name: name.to_string(),
        command,
        args,
        env,
        url,
    }
}

fn toml_to_string(value: &TomlValue) -> Option<String> {
    match value {
        TomlValue::String(text) => Some(text.clone()),
        TomlValue::Integer(number) => Some(number.to_string()),
        TomlValue::Float(number) => Some(number.to_string()),
        TomlValue::Boolean(flag) => Some(flag.to_string()),
        _ => None,
    }
}

fn redact_env_value(value: impl AsRef<str>) -> String {
    let value = value.as_ref();
    if value.is_empty() {
        "<empty>".to_string()
    } else {
        "<set>".to_string()
    }
}

fn tirith_binary_present() -> bool {
    let Some(path_var) = env::var_os("PATH") else {
        return false;
    };
    env::split_paths(&path_var).any(|dir| {
        let candidate = dir.join("tirith");
        let windows_candidate = dir.join("tirith.exe");
        candidate.is_file() || windows_candidate.is_file()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovers_linux_fixture_configs() {
        let root = Path::new("../../tests/fixtures/home");
        let items = discover(root);
        assert!(items.iter().any(|i| i.agent == AgentKind::ClaudeCode));
        assert!(items.iter().any(|i| i.agent == AgentKind::Cursor));
        assert!(items.iter().any(|i| i.agent == AgentKind::VsCode));
        assert!(items.iter().any(|i| i.agent == AgentKind::Windsurf));
        assert!(items.iter().any(|i| i.agent == AgentKind::GeminiCli));
        assert!(items.iter().any(|i| i.agent == AgentKind::Tirith));
    }

    #[test]
    fn discovers_windows_fixture_configs() {
        let root = Path::new("../../tests/fixtures/windows-home");
        let items = discover(root);
        assert!(items.iter().any(|i| i.agent == AgentKind::ClaudeCode));
        assert!(items.iter().any(|i| i.agent == AgentKind::Cursor));
        assert!(items.iter().any(|i| i.agent == AgentKind::VsCode));
        assert!(items.iter().any(|i| i.agent == AgentKind::Windsurf));
        assert!(items.iter().any(|i| i.agent == AgentKind::GeminiCli));
        assert!(items.iter().any(|i| i.agent == AgentKind::CodexCli));
        assert!(items
            .iter()
            .any(|i| i.config_path == "~/AppData/Roaming/Code/User/settings.json"));
    }

    #[test]
    fn parses_codex_toml_mcp_servers() {
        let root = Path::new("../../tests/fixtures/home");
        let items = discover(root);
        let codex = items
            .iter()
            .find(|i| i.agent == AgentKind::CodexCli)
            .expect("codex fixture");
        assert_eq!(codex.mcp_servers[0].name, "filesystem");
        assert_eq!(codex.mcp_servers[0].env[0].name, "FILESYSTEM_TOKEN");
    }

    #[test]
    fn display_path_normalizes_separators() {
        assert_eq!(
            normalize_path_string(r"C:\Users\example\AppData\Roaming\Code\User\settings.json"),
            "C:/Users/example/AppData/Roaming/Code/User/settings.json"
        );
    }

    #[test]
    fn minimal_fixture_configs_have_no_mcp_servers_and_no_parse_errors() {
        let root = Path::new("../../tests/fixtures/minimal-home");
        let items = discover(root);
        assert_eq!(items.len(), 5);
        for item in &items {
            assert!(
                item.mcp_servers.is_empty(),
                "unexpected servers in {}",
                item.config_path
            );
            assert!(
                !item
                    .evidence
                    .iter()
                    .any(|e| e.starts_with(PARSE_ERROR_EVIDENCE_PREFIX)),
                "unexpected parse error in {}",
                item.config_path
            );
        }
    }

    #[test]
    fn multi_fixture_servers_are_sorted_by_name_with_unknown_fields_ignored() {
        let root = Path::new("../../tests/fixtures/multi-home");
        let items = discover(root);
        let claude = items
            .iter()
            .find(|i| i.agent == AgentKind::ClaudeCode)
            .expect("claude fixture");
        let names: Vec<&str> = claude.mcp_servers.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["fetch", "filesystem", "github"]);
        assert!(claude.evidence.is_empty());

        let windsurf = items
            .iter()
            .find(|i| i.agent == AgentKind::Windsurf)
            .expect("windsurf fixture");
        let names: Vec<&str> = windsurf
            .mcp_servers
            .iter()
            .map(|s| s.name.as_str())
            .collect();
        assert_eq!(names, ["browser", "repo-context"]);
    }

    #[test]
    fn multi_fixture_url_only_server_is_recorded() {
        let root = Path::new("../../tests/fixtures/multi-home");
        let items = discover(root);
        let vscode = items
            .iter()
            .find(|i| i.agent == AgentKind::VsCode)
            .expect("vscode fixture");
        let server = &vscode.mcp_servers[0];
        assert_eq!(server.name, "remote-docs");
        assert_eq!(server.command, None);
        assert_eq!(server.url.as_deref(), Some("https://example.invalid/mcp"));
    }

    #[test]
    fn toml_args_and_env_accept_numbers_and_booleans_like_json() {
        let root = Path::new("../../tests/fixtures/multi-home");
        let items = discover(root);
        let codex = items
            .iter()
            .find(|i| i.agent == AgentKind::CodexCli)
            .expect("codex fixture");
        let search = codex
            .mcp_servers
            .iter()
            .find(|s| s.name == "search")
            .expect("search server");
        assert_eq!(search.args, ["web-search-mcp", "8080", "true"]);
        let timeout = search
            .env
            .iter()
            .find(|e| e.name == "SEARCH_TIMEOUT")
            .expect("numeric env value");
        assert_eq!(timeout.value_hint.as_deref(), Some("<set>"));
    }

    #[test]
    fn malformed_fixture_configs_are_inventoried_without_panics() {
        let root = Path::new("../../tests/fixtures/malformed-home");
        let items = discover(root);
        assert_eq!(items.len(), 6);

        let claude = items
            .iter()
            .find(|i| i.agent == AgentKind::ClaudeCode)
            .expect("claude fixture");
        assert!(claude.mcp_servers.is_empty());
        assert!(claude.evidence[0].starts_with(PARSE_ERROR_EVIDENCE_PREFIX));
        assert!(claude.evidence[0].contains("parsing JSON"));

        let codex = items
            .iter()
            .find(|i| i.agent == AgentKind::CodexCli)
            .expect("codex fixture");
        assert!(codex.mcp_servers.is_empty());
        assert!(codex.evidence[0].starts_with(PARSE_ERROR_EVIDENCE_PREFIX));
        assert!(codex.evidence[0].contains("parsing TOML"));
        assert!(
            !codex.evidence[0].contains('\n'),
            "parse error evidence must be single-line"
        );
    }

    #[test]
    fn malformed_fixture_wrong_shapes_degrade_gracefully() {
        let root = Path::new("../../tests/fixtures/malformed-home");
        let items = discover(root);

        let cursor = items
            .iter()
            .find(|i| i.agent == AgentKind::Cursor)
            .expect("cursor fixture");
        assert!(cursor.mcp_servers.is_empty());
        assert!(cursor
            .evidence
            .iter()
            .any(|e| e.contains("not a JSON object")));

        let vscode = items
            .iter()
            .find(|i| i.agent == AgentKind::VsCode)
            .expect("vscode fixture");
        let names: Vec<&str> = vscode.mcp_servers.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["bad-args", "broken"]);
        let bad_args = &vscode.mcp_servers[0];
        assert!(bad_args.args.is_empty(), "non-array args are ignored");
        assert!(bad_args.env.is_empty(), "non-object env is ignored");

        let gemini = items
            .iter()
            .find(|i| i.agent == AgentKind::GeminiCli)
            .expect("gemini fixture");
        assert!(gemini.mcp_servers.is_empty());
        assert!(
            gemini.evidence.is_empty(),
            "null mcpServers is not a warning"
        );

        let windsurf = items
            .iter()
            .find(|i| i.agent == AgentKind::Windsurf)
            .expect("windsurf fixture");
        let server = &windsurf.mcp_servers[0];
        assert_eq!(server.args, ["1", "true", "script.js"]);
        let null_env = server
            .env
            .iter()
            .find(|e| e.name == "API_TOKEN")
            .expect("null env entry");
        assert_eq!(null_env.value_hint, None);
    }
}
