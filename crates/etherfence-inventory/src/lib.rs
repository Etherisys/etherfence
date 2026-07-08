use anyhow::{Context, Result};
use etherfence_core::{AgentKind, EnvVar, InventoryItem, McpServer};
use serde_json::Value as JsonValue;
use std::env;
use std::fs;
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
                evidence: vec![format!("parse error: {err}")],
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

fn parse_candidate(root: &Path, path: &Path, candidate: Candidate) -> Result<InventoryItem> {
    let content =
        fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut item = InventoryItem {
        agent: candidate.agent,
        config_path: display_path(root, path),
        mcp_servers: Vec::new(),
        evidence: Vec::new(),
    };
    match candidate.format {
        ConfigFormat::Json => {
            let value: JsonValue = serde_json::from_str(&content).context("parsing JSON")?;
            item.mcp_servers = parse_json_mcp_servers(&value);
        }
        ConfigFormat::Toml => {
            let value: TomlValue = content.parse::<TomlValue>().context("parsing TOML")?;
            item.mcp_servers = parse_toml_mcp_servers(&value);
        }
        ConfigFormat::PresenceOnly => item.evidence.push("Tirith file present".to_string()),
    }
    Ok(item)
}

fn display_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .map(|p| format!("~/{}", normalize_path_string(&p.display().to_string())))
        .unwrap_or_else(|_| normalize_path_string(&path.display().to_string()))
}

fn normalize_path_string(path: &str) -> String {
    path.replace('\\', "/")
}

fn parse_json_mcp_servers(value: &JsonValue) -> Vec<McpServer> {
    let Some(map) = find_json_key(value, "mcpServers").and_then(JsonValue::as_object) else {
        return Vec::new();
    };
    map.iter()
        .map(|(name, server)| json_server(name, server))
        .collect()
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

fn parse_toml_mcp_servers(value: &TomlValue) -> Vec<McpServer> {
    let Some(table) = value.get("mcp_servers").and_then(TomlValue::as_table) else {
        return Vec::new();
    };
    table
        .iter()
        .map(|(name, server)| toml_server(name, server))
        .collect()
}

fn toml_server(name: &str, value: &TomlValue) -> McpServer {
    let command = value
        .get("command")
        .and_then(TomlValue::as_str)
        .map(ToOwned::to_owned);
    let url = value
        .get("url")
        .and_then(TomlValue::as_str)
        .map(ToOwned::to_owned);
    let args = value
        .get("args")
        .and_then(TomlValue::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let env = value
        .get("env")
        .and_then(TomlValue::as_table)
        .map(|env| {
            env.iter()
                .map(|(name, value)| EnvVar {
                    name: name.clone(),
                    value_hint: value.as_str().map(redact_env_value),
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
}
