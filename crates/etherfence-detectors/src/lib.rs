use etherfence_core::{AgentKind, Finding, FindingKind, InventoryItem, McpServer, Severity};

pub fn analyze(items: &[InventoryItem]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for item in items {
        if item.agent == AgentKind::Tirith {
            findings.push(finding(
                Severity::Info,
                FindingKind::TirithPresence,
                item,
                "Tirith presence detected; EtherFence treats Tirith as complementary terminal-command protection.",
                item.evidence.clone(),
            ));
            continue;
        }
        for server in &item.mcp_servers {
            findings.push(finding(
                Severity::Low,
                FindingKind::McpServerConfigured,
                item,
                &format!("MCP server '{}' is configured.", server.name),
                server_evidence(server),
            ));
            if let Some(evidence) = broad_filesystem_evidence(server) {
                findings.push(finding(
                    Severity::High,
                    FindingKind::BroadFilesystemAccess,
                    item,
                    &format!(
                        "MCP server '{}' hints at broad filesystem access.",
                        server.name
                    ),
                    evidence,
                ));
            }
            if let Some(evidence) = risky_command_evidence(server) {
                findings.push(finding(
                    Severity::Medium,
                    FindingKind::RiskyCommandToolHint,
                    item,
                    &format!(
                        "MCP server '{}' appears shell- or command-capable.",
                        server.name
                    ),
                    evidence,
                ));
            }
            if let Some(evidence) = network_evidence(server) {
                findings.push(finding(
                    Severity::Medium,
                    FindingKind::NetworkCapableToolHint,
                    item,
                    &format!("MCP server '{}' hints at network capability.", server.name),
                    evidence,
                ));
            }
            if !server.env.is_empty() {
                findings.push(finding(
                    Severity::Low,
                    FindingKind::ExposedMcpEnvironment,
                    item,
                    &format!(
                        "MCP server '{}' defines environment variables.",
                        server.name
                    ),
                    server.env.iter().map(|env| env.name.clone()).collect(),
                ));
            }
            let secret_env: Vec<String> = server
                .env
                .iter()
                .filter(|env| secret_looking_name(&env.name))
                .map(|env| env.name.clone())
                .collect();
            if !secret_env.is_empty() {
                findings.push(finding(
                    Severity::Medium,
                    FindingKind::SecretLookingEnvName,
                    item,
                    &format!(
                        "MCP server '{}' uses secret-looking environment variable names.",
                        server.name
                    ),
                    secret_env,
                ));
            }
        }
    }
    findings
}

fn finding(
    severity: Severity,
    kind: FindingKind,
    item: &InventoryItem,
    message: &str,
    evidence: Vec<String>,
) -> Finding {
    Finding {
        severity,
        kind,
        agent: item.agent,
        config_path: item.config_path.clone(),
        message: message.to_string(),
        evidence,
    }
}

fn server_evidence(server: &McpServer) -> Vec<String> {
    let mut evidence = vec![format!("server={}", server.name)];
    if let Some(command) = &server.command {
        evidence.push(format!("command={command}"));
    }
    if let Some(url) = &server.url {
        evidence.push(format!("url={url}"));
    }
    evidence
}

fn broad_filesystem_evidence(server: &McpServer) -> Option<Vec<String>> {
    let haystack = values(server);
    let matches: Vec<String> = haystack
        .into_iter()
        .filter(|value| {
            let lower = value.to_ascii_lowercase();
            lower == "/"
                || lower == "/home"
                || lower == "/home/user"
                || lower.contains("/home/user")
                || lower.contains("--allow-root")
                || lower.contains("filesystem")
                || lower.contains("file-system")
                || lower.contains("read_file")
                || lower.contains("write_file")
        })
        .collect();
    (!matches.is_empty()).then_some(matches)
}

fn risky_command_evidence(server: &McpServer) -> Option<Vec<String>> {
    let needles = [
        "bash",
        "sh",
        "zsh",
        "fish",
        "powershell",
        "pwsh",
        "cmd.exe",
        "shell",
        "terminal",
        "exec",
        "spawn",
        "command",
    ];
    matching_values(server, &needles)
}

fn network_evidence(server: &McpServer) -> Option<Vec<String>> {
    let needles = [
        "http://",
        "https://",
        "fetch",
        "browser",
        "playwright",
        "puppeteer",
        "curl",
        "wget",
        "network",
        "web-search",
        "search",
    ];
    matching_values(server, &needles)
}

fn matching_values(server: &McpServer, needles: &[&str]) -> Option<Vec<String>> {
    let matches: Vec<String> = values(server)
        .into_iter()
        .filter(|value| {
            let lower = value.to_ascii_lowercase();
            needles.iter().any(|needle| lower.contains(needle))
        })
        .collect();
    (!matches.is_empty()).then_some(matches)
}

fn values(server: &McpServer) -> Vec<String> {
    let mut values = vec![server.name.clone()];
    if let Some(command) = &server.command {
        values.push(command.clone());
    }
    values.extend(server.args.clone());
    if let Some(url) = &server.url {
        values.push(url.clone());
    }
    values
}

fn secret_looking_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    [
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASS",
        "API_KEY",
        "ACCESS_KEY",
        "PRIVATE_KEY",
        "CREDENTIAL",
    ]
    .iter()
    .any(|needle| upper.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherfence_core::{EnvVar, McpServer};

    #[test]
    fn flags_secret_env_and_filesystem_hint() {
        let item = InventoryItem {
            agent: AgentKind::ClaudeCode,
            config_path: "~/.claude.json".to_string(),
            mcp_servers: vec![McpServer {
                name: "filesystem".to_string(),
                command: Some("npx".to_string()),
                args: vec![
                    "@modelcontextprotocol/server-filesystem".to_string(),
                    "/home/user".to_string(),
                ],
                env: vec![EnvVar {
                    name: "API_TOKEN".to_string(),
                    value_hint: Some("<set>".to_string()),
                }],
                url: None,
            }],
            evidence: Vec::new(),
        };
        let findings = analyze(&[item]);
        assert!(findings
            .iter()
            .any(|f| f.kind == FindingKind::BroadFilesystemAccess));
        assert!(findings
            .iter()
            .any(|f| f.kind == FindingKind::SecretLookingEnvName));
    }
}
