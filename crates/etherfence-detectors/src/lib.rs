use etherfence_core::{
    AgentKind, Finding, FindingCategory, FindingKind, InventoryItem, McpServer, PolicyStatus,
    Severity, PARSE_ERROR_EVIDENCE_PREFIX,
};

pub fn analyze(items: &[InventoryItem]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for item in items {
        if item.agent == AgentKind::Tirith {
            findings.push(tirith_finding(item));
            continue;
        }
        if let Some(evidence) = parse_error_evidence(item) {
            findings.push(config_parse_error(item, evidence));
            continue;
        }
        for server in &item.mcp_servers {
            findings.push(mcp_configured(item, server));
            if let Some(evidence) = broad_filesystem_evidence(server) {
                findings.push(broad_filesystem(item, server, evidence));
            }
            if let Some(evidence) = risky_command_evidence(server) {
                findings.push(shell_capable(item, server, evidence));
            }
            if let Some(evidence) = network_evidence(server) {
                findings.push(network_capable(item, server, evidence));
            }
            if !server.env.is_empty() {
                findings.push(exposed_env(item, server));
            }
            let secret_env: Vec<String> = server
                .env
                .iter()
                .filter(|env| secret_looking_name(&env.name))
                .map(|env| format!("env={}", env.name))
                .collect();
            if !secret_env.is_empty() {
                findings.push(secret_env_name(item, server, secret_env));
            }
        }
    }
    findings
}

struct FindingTemplate {
    id: &'static str,
    title: &'static str,
    severity: Severity,
    kind: FindingKind,
    category: FindingCategory,
    rationale: &'static str,
    impact: &'static str,
    recommendation: &'static str,
}

fn parse_error_evidence(item: &InventoryItem) -> Option<Vec<String>> {
    let matches: Vec<String> = item
        .evidence
        .iter()
        .filter(|value| value.starts_with(PARSE_ERROR_EVIDENCE_PREFIX))
        .cloned()
        .collect();
    (!matches.is_empty()).then_some(matches)
}

fn config_parse_error(item: &InventoryItem, evidence: Vec<String>) -> Finding {
    finding(
        item,
        "config",
        evidence,
        FindingTemplate {
            id: "EF-CFG-001",
            title: "Agent config file could not be parsed",
            severity: Severity::Low,
            kind: FindingKind::ConfigParseError,
            category: FindingCategory::Risk,
            rationale: "A discovered agent configuration file exists but could not be parsed, so its MCP posture could not be inventoried.",
            impact: "MCP servers or risky settings inside an unparseable config file are invisible to posture scanning until the file is fixed.",
            recommendation: "Repair or regenerate the configuration file, then re-run the scan so its contents can be inventoried.",
        },
    )
}

fn mcp_configured(item: &InventoryItem, server: &McpServer) -> Finding {
    finding(
        item,
        &server.name,
        server_evidence(server),
        FindingTemplate {
            id: "EF-MCP-000",
            title: "MCP server configured",
            severity: Severity::Info,
            kind: FindingKind::McpServerConfigured,
            category: FindingCategory::Inventory,
            rationale: "An MCP server is configured for this agent. MCP servers can extend agent access beyond the base application.",
            impact: "This is expected in many developer setups, but each server should be reviewed for least privilege and provenance.",
            recommendation: "Confirm the server is needed, trusted, pinned where practical, and limited to the minimum required permissions.",
        },
    )
}

fn broad_filesystem(item: &InventoryItem, server: &McpServer, evidence: Vec<String>) -> Finding {
    finding(
        item,
        &server.name,
        evidence,
        FindingTemplate {
            id: "EF-MCP-001",
            title: "Broad filesystem access hint",
            severity: Severity::High,
            kind: FindingKind::BroadFilesystemAccess,
            category: FindingCategory::Risk,
            rationale: "The MCP server configuration contains values that look like broad filesystem roots or filesystem-capable tooling.",
            impact: "A compromised or over-permissioned agent workflow could read or modify more local files than intended.",
            recommendation: "Restrict MCP filesystem servers to explicit project directories such as /path/to/project, avoid home-directory or root-level grants, and separate sensitive repos where possible.",
        },
    )
}

fn shell_capable(item: &InventoryItem, server: &McpServer, evidence: Vec<String>) -> Finding {
    finding(
        item,
        &server.name,
        evidence,
        FindingTemplate {
            id: "EF-MCP-002",
            title: "Shell-capable MCP hint",
            severity: Severity::Medium,
            kind: FindingKind::RiskyCommandToolHint,
            category: FindingCategory::Risk,
            rationale: "The MCP server name, command, or arguments include shell/command-execution hints.",
            impact: "Command-capable tools can materially change the host if misused by a prompt injection, confused deputy flow, or untrusted server.",
            recommendation: "Review whether shell capability is necessary. Prefer narrower MCP servers, require human approval for risky actions, and use complementary terminal controls such as Tirith.",
        },
    )
}

fn network_capable(item: &InventoryItem, server: &McpServer, evidence: Vec<String>) -> Finding {
    finding(
        item,
        &server.name,
        evidence,
        FindingTemplate {
            id: "EF-MCP-003",
            title: "Network-capable MCP hint",
            severity: Severity::Medium,
            kind: FindingKind::NetworkCapableToolHint,
            category: FindingCategory::Risk,
            rationale: "The MCP server configuration suggests browser, search, HTTP, or other network-capable behavior.",
            impact: "Network-capable tools may exfiltrate context or fetch untrusted content that can influence an agent.",
            recommendation: "Limit network-capable MCP use to trusted workflows, avoid passing secrets into those servers, and monitor or review outbound-capable tooling.",
        },
    )
}

fn exposed_env(item: &InventoryItem, server: &McpServer) -> Finding {
    finding(
        item,
        &server.name,
        server
            .env
            .iter()
            .map(|env| format!("env={}", env.name))
            .collect(),
        FindingTemplate {
            id: "EF-MCP-004",
            title: "MCP environment variables exposed",
            severity: Severity::Info,
            kind: FindingKind::ExposedMcpEnvironment,
            category: FindingCategory::Inventory,
            rationale: "The MCP server receives environment variables from its agent configuration.",
            impact: "Environment variables increase the data available to the MCP process and may include operational context or credentials.",
            recommendation: "Keep MCP environment values minimal, prefer scoped tokens, and avoid sharing variables that are not required by the server.",
        },
    )
}

fn secret_env_name(item: &InventoryItem, server: &McpServer, evidence: Vec<String>) -> Finding {
    finding(
        item,
        &server.name,
        evidence,
        FindingTemplate {
            id: "EF-SEC-001",
            title: "Secret-looking MCP environment variable name",
            severity: Severity::Medium,
            kind: FindingKind::SecretLookingEnvName,
            category: FindingCategory::Risk,
            rationale: "One or more MCP environment variable names look like they may carry secrets or API credentials.",
            impact: "If the MCP server is over-broad, compromised, or logs its environment, these credentials could be exposed.",
            recommendation: "Use least-privilege tokens, rotate credentials periodically, avoid long-lived personal tokens, and confirm the server does not log environment values.",
        },
    )
}

fn tirith_finding(item: &InventoryItem) -> Finding {
    let is_binary = item.config_path == "PATH:tirith";
    let (id, title, kind, rationale, recommendation) = if is_binary {
        (
            "EF-TIRITH-001",
            "Tirith binary detected",
            FindingKind::TirithBinaryDetected,
            "The Tirith binary appears to be available on PATH.",
            "Treat Tirith as complementary terminal-command protection; verify it is configured for the workflows that need command controls.",
        )
    } else {
        (
            "EF-TIRITH-002",
            "Tirith config detected",
            FindingKind::TirithConfigDetected,
            "A Tirith configuration or lockfile marker was found.",
            "Review the Tirith configuration separately. EtherFence does not duplicate Tirith terminal-command detection.",
        )
    };
    finding(
        item,
        "tirith",
        item.evidence.clone(),
        FindingTemplate {
            id,
            title,
            severity: Severity::Info,
            kind,
            category: FindingCategory::Informational,
            rationale,
            impact: "This is informational and indicates complementary coverage may exist for terminal command controls.",
            recommendation,
        },
    )
}

fn finding(
    item: &InventoryItem,
    target: &str,
    evidence: Vec<String>,
    template: FindingTemplate,
) -> Finding {
    let mut finding = Finding {
        id: template.id.to_string(),
        title: template.title.to_string(),
        severity: template.severity,
        kind: template.kind,
        agent: item.agent,
        target: target.to_string(),
        config_path: item.config_path.clone(),
        rationale: template.rationale.to_string(),
        impact: template.impact.to_string(),
        recommendation: template.recommendation.to_string(),
        references: Vec::new(),
        fingerprint: String::new(),
        baseline_status: etherfence_core::BaselineStatus::NotApplicable,
        policy_status: PolicyStatus::NotApplicable,
        policy_id: None,
        evidence: evidence
            .into_iter()
            .map(|value| value.replace('\\', "/"))
            .collect(),
        category: template.category,
    };
    finding.refresh_fingerprint();
    finding
}

fn server_evidence(server: &McpServer) -> Vec<String> {
    let mut evidence = vec![format!("server={}", server.name)];
    if let Some(command) = &server.command {
        evidence.push(format!(
            "command={}",
            safe_evidence_value("command", command)
        ));
    }
    if let Some(url) = &server.url {
        evidence.push(format!("url={}", safe_evidence_value("url", url)));
    }
    evidence
}

fn broad_filesystem_evidence(server: &McpServer) -> Option<Vec<String>> {
    let matches: Vec<String> = labeled_values(server)
        .into_iter()
        .filter(|(_, value)| {
            let lower = value.to_ascii_lowercase();
            lower == "/"
                || lower == "/home"
                || lower == "/home/user"
                || lower.contains("/home/user")
                || lower == "c:/users/example"
                || lower.contains("c:/users/example")
                || lower.contains("--allow-root")
                || lower.contains("filesystem")
                || lower.contains("file-system")
                || lower.contains("read_file")
                || lower.contains("write_file")
        })
        .map(|(label, value)| format!("{label}={}", safe_evidence_value(&label, &value)))
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
    let matches: Vec<String> = labeled_values(server)
        .into_iter()
        .filter(|(_, value)| {
            let lower = value.to_ascii_lowercase();
            needles.iter().any(|needle| lower.contains(needle))
        })
        .map(|(label, value)| format!("{label}={}", safe_evidence_value(&label, &value)))
        .collect();
    (!matches.is_empty()).then_some(matches)
}

/// Server fields as `(field label, value)` pairs, so any evidence built from
/// these can name the exact field that matched (never just a bare value).
/// These are the RAW configured values, used only for heuristic keyword
/// matching (unchanged detection sensitivity) — never placed directly into
/// evidence. Use `safe_evidence_value` to sanitize a value before it is ever
/// formatted into an evidence string.
fn labeled_values(server: &McpServer) -> Vec<(String, String)> {
    let mut values = vec![("server".to_string(), server.name.clone())];
    if let Some(command) = &server.command {
        values.push(("command".to_string(), command.clone()));
    }
    for (index, arg) in server.args.iter().enumerate() {
        values.push((format!("args[{index}]"), arg.replace('\\', "/")));
    }
    if let Some(url) = &server.url {
        values.push(("url".to_string(), url.clone()));
    }
    values
}

/// Sanitizes a matched value before it is placed into finding evidence.
///
/// - Any value that is or looks like a URL (the `url` field, or an
///   `http(s)://`-prefixed value found in `command`/`args`) has its userinfo
///   (`user:pass@`), query string, and fragment stripped — these are the most
///   likely places an MCP server URL embeds a credential (e.g. an API key
///   query parameter).
/// - Any value shaped like `key=value` or `key:value` whose `key` looks
///   secret-shaped (per [`secret_looking_name`]) has its value replaced with
///   `<redacted>` — this covers common CLI flag conventions such as
///   `--token=abc123`.
///
/// This is a best-effort, bounded heuristic, not a general secret scanner:
/// it does not detect a credential passed as a bare positional argument or
/// as a separate `--token value` pair of argv elements. Operators should
/// prefer environment variables (whose values EtherFence never captures at
/// all) over embedding credentials directly in MCP server commands, args, or
/// URLs.
fn safe_evidence_value(label: &str, value: &str) -> String {
    let lower = value.to_ascii_lowercase();
    let value = if label == "url" || lower.starts_with("http://") || lower.starts_with("https://") {
        sanitize_url_for_evidence(value)
    } else {
        value.to_string()
    };
    redact_secret_looking_segment(&value)
}

/// Strips URL userinfo, query string, and fragment, keeping only the scheme,
/// host, and path — the parts of a URL that are safe to show as evidence.
/// Applied to any matched value that looks like a URL, not only the
/// dedicated `url` server field, since a credential-carrying URL can equally
/// appear as a positional `args[N]` value.
fn sanitize_url_for_evidence(url: &str) -> String {
    let without_fragment = url.split('#').next().unwrap_or(url);
    let without_query = without_fragment
        .split('?')
        .next()
        .unwrap_or(without_fragment);
    match without_query.find("://") {
        Some(scheme_end) => {
            let (scheme, rest) = without_query.split_at(scheme_end + 3);
            let first_slash = rest.find('/').unwrap_or(rest.len());
            match rest[..first_slash].rfind('@') {
                Some(at_index) => format!("{scheme}{}", &rest[at_index + 1..]),
                None => format!("{scheme}{rest}"),
            }
        }
        None => without_query.to_string(),
    }
}

/// Replaces the value half of a `key=value`/`key:value`-shaped segment with
/// `<redacted>` when `key` looks secret-shaped (checked with the first `=`,
/// then the first `:`, found in the original value).
fn redact_secret_looking_segment(value: &str) -> String {
    for separator in ['=', ':'] {
        if let Some(index) = value.find(separator) {
            let (key, rest) = value.split_at(index);
            let value_part = &rest[1..];
            if !value_part.is_empty() && secret_looking_name(key) {
                return format!("{key}{separator}<redacted>");
            }
        }
    }
    value.to_string()
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
    fn url_evidence_strips_userinfo_query_and_fragment() {
        let item = InventoryItem {
            agent: AgentKind::VsCode,
            config_path: "~/.vscode/mcp.json".to_string(),
            mcp_servers: vec![McpServer {
                name: "search".to_string(),
                command: None,
                args: Vec::new(),
                env: Vec::new(),
                url: Some(
                    "https://user:s3cr3t@api.example/mcp?api_key=actual-secret&x=1#frag"
                        .to_string(),
                ),
            }],
            evidence: Vec::new(),
        };
        let findings = analyze(&[item]);
        for finding in &findings {
            for entry in &finding.evidence {
                assert!(!entry.contains("s3cr3t"), "leaked userinfo in {entry:?}");
                assert!(
                    !entry.contains("actual-secret"),
                    "leaked query secret in {entry:?}"
                );
                assert!(!entry.contains("frag"), "leaked fragment in {entry:?}");
            }
        }
        let configured = findings
            .iter()
            .find(|f| f.id == "EF-MCP-000")
            .expect("mcp-configured finding");
        assert!(
            configured
                .evidence
                .iter()
                .any(|e| e == "url=https://api.example/mcp"),
            "evidence should keep scheme/host/path only: {:?}",
            configured.evidence
        );
    }

    #[test]
    fn args_evidence_redacts_secret_shaped_key_value_segments() {
        let item = InventoryItem {
            agent: AgentKind::ClaudeCode,
            config_path: "~/.claude.json".to_string(),
            mcp_servers: vec![McpServer {
                name: "runner".to_string(),
                command: Some("runner-mcp".to_string()),
                // "exec" makes this args[0] match the risky-command heuristic
                // (so it is actually included in evidence), while its
                // `=`-separated key ("--exec-token") looks secret-shaped.
                args: vec!["--exec-token=actual-secret-value".to_string()],
                env: Vec::new(),
                url: None,
            }],
            evidence: Vec::new(),
        };
        let findings = analyze(&[item]);
        for finding in &findings {
            for entry in &finding.evidence {
                assert!(
                    !entry.contains("actual-secret-value"),
                    "leaked secret-shaped arg value in {entry:?}"
                );
            }
        }
        let shell = findings
            .iter()
            .find(|f| f.id == "EF-MCP-002")
            .expect("risky-command finding matches the exec-shaped arg");
        assert!(
            shell
                .evidence
                .iter()
                .any(|e| e == "args[0]=--exec-token=<redacted>"),
            "secret-shaped arg key must be redacted, not dropped: {:?}",
            shell.evidence
        );
    }

    #[test]
    fn flags_secret_env_and_filesystem_hint_with_guidance() {
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
        let fs = findings
            .iter()
            .find(|f| f.id == "EF-MCP-001")
            .expect("filesystem finding");
        assert_eq!(fs.title, "Broad filesystem access hint");
        assert!(fs.rationale.contains("filesystem"));
        assert!(fs.recommendation.contains("Restrict"));
        assert_eq!(fs.category, FindingCategory::Risk);
        assert!(
            fs.evidence
                .iter()
                .any(|e| e.starts_with("args[0]=") || e.starts_with("args[1]=")),
            "filesystem evidence must name the matched args field: {:?}",
            fs.evidence
        );

        let secret = findings
            .iter()
            .find(|f| f.id == "EF-SEC-001")
            .expect("secret env finding");
        assert_eq!(secret.target, "filesystem");
        assert!(secret.impact.contains("credentials"));
        assert_eq!(secret.category, FindingCategory::Risk);
        assert_eq!(secret.evidence, vec!["env=API_TOKEN".to_string()]);

        let configured = findings
            .iter()
            .find(|f| f.id == "EF-MCP-000")
            .expect("mcp-configured finding");
        assert_eq!(configured.severity, Severity::Info);
        assert_eq!(configured.category, FindingCategory::Inventory);
        assert!(configured.evidence.iter().any(|e| e == "server=filesystem"));

        let exposed = findings
            .iter()
            .find(|f| f.id == "EF-MCP-004")
            .expect("exposed-env finding");
        assert_eq!(exposed.severity, Severity::Info);
        assert_eq!(exposed.category, FindingCategory::Inventory);
        assert_eq!(exposed.evidence, vec!["env=API_TOKEN".to_string()]);
    }

    #[test]
    fn each_heuristic_finding_evidence_names_its_matched_field() {
        let item = InventoryItem {
            agent: AgentKind::VsCode,
            config_path: "~/.vscode/mcp.json".to_string(),
            mcp_servers: vec![McpServer {
                name: "browser-shell".to_string(),
                command: Some("bash".to_string()),
                args: vec!["--allow-root".to_string()],
                env: Vec::new(),
                url: Some("https://example.invalid/mcp".to_string()),
            }],
            evidence: Vec::new(),
        };
        let findings = analyze(&[item]);

        let fs = findings
            .iter()
            .find(|f| f.id == "EF-MCP-001")
            .expect("broad filesystem finding");
        assert!(
            fs.evidence.iter().any(|e| e.starts_with("args[0]=")),
            "EF-MCP-001 evidence must name the matched args field: {:?}",
            fs.evidence
        );

        let shell = findings
            .iter()
            .find(|f| f.id == "EF-MCP-002")
            .expect("shell-capable finding");
        assert!(
            shell.evidence.iter().any(|e| e == "command=bash"),
            "EF-MCP-002 evidence must name the matched command field: {:?}",
            shell.evidence
        );

        let network = findings
            .iter()
            .find(|f| f.id == "EF-MCP-003")
            .expect("network-capable finding");
        assert!(
            network
                .evidence
                .iter()
                .any(|e| e == "url=https://example.invalid/mcp"),
            "EF-MCP-003 evidence must name the matched url field: {:?}",
            network.evidence
        );
    }

    #[test]
    fn evidence_never_includes_a_generic_env_name_as_secret_looking() {
        let item = InventoryItem {
            agent: AgentKind::ClaudeCode,
            config_path: "~/.claude.json".to_string(),
            mcp_servers: vec![McpServer {
                name: "logging".to_string(),
                command: Some("node".to_string()),
                args: vec!["server.js".to_string()],
                env: vec![EnvVar {
                    name: "LOG_LEVEL".to_string(),
                    value_hint: Some("<set>".to_string()),
                }],
                url: None,
            }],
            evidence: Vec::new(),
        };
        let findings = analyze(&[item]);
        assert!(
            !findings.iter().any(|f| f.id == "EF-SEC-001"),
            "a generic (non-secret-shaped) env var name must not trigger EF-SEC-001"
        );
        let exposed = findings
            .iter()
            .find(|f| f.id == "EF-MCP-004")
            .expect("exposed-env finding still fires for generic env vars");
        assert_eq!(exposed.category, FindingCategory::Inventory);
        assert_eq!(exposed.evidence, vec!["env=LOG_LEVEL".to_string()]);
    }

    #[test]
    fn analyze_is_deterministic_across_repeated_calls() {
        let item = InventoryItem {
            agent: AgentKind::Cursor,
            config_path: "~/.cursor/mcp.json".to_string(),
            mcp_servers: vec![McpServer {
                name: "shell-tools".to_string(),
                command: Some("bash".to_string()),
                args: vec!["--allow-root".to_string(), "/home".to_string()],
                env: vec![EnvVar {
                    name: "TOOL_TOKEN".to_string(),
                    value_hint: Some("<set>".to_string()),
                }],
                url: None,
            }],
            evidence: Vec::new(),
        };
        let first = analyze(std::slice::from_ref(&item));
        let second = analyze(&[item]);
        assert_eq!(first.len(), second.len());
        for (a, b) in first.iter().zip(second.iter()) {
            assert_eq!(a.id, b.id);
            assert_eq!(a.evidence, b.evidence);
            assert_eq!(a.category, b.category);
            assert_eq!(a.severity, b.severity);
        }
    }

    #[test]
    fn distinguishes_tirith_binary_and_config_findings() {
        let config = InventoryItem {
            agent: AgentKind::Tirith,
            config_path: "~/.tirith/config.toml".to_string(),
            mcp_servers: Vec::new(),
            evidence: vec!["Tirith file present".to_string()],
        };
        let binary = InventoryItem {
            agent: AgentKind::Tirith,
            config_path: "PATH:tirith".to_string(),
            mcp_servers: Vec::new(),
            evidence: vec!["tirith binary found on PATH".to_string()],
        };
        let findings = analyze(&[config, binary]);
        assert!(findings.iter().any(|f| f.id == "EF-TIRITH-002"));
        assert!(findings.iter().any(|f| f.id == "EF-TIRITH-001"));
    }

    #[test]
    fn unparseable_config_yields_single_parse_error_finding() {
        let item = InventoryItem {
            agent: AgentKind::CodexCli,
            config_path: "~/.codex/config.toml".to_string(),
            mcp_servers: Vec::new(),
            evidence: vec![format!(
                "{PARSE_ERROR_EVIDENCE_PREFIX} parsing TOML: invalid table header"
            )],
        };
        let findings = analyze(&[item]);
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.id, "EF-CFG-001");
        assert_eq!(finding.kind, FindingKind::ConfigParseError);
        assert_eq!(finding.severity, Severity::Low);
        assert_eq!(finding.target, "config");
        assert!(finding.evidence[0].starts_with(PARSE_ERROR_EVIDENCE_PREFIX));
    }
}
