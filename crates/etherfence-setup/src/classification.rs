use etherfence_core::McpServer;
use serde::Serialize;
use std::path::Path;

/// Fixed capability taxonomy, most-restrictive-first (research.md Decision
/// 4). This single declaration order serves both output ordering and the
/// `needs_review` merge rule in `recommend`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CapabilityLabel {
    Unknown,
    ShellCommandExecution,
    IdentityAuth,
    SecurityTooling,
    Database,
    MessagingCollaboration,
    SaasApi,
    Network,
    Browser,
    Filesystem,
}

impl CapabilityLabel {
    /// The full fixed taxonomy, in canonical (most-restrictive-first) order.
    pub const ALL: [CapabilityLabel; 10] = [
        CapabilityLabel::Unknown,
        CapabilityLabel::ShellCommandExecution,
        CapabilityLabel::IdentityAuth,
        CapabilityLabel::SecurityTooling,
        CapabilityLabel::Database,
        CapabilityLabel::MessagingCollaboration,
        CapabilityLabel::SaasApi,
        CapabilityLabel::Network,
        CapabilityLabel::Browser,
        CapabilityLabel::Filesystem,
    ];

    fn canonical_index(self) -> usize {
        Self::ALL
            .iter()
            .position(|label| *label == self)
            .expect("CapabilityLabel::ALL is exhaustive")
    }
}

/// Friendly, human-facing phrasing for a capability label. JSON output MUST
/// always use the `Serialize` (`kebab-case`) token instead — see
/// data-model.md `CapabilityLabel` "JSON vs. human representation."
pub fn human_label(label: CapabilityLabel) -> &'static str {
    match label {
        CapabilityLabel::Unknown => "unknown",
        CapabilityLabel::ShellCommandExecution => "shell / command execution",
        CapabilityLabel::IdentityAuth => "identity / auth",
        CapabilityLabel::SecurityTooling => "security tooling",
        CapabilityLabel::Database => "database",
        CapabilityLabel::MessagingCollaboration => "messaging / collaboration",
        CapabilityLabel::SaasApi => "SaaS / API",
        CapabilityLabel::Network => "network",
        CapabilityLabel::Browser => "browser",
        CapabilityLabel::Filesystem => "filesystem",
    }
}

/// The classified capability label set for one MCP server, plus the
/// evidence that justified each match. Never empty (FR-013): a server
/// matching no curated rule carries exactly `[Unknown]` with no evidence.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClassifiedCapabilities {
    pub labels: Vec<CapabilityLabel>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
}

/// One curated command/package signature rule. Exact-match only — no
/// substring, regex, or path-shape heuristics (research.md Decision 6).
struct EvidenceRule {
    /// The server's `command` field (matched by resolved file-name, e.g.
    /// `/usr/bin/npx` and `npx` are equivalent) must equal this.
    command: &'static str,
    /// When `Some`, the server's first argument (the resolved package name
    /// for an `npx`/`uvx`-style invocation) must also match. When `None`,
    /// the command alone is sufficient evidence (e.g. a bare shell binary
    /// invocation is shell/command execution regardless of its arguments).
    package: Option<&'static str>,
    labels: &'static [CapabilityLabel],
}

/// Curated, checked-in signature table. Every rule here has a corresponding
/// fixture and a test asserting its exact `ClassifiedCapabilities` output
/// (Constitution Principle V/XI) — see `tests/fixtures/home` and this
/// module's `tests` below.
const EVIDENCE_RULES: &[EvidenceRule] = &[
    EvidenceRule {
        command: "npx",
        package: Some("@modelcontextprotocol/server-filesystem"),
        labels: &[CapabilityLabel::Filesystem],
    },
    EvidenceRule {
        command: "bash",
        package: None,
        labels: &[CapabilityLabel::ShellCommandExecution],
    },
    EvidenceRule {
        command: "uvx",
        package: Some("web-search-mcp"),
        labels: &[CapabilityLabel::Network],
    },
    EvidenceRule {
        command: "npx",
        package: Some("@modelcontextprotocol/server-devops"),
        labels: &[
            CapabilityLabel::Filesystem,
            CapabilityLabel::ShellCommandExecution,
        ],
    },
];

/// Classifies one MCP server's static, locally-configured capabilities.
/// Pure function of `server`'s already-parsed fields — never starts a
/// process, opens a network connection, or invokes any MCP protocol method
/// (FR-008/FR-009/FR-010/FR-011).
pub fn classify_server(server: &McpServer) -> ClassifiedCapabilities {
    let mut matches: Vec<(CapabilityLabel, String)> = Vec::new();

    if let Some(command) = server.command.as_deref() {
        let command_name = command_file_name(command);
        let first_arg = server.args.first().map(String::as_str);
        for rule in EVIDENCE_RULES {
            let matched = command_name == rule.command
                && match rule.package {
                    Some(package) => first_arg == Some(package),
                    None => true,
                };
            if !matched {
                continue;
            }
            for label in rule.labels {
                matches.push((*label, rule_evidence(command_name, rule.package, *label)));
            }
        }
    }

    if matches.is_empty() {
        return ClassifiedCapabilities {
            labels: vec![CapabilityLabel::Unknown],
            evidence: Vec::new(),
        };
    }

    matches.sort_by_key(|(label, _)| label.canonical_index());
    let (labels, evidence) = matches.into_iter().unzip();
    ClassifiedCapabilities { labels, evidence }
}

fn command_file_name(command: &str) -> &str {
    Path::new(command)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(command)
}

fn rule_evidence(command: &str, package: Option<&str>, label: CapabilityLabel) -> String {
    match package {
        Some(package) => format!(
            "command '{command}' arg '{package}' matched {} rule",
            human_label(label)
        ),
        None => format!("command '{command}' matched {} rule", human_label(label)),
    }
}

/// Starter-policy recommendation tier. `Allow` is reserved for a future
/// release and is never produced by any v1.2.0 curated rule (research.md
/// Decision 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecommendationTier {
    Deny,
    Allow,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StarterPolicyRecommendation {
    pub tier: RecommendationTier,
    pub needs_review: bool,
    pub rationale: String,
}

/// Derives a deterministic starter-policy recommendation from a server's
/// classified capabilities (FR-015/FR-016/FR-017/FR-018). Total over any
/// label set the classifier can produce — no unreachable case.
pub fn recommend(capabilities: &ClassifiedCapabilities) -> StarterPolicyRecommendation {
    let escalating: Vec<&'static str> = [
        CapabilityLabel::Unknown,
        CapabilityLabel::ShellCommandExecution,
        CapabilityLabel::IdentityAuth,
    ]
    .into_iter()
    .filter(|label| capabilities.labels.contains(label))
    .map(human_label)
    .collect();

    let needs_review = !escalating.is_empty();
    let rationale = if needs_review {
        format!(
            "denied by default; flagged for review because capability includes {}",
            escalating.join(", ")
        )
    } else {
        "denied by default; no fixture-verified allow rule exists for this capability set"
            .to_string()
    };

    StarterPolicyRecommendation {
        tier: RecommendationTier::Deny,
        needs_review,
        rationale,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherfence_core::EnvVar;

    fn server(name: &str, command: Option<&str>, args: &[&str]) -> McpServer {
        McpServer {
            name: name.to_string(),
            command: command.map(ToOwned::to_owned),
            args: args
                .iter()
                .map(ToOwned::to_owned)
                .map(String::from)
                .collect(),
            env: Vec::<EnvVar>::new(),
            url: None,
        }
    }

    #[test]
    fn filesystem_rule_matches_npx_server_filesystem() {
        let s = server(
            "filesystem",
            Some("npx"),
            &[
                "@modelcontextprotocol/server-filesystem",
                "/home/user/projects",
            ],
        );
        let classified = classify_server(&s);
        assert_eq!(classified.labels, vec![CapabilityLabel::Filesystem]);
        assert_eq!(classified.evidence.len(), 1);
        assert!(classified.evidence[0].contains("filesystem rule"));
    }

    #[test]
    fn shell_rule_matches_bash_regardless_of_args() {
        let s = server("shell-tools", Some("bash"), &["-lc", "echo fixture"]);
        let classified = classify_server(&s);
        assert_eq!(
            classified.labels,
            vec![CapabilityLabel::ShellCommandExecution]
        );
        assert_eq!(classified.evidence.len(), 1);
    }

    #[test]
    fn network_rule_matches_uvx_web_search_mcp() {
        let s = server("search", Some("uvx"), &["web-search-mcp"]);
        let classified = classify_server(&s);
        assert_eq!(classified.labels, vec![CapabilityLabel::Network]);
    }

    #[test]
    fn combined_rule_produces_both_labels_in_canonical_order() {
        let s = server(
            "devops",
            Some("npx"),
            &["@modelcontextprotocol/server-devops"],
        );
        let classified = classify_server(&s);
        assert_eq!(
            classified.labels,
            vec![
                CapabilityLabel::ShellCommandExecution,
                CapabilityLabel::Filesystem
            ]
        );
        assert_eq!(classified.evidence.len(), 2);
    }

    #[test]
    fn unmatched_server_is_labeled_unknown_with_no_evidence() {
        let s = server("misc", Some("some-random-tool"), &[]);
        let classified = classify_server(&s);
        assert_eq!(classified.labels, vec![CapabilityLabel::Unknown]);
        assert!(classified.evidence.is_empty());
    }

    #[test]
    fn server_with_no_command_is_labeled_unknown() {
        let s = server("remote", None, &[]);
        let classified = classify_server(&s);
        assert_eq!(classified.labels, vec![CapabilityLabel::Unknown]);
        assert!(classified.evidence.is_empty());
    }

    /// Malformed/unparseable-shaped MCP server entries in
    /// `tests/fixtures/malformed-home/.vscode/mcp.json` (a non-object
    /// server value and a server with wrong-typed `args`/`env`) already
    /// degrade to a valid `McpServer` with no command via
    /// `etherfence_inventory::discover` (spec Edge Case 5: "malformed
    /// config -> unreadable/unknown, never a crash"). This proves
    /// `classify_server` handles that degraded shape safely.
    #[test]
    fn malformed_home_fixture_servers_classify_as_unknown_without_crashing() {
        let root = std::path::Path::new("../../tests/fixtures/malformed-home");
        let items = etherfence_inventory::discover(root);
        let vscode = items
            .iter()
            .find(|item| item.agent == etherfence_core::AgentKind::VsCode)
            .expect("malformed-home vscode fixture");
        assert!(
            !vscode.mcp_servers.is_empty(),
            "expected at least one degraded server entry"
        );
        for server in &vscode.mcp_servers {
            let classified = classify_server(server);
            assert_eq!(
                classified.labels,
                vec![CapabilityLabel::Unknown],
                "malformed server {:?} did not classify as unknown",
                server.name
            );
            assert!(classified.evidence.is_empty());
        }
    }

    #[test]
    fn labels_never_empty_across_all_cases() {
        let cases = [
            server(
                "a",
                Some("npx"),
                &["@modelcontextprotocol/server-filesystem"],
            ),
            server("b", Some("bash"), &[]),
            server("c", Some("uvx"), &["web-search-mcp"]),
            server("d", Some("npx"), &["@modelcontextprotocol/server-devops"]),
            server("e", Some("unknown-tool"), &[]),
            server("f", None, &[]),
        ];
        for case in cases {
            assert!(!classify_server(&case).labels.is_empty());
        }
    }

    #[test]
    fn json_labels_are_kebab_case_and_human_label_is_friendly_phrasing() {
        assert_eq!(
            serde_json::to_string(&CapabilityLabel::ShellCommandExecution).unwrap(),
            "\"shell-command-execution\""
        );
        assert_eq!(
            serde_json::to_string(&CapabilityLabel::IdentityAuth).unwrap(),
            "\"identity-auth\""
        );
        assert_eq!(
            serde_json::to_string(&CapabilityLabel::SecurityTooling).unwrap(),
            "\"security-tooling\""
        );
        assert_eq!(
            serde_json::to_string(&CapabilityLabel::MessagingCollaboration).unwrap(),
            "\"messaging-collaboration\""
        );
        assert_eq!(
            serde_json::to_string(&CapabilityLabel::SaasApi).unwrap(),
            "\"saas-api\""
        );
        assert_eq!(
            human_label(CapabilityLabel::ShellCommandExecution),
            "shell / command execution"
        );
        assert_eq!(
            human_label(CapabilityLabel::IdentityAuth),
            "identity / auth"
        );
        assert_eq!(
            human_label(CapabilityLabel::SecurityTooling),
            "security tooling"
        );
        assert_eq!(
            human_label(CapabilityLabel::MessagingCollaboration),
            "messaging / collaboration"
        );
        assert_eq!(human_label(CapabilityLabel::SaasApi), "SaaS / API");
    }

    fn caps(labels: &[CapabilityLabel]) -> ClassifiedCapabilities {
        ClassifiedCapabilities {
            labels: labels.to_vec(),
            evidence: Vec::new(),
        }
    }

    #[test]
    fn recommend_is_always_deny_and_never_allow() {
        for labels in [
            vec![CapabilityLabel::Filesystem],
            vec![CapabilityLabel::Unknown],
            vec![CapabilityLabel::ShellCommandExecution],
            vec![CapabilityLabel::IdentityAuth],
            vec![CapabilityLabel::Network, CapabilityLabel::Browser],
        ] {
            let recommendation = recommend(&caps(&labels));
            assert_eq!(recommendation.tier, RecommendationTier::Deny);
        }
    }

    #[test]
    fn recommend_needs_review_is_boolean_or_over_three_escalating_labels() {
        let escalating = [
            CapabilityLabel::Unknown,
            CapabilityLabel::ShellCommandExecution,
            CapabilityLabel::IdentityAuth,
        ];
        // Exercise all 8 combinations of the three escalating labels.
        for mask in 0u8..8 {
            let mut labels = Vec::new();
            for (i, label) in escalating.iter().enumerate() {
                if mask & (1 << i) != 0 {
                    labels.push(*label);
                }
            }
            let expected_needs_review = mask != 0;
            if labels.is_empty() {
                // A server can't classify to a truly empty label set
                // (FR-013 guarantees at least [Unknown]); use a benign
                // non-escalating label instead to test the "false" case.
                labels.push(CapabilityLabel::Filesystem);
            }
            let recommendation = recommend(&caps(&labels));
            assert_eq!(
                recommendation.needs_review,
                expected_needs_review || labels.contains(&CapabilityLabel::Unknown),
                "mask={mask:03b} labels={labels:?}"
            );
        }
    }

    #[test]
    fn recommend_needs_review_true_for_each_escalating_label_individually() {
        assert!(recommend(&caps(&[CapabilityLabel::Unknown])).needs_review);
        assert!(recommend(&caps(&[CapabilityLabel::ShellCommandExecution])).needs_review);
        assert!(recommend(&caps(&[CapabilityLabel::IdentityAuth])).needs_review);
    }

    #[test]
    fn recommend_needs_review_false_for_non_escalating_labels() {
        assert!(!recommend(&caps(&[CapabilityLabel::Filesystem])).needs_review);
        assert!(
            !recommend(&caps(&[CapabilityLabel::Network, CapabilityLabel::Browser])).needs_review
        );
    }

    #[test]
    fn no_test_case_ever_constructs_recommendation_tier_allow() {
        // RecommendationTier::Allow is reserved and unreachable from
        // `recommend` in v1.2.0; this test documents that invariant by
        // construction rather than by asserting a negative over all inputs.
        let _ = RecommendationTier::Allow; // exists in the type system only
    }
}
