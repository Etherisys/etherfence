//! Reusable, serverless helpers backing the `etherfence mcp-policy` CLI
//! commands (`explain` and `check`). These helpers only read an already
//! parsed [`McpPolicyFile`] and, for `check`, run the exact same
//! `inspect_client_line`/`inspect_server_line` decision functions the live
//! proxy uses — they never execute a tool, start a server, or open a
//! network connection.

use std::collections::BTreeSet;

use crate::audit::AuditRecord;
use crate::policy::{
    Decision, McpPolicyFile, MethodDirection, MethodRules, PathKeyGuard, ToolRules,
};
use crate::proxy::{
    inspect_client_line, inspect_server_line, ClientAction, ServerAction, TrackedRequests,
};

// --- explain ---

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolPolicySummary {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MethodPolicySummary {
    /// Whether a `[methods]` (or `[servers.<name>.methods]`) section is
    /// present at all. When `false`, the built-in default applies.
    pub configured: bool,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerScopeSummary {
    pub name: String,
    pub tools: ToolPolicySummary,
    pub methods: Option<MethodPolicySummary>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathRuleSummary {
    pub name: String,
    pub allow_roots: Vec<String>,
    pub deny_roots: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardScope {
    GlobalTool,
    GlobalMethod,
    ServerTool,
    ServerMethod,
}

impl GuardScope {
    pub fn as_str(self) -> &'static str {
        match self {
            GuardScope::GlobalTool => "global tool",
            GuardScope::GlobalMethod => "global method",
            GuardScope::ServerTool => "server tool",
            GuardScope::ServerMethod => "server method",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardSummary {
    pub scope: GuardScope,
    pub server_name: Option<String>,
    pub key: String,
    pub path_rule: String,
    pub path_keys: Vec<String>,
    pub uri_keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyExplanation {
    pub name: String,
    pub schema_version: String,
    pub global_tools: ToolPolicySummary,
    pub global_methods: MethodPolicySummary,
    pub servers: Vec<ServerScopeSummary>,
    pub path_rules: Vec<PathRuleSummary>,
    pub guards: Vec<GuardSummary>,
    pub warnings: Vec<String>,
}

/// Build a deterministic, human-reviewable explanation of a parsed MCP
/// policy: methods, tools, server scopes, path rules, guarded keys, and
/// operator warnings for risky or confusing policy shapes.
pub fn explain_policy(policy: &McpPolicyFile) -> PolicyExplanation {
    let global_tools = tool_summary(&policy.tools);
    let global_methods = method_summary(policy.methods.as_ref());

    let servers: Vec<ServerScopeSummary> = policy
        .servers
        .iter()
        .map(|(name, server)| ServerScopeSummary {
            name: name.clone(),
            tools: tool_summary(&server.tools),
            methods: server.methods.as_ref().map(|m| method_summary(Some(m))),
        })
        .collect();

    let path_rules: Vec<PathRuleSummary> = policy
        .path_rules
        .iter()
        .map(|(name, rule)| PathRuleSummary {
            name: name.clone(),
            allow_roots: rule.allow_roots.clone(),
            deny_roots: rule.deny_roots.clone(),
        })
        .collect();

    let mut guards = Vec::new();
    collect_tool_guards(&policy.tools, GuardScope::GlobalTool, None, &mut guards);
    if let Some(methods) = &policy.methods {
        collect_method_guards(methods, GuardScope::GlobalMethod, None, &mut guards);
    }
    for (server_name, server) in &policy.servers {
        collect_tool_guards(
            &server.tools,
            GuardScope::ServerTool,
            Some(server_name.clone()),
            &mut guards,
        );
        if let Some(methods) = &server.methods {
            collect_method_guards(
                methods,
                GuardScope::ServerMethod,
                Some(server_name.clone()),
                &mut guards,
            );
        }
    }

    let warnings = build_warnings(
        &global_tools,
        &global_methods,
        &servers,
        &path_rules,
        &guards,
    );

    PolicyExplanation {
        name: policy.name.clone(),
        schema_version: policy.schema_version.clone(),
        global_tools,
        global_methods,
        servers,
        path_rules,
        guards,
        warnings,
    }
}

fn tool_summary(rules: &ToolRules) -> ToolPolicySummary {
    ToolPolicySummary {
        allow: rules.allow.clone(),
        deny: rules.deny.clone(),
    }
}

fn method_summary(rules: Option<&MethodRules>) -> MethodPolicySummary {
    match rules {
        Some(rules) => MethodPolicySummary {
            configured: true,
            allow: rules.allow.clone(),
            deny: rules.deny.clone(),
        },
        None => MethodPolicySummary::default(),
    }
}

fn collect_tool_guards(
    rules: &ToolRules,
    scope: GuardScope,
    server_name: Option<String>,
    guards: &mut Vec<GuardSummary>,
) {
    for (tool_name, guard) in &rules.path_guards {
        if let Some(arguments) = &guard.arguments {
            guards.push(guard_summary(
                scope,
                server_name.clone(),
                tool_name.clone(),
                arguments,
            ));
        }
    }
}

fn collect_method_guards(
    rules: &MethodRules,
    scope: GuardScope,
    server_name: Option<String>,
    guards: &mut Vec<GuardSummary>,
) {
    for (method_name, guard) in &rules.path_guards {
        if let Some(params) = &guard.params {
            guards.push(guard_summary(
                scope,
                server_name.clone(),
                method_name.clone(),
                params,
            ));
        }
    }
}

fn guard_summary(
    scope: GuardScope,
    server_name: Option<String>,
    key: String,
    guard: &PathKeyGuard,
) -> GuardSummary {
    GuardSummary {
        scope,
        server_name,
        key,
        path_rule: guard.path_rule.clone(),
        path_keys: guard.path_keys.clone(),
        uri_keys: guard.uri_keys.clone(),
    }
}

fn build_warnings(
    global_tools: &ToolPolicySummary,
    global_methods: &MethodPolicySummary,
    servers: &[ServerScopeSummary],
    path_rules: &[PathRuleSummary],
    guards: &[GuardSummary],
) -> Vec<String> {
    let mut warnings = Vec::new();

    if global_methods.allow.iter().any(|entry| entry == "*") {
        warnings.push(
            "global [methods] allow list contains the \"*\" wildcard, which permits every known and unknown method except explicit denies".to_string(),
        );
    }

    let any_methods_configured =
        global_methods.configured || servers.iter().any(|server| server.methods.is_some());
    if !any_methods_configured {
        warnings.push(
            "no [methods] section is configured anywhere in this policy; the built-in default (allow only tools/list and tools/call) applies".to_string(),
        );
    }

    let any_tool_allow = !global_tools.allow.is_empty()
        || servers.iter().any(|server| !server.tools.allow.is_empty());
    if !any_tool_allow {
        warnings.push(
            "no tool is allowed anywhere in this policy; every tools/call request will be denied by default".to_string(),
        );
    }

    let referenced_rules: BTreeSet<&str> = guards
        .iter()
        .map(|guard| guard.path_rule.as_str())
        .collect();
    for rule in path_rules {
        if !referenced_rules.contains(rule.name.as_str()) {
            warnings.push(format!(
                "path rule \"{}\" is defined but is not referenced by any tool or method guard",
                rule.name
            ));
        }
    }

    let defined_rules: BTreeSet<&str> = path_rules.iter().map(|rule| rule.name.as_str()).collect();
    for guard in guards {
        if !defined_rules.contains(guard.path_rule.as_str()) {
            warnings.push(format!(
                "{} guard on \"{}\" references path rule \"{}\", which is not defined in [path_rules]",
                guard.scope.as_str(),
                guard.key,
                guard.path_rule
            ));
        }
    }

    for rule in path_rules {
        if rule.allow_roots.iter().any(|root| is_broad_root(root)) {
            warnings.push(format!(
                "path rule \"{}\" allow_roots includes a broad root (e.g. \"/\" or a drive root); this may allow access far beyond the intended project scope",
                rule.name
            ));
        }
        if rule.deny_roots.is_empty() {
            warnings.push(format!(
                "path rule \"{}\" has no deny_roots configured; consider denying sensitive subpaths (e.g. .git, .env, secrets) under the allowed root",
                rule.name
            ));
        }
    }

    warnings
}

fn is_broad_root(root: &str) -> bool {
    if root == "/" {
        return true;
    }
    let trimmed = root.trim_end_matches(['/', '\\']);
    let bytes = trimmed.as_bytes();
    bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

// --- check (dry run) ---

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckOutcome {
    pub allowed: bool,
    pub forwarded: bool,
    /// Whether the request was actually inspected against policy at all
    /// (a non-JSON-RPC-request line, such as a bare response, is passed
    /// through unchecked by the live proxy too).
    pub inspected: bool,
    pub event: String,
    pub decision: String,
    pub method: Option<String>,
    pub tool: Option<String>,
    pub reason: String,
    pub path_rule: Option<String>,
    pub path_key: Option<String>,
    pub path_classification: Option<String>,
}

/// Dry-run one JSON-RPC request/notification line against `policy` using the
/// exact same decision functions the live `mcp-proxy` uses. This never starts
/// or contacts an MCP server and never executes a tool — it only classifies
/// the single input line.
pub fn dry_run_check(
    policy: &McpPolicyFile,
    server_name: &str,
    direction: MethodDirection,
    raw_request: &str,
) -> CheckOutcome {
    match direction {
        MethodDirection::ClientToServer => {
            let inspected = inspect_client_line(policy, server_name, raw_request);
            let forwarded = matches!(inspected.action, ClientAction::Forward);
            outcome_from_audit(inspected.audit, forwarded)
        }
        MethodDirection::ServerToClient => {
            let mut pending = TrackedRequests::default();
            let inspected = inspect_server_line(policy, server_name, &mut pending, raw_request);
            let forwarded = matches!(inspected.action, ServerAction::Forward { .. });
            outcome_from_audit(inspected.audit, forwarded)
        }
    }
}

fn outcome_from_audit(audit: Option<AuditRecord>, forwarded: bool) -> CheckOutcome {
    match audit {
        Some(record) => CheckOutcome {
            allowed: record.decision == Decision::Allow.as_str(),
            forwarded,
            inspected: true,
            event: record.event,
            decision: record.decision,
            method: record.method,
            tool: record.tool,
            reason: record.reason,
            path_rule: record.path_rule,
            path_key: record.path_key,
            path_classification: record.path_classification,
        },
        None => CheckOutcome {
            allowed: forwarded,
            forwarded,
            inspected: false,
            event: "not_inspected".to_string(),
            decision: if forwarded {
                Decision::Allow.as_str().to_string()
            } else {
                Decision::Deny.as_str().to_string()
            },
            method: None,
            tool: None,
            reason: "input was not a JSON-RPC request/notification object with a \"method\" field; the live proxy would pass it through without policy inspection".to_string(),
            path_rule: None,
            path_key: None,
            path_classification: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::parse_mcp_policy;

    const EXPLAIN_POLICY: &str = r#"
schema_version = "ef-mcp-policy/v0.1"
name = "explain-me"

[methods]
allow = ["tools/list", "tools/call", "resources/read"]

[tools]
allow = ["filesystem.read"]

[servers.fs.tools]
allow = ["filesystem.read"]

[servers.fs.methods]
allow = ["resources/read"]

[path_rules.project_readonly]
allow_roots = ["/home/user/project"]
deny_roots = ["/home/user/project/.git"]

[path_rules.unused_rule]
allow_roots = ["/home/user/other"]

[tools."filesystem.read".arguments]
path_keys = ["path"]
path_rule = "project_readonly"

[methods."resources/read".params]
uri_keys = ["uri"]
path_rule = "project_readonly"
"#;

    #[test]
    fn explain_summarizes_methods_tools_servers_and_path_rules() {
        let policy = parse_mcp_policy(EXPLAIN_POLICY).unwrap();
        let explanation = explain_policy(&policy);
        assert_eq!(explanation.name, "explain-me");
        assert!(explanation.global_methods.configured);
        assert_eq!(
            explanation.global_methods.allow,
            vec!["tools/list", "tools/call", "resources/read"]
        );
        assert_eq!(explanation.global_tools.allow, vec!["filesystem.read"]);
        assert_eq!(explanation.servers.len(), 1);
        assert_eq!(explanation.servers[0].name, "fs");
        assert_eq!(explanation.path_rules.len(), 2);
        assert_eq!(explanation.guards.len(), 2);
    }

    #[test]
    fn explain_warns_on_unused_path_rule() {
        let policy = parse_mcp_policy(EXPLAIN_POLICY).unwrap();
        let explanation = explain_policy(&policy);
        assert!(explanation
            .warnings
            .iter()
            .any(|warning| warning.contains("unused_rule") && warning.contains("not referenced")));
    }

    #[test]
    fn explain_warns_on_empty_deny_roots() {
        let policy = parse_mcp_policy(EXPLAIN_POLICY).unwrap();
        let explanation = explain_policy(&policy);
        assert!(explanation
            .warnings
            .iter()
            .any(|warning| warning.contains("unused_rule") && warning.contains("no deny_roots")));
    }

    #[test]
    fn explain_warns_on_wildcard_method_allow_and_missing_guard_rule() {
        let content = r#"
schema_version = "ef-mcp-policy/v0.1"
name = "wildcard-and-missing-rule"

[methods]
allow = ["*"]

[tools]
allow = ["filesystem.read"]

[path_rules.only_rule]
allow_roots = ["/home/user/project"]
deny_roots = ["/home/user/project/.git"]

[tools."filesystem.read".arguments]
path_keys = ["path"]
path_rule = "missing_rule"
"#;
        let policy = parse_mcp_policy(content).unwrap();
        let explanation = explain_policy(&policy);
        assert!(explanation.warnings.iter().any(|w| w.contains("wildcard")));
        assert!(explanation
            .warnings
            .iter()
            .any(|w| w.contains("missing_rule") && w.contains("not defined")));
    }

    #[test]
    fn explain_warns_on_no_method_policy_and_empty_tool_allow() {
        let content = r#"
schema_version = "ef-mcp-policy/v0.1"
name = "bare"
"#;
        let policy = parse_mcp_policy(content).unwrap();
        let explanation = explain_policy(&policy);
        assert!(explanation
            .warnings
            .iter()
            .any(|w| w.contains("no [methods] section")));
        assert!(explanation
            .warnings
            .iter()
            .any(|w| w.contains("no tool is allowed")));
    }

    #[test]
    fn explain_warns_on_broad_allow_root() {
        let content = r#"
schema_version = "ef-mcp-policy/v0.1"
name = "broad-root"

[tools]
allow = ["filesystem.read"]

[path_rules.too_broad]
allow_roots = ["/"]
deny_roots = ["/etc"]

[tools."filesystem.read".arguments]
path_keys = ["path"]
path_rule = "too_broad"
"#;
        let policy = parse_mcp_policy(content).unwrap();
        let explanation = explain_policy(&policy);
        assert!(explanation
            .warnings
            .iter()
            .any(|w| w.contains("too_broad") && w.contains("broad root")));
    }

    const CHECK_POLICY: &str = r#"
schema_version = "ef-mcp-policy/v0.1"
name = "check-me"

[methods]
allow = ["tools/list", "tools/call", "resources/read"]

[tools]
allow = ["filesystem.read"]
deny = ["shell.run"]

[path_rules.project_readonly]
allow_roots = ["/home/user/project"]
deny_roots = ["/home/user/project/.git"]

[methods."resources/read".params]
uri_keys = ["uri"]
path_rule = "project_readonly"
"#;

    #[test]
    fn check_allows_allowed_tool_call() {
        let policy = parse_mcp_policy(CHECK_POLICY).unwrap();
        let request = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"filesystem.read","arguments":{}}}"#;
        let outcome = dry_run_check(&policy, "default", MethodDirection::ClientToServer, request);
        assert!(outcome.allowed);
        assert!(outcome.forwarded);
        assert_eq!(outcome.tool.as_deref(), Some("filesystem.read"));
    }

    #[test]
    fn check_denies_denied_tool_call() {
        let policy = parse_mcp_policy(CHECK_POLICY).unwrap();
        let request = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"shell.run","arguments":{}}}"#;
        let outcome = dry_run_check(&policy, "default", MethodDirection::ClientToServer, request);
        assert!(!outcome.allowed);
        assert!(!outcome.forwarded);
        assert_eq!(outcome.tool.as_deref(), Some("shell.run"));
    }

    #[test]
    fn check_denies_blocked_resources_read_uri() {
        let policy = parse_mcp_policy(CHECK_POLICY).unwrap();
        let request = r#"{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"file:///etc/passwd"}}"#;
        let outcome = dry_run_check(&policy, "default", MethodDirection::ClientToServer, request);
        assert!(!outcome.allowed);
        assert_eq!(
            outcome.path_classification.as_deref(),
            Some("outside_allowed_roots")
        );
    }

    #[test]
    fn check_denies_unicode_suspicious_tool_name() {
        let policy = parse_mcp_policy(CHECK_POLICY).unwrap();
        let request = format!(
            r#"{{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{{"name":"filesystem.{}read","arguments":{{}}}}}}"#,
            '\u{200B}'
        );
        let outcome = dry_run_check(
            &policy,
            "default",
            MethodDirection::ClientToServer,
            &request,
        );
        assert!(!outcome.allowed);
        assert!(outcome.reason.contains("unicode"));
    }

    #[test]
    fn check_denies_batch_fail_closed() {
        let policy = parse_mcp_policy(CHECK_POLICY).unwrap();
        let request = r#"[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"filesystem.read"}}]"#;
        let outcome = dry_run_check(&policy, "default", MethodDirection::ClientToServer, request);
        assert!(!outcome.allowed);
        assert!(!outcome.forwarded);
        assert_eq!(outcome.event, "batch_denied");
    }

    #[test]
    fn check_server_to_client_denies_unallowed_sampling() {
        let policy = parse_mcp_policy(CHECK_POLICY).unwrap();
        let request = r#"{"jsonrpc":"2.0","id":9,"method":"sampling/createMessage","params":{}}"#;
        let outcome = dry_run_check(&policy, "default", MethodDirection::ServerToClient, request);
        assert!(!outcome.allowed);
        assert!(!outcome.forwarded);
    }
}
