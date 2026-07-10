use serde_json::Value;
use std::path::Path;

#[test]
fn mcp_client_json_examples_are_valid() {
    for (name, content) in [
        (
            "generic-linux",
            include_str!("../../../docs/examples/mcp-client-generic-linux.json"),
        ),
        (
            "generic-windows",
            include_str!("../../../docs/examples/mcp-client-generic-windows.json"),
        ),
        (
            "claude-linux",
            include_str!("../../../docs/examples/claude-desktop-filesystem-linux.json"),
        ),
        (
            "cursor-linux",
            include_str!("../../../docs/examples/cursor-mcp-filesystem-linux.json"),
        ),
        (
            "vscode-linux",
            include_str!("../../../docs/examples/vscode-mcp-filesystem-linux.json"),
        ),
    ] {
        let json: Value = serde_json::from_str(content)
            .unwrap_or_else(|error| panic!("{name} example is invalid JSON: {error}"));
        assert!(
            json.to_string().contains("mcp-proxy"),
            "{name} example should wrap the server with etherfence mcp-proxy"
        );
        assert!(
            json.to_string().contains("--server-name"),
            "{name} example should set a server policy scope"
        );
        assert!(
            json.to_string().contains("--audit-log"),
            "{name} example should show audit logging"
        );
    }
}

#[test]
fn mcp_policy_examples_parse() {
    for (name, content) in [
        (
            "filesystem-readonly",
            include_str!("../../../examples/policies/mcp-filesystem-readonly.toml"),
        ),
        (
            "github-readonly",
            include_str!("../../../examples/policies/mcp-github-readonly.toml"),
        ),
        (
            "strict-tools-only",
            include_str!("../../../examples/policies/mcp-strict-tools-only.toml"),
        ),
        (
            "readonly",
            include_str!("../../../examples/policies/mcp-readonly.toml"),
        ),
        (
            "resources-denied",
            include_str!("../../../examples/policies/mcp-resources-denied.toml"),
        ),
        (
            "sampling-denied",
            include_str!("../../../examples/policies/mcp-sampling-denied.toml"),
        ),
        (
            "filesystem-project-readonly",
            include_str!("../../../examples/policies/mcp-filesystem-project-readonly.toml"),
        ),
        (
            "resources-project-only",
            include_str!("../../../examples/policies/mcp-resources-project-only.toml"),
        ),
        (
            "filesystem-project-readonly-hardened",
            include_str!(
                "../../../examples/policies/mcp-filesystem-project-readonly-hardened.toml"
            ),
        ),
        (
            "strict-method-only",
            include_str!("../../../examples/policies/mcp-strict-method-only.toml"),
        ),
        (
            "memory-notes-readonly",
            include_str!("../../../examples/policies/mcp-memory-notes-readonly.toml"),
        ),
    ] {
        let policy = etherfence_mcp::parse_mcp_policy(content)
            .unwrap_or_else(|error| panic!("{name} policy should parse: {error}"));
        assert_eq!(policy.schema_version, "ef-mcp-policy/v0.1");
        assert!(!policy.name.is_empty());
    }
}

#[test]
fn mcp_compatibility_matrix_documents_fake_fixture_row() {
    let matrix = include_str!("../../../docs/mcp-compatibility-matrix.md");
    for required in [
        "server name",
        "server version",
        "platform",
        "command template",
        "policy used",
        "tools/list behavior",
        "allowed `tools/call` result",
        "denied `tools/call` result",
        "audit result",
        "tester/date",
        "notes/limitations",
    ] {
        assert!(
            matrix.to_lowercase().contains(required),
            "compatibility matrix should document field: {required}"
        );
    }
    assert!(
        matrix.contains("etherfence-compat-fixture"),
        "matrix should include the checked fake MCP server compatibility row"
    );
    assert!(
        matrix.contains("stdio transport only"),
        "matrix should preserve the stdio-only scope guard"
    );

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    for policy in [
        "../../examples/policies/mcp-minimal-boundary.toml",
        "../../examples/policies/mcp-filesystem-readonly.toml",
        "../../examples/policies/mcp-github-readonly.toml",
        "../../examples/policies/mcp-strict-tools-only.toml",
        "../../examples/policies/mcp-readonly.toml",
        "../../examples/policies/mcp-resources-denied.toml",
        "../../examples/policies/mcp-sampling-denied.toml",
        "../../examples/policies/mcp-filesystem-project-readonly.toml",
        "../../examples/policies/mcp-resources-project-only.toml",
        "../../examples/policies/mcp-filesystem-project-readonly-hardened.toml",
        "../../examples/policies/mcp-strict-method-only.toml",
        "../../examples/policies/mcp-memory-notes-readonly.toml",
    ] {
        assert!(
            manifest_dir.join(policy).exists(),
            "referenced matrix policy should exist: {policy}"
        );
    }
}

#[test]
fn hardened_filesystem_project_readonly_denies_credential_like_paths() {
    let policy = etherfence_mcp::parse_mcp_policy(include_str!(
        "../../../examples/policies/mcp-filesystem-project-readonly-hardened.toml"
    ))
    .expect("hardened policy should parse");

    // A path inside the project root but outside every denied credential path
    // is allowed.
    let allowed = etherfence_mcp::decide_tool_argument_paths(
        &policy,
        "filesystem.read",
        Some(&serde_json::json!({"path": "/home/user/project/docs/readme.md"})),
    )
    .expect("path guard configured");
    assert_eq!(allowed.decision, etherfence_mcp::Decision::Allow);

    // Every configured credential-like deny_roots entry actually denies.
    for credential_path in [
        "/home/user/project/.git/config",
        "/home/user/project/.env",
        "/home/user/project/.env.local",
        "/home/user/project/secrets/token.txt",
        "/home/user/project/.ssh/id_ed25519",
        "/home/user/project/.aws/credentials",
        "/home/user/project/.npmrc",
        "/home/user/project/.netrc",
        "/home/user/project/.pypirc",
        "/home/user/project/credentials",
        "/home/user/project/id_rsa",
    ] {
        let decision = etherfence_mcp::decide_tool_argument_paths(
            &policy,
            "filesystem.read",
            Some(&serde_json::json!({"path": credential_path})),
        )
        .expect("path guard configured");
        assert_eq!(
            decision.decision,
            etherfence_mcp::Decision::Deny,
            "expected {credential_path} to be denied"
        );
    }
}

#[test]
fn strict_method_only_denies_every_non_tool_method_explicitly() {
    let policy = etherfence_mcp::parse_mcp_policy(include_str!(
        "../../../examples/policies/mcp-strict-method-only.toml"
    ))
    .expect("strict method-only policy should parse");

    for method in ["tools/list", "tools/call"] {
        assert_eq!(
            etherfence_mcp::decide_method(&policy, "default", method).decision,
            etherfence_mcp::Decision::Allow,
            "expected {method} to be allowed"
        );
    }

    for method in [
        "resources/list",
        "resources/read",
        "prompts/list",
        "prompts/get",
        "completion/complete",
        "roots/list",
        "sampling/createMessage",
        "elicitation/create",
    ] {
        assert_eq!(
            etherfence_mcp::decide_method(&policy, "default", method).decision,
            etherfence_mcp::Decision::Deny,
            "expected {method} to be denied"
        );
    }
}

#[test]
fn real_server_test_template_documents_json_argv_and_audit_collection() {
    let template = include_str!("../../../docs/mcp-real-server-test-template.md");
    assert!(template.contains("ETHERFENCE_REAL_MCP_CMD"));
    assert!(template.contains("JSON argv"));
    assert!(template.contains("optional_real_mcp_stdio_smoke_test"));
    assert!(template.contains("--audit-log"));
    assert!(template.contains("docs/mcp-compatibility-matrix.md"));
}
