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
    ] {
        assert!(
            manifest_dir.join(policy).exists(),
            "referenced matrix policy should exist: {policy}"
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
