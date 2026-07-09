use serde_json::Value;

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
    ] {
        let policy = etherfence_mcp::parse_mcp_policy(content)
            .unwrap_or_else(|error| panic!("{name} policy should parse: {error}"));
        assert_eq!(policy.schema_version, "ef-mcp-policy/v0.1");
        assert!(!policy.name.is_empty());
        assert!(!policy.servers.is_empty());
    }
}
