use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const ALL_PROFILES: &[&str] = &[
    "minimal",
    "strict-method-only",
    "filesystem-project-readonly",
    "filesystem-project-readonly-hardened",
    "resources-project-only",
];

/// `ef-mcp-policy/v0.2` profiles, one per documented user story in
/// specs/004-argument-aware-mcp-policy/spec.md.
const V2_PROFILES: &[&str] = &[
    "github-scoped-orgs",
    "messaging-named-destinations",
    "browser-approved-hosts",
    "readonly-operation-guard",
];

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

const EXPLAIN_POLICY: &str = r#"
schema_version = "ef-mcp-policy/v0.1"
name = "explain-me"

[methods]
allow = ["*"]

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
"#;

fn temp_path(name: &str, extension: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "etherfence-mcp-policy-{name}-{}-{nanos}.{extension}",
        std::process::id()
    ))
}

fn write_temp_policy(name: &str, content: &str) -> PathBuf {
    let path = temp_path(name, "toml");
    std::fs::write(&path, content).expect("write temp policy");
    path
}

fn example_policy_path(basename: &str) -> String {
    format!(
        "{}/../../examples/policies/{basename}.toml",
        env!("CARGO_MANIFEST_DIR")
    )
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_etherfence"))
        .args(args)
        .output()
        .expect("run etherfence mcp-policy")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

// --- validate ---

#[test]
fn validate_succeeds_for_example_policies() {
    let examples = [
        "mcp-minimal-boundary",
        "mcp-filesystem-readonly",
        "mcp-github-readonly",
        "mcp-strict-tools-only",
        "mcp-readonly",
        "mcp-resources-denied",
        "mcp-sampling-denied",
        "mcp-filesystem-project-readonly",
        "mcp-resources-project-only",
        "mcp-filesystem-project-readonly-hardened",
        "mcp-strict-method-only",
        "mcp-github-scoped-orgs",
        "mcp-messaging-named-destinations",
        "mcp-browser-approved-hosts",
        "mcp-readonly-operation-guard",
    ];
    for basename in examples {
        let path = example_policy_path(basename);
        let output = run(&["mcp-policy", "validate", &path]);
        assert!(
            output.status.success(),
            "expected {basename} to validate cleanly, stderr: {}",
            stderr(&output)
        );
        assert!(stdout(&output).contains("OK:"));
    }
}

#[test]
fn validate_succeeds_for_every_init_profile() {
    for profile in ALL_PROFILES {
        let init_output = run(&["mcp-policy", "init", "--profile", profile]);
        assert!(init_output.status.success(), "init --profile {profile}");
        let path = write_temp_policy(&format!("profile-{profile}"), &stdout(&init_output));
        let output = run(&["mcp-policy", "validate", path.to_str().unwrap()]);
        assert!(
            output.status.success(),
            "expected profile {profile} to validate cleanly, stderr: {}",
            stderr(&output)
        );
        let _ = std::fs::remove_file(&path);
    }
}

#[test]
fn validate_succeeds_for_every_v2_init_profile() {
    for profile in V2_PROFILES {
        let init_output = run(&["mcp-policy", "init", "--profile", profile]);
        assert!(init_output.status.success(), "init --profile {profile}");
        let path = write_temp_policy(&format!("v2-profile-{profile}"), &stdout(&init_output));
        let output = run(&["mcp-policy", "validate", path.to_str().unwrap()]);
        assert!(
            output.status.success(),
            "expected v0.2 profile {profile} to validate cleanly, stderr: {}",
            stderr(&output)
        );
        let _ = std::fs::remove_file(&path);
    }
}

#[test]
fn validate_fails_clearly_for_v2_construct_under_v1_schema() {
    let path = write_temp_policy(
        "v1-with-v2-construct",
        r#"
schema_version = "ef-mcp-policy/v0.1"
name = "v1-with-v2-construct"

[tools]
allow = ["demo.tool"]

[tools."demo.tool".arguments]
require_keys = ["org"]
"#,
    );
    let output = run(&["mcp-policy", "validate", path.to_str().unwrap()]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("ef-mcp-policy/v0.2"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn validate_fails_clearly_for_unsupported_schema_version() {
    let path = write_temp_policy(
        "bad-schema",
        r#"
schema_version = "ef-mcp-policy/v9.9"
name = "bad-schema"
"#,
    );
    let output = run(&["mcp-policy", "validate", path.to_str().unwrap()]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("unsupported"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn validate_fails_clearly_for_malformed_toml() {
    let path = write_temp_policy("malformed", "not valid toml [");
    let output = run(&["mcp-policy", "validate", path.to_str().unwrap()]);
    assert!(!output.status.success());
    assert!(!stderr(&output).is_empty());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn validate_fails_clearly_for_empty_allow_roots() {
    let path = write_temp_policy(
        "empty-allow-roots",
        r#"
schema_version = "ef-mcp-policy/v0.1"
name = "empty-allow-roots"

[path_rules.broken]
allow_roots = []
"#,
    );
    let output = run(&["mcp-policy", "validate", path.to_str().unwrap()]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("allow_roots"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn validate_fails_clearly_for_suspicious_unicode() {
    let path = write_temp_policy(
        "unicode-method",
        "schema_version = \"ef-mcp-policy/v0.1\"\nname = \"unicode-method\"\n\n[methods]\nallow = [\"t\u{03BF}ols/call\"]\n",
    );
    let output = run(&["mcp-policy", "validate", path.to_str().unwrap()]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("unicode_non_ascii_method"));
    let _ = std::fs::remove_file(&path);
}

// --- explain ---

#[test]
fn explain_includes_methods_tools_servers_path_rules_and_warnings() {
    let path = write_temp_policy("explain", EXPLAIN_POLICY);
    let output = run(&["mcp-policy", "explain", path.to_str().unwrap()]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let text = stdout(&output);

    assert!(text.contains("Policy name: explain-me"));
    assert!(text.contains("Global methods:"));
    assert!(text.contains("Global tools:"));
    assert!(text.contains("filesystem.read"));
    assert!(text.contains("Server scopes:"));
    assert!(text.contains("[fs]"));
    assert!(text.contains("Path rules:"));
    assert!(text.contains("project_readonly"));
    assert!(text.contains("Guarded keys:"));
    assert!(text.contains("Warnings:"));
    assert!(text.contains("wildcard"));
    assert!(text.contains("unused_rule"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn explain_reports_no_warnings_line_for_clean_policy() {
    let path = write_temp_policy(
        "clean",
        r#"
schema_version = "ef-mcp-policy/v0.1"
name = "clean-policy"

[methods]
allow = ["tools/list", "tools/call"]
deny = ["sampling/createMessage"]

[tools]
allow = ["filesystem.read"]
deny = ["shell.run"]
"#,
    );
    let output = run(&["mcp-policy", "explain", path.to_str().unwrap()]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("Warnings: (none)"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn explain_lists_v2_argument_guards() {
    let path = example_policy_path("mcp-github-scoped-orgs");
    let output = run(&["mcp-policy", "explain", &path]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("Argument/param field guards:"));
    assert!(text.contains("require_keys: org, repo"));
    assert!(text.contains("fields.\"org\" -> type=enum"));
    assert!(text.contains("fields.\"repo\" -> type=string"));
}

// --- init ---

#[test]
fn init_prints_valid_policy_to_stdout_for_every_profile() {
    for profile in ALL_PROFILES {
        let output = run(&["mcp-policy", "init", "--profile", profile]);
        assert!(output.status.success(), "init --profile {profile}");
        let text = stdout(&output);
        assert!(text.contains("schema_version = \"ef-mcp-policy/v0.1\""));
    }
}

#[test]
fn init_prints_valid_v2_policy_to_stdout_for_every_profile() {
    for profile in V2_PROFILES {
        let output = run(&["mcp-policy", "init", "--profile", profile]);
        assert!(output.status.success(), "init --profile {profile}");
        let text = stdout(&output);
        assert!(text.contains("schema_version = \"ef-mcp-policy/v0.2\""));
    }
}

#[test]
fn init_rejects_unknown_profile() {
    let output = run(&["mcp-policy", "init", "--profile", "does-not-exist"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("unknown MCP policy init profile"));
}

#[test]
fn init_output_writes_file_and_does_not_silently_overwrite() {
    let path = temp_path("init-output", "toml");
    let _ = std::fs::remove_file(&path);

    let first = run(&[
        "mcp-policy",
        "init",
        "--profile",
        "minimal",
        "--output",
        path.to_str().unwrap(),
    ]);
    assert!(first.status.success(), "stderr: {}", stderr(&first));
    let written = std::fs::read_to_string(&path).expect("read written policy");
    assert!(written.contains("schema_version = \"ef-mcp-policy/v0.1\""));

    let second = run(&[
        "mcp-policy",
        "init",
        "--profile",
        "strict-method-only",
        "--output",
        path.to_str().unwrap(),
    ]);
    assert!(!second.status.success());
    assert!(stderr(&second).contains("refusing to overwrite"));
    let unchanged = std::fs::read_to_string(&path).expect("read unchanged policy");
    assert_eq!(
        unchanged, written,
        "file must be unchanged after refused overwrite"
    );

    let third = run(&[
        "mcp-policy",
        "init",
        "--profile",
        "strict-method-only",
        "--output",
        path.to_str().unwrap(),
        "--overwrite",
    ]);
    assert!(third.status.success(), "stderr: {}", stderr(&third));
    let overwritten = std::fs::read_to_string(&path).expect("read overwritten policy");
    assert_ne!(
        overwritten, written,
        "file must change after explicit --overwrite"
    );

    let _ = std::fs::remove_file(&path);
}

// --- check ---

#[test]
fn check_allows_allowed_tool_call() {
    let path = write_temp_policy("check-allow", CHECK_POLICY);
    let output = run(&[
        "mcp-policy",
        "check",
        "--policy",
        path.to_str().unwrap(),
        "--request",
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"filesystem.read","arguments":{}}}"#,
    ]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("Decision: ALLOW"));
    assert!(text.contains("Would be forwarded: yes"));
    assert!(text.contains("Tool: filesystem.read"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn check_denies_denied_tool_call() {
    let path = write_temp_policy("check-deny-tool", CHECK_POLICY);
    let output = run(&[
        "mcp-policy",
        "check",
        "--policy",
        path.to_str().unwrap(),
        "--request",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"shell.run","arguments":{}}}"#,
    ]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("Decision: DENY"));
    assert!(text.contains("Would be forwarded: no"));
    assert!(text.contains("Tool: shell.run"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn check_denies_blocked_resources_read_uri() {
    let path = write_temp_policy("check-deny-uri", CHECK_POLICY);
    let output = run(&[
        "mcp-policy",
        "check",
        "--policy",
        path.to_str().unwrap(),
        "--request",
        r#"{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"file:///etc/passwd"}}"#,
    ]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("Decision: DENY"));
    assert!(text.contains("outside_allowed_roots"));
    assert!(!text.contains("/etc/passwd"), "raw URI must not be printed");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn check_denies_suspicious_unicode_tool_name() {
    let path = write_temp_policy("check-deny-unicode", CHECK_POLICY);
    let request = format!(
        r#"{{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{{"name":"filesystem.{}read","arguments":{{}}}}}}"#,
        '\u{200B}'
    );
    let output = run(&[
        "mcp-policy",
        "check",
        "--policy",
        path.to_str().unwrap(),
        "--request",
        &request,
    ]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("Decision: DENY"));
    assert!(text.to_lowercase().contains("unicode"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn check_denies_suspicious_unicode_method_name() {
    let path = write_temp_policy("check-deny-unicode-method", CHECK_POLICY);
    let request = format!(
        r#"{{"jsonrpc":"2.0","id":5,"method":"tools/{}call"}}"#,
        '\u{200B}'
    );
    let output = run(&[
        "mcp-policy",
        "check",
        "--policy",
        path.to_str().unwrap(),
        "--request",
        &request,
    ]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("Decision: DENY"));
    assert!(text.to_lowercase().contains("unicode"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn check_denies_batch_input_fail_closed() {
    let path = write_temp_policy("check-batch", CHECK_POLICY);
    let output = run(&[
        "mcp-policy",
        "check",
        "--policy",
        path.to_str().unwrap(),
        "--request",
        r#"[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"filesystem.read"}}]"#,
    ]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("Decision: DENY"));
    assert!(text.contains("Would be forwarded: no"));
    assert!(text.to_lowercase().contains("batch"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn check_rejects_invalid_request_json_with_clear_error() {
    let path = write_temp_policy("check-invalid-json", CHECK_POLICY);
    let output = run(&[
        "mcp-policy",
        "check",
        "--policy",
        path.to_str().unwrap(),
        "--request",
        "not json",
    ]);
    assert!(!output.status.success());
    assert!(stderr(&output).to_lowercase().contains("json"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn check_never_executes_a_tool_or_touches_network() {
    // The dry run only classifies the request; it must not spawn a process or
    // reach out anywhere. We assert this indirectly: the note in the output
    // documents the guarantee, and the command completes without any
    // `--server-command` / MCP server argument being accepted at all (the
    // `check` subcommand has no such flag).
    let path = write_temp_policy("check-no-exec", CHECK_POLICY);
    let output = run(&[
        "mcp-policy",
        "check",
        "--policy",
        path.to_str().unwrap(),
        "--request",
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"filesystem.read","arguments":{}}}"#,
    ]);
    assert!(output.status.success());
    assert!(stdout(&output)
        .contains("No MCP server was started or contacted and no tool was executed."));
    let _ = std::fs::remove_file(&path);
}

// --- v0.2 example-policy check scenarios (one per documented user story) ---

fn check_v2(basename: &str, request: &str) -> Output {
    let path = example_policy_path(basename);
    run(&[
        "mcp-policy",
        "check",
        "--policy",
        &path,
        "--request",
        request,
    ])
}

#[test]
fn us1_github_scoped_orgs_allows_in_allowlist_org() {
    let output = check_v2(
        "mcp-github-scoped-orgs",
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"github.create_issue","arguments":{"org":"my-org","repo":"my-org/svc","title":"x"}}}"#,
    );
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("Decision: ALLOW"));
}

#[test]
fn us1_github_scoped_orgs_denies_out_of_allowlist_org() {
    let output = check_v2(
        "mcp-github-scoped-orgs",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"github.create_issue","arguments":{"org":"other-org","repo":"other-org/svc","title":"x"}}}"#,
    );
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("Decision: DENY"));
    assert!(text.contains("enum_value_not_allowed"));
    assert!(
        !text.contains("other-org"),
        "denied value must not be echoed"
    );
}

#[test]
fn us1_github_scoped_orgs_denies_missing_required_key() {
    let output = check_v2(
        "mcp-github-scoped-orgs",
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"github.create_issue","arguments":{"repo":"my-org/svc"}}}"#,
    );
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("Decision: DENY"));
    assert!(text.contains("required_key_missing"));
}

#[test]
fn us2_messaging_named_destinations_allows_listed_destination() {
    let output = check_v2(
        "mcp-messaging-named-destinations",
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"messaging.send","arguments":{"destination":"eng-alerts","text":"hello"}}}"#,
    );
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("Decision: ALLOW"));
}

#[test]
fn us2_messaging_named_destinations_denies_unlisted_destination() {
    let output = check_v2(
        "mcp-messaging-named-destinations",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"messaging.send","arguments":{"destination":"random-channel","text":"hello"}}}"#,
    );
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("enum_value_not_allowed"));
}

#[test]
fn us2_messaging_named_destinations_denies_forbidden_key_present() {
    let output = check_v2(
        "mcp-messaging-named-destinations",
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"messaging.send","arguments":{"destination":"eng-alerts","bypass":false}}}"#,
    );
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("Decision: DENY"));
    assert!(text.contains("forbidden_key_present"));
}

#[test]
fn us3_browser_approved_hosts_allows_matching_url() {
    let output = check_v2(
        "mcp-browser-approved-hosts",
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"browser.fetch","arguments":{"url":"https://api.example.invalid/v1/search?q=x"}}}"#,
    );
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("Decision: ALLOW"));
}

#[test]
fn us3_browser_approved_hosts_denies_wrong_scheme_host_and_path() {
    for (label, url, expected_category) in [
        (
            "scheme",
            "http://api.example.invalid/v1/search",
            "url_scheme_not_allowed",
        ),
        (
            "host",
            "https://evil.example/v1/search",
            "url_host_not_allowed",
        ),
        (
            "path",
            "https://api.example.invalid/v2/search",
            "url_path_prefix_not_allowed",
        ),
    ] {
        let request = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"browser.fetch","arguments":{{"url":"{url}"}}}}}}"#
        );
        let output = check_v2("mcp-browser-approved-hosts", &request);
        assert!(
            output.status.success(),
            "{label} stderr: {}",
            stderr(&output)
        );
        let text = stdout(&output);
        assert!(text.contains("Decision: DENY"), "{label}");
        assert!(text.contains(expected_category), "{label}: {text}");
    }
}

#[test]
fn us3_browser_approved_hosts_never_echoes_a_denied_credential_bearing_url() {
    let output = check_v2(
        "mcp-browser-approved-hosts",
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"browser.fetch","arguments":{"url":"https://api.example.invalid@evil.example/v1/x?token=super-secret-token"}}}"#,
    );
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("Decision: DENY"));
    assert!(text.contains("url_malformed"));
    assert!(!text.contains("super-secret-token"));
    assert!(!text.contains("evil.example"));
}

#[test]
fn us4_readonly_operation_guard_allows_compliant_request() {
    let output = check_v2(
        "mcp-readonly-operation-guard",
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"data.query","arguments":{"operation":"read","limit":10,"filter":{"status":"open"}}}}"#,
    );
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("Decision: ALLOW"));
}

#[test]
fn us4_readonly_operation_guard_denies_each_primitive_violation() {
    for (label, request, expected_category) in [
        (
            "enum",
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"data.query","arguments":{"operation":"delete","limit":10,"filter":{"status":"open"}}}}"#,
            "enum_value_not_allowed",
        ),
        (
            "numeric-bound",
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"data.query","arguments":{"operation":"read","limit":1000,"filter":{"status":"open"}}}}"#,
            "number_above_maximum",
        ),
        (
            "wrong-type",
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"data.query","arguments":{"operation":"read","limit":"10","filter":{"status":"open"}}}}"#,
            "field_wrong_type",
        ),
        (
            "nested-selector-missing",
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"data.query","arguments":{"operation":"read","limit":10}}}"#,
            "field_missing",
        ),
    ] {
        let output = check_v2("mcp-readonly-operation-guard", request);
        assert!(
            output.status.success(),
            "{label} stderr: {}",
            stderr(&output)
        );
        let text = stdout(&output);
        assert!(text.contains("Decision: DENY"), "{label}");
        assert!(text.contains(expected_category), "{label}: {text}");
    }
}
