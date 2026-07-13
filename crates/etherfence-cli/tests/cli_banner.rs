//! Startup splash integration tests.
//!
//! The banner module's own unit tests prove the show/suppress decision
//! logic; these tests prove the module is actually wired into the binary
//! (a disconnected module compiles and passes unit tests without ever
//! printing anything) — across every human-facing entry point, including
//! the Clap help/version/error paths that bypass normal command dispatch.
//!
//! The PTY tests are unix-only: they need a real pseudo-terminal so the
//! binary sees an interactive stdout/stderr.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const BANNER_TAGLINE: &str = "AI Agent Security Posture & Runtime Control";

fn temp_root(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "etherfence-banner-{name}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("create temp root");
    dir
}

#[cfg(unix)]
fn fixture_root(name: &str) -> String {
    format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// Redirected (non-TTY) stdout must never show the splash, for any
/// command, even with color-friendly environment variables set.
#[test]
fn redirected_stdout_suppresses_banner() {
    let root = temp_root("redirected");
    let output = Command::new(env!("CARGO_BIN_EXE_etherfence"))
        .args(["setup", "detect", "--format", "human"])
        .arg("--root")
        .arg(&root)
        .env_remove("CI")
        .env_remove("NO_COLOR")
        .env("TERM", "xterm-256color")
        .output()
        .expect("run etherfence setup detect");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains(BANNER_TAGLINE),
        "banner tagline must not appear on redirected stdout:\n{stdout}"
    );
}

/// JSON output must never show the splash, even on a PTY.
#[cfg(unix)]
#[test]
fn json_format_suppresses_banner_on_pty() {
    let root = temp_root("json-pty");
    let stdout = run_in_pty(
        &[
            "setup",
            "detect",
            "--format",
            "json",
            "--root",
            root.to_str().expect("utf-8 temp root"),
        ],
        &root,
        true,
    );
    assert!(
        !stdout.contains(BANNER_TAGLINE),
        "banner tagline must not appear in JSON output:\n{stdout}"
    );
    assert!(
        stdout.contains("ef-setup-detect"),
        "expected detect JSON on the PTY:\n{stdout}"
    );
}

/// A human command on an interactive color PTY must show the splash.
#[cfg(unix)]
#[test]
fn human_command_shows_banner_on_pty() {
    let root = temp_root("human-pty");
    let stdout = run_in_pty(
        &[
            "setup",
            "detect",
            "--format",
            "human",
            "--root",
            root.to_str().expect("utf-8 temp root"),
        ],
        &root,
        true,
    );
    assert!(
        stdout.contains(BANNER_TAGLINE),
        "banner tagline must appear for a human command on a PTY:\n{stdout}"
    );
    assert!(
        stdout.contains(concat!("v", env!("CARGO_PKG_VERSION"))),
        "banner must include the version:\n{stdout}"
    );
}

/// Table-driven regression coverage for the previously-reported commands
/// that skipped the splash because `Cli::parse()` exited inside Clap
/// before `print_startup_banner()` ever ran: bare invocation, `help`,
/// `--help`, `policy` (missing subcommand), `policy --help`, `mcp-proxy`
/// (missing required args), `mcp-proxy --help`, plus `policy list` (newly
/// reclassified as human/splash-eligible). Every case must show the
/// splash *before* its own recognizable content on an interactive,
/// color-capable terminal.
#[cfg(unix)]
#[test]
fn reported_commands_show_banner_before_content_on_pty() {
    struct Case {
        name: &'static str,
        args: &'static [&'static str],
        expect_success: bool,
        content_marker: &'static str,
    }

    const CASES: &[Case] = &[
        Case {
            name: "bare",
            args: &[],
            expect_success: false,
            content_marker: "Usage:",
        },
        Case {
            name: "help-subcommand",
            args: &["help"],
            expect_success: true,
            content_marker: "Usage:",
        },
        Case {
            name: "help-flag",
            args: &["--help"],
            expect_success: true,
            content_marker: "Usage:",
        },
        Case {
            name: "policy-bare",
            args: &["policy"],
            expect_success: false,
            content_marker: "Usage:",
        },
        Case {
            name: "policy-help",
            args: &["policy", "--help"],
            expect_success: true,
            content_marker: "Usage:",
        },
        Case {
            name: "policy-list",
            args: &["policy", "list"],
            expect_success: true,
            // First entry of the built-in policy profile table.
            content_marker: "developer-laptop",
        },
        Case {
            name: "mcp-proxy-bare",
            args: &["mcp-proxy"],
            expect_success: false,
            content_marker: "Usage:",
        },
        Case {
            name: "mcp-proxy-help",
            args: &["mcp-proxy", "--help"],
            expect_success: true,
            content_marker: "Usage:",
        },
    ];

    for case in CASES {
        let root = temp_root(case.name);
        let output = run_in_pty(case.args, &root, case.expect_success);

        let banner_pos = output.find(BANNER_TAGLINE).unwrap_or_else(|| {
            panic!(
                "case {:?}: banner tagline must appear:\n{output}",
                case.name
            )
        });
        let content_pos = output.find(case.content_marker).unwrap_or_else(|| {
            panic!(
                "case {:?}: expected content marker {:?} not found:\n{output}",
                case.name, case.content_marker
            )
        });
        assert!(
            banner_pos < content_pos,
            "case {:?}: banner must appear before content (banner@{banner_pos}, content@{content_pos}):\n{output}",
            case.name
        );
    }
}

/// Clap help/version output must land only on stdout, never stderr, with
/// or without a splash (redirected here, so no splash — but this proves
/// the routing itself, independent of splash visibility).
#[test]
fn help_and_version_content_only_on_stdout() {
    for args in [vec!["--help"], vec!["help"], vec!["--version"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_etherfence"))
            .args(&args)
            .env_remove("CI")
            .env_remove("NO_COLOR")
            .output()
            .unwrap_or_else(|e| panic!("run etherfence {args:?}: {e}"));
        assert!(output.status.success(), "etherfence {args:?} must exit 0");
        assert!(
            !output.stdout.is_empty(),
            "etherfence {args:?} must write to stdout"
        );
        assert!(
            output.stderr.is_empty(),
            "etherfence {args:?} must not write to stderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

/// Clap usage/argument errors must land only on stderr, never stdout.
#[test]
fn usage_and_argument_errors_only_on_stderr() {
    for args in [vec![], vec!["policy"], vec!["mcp-proxy"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_etherfence"))
            .args(&args)
            .env_remove("CI")
            .env_remove("NO_COLOR")
            .output()
            .unwrap_or_else(|e| panic!("run etherfence {args:?}: {e}"));
        assert!(
            !output.status.success(),
            "etherfence {args:?} must exit non-zero"
        );
        assert!(
            output.stdout.is_empty(),
            "etherfence {args:?} must not write to stdout:\n{}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(
            !output.stderr.is_empty(),
            "etherfence {args:?} must write to stderr"
        );
    }
}

/// `policy show` emits raw TOML for piping and must never show the splash,
/// even on an interactive PTY (unlike `policy list`, which is human
/// terminal output).
#[cfg(unix)]
#[test]
fn policy_show_suppresses_banner_on_pty() {
    let root = temp_root("policy-show");
    let stdout = run_in_pty(&["policy", "show", "developer-laptop"], &root, true);
    assert!(
        !stdout.contains(BANNER_TAGLINE),
        "banner tagline must not appear in `policy show` output:\n{stdout}"
    );
    assert!(
        stdout.contains("schema_version"),
        "expected raw policy TOML on the PTY:\n{stdout}"
    );
}

/// `mcp-policy init` without `--output` emits raw policy TOML for piping
/// and must never show the splash.
#[cfg(unix)]
#[test]
fn mcp_policy_init_suppresses_banner_on_pty() {
    let root = temp_root("mcp-policy-init");
    let stdout = run_in_pty(&["mcp-policy", "init", "--profile", "minimal"], &root, true);
    assert!(
        !stdout.contains(BANNER_TAGLINE),
        "banner tagline must not appear in `mcp-policy init` output:\n{stdout}"
    );
    assert!(
        stdout.contains("schema_version"),
        "expected raw policy TOML on the PTY:\n{stdout}"
    );
}

/// `scan --format markdown`/`--format sarif` must never show the splash,
/// even on a PTY (only `--format human` is splash-eligible).
#[cfg(unix)]
#[test]
fn scan_machine_formats_suppress_banner_on_pty() {
    let root = fixture_root("home");
    for format in ["markdown", "sarif"] {
        let stdout = run_in_pty(
            &["scan", "--format", format, "--root", &root],
            &temp_root(&format!("scan-{format}")),
            true,
        );
        assert!(
            !stdout.contains(BANNER_TAGLINE),
            "banner tagline must not appear in scan --format {format} output:\n{stdout}"
        );
    }
}

/// `CI`, `NO_COLOR`, `CLICOLOR=0`, and `TERM=dumb` must each continue to
/// suppress the splash for a newly-splash-eligible Clap help path, exactly
/// as they already do for successfully-parsed human commands.
///
/// Note: `--help` output always includes Clap's own `about` text, which is
/// (coincidentally) the same string as `BANNER_TAGLINE`, so this test
/// checks for the banner's version line instead — a string that only the
/// rendered splash footer ever produces.
#[cfg(unix)]
#[test]
fn env_suppression_still_applies_to_help_on_pty() {
    let version_marker = concat!("v", env!("CARGO_PKG_VERSION"));
    let cases: &[(&str, &[(&str, &str)])] = &[
        ("CI", &[("CI", "1")]),
        ("NO_COLOR", &[("NO_COLOR", "1")]),
        ("CLICOLOR", &[("CLICOLOR", "0")]),
        ("TERM_dumb", &[("TERM", "dumb")]),
    ];
    for (name, extra_env) in cases {
        let root = temp_root(&format!("env-suppress-{name}"));
        let stdout = run_in_pty_with_env(&["--help"], &root, true, extra_env);
        assert!(
            !stdout.contains(version_marker),
            "case {name}: banner version line must not appear:\n{stdout}"
        );
        assert!(
            stdout.contains("Usage:"),
            "case {name}: help text must still be present:\n{stdout}"
        );
    }
}

/// Runs the etherfence binary inside a real pseudo-terminal with a
/// color-friendly environment and returns everything written to it.
/// Asserts the process exit status matches `expect_success`.
#[cfg(unix)]
fn run_in_pty(args: &[&str], cwd: &std::path::Path, expect_success: bool) -> String {
    run_in_pty_with_env(args, cwd, expect_success, &[])
}

/// Like [`run_in_pty`], but lets the caller layer additional/overriding
/// environment variables on top of the color-friendly PTY defaults.
#[cfg(unix)]
fn run_in_pty_with_env(
    args: &[&str],
    cwd: &std::path::Path,
    expect_success: bool,
    extra_env: &[(&str, &str)],
) -> String {
    use portable_pty::{native_pty_system, CommandBuilder, PtySize};
    use std::io::Read;

    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows: 40,
            cols: 120,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("open pty");

    let mut cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_etherfence"));
    cmd.args(args);
    cmd.cwd(cwd);
    cmd.env_remove("CI");
    cmd.env_remove("NO_COLOR");
    cmd.env_remove("CLICOLOR");
    cmd.env("TERM", "xterm-256color");
    cmd.env("COLUMNS", "120");
    for (key, value) in extra_env {
        cmd.env(key, value);
    }

    let mut child = pair.slave.spawn_command(cmd).expect("spawn in pty");
    drop(pair.slave);

    let mut reader = pair.master.try_clone_reader().expect("clone pty reader");
    let mut raw = Vec::new();
    // EOF arrives when the child exits and the slave side closes.
    let _ = reader.read_to_end(&mut raw);
    let status = child.wait().expect("wait for child");
    assert_eq!(
        status.success(),
        expect_success,
        "etherfence {args:?} exit status mismatch (expected success={expect_success})"
    );

    strip_ansi(&String::from_utf8_lossy(&raw))
}

/// Removes ANSI escape sequences so assertions match plain text.
#[cfg(unix)]
fn strip_ansi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\u{1b}' {
            out.push(ch);
            continue;
        }
        if chars.peek() == Some(&'[') {
            chars.next();
            for follow in chars.by_ref() {
                if follow.is_ascii_alphabetic() {
                    break;
                }
            }
        }
    }
    out
}
