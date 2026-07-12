//! Startup splash integration tests.
//!
//! The banner module's own unit tests prove the show/suppress decision
//! logic; these tests prove the module is actually wired into the binary
//! (a disconnected module compiles and passes unit tests without ever
//! printing anything).
//!
//! The PTY test is unix-only: it needs a real pseudo-terminal so the
//! binary sees an interactive stdout.

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

/// Runs the etherfence binary inside a real pseudo-terminal with a
/// color-friendly environment and returns everything written to it.
#[cfg(unix)]
fn run_in_pty(args: &[&str], cwd: &std::path::Path) -> String {
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

    let mut child = pair.slave.spawn_command(cmd).expect("spawn in pty");
    drop(pair.slave);

    let mut reader = pair.master.try_clone_reader().expect("clone pty reader");
    let mut raw = Vec::new();
    // EOF arrives when the child exits and the slave side closes.
    let _ = reader.read_to_end(&mut raw);
    let status = child.wait().expect("wait for child");
    assert!(status.success(), "etherfence {args:?} failed in pty");

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
