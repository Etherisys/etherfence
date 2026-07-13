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

/// The banner's version-footer line. Unlike `BANNER_TAGLINE`, Clap never
/// emits this string on its own (its `--version`/`-V` output is
/// `"etherfence {version}"`, with no leading `v` and no tagline), so it is
/// safe to use as a splash-only marker even for commands whose Clap help
/// text happens to repeat the tagline (see `BANNER_GLYPH_MARKER` below).
/// Only used by the unix-only PTY tests below.
#[cfg(unix)]
const BANNER_VERSION_MARKER: &str = concat!("v", env!("CARGO_PKG_VERSION"));

/// A fragment of the Unicode block-art wordmark rendered only by the
/// `Standard` banner style (selected whenever the PTY tests' fixed
/// 120-column width is in effect). Like `BANNER_VERSION_MARKER`, Clap never
/// emits this on its own; used together with the version marker so the
/// splash-only check does not rely on a single string. Only used by the
/// unix-only PTY tests below.
#[cfg(unix)]
const BANNER_GLYPH_MARKER: &str = "███";

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
/// `--help`, `--version`, `policy` (missing subcommand), `policy --help`,
/// `mcp-proxy` (missing required args), `mcp-proxy --help`, plus
/// `policy list` (newly reclassified as human/splash-eligible). Every case
/// must show the splash *before* its own recognizable content on an
/// interactive, color-capable terminal.
///
/// Detection deliberately does **not** use `BANNER_TAGLINE`: Clap's own
/// `about` text is that exact same string, so for `help`/`--help`/
/// `policy --help`/`mcp-proxy --help` a regression that removed the splash
/// entirely would still leave that text present (from Clap alone), before
/// `"Usage:"`, and this test would pass anyway. Instead it requires two
/// markers that only the rendered splash footer produces —
/// `BANNER_VERSION_MARKER` and `BANNER_GLYPH_MARKER` — both present and
/// both ordered before the command's own content.
#[cfg(unix)]
#[test]
fn reported_commands_show_banner_before_content_on_pty() {
    struct Case {
        name: &'static str,
        args: &'static [&'static str],
        expect_success: bool,
        content_marker: &'static str,
    }

    let version_content_marker = concat!("etherfence ", env!("CARGO_PKG_VERSION"));

    let cases: &[Case] = &[
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
            name: "version-flag",
            args: &["--version"],
            expect_success: true,
            // Clap's own version output ("etherfence 1.7.3", no leading
            // `v`) — distinct from the banner's "v1.7.3" version marker.
            content_marker: version_content_marker,
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

    for case in cases {
        let root = temp_root(case.name);
        let output = run_in_pty(case.args, &root, case.expect_success);

        let version_pos = output.find(BANNER_VERSION_MARKER).unwrap_or_else(|| {
            panic!(
                "case {:?}: banner version marker must appear:\n{output}",
                case.name
            )
        });
        let glyph_pos = output.find(BANNER_GLYPH_MARKER).unwrap_or_else(|| {
            panic!(
                "case {:?}: banner glyph marker must appear:\n{output}",
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
            version_pos < content_pos && glyph_pos < content_pos,
            "case {:?}: banner must appear before content (version@{version_pos}, glyph@{glyph_pos}, content@{content_pos}):\n{output}",
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

/// Which standard stream is attached to the real pseudo-terminal in a
/// split-stream test ([`run_split_stream`]); the other stream is a plain
/// OS pipe.
#[cfg(unix)]
#[derive(Clone, Copy)]
enum PtyStream {
    Stdout,
    Stderr,
}

/// Split-stream regression: with only stdout attached to a real terminal
/// and stderr piped, `--help` must show the splash on stdout, and the
/// piped stderr must stay empty. Positive case for the help→stdout routing
/// decision (FR-002/FR-003).
#[cfg(unix)]
#[test]
fn help_shows_banner_on_stdout_pty_with_stderr_piped() {
    let root = temp_root("split-help-stdout-pty");
    let (pty_text, piped_stderr) = run_split_stream(&["--help"], &root, PtyStream::Stdout, true);
    assert!(
        pty_text.contains(BANNER_VERSION_MARKER) && pty_text.contains(BANNER_GLYPH_MARKER),
        "banner must appear on the terminal-attached stdout:\n{pty_text}"
    );
    assert!(
        pty_text.contains("Usage:"),
        "help text must appear on the terminal-attached stdout:\n{pty_text}"
    );
    assert!(
        piped_stderr.is_empty(),
        "piped stderr must stay empty:\n{piped_stderr}"
    );
}

/// Split-stream regression: with only stderr attached to a real terminal
/// and stdout piped, a Clap usage error must show the splash on stderr,
/// and the piped stdout must stay empty. Positive case for the
/// error→stderr routing decision.
#[cfg(unix)]
#[test]
fn parse_error_shows_banner_on_stderr_pty_with_stdout_piped() {
    let root = temp_root("split-error-stderr-pty");
    let (pty_text, piped_stdout) =
        run_split_stream(&["mcp-proxy"], &root, PtyStream::Stderr, false);
    assert!(
        pty_text.contains(BANNER_VERSION_MARKER) && pty_text.contains(BANNER_GLYPH_MARKER),
        "banner must appear on the terminal-attached stderr:\n{pty_text}"
    );
    assert!(
        pty_text.contains("Usage:"),
        "usage error must appear on the terminal-attached stderr:\n{pty_text}"
    );
    assert!(
        piped_stdout.is_empty(),
        "piped stdout must stay empty:\n{piped_stdout}"
    );
}

/// Inverse of the positive help case: stdout (help's actual destination)
/// is piped/non-interactive even though stderr happens to be a real
/// terminal. The splash must not appear anywhere, proving eligibility
/// follows the destination stream rather than "some stream is a
/// terminal."
#[cfg(unix)]
#[test]
fn help_suppresses_banner_when_stdout_piped_even_with_stderr_pty() {
    let root = temp_root("split-help-stderr-pty");
    let (pty_text, piped_stdout) = run_split_stream(&["--help"], &root, PtyStream::Stderr, true);
    assert!(
        pty_text.is_empty(),
        "help output never targets stderr, terminal or not:\n{pty_text}"
    );
    assert!(
        piped_stdout.contains("Usage:"),
        "help text must still appear on piped stdout:\n{piped_stdout}"
    );
    assert!(
        !piped_stdout.contains(BANNER_VERSION_MARKER)
            && !piped_stdout.contains(BANNER_GLYPH_MARKER),
        "banner must not appear on the piped, non-interactive stdout:\n{piped_stdout}"
    );
}

/// Inverse of the positive error case: stderr (the error's actual
/// destination) is piped/non-interactive even though stdout happens to be
/// a real terminal. The splash must not appear anywhere — this is exactly
/// the scenario a regression that reverted to unconditionally checking
/// `io::stdout()` would get wrong: it would incorrectly show the splash on
/// the terminal-attached stdout, which never receives this content at all.
#[cfg(unix)]
#[test]
fn parse_error_suppresses_banner_when_stderr_piped_even_with_stdout_pty() {
    let root = temp_root("split-error-stdout-pty");
    let (pty_text, piped_stderr) =
        run_split_stream(&["mcp-proxy"], &root, PtyStream::Stdout, false);
    assert!(
        pty_text.is_empty(),
        "a Clap usage error never targets stdout, terminal or not:\n{pty_text}"
    );
    assert!(
        piped_stderr.contains("Usage:"),
        "usage error text must still appear on piped stderr:\n{piped_stderr}"
    );
    assert!(
        !piped_stderr.contains(BANNER_VERSION_MARKER)
            && !piped_stderr.contains(BANNER_GLYPH_MARKER),
        "banner must not appear on the piped, non-interactive stderr:\n{piped_stderr}"
    );
}

/// Runs the etherfence binary with exactly one of stdout/stderr attached
/// to a real pseudo-terminal (`pty_stream`) and the other as a plain OS
/// pipe. Returns `(pty_stream_text, piped_stream_text)`, with ANSI
/// stripped from the pty side. Asserts the process exit status matches
/// `expect_success`.
///
/// `portable-pty`'s `CommandBuilder` (used by [`run_in_pty`]) cannot attach
/// only one of a child's stdout/stderr to a pty — it always wires all
/// three standard fds to the same slave — so proving the splash follows
/// the correct *destination* stream (not just "some stream is a
/// terminal") needs this lower-level pair, combined with
/// `std::process::Command`'s native per-stream `Stdio`.
#[cfg(unix)]
fn run_split_stream(
    args: &[&str],
    cwd: &std::path::Path,
    pty_stream: PtyStream,
    expect_success: bool,
) -> (String, String) {
    use std::fs::File;
    use std::io::Read;
    use std::process::{Command, Stdio};

    let (master, slave) = open_pty(120, 40);

    let mut command = Command::new(env!("CARGO_BIN_EXE_etherfence"));
    command.args(args);
    command.current_dir(cwd);
    command.env_remove("CI");
    command.env_remove("NO_COLOR");
    command.env_remove("CLICOLOR");
    command.env("TERM", "xterm-256color");
    command.env("COLUMNS", "120");
    command.stdin(Stdio::null());

    match pty_stream {
        PtyStream::Stdout => {
            command.stdout(Stdio::from(File::from(slave)));
            command.stderr(Stdio::piped());
        }
        PtyStream::Stderr => {
            command.stderr(Stdio::from(File::from(slave)));
            command.stdout(Stdio::piped());
        }
    }

    let mut child = command
        .spawn()
        .expect("spawn split-stream etherfence process");
    // `command` (and the `Stdio`/`File` wrapping the slave fd it still
    // owns internally) must be dropped before reading the pty master: the
    // master only sees EOF once every open reference to the slave side is
    // closed, and `Command::spawn` does not consume `self`, so the parent
    // would otherwise keep its own copy of that fd open for as long as
    // `command` is alive, hanging the read below forever.
    drop(command);

    // The pty master is read on its own thread: it only reaches EOF once
    // the child (the sole holder of the pty slave side) exits, so reading
    // it on the main thread first could deadlock if the piped stream
    // produced more output than fits in the OS pipe buffer before the
    // child exits. Output here is at most a few hundred bytes, far under
    // any OS pipe buffer, but the thread keeps this correct unconditionally.
    let mut master_file = File::from(master);
    let pty_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = master_file.read_to_end(&mut buf);
        buf
    });

    let mut piped_bytes = Vec::new();
    match pty_stream {
        PtyStream::Stdout => child
            .stderr
            .take()
            .expect("stderr is piped")
            .read_to_end(&mut piped_bytes)
            .expect("read piped stderr"),
        PtyStream::Stderr => child
            .stdout
            .take()
            .expect("stdout is piped")
            .read_to_end(&mut piped_bytes)
            .expect("read piped stdout"),
    };

    let status = child.wait().expect("wait for split-stream child");
    let pty_bytes = pty_reader.join().expect("join pty reader thread");

    assert_eq!(
        status.success(),
        expect_success,
        "etherfence {args:?} (split-stream) exit status mismatch (expected success={expect_success})"
    );

    (
        strip_ansi(&String::from_utf8_lossy(&pty_bytes)),
        String::from_utf8_lossy(&piped_bytes).into_owned(),
    )
}

/// Opens a real pseudo-terminal pair via `libc::openpty`, mirroring the
/// approach `portable-pty`'s own unix backend uses internally (so this is
/// already proven to link cleanly in this repo's CI, as a transitive
/// dependency of the existing `portable-pty` dev-dependency).
#[cfg(unix)]
fn open_pty(cols: u16, rows: u16) -> (std::os::unix::io::OwnedFd, std::os::unix::io::OwnedFd) {
    use std::os::unix::io::{FromRawFd, OwnedFd};

    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    let size = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };

    // SAFETY: `master`/`slave` are valid out-pointers for the duration of
    // this call.
    let result = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            &size,
        )
    };
    assert_eq!(
        result,
        0,
        "openpty failed: {}",
        std::io::Error::last_os_error()
    );

    // SAFETY: both descriptors were just returned by `openpty` above,
    // are open, and are not owned anywhere else yet.
    unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) }
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
