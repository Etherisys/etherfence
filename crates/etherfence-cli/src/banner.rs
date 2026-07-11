use std::env;
use std::io::{self, IsTerminal, Write};

use anstream::{AutoStream, ColorChoice};
use terminal_size::{terminal_size_of, Width};

const STANDARD_MIN_WIDTH: u16 = 100;
const CYAN: &str = "\x1b[96m";
const PURPLE: &str = "\x1b[35m";
const DIM_WHITE: &str = "\x1b[2;37m";
const DARK_GRAY: &str = "\x1b[90m";
const RESET: &str = "\x1b[0m";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OutputMode {
    Human,
    Machine,
    Protocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BannerStyle {
    Standard,
    Compact,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TerminalEnvironment {
    stdout_is_terminal: bool,
    no_color: bool,
    ci: bool,
    clicolor_disabled: bool,
    term: Option<String>,
    columns: Option<u16>,
    ansi_supported: bool,
}

impl TerminalEnvironment {
    fn current() -> Self {
        Self {
            stdout_is_terminal: io::stdout().is_terminal(),
            no_color: env::var_os("NO_COLOR").is_some(),
            ci: env::var_os("CI").is_some(),
            clicolor_disabled: env::var("CLICOLOR").is_ok_and(|value| value == "0"),
            term: env::var("TERM").ok(),
            columns: terminal_width().or_else(columns_env),
            ansi_supported: ansi_supported_by_stdout(),
        }
    }

    fn colors_enabled(&self) -> bool {
        self.stdout_is_terminal
            && !self.no_color
            && !self.ci
            && !self.clicolor_disabled
            && self.ansi_supported
            && self.term.as_deref() != Some("dumb")
    }
}

fn terminal_width() -> Option<u16> {
    terminal_size_of(io::stdout()).map(|(Width(width), _)| width)
}

fn columns_env() -> Option<u16> {
    env::var("COLUMNS")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
}

fn ansi_supported_by_stdout() -> bool {
    !matches!(AutoStream::choice(&io::stdout()), ColorChoice::Never)
}

pub(crate) fn print_startup_banner(mode: OutputMode) {
    if let Some(output) = render_startup_banner(mode, &TerminalEnvironment::current()) {
        let mut stdout = anstream::stdout().lock();
        let _ = stdout.write_all(output.as_bytes());
    }
}

fn render_startup_banner(mode: OutputMode, env: &TerminalEnvironment) -> Option<String> {
    if !should_show(mode, env) {
        return None;
    }
    Some(match banner_style(env) {
        BannerStyle::Standard => render_standard_banner(),
        BannerStyle::Compact => render_compact_banner(),
    })
}

fn should_show(mode: OutputMode, env: &TerminalEnvironment) -> bool {
    mode == OutputMode::Human && env.colors_enabled()
}

fn banner_style(env: &TerminalEnvironment) -> BannerStyle {
    match env.columns {
        Some(width) if width < STANDARD_MIN_WIDTH => BannerStyle::Compact,
        Some(_) => BannerStyle::Standard,
        None => BannerStyle::Compact,
    }
}

fn render_standard_banner() -> String {
    let mut out = String::new();
    for (ether, fence) in STANDARD_BANNER_LINES {
        out.push_str(CYAN);
        out.push_str(ether);
        out.push_str(PURPLE);
        out.push_str(fence);
        out.push_str(RESET);
        out.push('\n');
    }
    out.push('\n');
    out.push_str(DIM_WHITE);
    out.push_str("                    AI Agent Security Posture & Runtime Control\n");
    out.push_str(RESET);
    out.push('\n');
    out.push_str(DARK_GRAY);
    out.push_str("                    v");
    out.push_str(env!("CARGO_PKG_VERSION"));
    out.push('\n');
    out.push_str(RESET);
    out.push('\n');
    out
}

fn render_compact_banner() -> String {
    format!(
        "{CYAN}ETHER{PURPLE}FENCE{RESET}\n{DIM_WHITE}AI Agent Security Posture & Runtime Control{RESET}\n{DARK_GRAY}v{}{RESET}\n\n",
        env!("CARGO_PKG_VERSION")
    )
}

const STANDARD_BANNER_LINES: &[(&str, &str)] = &[
    (
        "███████╗████████╗██╗  ██╗███████╗██████╗ ",
        "███████╗███████╗███╗   ██╗ ██████╗███████╗",
    ),
    (
        "██╔════╝╚══██╔══╝██║  ██║██╔════╝██╔══██╗",
        "██╔════╝██╔════╝████╗  ██║██╔════╝██╔════╝",
    ),
    (
        "█████╗     ██║   ███████║█████╗  ██████╔╝",
        "█████╗  █████╗  ██╔██╗ ██║██║     █████╗  ",
    ),
    (
        "██╔══╝     ██║   ██╔══██║██╔══╝  ██╔══██╗",
        "██╔══╝  ██╔══╝  ██║╚██╗██║██║     ██╔══╝  ",
    ),
    (
        "███████╗   ██║   ██║  ██║███████╗██║  ██║",
        "██║     ███████╗██║ ╚████║╚██████╗███████╗",
    ),
    (
        "╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝",
        "╚═╝     ╚══════╝╚═╝  ╚═══╝ ╚═════╝╚══════╝",
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    fn env(stdout_is_terminal: bool, columns: Option<u16>) -> TerminalEnvironment {
        TerminalEnvironment {
            stdout_is_terminal,
            no_color: false,
            ci: false,
            clicolor_disabled: false,
            term: Some("xterm-256color".to_string()),
            columns,
            ansi_supported: true,
        }
    }

    #[test]
    fn interactive_human_terminal_shows_banner() {
        assert!(should_show(OutputMode::Human, &env(true, Some(120))));
    }

    #[test]
    fn json_or_other_machine_output_suppresses_banner() {
        assert!(!should_show(OutputMode::Machine, &env(true, Some(120))));
    }

    #[test]
    fn protocol_output_suppresses_banner() {
        assert!(!should_show(OutputMode::Protocol, &env(true, Some(120))));
    }

    #[test]
    fn redirected_stdout_suppresses_banner() {
        assert!(!should_show(OutputMode::Human, &env(false, Some(120))));
    }

    #[test]
    fn no_color_suppresses_banner() {
        let mut terminal = env(true, Some(120));
        terminal.no_color = true;
        assert!(!should_show(OutputMode::Human, &terminal));
    }

    #[test]
    fn ci_suppresses_banner() {
        let mut terminal = env(true, Some(120));
        terminal.ci = true;
        assert!(!should_show(OutputMode::Human, &terminal));
    }

    #[test]
    fn dumb_terminal_suppresses_banner() {
        let mut terminal = env(true, Some(120));
        terminal.term = Some("dumb".to_string());
        assert!(!should_show(OutputMode::Human, &terminal));
    }

    #[test]
    fn compact_banner_selected_for_narrow_terminal() {
        assert_eq!(banner_style(&env(true, Some(80))), BannerStyle::Compact);
    }

    #[test]
    fn standard_banner_selected_for_wide_terminal() {
        assert_eq!(banner_style(&env(true, Some(120))), BannerStyle::Standard);
    }

    #[test]
    fn compact_banner_selected_when_width_is_unknown() {
        assert_eq!(banner_style(&env(true, None)), BannerStyle::Compact);
    }
}
