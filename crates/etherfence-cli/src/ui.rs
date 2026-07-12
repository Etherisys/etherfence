//! Terminal UI theme layer: semantic styles, badges, and layout helpers.
//!
//! One restrained, semantic color system for every human-facing surface:
//! terminal-default text for normal content, color only where it carries
//! meaning (risk, success, paths, technical IDs). All helpers degrade to
//! plain text automatically when colors are disabled (redirected output,
//! NO_COLOR, dumb terminals) via `console`'s own detection.

use dialoguer::console::Style;
use std::io;

use terminal_size::{terminal_size_of, Width};

/// Semantic styles for human-facing output.
///
/// `for_stderr` variants are used by the wizard (which prompts on stderr);
/// everything else writes to stdout.
pub(crate) struct UiTheme {
    pub heading: Style,
    pub success: Style,
    pub info: Style,
    pub warning: Style,
    pub danger: Style,
    pub muted: Style,
    pub path: Style,
}

impl UiTheme {
    pub fn for_stdout() -> Self {
        Self {
            heading: Style::new().bold().for_stdout(),
            success: Style::new().green().for_stdout(),
            info: Style::new().cyan().for_stdout(),
            warning: Style::new().yellow().for_stdout(),
            danger: Style::new().red().for_stdout(),
            muted: Style::new().dim().for_stdout(),
            path: Style::new().cyan().for_stdout(),
        }
    }

    pub fn for_stderr() -> Self {
        Self {
            heading: Style::new().bold().for_stderr(),
            success: Style::new().green().for_stderr(),
            info: Style::new().cyan().for_stderr(),
            warning: Style::new().yellow().for_stderr(),
            danger: Style::new().red().for_stderr(),
            muted: Style::new().dim().for_stderr(),
            path: Style::new().cyan().for_stderr(),
        }
    }

    /// A section heading followed by a horizontal rule.
    pub fn section(&self, title: &str) -> String {
        format!("{}\n{}", self.heading.apply_to(title), self.rule())
    }

    /// A wizard step heading (`Step 2 of 7  Choose AI clients`) with rule.
    pub fn step(&self, step: usize, total: usize, title: &str) -> String {
        format!(
            "{}  {}\n{}",
            self.muted.apply_to(format!("Step {step} of {total}")),
            self.heading.apply_to(title),
            self.rule()
        )
    }

    fn rule(&self) -> String {
        self.muted
            .apply_to("─".repeat(human_width().min(60)))
            .to_string()
    }

    /// A right-hand support badge for a client row.
    pub fn support_badge(&self, can_configure: bool) -> String {
        if can_configure {
            self.info.apply_to("CAN CONFIGURE").to_string()
        } else {
            self.muted.apply_to("DETECT ONLY").to_string()
        }
    }

    /// An aligned key/value row (`Scanned       /home/user`).
    pub fn key_value(&self, label: &str, value: &str) -> String {
        format!("{:<14}{}", label, value)
    }

    /// A width-aware aligned key/value block. ANSI styling in `value` is
    /// stripped during width measurement so colors never distort alignment.
    pub fn key_value_wrapped(&self, label: &str, value: &str, width: usize) -> String {
        let prefix = format!("{label:<14}");
        etherfence_report::human_layout::wrap_prefixed(
            &prefix,
            " ".repeat(14).as_str(),
            value,
            width,
        )
        .join("\n")
    }
}

/// Renders a finding-count line like `0 critical · 2 high · 5 medium · 9 low`.
pub(crate) fn severity_counts(
    theme: &UiTheme,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
) -> String {
    format!(
        "{} · {} · {} · {}",
        colored_count(&theme.danger, high, "high"),
        colored_count(&theme.warning, medium, "medium"),
        colored_count(&theme.info, low, "low"),
        colored_count(&theme.muted, info, "info"),
    )
}

fn colored_count(style: &Style, count: usize, label: &str) -> String {
    let text = format!("{count} {label}");
    if count == 0 {
        text
    } else {
        style.apply_to(text).to_string()
    }
}

/// Pads a plain string to `width` display columns. Styled strings must be
/// padded before styling (ANSI codes would break the count).
pub(crate) fn pad(text: &str, width: usize) -> String {
    let mut out = String::from(text);
    let len = text.chars().count();
    if len < width {
        for _ in len..width {
            out.push(' ');
        }
    }
    out
}

pub(crate) fn human_width() -> usize {
    terminal_size_of(io::stdout())
        .map(|(Width(width), _)| usize::from(width))
        .or_else(|| {
            std::env::var("COLUMNS")
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
        })
        .filter(|width| *width > 0)
        .unwrap_or(etherfence_report::human_layout::DEFAULT_HUMAN_WIDTH)
        .max(etherfence_report::human_layout::MIN_SUPPORTED_WIDTH)
}

pub(crate) fn wrap_prefixed(prefix: &str, continuation: &str, text: &str, width: usize) -> String {
    etherfence_report::human_layout::wrap_prefixed(prefix, continuation, text, width).join("\n")
}

/// `1 server` / `3 servers`, or `no MCP servers` when zero.
pub(crate) fn count_servers(count: usize) -> String {
    match count {
        0 => "no MCP servers".to_string(),
        1 => "1 MCP server".to_string(),
        n => format!("{n} MCP servers"),
    }
}

// ── Unicode / ASCII fallback ───────────────────────────────────────────

/// Whether the terminal is likely to support Unicode (box-drawing chars, symbols).
pub(crate) fn unicode_supported() -> bool {
    if std::env::var_os("NO_UNICODE").is_some() {
        return false;
    }
    let term = std::env::var("TERM").unwrap_or_default();
    if term == "dumb" {
        return false;
    }
    let lang = std::env::var("LANG").unwrap_or_default();
    let lc_all = std::env::var("LC_ALL").unwrap_or_default();
    if lang.ends_with("C") && !lang.contains("UTF-8") {
        return false;
    }
    if lc_all.ends_with("C") && !lc_all.contains("UTF-8") {
        return false;
    }
    true
}

#[allow(dead_code)]
pub(crate) fn checkmark() -> &'static str {
    if unicode_supported() {
        "\u{2713}"
    } else {
        "[OK]"
    }
}

#[allow(dead_code)]
pub(crate) fn circle() -> &'static str {
    if unicode_supported() {
        "\u{25cb}"
    } else {
        "[  ]"
    }
}

#[allow(dead_code)]
pub(crate) fn cross_mark() -> &'static str {
    if unicode_supported() {
        "\u{2717}"
    } else {
        "[!!]"
    }
}

pub(crate) fn rule_char() -> &'static str {
    if unicode_supported() {
        "\u{2500}"
    } else {
        "-"
    }
}

/// Box top border: `┌──...──┐` (or ASCII `+--...--+`).
#[allow(dead_code)]
pub(crate) fn box_top(width: usize) -> String {
    let w = width.saturating_sub(2);
    if unicode_supported() {
        format!("\u{250c}{}\u{2510}", "\u{2500}".repeat(w))
    } else {
        format!("+{}+", "-".repeat(w))
    }
}

/// Box bottom border: `└──...──┘` (or ASCII `+--...--+`).
#[allow(dead_code)]
pub(crate) fn box_bottom(width: usize) -> String {
    let w = width.saturating_sub(2);
    if unicode_supported() {
        format!("\u{2514}{}\u{2518}", "\u{2500}".repeat(w))
    } else {
        format!("+{}+", "-".repeat(w))
    }
}

/// Full-width horizontal rule.
#[allow(dead_code)]
pub(crate) fn rule(width: usize) -> String {
    rule_char().repeat(width)
}

#[cfg(test)]
mod unicode_tests {
    use super::*;
    use std::env;

    fn with_env<F, T>(vars: &[(&str, &str)], f: F) -> T
    where
        F: FnOnce() -> T,
    {
        // Save and restore env
        let saved: Vec<(&str, Option<String>)> =
            vars.iter().map(|(k, _)| (*k, env::var(k).ok())).collect();
        for (k, v) in vars {
            env::set_var(k, v);
        }
        let result = f();
        for (k, orig) in saved {
            match orig {
                Some(v) => env::set_var(k, v),
                None => env::remove_var(k),
            }
        }
        result
    }

    #[test]
    fn unicode_supported_true_in_normal_env() {
        with_env(
            &[("TERM", "xterm-256color"), ("LANG", "en_US.UTF-8")],
            || assert!(unicode_supported()),
        );
    }

    #[test]
    fn unicode_disabled_for_dumb_terminal() {
        with_env(&[("TERM", "dumb"), ("LANG", "en_US.UTF-8")], || {
            assert!(!unicode_supported())
        });
    }

    #[test]
    fn unicode_disabled_for_no_unicode_env() {
        with_env(
            &[
                ("TERM", "xterm-256color"),
                ("LANG", "en_US.UTF-8"),
                ("NO_UNICODE", "1"),
            ],
            || assert!(!unicode_supported()),
        );
    }

    #[test]
    fn unicode_disabled_for_lang_c() {
        with_env(&[("TERM", "xterm-256color"), ("LANG", "C")], || {
            assert!(!unicode_supported())
        });
    }

    #[test]
    fn unicode_disabled_for_lc_all_c() {
        with_env(
            &[
                ("TERM", "xterm-256color"),
                ("LANG", "en_US.UTF-8"),
                ("LC_ALL", "C"),
            ],
            || assert!(!unicode_supported()),
        );
    }
}
