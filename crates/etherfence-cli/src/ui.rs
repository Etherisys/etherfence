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
