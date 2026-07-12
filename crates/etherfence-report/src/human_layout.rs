//! Plain, deterministic terminal-width layout helpers for human reports.
//!
//! Inputs may carry ANSI SGR escape sequences (styling). Width measurement
//! strips those sequences first so styled text can be wrapped without
//! alignment distortion. Callers may style after layout, or may pass styled
//! text directly — both paths produce correct display widths.

use unicode_width::UnicodeWidthChar;

pub const DEFAULT_HUMAN_WIDTH: usize = 88;
pub const MIN_SUPPORTED_WIDTH: usize = 30;

pub fn display_width(text: &str) -> usize {
    let stripped = strip_ansi(text);
    stripped
        .chars()
        .map(|character| UnicodeWidthChar::width(character).unwrap_or(0))
        .sum()
}

/// Strip ANSI SGR escape sequences (CSI … m) so width measurement
/// ignores terminal styling bytes.
fn strip_ansi(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let bytes = text.as_bytes();
    let mut pos = 0usize;

    while pos < bytes.len() {
        if bytes[pos] == 0x1b && pos + 1 < bytes.len() && bytes[pos + 1] == b'[' {
            // Find the end of the CSI sequence (0x40–0x7E)
            let mut end = pos + 2;
            while end < bytes.len() && !(0x40..=0x7E).contains(&bytes[end]) {
                end += 1;
            }
            if end < bytes.len() {
                // include the final byte
                end += 1;
            } else {
                end = pos + 1; // malformed, skip just the ESC
            }
            pos = end;
        } else {
            // Count UTF-8 continuation bytes to advance correctly
            let c = chars.next().unwrap_or('\0');
            let len = c.len_utf8();
            result.push(c);
            pos += len;
        }
    }
    result
}

/// Wrap plain or styled text behind a first-line prefix and a stable continuation prefix.
/// Long words are split at Unicode character boundaries so a hostile or unusual
/// finding value cannot force arbitrary horizontal overflow.
pub fn wrap_prefixed(prefix: &str, continuation: &str, text: &str, width: usize) -> Vec<String> {
    let width = width.max(MIN_SUPPORTED_WIDTH);
    let mut lines = Vec::new();
    let mut current_prefix = prefix;
    let mut current = String::new();
    let mut capacity = width.saturating_sub(display_width(current_prefix));

    if capacity == 0 && !text.is_empty() {
        lines.push(prefix.trim_end().to_string());
        current_prefix = continuation;
        capacity = width.saturating_sub(display_width(current_prefix));
    }

    let stripped = strip_ansi(text);
    for word in stripped.split_whitespace() {
        let separator = usize::from(!current.is_empty());
        if display_width(&current) + separator + display_width(word) <= capacity {
            if separator == 1 {
                current.push(' ');
            }
            current.push_str(word);
            continue;
        }

        if !current.is_empty() {
            lines.push(format!("{current_prefix}{current}"));
            current_prefix = continuation;
            capacity = width.saturating_sub(display_width(current_prefix));
            current.clear();
        }

        let mut word_part = String::new();
        for character in word.chars() {
            let character_width = UnicodeWidthChar::width(character).unwrap_or(0);
            if !word_part.is_empty() && display_width(&word_part) + character_width > capacity {
                lines.push(format!("{current_prefix}{word_part}"));
                current_prefix = continuation;
                capacity = width.saturating_sub(display_width(current_prefix));
                word_part.clear();
            }
            word_part.push(character);
        }
        current = word_part;
    }

    if !current.is_empty() {
        lines.push(format!("{current_prefix}{current}"));
    } else if text.is_empty() {
        lines.push(prefix.trim_end().to_string());
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_long_unicode_and_ascii_with_stable_indentation() {
        let lines = wrap_prefixed(
            "  Recommendation: ",
            "                  ",
            "Review extraordinarilylongasciitoken and 影響範囲を確認してください before continuing.",
            32,
        );
        assert!(lines.len() > 2);
        assert!(lines.iter().all(|line| display_width(line) <= 32));
        assert!(lines[0].starts_with("  Recommendation: "));
        assert!(lines
            .iter()
            .skip(1)
            .all(|line| line.starts_with("                  ")));
    }

    #[test]
    fn preserves_a_line_for_empty_content() {
        assert_eq!(wrap_prefixed("Scope: ", "       ", "", 24), vec!["Scope:"]);
    }
}
