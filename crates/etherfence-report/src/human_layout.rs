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

/// Strip ANSI CSI escape sequences (`ESC [ … <final>`) so width measurement
/// ignores terminal styling bytes.
///
/// Single-cursor over `chars()`: a byte index desynchronises from the char
/// iterator the moment a multi-byte or escape sequence is skipped, which
/// previously corrupted and truncated every styled line that was wrapped.
fn strip_ansi(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            // Consume the '[' then everything up to and including the CSI
            // final byte (0x40–0x7E). A sequence truncated at end-of-string
            // is consumed entirely (nothing left to render anyway).
            chars.next();
            while let Some(&next) = chars.peek() {
                chars.next();
                if ('\u{40}'..='\u{7e}').contains(&next) {
                    break;
                }
            }
        } else {
            result.push(c);
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

    // Common case: the whole value fits on one line. Emit the ORIGINAL text
    // so any ANSI styling is preserved (the word-wrapping path below rebuilds
    // from ANSI-stripped words and necessarily drops styling).
    if !text.is_empty() && !text.contains('\n') && display_width(text) <= capacity {
        lines.push(format!("{current_prefix}{text}"));
        return lines;
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

    #[test]
    fn strip_ansi_does_not_truncate_after_escape() {
        // Regression: byte/char cursor desync used to drop everything after
        // the first CSI sequence and leak a raw escape.
        assert_eq!(strip_ansi("\x1b[31mHIGH\x1b[0m tail"), "HIGH tail");
        assert_eq!(strip_ansi("a\x1b[33mb\x1b[0mc"), "abc");
        assert_eq!(display_width("\x1b[31mHIGH\x1b[0m tail"), "HIGH tail".len());
    }

    #[test]
    fn strip_ansi_handles_multibyte_and_malformed() {
        assert_eq!(strip_ansi("影\x1b[1m響\x1b[0m"), "影響");
        // Malformed (ESC not followed by '[') is preserved as content.
        assert_eq!(strip_ansi("x\x1by"), "x\u{1b}y");
    }

    #[test]
    fn styled_value_that_fits_keeps_its_ansi() {
        // A short styled value must not lose its color when it fits one line.
        let styled = "0 high \x1b[33m2 medium\x1b[0m 5 low";
        let lines = wrap_prefixed("Findings      ", "              ", styled, 80);
        assert_eq!(lines, vec![format!("Findings      {styled}")]);
    }

    #[test]
    fn styled_value_that_wraps_is_complete_even_if_unstyled() {
        // When wrapping is required styling is dropped, but no text is lost
        // (regression: the old strip_ansi truncated the tail). Width 40 is
        // above the MIN_SUPPORTED_WIDTH floor so the requested width applies.
        let styled =
            "\x1b[31mextraordinarilylongasciitokenthatmustsplit\x1b[0m and another long token here";
        let lines = wrap_prefixed("  R: ", "     ", styled, 40);
        assert!(lines.iter().all(|line| display_width(line) <= 40));
        let joined: String = lines.iter().map(|l| l.trim()).collect::<Vec<_>>().join(" ");
        assert!(joined.contains("another long token here"));
    }
}
