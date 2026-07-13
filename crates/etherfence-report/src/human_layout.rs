//! Plain, deterministic terminal-width layout helpers for human reports.
//!
//! Inputs may carry ANSI SGR escape sequences (styling). Width measurement
//! strips those sequences first so styled text can be wrapped without
//! alignment distortion. Callers may style after layout, or may pass styled
//! text directly — both paths produce correct display widths.
//!
//! Some of the text laid out here originates in configuration EtherFence
//! does not control (MCP server names, finding targets, …), so this module
//! never trusts arbitrary terminal control content: [`sanitize_terminal_text`]
//! keeps only plain SGR styling (`ESC [ <params> m`) — the one escape shape
//! EtherFence's own theming ever emits — and drops every other C0/C1
//! control byte, CSI, OSC, DCS, or other terminal-control sequence outright.

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

/// Remove every recognized terminal control sequence (CSI of any kind, OSC,
/// DCS, and other string-introduced sequences) and every other C0/C1 control
/// byte, keeping only plain SGR styling sequences EtherFence itself emits.
///
/// This is the only sanitizer this module ships: width measurement
/// ([`strip_ansi`]) and safe-for-terminal output ([`sanitize_terminal_text`])
/// are the same scan with different output — see `keep_sgr` below. Consumers
/// must never emit un-sanitized configuration-derived text to a terminal, so
/// there is deliberately no "keep everything" mode.
///
/// Single-cursor over `chars()`: a byte index desynchronises from the char
/// iterator the moment a multi-byte or escape sequence is skipped, which
/// previously corrupted and truncated every styled line that was wrapped.
fn scan_ansi(text: &str, keep_sgr: bool) -> String {
    let mut result = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();

    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            match c {
                // Drop every C0 control byte and DEL except tab/newline,
                // which are ordinary whitespace in report text, and every C1
                // control byte (U+0080–U+009F, the 8-bit form of the same
                // control families handled below for the 7-bit ESC form).
                // Carriage return is dropped too: a bare CR is a classic
                // status-line-overwrite spoofing trick and has no legitimate
                // use in this single-line-oriented report text.
                '\u{00}'..='\u{08}'
                | '\u{0b}'..='\u{0d}'
                | '\u{0e}'..='\u{1f}'
                | '\u{7f}'
                | '\u{80}'..='\u{9f}' => {}
                _ => result.push(c),
            }
            continue;
        }

        match chars.peek() {
            Some('[') => {
                // CSI: ESC '[' <parameter/intermediate bytes> <final byte
                // 0x40-0x7E>. Only a plain SGR shape (parameters limited to
                // digits and ';', final byte 'm') is trusted and kept;
                // cursor movement, erase, private modes, and every other CSI
                // final byte are dropped along with the whole sequence.
                chars.next();
                let mut seq = String::from("\u{1b}[");
                let mut plain_sgr = true;
                let mut closed = false;
                // Scan through to the actual CSI final byte regardless of
                // what the parameter/intermediate bytes look like, so a
                // non-SGR sequence (private-mode `?` parameters, cursor
                // movement, erase, …) is fully consumed and dropped instead
                // of leaking its tail as literal text the moment a
                // non-digit byte disqualifies it from being plain SGR.
                for next in chars.by_ref() {
                    if ('\u{40}'..='\u{7e}').contains(&next) {
                        if next == 'm' && plain_sgr {
                            seq.push(next);
                        } else {
                            plain_sgr = false;
                        }
                        closed = true;
                        break;
                    }
                    if next.is_ascii_digit() || next == ';' {
                        seq.push(next);
                    } else {
                        plain_sgr = false;
                    }
                }
                if keep_sgr && plain_sgr && closed {
                    result.push_str(&seq);
                }
            }
            Some(']') | Some('P') | Some('X') | Some('^') | Some('_') => {
                // OSC / DCS / SOS / PM / APC: a "string" sequence terminated
                // by BEL or ST (`ESC \`). Never trusted — an OSC 8 hyperlink
                // or OSC 52 clipboard write, for example, must never reach
                // the terminal from configuration-derived text — so this is
                // always consumed and dropped regardless of `keep_sgr`.
                chars.next();
                loop {
                    match chars.next() {
                        None => break,
                        Some('\u{07}') => break,
                        Some('\u{1b}') => {
                            if chars.peek() == Some(&'\\') {
                                chars.next();
                            }
                            break;
                        }
                        Some(_) => {}
                    }
                }
            }
            _ => {
                // A bare or unrecognized escape: drop just the ESC byte
                // rather than emitting it as literal content. A stray ESC
                // has no legitimate display purpose and can be the prefix of
                // a sequence a stripping pass elsewhere failed to recognize.
            }
        }
    }
    result
}

fn strip_ansi(text: &str) -> String {
    scan_ansi(text, false)
}

/// Sanitize configuration-derived text before it reaches a terminal: strip
/// every control sequence except plain SGR styling. See the module docs and
/// [`scan_ansi`] for the trust model.
pub fn sanitize_terminal_text(text: &str) -> String {
    scan_ansi(text, true)
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

    // Common case: the whole value fits on one line. Emit the SANITIZED text
    // so any legitimate SGR styling is preserved (the word-wrapping path
    // below rebuilds from ANSI-stripped words and necessarily drops all
    // styling) while any other control content — including sequences a
    // hostile configuration value embedded to manipulate the terminal — is
    // removed rather than trusted.
    if !text.is_empty() && !text.contains('\n') && display_width(text) <= capacity {
        lines.push(format!("{current_prefix}{}", sanitize_terminal_text(text)));
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
        // A bare ESC not followed by a recognized introducer is dropped, not
        // preserved as literal content: a stray ESC has no legitimate
        // display purpose and must never reach a terminal untouched.
        assert_eq!(strip_ansi("x\x1by"), "xy");
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

    #[test]
    fn sanitize_terminal_text_keeps_only_plain_sgr() {
        assert_eq!(
            sanitize_terminal_text("\x1b[31mHIGH\x1b[0m"),
            "\x1b[31mHIGH\x1b[0m"
        );
        // Cursor movement / erase / private-mode CSI sequences (not SGR) are
        // dropped entirely, not passed through as literal text.
        assert_eq!(sanitize_terminal_text("a\x1b[2Jb\x1b[?25lc"), "abc");
        // OSC (e.g. a hyperlink or clipboard-write payload) is dropped along
        // with its terminator, whether BEL- or ST-terminated.
        assert_eq!(
            sanitize_terminal_text(
                "before\x1b]8;;http://evil.example\x07link text\x1b]8;;\x07after"
            ),
            "beforelink textafter"
        );
        assert_eq!(
            sanitize_terminal_text("before\x1b]52;c;ZXZpbA==\x1b\\after"),
            "beforeafter"
        );
        // Bare C0 controls and DEL are dropped; tab/newline survive as
        // ordinary whitespace.
        assert_eq!(sanitize_terminal_text("a\rb\x07c\x7fd\te\nf"), "abcd\te\nf");
    }

    #[test]
    fn wrap_prefixed_fast_path_sanitizes_control_sequences() {
        // Regression: a config-derived value that fits on one line used to
        // be emitted byte-for-byte, including any embedded control
        // sequences. A crafted server/finding name carrying an OSC 8
        // hyperlink or a cursor-erase CSI sequence must not reach the
        // terminal unsanitized just because it happened to fit.
        let hostile = "safe-looking-name\x1b]8;;http://evil.example\x07click me\x1b]8;;\x07\x1b[2J";
        let lines = wrap_prefixed("Server: ", "        ", hostile, 80);
        assert_eq!(lines, vec!["Server: safe-looking-nameclick me"]);
        for line in &lines {
            assert!(
                !line.contains('\u{1b}'),
                "no raw escape must survive: {line:?}"
            );
            assert!(!line.contains("evil.example"));
        }
    }
}
