//! Small Unicode hygiene checks for MCP policy and runtime identifiers.
//!
//! EtherFence deliberately does not normalize or fold Unicode confusables into
//! ASCII. For MCP method names, tool names, policy identifiers, path-rule names,
//! path keys, and guarded path-like values, suspicious Unicode is rejected or
//! denied with a safe reason category before exact policy matching/audit review.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnicodeRisk {
    BidiControl,
    ZeroWidth,
    NonAsciiMethod,
    NonAsciiTool,
    NonAsciiIdentifier,
}

impl UnicodeRisk {
    pub fn reason(self) -> &'static str {
        match self {
            UnicodeRisk::BidiControl => "unicode_bidi_control_detected",
            UnicodeRisk::ZeroWidth => "unicode_zero_width_detected",
            UnicodeRisk::NonAsciiMethod => "unicode_non_ascii_method",
            UnicodeRisk::NonAsciiTool => "unicode_non_ascii_tool",
            UnicodeRisk::NonAsciiIdentifier => "unicode_non_ascii_identifier",
        }
    }
}

pub fn inspect_method_name(value: &str) -> Option<UnicodeRisk> {
    inspect_no_bidi_zero_width(value)
        .or_else(|| (!value.is_ascii()).then_some(UnicodeRisk::NonAsciiMethod))
}

pub fn inspect_tool_name(value: &str) -> Option<UnicodeRisk> {
    inspect_no_bidi_zero_width(value)
        .or_else(|| (!value.is_ascii()).then_some(UnicodeRisk::NonAsciiTool))
}

pub fn inspect_policy_identifier(value: &str) -> Option<UnicodeRisk> {
    inspect_no_bidi_zero_width(value)
        .or_else(|| (!value.is_ascii()).then_some(UnicodeRisk::NonAsciiIdentifier))
}

pub fn inspect_path_value(value: &str) -> Option<UnicodeRisk> {
    inspect_no_bidi_zero_width(value)
}

fn inspect_no_bidi_zero_width(value: &str) -> Option<UnicodeRisk> {
    for ch in value.chars() {
        if is_bidi_control(ch) {
            return Some(UnicodeRisk::BidiControl);
        }
        if is_zero_width_or_invisible_format(ch) {
            return Some(UnicodeRisk::ZeroWidth);
        }
    }
    None
}

fn is_bidi_control(ch: char) -> bool {
    matches!(
        ch,
        '\u{061C}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
    )
}

fn is_zero_width_or_invisible_format(ch: char) -> bool {
    matches!(
        ch,
        '\u{00AD}' | '\u{034F}' | '\u{180E}' | '\u{200B}'..='\u{200F}' | '\u{2060}' | '\u{FEFF}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_bidi_before_non_ascii() {
        assert_eq!(
            inspect_method_name("tools/\u{202E}call"),
            Some(UnicodeRisk::BidiControl)
        );
    }

    #[test]
    fn classifies_zero_width_before_non_ascii() {
        assert_eq!(
            inspect_tool_name("filesystem.\u{200B}read"),
            Some(UnicodeRisk::ZeroWidth)
        );
    }

    #[test]
    fn classifies_plain_non_ascii_method_and_tool() {
        assert_eq!(
            inspect_method_name("t\u{03BF}ols/call"),
            Some(UnicodeRisk::NonAsciiMethod)
        );
        assert_eq!(
            inspect_tool_name("filesystem.re\u{0430}d"),
            Some(UnicodeRisk::NonAsciiTool)
        );
    }

    #[test]
    fn ascii_names_are_clean() {
        assert_eq!(inspect_method_name("tools/call"), None);
        assert_eq!(inspect_tool_name("filesystem.read"), None);
        assert_eq!(inspect_policy_identifier("project_readonly"), None);
        assert_eq!(inspect_path_value("/home/user/project/file.txt"), None);
    }
}
