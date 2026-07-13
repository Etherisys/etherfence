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
        '\u{00AD}'                 // soft hyphen
            | '\u{034F}'           // combining grapheme joiner
            | '\u{115F}'..='\u{1160}' // Hangul choseong/jungseong fillers
            | '\u{180E}'           // Mongolian vowel separator
            | '\u{200B}'..='\u{200F}' // zero-width space … RLM
            | '\u{2060}'..='\u{2064}' // word joiner + invisible math operators
            | '\u{206A}'..='\u{206F}' // deprecated format chars (2066-2069 = bidi)
            | '\u{3164}'           // Hangul filler
            | '\u{FEFF}'           // zero-width no-break space / BOM
            | '\u{FFF9}'..='\u{FFFB}' // interlinear annotation anchors
            | '\u{E0000}'..='\u{E007F}' // Unicode tag block (hidden-instruction vector)
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
    fn detects_tag_block_and_extra_invisibles_in_path_values() {
        // Unicode tag block (U+E0000–E007F) is the canonical hidden-instruction
        // vector; path values are the one surface that permits non-ASCII.
        assert_eq!(
            inspect_path_value("/home/user/\u{E0041}project"),
            Some(UnicodeRisk::ZeroWidth)
        );
        assert_eq!(
            inspect_path_value("/data/\u{2063}secret"),
            Some(UnicodeRisk::ZeroWidth)
        );
        assert_eq!(
            inspect_path_value("/data/\u{FFF9}x"),
            Some(UnicodeRisk::ZeroWidth)
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
