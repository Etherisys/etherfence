use std::path::PathBuf;
use std::process::Command;

// Regression-tests SC-006/FR-026 and Constitution Principle III (Truth in
// Claims): catalog/classification documentation and CLI output must never
// describe `setup catalog`/`setup detect` capability classification or
// starter-policy recommendations as runtime blocking, interception, or
// enforcement — they are posture/classification/starter-policy guidance
// only. This makes the v1.2.0 release-gate "no prohibited language" check
// (plan.md Release Gate Checklist) an automated property, not a manual step.

const README: &str = include_str!("../../../README.md");
const SETUP_ONBOARDING_DOCS: &str = include_str!("../../../docs/setup-onboarding.md");
const JSON_SCHEMA_DOCS: &str = include_str!("../../../docs/json-schema.md");

const PROHIBITED_TERMS: &[&str] = &[
    "block",
    "blocks",
    "blocking",
    "blocked",
    "intercept",
    "intercepts",
    "intercepting",
    "interception",
    "prevent",
    "prevents",
    "preventing",
    "enforce",
    "enforces",
    "enforcing",
    "enforcement",
];

fn fixture_root(name: &str) -> PathBuf {
    PathBuf::from(format!(
        "{}/../../tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_etherfence"))
        .args(args)
        .output()
        .expect("run etherfence")
}

/// Extracts the text of a Markdown section (from `heading` up to the next
/// `##`-level heading, or end of file) so prohibited-language checks are
/// scoped to catalog/classification content only — other sections (e.g.
/// `mcp-proxy`, which legitimately does enforce policy) are not affected.
fn section(content: &str, heading: &str) -> String {
    let start = content
        .find(heading)
        .unwrap_or_else(|| panic!("missing section heading {heading:?}"));
    let after_heading = &content[start + heading.len()..];
    let end = after_heading.find("\n## ").unwrap_or(after_heading.len());
    after_heading[..end].to_string()
}

const NEGATION_CUES: &[&str] = &["not ", "never ", "no ", "n't ", "without ", "non-"];

/// Fails if any sentence uses a prohibited enforcement/blocking term
/// *affirmatively* (claiming catalog/classification does block/intercept/
/// enforce). Honest disclaimers ("never imply runtime blocking... or
/// enforcement", "does not block") are the correct, expected pattern here
/// (see README's `mcp-proxy` section and the v1.0.1 CHANGELOG entry for
/// precedent) and must not trip this check — a sentence containing a
/// negation cue near the prohibited term is treated as a disclaimer, not
/// an overclaim.
fn assert_no_prohibited_terms(label: &str, text: &str) {
    let lowered = text.to_lowercase();
    for sentence in lowered.split(['.', '!', '?', '\n']) {
        let has_prohibited = PROHIBITED_TERMS.iter().any(|term| sentence.contains(term));
        if !has_prohibited {
            continue;
        }
        let has_negation = NEGATION_CUES.iter().any(|cue| sentence.contains(cue));
        assert!(
            has_negation,
            "{label}: sentence uses enforcement/blocking language without a disclaiming negation: {sentence:?}"
        );
    }
}

#[test]
fn readme_setup_catalog_section_has_no_prohibited_language() {
    let text = section(README, "## `setup catalog` example");
    assert_no_prohibited_terms("README.md `setup catalog` example section", &text);
    assert!(text.contains("read-only"));
}

#[test]
fn setup_onboarding_docs_catalog_section_has_no_prohibited_language() {
    let text = section(
        SETUP_ONBOARDING_DOCS,
        "## `etherfence setup catalog` (v1.2.0)",
    );
    assert_no_prohibited_terms(
        "docs/setup-onboarding.md `etherfence setup catalog` section",
        &text,
    );
    assert!(text.contains("read-only"));
}

#[test]
fn json_schema_docs_setup_sections_have_no_prohibited_language() {
    let catalog_text = section(
        JSON_SCHEMA_DOCS,
        "## `etherfence setup catalog` schema (`ef-setup-catalog/v0.1`)",
    );
    assert_no_prohibited_terms(
        "docs/json-schema.md ef-setup-catalog section",
        &catalog_text,
    );

    let detect_text = section(
        JSON_SCHEMA_DOCS,
        "## `etherfence setup detect` schema (`ef-setup-detect/v0.2`)",
    );
    assert_no_prohibited_terms("docs/json-schema.md ef-setup-detect section", &detect_text);
}

// Regression-tests v1.3.0's own honesty requirement (spec SC-008): trust-
// assessment documentation and CLI output must never claim a server is
// proven safe, trusted, certified, malware-free, benign, or definitively
// malicious.
const TRUST_PROHIBITED_TERMS: &[&str] = &[
    "is safe",
    "is trusted",
    "is certified",
    "malware-free",
    "is benign",
    "definitively malicious",
    "proven safe",
    "guaranteed safe",
];

/// Same negation-aware pattern as `assert_no_prohibited_terms`: an honest
/// disclaimer ("does not mean the program is safe") legitimately contains
/// the same words as the overclaim it's guarding against, so a bare
/// substring ban is the wrong test shape here too (the exact lesson from
/// the v1.2.0 `setup_catalog_docs.rs` false-fail, see project memory).
fn assert_no_trust_overclaims(label: &str, text: &str) {
    let lowered = text.to_lowercase();
    for sentence in lowered.split(['.', '!', '?', '\n']) {
        let has_overclaim = TRUST_PROHIBITED_TERMS
            .iter()
            .any(|term| sentence.contains(term));
        if !has_overclaim {
            continue;
        }
        let has_negation = NEGATION_CUES.iter().any(|cue| sentence.contains(cue));
        assert!(
            has_negation,
            "{label}: sentence claims a trust overclaim without a disclaiming negation: {sentence:?}"
        );
    }
}

#[test]
fn json_schema_docs_trust_assessment_section_has_no_overclaims() {
    let text = section(JSON_SCHEMA_DOCS, "### `servers[].trustAssessment` (v1.3.0)");
    assert_no_trust_overclaims("docs/json-schema.md trustAssessment section", &text);
    assert!(text.contains("never proves"));
}

#[test]
fn setup_onboarding_docs_trust_assessment_section_has_no_overclaims() {
    let text = section(
        SETUP_ONBOARDING_DOCS,
        "## `etherfence setup detect` trust and integrity assessment (v1.3.0)",
    );
    assert_no_trust_overclaims("docs/setup-onboarding.md trust-assessment section", &text);
}

#[test]
fn setup_detect_trust_assessment_cli_output_has_no_overclaims() {
    let root = fixture_root("trust-home");
    let human = run(&["setup", "detect", "--root", root.to_str().unwrap()]);
    assert!(human.status.success());
    assert_no_trust_overclaims(
        "`setup detect` human output (trust-home)",
        &String::from_utf8_lossy(&human.stdout),
    );

    let json = run(&[
        "setup",
        "detect",
        "--format",
        "json",
        "--root",
        root.to_str().unwrap(),
    ]);
    assert!(json.status.success());
    assert_no_trust_overclaims(
        "`setup detect --format json` output (trust-home)",
        &String::from_utf8_lossy(&json.stdout),
    );
}

#[test]
fn setup_catalog_cli_output_has_no_prohibited_language() {
    let root = fixture_root("home");
    let human = run(&["setup", "catalog", "--root", root.to_str().unwrap()]);
    assert!(human.status.success());
    assert_no_prohibited_terms(
        "`setup catalog` human output",
        &String::from_utf8_lossy(&human.stdout),
    );

    let json = run(&[
        "setup",
        "catalog",
        "--format",
        "json",
        "--root",
        root.to_str().unwrap(),
    ]);
    assert!(json.status.success());
    assert_no_prohibited_terms(
        "`setup catalog --format json` output",
        &String::from_utf8_lossy(&json.stdout),
    );
}

#[test]
fn setup_detect_cli_output_has_no_prohibited_language() {
    let root = fixture_root("home");
    let human = run(&["setup", "detect", "--root", root.to_str().unwrap()]);
    assert!(human.status.success());
    assert_no_prohibited_terms(
        "`setup detect` human output",
        &String::from_utf8_lossy(&human.stdout),
    );

    let json = run(&[
        "setup",
        "detect",
        "--format",
        "json",
        "--root",
        root.to_str().unwrap(),
    ]);
    assert!(json.status.success());
    assert_no_prohibited_terms(
        "`setup detect --format json` output",
        &String::from_utf8_lossy(&json.stdout),
    );
}
