use etherfence_core::AgentKind;
use serde::Serialize;
use std::path::Path;

/// The fixed, exhaustive v1.2.0 client catalog. Declaration order is the
/// catalog display order (research.md Decision 4). Two `AgentKind`
/// variants (`Cline`, `RooCode`) collapse into the single `ClineRooCode`
/// row (data-model.md `CatalogClient`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CatalogClient {
    ClaudeStyleConfig,
    Cursor,
    VsCode,
    Hermes,
    Antigravity,
    Windsurf,
    GeminiCli,
    CodexCli,
    OpenCode,
    ClineRooCode,
}

impl CatalogClient {
    /// All 10 catalog clients, in the fixed matrix-row order (FR-001, FR-004).
    pub const ALL: [CatalogClient; 10] = [
        CatalogClient::ClaudeStyleConfig,
        CatalogClient::Cursor,
        CatalogClient::VsCode,
        CatalogClient::Hermes,
        CatalogClient::Antigravity,
        CatalogClient::Windsurf,
        CatalogClient::GeminiCli,
        CatalogClient::CodexCli,
        CatalogClient::OpenCode,
        CatalogClient::ClineRooCode,
    ];

    pub fn display_name(self) -> &'static str {
        match self {
            Self::ClaudeStyleConfig => "Claude-style config",
            Self::Cursor => "Cursor",
            Self::VsCode => "VS Code",
            Self::Hermes => "Hermes",
            Self::Antigravity => "Antigravity",
            Self::Windsurf => "Windsurf",
            Self::GeminiCli => "Gemini CLI",
            Self::CodexCli => "Codex CLI",
            Self::OpenCode => "OpenCode",
            Self::ClineRooCode => "Cline / Roo Code",
        }
    }

    /// Fixed, checked-in tier assignment (research.md Decision 2). Not
    /// computed from runtime heuristics: a client may only be
    /// `FixtureVerified` once its catalog row has an accompanying fixture
    /// test asserting the exact `CatalogEntry` it produces (Constitution
    /// Principle V/XI).
    fn tier(self) -> CatalogSupportTier {
        match self {
            Self::ClaudeStyleConfig | Self::Cursor | Self::VsCode => {
                CatalogSupportTier::FixtureVerified
            }
            Self::Windsurf | Self::GeminiCli | Self::CodexCli => CatalogSupportTier::DetectOnly,
            Self::Hermes | Self::Antigravity | Self::OpenCode | Self::ClineRooCode => {
                CatalogSupportTier::AdvisoryOnly
            }
        }
    }

    /// The underlying `AgentKind` variant(s) whose local presence
    /// determines this catalog row's `found_locally`/`config_paths`.
    fn agent_kinds(self) -> &'static [AgentKind] {
        match self {
            Self::ClaudeStyleConfig => &[AgentKind::ClaudeCode],
            Self::Cursor => &[AgentKind::Cursor],
            Self::VsCode => &[AgentKind::VsCode],
            Self::Hermes => &[AgentKind::Hermes],
            Self::Antigravity => &[AgentKind::Antigravity],
            Self::Windsurf => &[AgentKind::Windsurf],
            Self::GeminiCli => &[AgentKind::GeminiCli],
            Self::CodexCli => &[AgentKind::CodexCli],
            Self::OpenCode => &[AgentKind::OpenCode],
            Self::ClineRooCode => &[AgentKind::Cline, AgentKind::RooCode],
        }
    }
}

/// Detection/classification confidence tier for a catalog row. Distinct
/// from `WriteSupport` (write-capability for `setup apply`) — see
/// research.md Decision 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CatalogSupportTier {
    FixtureVerified,
    DetectOnly,
    AdvisoryOnly,
    /// Reserved for a client whose detection state cannot be determined.
    /// Not assigned to any of the 10 fixed clients by default at ship time.
    Unknown,
}

/// One row of `etherfence setup catalog` output.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogEntry {
    pub client: CatalogClient,
    pub tier: CatalogSupportTier,
    pub found_locally: bool,
    /// Always serialized, even when empty (`[]`, never omitted or `null`) —
    /// see `contracts/setup-catalog.md` "Field notes".
    pub config_paths: Vec<String>,
}

/// Builds the fixed 10-row client catalog for `root`. Pure, read-only:
/// reuses `etherfence_inventory::discover`'s existing deterministic
/// candidate order for `config_paths` (data-model.md `CatalogEntry`
/// "Multi-path ordering") — no additional sorting or path normalization.
pub fn catalog(root: &Path) -> Vec<CatalogEntry> {
    let items = etherfence_inventory::discover(root);
    CatalogClient::ALL
        .into_iter()
        .map(|client| {
            let agent_kinds = client.agent_kinds();
            let config_paths: Vec<String> = items
                .iter()
                .filter(|item| agent_kinds.contains(&item.agent))
                .map(|item| item.config_path.clone())
                .collect();
            CatalogEntry {
                client,
                tier: client.tier(),
                found_locally: !config_paths.is_empty(),
                config_paths,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_root(name: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(format!("../../tests/fixtures/{name}"))
    }

    #[test]
    fn catalog_always_has_exactly_ten_rows_in_fixed_order() {
        let entries = catalog(&fixture_root("home"));
        assert_eq!(entries.len(), 10);
        let clients: Vec<CatalogClient> = entries.iter().map(|e| e.client).collect();
        assert_eq!(clients, CatalogClient::ALL);
    }

    #[test]
    fn catalog_config_paths_empty_iff_not_found_locally() {
        for fixture in ["home", "empty-home", "windows-home", "malformed-home"] {
            for entry in catalog(&fixture_root(fixture)) {
                assert_eq!(
                    entry.config_paths.is_empty(),
                    !entry.found_locally,
                    "fixture {fixture} client {:?}: config_paths.is_empty() must equal !found_locally",
                    entry.client
                );
            }
        }
    }

    #[test]
    fn home_fixture_reports_expected_tiers_and_presence() {
        let entries = catalog(&fixture_root("home"));
        let by_client = |client: CatalogClient| {
            entries
                .iter()
                .find(|e| e.client == client)
                .unwrap_or_else(|| panic!("missing catalog entry for {client:?}"))
        };

        let claude = by_client(CatalogClient::ClaudeStyleConfig);
        assert_eq!(claude.tier, CatalogSupportTier::FixtureVerified);
        assert!(claude.found_locally);
        assert_eq!(claude.config_paths, vec!["~/.claude.json".to_string()]);

        let cursor = by_client(CatalogClient::Cursor);
        assert_eq!(cursor.tier, CatalogSupportTier::FixtureVerified);
        assert!(cursor.found_locally);

        let vscode = by_client(CatalogClient::VsCode);
        assert_eq!(vscode.tier, CatalogSupportTier::FixtureVerified);
        assert!(vscode.found_locally);

        let windsurf = by_client(CatalogClient::Windsurf);
        assert_eq!(windsurf.tier, CatalogSupportTier::DetectOnly);
        assert!(windsurf.found_locally);

        let gemini = by_client(CatalogClient::GeminiCli);
        assert_eq!(gemini.tier, CatalogSupportTier::DetectOnly);
        assert!(gemini.found_locally);

        let codex = by_client(CatalogClient::CodexCli);
        assert_eq!(codex.tier, CatalogSupportTier::DetectOnly);
        assert!(codex.found_locally);

        let hermes = by_client(CatalogClient::Hermes);
        assert_eq!(hermes.tier, CatalogSupportTier::AdvisoryOnly);
        assert!(hermes.found_locally);

        let antigravity = by_client(CatalogClient::Antigravity);
        assert_eq!(antigravity.tier, CatalogSupportTier::AdvisoryOnly);
        assert!(antigravity.found_locally);

        let opencode = by_client(CatalogClient::OpenCode);
        assert_eq!(opencode.tier, CatalogSupportTier::AdvisoryOnly);
        assert!(opencode.found_locally);

        let cline_roo = by_client(CatalogClient::ClineRooCode);
        assert_eq!(cline_roo.tier, CatalogSupportTier::AdvisoryOnly);
        assert!(cline_roo.found_locally);
        assert_eq!(
            cline_roo.config_paths.len(),
            2,
            "both Cline and Roo Code fixture markers are present"
        );
    }

    #[test]
    fn empty_home_fixture_reports_all_ten_rows_not_found() {
        let entries = catalog(&fixture_root("empty-home"));
        assert_eq!(entries.len(), 10);
        for entry in &entries {
            assert!(
                !entry.found_locally,
                "unexpected presence for {:?}",
                entry.client
            );
            assert!(entry.config_paths.is_empty());
        }
    }

    #[test]
    fn windows_home_fixture_reports_expected_presence() {
        let entries = catalog(&fixture_root("windows-home"));
        let by_client = |client: CatalogClient| {
            entries
                .iter()
                .find(|e| e.client == client)
                .unwrap_or_else(|| panic!("missing catalog entry for {client:?}"))
        };
        assert!(by_client(CatalogClient::ClaudeStyleConfig).found_locally);
        assert!(by_client(CatalogClient::Cursor).found_locally);
        assert!(by_client(CatalogClient::VsCode).found_locally);
        assert!(by_client(CatalogClient::Windsurf).found_locally);
        assert!(by_client(CatalogClient::GeminiCli).found_locally);
        assert!(by_client(CatalogClient::CodexCli).found_locally);
        assert!(by_client(CatalogClient::Hermes).found_locally);
        assert!(by_client(CatalogClient::Antigravity).found_locally);
        assert!(by_client(CatalogClient::OpenCode).found_locally);
        assert!(by_client(CatalogClient::ClineRooCode).found_locally);
    }

    #[test]
    fn malformed_home_fixture_still_reports_all_ten_rows() {
        let entries = catalog(&fixture_root("malformed-home"));
        assert_eq!(entries.len(), 10);
        let claude = entries
            .iter()
            .find(|e| e.client == CatalogClient::ClaudeStyleConfig)
            .expect("claude entry");
        // Malformed JSON still counts as "found" (the file exists and was
        // located); parse failures surface via `setup detect`'s notes, not
        // catalog presence, matching existing `etherfence_inventory` behavior.
        assert!(claude.found_locally);
    }

    #[test]
    fn multi_path_home_fixture_lists_both_cursor_paths_in_candidates_order() {
        let entries = catalog(&fixture_root("multi-path-home"));
        let cursor = entries
            .iter()
            .find(|e| e.client == CatalogClient::Cursor)
            .expect("cursor entry");
        assert_eq!(
            cursor.config_paths,
            vec![
                "~/.cursor/mcp.json".to_string(),
                "~/.cursor/settings.json".to_string()
            ]
        );
    }
}
