//! Coverage transparency — which installed AI tools actually route through the
//! proxy, so a user is never silently *unprotected* while assuming otherwise.
//!
//! A no-MITM proxy only sees the traffic that flows through it. The dangerous
//! failure mode for a security proxy is **silent non-coverage**: a tool whose
//! traffic never reaches Burnwall, with nothing on screen to say so. This module
//! turns that invisible boundary into a per-tool readout.
//!
//! Three states per *detected* (installed-on-PATH) tool:
//!
//! * [`CoverageState::Protected`] — the tool's provider was seen routing through
//!   the proxy recently (we have a DB last-seen for it).
//! * [`CoverageState::InstalledNotSeen`] — on PATH, but no matching provider
//!   traffic has reached the proxy (routing not wired up, or simply idle).
//! * [`CoverageState::Bypasses`] — the tool is in a mode that *cannot* reach the
//!   proxy. The concrete case today: Codex on ChatGPT login talks to the ChatGPT
//!   backend over OAuth, which no no-MITM proxy (Burnwall, LiteLLM, OpenRouter)
//!   can see. Switching Codex to API-key mode routes it back through Burnwall.
//!
//! The originating *tool* isn't recoverable from proxied HTTP (every tool hits
//! the same provider route), but each tool maps to a known set of providers, so
//! "provider X was seen" is a sound proxy for "the tool that speaks X is routing".
//!
//! Metadata only: tool names, a local non-secret auth-mode discriminator, and
//! last-seen timestamps. No API keys, no token values, no prompt content.

use std::path::PathBuf;

use crate::storage::Storage;

/// How long after a provider's last proxied request we still call its tool
/// "protected". An active user refreshes this constantly; a longer gap just
/// means idle, so we down-rank to "installed, no recent traffic".
pub const SEEN_RECENCY_SECS: i64 = 24 * 3600;

/// Coverage verdict for one tool.
#[derive(Debug, Clone, PartialEq)]
pub enum CoverageState {
    /// Provider traffic seen `since_secs` ago through the proxy.
    Protected { since_secs: i64 },
    /// On PATH, but no matching proxied traffic (idle, or routing not wired up).
    InstalledNotSeen,
    /// Configured in a mode that bypasses the proxy entirely. `reason` is a
    /// short, user-facing explanation.
    Bypasses { reason: String },
}

/// One installed tool plus its coverage verdict.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolCoverage {
    pub label: String,
    pub binary: String,
    pub state: CoverageState,
}

/// Providers a given tool talks to. Used to map per-provider proxy traffic back
/// to the tool. Aider/OpenCode are multi-provider, so either provider counts.
fn tool_providers(binary: &str) -> &'static [&'static str] {
    match binary {
        "claude" => &["anthropic"],
        "codex" => &["openai"],
        "aider" => &["anthropic", "openai"],
        "opencode" => &["anthropic", "openai"],
        _ => &[],
    }
}

/// Codex CLI auth mode, derived from `~/.codex/auth.json`. We read *which* mode
/// is configured — a local, non-secret discriminator — never the token/key value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodexAuth {
    /// ChatGPT login (OAuth). Traffic goes to the ChatGPT backend, bypassing
    /// any no-MITM proxy.
    ChatGpt,
    /// API-key / custom provider. Routable via `OPENAI_BASE_URL` → the proxy.
    ApiKey,
}

/// Path to Codex's auth file, if a home dir resolves.
pub fn codex_auth_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".codex").join("auth.json"))
}

/// Read and classify Codex's configured auth mode. `None` when Codex has never
/// authenticated (no file) or the file is unreadable/unrecognized.
pub fn codex_auth_mode() -> Option<CodexAuth> {
    let text = std::fs::read_to_string(codex_auth_path()?).ok()?;
    classify_codex_auth(&text)
}

/// Pure classifier for `auth.json` contents (testable without the filesystem).
/// An OAuth `tokens` object means ChatGPT login; otherwise a non-empty
/// `OPENAI_API_KEY` means API-key mode.
pub fn classify_codex_auth(json: &str) -> Option<CodexAuth> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    if v.get("tokens").map(|t| t.is_object()).unwrap_or(false) {
        return Some(CodexAuth::ChatGpt);
    }
    let has_key = v
        .get("OPENAI_API_KEY")
        .and_then(|k| k.as_str())
        .map(|s| !s.is_empty())
        .unwrap_or(false);
    has_key.then_some(CodexAuth::ApiKey)
}

/// Decide one tool's coverage from its providers' last-seen ages and (for Codex)
/// its auth mode. Pure — unit-tested without a DB or filesystem.
///
/// `provider_age_secs(p)` returns how long ago provider `p` was last seen
/// through the proxy (`None` if never).
pub fn classify(
    binary: &str,
    provider_age_secs: impl Fn(&str) -> Option<i64>,
    codex_auth: Option<CodexAuth>,
) -> CoverageState {
    // Codex on ChatGPT login bypasses the proxy regardless of any DB traffic —
    // its subscription usage never reaches us. This is the safety-critical case.
    if binary == "codex" && codex_auth == Some(CodexAuth::ChatGpt) {
        return CoverageState::Bypasses {
            reason: "Codex on ChatGPT login routes to the ChatGPT backend (OAuth); API-key mode would route through Burnwall, but bills per-token — weigh the cost before switching".to_string(),
        };
    }
    let freshest = tool_providers(binary)
        .iter()
        .filter_map(|p| provider_age_secs(p))
        .min();
    match freshest {
        Some(age) if age <= SEEN_RECENCY_SECS => CoverageState::Protected { since_secs: age },
        _ => CoverageState::InstalledNotSeen,
    }
}

/// Assess coverage for every installed tool. `now` is the current unix epoch.
pub fn assess(db: &Storage, now: i64) -> Vec<ToolCoverage> {
    let last_seen = db.provider_last_seen().unwrap_or_default();
    let codex_auth = codex_auth_mode();
    let age = |provider: &str| -> Option<i64> {
        last_seen
            .iter()
            .find(|(p, _)| p == provider)
            .map(|(_, ts)| (now - ts.timestamp()).max(0))
    };
    crate::cli::init::detect_tools()
        .into_iter()
        .filter(|d| d.found)
        .map(|d| {
            let state = classify(&d.binary, age, codex_auth);
            ToolCoverage {
                label: d.label,
                binary: d.binary,
                state,
            }
        })
        .collect()
}

impl CoverageState {
    /// A one-line, glyph-led summary for a terminal readout.
    pub fn summary(&self) -> String {
        match self {
            CoverageState::Protected { since_secs } => {
                format!("🟢 protected (seen {} ago)", crate::ribbon::human_duration(*since_secs))
            }
            CoverageState::InstalledNotSeen => "⚪ installed — no traffic seen yet".to_string(),
            CoverageState::Bypasses { reason } => format!("🔴 not protected — {reason}"),
        }
    }

    /// Stable machine token for JSON consumers (IDE extension, scripts).
    pub fn kind(&self) -> &'static str {
        match self {
            CoverageState::Protected { .. } => "protected",
            CoverageState::InstalledNotSeen => "installed_not_seen",
            CoverageState::Bypasses { .. } => "bypasses",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chatgpt_login_codex_bypasses_even_with_traffic() {
        // Even if openai traffic was just seen, ChatGPT-login Codex is a bypass.
        let state = classify("codex", |_| Some(10), Some(CodexAuth::ChatGpt));
        assert!(matches!(state, CoverageState::Bypasses { .. }));
    }

    #[test]
    fn apikey_codex_with_recent_traffic_is_protected() {
        let state = classify("codex", |p| (p == "openai").then_some(120), Some(CodexAuth::ApiKey));
        assert_eq!(state, CoverageState::Protected { since_secs: 120 });
    }

    #[test]
    fn claude_recent_anthropic_is_protected() {
        let state = classify("claude", |p| (p == "anthropic").then_some(60), None);
        assert_eq!(state, CoverageState::Protected { since_secs: 60 });
    }

    #[test]
    fn stale_traffic_is_installed_not_seen() {
        let old = SEEN_RECENCY_SECS + 1;
        let state = classify("claude", |_| Some(old), None);
        assert_eq!(state, CoverageState::InstalledNotSeen);
    }

    #[test]
    fn never_seen_is_installed_not_seen() {
        let state = classify("claude", |_| None, None);
        assert_eq!(state, CoverageState::InstalledNotSeen);
    }

    #[test]
    fn multi_provider_tool_uses_freshest() {
        // Aider talks to both; the more recent of the two wins.
        let state = classify(
            "aider",
            |p| match p {
                "anthropic" => Some(9000),
                "openai" => Some(30),
                _ => None,
            },
            None,
        );
        assert_eq!(state, CoverageState::Protected { since_secs: 30 });
    }

    #[test]
    fn classify_codex_auth_detects_oauth_tokens() {
        let json = r#"{"OPENAI_API_KEY": null, "tokens": {"access_token": "x", "account_id": "y"}}"#;
        assert_eq!(classify_codex_auth(json), Some(CodexAuth::ChatGpt));
    }

    #[test]
    fn classify_codex_auth_detects_api_key() {
        let json = r#"{"OPENAI_API_KEY": "sk-abc", "tokens": null}"#;
        assert_eq!(classify_codex_auth(json), Some(CodexAuth::ApiKey));
    }

    #[test]
    fn classify_codex_auth_empty_is_none() {
        assert_eq!(classify_codex_auth(r#"{"OPENAI_API_KEY": ""}"#), None);
        assert_eq!(classify_codex_auth("not json"), None);
    }

    #[test]
    fn summary_strings_are_glyph_led() {
        assert!(CoverageState::Protected { since_secs: 60 }.summary().starts_with("🟢"));
        assert!(CoverageState::InstalledNotSeen.summary().starts_with("⚪"));
        assert!(CoverageState::Bypasses { reason: "x".into() }.summary().starts_with("🔴"));
    }
}
