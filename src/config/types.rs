//! User-facing configuration model. Mirrors the TOML schema in SPEC.md
//! §"Config File Format". One top-level [`Config`] struct serde-serializes
//! to the canonical `~/.burnwall/config.toml` shape.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Config {
    #[serde(default)]
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub budget: BudgetConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub loop_detection: LoopDetectionConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub tools: ToolsConfig,
    #[serde(default)]
    pub waste: WasteConfig,
    #[serde(default)]
    pub rules: RulesConfig,
    /// Deprecated: superseded by `[tools]`. Kept for one release as a global
    /// kill switch (`enabled = false` disables all log scraping). Prefer the
    /// per-tool `[tools]` switches. Only written back when set to a
    /// non-default value, so fresh configs don't re-introduce the old key.
    #[serde(default, skip_serializing_if = "log_scrape_is_default")]
    pub log_scrape: LogScrapeConfig,
}

fn log_scrape_is_default(c: &LogScrapeConfig) -> bool {
    *c == LogScrapeConfig::default()
}

impl Config {
    /// Whether to scrape Claude Code logs — the per-tool `[tools]` switch,
    /// gated by the deprecated global `[log_scrape]` kill switch.
    pub fn scrape_claude_code(&self) -> bool {
        self.log_scrape.enabled && self.tools.claude_code
    }

    /// Whether to scrape Codex logs.
    pub fn scrape_codex(&self) -> bool {
        self.log_scrape.enabled && self.tools.codex
    }

    /// Whether to scrape OpenCode logs.
    pub fn scrape_opencode(&self) -> bool {
        self.log_scrape.enabled && self.tools.opencode
    }

    /// Whether to scrape Aider logs.
    pub fn scrape_aider(&self) -> bool {
        self.log_scrape.enabled && self.tools.aider
    }

    /// Whether any tool's logs are scraped at all.
    pub fn any_scrape_enabled(&self) -> bool {
        self.scrape_claude_code()
            || self.scrape_codex()
            || self.scrape_opencode()
            || self.scrape_aider()
    }

    /// The per-tool selection in the shape `logscrape` consumes.
    pub fn scrape_tools(&self) -> crate::logscrape::Tools {
        crate::logscrape::Tools {
            claude_code: self.scrape_claude_code(),
            codex: self.scrape_codex(),
            opencode: self.scrape_opencode(),
            aider: self.scrape_aider(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProxyConfig {
    pub port: u16,
    pub host: String,
    /// Auto-inject Anthropic `cache_control` markers (ephemeral) onto
    /// the system prompt and the first message of outbound requests
    /// that have none. Off by default — Burnwall does not modify
    /// request bodies silently.
    #[serde(default)]
    pub cache_injection: bool,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            port: 4100,
            host: "127.0.0.1".to_string(),
            cache_injection: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BudgetConfig {
    /// Daily limit in USD. `0.0` = unlimited.
    pub daily: f64,
    /// Monthly limit in USD. `0.0` = unlimited.
    pub monthly: f64,
    /// Warn (don't block) at this percent of the daily limit.
    pub warn_percent: u8,
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self {
            daily: 50.0,
            monthly: 0.0,
            warn_percent: 80,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecurityConfig {
    pub enabled: bool,
    pub deny_paths: Vec<String>,
    pub deny_commands: Vec<String>,
    pub block_network_mounts: bool,
    pub detect_secrets: bool,
    /// Redact the `details` field in `security_events` rows and the
    /// `block_reason` in blocked `requests` rows — keeps filesystem paths
    /// out of stored data for users who sync or share the database.
    #[serde(default)]
    pub log_redact_details: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            deny_paths: crate::security::rules::DEFAULT_DENY_PATHS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            deny_commands: crate::security::rules::DEFAULT_DENY_COMMANDS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            block_network_mounts: true,
            detect_secrets: true,
            log_redact_details: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LoopDetectionConfig {
    pub enabled: bool,
    pub max_identical_requests: u32,
    pub window_seconds: u32,
    pub max_cost_per_window: f64,
}

impl Default for LoopDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_identical_requests: 5,
            window_seconds: 300,
            max_cost_per_window: 2.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LoggingConfig {
    pub level: String,
    pub file: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            file: "~/.burnwall/burnwall.log".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LogScrapeConfig {
    /// When true, `burnwall status` also scrapes local tool session logs
    /// (Claude Code, Codex) to show cross-tool spend that did not go
    /// through the proxy. Read-only — never writes to the database.
    pub enabled: bool,
}

impl Default for LogScrapeConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// Per-tool log scraping. All supported tools default ON; set one `false`
/// to skip it. Replaces the global `[log_scrape].enabled` bool.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolsConfig {
    pub claude_code: bool,
    pub codex: bool,
    // Added after the first `[tools]` shipped, so they carry per-field serde
    // defaults — an existing config that wrote only `claude_code` + `codex`
    // must still deserialize (a missing field would otherwise be an error).
    #[serde(default = "default_true")]
    pub opencode: bool,
    #[serde(default = "default_true")]
    pub aider: bool,
}

fn default_true() -> bool {
    true
}

impl Default for ToolsConfig {
    fn default() -> Self {
        Self {
            claude_code: true,
            codex: true,
            opencode: true,
            aider: true,
        }
    }
}

/// Waste-insights configuration. `enabled` toggles the whole advisory
/// engine (`burnwall waste` + the `status` teaser). Off-by-default,
/// privacy-relaxing rules and per-rule threshold overrides will hang off
/// sub-tables here in a later release.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WasteConfig {
    pub enabled: bool,
}

impl Default for WasteConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// Enabled official rule packs (v0.6). Each id names a bundled official pack;
/// `burnwall rules install <id>` adds to this list and `burnwall start` merges
/// the pack onto the runtime ruleset. A pack only ever EXTENDS the denylist
/// (invariant I2). Empty by default — no packs enabled.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct RulesConfig {
    #[serde(default)]
    pub enabled: Vec<String>,
}

/// Convert the persistent config's budget block into the runtime
/// [`crate::budget::BudgetConfig`] used by [`BudgetTracker`].
impl From<&BudgetConfig> for crate::budget::BudgetConfig {
    fn from(c: &BudgetConfig) -> Self {
        Self {
            daily_usd: c.daily,
            monthly_usd: c.monthly,
            warn_percent: c.warn_percent,
        }
    }
}

/// Convert the persistent config's security block into the runtime
/// [`crate::security::Ruleset`].
impl From<&SecurityConfig> for crate::security::Ruleset {
    fn from(c: &SecurityConfig) -> Self {
        Self {
            enabled: c.enabled,
            deny_paths: c.deny_paths.clone(),
            // `allow_paths` is project-profile-only — the global config has
            // no allow list. A discovered `.burnwall.yaml` merges into this
            // afterwards (see `cli::start`).
            allow_paths: Vec::new(),
            deny_commands: c.deny_commands.clone(),
            block_network_mounts: c.block_network_mounts,
            detect_secrets: c.detect_secrets,
            // Pack-contributed patterns are merged in later (Phase B startup
            // wiring), like a discovered project profile.
            secret_patterns: Vec::new(),
            log_redact_details: c.log_redact_details,
        }
    }
}

/// Convert the persistent loop_detection block into the runtime
/// [`crate::budget::LoopConfig`]. `hash_prefix_bytes` keeps its built-in
/// default (200) — we don't expose it as a TOML knob in v0.2.
impl From<&LoopDetectionConfig> for crate::budget::LoopConfig {
    fn from(c: &LoopDetectionConfig) -> Self {
        let defaults = crate::budget::LoopConfig::default();
        Self {
            enabled: c.enabled,
            max_identical_requests: c.max_identical_requests,
            window_seconds: c.window_seconds,
            max_cost_per_window: c.max_cost_per_window,
            hash_prefix_bytes: defaults.hash_prefix_bytes,
        }
    }
}
