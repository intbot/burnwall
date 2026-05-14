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
    pub log_scrape: LogScrapeConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProxyConfig {
    pub port: u16,
    pub host: String,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            port: 4100,
            host: "127.0.0.1".to_string(),
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
            deny_paths: c.deny_paths.clone(),
            // `allow_paths` is project-profile-only — the global config has
            // no allow list. A discovered `.burnwall.yaml` merges into this
            // afterwards (see `cli::start`).
            allow_paths: Vec::new(),
            deny_commands: c.deny_commands.clone(),
            block_network_mounts: c.block_network_mounts,
            detect_secrets: c.detect_secrets,
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
