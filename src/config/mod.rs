//! Config loading and persistence.
//!
//! `~/.burnwall/config.toml` is the canonical store. Missing fields fall
//! back to [`Config::default`] via `#[serde(default)]`, so partial files
//! (e.g. only the `[budget]` section after a `config set budget.daily`)
//! round-trip cleanly.

use std::path::{Path, PathBuf};

pub mod project;
pub mod types;

pub use types::{
    BudgetConfig, Config, FailoverEndpoints, LogScrapeConfig, LoggingConfig, LoopDetectionConfig,
    McpConfig, McpServerConfig, ObservabilityConfig, PricingConfig, ProxyConfig, ResilienceConfig,
    RulePublisher, RulesConfig, SecurityConfig, ToolsConfig, WasteConfig,
};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TOML parse error: {0}")]
    TomlDe(#[from] toml::de::Error),
    #[error("TOML serialize error: {0}")]
    TomlSer(#[from] toml::ser::Error),
    #[error("YAML parse error: {0}")]
    Yaml(#[from] serde_norway::Error),
    #[error("home directory not found")]
    NoHomeDir,
    #[error("unknown config key: {0}")]
    UnknownKey(String),
    #[error("invalid value for {key}: {detail}")]
    InvalidValue { key: String, detail: String },
}

pub type Result<T> = std::result::Result<T, ConfigError>;

/// Path to the user's config file. Defaults to `~/.burnwall/config.toml`;
/// honors the `BURNWALL_DATA_DIR` env var for tests.
pub fn default_path() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("BURNWALL_DATA_DIR") {
        return Ok(PathBuf::from(dir).join("config.toml"));
    }
    let home = dirs::home_dir().ok_or(ConfigError::NoHomeDir)?;
    Ok(home.join(".burnwall").join("config.toml"))
}

/// Read a config file. Returns `Config::default()` if the file does not
/// exist (first-run convenience).
pub fn load_or_default<P: AsRef<Path>>(path: P) -> Result<Config> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(Config::default());
    }
    let text = std::fs::read_to_string(path)?;
    let config: Config = toml::from_str(&text)?;
    Ok(config)
}

/// Serialize `config` to TOML and write atomically (write to a `.tmp` file
/// then rename).
pub fn save<P: AsRef<Path>>(path: P, config: &Config) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let text = toml::to_string_pretty(config)?;
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Update a single dotted key (e.g. `"budget.daily"`) on `config` from a
/// string value, parsing into the right field type. Used by `burnwall
/// config set <key> <value>`.
pub fn set_dotted_key(config: &mut Config, key: &str, value: &str) -> Result<()> {
    fn parse<T: std::str::FromStr>(key: &str, value: &str) -> Result<T>
    where
        T::Err: std::fmt::Display,
    {
        value.parse::<T>().map_err(|e| ConfigError::InvalidValue {
            key: key.to_string(),
            detail: e.to_string(),
        })
    }

    fn split_csv(value: &str) -> Vec<String> {
        value
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }

    match key {
        "proxy.port" => config.proxy.port = parse(key, value)?,
        "proxy.host" => config.proxy.host = value.to_string(),
        "proxy.cache_injection" => config.proxy.cache_injection = parse(key, value)?,
        "proxy.trim_tool_output" => config.proxy.trim_tool_output = parse(key, value)?,
        "budget.daily" => config.budget.daily = parse(key, value)?,
        "budget.monthly" => config.budget.monthly = parse(key, value)?,
        "budget.warn_percent" => config.budget.warn_percent = parse(key, value)?,
        "budget.per_session" => config.budget.per_session = parse(key, value)?,
        "budget.per_hour" => config.budget.per_hour = parse(key, value)?,
        "budget.enforce_on_plan" => config.budget.enforce_on_plan = parse(key, value)?,
        "budget.fallback_model" => config.budget.fallback_model = value.to_string(),
        "security.enabled" => config.security.enabled = parse(key, value)?,
        "security.deny_paths" => config.security.deny_paths = split_csv(value),
        "security.deny_commands" => config.security.deny_commands = split_csv(value),
        "security.block_network_mounts" => {
            config.security.block_network_mounts = parse(key, value)?
        }
        "security.detect_secrets" => config.security.detect_secrets = parse(key, value)?,
        "security.log_redact_details" => config.security.log_redact_details = parse(key, value)?,
        // Canary values are opaque; the comma-list setter mirrors deny_paths.
        // A value that needs a comma must be edited into the TOML directly.
        "security.canaries" => config.security.canaries = split_csv(value),
        "loop_detection.enabled" => config.loop_detection.enabled = parse(key, value)?,
        "loop_detection.max_identical_requests" => {
            config.loop_detection.max_identical_requests = parse(key, value)?
        }
        "loop_detection.window_seconds" => {
            config.loop_detection.window_seconds = parse(key, value)?
        }
        "loop_detection.max_cost_per_window" => {
            config.loop_detection.max_cost_per_window = parse(key, value)?
        }
        "loop_detection.cost_spiral_enforce" => {
            config.loop_detection.cost_spiral_enforce = parse(key, value)?
        }
        "loop_detection.action_repeat_threshold" => {
            config.loop_detection.action_repeat_threshold = parse(key, value)?
        }
        "loop_detection.action_repeat_enforce" => {
            config.loop_detection.action_repeat_enforce = parse(key, value)?
        }
        "logging.level" => config.logging.level = value.to_string(),
        "logging.file" => config.logging.file = value.to_string(),
        "tools.claude_code" => config.tools.claude_code = parse(key, value)?,
        "tools.codex" => config.tools.codex = parse(key, value)?,
        "tools.opencode" => config.tools.opencode = parse(key, value)?,
        "tools.aider" => config.tools.aider = parse(key, value)?,
        "waste.enabled" => config.waste.enabled = parse(key, value)?,
        // Prefer `burnwall rules install <id>` (it validates the id); this
        // setter is the raw escape hatch and does not validate pack ids.
        "rules.enabled" => config.rules.enabled = split_csv(value),
        "security.dlp" => config.security.dlp = parse(key, value)?,
        "security.block_credential_misdirection" => {
            config.security.block_credential_misdirection = parse(key, value)?
        }
        "security.paranoid" => config.security.paranoid = parse(key, value)?,
        "security.warn_response_exfil" => config.security.warn_response_exfil = parse(key, value)?,
        // `[[mcp.servers]]` is an array of tables — edit the TOML directly.
        "mcp.require_approval" => config.mcp.require_approval = parse(key, value)?,
        "resilience.enabled" => config.resilience.enabled = parse(key, value)?,
        "resilience.failure_threshold" => config.resilience.failure_threshold = parse(key, value)?,
        "resilience.cooldown_seconds" => config.resilience.cooldown_seconds = parse(key, value)?,
        // `[[resilience.endpoints]]` is an array of tables — edit the TOML directly.
        "observability.otel_spans" => config.observability.otel_spans = parse(key, value)?,
        "observability.otel_file" => config.observability.otel_file = value.to_string(),
        // Gateway chaining (#9): point a provider's upstream at an LLM gateway.
        // Empty restores the provider's own API. A `--upstream-*` start flag
        // overrides these at launch.
        "upstreams.anthropic" => config.upstreams.anthropic = value.to_string(),
        "upstreams.openai" => config.upstreams.openai = value.to_string(),
        "upstreams.google" => config.upstreams.google = value.to_string(),
        // Deprecated alias — still settable for one release.
        "log_scrape.enabled" => config.log_scrape.enabled = parse(key, value)?,
        _ => return Err(ConfigError::UnknownKey(key.to_string())),
    }
    Ok(())
}
