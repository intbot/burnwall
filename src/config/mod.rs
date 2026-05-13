//! Config loading and persistence.
//!
//! `~/.burnwall/config.toml` is the canonical store. Missing fields fall
//! back to [`Config::default`] via `#[serde(default)]`, so partial files
//! (e.g. only the `[budget]` section after a `config set budget.daily`)
//! round-trip cleanly.

use std::path::{Path, PathBuf};

pub mod types;

pub use types::{
    BudgetConfig, Config, LoggingConfig, LoopDetectionConfig, ProxyConfig, SecurityConfig,
};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TOML parse error: {0}")]
    TomlDe(#[from] toml::de::Error),
    #[error("TOML serialize error: {0}")]
    TomlSer(#[from] toml::ser::Error),
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
        "budget.daily" => config.budget.daily = parse(key, value)?,
        "budget.monthly" => config.budget.monthly = parse(key, value)?,
        "budget.warn_percent" => config.budget.warn_percent = parse(key, value)?,
        "security.enabled" => config.security.enabled = parse(key, value)?,
        "security.deny_paths" => config.security.deny_paths = split_csv(value),
        "security.deny_commands" => config.security.deny_commands = split_csv(value),
        "security.block_network_mounts" => {
            config.security.block_network_mounts = parse(key, value)?
        }
        "security.detect_secrets" => config.security.detect_secrets = parse(key, value)?,
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
        "logging.level" => config.logging.level = value.to_string(),
        "logging.file" => config.logging.file = value.to_string(),
        _ => return Err(ConfigError::UnknownKey(key.to_string())),
    }
    Ok(())
}
