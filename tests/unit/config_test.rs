//! Tests for the TOML-backed user config layer.

use burnwall::config::{self, Config};

#[test]
fn default_config_has_sensible_values() {
    let c = Config::default();
    assert_eq!(c.proxy.port, 4100);
    assert_eq!(c.proxy.host, "127.0.0.1");
    assert!((c.budget.daily - 50.0).abs() < 1e-9);
    assert_eq!(c.budget.warn_percent, 80);
    assert!(c.security.enabled);
    assert!(c.security.block_network_mounts);
    assert!(c.security.detect_secrets);
    assert!(!c.security.deny_paths.is_empty());
}

#[test]
fn load_returns_default_when_file_missing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let cfg = config::load_or_default(&path).expect("load");
    assert_eq!(cfg, Config::default());
}

#[test]
fn save_then_load_roundtrips() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let mut cfg = Config::default();
    cfg.budget.daily = 12.5;
    cfg.security.deny_paths.push("~/secret".to_string());

    config::save(&path, &cfg).expect("save");
    let read = config::load_or_default(&path).expect("load");
    assert_eq!(cfg, read);
}

#[test]
fn pricing_publishers_parse_and_default_empty() {
    // Empty by default — no remote pricing card is trusted out of the box.
    assert!(Config::default().pricing.publishers.is_empty());

    // A `[pricing]` section with publishers round-trips through TOML.
    let toml = r#"
[[pricing.publishers]]
name = "burnwall"
key = "aabbccdd"
"#;
    let cfg: Config = toml::from_str(toml).expect("parse pricing publishers");
    assert_eq!(cfg.pricing.publishers.len(), 1);
    assert_eq!(cfg.pricing.publishers[0].name, "burnwall");
    assert_eq!(cfg.pricing.publishers[0].key, "aabbccdd");
}

#[test]
fn save_creates_missing_directory() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nested").join("dir").join("config.toml");
    config::save(&path, &Config::default()).expect("save creates parents");
    assert!(path.exists());
}

#[test]
fn set_dotted_key_handles_numeric_fields() {
    let mut c = Config::default();
    config::set_dotted_key(&mut c, "budget.daily", "20").unwrap();
    assert!((c.budget.daily - 20.0).abs() < 1e-9);
    config::set_dotted_key(&mut c, "budget.warn_percent", "90").unwrap();
    assert_eq!(c.budget.warn_percent, 90);
    config::set_dotted_key(&mut c, "proxy.port", "8080").unwrap();
    assert_eq!(c.proxy.port, 8080);
}

#[test]
fn set_dotted_key_handles_string_fields() {
    let mut c = Config::default();
    config::set_dotted_key(&mut c, "proxy.host", "0.0.0.0").unwrap();
    assert_eq!(c.proxy.host, "0.0.0.0");
    config::set_dotted_key(&mut c, "logging.level", "debug").unwrap();
    assert_eq!(c.logging.level, "debug");
}

#[test]
fn set_dotted_key_handles_boolean_fields() {
    let mut c = Config::default();
    config::set_dotted_key(&mut c, "security.block_network_mounts", "false").unwrap();
    assert!(!c.security.block_network_mounts);
    config::set_dotted_key(&mut c, "security.detect_secrets", "true").unwrap();
    assert!(c.security.detect_secrets);
}

#[test]
fn set_dotted_key_parses_csv_lists() {
    let mut c = Config::default();
    config::set_dotted_key(&mut c, "security.deny_paths", "~/.ssh, ~/.aws, /etc/passwd").unwrap();
    assert_eq!(
        c.security.deny_paths,
        vec!["~/.ssh", "~/.aws", "/etc/passwd"]
    );
}

#[test]
fn set_dotted_key_rejects_unknown_keys() {
    let mut c = Config::default();
    let err = config::set_dotted_key(&mut c, "no.such.key", "x").unwrap_err();
    assert!(matches!(err, config::ConfigError::UnknownKey(_)));
}

#[test]
fn set_dotted_key_rejects_invalid_values() {
    let mut c = Config::default();
    let err = config::set_dotted_key(&mut c, "budget.daily", "not-a-number").unwrap_err();
    assert!(matches!(err, config::ConfigError::InvalidValue { .. }));
}

#[test]
fn budget_config_converts_to_runtime_type() {
    let c = Config::default();
    let runtime: burnwall::budget::BudgetConfig = (&c.budget).into();
    assert!((runtime.daily_usd - c.budget.daily).abs() < 1e-9);
    assert_eq!(runtime.warn_percent, c.budget.warn_percent);
}

#[test]
fn security_config_converts_to_runtime_ruleset() {
    let c = Config::default();
    let rules: burnwall::security::Ruleset = (&c.security).into();
    assert_eq!(rules.deny_paths, c.security.deny_paths);
    assert_eq!(rules.block_network_mounts, c.security.block_network_mounts);
    // `security.enabled` now flows into the runtime ruleset (was a dead toggle).
    assert!(rules.enabled);
}

#[test]
fn security_enabled_flows_into_ruleset() {
    let mut c = Config::default();
    c.security.enabled = false;
    let rules: burnwall::security::Ruleset = (&c.security).into();
    assert!(!rules.enabled);
}

#[test]
fn tools_and_waste_defaults_and_set() {
    let mut c = Config::default();
    assert!(c.tools.claude_code && c.tools.codex);
    assert!(c.waste.enabled);

    config::set_dotted_key(&mut c, "tools.codex", "false").unwrap();
    config::set_dotted_key(&mut c, "waste.enabled", "false").unwrap();
    assert!(!c.tools.codex);
    assert!(!c.waste.enabled);
}

#[test]
fn scrape_helpers_honor_per_tool_and_legacy_kill_switch() {
    let mut c = Config::default();
    assert!(c.scrape_claude_code() && c.scrape_codex() && c.any_scrape_enabled());

    // Per-tool switch.
    c.tools.codex = false;
    assert!(c.scrape_claude_code());
    assert!(!c.scrape_codex());
    assert!(c.any_scrape_enabled());

    // Legacy global kill switch disables everything.
    c.tools.codex = true;
    c.log_scrape.enabled = false;
    assert!(!c.scrape_claude_code());
    assert!(!c.scrape_codex());
    assert!(!c.any_scrape_enabled());
}

#[test]
fn default_config_does_not_serialize_deprecated_log_scrape() {
    // A fresh config should not re-introduce the deprecated [log_scrape] key.
    let toml_text = toml::to_string_pretty(&Config::default()).unwrap();
    assert!(toml_text.contains("[tools]"));
    assert!(toml_text.contains("[waste]"));
    assert!(!toml_text.contains("[log_scrape]"));
}

#[test]
fn explicitly_disabled_log_scrape_is_preserved() {
    // If a user sets the legacy kill switch, it must survive a save/load.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let mut c = Config::default();
    c.log_scrape.enabled = false;
    config::save(&path, &c).unwrap();
    let read = config::load_or_default(&path).unwrap();
    assert!(!read.log_scrape.enabled);
}
