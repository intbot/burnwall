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
fn set_dotted_key_handles_new_mode_toggles_and_upstreams() {
    let mut c = Config::default();
    // All three modes default OFF (opt-in per the no-false-positive rule).
    assert!(!c.proxy.trim_tool_output);
    assert!(!c.security.paranoid);
    assert!(!c.security.warn_response_exfil);

    config::set_dotted_key(&mut c, "proxy.trim_tool_output", "true").unwrap();
    assert!(c.proxy.trim_tool_output);
    config::set_dotted_key(&mut c, "security.paranoid", "true").unwrap();
    assert!(c.security.paranoid);
    config::set_dotted_key(&mut c, "security.warn_response_exfil", "true").unwrap();
    assert!(c.security.warn_response_exfil);

    // Gateway chaining: upstreams default empty (= provider's own API) and
    // are plain string setters; empty restores the default.
    assert!(c.upstreams.anthropic.is_empty());
    config::set_dotted_key(&mut c, "upstreams.openai", "https://gateway.local/v1").unwrap();
    assert_eq!(c.upstreams.openai, "https://gateway.local/v1");
    config::set_dotted_key(&mut c, "upstreams.openai", "").unwrap();
    assert!(c.upstreams.openai.is_empty());
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
fn canaries_default_empty_parse_set_and_filter() {
    // Default: no canaries.
    let c = Config::default();
    assert!(c.security.canaries.is_empty());

    // TOML parse: the key is read alongside the rest of the security table
    // (`canaries` itself is serde-defaulted, so older configs stay valid).
    let parsed: Config = toml::from_str(concat!(
        "[security]\n",
        "enabled = true\n",
        "deny_paths = []\n",
        "deny_commands = []\n",
        "block_network_mounts = true\n",
        "detect_secrets = true\n",
        "canaries = [\"CANARY-fake-token-001\", \"tiny\"]\n",
    ))
    .unwrap();
    assert_eq!(parsed.security.canaries.len(), 2);

    // The dotted-key setter accepts a comma list.
    let mut c = Config::default();
    config::set_dotted_key(
        &mut c,
        "security.canaries",
        "CANARY-aaaa-1111, CANARY-bbbb-2222",
    )
    .unwrap();
    assert_eq!(c.security.canaries.len(), 2);

    // Conversion to the runtime ruleset drops sub-minimum values.
    let rules: burnwall::security::Ruleset = (&parsed.security).into();
    assert_eq!(rules.canaries, vec!["CANARY-fake-token-001".to_string()]);
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

#[test]
fn per_session_budget_key_and_runtime_mapping() {
    let mut cfg = Config::default();
    assert_eq!(cfg.budget.per_session, 0.0); // off by default
    config::set_dotted_key(&mut cfg, "budget.per_session", "5.0").unwrap();
    assert!((cfg.budget.per_session - 5.0).abs() < 1e-9);

    // Survives a save/load round-trip.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    config::save(&path, &cfg).unwrap();
    let read = config::load_or_default(&path).unwrap();
    assert!((read.budget.per_session - 5.0).abs() < 1e-9);

    // Maps into the runtime budget config.
    let runtime: burnwall::budget::BudgetConfig = (&cfg.budget).into();
    assert!((runtime.per_session_usd - 5.0).abs() < 1e-9);
}

#[test]
fn hourly_brake_and_fallback_keys_default_off_and_round_trip() {
    // #2 / #18 defaults: brake disarmed, fallback empty.
    let c = Config::default();
    assert_eq!(c.budget.per_hour, 0.0);
    assert!(c.budget.fallback_model.is_empty());

    let mut c = Config::default();
    config::set_dotted_key(&mut c, "budget.per_hour", "3.50").unwrap();
    config::set_dotted_key(&mut c, "budget.fallback_model", "claude-haiku-4-5").unwrap();
    config::set_dotted_key(&mut c, "budget.enforce_on_plan", "true").unwrap();
    assert!((c.budget.per_hour - 3.50).abs() < 1e-9);
    assert_eq!(c.budget.fallback_model, "claude-haiku-4-5");
    assert!(c.budget.enforce_on_plan);

    // Round-trips through TOML.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    config::save(&path, &c).unwrap();
    let read = config::load_or_default(&path).unwrap();
    assert!((read.budget.per_hour - 3.50).abs() < 1e-9);
    assert_eq!(read.budget.fallback_model, "claude-haiku-4-5");

    // Maps into the runtime config (#2 ceiling + #18 fallback).
    let runtime: burnwall::budget::BudgetConfig = (&c.budget).into();
    assert!((runtime.per_hour_usd - 3.50).abs() < 1e-9);
    assert_eq!(runtime.fallback_model, "claude-haiku-4-5");
}

#[test]
fn action_repeat_keys_default_and_round_trip() {
    // #19 defaults: conservative threshold, enforcement OFF (warn-only).
    let c = Config::default();
    assert_eq!(c.loop_detection.action_repeat_threshold, 10);
    assert!(!c.loop_detection.action_repeat_enforce);

    let mut c = Config::default();
    config::set_dotted_key(&mut c, "loop_detection.action_repeat_threshold", "4").unwrap();
    config::set_dotted_key(&mut c, "loop_detection.action_repeat_enforce", "true").unwrap();
    assert_eq!(c.loop_detection.action_repeat_threshold, 4);
    assert!(c.loop_detection.action_repeat_enforce);

    // Maps into the runtime loop config.
    let runtime: burnwall::budget::LoopConfig = (&c.loop_detection).into();
    assert_eq!(runtime.action_repeat_threshold, 4);
    assert!(runtime.action_repeat_enforce);
}

#[test]
fn older_config_without_new_keys_still_deserializes() {
    // A config written before #2/#18/#19 (no per_hour/fallback_model/action_*
    // keys) must still load — the new fields are serde-defaulted.
    let toml = r#"
[budget]
daily = 25.0
monthly = 0.0
warn_percent = 80

[loop_detection]
enabled = true
max_identical_requests = 5
window_seconds = 300
max_cost_per_window = 2.0
"#;
    let cfg: Config = toml::from_str(toml).expect("older config must still parse");
    assert!((cfg.budget.daily - 25.0).abs() < 1e-9);
    assert_eq!(cfg.budget.per_hour, 0.0);
    assert!(cfg.budget.fallback_model.is_empty());
    assert_eq!(cfg.loop_detection.action_repeat_threshold, 10);
    assert!(!cfg.loop_detection.action_repeat_enforce);
}
