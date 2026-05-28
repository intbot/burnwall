//! End-to-end CLI tests using `assert_cmd`.
//!
//! Each test points `BURNWALL_DATA_DIR` at a `tempdir` so the binary
//! reads/writes config and SQLite in an isolated sandbox — no
//! `~/.burnwall/` pollution.

use std::fs;
use std::path::PathBuf;

use assert_cmd::Command;
use burnwall::providers::TokenUsage;
use burnwall::storage::{RequestRecord, SecurityEvent, Storage};
use chrono::Utc;
use predicates::prelude::*;

fn burnwall(data_dir: &PathBuf) -> Command {
    let mut cmd = Command::cargo_bin("burnwall").expect("binary");
    cmd.env("BURNWALL_DATA_DIR", data_dir);
    cmd
}

fn seed_storage(dir: &PathBuf) {
    fs::create_dir_all(dir).unwrap();
    let path = dir.join("burnwall.db");
    let storage = Storage::open(&path).expect("open");
    let usage = TokenUsage {
        input_tokens: 1000,
        output_tokens: 500,
        cache_creation_tokens: 0,
        cache_read_tokens: 0,
    };
    let mut r = RequestRecord::successful("anthropic", "claude-sonnet-4-6", &usage, 0.0105, None);
    r.timestamp = Utc::now();
    storage.insert_request(&r).unwrap();

    let evt = SecurityEvent::new("path_blocked", "~/.ssh/id_rsa")
        .with_provider("anthropic", "claude-sonnet-4-6");
    storage.insert_security_event(&evt).unwrap();
}

// ─────────────────────────────── status ───────────────────────────────

#[test]
fn status_table_shows_seeded_data() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    seed_storage(&path);

    burnwall(&path)
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("Today ("))
        .stdout(predicate::str::contains("anthropic/claude-sonnet-4-6"))
        .stdout(predicate::str::contains("$0.01"))
        .stdout(predicate::str::contains("Security: 1 blocked attempt"));
}

#[test]
fn status_json_emits_valid_structure() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    seed_storage(&path);

    let output = burnwall(&path)
        .args(["status", "--json"])
        .output()
        .expect("run");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert!(v["total_cost_usd"].as_f64().unwrap() > 0.0);
    assert_eq!(v["security_events"], 1);
    assert_eq!(v["breakdown"][0]["provider"], "anthropic");
}

#[test]
fn status_with_empty_db_does_not_panic() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    fs::create_dir_all(&path).unwrap();
    burnwall(&path)
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("no requests yet"));
}

// ─────────────────────────────── history ───────────────────────────────

#[test]
fn history_table_includes_seeded_day() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    seed_storage(&path);

    burnwall(&path)
        .arg("history")
        .assert()
        .success()
        .stdout(predicate::str::contains("Last 7 days"))
        .stdout(predicate::str::contains("Total"))
        .stdout(predicate::str::contains("Monthly burndown"))
        .stdout(predicate::str::contains("Projected EOM"));
}

#[test]
fn history_json_emits_array_of_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    seed_storage(&path);

    let output = burnwall(&path)
        .args(["history", "--days", "3", "--json"])
        .output()
        .expect("run");
    assert!(output.status.success());
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(v["days"], 3);
    assert!(v["rows"].is_array());
}

#[test]
fn history_json_includes_burndown() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    seed_storage(&path);

    let output = burnwall(&path)
        .args(["history", "--json"])
        .output()
        .expect("run");
    assert!(output.status.success());
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert!(v["burndown"]["spent_usd"].as_f64().unwrap() > 0.0);
    assert!(v["burndown"]["projected_eom_usd"].as_f64().unwrap() > 0.0);
    assert!(v["burndown"]["days_in_month"].as_u64().unwrap() >= 28);
}

// ─────────────────────────────── explore ──────────────────────────────

#[test]
fn explore_table_shows_proxied_breakdown() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    seed_storage(&path);
    // Isolate log scraping to an empty dir so output is deterministic.
    let empty = dir.path().join("empty-logs");

    burnwall(&path)
        .env("BURNWALL_CLAUDE_LOG_DIR", &empty)
        .env("BURNWALL_CODEX_LOG_DIR", &empty)
        .arg("explore")
        .assert()
        .success()
        .stdout(predicate::str::contains("Spend explorer"))
        .stdout(predicate::str::contains("by provider / model"))
        .stdout(predicate::str::contains("anthropic/claude-sonnet-4-6"))
        .stdout(predicate::str::contains("by harness"))
        .stdout(predicate::str::contains("by workspace"));
}

#[test]
fn explore_json_has_dimensions() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    seed_storage(&path);
    let empty = dir.path().join("empty-logs");

    let output = burnwall(&path)
        .env("BURNWALL_CLAUDE_LOG_DIR", &empty)
        .env("BURNWALL_CODEX_LOG_DIR", &empty)
        .args(["explore", "--days", "14", "--json"])
        .output()
        .expect("run");
    assert!(output.status.success());
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(v["window_days"], 14);
    assert_eq!(v["proxied_by_model"][0]["provider"], "anthropic");
    assert!(v["by_harness"].is_array());
    assert!(v["by_workspace"].is_array());
}

// ─────────────────────────────── config ───────────────────────────────

#[test]
fn config_show_prints_default_when_no_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    fs::create_dir_all(&path).unwrap();

    burnwall(&path)
        .args(["config", "show"])
        .assert()
        .success()
        .stdout(predicate::str::contains("[proxy]"))
        .stdout(predicate::str::contains("port = 4100"))
        .stdout(predicate::str::contains("[budget]"))
        .stdout(predicate::str::contains("daily = 50"));
}

#[test]
fn config_show_json_emits_valid_json() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    fs::create_dir_all(&path).unwrap();

    let output = burnwall(&path)
        .args(["config", "show", "--json"])
        .output()
        .expect("run");
    assert!(output.status.success());
    let v: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("config show --json must emit valid JSON");
    assert_eq!(v["proxy"]["port"], 4100);
    assert_eq!(v["budget"]["daily"], 50.0);
    assert!(v["security"]["enabled"].as_bool().unwrap());
}

#[test]
fn config_set_writes_to_file_and_persists() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    fs::create_dir_all(&path).unwrap();

    burnwall(&path)
        .args(["config", "set", "budget.daily", "12.50"])
        .assert()
        .success()
        .stdout(predicate::str::contains("budget.daily"))
        .stdout(predicate::str::contains("12.50"));

    let toml = fs::read_to_string(path.join("config.toml")).expect("config file written");
    assert!(toml.contains("daily = 12.5"));

    burnwall(&path)
        .args(["config", "show"])
        .assert()
        .success()
        .stdout(predicate::str::contains("daily = 12.5"));
}

#[test]
fn config_set_rejects_unknown_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    fs::create_dir_all(&path).unwrap();

    burnwall(&path)
        .args(["config", "set", "no.such.key", "x"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown config key"));
}

#[test]
fn config_doctor_reports_clean_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    fs::create_dir_all(&path).unwrap();

    burnwall(&path)
        .args(["config", "doctor"])
        .assert()
        .success()
        .stdout(predicate::str::contains("config doctor"))
        .stdout(predicate::str::contains("Effective configuration"))
        .stdout(predicate::str::contains("No problems found"));
}

#[test]
fn config_doctor_flags_relaxing_toggles_and_deprecated_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    fs::create_dir_all(&path).unwrap();
    // Hand-write a config with a deprecated section + a relaxing toggle ON.
    fs::write(
        path.join("config.toml"),
        "[proxy]\nport = 4100\nhost = \"127.0.0.1\"\ncache_injection = true\n\n[log_scrape]\nenabled = true\n",
    )
    .unwrap();

    burnwall(&path)
        .args(["config", "doctor"])
        .assert()
        .success() // warnings only → exit 0
        .stdout(predicate::str::contains("cache_injection is ON"))
        .stdout(predicate::str::contains("[log_scrape] is deprecated"));
}

#[test]
fn config_doctor_errors_on_out_of_range_value() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    fs::create_dir_all(&path).unwrap();
    fs::write(
        path.join("config.toml"),
        "[budget]\ndaily = 50.0\nmonthly = 0.0\nwarn_percent = 150\n",
    )
    .unwrap();

    burnwall(&path)
        .args(["config", "doctor"])
        .assert()
        .failure()
        .stdout(predicate::str::contains("out of range"));
}

// ============================ completions ============================

#[test]
fn completions_bash_emits_a_compinit_script() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    burnwall(&path)
        .args(["completions", "bash"])
        .assert()
        .success()
        // bash completion scripts always declare _<binary>() and call complete
        .stdout(predicate::str::contains("_burnwall()"))
        .stdout(predicate::str::contains("complete -F _burnwall"));
}

#[test]
fn completions_zsh_emits_compdef_block() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    burnwall(&path)
        .args(["completions", "zsh"])
        .assert()
        .success()
        .stdout(predicate::str::contains("#compdef burnwall"));
}

#[test]
fn completions_powershell_emits_argument_completer() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    burnwall(&path)
        .args(["completions", "powershell"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Register-ArgumentCompleter"));
}

#[test]
fn completions_rejects_unknown_shell() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    burnwall(&path)
        .args(["completions", "csh"])
        .assert()
        .failure();
}

// =============================== security ===============================

#[test]
fn security_command_lists_seeded_event() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    seed_storage(&path);

    burnwall(&path)
        .arg("security")
        .assert()
        .success()
        .stdout(predicate::str::contains("Security events"))
        .stdout(predicate::str::contains("path_blocked"))
        .stdout(predicate::str::contains("anthropic/claude-sonnet-4-6"))
        .stdout(predicate::str::contains("~/.ssh/id_rsa"))
        .stdout(predicate::str::contains("Total: 1 event"));
}

#[test]
fn security_command_json_emits_array() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    seed_storage(&path);

    let output = burnwall(&path)
        .args(["security", "--json"])
        .output()
        .expect("run");
    assert!(output.status.success());
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(v["count"], 1);
    assert_eq!(v["events"][0]["event_type"], "path_blocked");
    assert_eq!(v["events"][0]["details"], "~/.ssh/id_rsa");
}

#[test]
fn security_command_with_empty_db_says_none() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    fs::create_dir_all(&path).unwrap();
    burnwall(&path)
        .arg("security")
        .assert()
        .success()
        .stdout(predicate::str::contains("(none)"));
}

#[test]
fn security_command_filters_by_event_type() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    seed_storage(&path);

    // The seeded event is path_blocked. Filtering for command_blocked should hide it.
    burnwall(&path)
        .args(["security", "--event-type", "command_blocked"])
        .assert()
        .success()
        .stdout(predicate::str::contains("(none)"));

    burnwall(&path)
        .args(["security", "--event-type", "path_blocked"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Total: 1 event"));
}

#[test]
fn config_set_rejects_invalid_value() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    fs::create_dir_all(&path).unwrap();

    burnwall(&path)
        .args(["config", "set", "budget.daily", "twenty"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid value"));
}

// ───────────────────────── metrics + digest (v0.7) ─────────────────────────

fn seed_with_latency(dir: &PathBuf) {
    fs::create_dir_all(dir).unwrap();
    let path = dir.join("burnwall.db");
    let storage = Storage::open(&path).expect("open");
    let usage = TokenUsage {
        input_tokens: 1000,
        output_tokens: 500,
        cache_creation_tokens: 0,
        cache_read_tokens: 0,
    };
    for (lat, status) in [(120i64, 200i64), (240, 200), (360, 500)] {
        let mut r =
            RequestRecord::successful("anthropic", "claude-sonnet-4-6", &usage, 0.0105, None);
        r.timestamp = Utc::now();
        r.latency_ms = Some(lat);
        r.http_status = Some(status);
        storage.insert_request(&r).unwrap();
    }
}

#[test]
fn metrics_table_shows_percentiles() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    seed_with_latency(&path);

    burnwall(&path)
        .arg("metrics")
        .assert()
        .success()
        .stdout(predicate::str::contains("Latency & reliability"))
        .stdout(predicate::str::contains("anthropic/claude-sonnet-4-6"));
}

#[test]
fn metrics_json_is_valid() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    seed_with_latency(&path);

    let output = burnwall(&path)
        .args(["metrics", "--json"])
        .output()
        .expect("run");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["models"][0]["requests"], 3);
    assert_eq!(v["models"][0]["errors"], 1);
    assert_eq!(v["models"][0]["p50_ms"], 240);
}

#[test]
fn metrics_empty_db_does_not_panic() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    fs::create_dir_all(&path).unwrap();
    burnwall(&path)
        .arg("metrics")
        .assert()
        .success()
        .stdout(predicate::str::contains("no forwarded requests"));
}

#[test]
fn digest_table_shows_bill_of_materials() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    seed_storage(&path);

    burnwall(&path)
        .arg("digest")
        .assert()
        .success()
        .stdout(predicate::str::contains("Agent Bill of Materials"))
        .stdout(predicate::str::contains("anthropic/claude-sonnet-4-6"))
        .stdout(predicate::str::contains("Security checks fired: 1"));
}

#[test]
fn digest_json_is_valid() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    seed_storage(&path);

    let output = burnwall(&path)
        .args(["digest", "--json"])
        .output()
        .expect("run");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["models"][0]["provider"], "anthropic");
    assert_eq!(v["security_by_type"][0]["event_type"], "path_blocked");
}
