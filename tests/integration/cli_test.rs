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
        .stdout(predicate::str::contains("Today (UTC"))
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
        .stdout(predicate::str::contains("Estimated monthly"));
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
