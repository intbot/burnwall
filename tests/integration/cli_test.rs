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

    // One enforcement block + one advisory alert, so surfaces must show the
    // split (an alert presented as a "block" was a real dogfooding bug).
    let evt = SecurityEvent::new("path_blocked", "~/.ssh/id_rsa")
        .with_provider("anthropic", "claude-sonnet-4-6");
    storage.insert_security_event(&evt).unwrap();
    let alert = SecurityEvent::new("slow_drip_alert", "host targeted unusually often")
        .with_provider("anthropic", "claude-sonnet-4-6");
    storage.insert_security_event(&alert).unwrap();
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
        .stdout(predicate::str::contains(
            "Security: 1 request blocked · 1 alert",
        ));
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
    // Total kept for compatibility; the split fields carry the honest story.
    assert_eq!(v["security_events"], 2);
    assert_eq!(v["security_blocked"], 1);
    assert_eq!(v["security_alerts"], 1);
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

/// Seed several local days of activity so the delta chips (today vs yesterday,
/// window vs prior window) and the spend sparkline have data to render.
fn seed_multiday(dir: &PathBuf) {
    fs::create_dir_all(dir).unwrap();
    let path = dir.join("burnwall.db");
    let storage = Storage::open(&path).expect("open");
    // Distinct per-day cost so the sparkline has shape and the deltas are
    // non-flat. Day 0 = today, increasing days = further back.
    let daily_cost = [0.80f64, 0.20, 0.55, 0.05, 0.40, 0.10, 0.30];
    for (days_ago, cost) in daily_cost.iter().enumerate() {
        let usage = TokenUsage {
            input_tokens: 1000,
            output_tokens: 400,
            cache_creation_tokens: 0,
            // Some cache reads on recent days so the cache-hit delta moves.
            cache_read_tokens: if days_ago < 3 { 4000 } else { 0 },
        };
        let mut r =
            RequestRecord::successful("anthropic", "claude-sonnet-4-6", &usage, *cost, None);
        r.timestamp = Utc::now() - chrono::Duration::days(days_ago as i64);
        storage.insert_request(&r).unwrap();
    }
    // A second model today so the share-of-spend bars have >1 row.
    let usage = TokenUsage {
        input_tokens: 800,
        output_tokens: 300,
        cache_creation_tokens: 0,
        cache_read_tokens: 0,
    };
    let mut r2 = RequestRecord::successful("openai", "gpt-4o", &usage, 0.15, None);
    r2.timestamp = Utc::now();
    storage.insert_request(&r2).unwrap();
    // A block today and a block yesterday → a non-flat Blocked delta.
    for days_ago in [0i64, 1] {
        let mut evt = SecurityEvent::new("path_blocked", "~/.ssh/id_rsa")
            .with_provider("anthropic", "claude-sonnet-4-6");
        evt.timestamp = Utc::now() - chrono::Duration::days(days_ago);
        storage.insert_security_event(&evt).unwrap();
    }
}

#[test]
fn status_shows_share_bars_and_spend_sparkline() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    seed_multiday(&path);

    let out = burnwall(&path).arg("status").output().expect("run");
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    // Share-of-spend column + a filled bar cell in the Cost-by-model table.
    assert!(s.contains("Share"), "missing Share column:\n{s}");
    assert!(s.contains('▓'), "missing share fill bar:\n{s}");
    // 7-day spend trend sparkline (any block glyph).
    assert!(s.contains("7-day spend"), "missing sparkline label:\n{s}");
    assert!(
        s.chars().any(|c| "▁▂▃▄▅▆▇█".contains(c)),
        "missing sparkline glyphs:\n{s}"
    );
}

#[test]
fn status_shows_delta_chip_vs_yesterday() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    seed_multiday(&path);

    let out = burnwall(&path).arg("status").output().expect("run");
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    // Today ($0.95) vs yesterday ($0.20) — spend is up, so an up chip renders.
    assert!(
        s.contains('▲') || s.contains('▼'),
        "expected a delta chip vs yesterday:\n{s}"
    );
}

#[test]
fn status_json_includes_spend_series_and_previous_day() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    seed_multiday(&path);

    let out = burnwall(&path)
        .args(["status", "--json"])
        .output()
        .expect("run");
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    let series = v["spend_series"].as_array().expect("spend_series array");
    assert_eq!(series.len(), 7, "expected a dense 7-day series");
    assert!(v["previous_day"]["cost_usd"].as_f64().unwrap() > 0.0);
}

#[test]
fn history_shows_sparkline_and_delta_chips() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    seed_multiday(&path);

    let out = burnwall(&path)
        .args(["history", "--days", "5"])
        .output()
        .expect("run");
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.contains("Daily spend"), "missing sparkline label:\n{s}");
    assert!(
        s.chars().any(|c| "▁▂▃▄▅▆▇█".contains(c)),
        "missing sparkline glyphs:\n{s}"
    );
    // Window vs prior window → at least one delta chip.
    assert!(
        s.contains('▲') || s.contains('▼'),
        "expected a window delta chip:\n{s}"
    );
}

#[test]
fn accuracy_shows_overstatement_for_cache_heavy_spend() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    fs::create_dir_all(&path).unwrap();
    let storage = Storage::open(path.join("burnwall.db")).unwrap();
    // A cache-heavy request, stored at its REAL cache-aware cost — so the naive
    // sticker-rate tally must over-state it.
    let usage = TokenUsage {
        input_tokens: 2000,
        output_tokens: 3000,
        cache_creation_tokens: 0,
        cache_read_tokens: 120_000,
    };
    let model = "claude-sonnet-4-6";
    let cost = burnwall::pricing::calculate_cost(model, &usage).unwrap();
    let mut r = RequestRecord::successful("anthropic", model, &usage, cost, None);
    r.timestamp = Utc::now();
    storage.insert_request(&r).unwrap();

    // Table view.
    burnwall(&path)
        .arg("accuracy")
        .assert()
        .success()
        .stdout(predicate::str::contains("Cost accuracy"))
        .stdout(predicate::str::contains("On-wire"))
        .stdout(predicate::str::contains("Naive tally"));

    // JSON view: naive must exceed on-wire for a cache-heavy workload.
    let out = burnwall(&path)
        .args(["accuracy", "--json"])
        .output()
        .expect("run");
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    let wire = v["on_wire_usd"].as_f64().unwrap();
    let naive = v["naive_tally_usd"].as_f64().unwrap();
    assert!(naive > wire, "naive {naive} should exceed on-wire {wire}");
    assert!(v["overstated_usd"].as_f64().unwrap() > 0.0);
}

#[test]
fn tags_reports_spend_by_attribution_label() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    fs::create_dir_all(&path).unwrap();
    let storage = Storage::open(path.join("burnwall.db")).unwrap();
    let usage = TokenUsage {
        input_tokens: 1000,
        output_tokens: 500,
        cache_creation_tokens: 0,
        cache_read_tokens: 0,
    };
    for (client, cost) in [("acme", 0.40), ("acme", 0.20), ("globex", 0.10)] {
        let mut r = RequestRecord::successful("anthropic", "claude-sonnet-4-6", &usage, cost, None)
            .with_tags(Some(format!(r#"{{"client":"{client}","feature":"auth"}}"#)));
        r.timestamp = Utc::now();
        storage.insert_request(&r).unwrap();
    }

    // Table view groups by key and lists values.
    burnwall(&path)
        .arg("tags")
        .assert()
        .success()
        .stdout(predicate::str::contains("Attribution tags"))
        .stdout(predicate::str::contains("By client"))
        .stdout(predicate::str::contains("acme"))
        .stdout(predicate::str::contains("globex"));

    // JSON view: client=acme rolls up to 0.60 across two requests.
    let out = burnwall(&path)
        .args(["tags", "--key", "client", "--json"])
        .output()
        .expect("run");
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    let client = v["by_key"]["client"].as_array().unwrap();
    let acme = client.iter().find(|e| e["value"] == "acme").unwrap();
    assert!((acme["cost_usd"].as_f64().unwrap() - 0.60).abs() < 1e-9);
    assert_eq!(acme["requests"].as_i64().unwrap(), 2);
    // Filtering by key excludes the other key entirely.
    assert!(v["by_key"].get("feature").is_none());
}

#[test]
fn tags_empty_db_explains_the_header() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    fs::create_dir_all(&path).unwrap();
    burnwall(&path)
        .arg("tags")
        .assert()
        .success()
        .stdout(predicate::str::contains("no tagged requests"))
        .stdout(predicate::str::contains("x-burnwall-tags"));
}

#[test]
fn accuracy_empty_db_does_not_panic() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    fs::create_dir_all(&path).unwrap();
    burnwall(&path)
        .arg("accuracy")
        .assert()
        .success()
        .stdout(predicate::str::contains("no proxied spend"));
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
        .stdout(predicate::str::contains("slow_drip_alert"))
        .stdout(predicate::str::contains("anthropic/claude-sonnet-4-6"))
        .stdout(predicate::str::contains("~/.ssh/id_rsa"))
        .stdout(predicate::str::contains("Total: 2 event"));
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
    assert_eq!(v["count"], 2);
    let types: Vec<&str> = v["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["event_type"].as_str().unwrap())
        .collect();
    assert!(types.contains(&"path_blocked"), "got: {types:?}");
    assert!(types.contains(&"slow_drip_alert"), "got: {types:?}");
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
        .stdout(predicate::str::contains("Security checks fired: 2"));
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

// ─────────────────────────────── pricing ───────────────────────────────

#[test]
fn pricing_list_shows_builtin_and_local_override() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    fs::create_dir_all(&path).unwrap();
    // A local override for an unknown model + a shadow of a built-in.
    fs::write(
        path.join("pricing.toml"),
        "[[model]]\nname = \"claude-opus-4-9\"\ninput_per_mtok = 5.0\noutput_per_mtok = 25.0\n",
    )
    .unwrap();

    burnwall(&path)
        .args(["pricing", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("claude-opus-4-9"))
        .stdout(predicate::str::contains("override (new)"))
        .stdout(predicate::str::contains("claude-sonnet-4-6")) // built-in still listed
        .stdout(predicate::str::contains("1 override(s) active"));
}

#[test]
fn pricing_path_init_writes_starter_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    fs::create_dir_all(&path).unwrap();

    burnwall(&path)
        .args(["pricing", "path", "--init"])
        .assert()
        .success()
        .stdout(predicate::str::contains("starter file"));
    assert!(path.join("pricing.toml").exists());
}

/// Pull the hex public key out of `rules keygen` stdout (last non-empty line).
fn keygen_public_key(dir: &PathBuf, seed_path: &std::path::Path) -> String {
    let output = burnwall(dir)
        .args(["rules", "keygen"])
        .arg(seed_path)
        .output()
        .expect("keygen");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    stdout
        .lines()
        .map(str::trim)
        .rfind(|l| !l.is_empty())
        .expect("a public key line")
        .to_string()
}

#[test]
fn pricing_sign_then_verify_roundtrips_and_rejects_tamper() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    fs::create_dir_all(&path).unwrap();

    let seed = path.join("key.seed");
    let pubkey = keygen_public_key(&path, &seed);

    let card = path.join("card.toml");
    fs::write(
        &card,
        "[[model]]\nname = \"gpt-6\"\ninput_per_mtok = 2.5\noutput_per_mtok = 12.0\n",
    )
    .unwrap();
    let sig = path.join("card.sig");

    // Sign with the secret seed.
    burnwall(&path)
        .args(["pricing", "sign"])
        .arg(&card)
        .arg("--key")
        .arg(&seed)
        .arg("--out")
        .arg(&sig)
        .assert()
        .success();

    // Verify against the matching public key → trusted.
    burnwall(&path)
        .args(["pricing", "verify"])
        .arg(&card)
        .arg("--sig")
        .arg(&sig)
        .arg("--publisher")
        .arg(&pubkey)
        .assert()
        .success()
        .stdout(predicate::str::contains("Signature verifies"));

    // Tamper with the card → verification must fail (non-zero exit).
    fs::write(
        &card,
        "[[model]]\nname = \"gpt-6\"\ninput_per_mtok = 0.01\noutput_per_mtok = 0.01\n",
    )
    .unwrap();
    burnwall(&path)
        .args(["pricing", "verify"])
        .arg(&card)
        .arg("--sig")
        .arg(&sig)
        .arg("--publisher")
        .arg(&pubkey)
        .assert()
        .failure();
}

#[test]
fn pricing_verify_without_publishers_errors() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    fs::create_dir_all(&path).unwrap();
    let card = path.join("card.toml");
    fs::write(
        &card,
        "[[model]]\nname = \"x\"\ninput_per_mtok = 1.0\noutput_per_mtok = 1.0\n",
    )
    .unwrap();
    let sig = path.join("card.sig");
    fs::write(&sig, "deadbeef").unwrap();

    // No [pricing].publishers and no --publisher → refuse, don't fail-open.
    burnwall(&path)
        .args(["pricing", "verify"])
        .arg(&card)
        .arg("--sig")
        .arg(&sig)
        .assert()
        .failure()
        .stderr(predicate::str::contains("no trusted publishers"));
}

// ─────────────────────────────── statusline ───────────────────────────────

#[test]
fn statusline_renders_ribbon_from_claude_code_json() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    fs::create_dir_all(&path).unwrap();

    let json = r#"{"session_id":"s1","model":{"id":"claude-sonnet-4-6"},"cost":{"total_cost_usd":0.16},"context_window":{"used_percentage":22,"current_usage":{"input_tokens":5000,"output_tokens":615,"cache_creation_input_tokens":3000,"cache_read_input_tokens":5000}}}"#;

    burnwall(&path)
        .args(["statusline", "--no-color"])
        // Force the unprotected/direct path deterministically: if `cargo test`
        // is run from a burnwall-routed shell, a leaked ANTHROPIC_BASE_URL would
        // otherwise flip the ribbon to proxied and change what renders.
        .env_remove("ANTHROPIC_BASE_URL")
        .env_remove("OPENAI_BASE_URL")
        .env_remove("BURNWALL_BYPASS")
        .write_stdin(json)
        .assert()
        .success()
        .stdout(predicate::str::contains("🔥 burnwall · sonnet-4.6"))
        .stdout(predicate::str::contains("↑13k ↓615")) // input buckets summed
        // Direct = the proxy isn't in the path, so the cost/plan cluster is
        // suppressed (it would be stale). Both the plain and degraded direct
        // variants share this substring; the stdin-derived token + context
        // segments stay because they don't depend on the proxy.
        .stdout(predicate::str::contains("DIRECT (unprotected)"))
        .stdout(predicate::str::contains("sess").not())
        .stdout(predicate::str::contains("ctx [▓▓"))
        .stdout(predicate::str::contains("22%"));
}

#[test]
fn statusline_is_fail_open_on_garbage_stdin() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    fs::create_dir_all(&path).unwrap();

    // Non-JSON stdin must still produce a line (zeroed), never an error.
    burnwall(&path)
        .args(["statusline", "--no-color"])
        .write_stdin("not json at all")
        .assert()
        .success()
        .stdout(predicate::str::contains("🔥"));
}

// ─────────────────────────────── watch ───────────────────────────────

#[test]
fn watch_once_renders_cross_tool_ribbon() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    seed_storage(&path); // one anthropic/claude-sonnet-4-6 request

    burnwall(&path)
        .args(["watch", "--once", "--oneline", "--no-color"])
        .assert()
        .success()
        .stdout(predicate::str::contains("🔥 burnwall · sonnet-4.6"))
        .stdout(predicate::str::contains("today"));
}

#[test]
fn watch_once_empty_db_is_safe() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    fs::create_dir_all(&path).unwrap();
    burnwall(&path)
        .args(["watch", "--once", "--no-color"])
        .assert()
        .success()
        .stdout(predicate::str::contains("🔥"));
}

// ─────────────────────────────── savings ───────────────────────────────

#[test]
fn savings_reports_spend_and_is_json_valid() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    seed_storage(&path); // one anthropic/claude-sonnet-4-6 request, cost > 0

    burnwall(&path)
        .args(["savings", "--days", "30"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Savings & cost"))
        .stdout(predicate::str::contains("Real spend"));

    let output = burnwall(&path)
        .args(["savings", "--json"])
        .output()
        .expect("run");
    assert!(output.status.success());
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert!(v["real_spend_usd"].as_f64().is_some());
    assert!(v["opportunities"].is_array());
}

#[test]
fn status_shows_protection_heartbeat() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    seed_storage(&path);
    // Proxy isn't running in the test sandbox → the "not running" heartbeat.
    burnwall(&path)
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("Proxy not running"));
}

// ───────────────────── per-session attribution (v0.9.9) ─────────────────────

#[test]
fn status_shows_by_session_when_sessions_present() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    fs::create_dir_all(&path).unwrap();
    // Seed two requests carrying an x-burnwall-session id.
    let db = Storage::open(path.join("burnwall.db")).unwrap();
    let usage = TokenUsage {
        input_tokens: 1000,
        output_tokens: 200,
        cache_creation_tokens: 0,
        cache_read_tokens: 0,
    };
    for cost in [0.02_f64, 0.03] {
        let mut r = RequestRecord::successful(
            "anthropic",
            "claude-sonnet-4-6",
            &usage,
            cost,
            Some("swarm-7".into()),
        );
        r.timestamp = Utc::now();
        db.insert_request(&r).unwrap();
    }
    burnwall(&path)
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("By session"))
        .stdout(predicate::str::contains("swarm-7"));
}

// ─────────────────────────────── share ───────────────────────────────

#[test]
fn share_emits_signed_value_card() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    fs::create_dir_all(&path).unwrap();
    burnwall(&path)
        .args(["share", "--days", "30"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Burnwall · last 30 days"))
        .stdout(predicate::str::contains("signed"))
        .stdout(predicate::str::contains("verify: payload"));
}

#[test]
fn share_no_sign_emits_unsigned_card() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    fs::create_dir_all(&path).unwrap();
    burnwall(&path)
        .args(["share", "--no-sign"])
        .assert()
        .success()
        .stdout(predicate::str::contains("unsigned"));
}

// ─────────────────────────────── upgrade ───────────────────────────────

#[test]
fn upgrade_dry_run_prints_plan() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    fs::create_dir_all(&path).unwrap();
    burnwall(&path)
        .args(["upgrade", "--dry-run"])
        .assert()
        .success()
        .stdout(predicate::str::contains("latest release"))
        .stdout(predicate::str::contains("releases/latest/download"))
        .stdout(predicate::str::contains("stop the proxy"));
}

#[test]
fn self_upgrade_alias_works() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    fs::create_dir_all(&path).unwrap();
    burnwall(&path)
        .args(["self-upgrade", "--dry-run"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Upgrading Burnwall"));
}
