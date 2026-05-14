//! Tests for Tier-2 log scraping: per-tool JSONL parsing, date filtering,
//! tool+model aggregation, and fail-open behavior.

use std::fs;
use std::path::Path;
use std::sync::Mutex;

use chrono::{DateTime, NaiveDate, Utc};

use burnwall::logscrape::{self, claude_code, codex, UsageEntry};
use burnwall::providers::TokenUsage;

fn fixture(name: &str) -> String {
    let path = format!("tests/fixtures/{}", name);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {}", path, e))
}

fn dt(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .expect("valid rfc3339")
        .with_timezone(&Utc)
}

// `collect()` reads a process-global env var to find its log root. Serialize
// the tests that touch it and clean up on drop (panic-safe).
static ENV_LOCK: Mutex<()> = Mutex::new(());

struct EnvGuard {
    key: &'static str,
    _lock: std::sync::MutexGuard<'static, ()>,
}
impl Drop for EnvGuard {
    fn drop(&mut self) {
        std::env::remove_var(self.key);
    }
}
fn set_log_dir(key: &'static str, dir: &Path) -> EnvGuard {
    let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var(key, dir);
    EnvGuard { key, _lock: lock }
}

// ──────────────────────── Claude Code parser ────────────────────────

#[test]
fn claude_code_parse_str_extracts_assistant_turns() {
    let turns = claude_code::parse_str(&fixture("claude_code_session.jsonl"));
    // 3 distinct assistant turns + 1 duplicate; summary / user / garbage
    // lines are skipped.
    assert_eq!(turns.len(), 4);

    let first = &turns[0];
    assert_eq!(first.dedup_key.as_deref(), Some("msg_001:req_001"));
    assert_eq!(first.entry.tool, "claude-code");
    assert_eq!(first.entry.model, "claude-opus-4-7");
    assert_eq!(first.entry.timestamp, dt("2026-05-14T09:00:05Z"));
    assert_eq!(first.entry.usage.input_tokens, 12);
    assert_eq!(first.entry.usage.cache_creation_tokens, 8000);
    assert_eq!(first.entry.usage.cache_read_tokens, 45000);
    assert_eq!(first.entry.usage.output_tokens, 210);

    // The last line repeats msg_001/req_001 verbatim.
    assert_eq!(turns[3].dedup_key, turns[0].dedup_key);
}

#[test]
fn claude_code_collect_dedupes_across_files() {
    let dir = tempfile::tempdir().unwrap();
    // Nested a level deep to exercise the recursive walk.
    let sub = dir.path().join("project-a");
    fs::create_dir_all(&sub).unwrap();
    fs::write(
        sub.join("session.jsonl"),
        fixture("claude_code_session.jsonl"),
    )
    .unwrap();

    let _guard = set_log_dir("BURNWALL_CLAUDE_LOG_DIR", dir.path());
    let entries = claude_code::collect();

    // 4 parsed turns → 3 after dropping the duplicated (msg_id, request_id).
    assert_eq!(entries.len(), 3);
    assert!(entries.iter().all(|e| e.tool == "claude-code"));
    let models: Vec<&str> = entries.iter().map(|e| e.model.as_str()).collect();
    assert!(models.contains(&"claude-opus-4-7"));
    assert!(models.contains(&"claude-haiku-4-5"));
}

#[test]
fn claude_code_collect_missing_dir_is_empty() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("does-not-exist");
    let _guard = set_log_dir("BURNWALL_CLAUDE_LOG_DIR", &missing);
    assert!(claude_code::collect().is_empty());
}

// ─────────────────────────── Codex parser ───────────────────────────

#[test]
fn codex_parse_str_normalizes_token_usage() {
    let entries = codex::parse_str(&fixture("codex_session.jsonl"), None);
    // 3 real token_count events; the zero-usage rate-limit re-emit and the
    // garbage line are skipped.
    assert_eq!(entries.len(), 3);

    let first = &entries[0];
    assert_eq!(first.tool, "codex");
    assert_eq!(first.model, "gpt-5.5");
    assert_eq!(first.timestamp, dt("2026-05-14T08:00:31Z"));
    // Codex input_tokens (5000) includes the cached portion (4000), so the
    // non-cached input is 1000 and cache_read is 4000.
    assert_eq!(first.usage.input_tokens, 1000);
    assert_eq!(first.usage.cache_read_tokens, 4000);
    assert_eq!(first.usage.cache_creation_tokens, 0);
    assert_eq!(first.usage.output_tokens, 300);
}

#[test]
fn codex_parse_str_skips_events_without_a_known_model() {
    // A token_count before any turn_context / session_meta has no model.
    let contents = r#"{"timestamp":"2026-05-14T01:00:00Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":100,"cached_input_tokens":0,"output_tokens":10,"total_tokens":110}}}}"#;
    assert!(codex::parse_str(contents, None).is_empty());
}

#[test]
fn codex_parse_str_falls_back_to_path_date_when_line_has_no_timestamp() {
    let contents = concat!(
        r#"{"type":"turn_context","payload":{"model":"gpt-5.4"}}"#,
        "\n",
        r#"{"type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":100,"cached_input_tokens":0,"output_tokens":10,"total_tokens":110}}}}"#,
    );
    let fallback = NaiveDate::from_ymd_opt(2026, 5, 10);

    // With a fallback date the timestamp-less event is dated and kept.
    let with_fallback = codex::parse_str(contents, fallback);
    assert_eq!(with_fallback.len(), 1);
    assert_eq!(with_fallback[0].model, "gpt-5.4");
    assert_eq!(with_fallback[0].timestamp, dt("2026-05-10T00:00:00Z"));

    // Without one it cannot be dated, so it is dropped (fail-open).
    assert!(codex::parse_str(contents, None).is_empty());
}

#[test]
fn codex_collect_reads_rollout_files() {
    let dir = tempfile::tempdir().unwrap();
    let day = dir.path().join("2026").join("05").join("14");
    fs::create_dir_all(&day).unwrap();
    fs::write(
        day.join("rollout-abc.jsonl"),
        fixture("codex_session.jsonl"),
    )
    .unwrap();

    let _guard = set_log_dir("BURNWALL_CODEX_LOG_DIR", dir.path());
    let entries = codex::collect();
    assert_eq!(entries.len(), 3);
    assert!(entries
        .iter()
        .all(|e| e.tool == "codex" && e.model == "gpt-5.5"));
}

// ──────────────────────── Aggregation ────────────────────────

fn entry(tool: &'static str, model: &str, ts: &str, input: u64, output: u64) -> UsageEntry {
    UsageEntry {
        tool,
        model: model.to_string(),
        timestamp: dt(ts),
        usage: TokenUsage {
            input_tokens: input,
            output_tokens: output,
            cache_creation_tokens: 0,
            cache_read_tokens: 0,
        },
    }
}

#[test]
fn aggregate_filters_by_date_and_groups_by_tool_model() {
    let entries = vec![
        entry(
            "claude-code",
            "claude-opus-4-7",
            "2026-05-14T01:00:00Z",
            100,
            50,
        ),
        entry(
            "claude-code",
            "claude-opus-4-7",
            "2026-05-14T02:00:00Z",
            200,
            80,
        ),
        entry("codex", "gpt-5.5", "2026-05-14T03:00:00Z", 500, 120),
        // Different day — must be filtered out.
        entry(
            "claude-code",
            "claude-opus-4-7",
            "2026-05-13T23:00:00Z",
            999,
            999,
        ),
    ];
    let rows = logscrape::aggregate(entries, "2026-05-14");
    assert_eq!(rows.len(), 2);

    let cc = rows
        .iter()
        .find(|r| r.tool == "claude-code")
        .expect("claude-code row");
    assert_eq!(cc.model, "claude-opus-4-7");
    assert_eq!(cc.turns, 2);
    assert_eq!(cc.usage.input_tokens, 300);
    assert_eq!(cc.usage.output_tokens, 130);
    assert!(cc.cost > 0.0);

    let cx = rows.iter().find(|r| r.tool == "codex").expect("codex row");
    assert_eq!(cx.turns, 1);
}

#[test]
fn aggregate_unknown_model_costs_zero() {
    let entries = vec![entry(
        "codex",
        "some-unreleased-model",
        "2026-05-14T01:00:00Z",
        1000,
        1000,
    )];
    let rows = logscrape::aggregate(entries, "2026-05-14");
    assert_eq!(rows.len(), 1);
    // Fail-open: a pricing miss yields cost 0, not an error.
    assert_eq!(rows[0].cost, 0.0);
}

#[test]
fn aggregate_empty_input_is_empty() {
    assert!(logscrape::aggregate(Vec::new(), "2026-05-14").is_empty());
}

#[test]
fn subtotal_sums_row_costs() {
    let rows = logscrape::aggregate(
        vec![
            entry(
                "claude-code",
                "claude-opus-4-7",
                "2026-05-14T01:00:00Z",
                1000,
                500,
            ),
            entry("codex", "gpt-5.5", "2026-05-14T02:00:00Z", 1000, 500),
        ],
        "2026-05-14",
    );
    let expected: f64 = rows.iter().map(|r| r.cost).sum();
    assert!((logscrape::subtotal(&rows) - expected).abs() < 1e-12);
    assert!(logscrape::subtotal(&rows) > 0.0);
}
