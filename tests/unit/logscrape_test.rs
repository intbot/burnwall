//! Tests for Tier-2 log scraping: per-tool JSONL parsing, date filtering,
//! tool+model aggregation, and fail-open behavior.

use std::fs;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration as StdDuration, SystemTime};

use chrono::{DateTime, Duration, Local, NaiveDate, Utc};

use burnwall::logscrape::{self, aider, claude_code, codex, opencode, UsageEntry};
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

/// A timestamp at local noon, `offset_days` from today, as a UTC value.
/// `aggregate` buckets entries by their *local* date, so anchoring at noon
/// keeps the date stable regardless of the machine timezone.
fn local_noon(offset_days: i64) -> DateTime<Utc> {
    (Local::now() + Duration::days(offset_days))
        .date_naive()
        .and_hms_opt(12, 0, 0)
        .unwrap()
        .and_local_timezone(Local)
        .single()
        .unwrap()
        .with_timezone(&Utc)
}

/// The local `YYYY-MM-DD` date string `offset_days` from today.
fn local_date(offset_days: i64) -> String {
    (Local::now() + Duration::days(offset_days))
        .date_naive()
        .format("%Y-%m-%d")
        .to_string()
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
        // TODO: Audit that the environment access only happens in single-threaded code.
        unsafe { std::env::remove_var(self.key) };
    }
}
fn set_log_dir(key: &'static str, dir: &Path) -> EnvGuard {
    let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // TODO: Audit that the environment access only happens in single-threaded code.
    unsafe { std::env::set_var(key, dir) };
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
    // Session + workspace come from top-level line fields; no context window.
    assert_eq!(first.entry.session_id.as_deref(), Some("sess_cc_1"));
    assert_eq!(first.entry.workspace.as_deref(), Some("/home/dev/webapp"));
    assert_eq!(first.entry.context_window, None);

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
    // Reasoning tokens are a subset of output_tokens, surfaced separately.
    assert_eq!(first.reasoning_tokens, 120);
    // Session id + cwd come from session_meta/turn_context; context window
    // from the token_count info block.
    assert_eq!(first.session_id.as_deref(), Some("sess_1"));
    assert_eq!(first.workspace.as_deref(), Some("/home/dev/proj"));
    assert_eq!(first.context_window, Some(272000));
}

#[test]
fn claude_code_entries_report_no_reasoning_tokens() {
    // Claude Code's usage block has no separate reasoning count, so every
    // parsed turn carries reasoning_tokens == 0 (the rule fails open on it).
    let turns = claude_code::parse_str(&fixture("claude_code_session.jsonl"));
    assert!(turns.iter().all(|t| t.entry.reasoning_tokens == 0));
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
    // The fallback anchors at noon-local, so check the local calendar date
    // rather than an exact instant.
    let with_fallback = codex::parse_str(contents, fallback);
    assert_eq!(with_fallback.len(), 1);
    assert_eq!(with_fallback[0].model, "gpt-5.4");
    assert_eq!(
        with_fallback[0]
            .timestamp
            .with_timezone(&Local)
            .date_naive(),
        NaiveDate::from_ymd_opt(2026, 5, 10).unwrap()
    );

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

// ─────────────────────────── OpenCode parser ───────────────────────────

#[test]
fn opencode_parse_message_maps_separated_cache_buckets() {
    let value: serde_json::Value = serde_json::from_str(&fixture("opencode_message.json")).unwrap();
    let entry = opencode::parse_message(&value, Utc::now()).expect("assistant message");

    assert_eq!(entry.tool, "opencode");
    assert_eq!(entry.model, "claude-sonnet-4-6");
    // OpenCode reports cache separately from input — no subtraction.
    assert_eq!(entry.usage.input_tokens, 1200);
    assert_eq!(entry.usage.output_tokens, 340);
    assert_eq!(entry.usage.cache_read_tokens, 45000);
    assert_eq!(entry.usage.cache_creation_tokens, 8000);
    assert_eq!(entry.reasoning_tokens, 50);
    assert_eq!(entry.session_id.as_deref(), Some("ses_oc_1"));
    // `time.completed` (epoch ms) wins over the fallback.
    assert_eq!(
        entry.timestamp,
        DateTime::from_timestamp_millis(1747209607000).unwrap()
    );
}

#[test]
fn opencode_parse_message_skips_non_assistant_and_empty() {
    let user = serde_json::json!({"role": "user", "tokens": {"input": 5}});
    assert!(opencode::parse_message(&user, Utc::now()).is_none());

    let zero = serde_json::json!({
        "role": "assistant", "modelID": "m",
        "tokens": {"input": 0, "output": 0, "cache": {"read": 0, "write": 0}}
    });
    assert!(opencode::parse_message(&zero, Utc::now()).is_none());
}

#[test]
fn opencode_parse_message_uses_mtime_fallback_without_time_field() {
    let value = serde_json::json!({
        "role": "assistant", "modelID": "claude-sonnet-4-6",
        "tokens": {"input": 100, "output": 10}
    });
    let fallback = local_noon(0);
    let entry = opencode::parse_message(&value, fallback).unwrap();
    assert_eq!(entry.timestamp, fallback);
}

#[test]
fn opencode_collect_reads_message_files() {
    let dir = tempfile::tempdir().unwrap();
    let session = dir.path().join("ses_oc_1");
    fs::create_dir_all(&session).unwrap();
    fs::write(
        session.join("msg_abc123.json"),
        fixture("opencode_message.json"),
    )
    .unwrap();

    let _guard = set_log_dir("BURNWALL_OPENCODE_LOG_DIR", dir.path());
    let entries = opencode::collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].tool, "opencode");
    assert_eq!(entries[0].model, "claude-sonnet-4-6");
}

// ─────────────────────────── Aider parser ───────────────────────────

#[test]
fn aider_parse_str_reads_message_send_events() {
    let entries = aider::parse_str(&fixture("aider_analytics.jsonl"));
    // 2 real sends; the /command line, the garbage line, and the zero-token
    // send are all skipped.
    assert_eq!(entries.len(), 2);

    let first = &entries[0];
    assert_eq!(first.tool, "aider");
    // Provider prefix stripped so the bare name can match the pricing table.
    assert_eq!(first.model, "gpt-5.2");
    assert_eq!(first.usage.input_tokens, 10006);
    assert_eq!(first.usage.output_tokens, 81);
    // Aider analytics carry no cache breakdown.
    assert_eq!(first.usage.cache_read_tokens, 0);
    assert_eq!(first.usage.cache_creation_tokens, 0);
    assert_eq!(
        first.timestamp,
        DateTime::from_timestamp(1747209605, 0).unwrap()
    );

    assert_eq!(entries[1].model, "claude-sonnet-4-6");
}

#[test]
fn aider_collect_reads_analytics_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("analytics.jsonl");
    fs::write(&path, fixture("aider_analytics.jsonl")).unwrap();

    let _guard = set_log_dir("BURNWALL_AIDER_ANALYTICS", &path);
    let entries = aider::collect();
    assert_eq!(entries.len(), 2);
    assert!(entries.iter().all(|e| e.tool == "aider"));
}

#[test]
fn aider_collect_missing_file_is_empty() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nope.jsonl");
    let _guard = set_log_dir("BURNWALL_AIDER_ANALYTICS", &missing);
    assert!(aider::collect().is_empty());
}

// ──────────────────────── Aggregation ────────────────────────

fn entry(
    tool: &'static str,
    model: &str,
    timestamp: DateTime<Utc>,
    input: u64,
    output: u64,
) -> UsageEntry {
    UsageEntry {
        tool,
        model: model.to_string(),
        timestamp,
        usage: TokenUsage {
            input_tokens: input,
            output_tokens: output,
            cache_creation_tokens: 0,
            cache_read_tokens: 0,
        },
        reasoning_tokens: 0,
        session_id: None,
        workspace: None,
        context_window: None,
    }
}

#[test]
fn aggregate_filters_by_date_and_groups_by_tool_model() {
    let entries = vec![
        entry("claude-code", "claude-opus-4-7", local_noon(0), 100, 50),
        entry(
            "claude-code",
            "claude-opus-4-7",
            local_noon(0) + Duration::hours(1),
            200,
            80,
        ),
        entry(
            "codex",
            "gpt-5.5",
            local_noon(0) + Duration::hours(2),
            500,
            120,
        ),
        // Different day — must be filtered out.
        entry("claude-code", "claude-opus-4-7", local_noon(-1), 999, 999),
    ];
    let rows = logscrape::aggregate(entries, &local_date(0));
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
        local_noon(0),
        1000,
        1000,
    )];
    let rows = logscrape::aggregate(entries, &local_date(0));
    assert_eq!(rows.len(), 1);
    // Fail-open: a pricing miss yields cost 0, not an error.
    assert_eq!(rows[0].cost, 0.0);
}

#[test]
fn aggregate_empty_input_is_empty() {
    assert!(logscrape::aggregate(Vec::new(), &local_date(0)).is_empty());
}

// ──────────────────────── mtime cutoff pruning ────────────────────────

/// Rewind a file's mtime by `days` days from now.
fn age_file(path: &Path, days: u64) {
    let mtime = SystemTime::now() - StdDuration::from_secs(days * 24 * 60 * 60);
    let file = fs::OpenOptions::new().write(true).open(path).unwrap();
    file.set_modified(mtime).unwrap();
}

/// A window-start cutoff `days` days before now.
fn cutoff_days_ago(days: u64) -> SystemTime {
    SystemTime::now() - StdDuration::from_secs(days * 24 * 60 * 60)
}

#[test]
fn mtime_staleness_allows_a_one_day_margin_past_the_cutoff() {
    let cutoff = SystemTime::now();
    let hour = StdDuration::from_secs(3600);
    // At or after the cutoff → fresh.
    assert!(!logscrape::mtime_is_stale(cutoff, cutoff));
    assert!(!logscrape::mtime_is_stale(cutoff + hour, cutoff));
    // Before the cutoff but within the 1-day safety margin → still fresh
    // (clock skew / buffered writes must not drop in-window data).
    assert!(!logscrape::mtime_is_stale(cutoff - 23 * hour, cutoff));
    // More than the margin before the cutoff → stale, skipped unread.
    assert!(logscrape::mtime_is_stale(cutoff - 25 * hour, cutoff));
}

#[test]
fn cutoff_for_local_date_parses_dates_fail_open() {
    // A valid local date maps to its local midnight: today's cutoff is in
    // the past, and yesterday's is strictly earlier.
    let today = logscrape::cutoff_for_local_date(&local_date(0)).expect("valid date");
    let yesterday = logscrape::cutoff_for_local_date(&local_date(-1)).expect("valid date");
    assert!(today <= SystemTime::now());
    assert!(yesterday < today);
    // Garbage yields no cutoff — scrape everything rather than prune wrongly.
    assert!(logscrape::cutoff_for_local_date("not-a-date").is_none());
    assert!(logscrape::cutoff_for_local_date("").is_none());
}

#[test]
fn claude_code_collect_since_prunes_files_older_than_the_window() {
    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("project-a");
    fs::create_dir_all(&sub).unwrap();

    // An old session file (mtime 10 days back) and a fresh one written now,
    // with distinct dedup keys so pruning — not dedup — decides the count.
    let old = sub.join("old.jsonl");
    fs::write(&old, fixture("claude_code_session.jsonl")).unwrap();
    age_file(&old, 10);
    let fresh = sub.join("fresh.jsonl");
    fs::write(
        &fresh,
        r#"{"type":"assistant","timestamp":"2026-06-10T09:00:05.000Z","requestId":"req_fresh","sessionId":"sess_f","cwd":"/w","message":{"id":"msg_fresh","model":"claude-opus-4-7","usage":{"input_tokens":10,"output_tokens":5}}}"#,
    )
    .unwrap();

    let _guard = set_log_dir("BURNWALL_CLAUDE_LOG_DIR", dir.path());

    // Window starts 2 days ago: the 10-day-old file cannot contribute rows
    // inside it (even with the 1-day margin) and is skipped unread; the
    // file modified today is parsed.
    let entries = claude_code::collect_since(Some(cutoff_days_ago(2)));
    assert_eq!(entries.len(), 1, "got {entries:?}");
    assert_eq!(entries[0].model, "claude-opus-4-7");
    assert_eq!(entries[0].session_id.as_deref(), Some("sess_f"));

    // No cutoff preserves the old read-everything behavior:
    // 3 deduped turns from the old file + 1 fresh.
    assert_eq!(claude_code::collect_since(None).len(), 4);
}

#[test]
fn aider_collect_since_skips_a_stale_analytics_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("analytics.jsonl");
    fs::write(&path, fixture("aider_analytics.jsonl")).unwrap();
    age_file(&path, 10);

    let _guard = set_log_dir("BURNWALL_AIDER_ANALYTICS", &path);

    // The analytics log was last touched well before the window → skipped.
    assert!(aider::collect_since(Some(cutoff_days_ago(2))).is_empty());
    // No cutoff still reads it (previous behavior preserved).
    assert_eq!(aider::collect_since(None).len(), 2);
    // A file touched today survives the same cutoff.
    age_file(&path, 0);
    assert_eq!(aider::collect_since(Some(cutoff_days_ago(2))).len(), 2);
}

#[test]
fn codex_collect_since_prunes_stale_rollouts() {
    let dir = tempfile::tempdir().unwrap();
    let day = dir.path().join("2026").join("05").join("14");
    fs::create_dir_all(&day).unwrap();
    let rollout = day.join("rollout-abc.jsonl");
    fs::write(&rollout, fixture("codex_session.jsonl")).unwrap();
    age_file(&rollout, 10);

    let _guard = set_log_dir("BURNWALL_CODEX_LOG_DIR", dir.path());
    assert!(codex::collect_since(Some(cutoff_days_ago(2))).is_empty());
    // Streaming without a cutoff parses the same 3 events as before.
    assert_eq!(codex::collect_since(None).len(), 3);
}

#[test]
fn subtotal_sums_row_costs() {
    let rows = logscrape::aggregate(
        vec![
            entry("claude-code", "claude-opus-4-7", local_noon(0), 1000, 500),
            entry(
                "codex",
                "gpt-5.5",
                local_noon(0) + Duration::hours(1),
                1000,
                500,
            ),
        ],
        &local_date(0),
    );
    let expected: f64 = rows.iter().map(|r| r.cost).sum();
    assert!((logscrape::subtotal(&rows) - expected).abs() < 1e-12);
    assert!(logscrape::subtotal(&rows) > 0.0);
}
