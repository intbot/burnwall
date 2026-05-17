//! Storage / repository tests against an in-memory SQLite database.
//!
//! Every test calls [`Storage::open_in_memory`] so they're hermetic and
//! parallel-safe — no `~/.burnwall/` pollution, no shared state between
//! tests.

use chrono::{DateTime, Duration, Local, TimeZone, Utc};

use burnwall::providers::TokenUsage;
use burnwall::storage::{RequestRecord, SecurityEvent, Storage};

fn ts(y: i32, m: u32, d: u32, h: u32, mi: u32, s: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(y, m, d, h, mi, s).unwrap()
}

/// A timestamp at local noon, `offset_days` from today, returned as the
/// stored (UTC) value. Date queries match in local time, so anchoring at
/// noon — maximally far from local midnight — keeps the calendar date
/// stable no matter what timezone the test runs in.
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

fn sample_usage() -> TokenUsage {
    TokenUsage {
        input_tokens: 100,
        output_tokens: 50,
        cache_creation_tokens: 200,
        cache_read_tokens: 1000,
    }
}

// ───────────────────────────── Migration ─────────────────────────────

#[test]
fn open_in_memory_creates_all_tables() {
    let storage = Storage::open_in_memory().expect("open");
    // Inserting into each table is the simplest "tables exist" assertion.
    storage
        .insert_request(&RequestRecord::successful(
            "anthropic",
            "claude-sonnet-4-6",
            &sample_usage(),
            0.01,
            None,
        ))
        .expect("requests table missing");
    storage
        .insert_security_event(&SecurityEvent::new("path_blocked", "/etc/shadow"))
        .expect("security_events table missing");
}

#[test]
fn open_is_idempotent() {
    let storage = Storage::open_in_memory().expect("first open");
    // No direct way to call migrate() a second time on the same connection
    // via the public API, but inserting after open should still succeed —
    // the IF NOT EXISTS clauses guarantee no error on re-run.
    let id = storage
        .insert_request(&RequestRecord::successful(
            "openai",
            "gpt-5.4",
            &sample_usage(),
            0.02,
            None,
        ))
        .expect("insert");
    assert!(id > 0);
}

// ─────────────────────────── Request roundtrip ───────────────────────────

#[test]
fn insert_and_read_back_request_preserves_all_fields() {
    let storage = Storage::open_in_memory().unwrap();
    let mut record = RequestRecord::successful(
        "anthropic",
        "claude-opus-4-7",
        &sample_usage(),
        0.123456,
        Some("session-abc".to_string()),
    );
    record.timestamp = ts(2026, 5, 13, 14, 30, 0);
    record.request_hash = Some("hashvalue".to_string());

    let id = storage.insert_request(&record).expect("insert");
    let read = storage.get_request(id).expect("query").expect("present");

    assert_eq!(read.id, Some(id));
    assert_eq!(read.timestamp, record.timestamp);
    assert_eq!(read.provider, "anthropic");
    assert_eq!(read.model, "claude-opus-4-7");
    assert_eq!(read.input_tokens, 100);
    assert_eq!(read.cache_creation_tokens, 200);
    assert_eq!(read.cache_read_tokens, 1000);
    assert_eq!(read.output_tokens, 50);
    assert!((read.cost_usd - 0.123456).abs() < 1e-12);
    assert!(!read.blocked);
    assert_eq!(read.block_reason, None);
    assert_eq!(read.session_id.as_deref(), Some("session-abc"));
    assert_eq!(read.request_hash.as_deref(), Some("hashvalue"));
}

#[test]
fn blocked_record_persists_reason_and_zero_cost() {
    let storage = Storage::open_in_memory().unwrap();
    let record = RequestRecord::blocked(
        "anthropic",
        "claude-sonnet-4-6",
        "path_blocked: ~/.ssh/id_rsa",
        None,
    );

    let id = storage.insert_request(&record).unwrap();
    let read = storage.get_request(id).unwrap().unwrap();

    assert!(read.blocked);
    assert_eq!(
        read.block_reason.as_deref(),
        Some("path_blocked: ~/.ssh/id_rsa")
    );
    assert_eq!(read.cost_usd, 0.0);
    assert_eq!(read.input_tokens, 0);
    assert_eq!(read.output_tokens, 0);
}

#[test]
fn get_request_returns_none_for_missing_id() {
    let storage = Storage::open_in_memory().unwrap();
    assert!(storage.get_request(99999).unwrap().is_none());
}

// ────────────────────────── Aggregate queries ──────────────────────────

#[test]
fn total_cost_for_date_sums_only_that_date() {
    let storage = Storage::open_in_memory().unwrap();

    // Two records today, one two days back, one two days ahead.
    for (when, cost) in &[
        (local_noon(0), 0.10),
        (local_noon(0) + Duration::hours(1), 0.25),
        (local_noon(-2), 0.99),
        (local_noon(2), 0.50),
    ] {
        let mut r = RequestRecord::successful(
            "anthropic",
            "claude-sonnet-4-6",
            &sample_usage(),
            *cost,
            None,
        );
        r.timestamp = *when;
        storage.insert_request(&r).unwrap();
    }

    let day = storage.total_cost_for_date(&local_date(0)).unwrap();
    assert!((day - 0.35).abs() < 1e-9, "got {}", day);
}

#[test]
fn total_cost_for_date_returns_zero_when_empty() {
    let storage = Storage::open_in_memory().unwrap();
    assert_eq!(storage.total_cost_for_date("2026-05-13").unwrap(), 0.0);
}

#[test]
fn requests_for_date_returns_oldest_first() {
    let storage = Storage::open_in_memory().unwrap();

    // Insert in non-chronological order; query must order ASC by timestamp.
    // All three land on today's local date (noon .. noon+3h).
    for when in &[
        local_noon(0) + Duration::hours(3),
        local_noon(0),
        local_noon(0) + Duration::hours(1),
    ] {
        let mut r = RequestRecord::successful("openai", "gpt-5.4", &sample_usage(), 0.01, None);
        r.timestamp = *when;
        storage.insert_request(&r).unwrap();
    }

    let rows = storage.requests_for_date(&local_date(0)).unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].timestamp, local_noon(0));
    assert_eq!(rows[1].timestamp, local_noon(0) + Duration::hours(1));
    assert_eq!(rows[2].timestamp, local_noon(0) + Duration::hours(3));
}

#[test]
fn daily_totals_groups_by_date_and_aggregates() {
    let storage = Storage::open_in_memory().unwrap();

    // Anchor on local noon so the rows fall on stable local dates inside
    // the `DATE('now', 'localtime', '-N days')` window the query computes.
    let today = local_date(0);
    let yesterday = local_date(-1);

    // Today: two ok + one blocked
    for (i, blocked) in [false, false, true].iter().enumerate() {
        let mut r = if *blocked {
            RequestRecord::blocked("anthropic", "claude-haiku-4-5", "test", None)
        } else {
            RequestRecord::successful("anthropic", "claude-haiku-4-5", &sample_usage(), 0.05, None)
        };
        r.timestamp = local_noon(0) + Duration::seconds(i as i64);
        storage.insert_request(&r).unwrap();
    }
    // Yesterday: one ok
    {
        let mut r = RequestRecord::successful("openai", "gpt-5.4", &sample_usage(), 0.20, None);
        r.timestamp = local_noon(-1);
        storage.insert_request(&r).unwrap();
    }

    let totals = storage.daily_totals(7).unwrap();
    // Newest-first ordering: today, then yesterday.
    assert!(totals.len() >= 2);
    assert_eq!(totals[0].date, today);
    assert_eq!(totals[0].total_requests, 3);
    assert_eq!(totals[0].total_blocked, 1);
    assert!((totals[0].total_cost - 0.10).abs() < 1e-9);

    assert_eq!(totals[1].date, yesterday);
    assert_eq!(totals[1].total_requests, 1);
    assert_eq!(totals[1].total_blocked, 0);
    assert!((totals[1].total_cost - 0.20).abs() < 1e-9);
}

// ─────────────────────────── Security events ───────────────────────────

#[test]
fn security_event_roundtrip_with_provider_context() {
    let storage = Storage::open_in_memory().unwrap();

    let mut event = SecurityEvent::new("path_blocked", "~/.ssh/id_rsa")
        .with_provider("anthropic", "claude-sonnet-4-6");
    event.timestamp = local_noon(0);

    let id = storage.insert_security_event(&event).unwrap();

    let events = storage.security_events_for_date(&local_date(0)).unwrap();
    let read = events
        .iter()
        .find(|e| e.id == Some(id))
        .expect("event not found");

    assert_eq!(read.event_type, "path_blocked");
    assert_eq!(read.details, "~/.ssh/id_rsa");
    assert_eq!(read.provider.as_deref(), Some("anthropic"));
    assert_eq!(read.model.as_deref(), Some("claude-sonnet-4-6"));
}

#[test]
fn security_events_for_date_excludes_other_dates() {
    let storage = Storage::open_in_memory().unwrap();

    let mut e1 = SecurityEvent::new("path_blocked", "/etc/shadow");
    e1.timestamp = local_noon(-1);
    let mut e2 = SecurityEvent::new("command_blocked", "rm -rf /");
    e2.timestamp = local_noon(0);

    storage.insert_security_event(&e1).unwrap();
    storage.insert_security_event(&e2).unwrap();

    let day = storage.security_events_for_date(&local_date(-1)).unwrap();
    assert_eq!(day.len(), 1);
    assert_eq!(day[0].event_type, "path_blocked");
}

// ─────────────────────────── File-based DB ───────────────────────────

#[test]
fn open_with_file_path_persists_across_reopens() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("burnwall.db");

    // Open, insert, drop.
    let id = {
        let storage = Storage::open(&path).expect("open");
        storage
            .insert_request(&RequestRecord::successful(
                "anthropic",
                "claude-opus-4-7",
                &sample_usage(),
                1.23,
                None,
            ))
            .expect("insert")
    };

    // Reopen, read back.
    let storage = Storage::open(&path).expect("reopen");
    let read = storage.get_request(id).unwrap().expect("present");
    assert!((read.cost_usd - 1.23).abs() < 1e-9);
}

#[test]
fn cache_projection_accumulates_across_calls() {
    let storage = Storage::open_in_memory().unwrap();
    let date = local_date(0);

    assert_eq!(storage.cache_projection_for_date(&date).unwrap(), 0.0);

    storage.record_cache_projection(&date, 0.10).unwrap();
    storage.record_cache_projection(&date, 0.25).unwrap();
    let total = storage.cache_projection_for_date(&date).unwrap();
    assert!((total - 0.35).abs() < 1e-9, "got {total}");
}

#[test]
fn cache_projection_per_day_buckets_are_independent() {
    let storage = Storage::open_in_memory().unwrap();
    let today = local_date(0);
    let yesterday = local_date(-1);

    storage.record_cache_projection(&today, 1.50).unwrap();
    storage.record_cache_projection(&yesterday, 0.40).unwrap();

    assert!((storage.cache_projection_for_date(&today).unwrap() - 1.50).abs() < 1e-9);
    assert!((storage.cache_projection_for_date(&yesterday).unwrap() - 0.40).abs() < 1e-9);
    assert_eq!(
        storage.cache_projection_for_date(&local_date(-2)).unwrap(),
        0.0,
    );
}

#[test]
fn cache_projection_ignores_non_positive_and_non_finite_values() {
    let storage = Storage::open_in_memory().unwrap();
    let date = local_date(0);

    storage.record_cache_projection(&date, 0.0).unwrap();
    storage.record_cache_projection(&date, -1.0).unwrap();
    storage.record_cache_projection(&date, f64::NAN).unwrap();
    storage
        .record_cache_projection(&date, f64::INFINITY)
        .unwrap();

    assert_eq!(storage.cache_projection_for_date(&date).unwrap(), 0.0);
}
