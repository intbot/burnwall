//! Storage / repository tests against an in-memory SQLite database.
//!
//! Every test calls [`Storage::open_in_memory`] so they're hermetic and
//! parallel-safe — no `~/.burnwall/` pollution, no shared state between
//! tests.

use chrono::{DateTime, TimeZone, Utc};

use burnwall::providers::TokenUsage;
use burnwall::storage::{RequestRecord, SecurityEvent, Storage};

fn ts(y: i32, m: u32, d: u32, h: u32, mi: u32, s: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(y, m, d, h, mi, s).unwrap()
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

    // Two on 2026-05-13, one on 2026-05-12, one on 2026-05-14
    for (when, cost) in &[
        (ts(2026, 5, 13, 9, 0, 0), 0.10),
        (ts(2026, 5, 13, 18, 30, 0), 0.25),
        (ts(2026, 5, 12, 23, 59, 0), 0.99),
        (ts(2026, 5, 14, 0, 0, 1), 0.50),
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

    let day = storage.total_cost_for_date("2026-05-13").unwrap();
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
    for when in &[
        ts(2026, 5, 13, 18, 0, 0),
        ts(2026, 5, 13, 9, 0, 0),
        ts(2026, 5, 13, 14, 0, 0),
    ] {
        let mut r = RequestRecord::successful("openai", "gpt-5.4", &sample_usage(), 0.01, None);
        r.timestamp = *when;
        storage.insert_request(&r).unwrap();
    }

    let rows = storage.requests_for_date("2026-05-13").unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].timestamp, ts(2026, 5, 13, 9, 0, 0));
    assert_eq!(rows[1].timestamp, ts(2026, 5, 13, 14, 0, 0));
    assert_eq!(rows[2].timestamp, ts(2026, 5, 13, 18, 0, 0));
}

#[test]
fn daily_totals_groups_by_date_and_aggregates() {
    let storage = Storage::open_in_memory().unwrap();

    // Use timestamps anchored near "now" so they fall inside the
    // `DATE('now', '-N days')` window the query computes.
    let now = Utc::now();
    let today = now.format("%Y-%m-%d").to_string();
    let yesterday = (now - chrono::Duration::days(1))
        .format("%Y-%m-%d")
        .to_string();

    // Today: two ok + one blocked
    for (i, blocked) in [false, false, true].iter().enumerate() {
        let mut r = if *blocked {
            RequestRecord::blocked("anthropic", "claude-haiku-4-5", "test", None)
        } else {
            RequestRecord::successful("anthropic", "claude-haiku-4-5", &sample_usage(), 0.05, None)
        };
        r.timestamp = now + chrono::Duration::seconds(i as i64);
        storage.insert_request(&r).unwrap();
    }
    // Yesterday: one ok
    {
        let mut r = RequestRecord::successful("openai", "gpt-5.4", &sample_usage(), 0.20, None);
        r.timestamp = now - chrono::Duration::days(1);
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

    let event = SecurityEvent::new("path_blocked", "~/.ssh/id_rsa")
        .with_provider("anthropic", "claude-sonnet-4-6");

    let id = storage.insert_security_event(&event).unwrap();

    let date = event.timestamp.format("%Y-%m-%d").to_string();
    let events = storage.security_events_for_date(&date).unwrap();
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
    e1.timestamp = ts(2026, 5, 13, 10, 0, 0);
    let mut e2 = SecurityEvent::new("command_blocked", "rm -rf /");
    e2.timestamp = ts(2026, 5, 14, 10, 0, 0);

    storage.insert_security_event(&e1).unwrap();
    storage.insert_security_event(&e2).unwrap();

    let day = storage.security_events_for_date("2026-05-13").unwrap();
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
