//! Budget tracker tests.
//!
//! Two layers:
//! - Pure [`check_daily`] under various spend / limit / warn-percent
//!   combinations, including the "0 means unlimited" convention.
//! - [`BudgetTracker`] runtime: record/check/reset, hydration from
//!   [`Storage`], precision at sub-cent costs, and concurrent recording.

use std::sync::Arc;
use std::thread;

use burnwall::budget::{check_daily, BudgetConfig, BudgetStatus, BudgetTracker};
use burnwall::providers::TokenUsage;
use burnwall::storage::{RequestRecord, Storage};

fn cfg(daily: f64, warn: u8) -> BudgetConfig {
    BudgetConfig {
        daily_usd: daily,
        monthly_usd: 0.0,
        warn_percent: warn,
    }
}

const EPS: f64 = 1e-9;

// ───────────────────────────── Pure check ─────────────────────────────

#[test]
fn under_warning_threshold_returns_ok() {
    assert_eq!(check_daily(10.0, &cfg(50.0, 80)), BudgetStatus::Ok);
}

#[test]
fn at_warning_threshold_returns_warn() {
    // 80% of 50 = 40
    let status = check_daily(40.0, &cfg(50.0, 80));
    match status {
        BudgetStatus::Warn {
            spent,
            limit,
            percent,
        } => {
            assert!((spent - 40.0).abs() < EPS);
            assert!((limit - 50.0).abs() < EPS);
            assert_eq!(percent, 80);
        }
        _ => panic!("expected Warn, got {:?}", status),
    }
}

#[test]
fn above_warning_below_limit_still_warns() {
    let status = check_daily(45.0, &cfg(50.0, 80));
    assert!(matches!(status, BudgetStatus::Warn { .. }));
}

#[test]
fn at_daily_limit_blocks() {
    // SPEC step 4(b): `>= daily_limit` blocks.
    let status = check_daily(50.0, &cfg(50.0, 80));
    match status {
        BudgetStatus::Exceeded { spent, limit } => {
            assert!((spent - 50.0).abs() < EPS);
            assert!((limit - 50.0).abs() < EPS);
        }
        _ => panic!("expected Exceeded, got {:?}", status),
    }
    assert!(status.is_blocking());
}

#[test]
fn over_daily_limit_blocks() {
    let status = check_daily(51.0, &cfg(50.0, 80));
    assert!(matches!(status, BudgetStatus::Exceeded { .. }));
}

#[test]
fn zero_daily_means_unlimited() {
    // Even with huge spend, daily=0 returns Ok.
    let status = check_daily(1_000_000.0, &cfg(0.0, 80));
    assert_eq!(status, BudgetStatus::Ok);
}

// ─────────────────────────── Tracker basics ───────────────────────────

#[test]
fn tracker_starts_at_zero() {
    let t = BudgetTracker::new(cfg(50.0, 80));
    assert!((t.today_spent() - 0.0).abs() < EPS);
    assert_eq!(t.check(), BudgetStatus::Ok);
}

#[test]
fn record_accumulates() {
    let t = BudgetTracker::new(cfg(50.0, 80));
    t.record(1.25);
    t.record(2.50);
    t.record(0.50);
    assert!((t.today_spent() - 4.25).abs() < EPS);
}

#[test]
fn record_clamps_invalid_inputs() {
    // Negative, NaN, infinity must not corrupt the counter.
    let t = BudgetTracker::new(cfg(50.0, 80));
    t.record(1.0);
    t.record(-5.0);
    t.record(f64::NAN);
    t.record(f64::INFINITY);
    assert!((t.today_spent() - 1.0).abs() < EPS);
}

#[test]
fn sub_cent_costs_accumulate_precisely() {
    // Microcent precision is the point: 1_000 tiny gpt-5.4-mini-style
    // requests at 0.0001 USD each must reach 0.1 USD, not round to zero.
    let t = BudgetTracker::new(cfg(50.0, 80));
    for _ in 0..1_000 {
        t.record(0.0001);
    }
    assert!((t.today_spent() - 0.1).abs() < 1e-6);
}

#[test]
fn check_transitions_through_ok_warn_exceeded() {
    let t = BudgetTracker::new(cfg(10.0, 80));
    t.record(5.0);
    assert_eq!(t.check(), BudgetStatus::Ok);
    t.record(3.5); // 8.5 total → ≥ 80% of 10
    assert!(matches!(t.check(), BudgetStatus::Warn { .. }));
    t.record(2.0); // 10.5 total → over limit
    assert!(matches!(t.check(), BudgetStatus::Exceeded { .. }));
}

#[test]
fn reset_zeroes_counter() {
    let t = BudgetTracker::new(cfg(10.0, 80));
    t.record(7.0);
    t.reset();
    assert_eq!(t.today_spent(), 0.0);
    assert_eq!(t.check(), BudgetStatus::Ok);
}

// ─────────────────────────── Hydration from DB ───────────────────────────

fn sample_usage() -> TokenUsage {
    TokenUsage {
        input_tokens: 100,
        output_tokens: 50,
        cache_creation_tokens: 0,
        cache_read_tokens: 0,
    }
}

#[test]
fn hydrate_loads_todays_total_from_storage() {
    let storage = Storage::open_in_memory().expect("storage");
    // Insert two requests on the same date.
    let date = "2026-05-13";
    for cost in &[0.75, 1.50] {
        let mut r = RequestRecord::successful(
            "anthropic",
            "claude-sonnet-4-6",
            &sample_usage(),
            *cost,
            None,
        );
        r.timestamp = chrono::DateTime::parse_from_rfc3339("2026-05-13T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        storage.insert_request(&r).unwrap();
    }

    let tracker = BudgetTracker::new(cfg(50.0, 80));
    tracker.hydrate_for_date(&storage, date).expect("hydrate");
    assert!((tracker.today_spent() - 2.25).abs() < 1e-6);
}

#[test]
fn hydrate_on_empty_date_results_in_zero() {
    let storage = Storage::open_in_memory().unwrap();
    let tracker = BudgetTracker::new(cfg(50.0, 80));
    tracker.hydrate_for_date(&storage, "2026-05-13").unwrap();
    assert_eq!(tracker.today_spent(), 0.0);
}

#[test]
fn hydrate_replaces_existing_counter_value() {
    // Background: counter has some accumulated value, then we re-hydrate
    // (e.g. on date rollover). Hydration must REPLACE, not ADD.
    let storage = Storage::open_in_memory().unwrap();
    let date = "2026-05-13";
    let mut r = RequestRecord::successful("openai", "gpt-5.4", &sample_usage(), 3.00, None);
    r.timestamp = chrono::DateTime::parse_from_rfc3339("2026-05-13T12:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    storage.insert_request(&r).unwrap();

    let tracker = BudgetTracker::new(cfg(50.0, 80));
    tracker.record(99.0); // pretend it had stale state
    tracker.hydrate_for_date(&storage, date).unwrap();
    assert!((tracker.today_spent() - 3.00).abs() < 1e-6);
}

// ─────────────────────────── Concurrency ───────────────────────────

#[test]
fn record_is_safe_under_concurrent_writers() {
    let tracker = Arc::new(BudgetTracker::new(cfg(0.0, 80))); // unlimited
    let threads = 8;
    let per_thread = 10_000;
    let cost_each = 0.001; // 0.1 cent
    let mut handles = Vec::with_capacity(threads);
    for _ in 0..threads {
        let t = tracker.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..per_thread {
                t.record(cost_each);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let expected = (threads * per_thread) as f64 * cost_each;
    let actual = tracker.today_spent();
    assert!(
        (actual - expected).abs() < 1e-3,
        "lost cost under concurrency: expected {}, got {}",
        expected,
        actual
    );
}
