//! Cost export + wire-vs-logs tests (v0.9).
//!
//! Exercises the public API of the two cost features end-to-end with synthetic
//! in-memory data only — no real DB files, no network, no real session logs.
//!
//! - Feature 5: per-repo + per-session CSV export. Verifies concurrency-correct
//!   attribution (interleaved repos/sessions land in the right bucket) and
//!   RFC 4180 output.
//! - Feature 12: wire-vs-logs drift. Verifies the wire side read from a real
//!   in-memory `Storage` lines up against a synthetic log-scrape estimate.

use chrono::{TimeZone, Utc};

use burnwall::logscrape::UsageEntry;
use burnwall::observe::cost_export;
use burnwall::observe::wire_vs_logs::{self, LogsModel, WireModel};
use burnwall::providers::TokenUsage;
use burnwall::storage::{RequestRecord, Storage};

fn entry(model: &str, ws: Option<&str>, session: Option<&str>, secs: u32) -> UsageEntry {
    UsageEntry {
        tool: "claude-code",
        model: model.to_string(),
        timestamp: Utc.with_ymd_and_hms(2026, 6, 11, 12, 0, secs).unwrap(),
        usage: TokenUsage {
            input_tokens: 1000,
            output_tokens: 200,
            cache_creation_tokens: 0,
            cache_read_tokens: 0,
        },
        reasoning_tokens: 0,
        session_id: session.map(str::to_string),
        workspace: ws.map(str::to_string),
        context_window: None,
    }
}

#[test]
fn csv_export_attributes_interleaved_repos_and_sessions() {
    // Repo A / session s1 and Repo B / session s2 fire alternately in time.
    let entries = vec![
        entry("claude-opus-4-7", Some("/work/repo-a/src"), Some("s1"), 0),
        entry("claude-opus-4-7", Some("/work/repo-b"), Some("s2"), 1),
        entry("claude-opus-4-7", Some("/work/repo-a/tests"), Some("s1"), 2),
        entry("claude-opus-4-7", Some("/work/repo-b"), Some("s2"), 3),
    ];
    // repo-a's nested dirs collapse to one root; repo-b kept as-is.
    let roots = vec!["/work/repo-a".to_string()];
    let rows = cost_export::rows_from_entries(&entries, &roots);

    // Two buckets: (repo-a, s1) with 2 turns, (repo-b, s2) with 2 turns —
    // never merged across repo/session despite interleaving in time.
    assert_eq!(rows.len(), 2);
    let a = rows
        .iter()
        .find(|r| r.repo == "/work/repo-a" && r.session == "s1")
        .expect("repo-a/s1 bucket");
    assert_eq!(a.requests, 2);
    assert_eq!(a.input_tokens, 2000);
    assert!(a.cost_usd > 0.0);

    let b = rows
        .iter()
        .find(|r| r.repo == "/work/repo-b" && r.session == "s2")
        .expect("repo-b/s2 bucket");
    assert_eq!(b.requests, 2);

    // Deterministic, RFC4180 header + every data row present.
    let csv = cost_export::to_csv_string(&rows);
    let lines: Vec<&str> = csv.lines().collect();
    assert!(lines[0].starts_with("date,repo,session,model,requests"));
    assert_eq!(lines.len(), 3, "header + 2 data rows");
    // Re-running is byte-identical (deterministic ordering).
    assert_eq!(csv, cost_export::to_csv_string(&rows));
}

#[test]
fn wire_vs_logs_drift_from_real_storage() {
    let s = Storage::open_in_memory().unwrap();

    // On-the-wire: two opus turns + one gpt turn, proxied today.
    let usage = TokenUsage {
        input_tokens: 1000,
        output_tokens: 500,
        cache_creation_tokens: 0,
        cache_read_tokens: 0,
    };
    s.insert_request(&RequestRecord::successful(
        "anthropic",
        "claude-opus-4-7",
        &usage,
        0.10,
        None,
    ))
    .unwrap();
    s.insert_request(&RequestRecord::successful(
        "anthropic",
        "claude-opus-4-7",
        &usage,
        0.10,
        None,
    ))
    .unwrap();
    s.insert_request(&RequestRecord::successful(
        "openai", "gpt-5.5", &usage, 0.04, None,
    ))
    .unwrap();

    // Wire side as the CLI would read it: per-model aggregates from storage.
    let wire: Vec<WireModel> = s
        .breakdown_since_days(1)
        .unwrap()
        .into_iter()
        .map(|b| WireModel {
            model: b.model,
            cost_usd: b.cost,
            requests: b.requests as u64,
        })
        .collect();

    // Logs side: a scraper that under-counted opus (saw only $0.15 of $0.20)
    // and missed gpt entirely.
    let logs = vec![LogsModel {
        model: "claude-opus-4-7".to_string(),
        cost_usd: 0.15,
        turns: 2,
    }];

    let report = wire_vs_logs::compute_drift(1, &wire, &logs, false);

    // Total wire = 0.24, total logs = 0.15 ⇒ logs under-report by 0.09.
    assert!((report.total_wire_usd - 0.24).abs() < 1e-9);
    assert!((report.total_logs_usd - 0.15).abs() < 1e-9);
    assert!((report.total_drift_usd() - (-0.09)).abs() < 1e-9);

    // The gpt model the scraper missed still appears, at full negative drift.
    let gpt = report
        .by_model
        .iter()
        .find(|m| m.model == "gpt-5.5")
        .expect("missed model surfaced");
    assert_eq!(gpt.logs_cost_usd, 0.0);
    assert!((gpt.drift_pct().unwrap() - (-100.0)).abs() < 1e-9);

    // Sorted by wire cost desc: opus ($0.20) before gpt ($0.04).
    assert_eq!(report.by_model[0].model, "claude-opus-4-7");
}

#[test]
fn wire_check_degrades_when_logs_empty() {
    // No log entries ⇒ logs_unavailable, wire side stands alone.
    let wire = vec![WireModel {
        model: "claude-opus-4-7".to_string(),
        cost_usd: 0.5,
        requests: 3,
    }];
    let report = wire_vs_logs::compute_drift(7, &wire, &[], true);
    assert!(report.logs_unavailable);
    assert_eq!(report.total_logs_usd, 0.0);
    assert!((report.total_drift_usd() - (-0.5)).abs() < 1e-9);
    assert!((report.total_drift_pct().unwrap() - (-100.0)).abs() < 1e-9);
}
