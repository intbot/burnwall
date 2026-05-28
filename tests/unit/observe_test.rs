//! Observability tests (v0.7): the latency-sample query feeding the metrics
//! aggregator, and the Agent Bill of Materials digest assembled from storage.

use burnwall::observe::digest::Digest;
use burnwall::observe::metrics::aggregate;
use burnwall::providers::TokenUsage;
use burnwall::storage::{McpEvent, RequestRecord, SecurityEvent, Storage};

fn rec(provider: &str, model: &str, cost: f64, latency_ms: i64, status: i64) -> RequestRecord {
    let usage = TokenUsage {
        input_tokens: 100,
        output_tokens: 50,
        cache_creation_tokens: 0,
        cache_read_tokens: 0,
    };
    let mut r = RequestRecord::successful(provider, model, &usage, cost, None);
    r.latency_ms = Some(latency_ms);
    r.http_status = Some(status);
    r
}

#[test]
fn latency_samples_query_excludes_blocked_and_feeds_metrics() {
    let s = Storage::open_in_memory().unwrap();
    for (lat, st) in [(100, 200), (200, 200), (300, 500)] {
        s.insert_request(&rec("anthropic", "claude-opus-4-7", 0.01, lat, st))
            .unwrap();
    }
    // A blocked row has no latency/status — must be excluded from samples.
    s.insert_request(&RequestRecord::blocked(
        "anthropic",
        "claude-opus-4-7",
        "path_blocked",
        None,
    ))
    .unwrap();

    let samples = s.latency_samples_since_days(1).unwrap();
    assert_eq!(samples.len(), 3, "blocked row excluded");

    let metrics = aggregate(samples, 1);
    assert_eq!(metrics.len(), 1);
    assert_eq!(metrics[0].requests, 3);
    assert_eq!(metrics[0].errors, 1);
    assert_eq!(metrics[0].p50_ms, 200);
    assert_eq!(metrics[0].p95_ms, 300);
}

#[test]
fn digest_assembles_models_mcp_and_security_from_storage() {
    let s = Storage::open_in_memory().unwrap();

    s.insert_request(&rec("anthropic", "claude-opus-4-7", 0.05, 100, 200))
        .unwrap();
    s.insert_request(&rec("openai", "gpt-5.5", 0.02, 50, 200))
        .unwrap();
    s.insert_request(&RequestRecord::blocked(
        "anthropic",
        "claude-opus-4-7",
        "path_blocked",
        None,
    ))
    .unwrap();

    let ev = SecurityEvent::new("path_blocked", "~/.ssh/id_rsa")
        .with_provider("anthropic", "claude-opus-4-7");
    s.insert_security_event(&ev).unwrap();

    s.observe_mcp_tool("default", "search", "fp1").unwrap();
    s.insert_mcp_event(&McpEvent::new("search", Some("1"), 200))
        .unwrap();

    let d = Digest::build(&s, 7).unwrap();

    assert_eq!(d.models.len(), 2, "two forwarded models");
    assert!((d.total_cost_usd - 0.07).abs() < 1e-9);
    assert_eq!(d.turns, 3, "2 forwarded + 1 blocked");
    assert_eq!(d.blocked, 1);

    assert_eq!(d.mcp_tool_calls, 1);
    assert_eq!(d.distinct_mcp_tools, vec!["search".to_string()]);
    assert_eq!(d.mcp_tools.len(), 1);
    assert_eq!(d.mcp_tools[0].trust_state, "pending");

    assert_eq!(d.security_by_type.len(), 1);
    assert_eq!(d.security_by_type[0].event_type, "path_blocked");
    assert_eq!(d.security_by_type[0].count, 1);
    assert_eq!(d.distinct_targets, vec!["~/.ssh/id_rsa".to_string()]);
}

#[test]
fn digest_empty_storage_is_all_zero() {
    let s = Storage::open_in_memory().unwrap();
    let d = Digest::build(&s, 7).unwrap();
    assert_eq!(d.turns, 0);
    assert_eq!(d.total_cost_usd, 0.0);
    assert!(d.models.is_empty());
    assert!(d.mcp_tools.is_empty());
    assert!(d.security_by_type.is_empty());
}
