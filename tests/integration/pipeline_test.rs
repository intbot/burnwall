//! End-to-end pipeline tests: security → budget → forward → tee-parse →
//! storage record + budget counter increment.
//!
//! Each test stands up a `wiremock::MockServer` as the upstream and builds
//! a [`AppState`] with in-memory storage so assertions can read it back
//! directly.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use burnwall::budget::{BudgetConfig, BudgetTracker, LoopDetector};
use burnwall::proxy::{serve, AppState};
use burnwall::security::SecurityEngine;
use burnwall::storage::Storage;
use serde_json::json;
use tokio::net::TcpListener;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn spawn_proxy(state: AppState) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve(listener, Arc::new(state)).await;
    });
    addr
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

fn today() -> String {
    chrono::Utc::now().format("%Y-%m-%d").to_string()
}

/// Wait briefly for the tee callback to fire — it runs in a spawned task
/// after the response body is fully consumed.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(150)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn safe_anthropic_request_records_cost() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "msg_001",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "Hello"}],
            "model": "claude-sonnet-4-6",
            "usage": {"input_tokens": 1000, "output_tokens": 500}
        })))
        .expect(1)
        .mount(&mock)
        .await;

    let storage = Arc::new(Storage::open_in_memory().unwrap());
    let budget = Arc::new(BudgetTracker::with_defaults());
    let state = AppState {
        upstream_anthropic: mock.uri(),
        upstream_openai: "http://127.0.0.1:1".to_string(),
        http_client: reqwest::Client::new(),
        security: Arc::new(SecurityEngine::with_defaults()),
        budget: budget.clone(),
        loop_detector: Arc::new(LoopDetector::with_defaults()),
        storage: storage.clone(),
    };
    let addr = spawn_proxy(state).await;

    let resp = client()
        .post(format!("http://{}/anthropic/v1/messages", addr))
        .json(&json!({"model": "claude-sonnet-4-6", "max_tokens": 100}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let _ = resp.bytes().await.unwrap(); // drain so tee fires
    settle().await;

    // Cost math: input 1000 * 3.00 / 1M = $0.003;
    //            output 500 * 15.00 / 1M = $0.0075;
    //            total = $0.0105.
    let total = storage.total_cost_for_date(&today()).unwrap();
    assert!(
        (total - 0.0105).abs() < 1e-6,
        "storage total: expected $0.0105, got ${}",
        total
    );
    assert!((budget.today_spent() - 0.0105).abs() < 1e-6);

    let rows = storage.requests_for_date(&today()).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].provider, "anthropic");
    assert_eq!(rows[0].model, "claude-sonnet-4-6");
    assert!(!rows[0].blocked);
    assert_eq!(rows[0].input_tokens, 1000);
    assert_eq!(rows[0].output_tokens, 500);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn safe_openai_request_records_cost_with_cache() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-1",
            "model": "gpt-5.4",
            "choices": [{"message": {"role": "assistant", "content": "ok"}}],
            "usage": {
                "prompt_tokens": 2048,
                "completion_tokens": 512,
                "prompt_tokens_details": {"cached_tokens": 1536}
            }
        })))
        .expect(1)
        .mount(&mock)
        .await;

    let storage = Arc::new(Storage::open_in_memory().unwrap());
    let state = AppState {
        upstream_anthropic: "http://127.0.0.1:1".to_string(),
        upstream_openai: mock.uri(),
        http_client: reqwest::Client::new(),
        security: Arc::new(SecurityEngine::with_defaults()),
        budget: Arc::new(BudgetTracker::with_defaults()),
        loop_detector: Arc::new(LoopDetector::with_defaults()),
        storage: storage.clone(),
    };
    let addr = spawn_proxy(state).await;

    let resp = client()
        .post(format!("http://{}/openai/v1/chat/completions", addr))
        .json(&json!({"model": "gpt-5.4"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let _ = resp.bytes().await.unwrap();
    settle().await;

    let rows = storage.requests_for_date(&today()).unwrap();
    assert_eq!(rows.len(), 1);
    // gpt-5.4: cached 1536 → input = 2048-1536 = 512
    assert_eq!(rows[0].input_tokens, 512);
    assert_eq!(rows[0].cache_read_tokens, 1536);
    assert_eq!(rows[0].output_tokens, 512);
    // Cost: 512*1.25 + 1536*0.625 + 512*10.00, all / 1M = $0.00672
    assert!((rows[0].cost_usd - 0.00672).abs() < 1e-6);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn security_violation_returns_403_and_records_event() {
    // Mock should never be hit — security blocks before forwarding.
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock)
        .await;

    let storage = Arc::new(Storage::open_in_memory().unwrap());
    let state = AppState {
        upstream_anthropic: mock.uri(),
        upstream_openai: "http://127.0.0.1:1".to_string(),
        http_client: reqwest::Client::new(),
        security: Arc::new(SecurityEngine::with_defaults()),
        budget: Arc::new(BudgetTracker::with_defaults()),
        loop_detector: Arc::new(LoopDetector::with_defaults()),
        storage: storage.clone(),
    };
    let addr = spawn_proxy(state).await;

    let resp = client()
        .post(format!("http://{}/anthropic/v1/messages", addr))
        .json(&json!({
            "model": "claude-sonnet-4-6",
            "messages": [{
                "role": "assistant",
                "content": [{
                    "type": "tool_use",
                    "name": "bash",
                    "input": {"command": "cat ~/.ssh/id_rsa"}
                }]
            }]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["type"], "security_blocked");
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("Burnwall blocked"));

    settle().await;

    let events = storage.security_events_for_date(&today()).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, "path_blocked");
    assert_eq!(events[0].provider.as_deref(), Some("anthropic"));
    assert_eq!(events[0].model.as_deref(), Some("claude-sonnet-4-6"));

    // A blocked-request row is also logged with cost = 0.
    let rows = storage.requests_for_date(&today()).unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].blocked);
    assert_eq!(rows[0].cost_usd, 0.0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn budget_exceeded_returns_429_without_forwarding() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock)
        .await;

    let budget = Arc::new(BudgetTracker::new(BudgetConfig {
        daily_usd: 1.0,
        monthly_usd: 0.0,
        warn_percent: 80,
    }));
    budget.record(2.50); // already past the $1 cap

    let storage = Arc::new(Storage::open_in_memory().unwrap());
    let state = AppState {
        upstream_anthropic: mock.uri(),
        upstream_openai: "http://127.0.0.1:1".to_string(),
        http_client: reqwest::Client::new(),
        security: Arc::new(SecurityEngine::with_defaults()),
        budget,
        loop_detector: Arc::new(LoopDetector::with_defaults()),
        storage: storage.clone(),
    };
    let addr = spawn_proxy(state).await;

    let resp = client()
        .post(format!("http://{}/anthropic/v1/messages", addr))
        .json(&json!({"model": "claude-sonnet-4-6"}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 429);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["type"], "budget_exceeded");
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("Daily budget"));

    settle().await;
    let rows = storage.requests_for_date(&today()).unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].blocked);
    assert_eq!(rows[0].block_reason.as_deref(), Some("budget_exceeded"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sse_streaming_response_records_cost_from_message_start() {
    // Realistic Anthropic SSE payload with input_tokens in message_start and
    // output_tokens in message_delta.
    let sse = "event: message_start\n\
data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_x\",\"model\":\"claude-haiku-4-5\",\"usage\":{\"input_tokens\":2000,\"cache_creation_input_tokens\":0,\"cache_read_input_tokens\":500,\"output_tokens\":0}}}\n\
\n\
event: content_block_start\n\
data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\
\n\
event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hi\"}}\n\
\n\
event: message_delta\n\
data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":300}}\n\
\n\
event: message_stop\n\
data: {\"type\":\"message_stop\"}\n\n";

    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(sse.as_bytes(), "text/event-stream"))
        .expect(1)
        .mount(&mock)
        .await;

    let storage = Arc::new(Storage::open_in_memory().unwrap());
    let state = AppState {
        upstream_anthropic: mock.uri(),
        upstream_openai: "http://127.0.0.1:1".to_string(),
        http_client: reqwest::Client::new(),
        security: Arc::new(SecurityEngine::with_defaults()),
        budget: Arc::new(BudgetTracker::with_defaults()),
        loop_detector: Arc::new(LoopDetector::with_defaults()),
        storage: storage.clone(),
    };
    let addr = spawn_proxy(state).await;

    let resp = client()
        .post(format!("http://{}/anthropic/v1/messages", addr))
        .json(&json!({"model": "claude-haiku-4-5", "stream": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let bytes = resp.bytes().await.unwrap();
    assert_eq!(bytes.as_ref(), sse.as_bytes());
    settle().await;

    let rows = storage.requests_for_date(&today()).unwrap();
    assert_eq!(
        rows.len(),
        1,
        "expected SSE response to be parsed and stored"
    );
    assert_eq!(rows[0].model, "claude-haiku-4-5");
    assert_eq!(rows[0].input_tokens, 2000);
    assert_eq!(rows[0].cache_read_tokens, 500);
    assert_eq!(rows[0].output_tokens, 300);
    // haiku rates: input 1.00, cache_read 0.10, output 5.00
    //   2000/1M*1.00 + 500/1M*0.10 + 300/1M*5.00
    //   = 0.002 + 0.00005 + 0.0015 = 0.00355
    assert!(
        (rows[0].cost_usd - 0.00355).abs() < 1e-6,
        "got {}",
        rows[0].cost_usd
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn budget_warning_does_not_block() {
    // 9.5 spent vs $10 limit with 80% warn → Warn state, still forwarded.
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "msg",
            "model": "claude-sonnet-4-6",
            "usage": {"input_tokens": 1, "output_tokens": 1}
        })))
        .expect(1)
        .mount(&mock)
        .await;

    let budget = Arc::new(BudgetTracker::new(BudgetConfig {
        daily_usd: 10.0,
        monthly_usd: 0.0,
        warn_percent: 80,
    }));
    budget.record(9.50);

    let state = AppState {
        upstream_anthropic: mock.uri(),
        upstream_openai: "http://127.0.0.1:1".to_string(),
        http_client: reqwest::Client::new(),
        security: Arc::new(SecurityEngine::with_defaults()),
        budget,
        loop_detector: Arc::new(LoopDetector::with_defaults()),
        storage: Arc::new(Storage::open_in_memory().unwrap()),
    };
    let addr = spawn_proxy(state).await;

    let resp = client()
        .post(format!("http://{}/anthropic/v1/messages", addr))
        .json(&json!({"model": "claude-sonnet-4-6"}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loop_detection_blocks_after_threshold_identical_requests() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "msg",
            "model": "claude-haiku-4-5",
            "usage": {"input_tokens": 10, "output_tokens": 5}
        })))
        .mount(&mock)
        .await;

    // Detector tuned to block on the 3rd identical request within 60s.
    let detector = Arc::new(burnwall::budget::LoopDetector::new(
        burnwall::budget::LoopConfig {
            enabled: true,
            max_identical_requests: 3,
            window_seconds: 60,
            max_cost_per_window: 0.0, // disable cost-spiral for this test
            hash_prefix_bytes: 200,
        },
    ));

    let storage = Arc::new(Storage::open_in_memory().unwrap());
    let state = AppState {
        upstream_anthropic: mock.uri(),
        upstream_openai: "http://127.0.0.1:1".to_string(),
        http_client: reqwest::Client::new(),
        security: Arc::new(SecurityEngine::with_defaults()),
        budget: Arc::new(BudgetTracker::with_defaults()),
        loop_detector: detector,
        storage: storage.clone(),
    };
    let addr = spawn_proxy(state).await;

    let body = json!({"model": "claude-haiku-4-5", "messages": [{"role": "user", "content": "hi"}]});

    // First two: forwarded
    for i in 1..=2 {
        let resp = client()
            .post(format!("http://{}/anthropic/v1/messages", addr))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "request {} should pass", i);
        let _ = resp.bytes().await; // drain
    }

    // Third identical: blocked
    let resp = client()
        .post(format!("http://{}/anthropic/v1/messages", addr))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429, "3rd identical request should be loop-blocked");
    let body_text: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body_text["error"]["type"], "loop_detected");
    assert!(body_text["error"]["message"]
        .as_str()
        .unwrap()
        .contains("loop detected"));

    settle().await;

    // The two forwarded requests + the one blocked one should all be in storage.
    let rows = storage.requests_for_date(&today()).unwrap();
    assert_eq!(rows.len(), 3, "all 3 requests should be logged");
    let blocked: Vec<_> = rows.iter().filter(|r| r.blocked).collect();
    assert_eq!(blocked.len(), 1, "exactly 1 blocked row");
    assert!(blocked[0]
        .block_reason
        .as_ref()
        .map(|r| r.contains("loop detected"))
        .unwrap_or(false));
    // Successful rows should have request_hash populated.
    let successful: Vec<_> = rows.iter().filter(|r| !r.blocked).collect();
    assert!(successful.iter().all(|r| r.request_hash.is_some()));
    // Identical bodies -> identical hashes.
    assert_eq!(successful[0].request_hash, successful[1].request_hash);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn distinct_requests_dont_trip_loop_detector() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "msg", "model": "claude-haiku-4-5",
            "usage": {"input_tokens": 10, "output_tokens": 5}
        })))
        .mount(&mock)
        .await;

    let storage = Arc::new(Storage::open_in_memory().unwrap());
    let state = AppState {
        upstream_anthropic: mock.uri(),
        upstream_openai: "http://127.0.0.1:1".to_string(),
        http_client: reqwest::Client::new(),
        security: Arc::new(SecurityEngine::with_defaults()),
        budget: Arc::new(BudgetTracker::with_defaults()),
        loop_detector: Arc::new(burnwall::budget::LoopDetector::new(
            burnwall::budget::LoopConfig {
                enabled: true,
                max_identical_requests: 3,
                window_seconds: 60,
                max_cost_per_window: 0.0,
                hash_prefix_bytes: 200,
            },
        )),
        storage: storage.clone(),
    };
    let addr = spawn_proxy(state).await;

    // Send 5 requests with distinct bodies -- no loop should trip.
    for i in 0..5 {
        let body = json!({"model": "claude-haiku-4-5", "n": i});
        let resp = client()
            .post(format!("http://{}/anthropic/v1/messages", addr))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "distinct request {} should pass", i);
        let _ = resp.bytes().await;
    }
}
