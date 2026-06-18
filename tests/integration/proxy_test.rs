//! Integration tests for the Session 2 proxy.
//!
//! Each test stands up a `wiremock::MockServer` as the upstream and a Burnwall
//! proxy on a port-zero `TcpListener`, then drives the proxy with `reqwest`
//! and asserts pass-through semantics: status, headers, body, query string.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use burnwall::proxy::{AppState, serve};
use burnwall::security::{Ruleset, SecurityEngine};
use bytes::Bytes;
use serde_json::json;
use tokio::net::TcpListener;
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Serializes tests that are sensitive to the process-global `BURNWALL_BYPASS`
/// env var: the bypass test sets it for one request, and any test that asserts
/// a security *block* must not have its request land inside that window (a
/// concurrent bypass would relay it unchecked and the block would not fire).
/// Holding this lock across the env-sensitive section makes those tests
/// deterministic. A `tokio::sync::Mutex` (not `std`) so the guard can be held
/// across the awaited request in a multi-thread test (its guard is `Send`).
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn spawn_proxy(state: AppState) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind 127.0.0.1:0");
    let addr = listener.local_addr().expect("local_addr");

    tokio::spawn(async move {
        if let Err(e) = serve(listener, Arc::new(state)).await {
            eprintln!("proxy serve error: {}", e);
        }
    });

    addr
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("reqwest client")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forwards_anthropic_post_with_body_and_auth_header() {
    let mock = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .and(header("x-api-key", "test-key"))
        .and(header("anthropic-version", "2023-06-01"))
        .and(body_json(
            json!({"model": "claude-sonnet-4-6", "max_tokens": 100}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "msg_01ABC",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "Hello from upstream"}],
            "model": "claude-sonnet-4-6",
            "usage": {"input_tokens": 5, "output_tokens": 3}
        })))
        .expect(1)
        .mount(&mock)
        .await;

    let state = AppState::new(mock.uri(), "http://127.0.0.1:1".to_string());
    let proxy = spawn_proxy(state).await;

    let resp = client()
        .post(format!("http://{}/anthropic/v1/messages", proxy))
        .header("x-api-key", "test-key")
        .header("anthropic-version", "2023-06-01")
        .json(&json!({"model": "claude-sonnet-4-6", "max_tokens": 100}))
        .send()
        .await
        .expect("proxy POST");

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("parse json");
    assert_eq!(body["id"], "msg_01ABC");
    assert_eq!(body["usage"]["input_tokens"], 5);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn healthz_returns_ok_without_touching_upstream() {
    // No upstream mock â€” the test asserts /healthz never reaches a backend.
    // We point both upstreams at an unreachable 127.0.0.1:1 to prove that
    // a successful response only comes from the proxy itself.
    let state = AppState::new(
        "http://127.0.0.1:1".to_string(),
        "http://127.0.0.1:1".to_string(),
    );
    let proxy = spawn_proxy(state).await;

    let resp = client()
        .get(format!("http://{}/healthz", proxy))
        .send()
        .await
        .expect("proxy GET /healthz");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("parse json");
    assert_eq!(body["status"], "ok");
    assert_eq!(body["service"], "burnwall");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bypass_skips_security_scan() {
    // With BURNWALL_BYPASS=1 the proxy is a pure relay. A request body that
    // would normally trip the security scan must still reach upstream and
    // get the upstream's response back. We verify by setting up an upstream
    // that returns 200 OK for the request that should have been blocked,
    // then setting the env var and asserting the request lands.
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .expect(1)
        .mount(&mock)
        .await;

    let state = AppState::new(mock.uri(), "http://127.0.0.1:1".to_string());
    let proxy = spawn_proxy(state).await;

    // Race risk: BURNWALL_BYPASS is global to the process. Hold ENV_LOCK across
    // the set→request→unset window so a concurrent block-asserting test isn't
    // relayed unchecked. The fail-open semantics of `handle` read the var on
    // each call so unsetting after is sufficient.
    let _guard = ENV_LOCK.lock().await;
    // TODO: Audit that the environment access only happens in single-threaded code.
    unsafe { std::env::set_var("BURNWALL_BYPASS", "1") };
    let resp = client()
        .post(format!("http://{}/anthropic/v1/messages", proxy))
        .json(&json!({
            "model": "claude-sonnet-4-6",
            "messages": [{
                "role": "user",
                "content": [{
                    "type": "tool_use",
                    "input": {"path": "~/.ssh/id_rsa"}
                }]
            }]
        }))
        .send()
        .await
        .expect("proxy POST");
    // TODO: Audit that the environment access only happens in single-threaded code.
    unsafe { std::env::remove_var("BURNWALL_BYPASS") };

    // Without bypass this would be 403 from the security scan. With bypass
    // the upstream's 200 reaches us.
    assert_eq!(resp.status(), 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forwards_openai_post_with_bearer_auth() {
    let mock = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(header("authorization", "Bearer sk-test"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-1",
            "choices": [{"message": {"role": "assistant", "content": "ok"}}],
            "usage": {"prompt_tokens": 4, "completion_tokens": 1, "total_tokens": 5}
        })))
        .expect(1)
        .mount(&mock)
        .await;

    let state = AppState::new("http://127.0.0.1:1".to_string(), mock.uri());
    let proxy = spawn_proxy(state).await;

    let resp = client()
        .post(format!("http://{}/openai/v1/chat/completions", proxy))
        .header("authorization", "Bearer sk-test")
        .json(&json!({"model": "gpt-5.4"}))
        .send()
        .await
        .expect("proxy POST");

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("parse json");
    assert_eq!(body["id"], "chatcmpl-1");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preserves_query_string() {
    let mock = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .and(query_param("limit", "10"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .expect(1)
        .mount(&mock)
        .await;

    let state = AppState::new(mock.uri(), mock.uri());
    let proxy = spawn_proxy(state).await;

    let resp = client()
        .get(format!("http://{}/anthropic/v1/models?limit=10", proxy))
        .send()
        .await
        .expect("proxy GET");

    assert_eq!(resp.status(), 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forwards_sse_streaming_body_and_content_type() {
    // Wiremock sends the bytes as one response, but the proxy must (a)
    // preserve `text/event-stream` content-type and (b) emit the body bytes
    // unmodified. That's what an SSE-aware client cares about.
    let mock = MockServer::start().await;

    let sse_body: &[u8] = b"event: message_start\ndata: {\"type\":\"message_start\"}\n\n\
                            event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"Hi\"}}\n\n\
                            event: message_delta\ndata: {\"usage\":{\"output_tokens\":2}}\n\n\
                            event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";

    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(sse_body, "text/event-stream"))
        .expect(1)
        .mount(&mock)
        .await;

    let state = AppState::new(mock.uri(), mock.uri());
    let proxy = spawn_proxy(state).await;

    let resp = client()
        .post(format!("http://{}/anthropic/v1/messages", proxy))
        .json(&json!({"stream": true}))
        .send()
        .await
        .expect("proxy POST");

    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .expect("content-type header"),
        "text/event-stream"
    );

    let body = resp.bytes().await.expect("read body");
    assert_eq!(body, Bytes::copy_from_slice(sse_body));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forwards_upstream_error_status_unchanged() {
    let mock = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(429).set_body_json(json!({
            "error": {"type": "rate_limit_error", "message": "too many requests"}
        })))
        .expect(1)
        .mount(&mock)
        .await;

    let state = AppState::new(mock.uri(), mock.uri());
    let proxy = spawn_proxy(state).await;

    let resp = client()
        .post(format!("http://{}/anthropic/v1/messages", proxy))
        .json(&json!({}))
        .send()
        .await
        .expect("proxy POST");

    assert_eq!(resp.status(), 429);
    let body: serde_json::Value = resp.json().await.expect("parse json");
    assert_eq!(body["error"]["type"], "rate_limit_error");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn returns_404_for_unknown_route() {
    let state = AppState::with_defaults();
    let proxy = spawn_proxy(state).await;

    let resp = client()
        .get(format!("http://{}/cohere/v1/models", proxy))
        .send()
        .await
        .expect("proxy GET");

    assert_eq!(resp.status(), 404);
    let body: serde_json::Value = resp.json().await.expect("parse json");
    assert_eq!(body["error"]["type"], "proxy_error");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn returns_502_when_upstream_unreachable() {
    // Port 1 is virtually always closed.
    let state = AppState::new(
        "http://127.0.0.1:1".to_string(),
        "http://127.0.0.1:1".to_string(),
    );
    let proxy = spawn_proxy(state).await;

    let resp = client()
        .post(format!("http://{}/anthropic/v1/messages", proxy))
        .json(&json!({}))
        .send()
        .await
        .expect("proxy POST");

    assert_eq!(resp.status(), 502);
    let body: serde_json::Value = resp.json().await.expect("parse json");
    assert_eq!(body["error"]["type"], "proxy_error");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn file_upload_with_secret_is_blocked_when_egress_on() {
    // #3: a multipart/form-data upload to /v1/files is non-JSON, so the JSON
    // scanner fails open — the raw-body egress scan must catch a secret in it
    // when `detect_egress` is on. The upstream returns 200, but the request
    // must never reach it: a 403 from the proxy proves the upload was inspected.
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/files"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "file_1"})))
        // The block must short-circuit before the upstream is touched.
        .expect(0)
        .mount(&mock)
        .await;

    let mut state = AppState::new(mock.uri(), "http://127.0.0.1:1".to_string());
    state.security = std::sync::Arc::new(SecurityEngine::new(Ruleset {
        detect_egress: true,
        ..Ruleset::default()
    }));
    let proxy = spawn_proxy(state).await;

    // Build the dangerous literal at runtime (concat), then wrap in multipart.
    let key = format!("AWS_KEY=AKIA{}", "QQQQRRRRSSSSTTTT");
    let boundary = "----burnwalltestboundary";
    let body = format!(
        "--{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"d.txt\"\r\nContent-Type: text/plain\r\n\r\n{v}\r\n--{b}--\r\n",
        b = boundary,
        v = key
    );

    // Serialize against the bypass test: a concurrent global bypass would relay
    // this unchecked and the block wouldn't fire.
    let resp = {
        let _guard = ENV_LOCK.lock().await;
        client()
            .post(format!("http://{}/anthropic/v1/files", proxy))
            .header(
                "content-type",
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(body)
            .send()
            .await
            .expect("proxy POST")
    };

    assert_eq!(resp.status(), 403);
    assert!(resp.headers().contains_key("x-burnwall-blocked"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clean_file_upload_passes_through_when_egress_on() {
    // The complement: a benign upload to /v1/files is forwarded unchanged even
    // with egress on — the raw scan must not false-block ordinary file content.
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/files"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "file_ok"})))
        .expect(1)
        .mount(&mock)
        .await;

    let mut state = AppState::new("http://127.0.0.1:1".to_string(), mock.uri());
    state.security = std::sync::Arc::new(SecurityEngine::new(Ruleset {
        detect_egress: true,
        ..Ruleset::default()
    }));
    let proxy = spawn_proxy(state).await;

    let boundary = "----burnwalltestboundary";
    let body = format!(
        "--{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"notes.txt\"\r\nContent-Type: text/plain\r\n\r\njust ordinary meeting notes\r\n--{b}--\r\n",
        b = boundary
    );

    let resp = client()
        .post(format!("http://{}/openai/v1/files", proxy))
        .header(
            "content-type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(body)
        .send()
        .await
        .expect("proxy POST");

    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(json["id"], "file_ok");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn billing_flip_alerts_but_never_blocks() {
    // #11: a session seen first as subscription (Anthropic OAuth bearer) then
    // as metered (x-api-key) must NOT be blocked on either request — the
    // watchdog is alert-only. Both requests reach the upstream and return 200.
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "msg_x", "type": "message", "role": "assistant",
            "content": [{"type": "text", "text": "ok"}],
            "model": "claude-sonnet-4-6",
            "usage": {"input_tokens": 1, "output_tokens": 1}
        })))
        .expect(2)
        .mount(&mock)
        .await;

    let state = AppState::new(mock.uri(), "http://127.0.0.1:1".to_string());
    let proxy = spawn_proxy(state).await;

    let session = format!("flip-{}", std::process::id());

    // 1) Subscription request: OAuth bearer of the sk-ant-oat shape.
    let sub_bearer = format!("Bearer sk-ant-oat{}", "01-fake-subscription-token");
    let r1 = client()
        .post(format!("http://{}/anthropic/v1/messages", proxy))
        .header("authorization", sub_bearer)
        .header("x-burnwall-session", &session)
        .json(&json!({"model": "claude-sonnet-4-6", "max_tokens": 1}))
        .send()
        .await
        .expect("sub POST");
    assert_eq!(r1.status(), 200, "subscription request must not block");

    // 2) Metered request on the SAME session: x-api-key present → the flip.
    let r2 = client()
        .post(format!("http://{}/anthropic/v1/messages", proxy))
        .header("x-api-key", "test-metered-key")
        .header("x-burnwall-session", &session)
        .json(&json!({"model": "claude-sonnet-4-6", "max_tokens": 1}))
        .send()
        .await
        .expect("metered POST");
    assert_eq!(r2.status(), 200, "the billing flip must not block");
}

/// Build a budget config with the given daily/hourly caps and a fallback model,
/// metered-or-plan enforcement, used by the #2 / #18 handler tests.
fn budget_config(
    daily: f64,
    per_hour: f64,
    enforce_on_plan: bool,
    fallback_model: &str,
) -> burnwall::budget::BudgetConfig {
    burnwall::budget::BudgetConfig {
        daily_usd: daily,
        monthly_usd: 0.0,
        warn_percent: 80,
        per_session_usd: 0.0,
        per_hour_usd: per_hour,
        enforce_on_plan,
        fallback_model: fallback_model.to_string(),
    }
}

// ─────────────────── #2 hourly brake (emergency brake) ───────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hourly_cap_blocks_metered_when_exceeded() {
    // A metered request (x-api-key) over an already-exceeded hourly ceiling is
    // 429'd with the new `hourly_budget_exceeded` block kind, before upstream.
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .expect(0) // the block must short-circuit before upstream
        .mount(&mock)
        .await;

    let mut state = AppState::new(mock.uri(), "http://127.0.0.1:1".to_string());
    let budget = burnwall::budget::BudgetTracker::new(budget_config(0.0, 1.0, false, ""));
    budget.record(2.0); // rolling hour already $2 > $1 ceiling
    state.budget = std::sync::Arc::new(budget);
    let proxy = spawn_proxy(state).await;

    let resp = {
        let _guard = ENV_LOCK.lock().await;
        client()
            .post(format!("http://{}/anthropic/v1/messages", proxy))
            .header("x-api-key", "metered-key")
            .json(&json!({"model": "claude-sonnet-4-6", "max_tokens": 1}))
            .send()
            .await
            .expect("proxy POST")
    };

    assert_eq!(resp.status(), 429);
    assert_eq!(
        resp.headers()
            .get("x-burnwall-blocked")
            .and_then(|v| v.to_str().ok()),
        Some("hourly_budget_exceeded")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hourly_cap_does_not_block_plan_traffic() {
    // The same over-cap state, but a subscription (sk-ant-oat bearer) with
    // enforce_on_plan = false: notional dollars, so the brake must NOT block.
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "m", "type": "message", "role": "assistant",
            "content": [{"type": "text", "text": "ok"}],
            "model": "claude-sonnet-4-6",
            "usage": {"input_tokens": 1, "output_tokens": 1}
        })))
        .expect(1)
        .mount(&mock)
        .await;

    let mut state = AppState::new(mock.uri(), "http://127.0.0.1:1".to_string());
    let budget = burnwall::budget::BudgetTracker::new(budget_config(0.0, 1.0, false, ""));
    budget.record(5.0); // way over the $1 ceiling
    state.budget = std::sync::Arc::new(budget);
    let proxy = spawn_proxy(state).await;

    let bearer = format!("Bearer sk-ant-oat{}", "01-fake-plan-token");
    let resp = client()
        .post(format!("http://{}/anthropic/v1/messages", proxy))
        .header("authorization", bearer)
        .json(&json!({"model": "claude-sonnet-4-6", "max_tokens": 1}))
        .send()
        .await
        .expect("proxy POST");

    assert_eq!(
        resp.status(),
        200,
        "plan traffic must not be blocked on a notional hourly cap"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hourly_cap_off_by_default_does_not_block() {
    // per_hour = 0 (the default) → the brake is disarmed; even huge spend flows.
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "m", "type": "message", "role": "assistant",
            "content": [{"type": "text", "text": "ok"}],
            "model": "claude-sonnet-4-6",
            "usage": {"input_tokens": 1, "output_tokens": 1}
        })))
        .expect(1)
        .mount(&mock)
        .await;

    let mut state = AppState::new(mock.uri(), "http://127.0.0.1:1".to_string());
    let budget = burnwall::budget::BudgetTracker::new(budget_config(0.0, 0.0, false, ""));
    budget.record(1_000.0); // huge spend, but the brake is off
    state.budget = std::sync::Arc::new(budget);
    let proxy = spawn_proxy(state).await;

    let resp = client()
        .post(format!("http://{}/anthropic/v1/messages", proxy))
        .header("x-api-key", "metered-key")
        .json(&json!({"model": "claude-sonnet-4-6", "max_tokens": 1}))
        .send()
        .await
        .expect("proxy POST");

    assert_eq!(resp.status(), 200, "a disarmed hourly brake must not block");
}

// ─────────────────── #18 budget → cheaper-model fallback ───────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn over_cap_request_is_rewritten_to_fallback_model_not_blocked() {
    // With a fallback model set and the daily cap exceeded on metered traffic,
    // the request must be FORWARDED with its `model` rewritten to the fallback —
    // not 429'd. The upstream asserts it received the downgraded model.
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        // The proof: upstream only matches when the model was rewritten.
        .and(body_json(json!({
            "model": "claude-haiku-4-5",
            "max_tokens": 1
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "m", "type": "message", "role": "assistant",
            "content": [{"type": "text", "text": "ok"}],
            "model": "claude-haiku-4-5",
            "usage": {"input_tokens": 1, "output_tokens": 1}
        })))
        .expect(1)
        .mount(&mock)
        .await;

    let mut state = AppState::new(mock.uri(), "http://127.0.0.1:1".to_string());
    // Daily cap $1, already $5 spent → exceeded; fallback to haiku.
    let budget =
        burnwall::budget::BudgetTracker::new(budget_config(1.0, 0.0, false, "claude-haiku-4-5"));
    budget.record(5.0);
    state.budget = std::sync::Arc::new(budget);
    let proxy = spawn_proxy(state).await;

    let resp = {
        let _guard = ENV_LOCK.lock().await;
        client()
            .post(format!("http://{}/anthropic/v1/messages", proxy))
            .header("x-api-key", "metered-key")
            // Original model is the expensive opus — should be rewritten.
            .json(&json!({"model": "claude-opus-4-7", "max_tokens": 1}))
            .send()
            .await
            .expect("proxy POST")
    };

    assert_eq!(
        resp.status(),
        200,
        "over-cap request with a fallback must be forwarded, not blocked"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn over_cap_request_blocks_without_fallback_model() {
    // Same over-cap state, but no fallback model configured → 429 as before.
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .expect(0)
        .mount(&mock)
        .await;

    let mut state = AppState::new(mock.uri(), "http://127.0.0.1:1".to_string());
    let budget = burnwall::budget::BudgetTracker::new(budget_config(1.0, 0.0, false, ""));
    budget.record(5.0);
    state.budget = std::sync::Arc::new(budget);
    let proxy = spawn_proxy(state).await;

    let resp = {
        let _guard = ENV_LOCK.lock().await;
        client()
            .post(format!("http://{}/anthropic/v1/messages", proxy))
            .header("x-api-key", "metered-key")
            .json(&json!({"model": "claude-opus-4-7", "max_tokens": 1}))
            .send()
            .await
            .expect("proxy POST")
    };

    assert_eq!(resp.status(), 429);
    assert_eq!(
        resp.headers()
            .get("x-burnwall-blocked")
            .and_then(|v| v.to_str().ok()),
        Some("budget_exceeded")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn over_cap_non_json_body_falls_back_to_block_even_with_fallback() {
    // Fallback is set, the cap is exceeded, but the body isn't JSON (can't
    // safely rewrite the model) → the proxy must BLOCK rather than forward an
    // over-budget request unchanged. A plain-text body to /v1/messages.
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .expect(0)
        .mount(&mock)
        .await;

    let mut state = AppState::new(mock.uri(), "http://127.0.0.1:1".to_string());
    let budget =
        burnwall::budget::BudgetTracker::new(budget_config(1.0, 0.0, false, "claude-haiku-4-5"));
    budget.record(5.0);
    state.budget = std::sync::Arc::new(budget);
    let proxy = spawn_proxy(state).await;

    let resp = {
        let _guard = ENV_LOCK.lock().await;
        client()
            .post(format!("http://{}/anthropic/v1/messages", proxy))
            .header("content-type", "text/plain")
            .body("this is not json and has no model field")
            .send()
            .await
            .expect("proxy POST")
    };

    assert_eq!(
        resp.status(),
        429,
        "an un-rewritable over-cap body must block, never forward unchanged"
    );
    assert_eq!(
        resp.headers()
            .get("x-burnwall-blocked")
            .and_then(|v| v.to_str().ok()),
        Some("budget_exceeded")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn does_not_route_anthropicfoo_to_anthropic() {
    // Prefix must be followed by `/` or end-of-path. `/anthropicfoo` is not
    // an Anthropic route.
    let state = AppState::with_defaults();
    let proxy = spawn_proxy(state).await;

    let resp = client()
        .get(format!("http://{}/anthropicfoo", proxy))
        .send()
        .await
        .expect("proxy GET");

    assert_eq!(resp.status(), 404);
}
