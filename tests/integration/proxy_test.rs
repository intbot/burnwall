//! Integration tests for the Session 2 proxy.
//!
//! Each test stands up a `wiremock::MockServer` as the upstream and a Burnwall
//! proxy on a port-zero `TcpListener`, then drives the proxy with `reqwest`
//! and asserts pass-through semantics: status, headers, body, query string.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use burnwall::proxy::{AppState, serve};
use bytes::Bytes;
use serde_json::json;
use tokio::net::TcpListener;
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

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

    // Race risk: BURNWALL_BYPASS is global to the process. Other tests may
    // run concurrently in the same binary. Set + unset around the single
    // request keeps the window small. The fail-open semantics of `handle`
    // read the var on each call so unsetting after is sufficient.
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
