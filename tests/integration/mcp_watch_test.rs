//! End-to-end tests for `burnwall mcp-watch`: spin up the watcher in
//! front of a `wiremock` upstream, POST JSON-RPC frames, and assert that
//! tools/call invocations are persisted to `mcp_events` while other
//! request shapes pass through silently.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use burnwall::mcp::{parse_tool_call, serve_with_shutdown, ToolCall, WatchState};
use burnwall::security::SecurityEngine;
use burnwall::storage::Storage;
use serde_json::json;
use tokio::net::TcpListener;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn spawn_watcher(state: WatchState) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve_with_shutdown(listener, Arc::new(state), std::future::pending::<()>()).await;
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
    chrono::Local::now().format("%Y-%m-%d").to_string()
}

#[test]
fn parse_tool_call_extracts_name_and_id() {
    let body = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "src/lib.rs"}},
        "id": 42,
    }))
    .unwrap();
    let parsed = parse_tool_call(&body);
    assert_eq!(
        parsed,
        Some(ToolCall {
            name: "read_file".to_string(),
            id: Some("42".to_string()),
        }),
    );
}

#[test]
fn parse_tool_call_returns_none_for_other_methods() {
    let body = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {"protocolVersion": "2024-11-05"},
        "id": 1,
    }))
    .unwrap();
    assert!(parse_tool_call(&body).is_none());
}

#[test]
fn parse_tool_call_handles_notifications_without_id() {
    let body = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {"name": "broadcast"},
    }))
    .unwrap();
    let parsed = parse_tool_call(&body).unwrap();
    assert_eq!(parsed.name, "broadcast");
    assert!(parsed.id.is_none());
}

#[test]
fn parse_tool_call_ignores_invalid_json() {
    assert!(parse_tool_call(b"not json").is_none());
    assert!(parse_tool_call(b"").is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tools_call_is_forwarded_and_logged_with_upstream_status() {
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"jsonrpc": "2.0", "id": 1, "result": "ok"})),
        )
        .mount(&upstream)
        .await;

    let storage = Arc::new(Storage::open_in_memory().unwrap());
    let state = WatchState {
        upstream: upstream.uri(),
        http_client: reqwest::Client::new(),
        storage: storage.clone(),
        security: Arc::new(SecurityEngine::with_defaults()),
    };
    let addr = spawn_watcher(state).await;

    let resp = client()
        .post(format!("http://{}/messages", addr))
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "X"}},
            "id": 1,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["result"], "ok");

    let events = storage.mcp_events_for_date(&today()).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].tool_name, "read_file");
    assert_eq!(events[0].rpc_id.as_deref(), Some("1"));
    assert_eq!(events[0].upstream_status, 200);
    let upstream_uri = events[0].upstream_uri.as_deref().unwrap();
    assert!(
        upstream_uri.starts_with(&upstream.uri()),
        "got {upstream_uri}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_tool_call_methods_pass_through_without_recording() {
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"jsonrpc": "2.0", "id": 1, "result": {}})),
        )
        .mount(&upstream)
        .await;

    let storage = Arc::new(Storage::open_in_memory().unwrap());
    let state = WatchState {
        upstream: upstream.uri(),
        http_client: reqwest::Client::new(),
        storage: storage.clone(),
        security: Arc::new(SecurityEngine::with_defaults()),
    };
    let addr = spawn_watcher(state).await;

    let resp = client()
        .post(format!("http://{}/messages", addr))
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05"},
            "id": 1,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let _ = resp.bytes().await;

    let events = storage.mcp_events_for_date(&today()).unwrap();
    assert!(events.is_empty(), "no events expected; got {events:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstream_failure_still_records_tool_call_with_status_zero() {
    // Bind to a port we never serve, so the forward fails immediately.
    let dead_upstream = "http://127.0.0.1:1";

    let storage = Arc::new(Storage::open_in_memory().unwrap());
    let state = WatchState {
        upstream: dead_upstream.to_string(),
        http_client: reqwest::Client::builder()
            .timeout(Duration::from_millis(300))
            .build()
            .unwrap(),
        storage: storage.clone(),
        security: Arc::new(SecurityEngine::with_defaults()),
    };
    let addr = spawn_watcher(state).await;

    let resp = client()
        .post(format!("http://{}/messages", addr))
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "list_dir"},
            "id": "abc",
        }))
        .send()
        .await
        .unwrap();
    // Watcher converts the upstream failure into a 502 to the client.
    assert_eq!(resp.status(), 502);

    let events = storage.mcp_events_for_date(&today()).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].tool_name, "list_dir");
    assert_eq!(events[0].rpc_id.as_deref(), Some("abc"));
    assert_eq!(events[0].upstream_status, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstream_path_and_query_are_preserved() {
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(wiremock::matchers::path("/mcp/rpc"))
        .and(wiremock::matchers::query_param("server", "fs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .expect(1)
        .mount(&upstream)
        .await;

    let storage = Arc::new(Storage::open_in_memory().unwrap());
    let state = WatchState {
        upstream: upstream.uri(),
        http_client: reqwest::Client::new(),
        storage: storage.clone(),
        security: Arc::new(SecurityEngine::with_defaults()),
    };
    let addr = spawn_watcher(state).await;

    let resp = client()
        .post(format!("http://{}/mcp/rpc?server=fs", addr))
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": 7,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    // Drain so any spawned task running on the connection is unblocked.
    let _ = resp.bytes().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tools_call_with_denied_path_in_arguments_returns_403_and_never_forwards() {
    // Upstream should never be hit — the scan blocks before forward.
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&upstream)
        .await;

    let storage = Arc::new(Storage::open_in_memory().unwrap());
    let state = WatchState {
        upstream: upstream.uri(),
        http_client: reqwest::Client::new(),
        storage: storage.clone(),
        security: Arc::new(SecurityEngine::with_defaults()),
    };
    let addr = spawn_watcher(state).await;

    let resp = client()
        .post(format!("http://{}/mcp/rpc", addr))
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {"path": "~/.ssh/id_rsa"},
            },
            "id": 11,
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["type"], "security_blocked");

    // No mcp_events row (we only log forwarded tool calls).
    let events = storage.mcp_events_for_date(&today()).unwrap();
    assert!(
        events.is_empty(),
        "blocked call should not appear in mcp_events"
    );

    // A security_events row was inserted with provider=mcp + tool name.
    let sec = storage.security_events_for_date(&today()).unwrap();
    assert_eq!(sec.len(), 1);
    assert_eq!(sec[0].event_type, "path_blocked");
    assert_eq!(sec[0].provider.as_deref(), Some("mcp"));
    assert_eq!(sec[0].model.as_deref(), Some("read_file"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn denied_command_in_tool_arguments_is_blocked() {
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&upstream)
        .await;

    let storage = Arc::new(Storage::open_in_memory().unwrap());
    let state = WatchState {
        upstream: upstream.uri(),
        http_client: reqwest::Client::new(),
        storage: storage.clone(),
        security: Arc::new(SecurityEngine::with_defaults()),
    };
    let addr = spawn_watcher(state).await;

    let resp = client()
        .post(format!("http://{}/mcp/rpc", addr))
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "bash", "arguments": {"command": "rm -rf /"}},
            "id": 12,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    let sec = storage.security_events_for_date(&today()).unwrap();
    assert_eq!(sec.len(), 1);
    assert_eq!(sec[0].event_type, "command_blocked");
    assert_eq!(sec[0].provider.as_deref(), Some("mcp"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn secret_pattern_in_tool_arguments_is_blocked() {
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&upstream)
        .await;

    let storage = Arc::new(Storage::open_in_memory().unwrap());
    let state = WatchState {
        upstream: upstream.uri(),
        http_client: reqwest::Client::new(),
        storage: storage.clone(),
        security: Arc::new(SecurityEngine::with_defaults()),
    };
    let addr = spawn_watcher(state).await;

    let resp = client()
        .post(format!("http://{}/mcp/rpc", addr))
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "upload",
                "arguments": {"body": "AKIAIOSFODNN7EXAMPLE"},
            },
            "id": 13,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    let sec = storage.security_events_for_date(&today()).unwrap();
    assert_eq!(sec.len(), 1);
    assert_eq!(sec[0].event_type, "secret_detected");
}
