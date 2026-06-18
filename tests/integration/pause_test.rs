//! End-to-end tests for the runtime protection pause (`burnwall pause` /
//! `resume` / `allow-once`).
//!
//! Lives in its own test binary, NOT in `proxy_test.rs`: that binary's
//! `bypass_skips_security_scan` flips the process-global `BURNWALL_BYPASS` env
//! var around its request, and a pause-test request landing inside that window
//! would take the env-bypass path without consuming the allow-once file —
//! a flaky cross-test race no assertion can tolerate. Separate binary =
//! separate process = separate environment.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use burnwall::proxy::{AppState, serve};
use serde_json::json;
use tokio::net::TcpListener;
use wiremock::matchers::{method, path};
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

/// A request body whose in-flight tool round trips the path scan — blocked by
/// the default ruleset unless protection is paused.
fn violating_body() -> serde_json::Value {
    json!({
        "model": "claude-sonnet-4-6",
        "messages": [{
            "role": "assistant",
            "content": [{
                "type": "tool_use", "id": "t1", "name": "bash",
                "input": {"command": "cat ~/.ssh/id_rsa"}
            }]
        }]
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pause_file_relays_unchecked_and_resume_restores() {
    // The live escape hatch: `burnwall pause` writes a state file the RUNNING
    // daemon picks up per request — no restart of anything. (The env-var
    // bypass is frozen at daemon spawn, so for a backgrounded daemon it never
    // was a usable remediation.)
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .expect(1) // exactly the paused request lands upstream
        .mount(&mock)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let pause_path = dir.path().join("pause.json");
    let mut state = AppState::new(mock.uri(), "http://127.0.0.1:1".to_string());
    state.pause_path = Some(pause_path.clone());
    let proxy = spawn_proxy(state).await;
    let url = format!("http://{}/anthropic/v1/messages", proxy);

    // 1. Protected: the violating request is blocked, and the block message
    //    advertises the runtime toggles that actually work live.
    let resp = client()
        .post(&url)
        .json(&violating_body())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("burnwall allow-once"),
        "remedies advertise allow-once: {body}"
    );
    assert!(
        body.contains("burnwall pause"),
        "remedies advertise pause: {body}"
    );
    assert!(
        !body.contains("BURNWALL_BYPASS"),
        "dead env-var advice removed: {body}"
    );

    // 2. Pause (the exact JSON `burnwall pause` writes — pins the wire format).
    let now = chrono::Utc::now().timestamp();
    std::fs::write(
        &pause_path,
        format!(r#"{{"mode":"pause","expires_at":{}}}"#, now + 60),
    )
    .unwrap();
    let resp = client()
        .post(&url)
        .json(&violating_body())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "paused proxy must relay unchecked");

    // 3. Resume (`burnwall resume` deletes the file) → protected again.
    std::fs::remove_file(&pause_path).unwrap();
    let resp = client()
        .post(&url)
        .json(&violating_body())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "resume must restore protection");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drain_file_relays_unchecked_so_a_soft_stop_never_wedges_a_tool() {
    // A soft `burnwall stop` leaves the proxy up in drain (relay-only) mode so
    // an already-running tool keeps working instead of hitting a dead port.
    // The handler must honor the `drain` state exactly like a pause: relay
    // unchecked. Clearing it (a fresh `start` / idle-retire) restores guarding.
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .expect(1) // exactly the drained request lands upstream
        .mount(&mock)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let pause_path = dir.path().join("pause.json");
    let mut state = AppState::new(mock.uri(), "http://127.0.0.1:1".to_string());
    state.pause_path = Some(pause_path.clone());
    let proxy = spawn_proxy(state).await;
    let url = format!("http://{}/anthropic/v1/messages", proxy);

    // Drain active (the exact JSON a soft `burnwall stop` writes) → relayed.
    let now = chrono::Utc::now().timestamp();
    std::fs::write(
        &pause_path,
        format!(r#"{{"mode":"drain","expires_at":{}}}"#, now + 3600),
    )
    .unwrap();
    let resp = client()
        .post(&url)
        .json(&violating_body())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "a draining proxy must relay unchecked");

    // Drain cleared (a fresh `start` clears it) → protection restored.
    std::fs::remove_file(&pause_path).unwrap();
    let resp = client()
        .post(&url)
        .json(&violating_body())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "clearing drain must restore protection");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn allow_once_relays_exactly_one_request() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .expect(1) // only the armed request gets through
        .mount(&mock)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let pause_path = dir.path().join("pause.json");
    let mut state = AppState::new(mock.uri(), "http://127.0.0.1:1".to_string());
    state.pause_path = Some(pause_path.clone());
    let proxy = spawn_proxy(state).await;
    let url = format!("http://{}/anthropic/v1/messages", proxy);

    // Arm allow-once (the exact JSON `burnwall allow-once` writes).
    let now = chrono::Utc::now().timestamp();
    std::fs::write(
        &pause_path,
        format!(r#"{{"mode":"allow_once","expires_at":{}}}"#, now + 600),
    )
    .unwrap();

    // First violating request: relayed unchecked, and the arm is consumed.
    let resp = client()
        .post(&url)
        .json(&violating_body())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "armed request must relay");
    assert!(!pause_path.exists(), "allow-once must be consumed on use");

    // Second identical request: protection has restored itself.
    let resp = client()
        .post(&url)
        .json(&violating_body())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "protection must auto-restore after one use"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_pause_file_does_not_bypass() {
    // The escape hatch must never outlive its window: a leftover expired file
    // (e.g. the machine slept through the pause) keeps protection ON.
    let dir = tempfile::tempdir().unwrap();
    let pause_path = dir.path().join("pause.json");
    let mut state = AppState::new(
        "http://127.0.0.1:1".to_string(),
        "http://127.0.0.1:1".to_string(),
    );
    state.pause_path = Some(pause_path.clone());
    let proxy = spawn_proxy(state).await;

    let now = chrono::Utc::now().timestamp();
    std::fs::write(
        &pause_path,
        format!(r#"{{"mode":"pause","expires_at":{}}}"#, now - 10),
    )
    .unwrap();

    let resp = client()
        .post(format!("http://{}/anthropic/v1/messages", proxy))
        .json(&violating_body())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "expired pause must not bypass");
    assert!(!pause_path.exists(), "expired file is self-cleaned");
}
