//! Torture-proxy suite (P0): adversarial upstream behaviour the wiremock
//! happy-path tests can't express — SSE split across tiny TCP frames, an
//! upstream that accepts then stalls forever, and a client that disconnects
//! mid-stream. These exercise the streaming tee and the new timeout/keepalive
//! and disconnect-cancel paths (P-C1/P-C2) that earlier idealized tests missed.
//!
//! The fake upstream is a raw `tokio::net::TcpListener` (not wiremock) so we
//! control flush boundaries and can stall a live socket. Every case is wrapped
//! in `tokio::time::timeout` so a regression *hangs the test deadline* rather
//! than the whole suite.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use burnwall::budget::{BudgetTracker, LoopDetector};
use burnwall::proxy::{AppState, serve};
use burnwall::security::SecurityEngine;
use burnwall::storage::Storage;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A realistic Anthropic SSE response: input/cache tokens in `message_start`,
/// output tokens in `message_delta`.
const SSE: &str = "event: message_start\n\
data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_x\",\"model\":\"claude-haiku-4-5\",\"usage\":{\"input_tokens\":2000,\"cache_creation_input_tokens\":0,\"cache_read_input_tokens\":500,\"output_tokens\":0}}}\n\
\n\
event: message_delta\n\
data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":300}}\n\
\n\
event: message_stop\n\
data: {\"type\":\"message_stop\"}\n\n";

fn today() -> String {
    chrono::Local::now().format("%Y-%m-%d").to_string()
}

/// Build an `AppState` pointed at `upstream`, with a caller-supplied HTTP
/// client (so a test can set a short read_timeout to exercise stall recovery).
fn state_for(upstream: String, storage: Arc<Storage>, client: reqwest::Client) -> AppState {
    AppState {
        upstream_anthropic: upstream,
        upstream_openai: "http://127.0.0.1:1".to_string(),
        upstream_google: "http://127.0.0.1:1".to_string(),
        http_client: client,
        security: Arc::new(SecurityEngine::with_defaults()),
        budget: Arc::new(BudgetTracker::with_defaults()),
        loop_detector: Arc::new(LoopDetector::with_defaults()),
        storage,
        cache_injection: false,
        resilience: Default::default(),
        #[cfg(feature = "observe")]
        otel: None,
        pause_path: None,
    }
}

async fn spawn_proxy(state: AppState) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve(listener, Arc::new(state)).await;
    });
    addr
}

/// Read past the end of an HTTP request's headers on `sock` (we don't care
/// about the body for these tests — the proxy has already sent it).
async fn drain_request_headers(sock: &mut tokio::net::TcpStream) {
    let mut buf = [0u8; 4096];
    // One read is enough to get the headers for our small POSTs; we just need
    // the upstream to have accepted and consumed enough to reply.
    let _ = sock.read(&mut buf).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sse_split_across_tiny_frames_round_trips_and_records() {
    // The tee must reassemble a stream delivered one byte at a time: the client
    // gets the exact bytes, and usage is parsed from the reassembled body.
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up_addr = upstream.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut sock, _) = upstream.accept().await.unwrap();
        drain_request_headers(&mut sock).await;
        let header = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\n\r\n",
            SSE.len()
        );
        sock.write_all(header.as_bytes()).await.unwrap();
        // One byte per write, each flushed — maximally adversarial framing.
        for b in SSE.as_bytes() {
            sock.write_all(&[*b]).await.unwrap();
            sock.flush().await.unwrap();
        }
        sock.shutdown().await.ok();
    });

    let storage = Arc::new(Storage::open_in_memory().unwrap());
    let state = state_for(
        format!("http://{up_addr}"),
        storage.clone(),
        reqwest::Client::new(),
    );
    let addr = spawn_proxy(state).await;

    let body = tokio::time::timeout(Duration::from_secs(10), async {
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/anthropic/v1/messages"))
            .json(&json!({"model": "claude-haiku-4-5", "stream": true}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        resp.bytes().await.unwrap()
    })
    .await
    .expect("byte-at-a-time stream must not hang");

    assert_eq!(
        body.as_ref(),
        SSE.as_bytes(),
        "stream must round-trip intact"
    );

    tokio::time::sleep(Duration::from_millis(250)).await;
    let rows = storage.requests_for_date(&today()).unwrap();
    assert_eq!(
        rows.len(),
        1,
        "the reassembled stream should record one row"
    );
    assert!(rows[0].cost_usd > 0.0, "usage parsed from reassembled body");
    assert_eq!(rows[0].input_tokens, 2000);
    assert_eq!(rows[0].output_tokens, 300);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upstream_that_stalls_forever_is_bounded_by_read_timeout() {
    // P-C1: an upstream that sends headers + a partial body then goes silent
    // must NOT hang the proxy/client forever. With a short read_timeout the
    // socket is reclaimed; without the fix this test's deadline would trip.
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up_addr = upstream.local_addr().unwrap();
    let _server = tokio::spawn(async move {
        let (mut sock, _) = upstream.accept().await.unwrap();
        drain_request_headers(&mut sock).await;
        // Claim a long body, send a sliver, then stall indefinitely.
        sock.write_all(
            b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: 100000\r\n\r\nevent: ping\n",
        )
        .await
        .unwrap();
        sock.flush().await.unwrap();
        // Never write the rest. Hold the socket open.
        tokio::time::sleep(Duration::from_secs(120)).await;
    });

    let storage = Arc::new(Storage::open_in_memory().unwrap());
    // Short read_timeout stands in for the production 600s backstop so the test
    // resolves quickly — the point is that a stalled read is reclaimed at all.
    let stall_client = reqwest::Client::builder()
        .read_timeout(Duration::from_millis(800))
        .build()
        .unwrap();
    let state = state_for(format!("http://{up_addr}"), storage.clone(), stall_client);
    let addr = spawn_proxy(state).await;

    // The whole exchange must finish well inside the deadline: the client gets
    // headers (200) then the body stream errors out when the upstream read
    // times out. Either way it must not hang.
    let outcome = tokio::time::timeout(Duration::from_secs(8), async {
        let resp = reqwest::Client::builder()
            .build()
            .unwrap()
            .post(format!("http://{addr}/anthropic/v1/messages"))
            .json(&json!({"model": "claude-haiku-4-5", "stream": true}))
            .send()
            .await;
        // Read the (truncated) body to completion or error.
        if let Ok(r) = resp {
            let _ = r.bytes().await;
        }
    })
    .await;

    assert!(
        outcome.is_ok(),
        "a stalled upstream must be bounded by read_timeout, not hang"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_disconnect_midstream_does_not_hang_the_proxy() {
    // P-C2: when the client drops mid-stream, the tee stops draining and the
    // proxy stays responsive. We assert the proxy serves a *subsequent* request
    // fine after a client abandoned a prior streaming response.
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up_addr = upstream.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = upstream.accept().await else {
                break;
            };
            tokio::spawn(async move {
                drain_request_headers(&mut sock).await;
                let header = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\n\r\n",
                    SSE.len()
                );
                let _ = sock.write_all(header.as_bytes()).await;
                // Trickle the body slowly so the client can disconnect mid-way.
                for chunk in SSE.as_bytes().chunks(8) {
                    if sock.write_all(chunk).await.is_err() {
                        break;
                    }
                    let _ = sock.flush().await;
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                let _ = sock.shutdown().await;
            });
        }
    });

    let storage = Arc::new(Storage::open_in_memory().unwrap());
    let state = state_for(
        format!("http://{up_addr}"),
        storage.clone(),
        reqwest::Client::new(),
    );
    let addr = spawn_proxy(state).await;

    // First request: start streaming, then drop the response without reading it
    // all (simulates the user pressing Esc).
    {
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/anthropic/v1/messages"))
            .json(&json!({"model": "claude-haiku-4-5", "stream": true}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        drop(resp); // abandon mid-stream
    }

    // Second request must still be served promptly — the proxy isn't wedged.
    let ok = tokio::time::timeout(Duration::from_secs(8), async {
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/anthropic/v1/messages"))
            .json(&json!({"model": "claude-haiku-4-5", "stream": true}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let _ = resp.bytes().await;
    })
    .await;
    assert!(
        ok.is_ok(),
        "proxy must stay responsive after a client disconnect"
    );
}
