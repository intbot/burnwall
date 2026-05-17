//! MCP (Model Context Protocol) pass-through watcher — phase 1 of
//! `burnwall mcp-watch`.
//!
//! Listens on a local port and forwards every HTTP request to a single
//! upstream MCP server. For each POST whose body parses as a JSON-RPC
//! `tools/call`, a row is inserted into `mcp_events` with the tool name,
//! request id, and upstream HTTP status. Other request shapes pass
//! through silently — we never block, never modify the request body,
//! and never store argument payloads (those can contain prompt content).

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::BodyExt as _;
use hyper::body::Incoming;
use hyper::http::{HeaderMap, HeaderName, HeaderValue, Method};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use serde_json::Value;
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};

use crate::proxy::streaming::{self, ProxyBody};
use crate::security::SecurityEngine;
use crate::storage::{McpEvent, SecurityEvent, Storage};

#[derive(Clone)]
pub struct WatchState {
    pub upstream: String,
    pub http_client: reqwest::Client,
    pub storage: Arc<Storage>,
    /// Same engine as the LLM proxy uses. Applied to every MCP request
    /// body so the path / command / mount / secret denylist also covers
    /// `tools/call` arguments. A violation returns 403, writes a
    /// `security_events` row, and never forwards.
    pub security: Arc<SecurityEngine>,
}

/// Parsed JSON-RPC `tools/call` request, captured for the event log.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolCall {
    pub name: String,
    /// JSON-RPC id, stringified. Notifications (no id) become `None`.
    pub id: Option<String>,
}

/// Inspect a JSON-RPC body and return the tool name + request id if the
/// method is `tools/call`. Returns `None` for any non-`tools/call`
/// message, malformed JSON, or batch requests (we only log the simple
/// single-call case in phase 1).
pub fn parse_tool_call(body: &[u8]) -> Option<ToolCall> {
    let v: Value = serde_json::from_slice(body).ok()?;
    let method = v.get("method").and_then(Value::as_str)?;
    if method != "tools/call" {
        return None;
    }
    let name = v
        .get("params")
        .and_then(|p| p.get("name"))
        .and_then(Value::as_str)?
        .to_string();
    let id = v.get("id").and_then(|x| match x {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Null => None,
        _ => None,
    });
    Some(ToolCall { name, id })
}

/// Bind `addr` and forward all traffic to `upstream` until cancelled.
pub async fn run(addr: SocketAddr, state: WatchState) -> std::io::Result<()> {
    run_with_shutdown(addr, state, std::future::pending::<()>()).await
}

/// Bind `addr` and forward until `shutdown` resolves.
pub async fn run_with_shutdown(
    addr: SocketAddr,
    state: WatchState,
    shutdown: impl std::future::Future<Output = ()>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    info!("Burnwall mcp-watch listening on http://{}", bound);
    info!("  forwarding all requests to {}", state.upstream);
    serve_with_shutdown(listener, Arc::new(state), shutdown).await
}

/// Run the accept loop on a caller-supplied listener until `shutdown`
/// resolves. Tests bind port 0 and use this entry point.
pub async fn serve_with_shutdown(
    listener: TcpListener,
    state: Arc<WatchState>,
    shutdown: impl std::future::Future<Output = ()>,
) -> std::io::Result<()> {
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                let io = TokioIo::new(stream);
                let state = state.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |req: Request<Incoming>| {
                        let state = state.clone();
                        async move { handle(req, state).await }
                    });
                    if let Err(e) = Builder::new(TokioExecutor::new())
                        .serve_connection(io, service)
                        .await
                    {
                        error!("mcp-watch connection error from {}: {}", peer, e);
                    }
                });
            }
            _ = &mut shutdown => {
                info!("mcp-watch shutdown signal received");
                return Ok(());
            }
        }
    }
}

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
];

fn is_hop_by_hop(name: &str) -> bool {
    HOP_BY_HOP.iter().any(|h| name.eq_ignore_ascii_case(h))
}

async fn handle(
    req: Request<Incoming>,
    state: Arc<WatchState>,
) -> Result<Response<ProxyBody>, Infallible> {
    let method = req.method().clone();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/")
        .to_string();
    let upstream_uri = format!("{}{}", state.upstream.trim_end_matches('/'), path_and_query);

    let (parts, body) = req.into_parts();
    let body_bytes = match body.collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => {
            warn!("mcp-watch: body read failed: {}", e);
            return Ok(error_response(StatusCode::BAD_REQUEST, "read_failed"));
        }
    };

    // Parse JSON-RPC body up front — we'll log after the forward so the
    // recorded `upstream_status` matches what the client actually got.
    let tool_call = if method == Method::POST {
        parse_tool_call(&body_bytes)
    } else {
        None
    };

    // Security scan: the same engine the LLM proxy uses, applied to the
    // raw JSON-RPC body. Walks every string leaf — that means `tools/call`
    // arguments get the path / command / mount / secret denylist for free.
    // A violation returns 403 and never forwards (mirrors the LLM proxy's
    // 403 path); the `security_events` row gets `provider="mcp"` and the
    // tool name when we have one, so `burnwall security` shows the source.
    if let Some(violation) = state.security.scan(&body_bytes) {
        warn!("🛡️ MCP BLOCKED: {}", violation.message());
        let redact = state.security.rules().log_redact_details;
        let stored_details = if redact {
            "<redacted>".to_string()
        } else {
            violation.matched.clone()
        };
        let tool_label = tool_call
            .as_ref()
            .map(|c| c.name.clone())
            .unwrap_or_else(|| "unknown".to_string());
        let event = SecurityEvent::new(violation.kind.event_type(), &stored_details)
            .with_provider("mcp", &tool_label);
        if let Err(e) = state.storage.insert_security_event(&event) {
            error!("mcp security_event insert failed: {}", e);
        }
        return Ok(error_response(StatusCode::FORBIDDEN, "security_blocked"));
    }

    let mut outbound_headers = HeaderMap::new();
    for (name, value) in parts.headers.iter() {
        if !is_hop_by_hop(name.as_str()) {
            outbound_headers.append(name.clone(), value.clone());
        }
    }

    let mut builder = state
        .http_client
        .request(method.clone(), &upstream_uri)
        .headers(outbound_headers);
    if !body_bytes.is_empty() {
        builder = builder.body(body_bytes);
    }

    let upstream_resp = match builder.send().await {
        Ok(r) => r,
        Err(e) => {
            warn!("mcp-watch upstream error for {}: {}", upstream_uri, e);
            // We still record the tool_call attempt with status 0 so
            // operators can spot upstream connectivity issues in the log.
            if let Some(call) = tool_call {
                let event = McpEvent::new(&call.name, call.id.as_deref(), 0)
                    .with_upstream_uri(&upstream_uri);
                if let Err(e) = state.storage.insert_mcp_event(&event) {
                    error!("mcp_event insert failed: {}", e);
                }
            }
            return Ok(error_response(StatusCode::BAD_GATEWAY, "upstream_error"));
        }
    };

    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();
    debug!("mcp-watch ← {} {}", status.as_u16(), upstream_uri);

    if let Some(call) = tool_call {
        let event = McpEvent::new(&call.name, call.id.as_deref(), status.as_u16() as i64)
            .with_upstream_uri(&upstream_uri);
        if let Err(e) = state.storage.insert_mcp_event(&event) {
            error!("mcp_event insert failed: {}", e);
        }
    }

    let body = streaming::from_stream(upstream_resp.bytes_stream());
    let mut response = Response::builder().status(status.as_u16());
    let headers_mut = response
        .headers_mut()
        .expect("Response::builder is valid prior to .body()");
    for (name, value) in resp_headers.iter() {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        if let (Ok(hn), Ok(hv)) = (
            HeaderName::from_bytes(name.as_str().as_bytes()),
            HeaderValue::from_bytes(value.as_bytes()),
        ) {
            headers_mut.append(hn, hv);
        }
    }
    Ok(response.body(body).expect("response: build failed"))
}

fn error_response(status: StatusCode, kind: &str) -> Response<ProxyBody> {
    let body = format!(r#"{{"error":{{"type":"{}"}}}}"#, kind);
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(streaming::full(Bytes::from(body)))
        .expect("error_response: response builder failed")
}
