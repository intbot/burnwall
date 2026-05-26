//! MCP (Model Context Protocol) pass-through watcher — phase 1 of
//! `burnwall mcp-watch`.
//!
//! Listens on a local port and forwards every HTTP request to a single
//! upstream MCP server. For each POST whose body parses as a JSON-RPC
//! `tools/call`, a row is inserted into `mcp_events` with the tool name,
//! request id, and upstream HTTP status. Other request shapes pass
//! through silently — we never block, never modify the request body,
//! and never store argument payloads (those can contain prompt content).

pub mod firewall;

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
use crate::storage::{McpEvent, McpToolObservation, SecurityEvent, Storage};

#[derive(Clone)]
pub struct WatchState {
    /// Fallback upstream for paths that match no named [`servers`] entry —
    /// this is the `--upstream` value and preserves the v0.5 single-server
    /// behavior. Empty string means "no default" (multi-server-only).
    pub upstream: String,
    /// Named upstream MCP servers for multi-server routing (v0.6.5). A request
    /// to `/<name>/...` forwards to the matching server with the prefix
    /// stripped. Empty in the single-upstream case.
    pub servers: Vec<McpServer>,
    /// Enforce mode (v0.6.5). When `true`, a `tools/call` to a tool that has
    /// not been approved (`burnwall mcp approve`) is blocked with 403 instead
    /// of forwarded. Off by default — observe-only, as in v0.5.
    pub require_approval: bool,
    pub http_client: reqwest::Client,
    pub storage: Arc<Storage>,
    /// Same engine as the LLM proxy uses. Applied to every MCP request
    /// body so the path / command / mount / secret denylist also covers
    /// `tools/call` arguments. A violation returns 403, writes a
    /// `security_events` row, and never forwards.
    pub security: Arc<SecurityEngine>,
}

impl WatchState {
    /// Construct a single-upstream watcher (the v0.5 shape): one fallback
    /// upstream, no named servers, observe-only. Multi-server / enforce-mode
    /// callers set the extra fields directly.
    pub fn single_upstream(
        upstream: String,
        http_client: reqwest::Client,
        storage: Arc<Storage>,
        security: Arc<SecurityEngine>,
    ) -> Self {
        Self {
            upstream,
            servers: Vec::new(),
            require_approval: false,
            http_client,
            storage,
            security,
        }
    }

    /// Resolve a request path against this state's routing table.
    fn route(&self, path: &str) -> Option<Route> {
        let default = if self.upstream.is_empty() {
            None
        } else {
            Some(self.upstream.as_str())
        };
        resolve_route(&self.servers, default, path)
    }
}

/// One named upstream MCP server for multi-server routing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpServer {
    pub name: String,
    pub upstream: String,
}

/// The resolved target for a request: which configured server (the stable
/// fingerprint key), its upstream base URL, and the path to forward (with the
/// `/<name>` prefix stripped for a named server).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub server: String,
    pub upstream: String,
    pub forward_path: String,
}

/// Pure routing: pick the upstream for `path` (no query string).
///
/// A named server matches `/<name>` exactly or `/<name>/...` (the prefix is
/// stripped from `forward_path`); a partial token like `/<name>foo` does NOT
/// match. If no named server matches, fall back to `default_upstream`
/// (forwarding the path unchanged, server name `"default"`). Returns `None`
/// only when nothing matches and there is no default — the caller answers 404.
pub fn resolve_route(
    servers: &[McpServer],
    default_upstream: Option<&str>,
    path: &str,
) -> Option<Route> {
    for s in servers {
        let prefix = format!("/{}", s.name);
        if path == prefix {
            return Some(Route {
                server: s.name.clone(),
                upstream: s.upstream.clone(),
                forward_path: "/".to_string(),
            });
        }
        if let Some(rest) = path.strip_prefix(&format!("{prefix}/")) {
            return Some(Route {
                server: s.name.clone(),
                upstream: s.upstream.clone(),
                forward_path: format!("/{rest}"),
            });
        }
    }
    default_upstream.map(|up| Route {
        server: "default".to_string(),
        upstream: up.to_string(),
        forward_path: path.to_string(),
    })
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
    let body = body.strip_prefix(b"\xef\xbb\xbf").unwrap_or(body);
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

/// Return the JSON-RPC `method` of a request body, if it is parseable JSON
/// with a string `method`. Used to recognise `tools/list` so its response can
/// be inspected for poisoned / changed tool definitions.
fn parse_rpc_method(body: &[u8]) -> Option<String> {
    let body = body.strip_prefix(b"\xef\xbb\xbf").unwrap_or(body);
    let v: Value = serde_json::from_slice(body).ok()?;
    v.get("method").and_then(Value::as_str).map(str::to_string)
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
    let path = req.uri().path().to_string();
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();

    // Resolve the upstream for this path (named server prefix or fallback).
    let route = match state.route(&path) {
        Some(r) => r,
        None => {
            warn!("mcp-watch: no route for path {path}");
            return Ok(error_response(StatusCode::NOT_FOUND, "no_route"));
        }
    };
    let upstream_uri = format!(
        "{}{}{}",
        route.upstream.trim_end_matches('/'),
        route.forward_path,
        query
    );

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
    // A `tools/list` reply advertises the server's tools — inspect it for
    // poisoned / silently-changed definitions on the response path below.
    let is_tools_list =
        method == Method::POST && parse_rpc_method(&body_bytes).as_deref() == Some("tools/list");

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

    // Enforce mode (v0.6.5): a `tools/call` to a tool that has not been
    // approved is held — blocked with 403, never forwarded — until the user
    // runs `burnwall mcp approve`. A never-listed or rug-pulled (reset to
    // pending) tool is therefore also blocked. Observe-only (the default)
    // skips this entirely.
    if state.require_approval {
        if let Some(call) = tool_call.as_ref() {
            let approved = matches!(
                state
                    .storage
                    .mcp_tool_trust_state(&route.server, &call.name),
                Ok(Some(ref s)) if s == "approved"
            );
            if !approved {
                warn!(
                    "🛡️ MCP tools/call to unapproved tool '{}' on '{}' blocked (enforce mode)",
                    call.name, route.server
                );
                let event = SecurityEvent::new("mcp_tool_unapproved", &route.server)
                    .with_provider("mcp", &call.name);
                if let Err(e) = state.storage.insert_security_event(&event) {
                    error!("mcp security_event insert failed: {}", e);
                }
                return Ok(error_response(StatusCode::FORBIDDEN, "approval_required"));
            }
        }
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

    // For `tools/list` we buffer the (small JSON) reply, run the firewall
    // inspection, then forward the exact same bytes — read-only, the response
    // is never altered. Every other shape streams straight through unbuffered.
    let body = if is_tools_list {
        match upstream_resp.bytes().await {
            Ok(bytes) => {
                inspect_tools_list(&bytes, &state, &route.server);
                streaming::full(bytes)
            }
            Err(e) => {
                warn!("mcp-watch upstream body error for {}: {}", upstream_uri, e);
                return Ok(error_response(StatusCode::BAD_GATEWAY, "upstream_error"));
            }
        }
    } else {
        streaming::from_stream(upstream_resp.bytes_stream())
    };
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

/// Inspect a buffered `tools/list` reply for poisoned or silently-changed
/// tool definitions. Read-only: findings are recorded as `security_events`
/// (so `burnwall security` surfaces them) and the caller forwards the
/// response bytes unchanged. Fail-open — a non-`tools/list` body yields no
/// tools and no findings.
fn inspect_tools_list(body: &[u8], state: &WatchState, server: &str) {
    for tool in firewall::parse_tools_list(body) {
        // 1. Prompt-injection tells in the advertised name + description.
        let surface = format!("{} {}", tool.name, tool.description);
        if let Some(marker) = firewall::injection_marker(&surface) {
            warn!(
                "🛡️ MCP tool '{}' flagged: injection marker {:?}",
                tool.name, marker
            );
            record_mcp_security(state, "mcp_tool_poisoning", marker, &tool.name);
        }

        // 2. Reuse the request-side denylist on the raw tool object: a
        //    description smuggling a secret / path / command is caught by the
        //    same patterns the proxy already enforces.
        if let Ok(raw) = serde_json::to_vec(&tool.raw) {
            if let Some(v) = state.security.scan(&raw) {
                warn!("🛡️ MCP tool '{}' flagged: {}", tool.name, v.message());
                record_mcp_security(state, v.kind.event_type(), &v.matched, &tool.name);
            }
        }

        // 3. Rug pull — definition changed since we last fingerprinted it.
        match state
            .storage
            .observe_mcp_tool(server, &tool.name, &tool.fingerprint)
        {
            Ok(McpToolObservation::Changed) => {
                warn!(
                    "🛡️ MCP tool '{}' definition changed since last seen (possible rug pull)",
                    tool.name
                );
                record_mcp_security(state, "mcp_tool_changed", &tool.name, &tool.name);
            }
            Ok(_) => {}
            Err(e) => error!("mcp_tools observe failed: {}", e),
        }
    }
}

/// Write a `security_events` row for an MCP firewall finding, honoring the
/// `log_redact_details` config (the detail can name a path or pattern).
fn record_mcp_security(state: &WatchState, event_type: &str, detail: &str, tool: &str) {
    let detail = if state.security.rules().log_redact_details {
        "<redacted>"
    } else {
        detail
    };
    let event = SecurityEvent::new(event_type, detail).with_provider("mcp", tool);
    if let Err(e) = state.storage.insert_security_event(&event) {
        error!("mcp security_event insert failed: {}", e);
    }
}

fn error_response(status: StatusCode, kind: &str) -> Response<ProxyBody> {
    let body = format!(r#"{{"error":{{"type":"{}"}}}}"#, kind);
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(streaming::full(Bytes::from(body)))
        .expect("error_response: response builder failed")
}
