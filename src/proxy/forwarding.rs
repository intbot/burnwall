//! Forward a request to an upstream provider via reqwest, tee the response
//! body so the proxy can stream it back to the client AND parse it in the
//! background for cost tracking.
//!
//! Hop-by-hop headers (RFC 7230 §6.1) plus `Host` and `Content-Length` are
//! stripped on both legs. Body bytes, method, query string, status, and
//! the remaining headers pass through unchanged.
//!
//! ## Failover (v0.7)
//!
//! When `[resilience]` is enabled, the same request shape is tried against
//! each candidate base URL for the provider in order, skipping endpoints the
//! circuit breaker has opened, advancing on a connection error or 5xx. With
//! resilience disabled the behavior is unchanged: a single upstream, and a
//! 5xx is forwarded to the client verbatim.

use std::collections::HashSet;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Instant;

use bytes::Bytes;
use hyper::Response;
use hyper::http::{HeaderMap, HeaderName, HeaderValue, Method};
use tracing::{debug, error, warn};

use crate::pricing;
use crate::providers::{ParsedResponse, TokenUsage, anthropic, google, openai};
use crate::storage::RequestRecord;

use super::{AppState, BoxError, ProxyBody, streaming};

// RFC 7230 §6.1 hop-by-hop headers, plus `Host` (reqwest derives it from
// the URL) and `Content-Length` (we re-stream, so chunked encoding will
// recompute the length).
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

/// Headers forwarded upstream on the tracked path: hop-by-hop stripped, plus
/// `Accept-Encoding`. The response tee parses the body for usage/cost, and
/// the proxy's HTTP client is built without decompression support — so when
/// the client's `Accept-Encoding` (Claude Code sends `gzip, br, zstd`) is
/// forwarded, the upstream compresses the body and the tee sees opaque bytes:
/// cost tracking silently records nothing. Dropping the header makes the
/// upstream respond in identity encoding; the response still passes through
/// byte-for-byte unchanged. The bypass relay ([`passthrough`]) keeps the
/// client's header — it never parses anything.
fn tracked_outbound_headers(req_headers: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in req_headers.iter() {
        if is_hop_by_hop(name.as_str()) || name.as_str().eq_ignore_ascii_case("accept-encoding") {
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    out
}

#[allow(clippy::too_many_arguments)]
pub async fn forward(
    method: Method,
    primary_base: &str,
    path_and_query: &str,
    req_headers: HeaderMap,
    body: Bytes,
    state: &Arc<AppState>,
    provider: &'static str,
    request_hash_hex: String,
    // Loop-detector hash to record an arrival under, but ONLY when the upstream
    // returns 2xx — `None` for GET/body-less requests that aren't loop-tracked.
    // Recording on the response path (not pre-forward) is what stops blocked
    // 429s and failed-request retries from feeding the window (B-C2).
    loop_hash: Option<u64>,
    // Cache-savings projection (USD) to persist off the hot path in the tee,
    // instead of a synchronous pre-forward write (D-M5). `None` when cache
    // injection is on or the request isn't an eligible Messages-API call.
    cache_projection: Option<f64>,
) -> Result<Response<ProxyBody>, BoxError> {
    // Opt-in session/swarm id for per-session attribution + budget recording.
    let session_id = super::handler::session_from_headers(&req_headers);

    let outbound_headers = tracked_outbound_headers(&req_headers);

    let candidates = state.resilience.candidates(provider, primary_base);
    let use_breaker = state.resilience.enabled;

    let started = Instant::now();
    let mut chosen: Option<reqwest::Response> = None;
    let mut last_err: Option<BoxError> = None;

    for base in &candidates {
        if use_breaker && !state.resilience.breaker.is_available(base) {
            debug!("skipping {} — circuit open", base);
            continue;
        }
        let uri = format!("{}{}", base, path_and_query);
        debug!("→ {} {} ({} bytes)", method, uri, body.len());

        let mut builder = state
            .http_client
            .request(method.clone(), &uri)
            .headers(outbound_headers.clone());
        if !body.is_empty() {
            builder = builder.body(body.clone());
        }

        match builder.send().await {
            Ok(resp) => {
                let status = resp.status();
                if status.is_server_error() {
                    // A 5xx is an endpoint-level failure for failover purposes.
                    if use_breaker {
                        state.resilience.breaker.record_failure(base);
                    }
                    last_err = Some(format!("{} returned {}", base, status).into());
                    // Keep it as the fallback response in case no healthy
                    // endpoint answers — then we forward this 5xx verbatim.
                    chosen = Some(resp);
                    if candidates.len() > 1 {
                        warn!("endpoint {} returned {}, trying next", base, status);
                    }
                    continue;
                }
                if use_breaker {
                    state.resilience.breaker.record_success(base);
                }
                debug!("← {} {}", status.as_u16(), uri);
                chosen = Some(resp);
                last_err = None;
                break;
            }
            Err(e) => {
                if use_breaker {
                    state.resilience.breaker.record_failure(base);
                }
                warn!("endpoint {} unreachable: {}", base, e);
                last_err = Some(Box::new(e));
                continue;
            }
        }
    }

    let upstream_resp = match chosen {
        Some(r) => r,
        None => return Err(last_err.unwrap_or_else(|| "all endpoints unavailable".into())),
    };

    let latency_ms = started.elapsed().as_millis().min(i64::MAX as u128) as i64;
    let status = upstream_resp.status();
    let status_code = status.as_u16() as i64;
    let resp_headers = upstream_resp.headers().clone();

    // Captured for the tee's parse-failure diagnostics: a non-identity
    // encoding here means the body bytes are compressed and unparseable.
    let content_encoding = resp_headers
        .get("content-encoding")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("identity")
        .to_string();

    // Subscription-plan limit headroom rides on the upstream response (e.g.
    // Anthropic's `unified-*` headers); `None` for API keys / unprobed providers.
    // Parsed here (cheap, in-memory); persisted off the response path in the tee
    // callback below.
    let plan_snapshot =
        crate::plan::parse_limits(provider, &resp_headers, chrono::Utc::now().timestamp());

    // Tee callback: parse the full body once the stream finishes and record
    // a `requests` row (with latency + status) + bump the budget tracker +
    // feed the loop detector's cost-spiral window + emit an OTel span. Fire-
    // and-forget — the proxy response returns to the client before this runs.
    let storage = state.storage.clone();
    let budget = state.budget.clone();
    let loop_detector = state.loop_detector.clone();
    #[cfg(feature = "observe")]
    let otel = state.otel.clone();
    let provider_str = provider.to_string();
    let hash_hex = request_hash_hex;
    let session_for_tee = session_id.clone();

    let teed = streaming::tee_stream(upstream_resp.bytes_stream(), move |chunks, aborted| {
        // Record a loop-detector arrival only for a forwarded 2xx (B-C2): a
        // genuine repeat is an identical body that keeps *succeeding*. Retries
        // of a block or of an upstream error never reach here with a 2xx, so
        // they can't refill the window. A client-aborted request isn't a
        // completed success, so it doesn't count toward a loop either.
        if let Some(hash) = loop_hash {
            if !aborted && (200..300).contains(&status_code) {
                loop_detector.record_arrival(hash);
            }
        }

        // Deferred cache-savings projection write (D-M5): off the response path,
        // so the synchronous SQLite UPSERT/fsync never sits in front of the
        // request the way a pre-forward write did.
        if let Some(savings) = cache_projection {
            let today = chrono::Local::now().format("%Y-%m-%d").to_string();
            if let Err(e) = storage.record_cache_projection(&today, savings) {
                debug!("cache projection record failed: {}", e);
            }
        }

        // Persist the subscription-limit snapshot if this was a unified response.
        // Off the response path — the client already has its bytes.
        if let Some(snap) = &plan_snapshot {
            let _ = crate::plan::write_snapshot(snap);
        }

        let mut total = Vec::with_capacity(chunks.iter().map(|b| b.len()).sum());
        for b in &chunks {
            total.extend_from_slice(b);
        }

        match parse_for_provider(&provider_str, &total) {
            Some(p) => {
                let cost = cost_or_zero(&p.model, &p.usage);
                let mut record = RequestRecord::successful(
                    &provider_str,
                    &p.model,
                    &p.usage,
                    cost,
                    session_for_tee.clone(),
                );
                record.request_hash = Some(hash_hex.clone());
                record.latency_ms = Some(latency_ms);
                // 499 (client closed request) marks a partial response the user
                // cancelled mid-stream, so its cost is attributable but
                // distinguishable from a clean completion.
                record.http_status = Some(if aborted { 499 } else { status_code });
                if let Err(e) = storage.insert_request(&record) {
                    error!("requests insert failed: {}", e);
                }
                // Per-session/swarm budget accounting (no-op unless a session id
                // is present and a per-session cap is configured).
                if let Some(sid) = &session_for_tee {
                    budget.record_session(sid, cost);
                }
                // Nudge status-ribbon surfaces (editor bar, `burnwall watch`) to
                // refresh. Off the response path — the client already has its
                // bytes — so this tiny write adds nothing to request latency.
                crate::storage::touch_watch_signal(hash_hex.as_str());
                budget.record(cost);
                // Feed the cost-spiral window. The verdict is observable (not
                // silently dropped): a tripped spiral is logged so it surfaces
                // in the proxy log. (Turning this into active request-blocking
                // is a deliberate product decision — see review notes.)
                let spiral = loop_detector.record_cost(cost);
                if spiral.is_blocking() {
                    warn!("💸 {}", spiral.message());
                }
                #[cfg(feature = "observe")]
                if let Some(w) = &otel {
                    w.record(
                        &provider_str,
                        &p.model,
                        &p.usage,
                        cost,
                        latency_ms,
                        status_code,
                    );
                }
                debug!(
                    "recorded {} {}: ${:.6} ({} in / {} out / {} cache_read / {} cache_write) {}ms status={}",
                    provider_str,
                    p.model,
                    cost,
                    p.usage.input_tokens,
                    p.usage.output_tokens,
                    p.usage.cache_read_tokens,
                    p.usage.cache_creation_tokens,
                    latency_ms,
                    status_code,
                );
            }
            None if aborted => {
                // A client-cancelled stream is usually a partial body that
                // can't parse — expected, not a systemic problem. Don't
                // warn-spam on every Esc.
                debug!(
                    "{} response not recorded — client aborted mid-stream ({} bytes)",
                    provider_str,
                    total.len(),
                );
            }
            None => {
                // warn, not debug: an unparseable body means this request is
                // invisible to cost tracking and coverage. A long stretch of
                // these in the log is the signal that something systemic
                // (e.g. an encoding we don't handle) is hiding traffic.
                warn!(
                    "could not parse {} response for usage tracking ({} bytes, content-encoding: {}, status {}) — request not recorded",
                    provider_str,
                    total.len(),
                    content_encoding,
                    status_code,
                );
            }
        }
    });

    let body = streaming::from_stream(teed);

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

fn parse_for_provider(provider: &str, body: &[u8]) -> Option<ParsedResponse> {
    match provider {
        "anthropic" => anthropic::parse_any(body),
        "openai" => openai::parse_any(body),
        "google" => google::parse_any(body),
        _ => None,
    }
}

/// Cost for a parsed response, or `0.0` when the model has no pricing entry.
///
/// Fail-open: the row is still recorded (the token counts are real and the
/// request must stay visible to history/budget), but pricing an unknown model
/// at $0 silently would understate spend with no trace — so the first time
/// each model name misses, warn and point at the override file. Once per
/// model per process, not per request: an agent can replay the same unknown
/// model thousands of times an hour.
fn cost_or_zero(model: &str, usage: &TokenUsage) -> f64 {
    match pricing::calculate_cost(model, usage) {
        Some(c) => c,
        None => {
            static WARNED: LazyLock<Mutex<HashSet<String>>> =
                LazyLock::new(|| Mutex::new(HashSet::new()));
            let mut warned = WARNED.lock().unwrap_or_else(|p| p.into_inner());
            if warned.insert(model.to_string()) {
                warn!(
                    "unknown model '{}' — no pricing entry, cost recorded as $0. \
                     Add a [[model]] override in ~/.burnwall/pricing.toml to price it.",
                    model,
                );
            }
            0.0
        }
    }
}

/// Pure pass-through: forward `method/headers/body` to `upstream_base + path_and_query`,
/// stream the response back. No security scan, no parsing, no storage write,
/// no failover, no breaker. Used by the BURNWALL_BYPASS kill-switch (L2).
pub async fn passthrough(
    method: Method,
    upstream_base: &str,
    path_and_query: &str,
    req_headers: HeaderMap,
    body: Bytes,
    state: &Arc<AppState>,
) -> Result<Response<ProxyBody>, BoxError> {
    let mut outbound_headers = HeaderMap::new();
    for (name, value) in req_headers.iter() {
        if !is_hop_by_hop(name.as_str()) {
            outbound_headers.append(name.clone(), value.clone());
        }
    }
    let uri = format!("{}{}", upstream_base, path_and_query);
    let mut builder = state
        .http_client
        .request(method, &uri)
        .headers(outbound_headers);
    if !body.is_empty() {
        builder = builder.body(body);
    }
    let upstream_resp = builder.send().await?;
    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();
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
    Ok(response
        .body(body)
        .expect("passthrough: response build failed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracked_outbound_headers_strips_accept_encoding_and_hop_by_hop() {
        let mut h = HeaderMap::new();
        h.insert(
            "accept-encoding",
            HeaderValue::from_static("gzip, br, zstd"),
        );
        h.insert("connection", HeaderValue::from_static("keep-alive"));
        h.insert("content-length", HeaderValue::from_static("42"));
        h.insert("x-api-key", HeaderValue::from_static("k"));
        h.insert("anthropic-version", HeaderValue::from_static("2023-06-01"));
        let out = tracked_outbound_headers(&h);
        // Forwarding the client's accept-encoding lets the upstream compress
        // the body, which the tee can't parse — cost tracking goes dark.
        assert!(out.get("accept-encoding").is_none());
        assert!(out.get("connection").is_none());
        assert!(out.get("content-length").is_none());
        assert_eq!(out.get("x-api-key").unwrap(), "k");
        assert_eq!(out.get("anthropic-version").unwrap(), "2023-06-01");
    }
}
