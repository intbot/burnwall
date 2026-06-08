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

use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use hyper::http::{HeaderMap, HeaderName, HeaderValue, Method};
use hyper::Response;
use tracing::{debug, error, warn};

use crate::pricing;
use crate::providers::{anthropic, google, openai, ParsedResponse};
use crate::storage::RequestRecord;

use super::{streaming, AppState, BoxError, ProxyBody};

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
) -> Result<Response<ProxyBody>, BoxError> {
    let mut outbound_headers = HeaderMap::new();
    for (name, value) in req_headers.iter() {
        if !is_hop_by_hop(name.as_str()) {
            outbound_headers.append(name.clone(), value.clone());
        }
    }

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

    let teed = streaming::tee_stream(upstream_resp.bytes_stream(), move |chunks| {
        let mut total = Vec::with_capacity(chunks.iter().map(|b| b.len()).sum());
        for b in &chunks {
            total.extend_from_slice(b);
        }

        match parse_for_provider(&provider_str, &total) {
            Some(p) => {
                let cost = pricing::calculate_cost(&p.model, &p.usage).unwrap_or(0.0);
                let mut record =
                    RequestRecord::successful(&provider_str, &p.model, &p.usage, cost, None);
                record.request_hash = Some(hash_hex.clone());
                record.latency_ms = Some(latency_ms);
                record.http_status = Some(status_code);
                if let Err(e) = storage.insert_request(&record) {
                    error!("requests insert failed: {}", e);
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
            None => {
                debug!(
                    "could not parse {} response body for usage tracking ({} bytes)",
                    provider_str,
                    total.len()
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
    Ok(response.body(body).expect("passthrough: response build failed"))
}
