//! Forward a request to an upstream provider via reqwest, tee the response
//! body so the proxy can stream it back to the client AND parse it in the
//! background for cost tracking.
//!
//! Hop-by-hop headers (RFC 7230 §6.1) plus `Host` and `Content-Length` are
//! stripped on both legs. Body bytes, method, query string, status, and
//! the remaining headers pass through unchanged.

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::BodyExt as _;
use hyper::http::{HeaderMap, HeaderName, HeaderValue, Method};
use hyper::Response;
use reqwest::Client;
use tracing::{debug, error};

use crate::pricing;
use crate::providers::{anthropic, openai, ParsedResponse};
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

pub async fn forward(
    method: Method,
    upstream_uri: &str,
    req_headers: HeaderMap,
    body: Bytes,
    state: &Arc<AppState>,
    provider: &'static str,
) -> Result<Response<ProxyBody>, BoxError> {
    debug!("→ {} {} ({} bytes)", method, upstream_uri, body.len());

    let mut outbound_headers = HeaderMap::new();
    for (name, value) in req_headers.iter() {
        if !is_hop_by_hop(name.as_str()) {
            outbound_headers.append(name.clone(), value.clone());
        }
    }

    let mut builder = state
        .http_client
        .request(method, upstream_uri)
        .headers(outbound_headers);
    if !body.is_empty() {
        builder = builder.body(body);
    }

    let upstream_resp = builder.send().await?;
    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();
    debug!("← {} {}", status.as_u16(), upstream_uri);

    // Tee callback: parse the full body once the stream finishes and record
    // a `requests` row + bump the budget tracker. Fire-and-forget — the
    // proxy response is returned to the client before this callback runs.
    let storage = state.storage.clone();
    let budget = state.budget.clone();
    let provider_str = provider.to_string();

    let teed = streaming::tee_stream(upstream_resp.bytes_stream(), move |chunks| {
        let mut total = Vec::with_capacity(chunks.iter().map(|b| b.len()).sum());
        for b in &chunks {
            total.extend_from_slice(b);
        }

        let parsed = parse_for_provider(&provider_str, &total);
        match parsed {
            Some(p) => {
                let cost = pricing::calculate_cost(&p.model, &p.usage).unwrap_or(0.0);
                let record =
                    RequestRecord::successful(&provider_str, &p.model, &p.usage, cost, None);
                if let Err(e) = storage.insert_request(&record) {
                    error!("requests insert failed: {}", e);
                }
                budget.record(cost);
                debug!(
                    "recorded {} {}: ${:.6} ({} in / {} out / {} cache_read / {} cache_write)",
                    provider_str,
                    p.model,
                    cost,
                    p.usage.input_tokens,
                    p.usage.output_tokens,
                    p.usage.cache_read_tokens,
                    p.usage.cache_creation_tokens
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
        _ => None,
    }
}
