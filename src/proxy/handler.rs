//! Per-request entry: route by URL prefix, run security and budget checks,
//! hand off to the forwarder. Each step short-circuits with a JSON error
//! body matching SPEC.md §"Proxy Behavior".

use std::convert::Infallible;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use tracing::warn;

use crate::budget::BudgetStatus;
use crate::storage::{RequestRecord, SecurityEvent};

use super::{cache_injection, forwarding, streaming, AppState, ProxyBody};

pub async fn handle(
    req: Request<Incoming>,
    state: Arc<AppState>,
) -> Result<Response<ProxyBody>, Infallible> {
    let path = req.uri().path().to_string();

    // ─── route ───
    let routed: Option<(&'static str, String, String)> =
        if path == "/anthropic" || path.starts_with("/anthropic/") {
            Some((
                "anthropic",
                state.upstream_anthropic.clone(),
                path["/anthropic".len()..].to_string(),
            ))
        } else if path == "/openai" || path.starts_with("/openai/") {
            Some((
                "openai",
                state.upstream_openai.clone(),
                path["/openai".len()..].to_string(),
            ))
        } else if path == "/google" || path.starts_with("/google/") {
            Some((
                "google",
                state.upstream_google.clone(),
                path["/google".len()..].to_string(),
            ))
        } else {
            None
        };

    let (provider, upstream_base, rest) = match routed {
        Some(r) => r,
        None => {
            warn!("unknown route: {}", path);
            return Ok(error_response(
                StatusCode::NOT_FOUND,
                "proxy_error",
                "Unknown route. Use /anthropic/*, /openai/*, or /google/* prefix.",
            ));
        }
    };

    // The path + query that gets appended to each candidate base URL. Built
    // once here so endpoint failover can retry the same request shape against
    // alternate upstreams.
    let mut path_and_query = rest.clone();
    if let Some(q) = req.uri().query() {
        path_and_query.push('?');
        path_and_query.push_str(q);
    }

    // ─── read request body once (security scan needs it; forwarding too) ───
    let (parts, body) = req.into_parts();
    let body_bytes = match body.collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => {
            warn!("failed to read request body: {}", e);
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "proxy_error",
                "Failed to read request body.",
            ));
        }
    };

    let model = extract_model(&body_bytes).unwrap_or_else(|| "unknown".to_string());

    // ─── security check ───
    if let Some(violation) = state.security.scan(&body_bytes) {
        warn!("🛡️ BLOCKED {}: {}", provider, violation.message());

        // When log_redact_details is on, storage rows strip the matched-rule
        // detail and keep only the event-type label. The 403 below stays
        // informative -- legitimate users still see what was blocked.
        let redact = state.security.rules().log_redact_details;
        let stored_details = if redact {
            "<redacted>".to_string()
        } else {
            violation.matched.clone()
        };
        let stored_reason = if redact {
            violation.kind.event_type().to_string()
        } else {
            format!("{}: {}", violation.kind.event_type(), violation.matched)
        };

        let event = SecurityEvent::new(violation.kind.event_type(), &stored_details)
            .with_provider(provider, &model);
        if let Err(e) = state.storage.insert_security_event(&event) {
            tracing::error!("security_event insert failed: {}", e);
        }
        let record = RequestRecord::blocked(provider, &model, &stored_reason, None);
        if let Err(e) = state.storage.insert_request(&record) {
            tracing::error!("blocked-request insert failed: {}", e);
        }

        let msg = format!("Burnwall blocked: {}", violation.message());
        return Ok(error_response(
            StatusCode::FORBIDDEN,
            "security_blocked",
            &msg,
        ));
    }

    // ─── budget check ───
    match state.budget.check() {
        BudgetStatus::Exceeded { spent, limit } => {
            warn!("💰 BUDGET EXCEEDED: ${:.2}/${:.2}", spent, limit);
            let record = RequestRecord::blocked(provider, &model, "budget_exceeded", None);
            if let Err(e) = state.storage.insert_request(&record) {
                tracing::error!("blocked-request insert failed: {}", e);
            }
            let msg = format!(
                "Daily budget of ${:.2} exceeded (${:.2} spent)",
                limit, spent
            );
            return Ok(error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "budget_exceeded",
                &msg,
            ));
        }
        BudgetStatus::Warn {
            spent,
            limit,
            percent,
        } => {
            warn!("⚠️ Budget {}% used (${:.2}/${:.2})", percent, spent, limit);
        }
        BudgetStatus::Ok => {}
    }

    // ─── loop detection ───
    let request_hash = state.loop_detector.hash(&body_bytes);
    let request_hash_hex = format!("{:016x}", request_hash);
    let verdict = state.loop_detector.check_request(request_hash);
    if verdict.is_blocking() {
        warn!("🔄 LOOP BLOCKED {}: {}", provider, verdict.message());
        let mut record = RequestRecord::blocked(provider, &model, &verdict.message(), None);
        record.request_hash = Some(request_hash_hex.clone());
        if let Err(e) = state.storage.insert_request(&record) {
            tracing::error!("blocked-request insert failed: {}", e);
        }
        return Ok(error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "loop_detected",
            &verdict.message(),
        ));
    }

    // ─── cost-spiral enforcement (opt-in) ───
    // `record_cost` (response path) feeds the rolling window and warns when it
    // trips. Blocking the *next* request only happens when the user opted in
    // via `loop_detection.cost_spiral_enforce`; otherwise this is a no-op.
    let spiral = state.loop_detector.check_cost_spiral();
    if spiral.is_blocking() {
        warn!("💸 COST SPIRAL BLOCKED {}: {}", provider, spiral.message());
        let mut record = RequestRecord::blocked(provider, &model, &spiral.message(), None);
        record.request_hash = Some(request_hash_hex.clone());
        if let Err(e) = state.storage.insert_request(&record) {
            tracing::error!("blocked-request insert failed: {}", e);
        }
        return Ok(error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "cost_spiral",
            &spiral.message(),
        ));
    }

    // ─── cache injection (Anthropic only, opt-in) ───
    // When on: replace `body_bytes` with a rewritten body that has
    // `cache_control` ephemeral markers on the system prompt and first
    // message. When off: estimate the steady-state savings we would have
    // captured and accumulate them in `daily_projection`, so `burnwall
    // status` can surface "you would have saved $X today". Both branches
    // gate to provider=anthropic + path=/v1/messages (the only Anthropic
    // endpoint that accepts these markers).
    let messages_api = provider == "anthropic" && cache_injection::is_messages_path(&rest);
    let forward_body = if state.cache_injection && messages_api {
        let outcome = cache_injection::inject_if_eligible(&body_bytes);
        if outcome.modified {
            tracing::debug!("cache_control injected on Anthropic request");
        }
        outcome.body
    } else {
        if !state.cache_injection && messages_api {
            let projected = cache_injection::estimate_savings_usd(&body_bytes);
            if projected > 0.0 {
                let today = chrono::Local::now().format("%Y-%m-%d").to_string();
                if let Err(e) = state.storage.record_cache_projection(&today, projected) {
                    tracing::warn!("cache projection record failed: {}", e);
                }
            }
        }
        body_bytes
    };

    // ─── forward (with optional failover) + tee-parse ───
    match forwarding::forward(
        parts.method,
        &upstream_base,
        &path_and_query,
        parts.headers,
        forward_body,
        &state,
        provider,
        request_hash_hex,
    )
    .await
    {
        Ok(resp) => Ok(resp),
        Err(e) => {
            warn!(
                "upstream error for {}{}: {}",
                upstream_base, path_and_query, e
            );
            Ok(error_response(
                StatusCode::BAD_GATEWAY,
                "proxy_error",
                &format!("Upstream unreachable: {}", e),
            ))
        }
    }
}

/// Build a JSON error response in SPEC.md's `{"error":{"type":"X","message":"Y"}}`
/// shape.
fn error_response(status: StatusCode, kind: &str, msg: &str) -> Response<ProxyBody> {
    let escaped_kind = escape_json(kind);
    let escaped_msg = escape_json(msg);
    let body = format!(
        r#"{{"error":{{"type":"{}","message":"{}"}}}}"#,
        escaped_kind, escaped_msg
    );
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(streaming::full(Bytes::from(body)))
        .expect("error_response: response builder failed")
}

fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Best-effort extraction of the `model` field from a request body. Used
/// to populate `RequestRecord.model` even when the request was blocked.
fn extract_model(body: &[u8]) -> Option<String> {
    let body = body.strip_prefix(b"\xef\xbb\xbf").unwrap_or(body);
    let val: serde_json::Value = serde_json::from_slice(body).ok()?;
    val.get("model").and_then(|m| m.as_str()).map(String::from)
}
