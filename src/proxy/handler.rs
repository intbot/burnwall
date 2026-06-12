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

use super::{AppState, ProxyBody, cache_injection, forwarding, streaming, tool_trim};

pub async fn handle(
    req: Request<Incoming>,
    state: Arc<AppState>,
) -> Result<Response<ProxyBody>, Infallible> {
    let path = req.uri().path().to_string();

    // ─── healthz ───
    // Cheap local probe used by `burnwall enable-routing` preflight, by the
    // login-service crash-loop circuit breaker, and by any external monitor.
    // Returns 200 with a tiny JSON body. Never touches upstreams.
    if path == "/healthz" {
        return Ok(healthz_response());
    }

    // ─── bypass kill-switch (L2) ───
    // BURNWALL_BYPASS=1 turns the proxy into a pure relay: no security scan,
    // no budget check, no loop detection, no storage write. The user's last-
    // resort escape hatch when a bad release misbehaves. Set the env var,
    // restart the AI tool, traffic flows through unmodified.
    if bypass_active() {
        return Ok(passthrough(req, &state).await);
    }

    // ─── runtime pause (file-based, flips live) ───
    // `burnwall pause` / `burnwall allow-once` write a small auto-expiring
    // state file the proxy checks here, per request — the escape hatch that
    // actually works on a running daemon (the env var above is frozen at
    // daemon spawn). Cost on the fast path: one stat() of an absent file.
    if let Some(pause_path) = state.pause_path.as_deref() {
        let now = chrono::Utc::now().timestamp();
        match crate::bypass::read_at(pause_path, now) {
            crate::bypass::Bypass::Paused { resumes_in_secs } => {
                tracing::debug!(
                    "⏸ protection paused — relaying unchecked ({}s left)",
                    resumes_in_secs
                );
                return Ok(passthrough(req, &state).await);
            }
            crate::bypass::Bypass::AllowOnce { .. } => {
                // The file delete is the atomic claim — exactly one request
                // gets through unchecked, concurrent losers stay protected.
                if crate::bypass::consume_allow_once_at(pause_path) {
                    warn!("⏸ allow-once consumed — relaying this one request unchecked");
                    return Ok(passthrough(req, &state).await);
                }
            }
            crate::bypass::Bypass::None => {}
        }
    }

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

    // Opt-in session/swarm id (for per-session budget ceilings + attribution).
    // Agents in a fan-out that set the same `x-burnwall-session` header share
    // one budget + show up grouped; absent header = feature dormant.
    let session_id = session_from_headers(&parts.headers);

    // ─── security check ───
    // `scan_request_for`, not `scan`: command-shaped rules apply only to
    // tool-call arguments, so a system prompt or chat message that merely
    // *mentions* a denied path/command doesn't 403 the whole session. The
    // destination `provider` is threaded in for the credential-misdirection
    // check (opt-in) — a provider key bound for a different provider's endpoint.
    //
    // File-upload egress fallback (#3): `scan_request_for` parses JSON and
    // fails open on a non-JSON body, so a multipart/form-data upload to a
    // provider file endpoint (`/v1/files`) was never inspected. When egress
    // detection (`security.dlp`) is on and this is a file-upload route whose
    // body isn't JSON, scan the raw body for secrets / DLP / canaries. This is
    // the one body inspection that is intentionally NOT tool-call-scoped — a
    // raw upload has no prose/tool-call structure; the whole body is the egress
    // payload (justified in `scanner::scan_raw_upload`).
    let upload_violation = if is_file_upload_route(&rest) && !looks_like_json(&body_bytes) {
        state.security.scan_upload(&body_bytes)
    } else {
        None
    };
    if let Some(violation) = state
        .security
        .scan_request_for(&body_bytes, provider)
        .or(upload_violation)
    {
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

        // Self-explaining block: which tool tripped which rule (with a masked
        // preview for secret/DLP hits) and *why* — not a bare category label.
        let what = violation.block_explanation();
        return Ok(block::build(
            provider,
            "security_blocked",
            StatusCode::FORBIDDEN,
            &what,
            block::SECURITY_REMEDIES,
            None,
        ));
    }

    // ─── paranoid mode (#20, opt-in fail-closed) ───
    // Burnwall's default is fail-open: a non-empty body the scanner can't
    // parse as JSON is forwarded unscanned (counted + warned periodically in
    // the engine). With `security.paranoid = true` that blind spot closes:
    // an uninspectable body is blocked instead of forwarded. Known
    // file-upload routes are exempt — multipart uploads are legitimately
    // non-JSON and already got the raw egress scan above. Off by default
    // (R2): exotic encodings would otherwise false-positive entire tools.
    if state.paranoid
        && state.security.rules().enabled
        && !body_bytes.is_empty()
        && !is_file_upload_route(&rest)
        && !state.security.scannable_json(&body_bytes)
    {
        warn!(
            "🛡️ PARANOID BLOCKED {}: request body is not parseable JSON ({} bytes) — it cannot be scanned",
            provider,
            body_bytes.len()
        );
        let event = SecurityEvent::new(
            "paranoid_unscannable",
            "request body could not be parsed for scanning; paranoid mode blocks instead of forwarding unscanned",
        )
        .with_provider(provider, &model);
        if let Err(e) = state.storage.insert_security_event(&event) {
            tracing::error!("security_event insert failed: {}", e);
        }
        let record = RequestRecord::blocked(provider, &model, "paranoid_unscannable", None);
        if let Err(e) = state.storage.insert_request(&record) {
            tracing::error!("blocked-request insert failed: {}", e);
        }
        let what = format!(
            "Paranoid mode is on, and this request's body ({} bytes) is not parseable JSON, so the security scanner cannot inspect it. Fail-closed means it is blocked rather than forwarded unscanned.",
            body_bytes.len()
        );
        return Ok(block::build(
            provider,
            "paranoid_blocked",
            StatusCode::FORBIDDEN,
            &what,
            block::PARANOID_REMEDIES,
            None,
        ));
    }

    // ─── budget check ───
    // Plan-aware (B-H4): a subscription request (OAuth bearer, no API key) is
    // not metered per token, so the dollar cap is notional — we track and warn
    // but do not 429-block it unless `budget.enforce_on_plan` is set. Metered
    // API-key traffic is always enforced.
    let kind = auth_kind(&parts.headers, provider);
    let metered = kind == AuthKind::Metered;
    let enforce_dollar_cap = metered || state.budget.config().enforce_on_plan;

    // ─── silent-billing watchdog (#11, ALERT-ONLY, never blocks) ───
    // Track the billing kind per session. If a session that was on a flat-rate
    // subscription flips to metered API billing (the user's plan coverage
    // silently lapsing — e.g. a `claude -p` request that bills the API), warn
    // once and record one informational event. Uses the same plan-aware
    // `auth_kind` gate as budget enforcement (R3); it never returns a 4xx.
    if let Some(sid) = &session_id {
        let kind_label = match kind {
            AuthKind::Subscription => super::AUTH_SUBSCRIPTION,
            AuthKind::Metered => super::AUTH_METERED,
        };
        if super::BILLING_WATCH.record(sid, kind_label) {
            warn!(
                "💳 billing flip on session {}: subscription → metered (plan coverage may have lapsed — this request bills the API)",
                sid
            );
            let event = SecurityEvent::new(
                "billing_flip",
                "session switched from subscription to metered billing",
            )
            .with_provider(provider, &model);
            if let Err(e) = state.storage.insert_security_event(&event) {
                tracing::error!("billing_flip event insert failed: {}", e);
            }
        }
    }

    // ─── slow-drip exfiltration monitor (#16, ALERT-ONLY, never blocks) ───
    // Best-effort: count outbound network hosts seen in this body and warn once
    // if any single host is targeted an unusual number of times over the
    // process lifetime. Coarse and conservative by design (a high-frequency
    // host is far more often a legitimate API than an exfil sink), so it only
    // ever logs + records an informational event — it does NOT gate the
    // request. Skipped for body-less/GET requests (nothing to scan).
    if !body_bytes.is_empty() {
        for host in super::extract_hosts(&String::from_utf8_lossy(&body_bytes)) {
            if super::DRIP_MONITOR.observe(&host) {
                warn!(
                    "🐌 slow-drip monitor: host {} targeted {}+ times this session — review for low-and-slow exfiltration",
                    host,
                    super::DripMonitor::THRESHOLD
                );
                let event = SecurityEvent::new(
                    "slow_drip_alert",
                    "a single outbound host was targeted an unusual number of times",
                )
                .with_provider(provider, &model);
                if let Err(e) = state.storage.insert_security_event(&event) {
                    tracing::error!("slow_drip_alert event insert failed: {}", e);
                }
            }
        }
    }

    // ─── burn-rate speedometer (#2, ALWAYS-ON, warn/surface only) ───
    // Compute a short-window burn rate (last 5 minutes, expressed as USD/hour)
    // from the rolling-hour window the tracker keeps. Never blocks. When it
    // spikes past the configured hourly ceiling (or, when no ceiling is set, a
    // high absolute rate), log a warning so a runaway burn is visible in the
    // proxy log. `status` surfaces the same number for the steady-state view.
    {
        const BURN_WINDOW_MINS: u32 = 5;
        let rate = state.budget.burn_rate_per_hour(BURN_WINDOW_MINS);
        let cap = state.budget.config().per_hour_usd;
        // Spike threshold: 80% of the hourly ceiling when armed; otherwise a
        // generous absolute floor so we don't warn on ordinary bursts.
        let spike = if cap > 0.0 { cap * 0.8 } else { 20.0 };
        if rate >= spike && rate > 0.0 {
            warn!(
                "🏎️ burn-rate spike: ~${:.2}/hr (last {}m){}",
                rate,
                BURN_WINDOW_MINS,
                if cap > 0.0 {
                    format!(" — hourly cap ${cap:.2}")
                } else {
                    String::new()
                }
            );
        }
    }

    // Cheaper-model fallback target (#18). Resolved once: non-empty only when
    // the user opted in via `budget.fallback_model`. When a dollar cap would
    // block below AND this is set, we rewrite the request `model` instead of
    // returning 429. Threaded to the forward-body selection further down.
    let fallback_model = {
        let f = state.budget.config().fallback_model.trim();
        if f.is_empty() {
            None
        } else {
            Some(f.to_string())
        }
    };
    // Set true once any enforced dollar cap is exceeded — drives the fallback
    // rewrite decision after the cap loop.
    let mut dollar_cap_would_block = false;

    // Monthly cap first (the hard backstop), then daily, then the hourly brake.
    for (status, label) in [
        (state.budget.check_monthly(), "monthly"),
        (state.budget.check(), "daily"),
        (state.budget.check_hourly(), "hourly"),
    ] {
        match status {
            BudgetStatus::Exceeded { spent, limit } => {
                if enforce_dollar_cap {
                    // #18: if a fallback model is configured, don't block — fall
                    // through to the request rewrite (logged) below. Blocking is
                    // only the path when no fallback is set.
                    if fallback_model.is_some() {
                        dollar_cap_would_block = true;
                        warn!(
                            "💰 {} budget exceeded ${:.2}/${:.2} — downgrading to fallback model instead of blocking",
                            label, spent, limit
                        );
                        // Don't `return`; keep evaluating but the rewrite below
                        // handles forwarding. Break so we rewrite once.
                        break;
                    }
                    warn!("💰 {} BUDGET EXCEEDED: ${:.2}/${:.2}", label, spent, limit);
                    let kind = match label {
                        "monthly" => "monthly_budget_exceeded",
                        "hourly" => "hourly_budget_exceeded",
                        _ => "budget_exceeded",
                    };
                    let record = RequestRecord::blocked(provider, &model, kind, None);
                    if let Err(e) = state.storage.insert_request(&record) {
                        tracing::error!("blocked-request insert failed: {}", e);
                    }
                    let (reset, retry_after, remedies): (&str, Option<u64>, &[&str]) = match label {
                        "monthly" => (
                            "the 1st of next month",
                            Some(block::seconds_until_local_midnight()),
                            block::BUDGET_REMEDIES,
                        ),
                        "hourly" => (
                            "the end of the rolling hour",
                            // The rolling-hour window drains in at most an hour;
                            // steer well-behaved clients to back off that long.
                            Some(3600),
                            block::HOURLY_BUDGET_REMEDIES,
                        ),
                        _ => (
                            "local midnight",
                            Some(block::seconds_until_local_midnight()),
                            block::BUDGET_REMEDIES,
                        ),
                    };
                    let what = format!(
                        "Your {label} budget of ${:.2} is used up (${:.2} spent). It resets at {reset}.",
                        limit, spent
                    );
                    return Ok(block::build(
                        provider,
                        kind,
                        StatusCode::TOO_MANY_REQUESTS,
                        &what,
                        remedies,
                        retry_after,
                    ));
                } else {
                    // Subscription traffic: notional dollars, plan is the real
                    // limit. Warn once-ish, never block.
                    warn!(
                        "💰 {} notional spend ${:.2} over ${:.2} cap — plan traffic, not blocking (set budget.enforce_on_plan=true to enforce)",
                        label, spent, limit
                    );
                }
            }
            BudgetStatus::Warn {
                spent,
                limit,
                percent,
            } => {
                warn!(
                    "⚠️ {} budget {}% used (${:.2}/${:.2})",
                    label, percent, spent, limit
                );
            }
            BudgetStatus::Ok => {}
        }
    }

    // ─── per-session / swarm budget ceiling (opt-in via x-burnwall-session) ───
    // Same plan-aware gate as the daily/monthly caps: an explicit per-session
    // cap is still enforced on metered traffic, but a notional cap on plan
    // traffic only warns unless the user opted in.
    if let Some(sid) = &session_id {
        if let BudgetStatus::Exceeded { spent, limit } = state.budget.check_session(sid) {
            if enforce_dollar_cap {
                warn!("💰 SESSION BUDGET EXCEEDED: ${:.2}/${:.2}", spent, limit);
                let record = RequestRecord::blocked(
                    provider,
                    &model,
                    "session_budget_exceeded",
                    Some(sid.clone()),
                );
                if let Err(e) = state.storage.insert_request(&record) {
                    tracing::error!("blocked-request insert failed: {}", e);
                }
                let what = format!(
                    "This session/swarm hit its ${:.2} cap (${:.2} spent).",
                    limit, spent
                );
                return Ok(block::build(
                    provider,
                    "session_budget_exceeded",
                    StatusCode::TOO_MANY_REQUESTS,
                    &what,
                    block::SESSION_REMEDIES,
                    None,
                ));
            } else {
                warn!(
                    "💰 session notional spend ${:.2} over ${:.2} cap — plan traffic, not blocking",
                    spent, limit
                );
            }
        }
    }

    // ─── loop detection ───
    // Skip body-less / GET requests entirely (B-H1): a `GET /v1/models` cannot
    // be a runaway agent loop worth blocking, and all empty bodies would
    // otherwise collide into one bucket. `should_track` gates both the
    // pre-forward peek and the on-2xx arrival recording.
    let should_track_loop = parts.method != hyper::Method::GET && !body_bytes.is_empty();
    let request_hash =
        state
            .loop_detector
            .hash(parts.method.as_str(), provider, &rest, &body_bytes);
    let request_hash_hex = format!("{:016x}", request_hash);
    if should_track_loop {
        // Read-only peek — the arrival is recorded later by the tee, and only
        // on a 2xx, so a blocked 429 (or a retry after an upstream failure)
        // never feeds the window. This is the death-spiral fix (B-C2).
        let verdict = state.loop_detector.check_request(request_hash);
        if verdict.is_blocking() {
            warn!("🔄 LOOP BLOCKED {}: {}", provider, verdict.message());
            let mut record = RequestRecord::blocked(provider, &model, &verdict.message(), None);
            record.request_hash = Some(request_hash_hex.clone());
            if let Err(e) = state.storage.insert_request(&record) {
                tracing::error!("blocked-request insert failed: {}", e);
            }
            let what = format!(
                "{}. This usually means your tool retried an identical request; it clears automatically.",
                verdict.message()
            );
            return Ok(block::build(
                provider,
                "loop_detected",
                StatusCode::TOO_MANY_REQUESTS,
                &what,
                block::LOOP_REMEDIES,
                verdict.retry_after_secs(),
            ));
        }

        // ─── near-duplicate action-repeat detector (#19, WARN-only by default) ───
        // Separate from the full-body hash above: the body hash deliberately
        // ignores the growing transcript, so an agent that keeps re-issuing the
        // *same tool-call action* every turn (a different body each time) slips
        // past it. This detector fingerprints just the latest assistant turn's
        // action and counts repeats in the window. By default it only WARNs (R5);
        // it blocks only when `loop_detection.action_repeat_enforce` is on, and
        // even then it never tightens the existing full-body-hash block.
        let action_verdict = state.loop_detector.check_action_repeat(&body_bytes);
        if let crate::budget::LoopVerdict::ActionRepeat {
            count, enforced, ..
        } = action_verdict
        {
            warn!(
                "🔁 action loop {}: same tool call repeated {} times in {}s{}",
                provider,
                count,
                state.loop_detector.config().window_seconds,
                if enforced {
                    " — blocking (action_repeat_enforce)"
                } else {
                    " — warn-only"
                }
            );
            if action_verdict.is_blocking() {
                let mut record =
                    RequestRecord::blocked(provider, &model, &action_verdict.message(), None);
                record.request_hash = Some(request_hash_hex.clone());
                if let Err(e) = state.storage.insert_request(&record) {
                    tracing::error!("blocked-request insert failed: {}", e);
                }
                let what = format!(
                    "{}. Your agent appears stuck repeating the same tool call; it clears once the window drains.",
                    action_verdict.message()
                );
                return Ok(block::build(
                    provider,
                    "action_loop_detected",
                    StatusCode::TOO_MANY_REQUESTS,
                    &what,
                    block::LOOP_REMEDIES,
                    action_verdict.retry_after_secs(),
                ));
            }
        }
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
        let what = format!("{}.", spiral.message());
        return Ok(block::build(
            provider,
            "cost_spiral",
            StatusCode::TOO_MANY_REQUESTS,
            &what,
            block::COST_SPIRAL_REMEDIES,
            spiral.retry_after_secs(),
        ));
    }

    // ─── budget → cheaper-model fallback (#18, opt-in request rewrite) ───
    // When an enforced dollar cap WOULD have blocked above and
    // `budget.fallback_model` is set, rewrite the request's JSON `model` to the
    // fallback and forward — a downgrade that keeps work moving past the cap
    // instead of returning 429. Provider-correct + fail-safe: only the JSON
    // `model` field is touched; if the body isn't JSON or has no `model`, we
    // can't safely downgrade, so we fall back to BLOCKING (never corrupt the
    // body). Modifies the request, so it is logged like cache injection.
    let mut body_bytes = body_bytes;
    if dollar_cap_would_block {
        match fallback_model
            .as_ref()
            .and_then(|fm| rewrite_model_field(&body_bytes, fm).map(|b| (b, fm.clone())))
        {
            Some((rewritten, fm)) => {
                tracing::info!(
                    "💰→🪙 budget cap reached: downgraded {} → {} (model rewrite) and forwarding",
                    model,
                    fm
                );
                body_bytes = rewritten;
            }
            None => {
                // Fallback set but un-rewritable (non-JSON / no model field):
                // block rather than forward an over-budget request unchanged.
                warn!(
                    "💰 budget cap reached and fallback model could not be applied (body not JSON or no model field) — blocking"
                );
                let record = RequestRecord::blocked(provider, &model, "budget_exceeded", None);
                if let Err(e) = state.storage.insert_request(&record) {
                    tracing::error!("blocked-request insert failed: {}", e);
                }
                let what =
                    "Your budget is used up and the cheaper-model fallback could not be applied to this request.".to_string();
                return Ok(block::build(
                    provider,
                    "budget_exceeded",
                    StatusCode::TOO_MANY_REQUESTS,
                    &what,
                    block::BUDGET_REMEDIES,
                    Some(block::seconds_until_local_midnight()),
                ));
            }
        }
    }

    // ─── tool-output trim (#17, opt-in request rewrite) ───
    // Oversized tool results (a dump of a huge file, a verbose test run) get
    // re-sent on every turn of an agent loop and quietly dominate input cost.
    // When `proxy.trim_tool_output` is on, middle-truncate tool-result blocks
    // beyond a keep-head/keep-tail window before forwarding, with an explicit
    // in-band marker so the model knows content was elided. Only tool outputs
    // are touched — never prose, system prompts, or user messages. Fail-open:
    // a body that doesn't parse is forwarded unchanged.
    if state.trim_tool_output {
        let outcome = tool_trim::trim(&body_bytes, tool_trim::DEFAULT_KEEP);
        if outcome.modified {
            tracing::info!(
                "✂️ trimmed {} bytes of oversized tool output before forwarding (proxy.trim_tool_output)",
                outcome.saved_bytes
            );
            body_bytes = outcome.body;
        }
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
    // Cache-savings projection (cache injection OFF): the estimate is an
    // in-memory parse here, but the DB write is deferred to the tee callback
    // (off the response path) instead of a synchronous pre-forward fsync that
    // could stall the request behind a contended write — D-M5.
    let mut cache_projection = None;
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
                cache_projection = Some(projected);
            }
        }
        body_bytes
    };

    // ─── forward (with optional failover) + tee-parse ───
    // Pass the loop hash so the tee can record the arrival on a 2xx (and only
    // then). `None` when this request isn't loop-tracked (GET/body-less).
    let loop_hash = should_track_loop.then_some(request_hash);
    match forwarding::forward(
        parts.method,
        &upstream_base,
        &path_and_query,
        parts.headers,
        forward_body,
        &state,
        provider,
        request_hash_hex,
        loop_hash,
        cache_projection,
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

/// Which credential kind a request carries — drives plan-aware budget
/// enforcement (B-H4). We classify the *kind* only and never read or log the
/// credential value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthKind {
    /// Metered API key (`x-api-key`, or any bearer we can't identify as a
    /// subscription) — real per-token dollars, so the dollar cap applies.
    Metered,
    /// Flat-rate subscription (Claude Pro/Max via an OAuth bearer) — not
    /// metered per token, so the dollar figure is notional.
    Subscription,
}

/// Classify the request's credential kind. Defaults to [`AuthKind::Metered`] so
/// enforcement is only ever *relaxed* for a positively-identified subscription,
/// never weakened for an unknown auth shape.
fn auth_kind(headers: &hyper::HeaderMap, provider: &str) -> AuthKind {
    // An API key is unambiguously metered.
    if headers
        .get("x-api-key")
        .map(|v| !v.is_empty())
        .unwrap_or(false)
    {
        return AuthKind::Metered;
    }
    // Anthropic OAuth tokens (Claude Code on a Pro/Max plan) start with
    // `sk-ant-oat`. The API authenticates with `x-api-key`, so a bearer of this
    // shape is a subscription. We inspect only the prefix; the token is never
    // logged. OpenAI/Google bearers are API-metered, so they fall through to
    // Metered.
    if provider == "anthropic" {
        if let Some(auth) = headers
            .get(hyper::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
        {
            let token = auth
                .strip_prefix("Bearer ")
                .or_else(|| auth.strip_prefix("bearer "))
                .unwrap_or("");
            if token.starts_with("sk-ant-oat") {
                return AuthKind::Subscription;
            }
        }
    }
    AuthKind::Metered
}

/// Self-identifying, actionable block responses (W1-7). Every block Burnwall
/// imposes tells the user: (1) that *Burnwall* did it, before the request left
/// the machine; (2) what matched and where; (3) how to proceed if it's a false
/// positive, escalating inspect → allow-once → narrow → pause → stop; and
/// (4) how to report it. Limit blocks also carry a `Retry-After`. The JSON envelope
/// matches the upstream provider's error shape (P-M2) so the AI tool renders a
/// clean error instead of a raw blob.
pub(crate) mod block {
    use bytes::Bytes;
    use hyper::{Response, StatusCode};
    use serde_json::json;

    use crate::proxy::{ProxyBody, streaming};

    // The escape-hatch lines point at `burnwall allow-once` / `burnwall pause`
    // — runtime toggles the daemon picks up live. (The old advice, "set
    // BURNWALL_BYPASS=1 and restart your AI tool", set the var in the tool's
    // shell where the daemon never saw it: on a backgrounded daemon it did
    // nothing, and it cost the user their agent session to find out.)
    pub const SECURITY_REMEDIES: &[&str] = &[
        "See exactly what was caught:  burnwall security",
        "False positive? Let just the next request through, then auto-restore:  burnwall allow-once",
        "If it's wrong, adjust the rule in ~/.burnwall/config.toml (security.deny_paths / deny_commands), or disable a pack:  burnwall rules disable <pack>",
        "Pause all protection briefly — UNPROTECTED:  burnwall pause   (auto-resumes in 5m; restore early with: burnwall resume)",
        "Turn Burnwall off entirely — UNPROTECTED:  burnwall stop",
    ];
    pub const PARANOID_REMEDIES: &[&str] = &[
        "This block exists because security.paranoid is ON — Burnwall could not inspect this request body, and paranoid mode refuses to forward what it cannot scan.",
        "Let just this next request through, then auto-restore:  burnwall allow-once",
        "Return to the fail-open default:  burnwall config set security.paranoid false",
        "Pause all protection briefly — UNPROTECTED:  burnwall pause   (auto-resumes in 5m)",
    ];
    pub const BUDGET_REMEDIES: &[&str] = &[
        "See today's spend:  burnwall status",
        "Raise or remove the cap:  burnwall config set budget.daily <usd>   (0 = unlimited)",
        "On a flat-rate plan? The dollar cap is notional — plan traffic isn't blocked by default (budget.enforce_on_plan).",
        "Pause all protection briefly — UNPROTECTED:  burnwall pause   (auto-resumes in 5m)",
    ];
    pub const SESSION_REMEDIES: &[&str] = &[
        "Raise or turn off the per-session cap:  burnwall config set budget.per_session <usd>   (0 = off)",
        "Pause all protection briefly — UNPROTECTED:  burnwall pause   (auto-resumes in 5m)",
    ];
    pub const HOURLY_BUDGET_REMEDIES: &[&str] = &[
        "See the current burn rate:  burnwall status",
        "Raise or turn off the hourly brake:  burnwall config set budget.per_hour <usd>   (0 = off)",
        "Keep working past the cap on a cheaper model instead of blocking:  burnwall config set budget.fallback_model <model>",
        "On a flat-rate plan? The dollar cap is notional — plan traffic isn't blocked by default (budget.enforce_on_plan).",
        "Pause all protection briefly — UNPROTECTED:  burnwall pause   (auto-resumes in 5m)",
    ];
    pub const LOOP_REMEDIES: &[&str] = &[
        "This clears on its own once the retry window drains — usually a client resending an identical request.",
        "Tune the threshold:  burnwall config set loop_detection.max_identical_requests <n>",
        "Disable loop detection:  burnwall config set loop_detection.enabled false",
        "Pause all protection briefly — UNPROTECTED:  burnwall pause   (auto-resumes in 5m)",
    ];
    pub const COST_SPIRAL_REMEDIES: &[&str] = &[
        "Raise the window cap:  burnwall config set loop_detection.max_cost_per_window <usd>",
        "Disable spiral blocking:  burnwall config set loop_detection.cost_spiral_enforce false",
        "Pause all protection briefly — UNPROTECTED:  burnwall pause   (auto-resumes in 5m)",
    ];

    /// Seconds until the next local midnight — the daily budget reset time.
    pub fn seconds_until_local_midnight() -> u64 {
        use chrono::Timelike;
        let secs_today = chrono::Local::now().num_seconds_from_midnight() as u64;
        86_400u64.saturating_sub(secs_today).max(1)
    }

    /// Assemble the human-readable block message: self-identify, what/where,
    /// escape hatches, report path.
    fn message(what: &str, remedies: &[&str]) -> String {
        let mut m = String::new();
        m.push_str("🛡️  Burnwall blocked this request before it left your machine.\n");
        m.push_str(what);
        if !remedies.is_empty() {
            m.push_str("\n\nIf this is a false positive, you can:");
            for r in remedies {
                m.push_str("\n  • ");
                m.push_str(r);
            }
        }
        m.push_str(
            "\n\nReport a false positive (nothing leaves your machine):  burnwall report-bug",
        );
        m
    }

    /// Build the provider-correct JSON error response with the block message
    /// and an optional `Retry-After` header.
    pub fn build(
        provider: &str,
        kind: &str,
        status: StatusCode,
        what: &str,
        remedies: &[&str],
        retry_after_secs: Option<u64>,
    ) -> Response<ProxyBody> {
        let msg = message(what, remedies);
        // Match each provider's native error envelope so the client SDK renders
        // it as an error rather than failing to parse an unexpected shape.
        let value = match provider {
            "anthropic" => json!({"type": "error", "error": {"type": kind, "message": msg}}),
            "google" => {
                let gstatus = match status {
                    StatusCode::TOO_MANY_REQUESTS => "RESOURCE_EXHAUSTED",
                    StatusCode::FORBIDDEN => "PERMISSION_DENIED",
                    _ => "FAILED_PRECONDITION",
                };
                json!({"error": {"code": status.as_u16(), "message": msg, "status": gstatus}})
            }
            _ => json!({"error": {"message": msg, "type": kind, "code": kind}}),
        };
        let body = serde_json::to_string(&value).unwrap_or_else(|_| {
            r#"{"error":{"message":"Burnwall blocked this request."}}"#.to_string()
        });

        let mut builder = Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .header("x-burnwall-blocked", kind);
        if let Some(secs) = retry_after_secs {
            builder = builder.header("retry-after", secs.to_string());
        }
        builder
            .body(streaming::full(Bytes::from(body)))
            .expect("block::build: response builder failed")
    }
}

/// Is `rest` (the upstream path, prefix already stripped) a provider
/// file-upload endpoint? Anthropic and OpenAI both expose `/v1/files`, which
/// accepts a `multipart/form-data` body — non-JSON, so the JSON scanner fails
/// open on it. Used to gate the raw-body egress scan (#3). Matches the exact
/// path and any subpath/query (`/v1/files`, `/v1/files?…`, `/v1/files/…`).
fn is_file_upload_route(rest: &str) -> bool {
    let path = rest.split('?').next().unwrap_or(rest);
    path == "/v1/files" || path.starts_with("/v1/files/")
}

/// Cheap check: does `body` look like a JSON document? A multipart upload
/// starts with a boundary marker (`--…`), never `{`/`[`, so this distinguishes
/// a JSON chat/files-metadata body (handled by the JSON scanner) from a raw
/// file upload (handled by the raw egress scan). Skips a leading UTF-8 BOM and
/// ASCII whitespace before looking at the first significant byte.
fn looks_like_json(body: &[u8]) -> bool {
    let body = body.strip_prefix(b"\xef\xbb\xbf").unwrap_or(body);
    let first = body.iter().copied().find(|b| !b.is_ascii_whitespace());
    matches!(first, Some(b'{') | Some(b'['))
}

/// Best-effort extraction of the `model` field from a request body. Used
/// to populate `RequestRecord.model` even when the request was blocked.
fn extract_model(body: &[u8]) -> Option<String> {
    let body = body.strip_prefix(b"\xef\xbb\xbf").unwrap_or(body);
    let val: serde_json::Value = serde_json::from_slice(body).ok()?;
    val.get("model").and_then(|m| m.as_str()).map(String::from)
}

/// Provider-correct, fail-safe rewrite of the JSON `model` field to
/// `new_model`, used by the budget→cheaper-model fallback (#18). Returns the
/// rewritten body, or `None` when the rewrite must NOT be applied:
///
/// - the body is not valid JSON (e.g. a multipart upload),
/// - the top-level value is not a JSON object,
/// - there is no existing string `model` field, or
/// - re-serialization fails.
///
/// Returning `None` is the fail-safe signal — the caller blocks rather than
/// forward an over-budget request, never corrupting the body. Only the `model`
/// field is changed; every other byte of structure is preserved. This is the
/// same field all three providers (Anthropic / OpenAI / Google REST) name
/// `model`, so it is provider-correct.
fn rewrite_model_field(body: &[u8], new_model: &str) -> Option<bytes::Bytes> {
    let stripped = body.strip_prefix(b"\xef\xbb\xbf").unwrap_or(body);
    let mut value: serde_json::Value = serde_json::from_slice(stripped).ok()?;
    let obj = value.as_object_mut()?;
    // Only rewrite when a string `model` field is actually present — a body
    // with no model (or a non-string model) is one we can't safely downgrade.
    match obj.get("model") {
        Some(serde_json::Value::String(_)) => {}
        _ => return None,
    }
    obj.insert(
        "model".to_string(),
        serde_json::Value::String(new_model.to_string()),
    );
    serde_json::to_vec(&value).ok().map(bytes::Bytes::from)
}

/// Cheap 200 OK response for `/healthz` probes.
fn healthz_response() -> Response<ProxyBody> {
    let body = r#"{"status":"ok","service":"burnwall"}"#;
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(streaming::full(Bytes::from(body)))
        .expect("healthz_response: builder")
}

/// Read BURNWALL_BYPASS each call (no caching) so a user can flip it without
/// restarting the proxy. Truthy values: `1`, `true`, `yes`, `on` (case-
/// insensitive).
/// Extract a non-empty `x-burnwall-session` header value, if present. Shared
/// shape with the forwarder so enforcement (here) and recording (there) key on
/// the same id.
pub fn session_from_headers(headers: &hyper::HeaderMap) -> Option<String> {
    headers
        .get("x-burnwall-session")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn bypass_active() -> bool {
    match std::env::var("BURNWALL_BYPASS") {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => false,
    }
}

/// Pure-relay path used only when [`bypass_active`] is true. Routes by URL
/// prefix, forwards the request as-is to the upstream, streams the response
/// back. No security scan, no storage, no parsing.
async fn passthrough(req: Request<Incoming>, state: &Arc<AppState>) -> Response<ProxyBody> {
    let path = req.uri().path().to_string();
    let routed: Option<(String, String)> =
        if path == "/anthropic" || path.starts_with("/anthropic/") {
            Some((
                state.upstream_anthropic.clone(),
                path["/anthropic".len()..].to_string(),
            ))
        } else if path == "/openai" || path.starts_with("/openai/") {
            Some((
                state.upstream_openai.clone(),
                path["/openai".len()..].to_string(),
            ))
        } else if path == "/google" || path.starts_with("/google/") {
            Some((
                state.upstream_google.clone(),
                path["/google".len()..].to_string(),
            ))
        } else {
            None
        };
    let (upstream_base, rest) = match routed {
        Some(r) => r,
        None => {
            return error_response(
                StatusCode::NOT_FOUND,
                "proxy_error",
                "Unknown route. Use /anthropic/*, /openai/*, or /google/* prefix.",
            );
        }
    };
    let mut path_and_query = rest;
    if let Some(q) = req.uri().query() {
        path_and_query.push('?');
        path_and_query.push_str(q);
    }
    let (parts, body) = req.into_parts();
    let body_bytes = match body.collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "proxy_error",
                "Failed to read request body.",
            );
        }
    };
    match forwarding::passthrough(
        parts.method,
        &upstream_base,
        &path_and_query,
        parts.headers,
        body_bytes,
        state,
    )
    .await
    {
        Ok(resp) => resp,
        Err(e) => {
            warn!(
                "bypass upstream error for {}{}: {}",
                upstream_base, path_and_query, e
            );
            error_response(
                StatusCode::BAD_GATEWAY,
                "proxy_error",
                &format!("Upstream unreachable: {}", e),
            )
        }
    }
}
