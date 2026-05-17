//! Anthropic prompt-cache auto-injection (opt-in).
//!
//! When enabled, rewrites Messages API requests to add
//! `cache_control: {"type": "ephemeral"}` markers on two stable blocks:
//! the system prompt and the first message's content. Requests that
//! already carry any `cache_control` marker are left untouched — we never
//! override the caching choices the caller already made.
//!
//! Off by default. Burnwall does not modify request bodies silently;
//! enabling injection is an explicit opt-in via config or CLI flag.

use bytes::Bytes;
use serde_json::{json, Value};

/// Outcome of an attempt to rewrite a request body.
#[derive(Debug, Clone)]
pub struct InjectionOutcome {
    /// The body to forward upstream — original if no rewrite was applied.
    pub body: Bytes,
    /// True when the body was rewritten and differs from the input.
    pub modified: bool,
}

/// Inject `cache_control` markers when the body is an Anthropic Messages
/// API request without any existing markers. Returns the original body
/// untouched when:
///
/// - the body is not valid JSON (fail-open),
/// - the body already contains any `cache_control` marker,
/// - there is no system prompt and no messages to mark, or
/// - serializing the rewritten value fails.
pub fn inject_if_eligible(body: &Bytes) -> InjectionOutcome {
    let Ok(mut value) = serde_json::from_slice::<Value>(body) else {
        return InjectionOutcome {
            body: body.clone(),
            modified: false,
        };
    };

    if has_cache_control(&value) {
        return InjectionOutcome {
            body: body.clone(),
            modified: false,
        };
    }

    let marked_system = match value.get_mut("system") {
        Some(sys) => mark_value(sys),
        None => false,
    };

    let marked_first_message = value
        .get_mut("messages")
        .and_then(Value::as_array_mut)
        .and_then(|arr| arr.first_mut())
        .and_then(|msg| msg.get_mut("content"))
        .map(mark_value)
        .unwrap_or(false);

    if !marked_system && !marked_first_message {
        return InjectionOutcome {
            body: body.clone(),
            modified: false,
        };
    }

    match serde_json::to_vec(&value) {
        Ok(v) => InjectionOutcome {
            body: Bytes::from(v),
            modified: true,
        },
        Err(_) => InjectionOutcome {
            body: body.clone(),
            modified: false,
        },
    }
}

/// Add an ephemeral cache_control marker to `v`. Strings are widened
/// into a single-element text-block array so the marker has somewhere
/// to live; arrays get the marker on the last block. Anything else is
/// left alone.
fn mark_value(v: &mut Value) -> bool {
    match v {
        Value::String(s) => {
            let original = std::mem::take(s);
            *v = json!([{
                "type": "text",
                "text": original,
                "cache_control": {"type": "ephemeral"},
            }]);
            true
        }
        Value::Array(arr) => {
            let Some(last) = arr.last_mut() else {
                return false;
            };
            let Some(obj) = last.as_object_mut() else {
                return false;
            };
            obj.insert("cache_control".to_string(), json!({"type": "ephemeral"}));
            true
        }
        _ => false,
    }
}

fn has_cache_control(v: &Value) -> bool {
    match v {
        Value::Object(map) => {
            map.contains_key("cache_control") || map.values().any(has_cache_control)
        }
        Value::Array(arr) => arr.iter().any(has_cache_control),
        _ => false,
    }
}

/// Path on the Anthropic side where cache injection is meaningful. The
/// proxy strips its own `/anthropic` prefix, so a request to
/// `/anthropic/v1/messages` arrives here as `/v1/messages`.
pub fn is_messages_path(rest: &str) -> bool {
    rest == "/v1/messages" || rest.starts_with("/v1/messages?")
}

/// Rough heuristic for English-text tokens. The Anthropic tokenizer is
/// not bundled, so the projection deliberately stays approximate.
const CHARS_PER_TOKEN_ESTIMATE: f64 = 4.0;

/// Estimate the steady-state cache savings, in USD, that would have
/// applied to this Anthropic request if `cache_injection` were enabled.
/// Returns 0.0 when:
///
/// - the body is not a valid Messages-API JSON request,
/// - the request already carries any `cache_control` marker (the user is
///   already opted in — there are no foregone savings to surface),
/// - the model is unknown to the pricing table, or
/// - no eligible content (system + first message) is present.
///
/// The projection ignores the one-time cache *write* premium on the
/// first request and reports the after-warm-up per-request delta:
/// `(input_per_mtok − cache_read_per_mtok) × eligible_tokens / 1M`.
/// Status surfaces this as "Cache injection (off): est. $X foregone
/// today" so users have a number to weigh before flipping the switch.
pub fn estimate_savings_usd(body: &[u8]) -> f64 {
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return 0.0;
    };
    if has_cache_control(&value) {
        return 0.0;
    }
    let Some(model) = value.get("model").and_then(Value::as_str) else {
        return 0.0;
    };
    let Some(pricing) = crate::pricing::get_pricing(model) else {
        return 0.0;
    };

    let mut chars: usize = 0;
    if let Some(sys) = value.get("system") {
        chars += count_eligible_chars(sys);
    }
    if let Some(first_content) = value
        .get("messages")
        .and_then(Value::as_array)
        .and_then(|arr| arr.first())
        .and_then(|m| m.get("content"))
    {
        chars += count_eligible_chars(first_content);
    }
    if chars == 0 {
        return 0.0;
    }

    let tokens = chars as f64 / CHARS_PER_TOKEN_ESTIMATE;
    let savings_per_token = (pricing.input_per_mtok - pricing.cache_read_per_mtok) / 1_000_000.0;
    let savings = tokens * savings_per_token;
    if savings.is_finite() && savings > 0.0 {
        savings
    } else {
        0.0
    }
}

/// Sum of textual characters reachable from `v`. Strings count their own
/// length; arrays of content blocks sum each block's `text` field;
/// objects sum the same field if present. Anything else contributes 0.
fn count_eligible_chars(v: &Value) -> usize {
    match v {
        Value::String(s) => s.chars().count(),
        Value::Array(arr) => arr.iter().map(count_eligible_chars).sum(),
        Value::Object(map) => map
            .get("text")
            .and_then(Value::as_str)
            .map(|s| s.chars().count())
            .unwrap_or(0),
        _ => 0,
    }
}
