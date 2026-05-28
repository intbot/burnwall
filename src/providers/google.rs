//! Google Gemini API response parser (v0.7).
//!
//! Handles the `generateContent` response shape and its SSE streaming
//! counterpart (`streamGenerateContent?alt=sse`). Token counts come from the
//! `usageMetadata` block; the model from `modelVersion`.
//!
//! ## Token normalization
//!
//! Gemini's `promptTokenCount` is the TOTAL prompt size, cached portion
//! included — like OpenAI's `prompt_tokens`. We subtract
//! `cachedContentTokenCount` to get the non-cached `input_tokens` and surface
//! the cached part as `cache_read_tokens`. `thoughtsTokenCount` (thinking
//! models) is billed at the output rate, so it folds into `output_tokens`.
//! Gemini has no per-response cache-write count, so `cache_creation_tokens`
//! is always 0.

use serde::Deserialize;

use super::{ParseError, ParsedResponse, TokenUsage};

#[derive(Deserialize)]
struct Response {
    #[serde(rename = "modelVersion")]
    model_version: Option<String>,
    #[serde(rename = "usageMetadata")]
    usage_metadata: UsageMetadata,
}

#[derive(Deserialize, Default, Clone)]
struct UsageMetadata {
    #[serde(default, rename = "promptTokenCount")]
    prompt_token_count: u64,
    #[serde(default, rename = "candidatesTokenCount")]
    candidates_token_count: u64,
    #[serde(default, rename = "cachedContentTokenCount")]
    cached_content_token_count: u64,
    #[serde(default, rename = "thoughtsTokenCount")]
    thoughts_token_count: u64,
}

fn to_usage(u: &UsageMetadata) -> TokenUsage {
    let cached = u.cached_content_token_count;
    let non_cached_input = u.prompt_token_count.saturating_sub(cached);
    TokenUsage {
        input_tokens: non_cached_input,
        // Thinking tokens are billed at the output rate.
        output_tokens: u.candidates_token_count + u.thoughts_token_count,
        cache_creation_tokens: 0,
        cache_read_tokens: cached,
    }
}

/// Parse a non-streaming `generateContent` response body. Errors if the JSON
/// is invalid or `usageMetadata` is missing.
pub fn parse(body: &[u8]) -> Result<ParsedResponse, ParseError> {
    let r: Response = serde_json::from_slice(body)?;
    Ok(ParsedResponse {
        // The request path carries the model for Gemini, but the response
        // echoes it as `modelVersion`; fall back to "gemini" so the row is
        // still recorded (pricing lookup then misses → cost 0, fail-open).
        model: r.model_version.unwrap_or_else(|| "gemini".to_string()),
        usage: to_usage(&r.usage_metadata),
    })
}

/// Parse an SSE stream body — `data: {chunk}` lines. Gemini emits cumulative
/// `usageMetadata`; we keep the last non-empty one and the first `modelVersion`
/// seen.
pub fn parse_sse(body: &[u8]) -> Option<ParsedResponse> {
    let text = std::str::from_utf8(body).ok()?;
    let mut model: Option<String> = None;
    let mut usage: Option<UsageMetadata> = None;

    for line in text.lines() {
        let Some(json_str) = line.strip_prefix("data: ") else {
            continue;
        };
        let trimmed = json_str.trim();
        if trimmed.is_empty() || trimmed == "[DONE]" {
            continue;
        }
        let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) else {
            continue;
        };
        if model.is_none() {
            model = val
                .get("modelVersion")
                .and_then(|m| m.as_str())
                .map(String::from);
        }
        if let Some(um) = val.get("usageMetadata") {
            if let Ok(u) = serde_json::from_value::<UsageMetadata>(um.clone()) {
                if u.prompt_token_count > 0 || u.candidates_token_count > 0 {
                    usage = Some(u);
                }
            }
        }
    }

    let usage = usage?;
    Some(ParsedResponse {
        model: model.unwrap_or_else(|| "gemini".to_string()),
        usage: to_usage(&usage),
    })
}

/// Try [`parse`] (non-streaming JSON), then [`parse_sse`].
pub fn parse_any(body: &[u8]) -> Option<ParsedResponse> {
    if let Ok(p) = parse(body) {
        return Some(p);
    }
    parse_sse(body)
}
