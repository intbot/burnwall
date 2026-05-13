//! OpenAI Chat Completions API response parser.
//!
//! Two response shapes:
//! - **Non-streaming**: single JSON with `model` + `usage` block. [`parse`].
//! - **SSE streaming** (when `stream_options.include_usage` is set): a stream
//!   of `data: {...}` chunks where one — typically the second-to-last — has
//!   a populated `usage` field. [`parse_sse`].
//!
//! [`parse_any`] tries non-streaming first, then SSE.
//!
//! Normalization: `prompt_tokens` is the TOTAL prompt size (cached + not).
//! We subtract `prompt_tokens_details.cached_tokens` to produce the
//! `input_tokens` (non-cached) field of [`TokenUsage`]. OpenAI never has
//! cache writes — caching is automatic, no opt-in.

use serde::Deserialize;

use super::{ParseError, ParsedResponse, TokenUsage};

#[derive(Deserialize)]
struct Response {
    model: String,
    usage: Usage,
}

#[derive(Deserialize, Default, Clone)]
struct Usage {
    #[serde(default)]
    prompt_tokens: u64,
    #[serde(default)]
    completion_tokens: u64,
    #[serde(default)]
    prompt_tokens_details: PromptDetails,
}

#[derive(Deserialize, Default, Clone)]
struct PromptDetails {
    #[serde(default)]
    cached_tokens: u64,
}

fn to_parsed(model: String, usage: Usage) -> ParsedResponse {
    let cached = usage.prompt_tokens_details.cached_tokens;
    let non_cached_input = usage.prompt_tokens.saturating_sub(cached);
    ParsedResponse {
        model,
        usage: TokenUsage {
            input_tokens: non_cached_input,
            output_tokens: usage.completion_tokens,
            cache_creation_tokens: 0,
            cache_read_tokens: cached,
        },
    }
}

/// Parse a non-streaming Chat Completions response body.
pub fn parse(body: &[u8]) -> Result<ParsedResponse, ParseError> {
    let r: Response = serde_json::from_slice(body)?;
    Ok(to_parsed(r.model, r.usage))
}

/// Parse an SSE stream body. Looks for the chunk with a non-empty `usage`
/// field; reports the first `model` seen.
pub fn parse_sse(body: &[u8]) -> Option<ParsedResponse> {
    let text = std::str::from_utf8(body).ok()?;
    let mut model: Option<String> = None;
    let mut usage: Option<Usage> = None;

    for line in text.lines() {
        let Some(json_str) = line.strip_prefix("data: ") else {
            continue;
        };
        if json_str.trim() == "[DONE]" {
            continue;
        }
        let Ok(val) = serde_json::from_str::<serde_json::Value>(json_str) else {
            continue;
        };
        if model.is_none() {
            model = val.get("model").and_then(|m| m.as_str()).map(String::from);
        }
        if let Some(usage_val) = val.get("usage") {
            if !usage_val.is_null() {
                if let Ok(u) = serde_json::from_value::<Usage>(usage_val.clone()) {
                    // Keep the most recent non-empty usage block.
                    if u.prompt_tokens > 0 || u.completion_tokens > 0 {
                        usage = Some(u);
                    }
                }
            }
        }
    }

    Some(to_parsed(model?, usage?))
}

/// Try [`parse`] (non-streaming JSON), then [`parse_sse`].
pub fn parse_any(body: &[u8]) -> Option<ParsedResponse> {
    if let Ok(p) = parse(body) {
        return Some(p);
    }
    parse_sse(body)
}
