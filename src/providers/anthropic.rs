//! Anthropic Messages API response parser.
//!
//! Two response shapes are handled:
//!
//! - **Non-streaming** (default): one JSON object with a top-level `model`
//!   and `usage`. Parsed by [`parse`].
//! - **SSE streaming** (`stream: true`): a sequence of `event:` / `data:`
//!   lines. The model and prompt-token counts arrive in the `message_start`
//!   event; the final `output_tokens` arrives in `message_delta`. Parsed by
//!   [`parse_sse`].
//!
//! Use [`parse_any`] when you don't know which shape the response will be —
//! it tries non-streaming first, then SSE.

use serde::Deserialize;

use super::{ParseError, ParsedResponse, TokenUsage};

#[derive(Deserialize)]
struct Response {
    model: String,
    usage: Usage,
}

#[derive(Deserialize, Default)]
struct Usage {
    #[serde(default)]
    input_tokens: u64,
    #[serde(default)]
    output_tokens: u64,
    #[serde(default)]
    cache_creation_input_tokens: u64,
    #[serde(default)]
    cache_read_input_tokens: u64,
}

/// Parse a non-streaming Messages API response body.
pub fn parse(body: &[u8]) -> Result<ParsedResponse, ParseError> {
    let r: Response = serde_json::from_slice(body)?;
    Ok(ParsedResponse {
        model: r.model,
        usage: TokenUsage {
            input_tokens: r.usage.input_tokens,
            output_tokens: r.usage.output_tokens,
            cache_creation_tokens: r.usage.cache_creation_input_tokens,
            cache_read_tokens: r.usage.cache_read_input_tokens,
        },
    })
}

/// Parse an SSE stream body — concatenated `event:`/`data:` lines.
/// Returns `None` if no `model` is found (means we can't price the call).
pub fn parse_sse(body: &[u8]) -> Option<ParsedResponse> {
    let text = std::str::from_utf8(body).ok()?;
    let mut model: Option<String> = None;
    let mut input_tokens: u64 = 0;
    let mut output_tokens: u64 = 0;
    let mut cache_creation: u64 = 0;
    let mut cache_read: u64 = 0;

    for line in text.lines() {
        let Some(json_str) = line.strip_prefix("data: ") else {
            continue;
        };
        let Ok(val) = serde_json::from_str::<serde_json::Value>(json_str) else {
            continue;
        };
        let event_type = val.get("type").and_then(|t| t.as_str()).unwrap_or("");
        match event_type {
            "message_start" => {
                if let Some(message) = val.get("message") {
                    if model.is_none() {
                        model = message
                            .get("model")
                            .and_then(|m| m.as_str())
                            .map(String::from);
                    }
                    if let Some(usage) = message.get("usage") {
                        input_tokens = u64_field(usage, "input_tokens");
                        cache_creation = u64_field(usage, "cache_creation_input_tokens");
                        cache_read = u64_field(usage, "cache_read_input_tokens");
                        // `message_delta.usage.output_tokens` overrides this.
                        let initial_out = u64_field(usage, "output_tokens");
                        if initial_out > output_tokens {
                            output_tokens = initial_out;
                        }
                    }
                }
            }
            "message_delta" => {
                if let Some(usage) = val.get("usage") {
                    // Anthropic emits the running output_tokens here; take
                    // the max so we get the final tally.
                    let n = u64_field(usage, "output_tokens");
                    if n > output_tokens {
                        output_tokens = n;
                    }
                }
            }
            _ => {}
        }
    }

    Some(ParsedResponse {
        model: model?,
        usage: TokenUsage {
            input_tokens,
            output_tokens,
            cache_creation_tokens: cache_creation,
            cache_read_tokens: cache_read,
        },
    })
}

/// Try [`parse`] (non-streaming JSON), then [`parse_sse`]. Returns the first
/// success or `None`.
pub fn parse_any(body: &[u8]) -> Option<ParsedResponse> {
    if let Ok(p) = parse(body) {
        return Some(p);
    }
    parse_sse(body)
}

fn u64_field(obj: &serde_json::Value, key: &str) -> u64 {
    obj.get(key).and_then(|v| v.as_u64()).unwrap_or(0)
}
