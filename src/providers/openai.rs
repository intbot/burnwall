//! OpenAI Chat Completions + Responses API response parser.
//!
//! Two APIs, each with a streaming and non-streaming shape:
//! - **Chat Completions** (`/v1/chat/completions`): `usage` carries
//!   `prompt_tokens` / `completion_tokens` / `prompt_tokens_details.cached_tokens`.
//! - **Responses API** (`/v1/responses`, what Codex CLI defaults to): `usage`
//!   carries `input_tokens` / `output_tokens` / `input_tokens_details.cached_tokens`.
//!
//! Non-streaming bodies for both are a single JSON with top-level `model` +
//! `usage` — [`parse`] handles both via serde field aliases. SSE streams
//! differ: Chat Completions puts `model`/`usage` at the top of a chunk (when
//! `stream_options.include_usage` is set, typically the second-to-last chunk);
//! the Responses API nests them under `response` in typed events, with usage
//! arriving on the `response.completed` event — [`parse_sse`] handles both.
//!
//! [`parse_any`] tries non-streaming first, then SSE — and treats an all-zero
//! usage as a parse failure: every `Usage` field is `#[serde(default)]`, so an
//! unrecognized usage shape would otherwise "succeed" with zero tokens and be
//! recorded as a $0 row. A real response always bills at least one input
//! token; all-zero is the signature of a shape we didn't understand.
//!
//! Normalization: the prompt/input count is the TOTAL prompt size (cached +
//! not) in both APIs. We subtract the cached portion to produce the
//! `input_tokens` (non-cached) field of [`TokenUsage`]. OpenAI never has
//! cache writes — caching is automatic, no opt-in.

use serde::Deserialize;

use super::{ParseError, ParsedResponse, TokenUsage};

#[derive(Deserialize)]
struct Response {
    model: String,
    usage: Usage,
}

/// Usage block for both OpenAI APIs. The aliases map the Responses API
/// field names (`input_tokens` / `output_tokens` / `input_tokens_details`)
/// onto the Chat Completions ones — the semantics are identical (totals
/// including the cached portion), only the names differ.
#[derive(Deserialize, Default, Clone)]
struct Usage {
    #[serde(default, alias = "input_tokens")]
    prompt_tokens: u64,
    #[serde(default, alias = "output_tokens")]
    completion_tokens: u64,
    #[serde(default, alias = "input_tokens_details")]
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

/// Parse a non-streaming response body — Chat Completions or Responses API
/// (both have top-level `model` + `usage`; the field aliases on [`Usage`]
/// absorb the naming difference).
pub fn parse(body: &[u8]) -> Result<ParsedResponse, ParseError> {
    let r: Response = serde_json::from_slice(body)?;
    Ok(to_parsed(r.model, r.usage))
}

/// Parse an SSE stream body — Chat Completions chunks or Responses API
/// events. Looks for a non-empty `usage` block (top-level for Chat
/// Completions, under `response` for Responses API events — usage rides on
/// `response.completed`); reports the first `model` seen.
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
        // Responses API events (`response.created`, `response.completed`, …)
        // nest the payload under `response`; Chat Completions chunks carry
        // `model`/`usage` at the top level. Events without a `response`
        // object (e.g. `response.output_text.delta`) fall through harmlessly.
        let payload = val.get("response").unwrap_or(&val);
        if model.is_none() {
            model = payload
                .get("model")
                .and_then(|m| m.as_str())
                .map(String::from);
        }
        if let Some(usage_val) = payload.get("usage") {
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
///
/// All-zero guard: every [`Usage`] field is `#[serde(default)]`, so a body
/// whose usage shape we don't recognize deserializes "successfully" with
/// zero in every bucket. Recording that would silently book a $0 row for a
/// request that cost real money — worse than not recording, because it looks
/// covered. A billable response always has `input_tokens > 0` (a prompt was
/// processed), so all-zero is treated as a parse failure and the caller's
/// not-recorded warning fires instead.
pub fn parse_any(body: &[u8]) -> Option<ParsedResponse> {
    if let Ok(p) = parse(body) {
        if p.usage.total() > 0 {
            return Some(p);
        }
        // Structurally valid JSON but no recognized usage fields — fall
        // through to the SSE parser, then report failure.
    }
    parse_sse(body).filter(|p| p.usage.total() > 0)
}
