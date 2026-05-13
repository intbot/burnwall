//! Provider response parsers.
//!
//! Each provider parser turns an HTTP response body (raw JSON bytes) into a
//! provider-neutral [`ParsedResponse`] carrying the model name and a
//! normalized [`TokenUsage`]. Downstream code (pricing, storage) only deals
//! with the unified type — never the provider-specific JSON shape.

pub mod anthropic;
pub mod google;
pub mod openai;

/// Provider-neutral token counts.
///
/// All four buckets are billed independently. For Anthropic, the response
/// already splits non-cached input from cache writes and reads. For OpenAI,
/// `prompt_tokens` includes the cached portion, so the parser subtracts to
/// produce `input_tokens` (non-cached) and `cache_read_tokens` (cached).
/// OpenAI never has cache writes (caching is automatic, no opt-in).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TokenUsage {
    /// Non-cached input tokens, billed at the base input rate.
    pub input_tokens: u64,
    /// Output / completion tokens, billed at the output rate.
    pub output_tokens: u64,
    /// Tokens written to cache this turn, billed at the cache-write rate
    /// (Anthropic: 1.25× input for 5-min cache, 2× for 1-hour). Always 0
    /// for OpenAI.
    pub cache_creation_tokens: u64,
    /// Tokens served from cache, billed at the cache-read rate
    /// (Anthropic: 0.1×, OpenAI: 0.5×).
    pub cache_read_tokens: u64,
}

impl TokenUsage {
    pub fn total(&self) -> u64 {
        self.input_tokens + self.output_tokens + self.cache_creation_tokens + self.cache_read_tokens
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedResponse {
    pub model: String,
    pub usage: TokenUsage,
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("response JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
}
