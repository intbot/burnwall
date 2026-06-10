//! Provider response parser tests using the fixture JSON files in
//! `tests/fixtures/`. Each fixture is a real (sanitized) sample of what the
//! provider returns; parsing must produce the exact token counts and preserve
//! the date-stamped model ID verbatim (pricing lookup handles normalization).

use std::fs;

use burnwall::providers::{anthropic, google, openai, TokenUsage};

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("tests/fixtures/{}", name);
    fs::read(&path).unwrap_or_else(|e| panic!("read {}: {}", path, e))
}

// ─────────────────────────────── Anthropic ───────────────────────────────

#[test]
fn anthropic_uncached_parses_zero_cache_buckets() {
    let parsed = anthropic::parse(&fixture("anthropic_uncached.json")).expect("parse");

    assert_eq!(parsed.model, "claude-haiku-4-5-20251001");
    assert_eq!(
        parsed.usage,
        TokenUsage {
            input_tokens: 53248,
            output_tokens: 1024,
            cache_creation_tokens: 0,
            cache_read_tokens: 0,
        }
    );
}

#[test]
fn anthropic_cached_splits_write_and_read_buckets() {
    let parsed = anthropic::parse(&fixture("anthropic_cached.json")).expect("parse");

    assert_eq!(parsed.model, "claude-sonnet-4-6-20250514");
    assert_eq!(
        parsed.usage,
        TokenUsage {
            input_tokens: 512,
            output_tokens: 28,
            cache_creation_tokens: 8192,
            cache_read_tokens: 45056,
        }
    );
    // Sanity: total exceeds non-cached input, as expected with caching active.
    assert_eq!(parsed.usage.total(), 512 + 28 + 8192 + 45056);
}

#[test]
fn anthropic_missing_cache_fields_defaults_to_zero() {
    // Real responses sometimes omit cache fields entirely when no caching is
    // in use. The parser must treat them as 0, not error out.
    let body = br#"{"model":"claude-sonnet-4-6","usage":{"input_tokens":100,"output_tokens":50}}"#;
    let parsed = anthropic::parse(body).expect("parse with no cache fields");

    assert_eq!(parsed.usage.input_tokens, 100);
    assert_eq!(parsed.usage.output_tokens, 50);
    assert_eq!(parsed.usage.cache_creation_tokens, 0);
    assert_eq!(parsed.usage.cache_read_tokens, 0);
}

#[test]
fn anthropic_invalid_json_returns_error() {
    assert!(anthropic::parse(b"not valid json").is_err());
}

#[test]
fn anthropic_missing_usage_block_returns_error() {
    let body = br#"{"model":"claude-sonnet-4-6","content":[]}"#;
    assert!(anthropic::parse(body).is_err());
}

// ──────────────────────────────── OpenAI ────────────────────────────────

#[test]
fn openai_uncached_yields_full_prompt_as_input() {
    let parsed = openai::parse(&fixture("openai_uncached.json")).expect("parse");

    assert_eq!(parsed.model, "gpt-5.4-mini-2026-03-01");
    assert_eq!(
        parsed.usage,
        TokenUsage {
            input_tokens: 4096,
            output_tokens: 256,
            cache_creation_tokens: 0,
            cache_read_tokens: 0,
        }
    );
}

#[test]
fn openai_cached_subtracts_cached_from_prompt_tokens() {
    let parsed = openai::parse(&fixture("openai_cached.json")).expect("parse");

    // prompt_tokens=2048, cached_tokens=1536 → input=512, cache_read=1536
    assert_eq!(parsed.model, "gpt-5.4-2026-01-15");
    assert_eq!(
        parsed.usage,
        TokenUsage {
            input_tokens: 512,
            output_tokens: 512,
            cache_creation_tokens: 0,
            cache_read_tokens: 1536,
        }
    );
}

#[test]
fn openai_missing_prompt_tokens_details_defaults_to_zero_cache() {
    let body = br#"{"model":"gpt-5.4","usage":{"prompt_tokens":100,"completion_tokens":50}}"#;
    let parsed = openai::parse(body).expect("parse without prompt_tokens_details");

    assert_eq!(parsed.usage.input_tokens, 100);
    assert_eq!(parsed.usage.cache_read_tokens, 0);
}

#[test]
fn openai_invalid_json_returns_error() {
    assert!(openai::parse(b"<html>").is_err());
}

// ──────────────────────── OpenAI Responses API ──────────────────────────

#[test]
fn openai_responses_api_body_parses_input_output_and_cached() {
    // /v1/responses (Codex CLI default) names the usage fields
    // input_tokens/output_tokens/input_tokens_details — same semantics as
    // Chat Completions (input includes the cached portion), different names.
    let body = br#"{
        "id": "resp_abc123",
        "object": "response",
        "status": "completed",
        "model": "gpt-5.4-codex",
        "output": [{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "ok"}]}],
        "usage": {
            "input_tokens": 2048,
            "input_tokens_details": {"cached_tokens": 1536},
            "output_tokens": 256,
            "output_tokens_details": {"reasoning_tokens": 64},
            "total_tokens": 2304
        }
    }"#;
    let parsed = openai::parse(body).expect("parse Responses API body");

    // input_tokens=2048, cached=1536 → non-cached input=512, cache_read=1536
    assert_eq!(parsed.model, "gpt-5.4-codex");
    assert_eq!(
        parsed.usage,
        TokenUsage {
            input_tokens: 512,
            output_tokens: 256,
            cache_creation_tokens: 0,
            cache_read_tokens: 1536,
        }
    );

    // The proxy tee goes through parse_any — same result.
    assert_eq!(openai::parse_any(body), Some(parsed));
}

#[test]
fn openai_responses_api_sse_reads_usage_from_completed_event() {
    // Responses API streaming nests model/usage under `response` in typed
    // events; usage arrives on the final `response.completed` event.
    let sse = "event: response.created\n\
data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_1\",\"model\":\"gpt-5.4-codex\",\"status\":\"in_progress\",\"usage\":null}}\n\
\n\
event: response.output_text.delta\n\
data: {\"type\":\"response.output_text.delta\",\"delta\":\"Hello\"}\n\
\n\
event: response.completed\n\
data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"model\":\"gpt-5.4-codex\",\"status\":\"completed\",\"usage\":{\"input_tokens\":1000,\"input_tokens_details\":{\"cached_tokens\":400},\"output_tokens\":50,\"total_tokens\":1050}}}\n\n";

    let parsed = openai::parse_sse(sse.as_bytes()).expect("sse parse");
    assert_eq!(parsed.model, "gpt-5.4-codex");
    assert_eq!(
        parsed.usage,
        TokenUsage {
            input_tokens: 600,
            output_tokens: 50,
            cache_creation_tokens: 0,
            cache_read_tokens: 400,
        }
    );
}

#[test]
fn openai_chat_completions_still_parses_via_parse_any() {
    // The Responses API support must not disturb the Chat Completions path
    // the tee already relies on.
    let parsed = openai::parse_any(&fixture("openai_cached.json")).expect("parse_any");
    assert_eq!(parsed.model, "gpt-5.4-2026-01-15");
    assert_eq!(
        parsed.usage,
        TokenUsage {
            input_tokens: 512,
            output_tokens: 512,
            cache_creation_tokens: 0,
            cache_read_tokens: 1536,
        }
    );
}

#[test]
fn openai_all_zero_usage_returns_none_from_parse_any() {
    // Every Usage field is #[serde(default)], so an unrecognized usage shape
    // deserializes "successfully" with zero tokens. parse_any must treat that
    // as a parse failure (None → tee warns) instead of recording a $0 row.
    let empty_usage = br#"{"model":"gpt-5.4","usage":{}}"#;
    assert_eq!(openai::parse_any(empty_usage), None);

    let unknown_shape = br#"{"model":"gpt-5.4","usage":{"weird_tokens":123}}"#;
    assert_eq!(openai::parse_any(unknown_shape), None);
}

#[test]
fn openai_zero_output_with_nonzero_input_still_parses() {
    // The all-zero guard must not reject legitimate edge cases: a response
    // that billed input but produced no output tokens is still a real,
    // billable response.
    let body = br#"{"model":"gpt-5.4","usage":{"prompt_tokens":300,"completion_tokens":0}}"#;
    let parsed = openai::parse_any(body).expect("nonzero input must parse");
    assert_eq!(parsed.usage.input_tokens, 300);
    assert_eq!(parsed.usage.output_tokens, 0);
}

// ──────────────────────────────── Google ────────────────────────────────

#[test]
fn google_uncached_yields_full_prompt_as_input() {
    let parsed = google::parse(&fixture("google_uncached.json")).expect("parse");

    assert_eq!(parsed.model, "gemini-2.5-pro");
    assert_eq!(
        parsed.usage,
        TokenUsage {
            input_tokens: 4096,
            output_tokens: 256,
            cache_creation_tokens: 0,
            cache_read_tokens: 0,
        }
    );
}

#[test]
fn google_cached_subtracts_cache_and_folds_thoughts_into_output() {
    let parsed = google::parse(&fixture("google_cached.json")).expect("parse");

    // promptTokenCount=2048, cached=1536 → input=512, cache_read=1536.
    // candidates=200 + thoughts=100 → output=300.
    assert_eq!(parsed.model, "gemini-2.5-flash");
    assert_eq!(
        parsed.usage,
        TokenUsage {
            input_tokens: 512,
            output_tokens: 300,
            cache_creation_tokens: 0,
            cache_read_tokens: 1536,
        }
    );
}

#[test]
fn google_missing_model_version_falls_back_to_gemini() {
    let body = br#"{"usageMetadata":{"promptTokenCount":100,"candidatesTokenCount":50}}"#;
    let parsed = google::parse(body).expect("parse without modelVersion");
    assert_eq!(parsed.model, "gemini");
    assert_eq!(parsed.usage.input_tokens, 100);
    assert_eq!(parsed.usage.output_tokens, 50);
}

#[test]
fn google_invalid_json_returns_error() {
    assert!(google::parse(b"not json").is_err());
}

#[test]
fn google_missing_usage_metadata_returns_error() {
    let body = br#"{"candidates":[],"modelVersion":"gemini-2.5-pro"}"#;
    assert!(google::parse(body).is_err());
}

#[test]
fn google_sse_stream_reads_cumulative_usage() {
    let sse = "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"Hi\"}]}}],\"modelVersion\":\"gemini-2.5-flash\"}\n\
\n\
data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\" there\"}]}}],\"usageMetadata\":{\"promptTokenCount\":1000,\"candidatesTokenCount\":40},\"modelVersion\":\"gemini-2.5-flash\"}\n\n";
    let parsed = google::parse_sse(sse.as_bytes()).expect("sse parse");
    assert_eq!(parsed.model, "gemini-2.5-flash");
    assert_eq!(parsed.usage.input_tokens, 1000);
    assert_eq!(parsed.usage.output_tokens, 40);
}
