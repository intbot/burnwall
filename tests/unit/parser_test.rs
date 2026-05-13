//! Provider response parser tests using the fixture JSON files in
//! `tests/fixtures/`. Each fixture is a real (sanitized) sample of what the
//! provider returns; parsing must produce the exact token counts and preserve
//! the date-stamped model ID verbatim (pricing lookup handles normalization).

use std::fs;

use burnwall::providers::{anthropic, openai, TokenUsage};

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
