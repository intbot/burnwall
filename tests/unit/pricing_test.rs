//! Pricing-table lookup + cost-calculation tests.
//!
//! Expected dollar amounts are computed by hand from SPEC.md's rate cards.
//! Floats are compared with a small absolute epsilon — the calc uses straight
//! `f64` multiplication, no exotic rounding.

use burnwall::pricing::{cache_savings, calculate_cost, cost, cost_without_cache, get_pricing};
use burnwall::providers::TokenUsage;

const EPSILON: f64 = 1e-9;

fn approx_eq(actual: f64, expected: f64, label: &str) {
    assert!(
        (actual - expected).abs() < EPSILON,
        "{}: actual {} vs expected {}",
        label,
        actual,
        expected
    );
}

// ─────────────────────── Model-name normalization ───────────────────────

#[test]
fn lookup_matches_exact_name() {
    assert!(get_pricing("claude-sonnet-4-6").is_some());
    assert!(get_pricing("gpt-5.4").is_some());
}

#[test]
fn lookup_strips_anthropic_date_suffix() {
    let exact = get_pricing("claude-sonnet-4-6").expect("exact");
    let dated = get_pricing("claude-sonnet-4-6-20250514").expect("with date");
    assert_eq!(exact, dated);
}

#[test]
fn lookup_strips_openai_date_suffix() {
    let exact = get_pricing("gpt-5.4").expect("exact");
    let dated = get_pricing("gpt-5.4-2026-01-15").expect("with date");
    assert_eq!(exact, dated);
}

#[test]
fn lookup_disambiguates_gpt_mini_from_gpt_base() {
    // The critical ordering case: `gpt-5.4-mini-2026-03-01` must hit the mini
    // rates (0.15/MTok), NOT the base gpt-5.4 rates (1.25/MTok).
    let mini = get_pricing("gpt-5.4-mini-2026-03-01").expect("mini variant");
    assert!((mini.input_per_mtok - 0.15).abs() < EPSILON);
}

#[test]
fn lookup_returns_none_for_unknown_model() {
    assert!(get_pricing("claude-instant-1").is_none());
    assert!(get_pricing("gpt-4").is_none());
    assert!(get_pricing("").is_none());
}

#[test]
fn lookup_does_not_match_unrelated_prefix() {
    // "claude-sonnet-4-6" must NOT match "claude-sonnet-4-6dev" (no hyphen).
    assert!(get_pricing("claude-sonnet-4-6dev").is_none());
}

// ─────────────────────────── Cost calculation ───────────────────────────

#[test]
fn cost_anthropic_cached_matches_hand_calculation() {
    // Numbers from tests/fixtures/anthropic_cached.json with claude-sonnet-4-6
    // rates (input 3.00, write 3.75, read 0.30, output 15.00 per MTok):
    //   input:       512  / 1M * 3.00  = 0.001536
    //   cache_write: 8192 / 1M * 3.75  = 0.030720
    //   cache_read:  45056/ 1M * 0.30  = 0.0135168
    //   output:      28   / 1M * 15.00 = 0.000420
    //   total                            0.0461928
    let usage = TokenUsage {
        input_tokens: 512,
        output_tokens: 28,
        cache_creation_tokens: 8192,
        cache_read_tokens: 45056,
    };
    let pricing = get_pricing("claude-sonnet-4-6").expect("pricing");
    approx_eq(cost(&usage, pricing), 0.0461928, "anthropic cached cost");
}

#[test]
fn cost_anthropic_uncached_matches_hand_calculation() {
    // claude-haiku-4-5 rates (1.00, 1.25, 0.10, 5.00):
    //   input:  53248 / 1M * 1.00 = 0.053248
    //   output: 1024  / 1M * 5.00 = 0.005120
    //   total                       0.058368
    let usage = TokenUsage {
        input_tokens: 53248,
        output_tokens: 1024,
        cache_creation_tokens: 0,
        cache_read_tokens: 0,
    };
    let pricing = get_pricing("claude-haiku-4-5").expect("pricing");
    approx_eq(cost(&usage, pricing), 0.058368, "haiku uncached cost");
}

#[test]
fn cost_openai_cached_matches_hand_calculation() {
    // gpt-5.4 rates (1.25, 0.0, 0.625, 10.00). Fixture splits to
    // input=512, output=512, cache_read=1536:
    //   input:      512  / 1M * 1.25   = 0.00064
    //   cache_read: 1536 / 1M * 0.625  = 0.00096
    //   output:     512  / 1M * 10.00  = 0.00512
    //   total                            0.00672
    let usage = TokenUsage {
        input_tokens: 512,
        output_tokens: 512,
        cache_creation_tokens: 0,
        cache_read_tokens: 1536,
    };
    let pricing = get_pricing("gpt-5.4").expect("pricing");
    approx_eq(cost(&usage, pricing), 0.00672, "gpt-5.4 cached cost");
}

#[test]
fn cost_zero_usage_is_zero() {
    let pricing = get_pricing("claude-opus-4-7").expect("pricing");
    approx_eq(cost(&TokenUsage::default(), pricing), 0.0, "zero usage");
}

// ────────────────────────── Cache savings math ──────────────────────────

#[test]
fn cost_without_cache_bills_everything_at_input_rate() {
    // For anthropic_cached fixture: all 512+8192+45056 = 53760 prompt tokens
    // would have been billed at 3.00/MTok:
    //   53760 / 1M * 3.00 = 0.16128
    //   plus output 28 / 1M * 15.00 = 0.00042
    //   total                         0.16170
    let usage = TokenUsage {
        input_tokens: 512,
        output_tokens: 28,
        cache_creation_tokens: 8192,
        cache_read_tokens: 45056,
    };
    let pricing = get_pricing("claude-sonnet-4-6").expect("pricing");
    approx_eq(
        cost_without_cache(&usage, pricing),
        0.16170,
        "uncached cost",
    );
}

#[test]
fn cache_savings_is_uncached_minus_actual() {
    let usage = TokenUsage {
        input_tokens: 512,
        output_tokens: 28,
        cache_creation_tokens: 8192,
        cache_read_tokens: 45056,
    };
    let pricing = get_pricing("claude-sonnet-4-6").expect("pricing");
    let expected = cost_without_cache(&usage, pricing) - cost(&usage, pricing);
    approx_eq(cache_savings(&usage, pricing), expected, "cache savings");
    // And it must be positive when caching saved money:
    assert!(cache_savings(&usage, pricing) > 0.0);
}

#[test]
fn cache_savings_is_zero_when_no_cache_activity() {
    let usage = TokenUsage {
        input_tokens: 1000,
        output_tokens: 100,
        cache_creation_tokens: 0,
        cache_read_tokens: 0,
    };
    let pricing = get_pricing("claude-sonnet-4-6").expect("pricing");
    approx_eq(cache_savings(&usage, pricing), 0.0, "no-cache savings = 0");
}

// ─────────────────────────── Convenience API ───────────────────────────

#[test]
fn calculate_cost_returns_some_for_known_model() {
    let usage = TokenUsage {
        input_tokens: 1_000_000,
        output_tokens: 0,
        cache_creation_tokens: 0,
        cache_read_tokens: 0,
    };
    let result = calculate_cost("claude-sonnet-4-6", &usage).expect("known model");
    approx_eq(result, 3.00, "1 MTok of input at $3/MTok");
}

#[test]
fn calculate_cost_returns_none_for_unknown_model() {
    let usage = TokenUsage::default();
    assert!(calculate_cost("never-heard-of-this", &usage).is_none());
}

#[test]
fn pricing_age_days_zero_when_today_equals_last_updated() {
    use chrono::NaiveDate;
    let updated = NaiveDate::parse_from_str(burnwall::pricing::PRICING_LAST_UPDATED, "%Y-%m-%d")
        .expect("PRICING_LAST_UPDATED parses");
    assert_eq!(burnwall::pricing::pricing_age_days(updated), Some(0));
}

#[test]
fn pricing_age_days_positive_when_future() {
    use chrono::NaiveDate;
    let updated =
        NaiveDate::parse_from_str(burnwall::pricing::PRICING_LAST_UPDATED, "%Y-%m-%d").unwrap();
    let later = updated + chrono::Duration::days(45);
    assert_eq!(burnwall::pricing::pricing_age_days(later), Some(45));
}
