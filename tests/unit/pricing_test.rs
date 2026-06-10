//! Pricing-table lookup + cost-calculation tests.
//!
//! Expected dollar amounts are computed by hand from SPEC.md's rate cards.
//! Floats are compared with a small absolute epsilon — the calc uses straight
//! `f64` multiplication, no exotic rounding.

use burnwall::pricing::{
    cache_savings, calculate_cost, cost, cost_without_cache, get_pricing, get_pricing_with,
    overrides, ModelPricing,
};
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
    // rates (0.75/MTok), NOT the base gpt-5.4 rates (2.50/MTok).
    let mini = get_pricing("gpt-5.4-mini-2026-03-01").expect("mini variant");
    assert!((mini.input_per_mtok - 0.75).abs() < EPSILON);
    // Same for nano and pro — every longer variant must shadow the base.
    let nano = get_pricing("gpt-5.4-nano").expect("nano variant");
    assert!((nano.input_per_mtok - 0.20).abs() < EPSILON);
    let pro = get_pricing("gpt-5.4-pro").expect("pro variant");
    assert!((pro.input_per_mtok - 30.00).abs() < EPSILON);
}

#[test]
fn codex_model_is_priced() {
    // The Codex CLI's dedicated model id must resolve — it has no bare
    // `gpt-5.3` base entry to fall back to.
    let p = get_pricing("gpt-5.3-codex").expect("codex model");
    assert!((p.input_per_mtok - 1.75).abs() < EPSILON);
    assert!((p.output_per_mtok - 14.00).abs() < EPSILON);
}

#[test]
fn legacy_anthropic_models_are_priced() {
    // Deprecated-but-billable models must still track cost: Opus 4.1 / Opus 4
    // bill at 3× the current Opus rate — the worst models to silently miss.
    for id in [
        "claude-opus-4-1",
        "claude-opus-4-1-20250805",
        "claude-opus-4-0",
        "claude-opus-4-20250514",
    ] {
        let p = get_pricing(id).unwrap_or_else(|| panic!("{id} should be priced"));
        assert!((p.input_per_mtok - 15.00).abs() < EPSILON, "{id}");
        assert!((p.output_per_mtok - 75.00).abs() < EPSILON, "{id}");
    }
    for id in [
        "claude-sonnet-4-5",
        "claude-sonnet-4-5-20250929",
        "claude-sonnet-4-0",
        "claude-sonnet-4-20250514",
        "claude-opus-4-5-20251101",
    ] {
        assert!(get_pricing(id).is_some(), "{id} should be priced");
    }
}

#[test]
fn known_models_table_orders_longer_prefixes_first() {
    // The lookup returns the FIRST dash/bracket-prefix match, so any key that
    // is itself a dash-prefix of another key must come after it — e.g.
    // `gpt-5.4` after `gpt-5.4-mini`, `gemini-2.5-flash` after
    // `gemini-2.5-flash-lite`. This guards the invariant for future edits.
    let keys: Vec<&str> = burnwall::pricing::KNOWN_MODELS
        .iter()
        .map(|(k, _)| *k)
        .collect();
    for (i, shorter) in keys.iter().enumerate() {
        for longer in keys.iter().skip(i + 1) {
            let shadowed = longer
                .strip_prefix(shorter)
                .is_some_and(|rest| rest.starts_with('-') || rest.starts_with('['));
            assert!(
                !shadowed,
                "table order bug: '{shorter}' (index {i}) shadows the later key '{longer}'"
            );
        }
    }
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

#[test]
fn fable_5_is_priced() {
    // Released 2026-06-09: $10/$50 per MTok, standard cache multipliers.
    let p = get_pricing("claude-fable-5").expect("fable 5");
    assert!((p.input_per_mtok - 10.00).abs() < EPSILON);
    assert!((p.output_per_mtok - 50.00).abs() < EPSILON);
    assert!((p.cache_write_per_mtok - 12.50).abs() < EPSILON);
    assert!((p.cache_read_per_mtok - 1.00).abs() < EPSILON);
}

#[test]
fn opus_4_8_is_priced_at_opus_rates() {
    let p48 = get_pricing("claude-opus-4-8").expect("opus 4.8");
    let p47 = get_pricing("claude-opus-4-7").expect("opus 4.7");
    assert_eq!(p48, p47);
}

#[test]
fn lookup_strips_bracket_variant_tag() {
    // Claude Code requests the 1M-context tier as `<model>[1m]` — the tag
    // must resolve to the base model's rates, not fall through to unknown.
    let exact = get_pricing("claude-fable-5").expect("exact");
    let tagged = get_pricing("claude-fable-5[1m]").expect("with [1m] tag");
    assert_eq!(exact, tagged);
    assert!(get_pricing("claude-opus-4-8[1m]").is_some());
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
    // gpt-5.4 rates (2.50, 0.0, 0.25, 15.00). Fixture splits to
    // input=512, output=512, cache_read=1536:
    //   input:      512  / 1M * 2.50   = 0.00128
    //   cache_read: 1536 / 1M * 0.25   = 0.000384
    //   output:     512  / 1M * 15.00  = 0.00768
    //   total                            0.009344
    let usage = TokenUsage {
        input_tokens: 512,
        output_tokens: 512,
        cache_creation_tokens: 0,
        cache_read_tokens: 1536,
    };
    let pricing = get_pricing("gpt-5.4").expect("pricing");
    approx_eq(cost(&usage, pricing), 0.009344, "gpt-5.4 cached cost");
}

#[test]
fn lookup_disambiguates_gemini_pro_from_flash() {
    let pro = get_pricing("gemini-2.5-pro").expect("pro");
    let flash = get_pricing("gemini-2.5-flash").expect("flash");
    assert!((pro.input_per_mtok - 1.25).abs() < EPSILON);
    assert!((flash.input_per_mtok - 0.30).abs() < EPSILON);
    // Date-stamped variant still resolves.
    let dated = get_pricing("gemini-2.5-flash-002").expect("dated flash");
    assert_eq!(flash, dated);
}

#[test]
fn cost_gemini_cached_matches_hand_calculation() {
    // google_cached.json with gemini-2.5-flash rates (0.30, 0.0, 0.03, 2.50).
    // Split: input=512, output=300, cache_read=1536.
    //   input:      512  / 1M * 0.30  = 0.0001536
    //   cache_read: 1536 / 1M * 0.03  = 0.00004608
    //   output:     300  / 1M * 2.50  = 0.00075
    //   total                           0.00094968
    let usage = TokenUsage {
        input_tokens: 512,
        output_tokens: 300,
        cache_creation_tokens: 0,
        cache_read_tokens: 1536,
    };
    let pricing = get_pricing("gemini-2.5-flash").expect("pricing");
    approx_eq(cost(&usage, pricing), 0.00094968, "gemini flash cached cost");
}

#[test]
fn lookup_disambiguates_gemini_flash_lite_from_flash() {
    // `gemini-2.5-flash` is a dash-prefix of `gemini-2.5-flash-lite`, so the
    // lite entry must come first in the table or it would bill at flash rates.
    let lite = get_pricing("gemini-2.5-flash-lite").expect("flash lite");
    assert!((lite.input_per_mtok - 0.10).abs() < EPSILON);
    let lite31 = get_pricing("gemini-3.1-flash-lite").expect("3.1 flash lite");
    assert!((lite31.input_per_mtok - 0.25).abs() < EPSILON);
}

#[test]
fn gemini_3_generation_is_priced() {
    // The preview suffixes on current Gemini IDs resolve via the `-` rule.
    let pro = get_pricing("gemini-3.1-pro-preview").expect("3.1 pro preview");
    assert!((pro.input_per_mtok - 2.00).abs() < EPSILON);
    let flash = get_pricing("gemini-3-flash-preview").expect("3 flash preview");
    assert!((flash.input_per_mtok - 0.50).abs() < EPSILON);
    assert!(get_pricing("gemini-3.5-flash").is_some());
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

// ─────────────────────── Local pricing overrides (B) ───────────────────────
// `get_pricing_with` takes the override table explicitly, so precedence and
// longest-prefix behavior are tested without touching the process-global table.

#[test]
fn override_wins_over_builtin_for_same_model() {
    let table = overrides::parse(
        r#"
[[model]]
name = "claude-sonnet-4-6"
input_per_mtok = 99.0
output_per_mtok = 199.0
"#,
    )
    .expect("parse");
    let p = get_pricing_with("claude-sonnet-4-6", &table).expect("override hit");
    assert!((p.input_per_mtok - 99.0).abs() < EPSILON);
    assert!((p.output_per_mtok - 199.0).abs() < EPSILON);
    // The built-in card is unchanged when no override is supplied.
    let builtin = get_pricing_with("claude-sonnet-4-6", &[]).expect("builtin");
    assert!((builtin.input_per_mtok - 3.0).abs() < EPSILON);
}

#[test]
fn override_adds_a_brand_new_model() {
    // A model the binary never shipped with is unknown by default...
    assert!(get_pricing("claude-opus-4-9").is_none());
    // ...but a local override prices it.
    let table = overrides::parse(
        r#"
[[model]]
name = "claude-opus-4-9"
input_per_mtok = 5.0
cache_write_per_mtok = 6.25
cache_read_per_mtok = 0.5
output_per_mtok = 25.0
"#,
    )
    .expect("parse");
    let p = get_pricing_with("claude-opus-4-9", &table).expect("new model");
    assert!((p.output_per_mtok - 25.0).abs() < EPSILON);
}

#[test]
fn override_honors_date_suffix_and_longest_prefix() {
    let table = overrides::parse(
        r#"
[[model]]
name = "gpt-6"
input_per_mtok = 2.0
output_per_mtok = 12.0

[[model]]
name = "gpt-6-mini"
input_per_mtok = 0.2
output_per_mtok = 1.2
"#,
    )
    .expect("parse");
    // Date-stamped base variant resolves to the base entry.
    let base = get_pricing_with("gpt-6-2026-09-01", &table).expect("base dated");
    assert!((base.input_per_mtok - 2.0).abs() < EPSILON);
    // The mini variant must hit the mini entry, not the shorter base prefix.
    let mini = get_pricing_with("gpt-6-mini-2026-09-01", &table).expect("mini dated");
    assert!((mini.input_per_mtok - 0.2).abs() < EPSILON);
}

#[test]
fn empty_overrides_match_builtin_lookup() {
    // get_pricing_with with an empty table is exactly the built-in card.
    let empty: Vec<(String, ModelPricing)> = Vec::new();
    let a = get_pricing_with("gpt-5.4", &empty).expect("builtin via with");
    let b = get_pricing("gpt-5.4").expect("builtin via global");
    assert_eq!(a, b);
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
