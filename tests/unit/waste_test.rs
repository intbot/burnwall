//! Unit tests for the waste-insights engine.

use chrono::Utc;

use burnwall::logscrape::UsageEntry;
use burnwall::providers::TokenUsage;
use burnwall::waste::{
    self,
    rules::{CacheHitStarvation, ModelOverreliance, ReasoningEffortOveruse},
    WasteRule,
};

fn entry(model: &str, input: u64, cache_creation: u64, cache_read: u64) -> UsageEntry {
    entry_out(model, input, cache_creation, cache_read, 0)
}

fn entry_out(
    model: &str,
    input: u64,
    cache_creation: u64,
    cache_read: u64,
    output: u64,
) -> UsageEntry {
    UsageEntry {
        tool: "claude-code",
        model: model.to_string(),
        timestamp: Utc::now(),
        usage: TokenUsage {
            input_tokens: input,
            output_tokens: output,
            cache_creation_tokens: cache_creation,
            cache_read_tokens: cache_read,
        },
        reasoning_tokens: 0,
    }
}

/// An entry with reasoning tokens (a subset of `output`), as Codex reports.
fn reasoning_entry(model: &str, input: u64, output: u64, reasoning: u64) -> UsageEntry {
    let mut e = entry_out(model, input, 0, 0, output);
    e.reasoning_tokens = reasoning;
    e
}

/// A rule with low thresholds so tests don't need 20 entries.
fn test_rule() -> CacheHitStarvation {
    CacheHitStarvation {
        min_prompt_tokens: 5_000,
        min_sample: 3,
        min_cache_rate: 0.10,
    }
}

#[test]
fn flags_large_prompts_with_low_cache_rate() {
    // 5 requests, each ~8k-token prompt, almost no cache reads.
    let entries: Vec<UsageEntry> = (0..5)
        .map(|_| entry("claude-sonnet-4-6", 8_000, 0, 100))
        .collect();

    let finding = test_rule()
        .evaluate(&waste::WasteContext { entries: &entries })
        .expect("should flag cache starvation");

    assert_eq!(finding.rule_id, "cache-hit-starvation");
    assert_eq!(finding.count, 5);
    assert!(
        finding.observed_waste_usd > 0.0,
        "waste should be positive, got {}",
        finding.observed_waste_usd
    );
    // Sonnet: input $3.00, cache_read $0.30 → delta $2.70/MTok.
    // 5 × 8000 input × 2.70 / 1e6 = $0.108.
    assert!((finding.observed_waste_usd - 0.108).abs() < 1e-6);
}

#[test]
fn healthy_cache_rate_is_not_flagged() {
    // Big prompts, but mostly served from cache → no waste.
    let entries: Vec<UsageEntry> = (0..5)
        .map(|_| entry("claude-sonnet-4-6", 500, 0, 9_500))
        .collect();

    assert!(test_rule()
        .evaluate(&waste::WasteContext { entries: &entries })
        .is_none());
}

#[test]
fn below_sample_threshold_is_not_flagged() {
    // Only 2 qualifying requests; min_sample is 3.
    let entries: Vec<UsageEntry> = (0..2)
        .map(|_| entry("claude-sonnet-4-6", 8_000, 0, 0))
        .collect();

    assert!(test_rule()
        .evaluate(&waste::WasteContext { entries: &entries })
        .is_none());
}

#[test]
fn small_prompts_are_ignored() {
    // Prompts under the token threshold never qualify, regardless of count.
    let entries: Vec<UsageEntry> = (0..10)
        .map(|_| entry("claude-sonnet-4-6", 1_000, 0, 0))
        .collect();

    assert!(test_rule()
        .evaluate(&waste::WasteContext { entries: &entries })
        .is_none());
}

#[test]
fn unknown_model_contributes_no_waste() {
    // Large prompts, low cache, but the model isn't in the pricing table —
    // the pattern is present but we can't price it, so no positive waste →
    // no finding (we don't emit a $0 cost-waste finding).
    let entries: Vec<UsageEntry> = (0..5)
        .map(|_| entry("claude-imaginary-9000", 8_000, 0, 0))
        .collect();

    assert!(test_rule()
        .evaluate(&waste::WasteContext { entries: &entries })
        .is_none());
}

#[test]
fn empty_input_yields_no_findings() {
    let findings = waste::analyze(&[]);
    assert!(findings.is_empty());
    assert_eq!(waste::total_waste_usd(&findings), 0.0);
}

fn small_entry(model: &str) -> UsageEntry {
    // ~500-token prompt, ~200-token answer — a trivial request.
    entry_out(model, 500, 0, 0, 200)
}

#[test]
fn flags_flagship_model_on_trivial_requests() {
    let rule = ModelOverreliance {
        max_prompt_tokens: 2_000,
        max_output_tokens: 600,
        min_sample: 10,
    };
    let entries: Vec<UsageEntry> = (0..12).map(|_| small_entry("claude-opus-4-7")).collect();

    let finding = rule
        .evaluate(&waste::WasteContext { entries: &entries })
        .expect("should flag flagship overreliance");
    assert_eq!(finding.rule_id, "model-overreliance");
    assert_eq!(finding.count, 12);
    // Per request: opus (500*5 + 200*25)/1e6 = $0.0075; haiku (500*1 + 200*5)/1e6
    // = $0.0015; delta $0.006 × 12 = $0.072.
    assert!((finding.observed_waste_usd - 0.072).abs() < 1e-6);
}

#[test]
fn mid_tier_model_is_not_flagged_as_overreliance() {
    // Sonnet is the workhorse, not a flagship — using it for small requests
    // is a judgment call we don't second-guess.
    let rule = ModelOverreliance {
        max_prompt_tokens: 2_000,
        max_output_tokens: 600,
        min_sample: 3,
    };
    let entries: Vec<UsageEntry> = (0..10).map(|_| small_entry("claude-sonnet-4-6")).collect();
    assert!(rule
        .evaluate(&waste::WasteContext { entries: &entries })
        .is_none());
}

#[test]
fn large_requests_are_not_overreliance() {
    // Flagship on a big, long request is legitimate — not flagged.
    let rule = ModelOverreliance {
        max_prompt_tokens: 2_000,
        max_output_tokens: 600,
        min_sample: 3,
    };
    let entries: Vec<UsageEntry> = (0..10)
        .map(|_| entry_out("claude-opus-4-7", 50_000, 0, 0, 4_000))
        .collect();
    assert!(rule
        .evaluate(&waste::WasteContext { entries: &entries })
        .is_none());
}

#[test]
fn flags_heavy_reasoning_on_routine_requests() {
    let rule = ReasoningEffortOveruse {
        max_prompt_tokens: 2_000,
        min_reasoning_tokens: 1_000,
        min_sample: 10,
    };
    // 12 routine prompts (~800 tokens) that each burned 1200 reasoning tokens.
    let entries: Vec<UsageEntry> = (0..12)
        .map(|_| reasoning_entry("gpt-5.5", 800, 1_500, 1_200))
        .collect();

    let finding = rule
        .evaluate(&waste::WasteContext { entries: &entries })
        .expect("should flag reasoning overuse");
    assert_eq!(finding.rule_id, "reasoning-effort-overuse");
    assert_eq!(finding.count, 12);
    // gpt-5.5 output $10/MTok: 1200 reasoning × 10 / 1e6 = $0.012 each × 12 = $0.144.
    assert!((finding.observed_waste_usd - 0.144).abs() < 1e-6);
}

#[test]
fn light_reasoning_is_not_flagged() {
    let rule = ReasoningEffortOveruse {
        max_prompt_tokens: 2_000,
        min_reasoning_tokens: 1_000,
        min_sample: 3,
    };
    // Reasoning under the threshold — a little thinking is fine.
    let entries: Vec<UsageEntry> = (0..10)
        .map(|_| reasoning_entry("gpt-5.5", 800, 400, 200))
        .collect();
    assert!(rule
        .evaluate(&waste::WasteContext { entries: &entries })
        .is_none());
}

#[test]
fn heavy_reasoning_on_large_prompts_is_not_flagged() {
    // A big prompt is not "routine" — deep reasoning there can be warranted.
    let rule = ReasoningEffortOveruse {
        max_prompt_tokens: 2_000,
        min_reasoning_tokens: 1_000,
        min_sample: 3,
    };
    let entries: Vec<UsageEntry> = (0..10)
        .map(|_| reasoning_entry("gpt-5.5", 50_000, 3_000, 2_000))
        .collect();
    assert!(rule
        .evaluate(&waste::WasteContext { entries: &entries })
        .is_none());
}

#[test]
fn tools_without_reasoning_counts_never_trip() {
    // Claude Code entries carry reasoning_tokens == 0, so the rule fails open
    // on them no matter how many trivial requests there are.
    let rule = ReasoningEffortOveruse {
        max_prompt_tokens: 2_000,
        min_reasoning_tokens: 1_000,
        min_sample: 3,
    };
    let entries: Vec<UsageEntry> = (0..20).map(|_| small_entry("claude-opus-4-7")).collect();
    assert!(rule
        .evaluate(&waste::WasteContext { entries: &entries })
        .is_none());
}

#[test]
fn default_rules_run_end_to_end() {
    // Enough volume to clear the production default min_sample (20).
    let entries: Vec<UsageEntry> = (0..25)
        .map(|_| entry("claude-opus-4-7", 10_000, 0, 0))
        .collect();
    let findings = waste::analyze(&entries);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cache-hit-starvation");
    assert!(findings[0].observed_waste_usd > 0.0);
}
