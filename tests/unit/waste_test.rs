//! Unit tests for the waste-insights engine.

use chrono::{Duration, Utc};

use burnwall::logscrape::UsageEntry;
use burnwall::providers::TokenUsage;
use burnwall::waste::{
    self, Finding, Severity, WasteRule,
    rules::{
        CacheHitStarvation, ContextWindowSaturation, MegaSessions, ModelOverreliance,
        ReasoningEffortOveruse, RunawayContextGrowth,
    },
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
        session_id: None,
        workspace: None,
        context_window: None,
    }
}

/// An entry with reasoning tokens (a subset of `output`), as Codex reports.
fn reasoning_entry(model: &str, input: u64, output: u64, reasoning: u64) -> UsageEntry {
    let mut e = entry_out(model, input, 0, 0, output);
    e.reasoning_tokens = reasoning;
    e
}

/// An entry belonging to `session`, ordered by `idx`, with the given input.
fn session_entry(session: &str, model: &str, input: u64, idx: i64) -> UsageEntry {
    let mut e = entry_out(model, input, 0, 0, 0);
    e.session_id = Some(session.to_string());
    e.timestamp = Utc::now() + Duration::seconds(idx);
    e
}

/// A Codex-style entry that reports its context-window size.
fn ctx_entry(model: &str, input: u64, window: u64) -> UsageEntry {
    let mut e = entry_out(model, input, 0, 0, 0);
    e.context_window = Some(window);
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

    assert!(
        test_rule()
            .evaluate(&waste::WasteContext { entries: &entries })
            .is_none()
    );
}

#[test]
fn below_sample_threshold_is_not_flagged() {
    // Only 2 qualifying requests; min_sample is 3.
    let entries: Vec<UsageEntry> = (0..2)
        .map(|_| entry("claude-sonnet-4-6", 8_000, 0, 0))
        .collect();

    assert!(
        test_rule()
            .evaluate(&waste::WasteContext { entries: &entries })
            .is_none()
    );
}

#[test]
fn small_prompts_are_ignored() {
    // Prompts under the token threshold never qualify, regardless of count.
    let entries: Vec<UsageEntry> = (0..10)
        .map(|_| entry("claude-sonnet-4-6", 1_000, 0, 0))
        .collect();

    assert!(
        test_rule()
            .evaluate(&waste::WasteContext { entries: &entries })
            .is_none()
    );
}

#[test]
fn unknown_model_contributes_no_waste() {
    // Large prompts, low cache, but the model isn't in the pricing table —
    // the pattern is present but we can't price it, so no positive waste →
    // no finding (we don't emit a $0 cost-waste finding).
    let entries: Vec<UsageEntry> = (0..5)
        .map(|_| entry("claude-imaginary-9000", 8_000, 0, 0))
        .collect();

    assert!(
        test_rule()
            .evaluate(&waste::WasteContext { entries: &entries })
            .is_none()
    );
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
    assert!(
        rule.evaluate(&waste::WasteContext { entries: &entries })
            .is_none()
    );
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
    assert!(
        rule.evaluate(&waste::WasteContext { entries: &entries })
            .is_none()
    );
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
    // gpt-5.5 output $30/MTok: 1200 reasoning × 30 / 1e6 = $0.036 each × 12 = $0.432.
    assert!((finding.observed_waste_usd - 0.432).abs() < 1e-6);
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
    assert!(
        rule.evaluate(&waste::WasteContext { entries: &entries })
            .is_none()
    );
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
    assert!(
        rule.evaluate(&waste::WasteContext { entries: &entries })
            .is_none()
    );
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
    assert!(
        rule.evaluate(&waste::WasteContext { entries: &entries })
            .is_none()
    );
}

#[test]
fn flags_context_window_saturation() {
    let rule = ContextWindowSaturation {
        min_fill_rate: 0.85,
        min_sample: 10,
    };
    // 12 requests at ~88% of a 272k window.
    let entries: Vec<UsageEntry> = (0..12)
        .map(|_| ctx_entry("gpt-5.5", 240_000, 272_000))
        .collect();
    let f = rule
        .evaluate(&waste::WasteContext { entries: &entries })
        .expect("should flag saturation");
    assert_eq!(f.rule_id, "context-window-saturation");
    assert_eq!(f.count, 12);
    // gpt-5.5 input $5/MTok: 240000 × 5 / 1e6 = $1.20 each × 12 = $14.40.
    assert!((f.observed_waste_usd - 14.40).abs() < 1e-6);
}

#[test]
fn entries_without_a_window_are_not_saturation() {
    // Claude Code entries carry context_window == None → skipped.
    let rule = ContextWindowSaturation {
        min_fill_rate: 0.85,
        min_sample: 3,
    };
    let entries: Vec<UsageEntry> = (0..10)
        .map(|_| entry_out("claude-opus-4-7", 240_000, 0, 0, 0))
        .collect();
    assert!(
        rule.evaluate(&waste::WasteContext { entries: &entries })
            .is_none()
    );
}

#[test]
fn flags_runaway_context_growth() {
    let rule = RunawayContextGrowth {
        min_turns: 8,
        growth_factor: 3.0,
    };
    // 9-turn session: early ~1k context, late ~12k context.
    let inputs = [
        1_000u64, 1_000, 1_000, 4_000, 6_000, 8_000, 12_000, 12_000, 12_000,
    ];
    let entries: Vec<UsageEntry> = inputs
        .iter()
        .enumerate()
        .map(|(i, &v)| session_entry("s1", "claude-sonnet-4-6", v, i as i64))
        .collect();
    let f = rule
        .evaluate(&waste::WasteContext { entries: &entries })
        .expect("should flag growth");
    assert_eq!(f.rule_id, "runaway-context-growth");
    assert_eq!(f.count, 1);
    // baseline input = 1000; extra summed = 48000; sonnet input $3/MTok → $0.144.
    assert!((f.observed_waste_usd - 0.144).abs() < 1e-6);
}

#[test]
fn stable_session_is_not_runaway() {
    let rule = RunawayContextGrowth {
        min_turns: 8,
        growth_factor: 3.0,
    };
    let entries: Vec<UsageEntry> = (0..9)
        .map(|i| session_entry("s1", "claude-sonnet-4-6", 5_000, i))
        .collect();
    assert!(
        rule.evaluate(&waste::WasteContext { entries: &entries })
            .is_none()
    );
}

#[test]
fn short_session_is_not_runaway() {
    let rule = RunawayContextGrowth {
        min_turns: 8,
        growth_factor: 3.0,
    };
    // Big growth, but only 3 turns — under min_turns.
    let inputs = [1_000u64, 6_000, 12_000];
    let entries: Vec<UsageEntry> = inputs
        .iter()
        .enumerate()
        .map(|(i, &v)| session_entry("s1", "claude-sonnet-4-6", v, i as i64))
        .collect();
    assert!(
        rule.evaluate(&waste::WasteContext { entries: &entries })
            .is_none()
    );
}

#[test]
fn flags_mega_sessions_as_informational() {
    let rule = MegaSessions {
        min_turns: 40,
        min_total_prompt_tokens: 500_000,
    };
    // 40 turns × 15k = 600k prompt tokens.
    let entries: Vec<UsageEntry> = (0..40)
        .map(|i| session_entry("s1", "claude-opus-4-7", 15_000, i))
        .collect();
    let f = rule
        .evaluate(&waste::WasteContext { entries: &entries })
        .expect("should flag mega session");
    assert_eq!(f.rule_id, "mega-sessions");
    assert_eq!(f.count, 1);
    // Informational — no isolated dollar figure.
    assert_eq!(f.observed_waste_usd, 0.0);
}

#[test]
fn small_session_is_not_mega() {
    let rule = MegaSessions {
        min_turns: 40,
        min_total_prompt_tokens: 500_000,
    };
    let entries: Vec<UsageEntry> = (0..10)
        .map(|i| session_entry("s1", "claude-opus-4-7", 15_000, i))
        .collect();
    assert!(
        rule.evaluate(&waste::WasteContext { entries: &entries })
            .is_none()
    );
}

#[test]
fn capped_waste_never_exceeds_actual_spend() {
    let entries = vec![entry_out("claude-haiku-4-5", 1_000, 0, 0, 200)];
    let spend = waste::total_spend_usd(&entries);
    // A finding claiming 10× the real spend must be clamped to actual spend.
    let findings = vec![Finding {
        rule_id: "synthetic",
        title: "synthetic".to_string(),
        severity: Severity::Low,
        count: 1,
        observed_waste_usd: spend * 10.0,
        detail: "synthetic".to_string(),
    }];
    let capped = waste::capped_waste_usd(&findings, &entries);
    assert!(spend > 0.0);
    assert!((capped - spend).abs() < 1e-9);
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
