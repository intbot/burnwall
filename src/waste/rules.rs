//! Built-in waste rules behind the [`WasteRule`] trait.

use crate::pricing::{self, ModelPricing};

use super::types::{Finding, Severity, WasteContext, WasteRule};

/// Total prompt-side tokens for an entry (input + cache write + cache read).
fn prompt_tokens(usage: &crate::providers::TokenUsage) -> u64 {
    usage.input_tokens + usage.cache_creation_tokens + usage.cache_read_tokens
}

/// If `model` is a flagship-tier model, return the pricing of the cheaper
/// alternative in the same provider family. `None` for non-flagship or
/// unknown models — the rule simply doesn't apply to them. Deliberately
/// scoped to the *top* tier (opus, gpt-5.5): using the flagship for a
/// one-line question is unambiguous waste; using the mid-tier workhorse is a
/// judgment call we don't second-guess.
fn flagship_downgrade(model: &str) -> Option<&'static ModelPricing> {
    let m = model.to_ascii_lowercase();
    if m.starts_with("claude-opus") {
        pricing::get_pricing("claude-haiku-4-5")
    } else if m.starts_with("gpt-5.5") {
        pricing::get_pricing("gpt-5.4-mini")
    } else {
        None
    }
}

/// **Cache-hit starvation** — the flagship rule. Large prompts that are
/// barely served from cache mean every turn re-pays full input price for the
/// same prefixes (churning instructions, frequent compaction, unstable system
/// prompts). Burnwall reads `cache_read_tokens` straight from the provider's
/// `usage` block, so this is computed from real numbers, not an estimate of
/// token counts.
///
/// Trips when, across the window, there are at least `min_sample` requests
/// with prompts over `min_prompt_tokens` AND the aggregate cache-read rate is
/// below `min_cache_rate`.
pub struct CacheHitStarvation {
    pub min_prompt_tokens: u64,
    pub min_sample: usize,
    pub min_cache_rate: f64,
}

impl Default for CacheHitStarvation {
    fn default() -> Self {
        // Conservative defaults; tunable via config.
        Self {
            min_prompt_tokens: 5_000,
            min_sample: 20,
            min_cache_rate: 0.10,
        }
    }
}

impl WasteRule for CacheHitStarvation {
    fn id(&self) -> &'static str {
        "cache-hit-starvation"
    }

    fn evaluate(&self, ctx: &WasteContext) -> Option<Finding> {
        let mut count = 0usize;
        let mut total_prompt = 0u64;
        let mut total_cache_read = 0u64;
        // Upper-bound waste estimate: the uncached input tokens on these large
        // prompts, priced at the gap between full input rate and the cache-read
        // rate — i.e. what they'd have cost if served from cache instead.
        let mut waste_usd = 0.0f64;

        for e in ctx.entries {
            let prompt = prompt_tokens(&e.usage);
            if prompt <= self.min_prompt_tokens {
                continue;
            }
            count += 1;
            total_prompt += prompt;
            total_cache_read += e.usage.cache_read_tokens;
            if let Some(p) = pricing::get_pricing(&e.model) {
                let rate_delta = (p.input_per_mtok - p.cache_read_per_mtok) / 1_000_000.0;
                if rate_delta > 0.0 {
                    waste_usd += e.usage.input_tokens as f64 * rate_delta;
                }
            }
        }

        if count < self.min_sample || total_prompt == 0 {
            return None;
        }
        let cache_rate = total_cache_read as f64 / total_prompt as f64;
        if cache_rate >= self.min_cache_rate || waste_usd <= 0.0 {
            return None;
        }

        Some(Finding {
            rule_id: "cache-hit-starvation",
            title: "Prompt cache starvation".to_string(),
            severity: Severity::Medium,
            count,
            observed_waste_usd: waste_usd,
            detail: format!(
                "{count} large requests (>{}k-token prompts) drew only {:.1}% of prompt tokens from cache. \
                 Up to ${:.2} went to prefixes the model could have served from cache. \
                 Keep system prompts short and stable and avoid mid-task context churn.",
                self.min_prompt_tokens / 1000,
                cache_rate * 100.0,
                waste_usd,
            ),
        })
    }
}

/// **Model overreliance** — a flagship model (Opus, GPT-5.5) used for trivial
/// requests (small prompt, short answer) that a cheaper model in the same
/// family would have handled. Waste is the *real* cost difference: what the
/// request cost on the flagship minus what the same token counts would have
/// cost on the family's cheap tier.
pub struct ModelOverreliance {
    pub max_prompt_tokens: u64,
    pub max_output_tokens: u64,
    pub min_sample: usize,
}

impl Default for ModelOverreliance {
    fn default() -> Self {
        Self {
            max_prompt_tokens: 2_000,
            max_output_tokens: 600,
            min_sample: 10,
        }
    }
}

impl WasteRule for ModelOverreliance {
    fn id(&self) -> &'static str {
        "model-overreliance"
    }

    fn evaluate(&self, ctx: &WasteContext) -> Option<Finding> {
        let mut count = 0usize;
        let mut waste_usd = 0.0f64;

        for e in ctx.entries {
            if prompt_tokens(&e.usage) > self.max_prompt_tokens
                || e.usage.output_tokens > self.max_output_tokens
            {
                continue;
            }
            let (Some(actual), Some(cheaper)) =
                (pricing::get_pricing(&e.model), flagship_downgrade(&e.model))
            else {
                continue;
            };
            let delta = pricing::cost(&e.usage, actual) - pricing::cost(&e.usage, cheaper);
            if delta > 0.0 {
                count += 1;
                waste_usd += delta;
            }
        }

        if count < self.min_sample || waste_usd <= 0.0 {
            return None;
        }

        Some(Finding {
            rule_id: "model-overreliance",
            title: "Flagship model on trivial requests".to_string(),
            severity: Severity::Medium,
            count,
            observed_waste_usd: waste_usd,
            detail: format!(
                "{count} small requests (short prompt + short answer) ran on a flagship model. \
                 Routing those to a cheaper model in the same family would have cost about ${:.2} less. \
                 Reserve the flagship for complex, multi-step work.",
                waste_usd,
            ),
        })
    }
}

/// **Reasoning-effort overuse** — routine requests (small prompt) that burned a
/// large amount of *reasoning* on the way to a short answer. Reasoning tokens
/// are billed at the output rate, so heavy thinking on a trivial ask is spend a
/// lower reasoning-effort setting would have avoided.
///
/// Only tools that itemize reasoning tokens can trip this — today that's Codex
/// (`reasoning_output_tokens`). Claude Code reports no separate count, so its
/// entries carry `reasoning_tokens == 0` and never qualify (fail-open).
///
/// Waste is the reasoning tokens on qualifying entries priced at the model's
/// output rate — a re-attribution of money already spent, never a guess at
/// future savings. Advisory only: a small prompt *can* be a hard problem, so
/// this is the softest of the cost rules (severity Low) and the detail says so.
pub struct ReasoningEffortOveruse {
    pub max_prompt_tokens: u64,
    pub min_reasoning_tokens: u64,
    pub min_sample: usize,
}

impl Default for ReasoningEffortOveruse {
    fn default() -> Self {
        Self {
            max_prompt_tokens: 2_000,
            min_reasoning_tokens: 1_000,
            min_sample: 10,
        }
    }
}

impl WasteRule for ReasoningEffortOveruse {
    fn id(&self) -> &'static str {
        "reasoning-effort-overuse"
    }

    fn evaluate(&self, ctx: &WasteContext) -> Option<Finding> {
        let mut count = 0usize;
        let mut waste_usd = 0.0f64;

        for e in ctx.entries {
            if e.reasoning_tokens < self.min_reasoning_tokens
                || prompt_tokens(&e.usage) > self.max_prompt_tokens
            {
                continue;
            }
            let Some(p) = pricing::get_pricing(&e.model) else {
                continue;
            };
            let cost = e.reasoning_tokens as f64 * p.output_per_mtok / 1_000_000.0;
            if cost > 0.0 {
                count += 1;
                waste_usd += cost;
            }
        }

        if count < self.min_sample || waste_usd <= 0.0 {
            return None;
        }

        Some(Finding {
            rule_id: "reasoning-effort-overuse",
            title: "Heavy reasoning on routine requests".to_string(),
            severity: Severity::Low,
            count,
            observed_waste_usd: waste_usd,
            detail: format!(
                "{count} routine requests (short prompts) spent a lot of reasoning to reach a short answer, \
                 costing about ${:.2} in reasoning tokens. \
                 Lowering the reasoning-effort setting for routine work can recover most of that — \
                 keep high effort for genuinely hard problems.",
                waste_usd,
            ),
        })
    }
}
