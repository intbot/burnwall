//! Built-in waste rules behind the [`WasteRule`] trait.

use std::collections::HashMap;

use crate::logscrape::UsageEntry;
use crate::pricing::{self, ModelPricing};

use super::types::{Finding, Severity, WasteContext, WasteRule};

/// Total prompt-side tokens for an entry (input + cache write + cache read).
fn prompt_tokens(usage: &crate::providers::TokenUsage) -> u64 {
    usage.input_tokens + usage.cache_creation_tokens + usage.cache_read_tokens
}

/// The per-token input rate (USD) for an entry's model, or `None` if unknown.
fn input_rate(model: &str) -> Option<f64> {
    pricing::get_pricing(model).map(|p| p.input_per_mtok / 1_000_000.0)
}

/// Group entries into sessions by `session_id` (entries without one are
/// skipped), each session's turns sorted oldest-first. Used by the
/// multi-turn rules; single-turn rules ignore session identity.
fn sessions<'a>(ctx: &WasteContext<'a>) -> Vec<Vec<&'a UsageEntry>> {
    let mut map: HashMap<&str, Vec<&UsageEntry>> = HashMap::new();
    for e in ctx.entries {
        if let Some(sid) = e.session_id.as_deref() {
            map.entry(sid).or_default().push(e);
        }
    }
    let mut out: Vec<Vec<&UsageEntry>> = map.into_values().collect();
    for s in &mut out {
        s.sort_by_key(|e| e.timestamp);
    }
    out
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

    fn evaluate(&self, ctx: &WasteContext<'_>) -> Option<Finding> {
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

/// **Cache dead-zone** — a workload that repeatedly pays full price to *write*
/// the cache (`cache_creation_tokens`) but almost never *reads* it back
/// (`cache_read_tokens`). This is the signature of a loop rebuilding context
/// just slower than the cache lifetime: every turn re-creates the cache entry
/// at the premium write rate, the entry expires before the next turn reuses it,
/// so the cache never pays off — it costs *extra* (writes are billed above the
/// base input rate) for zero benefit.
///
/// Distinct from [`CacheHitStarvation`], which flags large prompts that simply
/// aren't cached. This rule specifically catches the case where the caller *is*
/// paying to cache (lots of writes) but the reads never materialize — money
/// spent on a cache that's structurally dead.
///
/// Computed from real provider numbers. Trips when, across the window, there are
/// at least `min_sample` requests that wrote cache, the total cache writes are
/// substantial (`min_creation_tokens`), and the read:write ratio is below
/// `max_read_write_ratio`. Advisory only (the waste engine never blocks).
///
/// Waste estimate: the *premium* paid on the wasted cache writes — the gap
/// between the cache-write rate and the base input rate `(cache_write − input)`
/// applied to the un-reused write tokens. That premium is pure overhead when the
/// write is never read, framed (per the [`Finding`] contract) as money already
/// spent, never a speculative saving.
pub struct CacheDeadZone {
    pub min_creation_tokens: u64,
    pub min_sample: usize,
    pub max_read_write_ratio: f64,
}

impl Default for CacheDeadZone {
    fn default() -> Self {
        // Conservative: needs real, repeated cache-write volume with almost no
        // reads before it says anything.
        Self {
            min_creation_tokens: 20_000,
            min_sample: 20,
            max_read_write_ratio: 0.05,
        }
    }
}

impl WasteRule for CacheDeadZone {
    fn id(&self) -> &'static str {
        "cache-dead-zone"
    }

    fn evaluate(&self, ctx: &WasteContext<'_>) -> Option<Finding> {
        let mut count = 0usize;
        let mut total_creation = 0u64;
        let mut total_read = 0u64;
        let mut waste_usd = 0.0f64;

        for e in ctx.entries {
            // Only requests that actually paid to write the cache qualify.
            if e.usage.cache_creation_tokens == 0 {
                continue;
            }
            count += 1;
            total_creation += e.usage.cache_creation_tokens;
            total_read += e.usage.cache_read_tokens;
            if let Some(p) = pricing::get_pricing(&e.model) {
                // The write *premium* over the base input rate is the overhead
                // that buys nothing when the write is never read back.
                let premium = (p.cache_write_per_mtok - p.input_per_mtok) / 1_000_000.0;
                if premium > 0.0 {
                    waste_usd += e.usage.cache_creation_tokens as f64 * premium;
                }
            }
        }

        if count < self.min_sample || total_creation < self.min_creation_tokens {
            return None;
        }
        let ratio = total_read as f64 / total_creation as f64;
        if ratio > self.max_read_write_ratio || waste_usd <= 0.0 {
            return None;
        }

        Some(Finding {
            rule_id: "cache-dead-zone",
            title: "Cache writes that never pay off".to_string(),
            severity: Severity::Medium,
            count,
            observed_waste_usd: waste_usd,
            detail: format!(
                "{count} requests paid to *write* the prompt cache but read back only {:.1}% of it — \
                 the signature of a loop rebuilding context just slower than the cache lifetime, so the \
                 cache expires before it's reused. About ${:.2} went to the cache-write premium for nothing. \
                 Keep cached prefixes stable and reuse them within the cache window, or stop caching content \
                 that won't be re-read.",
                ratio * 100.0,
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

    fn evaluate(&self, ctx: &WasteContext<'_>) -> Option<Finding> {
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

    fn evaluate(&self, ctx: &WasteContext<'_>) -> Option<Finding> {
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

/// **Context-window saturation** — requests whose prompt fills most of the
/// model's context window. These pay peak per-turn input cost and risk
/// truncation/quality loss. Feasible because Codex reports the real
/// `model_context_window`; entries without a window (Claude Code) are skipped.
///
/// Waste is the uncached input spend on the saturated turns — money you'd trim
/// by compacting or splitting the work. (It overlaps other rules; the report's
/// headline is capped at actual spend.)
pub struct ContextWindowSaturation {
    pub min_fill_rate: f64,
    pub min_sample: usize,
}

impl Default for ContextWindowSaturation {
    fn default() -> Self {
        Self {
            min_fill_rate: 0.85,
            min_sample: 10,
        }
    }
}

impl WasteRule for ContextWindowSaturation {
    fn id(&self) -> &'static str {
        "context-window-saturation"
    }

    fn evaluate(&self, ctx: &WasteContext<'_>) -> Option<Finding> {
        let mut count = 0usize;
        let mut waste_usd = 0.0f64;

        for e in ctx.entries {
            let Some(window) = e.context_window.filter(|&w| w > 0) else {
                continue;
            };
            let fill = prompt_tokens(&e.usage) as f64 / window as f64;
            if fill < self.min_fill_rate {
                continue;
            }
            count += 1;
            if let Some(rate) = input_rate(&e.model) {
                waste_usd += e.usage.input_tokens as f64 * rate;
            }
        }

        if count < self.min_sample || waste_usd <= 0.0 {
            return None;
        }

        Some(Finding {
            rule_id: "context-window-saturation",
            title: "Requests near the context-window limit".to_string(),
            severity: Severity::Low,
            count,
            observed_waste_usd: waste_usd,
            detail: format!(
                "{count} requests ran at {:.0}%+ of the model's context window, spending about \
                 ${:.2} on input at peak per-turn cost (and risking truncation). \
                 Compacting or splitting the work keeps prompts well under the limit.",
                self.min_fill_rate * 100.0,
                waste_usd,
            ),
        })
    }
}

/// **Runaway context growth** — a session whose per-turn prompt keeps climbing,
/// so later turns re-pay for an ever-larger carried context. Trips when a
/// session's last-third average context is at least `growth_factor`× its
/// first-third average. Needs session grouping, so Claude Code (which logs a
/// `sessionId`) and Codex both qualify.
///
/// Waste is the input spend above the session's early baseline — what the
/// growth cost you. Compacting earlier would have avoided it.
pub struct RunawayContextGrowth {
    pub min_turns: usize,
    pub growth_factor: f64,
}

impl Default for RunawayContextGrowth {
    fn default() -> Self {
        Self {
            min_turns: 8,
            growth_factor: 3.0,
        }
    }
}

impl WasteRule for RunawayContextGrowth {
    fn id(&self) -> &'static str {
        "runaway-context-growth"
    }

    fn evaluate(&self, ctx: &WasteContext<'_>) -> Option<Finding> {
        let mut flagged = 0usize;
        let mut waste_usd = 0.0f64;

        for s in sessions(ctx) {
            if s.len() < self.min_turns {
                continue;
            }
            let third = (s.len() / 3).max(1);
            let early = &s[..third];
            let late = &s[s.len() - third..];
            let early_ctx = mean(early, |e| prompt_tokens(&e.usage));
            let late_ctx = mean(late, |e| prompt_tokens(&e.usage));
            if early_ctx <= 0.0 || late_ctx < self.growth_factor * early_ctx {
                continue;
            }
            // Input above the early baseline, priced per turn at its model rate.
            let baseline_input = mean(early, |e| e.usage.input_tokens);
            let mut session_waste = 0.0f64;
            for e in &s {
                let extra = (e.usage.input_tokens as f64 - baseline_input).max(0.0);
                if let Some(rate) = input_rate(&e.model) {
                    session_waste += extra * rate;
                }
            }
            if session_waste > 0.0 {
                flagged += 1;
                waste_usd += session_waste;
            }
        }

        if flagged == 0 || waste_usd <= 0.0 {
            return None;
        }

        Some(Finding {
            rule_id: "runaway-context-growth",
            title: "Sessions with a ballooning context".to_string(),
            severity: Severity::Low,
            count: flagged,
            observed_waste_usd: waste_usd,
            detail: format!(
                "{flagged} session(s) let the context grow {:.0}×+ from start to finish, \
                 spending about ${:.2} re-sending the accumulated context. \
                 Compacting or starting a fresh session for a new task trims this.",
                self.growth_factor, waste_usd,
            ),
        })
    }
}

/// **Mega-sessions** — sessions that run for very many turns while sustaining a
/// large context. Informational (no isolated dollar figure — the spend overlaps
/// the cache/growth rules), so it reports `observed_waste_usd == 0.0` and just
/// surfaces the count, per the [`Finding`] contract.
pub struct MegaSessions {
    pub min_turns: usize,
    pub min_total_prompt_tokens: u64,
}

impl Default for MegaSessions {
    fn default() -> Self {
        Self {
            min_turns: 40,
            min_total_prompt_tokens: 500_000,
        }
    }
}

impl WasteRule for MegaSessions {
    fn id(&self) -> &'static str {
        "mega-sessions"
    }

    fn evaluate(&self, ctx: &WasteContext<'_>) -> Option<Finding> {
        let count = sessions(ctx)
            .into_iter()
            .filter(|s| {
                s.len() >= self.min_turns
                    && s.iter().map(|e| prompt_tokens(&e.usage)).sum::<u64>()
                        >= self.min_total_prompt_tokens
            })
            .count();

        if count == 0 {
            return None;
        }

        Some(Finding {
            rule_id: "mega-sessions",
            title: "Very long sessions".to_string(),
            severity: Severity::Low,
            count,
            observed_waste_usd: 0.0,
            detail: format!(
                "{count} session(s) ran {}+ turns on a large sustained context. \
                 Long sessions re-pay for a growing context every turn — splitting focused \
                 work into shorter sessions keeps prompts (and cost) down.",
                self.min_turns,
            ),
        })
    }
}

/// Arithmetic mean of `f` over `entries` (`0.0` for an empty slice).
fn mean<F: Fn(&UsageEntry) -> u64>(entries: &[&UsageEntry], f: F) -> f64 {
    if entries.is_empty() {
        return 0.0;
    }
    entries.iter().map(|e| f(e) as f64).sum::<f64>() / entries.len() as f64
}
