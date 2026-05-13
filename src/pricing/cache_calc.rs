//! Cache-aware cost calculation.
//!
//! `cost` sums the four token buckets each at its own rate.
//! `cost_without_cache` answers "what would this have cost if every prompt
//! token had been billed at the base input rate" — the difference is the
//! cache savings displayed in `burnwall status`.

use super::rates::ModelPricing;
use crate::providers::TokenUsage;

const TOKENS_PER_MTOK: f64 = 1_000_000.0;

/// Total billed cost in USD given the four token buckets and the rate card.
pub fn cost(usage: &TokenUsage, pricing: &ModelPricing) -> f64 {
    let input = (usage.input_tokens as f64) * pricing.input_per_mtok;
    let cache_write = (usage.cache_creation_tokens as f64) * pricing.cache_write_per_mtok;
    let cache_read = (usage.cache_read_tokens as f64) * pricing.cache_read_per_mtok;
    let output = (usage.output_tokens as f64) * pricing.output_per_mtok;
    (input + cache_write + cache_read + output) / TOKENS_PER_MTOK
}

/// Hypothetical cost if no caching existed: every prompt token (cached writes
/// + cached reads + non-cached) billed at the base input rate.
pub fn cost_without_cache(usage: &TokenUsage, pricing: &ModelPricing) -> f64 {
    let total_input = usage.input_tokens + usage.cache_creation_tokens + usage.cache_read_tokens;
    let input = (total_input as f64) * pricing.input_per_mtok;
    let output = (usage.output_tokens as f64) * pricing.output_per_mtok;
    (input + output) / TOKENS_PER_MTOK
}

/// Dollars saved versus the no-cache hypothetical. Non-negative for any
/// well-formed rate card (cache_read_per_mtok ≤ input_per_mtok).
pub fn cache_savings(usage: &TokenUsage, pricing: &ModelPricing) -> f64 {
    cost_without_cache(usage, pricing) - cost(usage, pricing)
}
