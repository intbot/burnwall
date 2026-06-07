//! Pricing database and cost calculator.
//!
//! Public surface:
//! - [`get_pricing`]: model name → [`ModelPricing`] (with date-suffix tolerance)
//! - [`cost`] / [`cost_without_cache`] / [`cache_savings`]: cache-aware math
//! - [`calculate_cost`]: convenience that combines lookup + calculation

pub mod cache_calc;
pub mod overrides;
pub mod rates;

pub use cache_calc::{cache_savings, cost, cost_without_cache};
pub use rates::{get_pricing, get_pricing_with, ModelPricing, KNOWN_MODELS, PRICING_LAST_UPDATED};

/// Load user pricing overrides from `~/.burnwall/pricing.toml` into the
/// process-global table. Call once at startup, before any cost is computed.
/// Returns the number of overrides loaded; a malformed file is an error the
/// caller should surface but not treat as fatal (fail-open).
pub fn init_overrides() -> Result<usize, overrides::OverrideError> {
    overrides::init()
}

use crate::providers::TokenUsage;

/// Look up `model` and compute billed cost in USD. Returns `None` when the
/// model is unknown — callers should treat this as "cost unknown, log and
/// proceed" per the fail-open policy (never break the user's workflow over
/// a pricing miss).
pub fn calculate_cost(model: &str, usage: &TokenUsage) -> Option<f64> {
    get_pricing(model).map(|p| cost(usage, p))
}

/// Days since [`PRICING_LAST_UPDATED`] vs the supplied "today". `None` if
/// the constant is malformed (parse failure) -- callers should treat this
/// as "freshness unknown" rather than panicking.
pub fn pricing_age_days(today: chrono::NaiveDate) -> Option<i64> {
    let updated = chrono::NaiveDate::parse_from_str(PRICING_LAST_UPDATED, "%Y-%m-%d").ok()?;
    Some((today - updated).num_days())
}
