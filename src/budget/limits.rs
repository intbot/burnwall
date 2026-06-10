//! Budget limit configuration and pure check logic.
//!
//! Kept separate from the runtime counter ([`super::BudgetTracker`]) so the
//! check function can be tested in isolation with no state.

/// Daily / monthly USD limits and the warning threshold. A limit of `0.0`
/// means unlimited — matches the TOML config convention in SPEC.md.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BudgetConfig {
    pub daily_usd: f64,
    pub monthly_usd: f64,
    /// Print ⚠️ once spend reaches this percent of the daily limit (0–100).
    pub warn_percent: u8,
    /// Hard cap on spend for a single session/swarm (USD), keyed on an opt-in
    /// `x-burnwall-session` request header. `0.0` = unlimited (off). Lets agents
    /// in a fan-out that share a session id share one blast-radius ceiling.
    pub per_session_usd: f64,
    /// Enforce the dollar caps (daily/monthly/session) on subscription traffic
    /// too. Off by default: a flat-rate plan (Claude Pro/Max via OAuth) is not
    /// metered per token, so the calculated API-equivalent dollar figure is
    /// notional — blocking on it walls the user off from money they are not
    /// spending. With `false`, subscription requests are tracked and *warned*
    /// but never blocked on the dollar cap; metered API-key traffic is always
    /// enforced. The loop detector / cost spiral still apply to both. See B-H4.
    pub enforce_on_plan: bool,
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self {
            daily_usd: 50.0,
            monthly_usd: 0.0, // unlimited per SPEC default
            warn_percent: 80,
            per_session_usd: 0.0, // off by default
            enforce_on_plan: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BudgetStatus {
    /// Spend is below the warning threshold — forward without comment.
    Ok,
    /// Spend has reached `warn_percent` of the daily limit — forward, but
    /// the proxy prints a warning. `percent` is the actual usage rounded.
    Warn { spent: f64, limit: f64, percent: u8 },
    /// Spend has reached the daily limit — proxy returns 429 and writes a
    /// blocked record.
    Exceeded { spent: f64, limit: f64 },
}

impl BudgetStatus {
    /// Convenience: should the proxy block this request?
    pub fn is_blocking(&self) -> bool {
        matches!(self, BudgetStatus::Exceeded { .. })
    }
}

/// Pure: classify `spent_usd` against the daily limit.
///
/// Boundary behavior matches SPEC step 4: `>=` daily limit blocks (b);
/// `>=` `warn_percent` of daily warns but forwards (c).
pub fn check_daily(spent_usd: f64, config: &BudgetConfig) -> BudgetStatus {
    if config.daily_usd <= 0.0 {
        return BudgetStatus::Ok;
    }
    if spent_usd >= config.daily_usd {
        return BudgetStatus::Exceeded {
            spent: spent_usd,
            limit: config.daily_usd,
        };
    }
    let warn_threshold = config.daily_usd * (config.warn_percent as f64) / 100.0;
    if spent_usd >= warn_threshold {
        let pct = ((spent_usd / config.daily_usd) * 100.0).round() as u8;
        return BudgetStatus::Warn {
            spent: spent_usd,
            limit: config.daily_usd,
            percent: pct,
        };
    }
    BudgetStatus::Ok
}

/// Pure: classify `spent_usd` (month-to-date) against the monthly limit.
///
/// Mirrors [`check_daily`] but against `monthly_usd` and with no warn tier —
/// the monthly cap is a hard backstop, and the daily warn already nudges.
/// `0.0` monthly limit = unlimited.
pub fn check_monthly(spent_usd: f64, config: &BudgetConfig) -> BudgetStatus {
    if config.monthly_usd <= 0.0 {
        return BudgetStatus::Ok;
    }
    if spent_usd >= config.monthly_usd {
        return BudgetStatus::Exceeded {
            spent: spent_usd,
            limit: config.monthly_usd,
        };
    }
    BudgetStatus::Ok
}

/// Pure: classify a session's `spent_usd` against the per-session cap. Returns
/// `Exceeded` once spend reaches the cap; no warn tier (a swarm ceiling is a
/// hard stop). `0.0` cap = unlimited.
pub fn check_session(spent_usd: f64, config: &BudgetConfig) -> BudgetStatus {
    if config.per_session_usd <= 0.0 {
        return BudgetStatus::Ok;
    }
    if spent_usd >= config.per_session_usd {
        return BudgetStatus::Exceeded {
            spent: spent_usd,
            limit: config.per_session_usd,
        };
    }
    BudgetStatus::Ok
}
