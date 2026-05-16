//! Budget tracker.
//!
//! [`BudgetTracker`] keeps today's spend in a single `AtomicU64` so the
//! pre-forward check is lock-free and sub-millisecond. The value is stored
//! as **microcents** (10⁻⁸ USD) rather than cents — the SPEC says "cents"
//! but a single short request to `gpt-5.4-mini` costs ~0.005 cents, which
//! would round to zero and silently break the budget. Microcents give 8
//! decimal digits of precision (one cent = 1_000_000 microcents) while
//! still fitting comfortably in `u64` (max ≈ $1.8 × 10¹¹).
//!
//! ### Race window
//! Per ARCHITECTURE.md "Budget Tracking", there is a small window where
//! several concurrent in-flight requests can collectively overshoot the
//! limit (each saw the counter under the limit before any added cost). We
//! accept this — locking every request adds latency, and a few cents of
//! overshoot is harmless.
//!
//! ### Date awareness
//! The tracker is date-agnostic: it just accumulates. The caller (the proxy
//! / a scheduled reset task) tells it when to reset by calling
//! [`BudgetTracker::reset`] at midnight, and the caller picks UTC vs local.

use std::sync::atomic::{AtomicU64, Ordering};

pub mod limits;
pub mod loop_detector;

pub use limits::{check_daily, BudgetConfig, BudgetStatus};
pub use loop_detector::{LoopConfig, LoopDetector, LoopVerdict};

use crate::storage::Storage;

/// 1 USD in microcents = 10⁸.
const MICROCENTS_PER_USD: f64 = 100_000_000.0;

pub struct BudgetTracker {
    today_microcents: AtomicU64,
    config: BudgetConfig,
}

impl BudgetTracker {
    pub fn new(config: BudgetConfig) -> Self {
        Self {
            today_microcents: AtomicU64::new(0),
            config,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(BudgetConfig::default())
    }

    pub fn config(&self) -> &BudgetConfig {
        &self.config
    }

    /// Current accumulated spend in USD.
    pub fn today_spent(&self) -> f64 {
        (self.today_microcents.load(Ordering::Relaxed) as f64) / MICROCENTS_PER_USD
    }

    /// Add a request's cost to the counter. Lock-free.
    /// Negative inputs are clamped to zero — costs are always non-negative.
    pub fn record(&self, cost_usd: f64) {
        if !cost_usd.is_finite() || cost_usd <= 0.0 {
            return;
        }
        let units = (cost_usd * MICROCENTS_PER_USD).round() as u64;
        self.today_microcents.fetch_add(units, Ordering::Relaxed);
    }

    /// Classify the current state against the configured daily limit.
    pub fn check(&self) -> BudgetStatus {
        check_daily(self.today_spent(), &self.config)
    }

    /// Zero the counter — call at midnight (caller decides UTC vs local).
    pub fn reset(&self) {
        self.today_microcents.store(0, Ordering::Relaxed);
    }

    /// Load today's spend from storage into the counter on startup, so
    /// restarting Burnwall mid-day doesn't reset the budget to zero.
    ///
    /// `date` is a `YYYY-MM-DD` string; the caller decides whether that's
    /// UTC or local. Replaces (not adds to) the existing counter value.
    pub fn hydrate_for_date(&self, storage: &Storage, date: &str) -> crate::storage::Result<()> {
        let spent = storage.total_cost_for_date(date)?;
        let units = (spent * MICROCENTS_PER_USD).round() as u64;
        self.today_microcents.store(units, Ordering::Relaxed);
        Ok(())
    }
}
