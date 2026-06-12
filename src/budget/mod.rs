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
//! The tracker is **day- and month-aware**: it stamps the local calendar day
//! and month at construction/hydration, and on every [`record`](BudgetTracker::record)
//! / [`check`](BudgetTracker::check) it lazily rolls the counter to zero when
//! the local day (or month) has changed since the stamp. This is restart-proof
//! (hydration re-derives the stamp) and clock-change-proof (any date change
//! triggers it) — unlike the old design where the documented `reset()` task was
//! never wired up, so a multi-day daemon accumulated forever and eventually
//! 429'd all traffic against the daily cap (B-C1).

use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use chrono::Datelike;

pub mod limits;
pub mod loop_detector;

pub use limits::{
    BudgetConfig, BudgetStatus, check_daily, check_hourly, check_monthly, check_session,
};
pub use loop_detector::{LoopConfig, LoopDetector, LoopVerdict};

use crate::storage::Storage;

/// 1 USD in microcents = 10⁸.
const MICROCENTS_PER_USD: f64 = 100_000_000.0;

/// Local calendar day as a monotonic integer (days since CE), for the
/// day-rollover stamp.
fn local_epoch_day() -> i64 {
    chrono::Local::now().date_naive().num_days_from_ce() as i64
}

/// Local calendar month as a monotonic integer (`year*12 + month0`), for the
/// month-rollover stamp.
fn local_epoch_month() -> i64 {
    let d = chrono::Local::now().date_naive();
    (d.year() as i64) * 12 + (d.month0() as i64)
}

pub struct BudgetTracker {
    today_microcents: AtomicU64,
    /// Month-to-date spend (microcents) for the monthly cap (B-H2).
    month_microcents: AtomicU64,
    /// Local calendar day the `today_microcents` counter belongs to. When the
    /// current local day differs, the counter is reset before use.
    day_stamp: AtomicI64,
    /// Local calendar month the `month_microcents` counter belongs to.
    month_stamp: AtomicI64,
    /// Per-session/swarm spend (microcents), keyed on the opt-in
    /// `x-burnwall-session` header. Only populated when a session id is present.
    session_microcents: dashmap::DashMap<String, u64>,
    /// Rolling window of `(timestamp, cost_usd)` for the hourly brake +
    /// speedometer (feature #2). Sliding 1-hour window held in memory only, so
    /// the pre-forward check stays sub-millisecond and restart-resets cleanly.
    /// Always tracked (the speedometer is always-on); enforcement is opt-in via
    /// `per_hour_usd`.
    hour_history: Mutex<VecDeque<(chrono::DateTime<chrono::Utc>, f64)>>,
    config: BudgetConfig,
}

impl BudgetTracker {
    pub fn new(config: BudgetConfig) -> Self {
        Self {
            today_microcents: AtomicU64::new(0),
            month_microcents: AtomicU64::new(0),
            day_stamp: AtomicI64::new(local_epoch_day()),
            month_stamp: AtomicI64::new(local_epoch_month()),
            session_microcents: dashmap::DashMap::new(),
            hour_history: Mutex::new(VecDeque::new()),
            config,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(BudgetConfig::default())
    }

    pub fn config(&self) -> &BudgetConfig {
        &self.config
    }

    /// Current accumulated spend in USD (after a lazy day-rollover).
    pub fn today_spent(&self) -> f64 {
        self.roll_if_new_period();
        (self.today_microcents.load(Ordering::Relaxed) as f64) / MICROCENTS_PER_USD
    }

    /// Month-to-date accumulated spend in USD (after a lazy month-rollover).
    pub fn month_spent(&self) -> f64 {
        self.roll_if_new_period();
        (self.month_microcents.load(Ordering::Relaxed) as f64) / MICROCENTS_PER_USD
    }

    /// Reset the daily and/or monthly counters if the local calendar day or
    /// month has advanced past the stamp. Lazy and idempotent: the first caller
    /// to observe the new period wins the compare-and-swap and zeroes the
    /// counter; concurrent callers see the already-swapped stamp and skip.
    /// At a true midnight rollover the new period's storage spend is ~0, so a
    /// reset-to-zero is correct without re-reading storage.
    fn roll_if_new_period(&self) {
        let today = local_epoch_day();
        let stamped_day = self.day_stamp.load(Ordering::Relaxed);
        if today != stamped_day
            && self
                .day_stamp
                .compare_exchange(stamped_day, today, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
        {
            self.today_microcents.store(0, Ordering::Relaxed);
        }
        let month = local_epoch_month();
        let stamped_month = self.month_stamp.load(Ordering::Relaxed);
        if month != stamped_month
            && self
                .month_stamp
                .compare_exchange(stamped_month, month, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
        {
            self.month_microcents.store(0, Ordering::Relaxed);
        }
    }

    /// Add a request's cost to the day + month counters AND the rolling-hour
    /// window. Lock-free for the day/month atomics; the hour window takes a
    /// short mutex. Negative / non-finite inputs are clamped to zero — costs
    /// are always non-negative.
    pub fn record(&self, cost_usd: f64) {
        if !cost_usd.is_finite() || cost_usd <= 0.0 {
            return;
        }
        self.roll_if_new_period();
        let units = (cost_usd * MICROCENTS_PER_USD).round() as u64;
        self.today_microcents.fetch_add(units, Ordering::Relaxed);
        self.month_microcents.fetch_add(units, Ordering::Relaxed);

        // Feed the rolling-hour window (speedometer + emergency brake, #2).
        let now = chrono::Utc::now();
        let mut hist = self.hour_history.lock().unwrap_or_else(|p| p.into_inner());
        Self::prune_hour(&mut hist, now);
        hist.push_back((now, cost_usd));
    }

    /// Drop entries older than one hour from the rolling-hour window.
    fn prune_hour(
        hist: &mut VecDeque<(chrono::DateTime<chrono::Utc>, f64)>,
        now: chrono::DateTime<chrono::Utc>,
    ) {
        let cutoff = now - chrono::Duration::hours(1);
        while let Some(front) = hist.front() {
            if front.0 < cutoff {
                hist.pop_front();
            } else {
                break;
            }
        }
    }

    /// Rolling spend (USD) over the last hour — the denominator of the hourly
    /// brake and the basis for the burn-rate speedometer.
    pub fn hour_spent(&self) -> f64 {
        let now = chrono::Utc::now();
        let mut hist = self.hour_history.lock().unwrap_or_else(|p| p.into_inner());
        Self::prune_hour(&mut hist, now);
        hist.iter().map(|(_, c)| c).sum()
    }

    /// Burn rate over the last `minutes` minutes, expressed as **USD/hour** so a
    /// short-window reading is comparable to the hourly cap (#2 speedometer).
    /// E.g. $0.50 spent in the last 5 minutes reads as $6.00/hour. Always-on and
    /// read-only — never blocks. `minutes` is clamped to `[1, 60]` (the window
    /// only holds an hour of data).
    pub fn burn_rate_per_hour(&self, minutes: u32) -> f64 {
        let minutes = minutes.clamp(1, 60);
        let now = chrono::Utc::now();
        let win_start = now - chrono::Duration::minutes(minutes as i64);
        let mut hist = self.hour_history.lock().unwrap_or_else(|p| p.into_inner());
        Self::prune_hour(&mut hist, now);
        let recent: f64 = hist
            .iter()
            .filter(|(t, _)| *t >= win_start)
            .map(|(_, c)| c)
            .sum();
        // Scale the windowed spend up to an hourly rate.
        recent * (60.0 / minutes as f64)
    }

    /// Classify rolling-hour spend against the configured hourly ceiling.
    /// `Ok` when the brake is disarmed (`per_hour_usd <= 0.0`).
    pub fn check_hourly(&self) -> BudgetStatus {
        check_hourly(self.hour_spent(), &self.config)
    }

    /// Classify the current state against the configured daily limit.
    pub fn check(&self) -> BudgetStatus {
        check_daily(self.today_spent(), &self.config)
    }

    /// Classify month-to-date spend against the configured monthly limit.
    pub fn check_monthly(&self) -> BudgetStatus {
        check_monthly(self.month_spent(), &self.config)
    }

    /// Add a request's cost to a session/swarm counter (keyed on the opt-in
    /// `x-burnwall-session` header). No-op when per-session capping is off.
    pub fn record_session(&self, session: &str, cost_usd: f64) {
        if self.config.per_session_usd <= 0.0 || !cost_usd.is_finite() || cost_usd <= 0.0 {
            return;
        }
        let units = (cost_usd * MICROCENTS_PER_USD).round() as u64;
        *self
            .session_microcents
            .entry(session.to_string())
            .or_insert(0) += units;
    }

    /// Spend so far for a session (USD).
    pub fn session_spent(&self, session: &str) -> f64 {
        self.session_microcents
            .get(session)
            .map(|v| (*v as f64) / MICROCENTS_PER_USD)
            .unwrap_or(0.0)
    }

    /// Classify a session against the per-session/swarm cap. `Ok` when capping
    /// is off or no session id is supplied.
    pub fn check_session(&self, session: &str) -> BudgetStatus {
        check_session(self.session_spent(session), &self.config)
    }

    /// Zero the daily counter and re-stamp to the current local day. Normally
    /// the lazy [`roll_if_new_period`](Self::roll_if_new_period) handles
    /// rollover; this is kept for explicit resets and tests.
    pub fn reset(&self) {
        self.today_microcents.store(0, Ordering::Relaxed);
        self.day_stamp.store(local_epoch_day(), Ordering::Relaxed);
    }

    /// Load today's spend from storage into the counter on startup, so
    /// restarting Burnwall mid-day doesn't reset the budget to zero. Stamps the
    /// counter with the **current** local day so the lazy rollover fires at the
    /// next local-day change (production always hydrates today's date; the
    /// counter reflects "now", not the queried date).
    ///
    /// `date` is a `YYYY-MM-DD` string. Replaces (not adds to) the existing
    /// counter value.
    pub fn hydrate_for_date(&self, storage: &Storage, date: &str) -> crate::storage::Result<()> {
        let spent = storage.total_cost_for_date(date)?;
        let units = (spent * MICROCENTS_PER_USD).round() as u64;
        self.today_microcents.store(units, Ordering::Relaxed);
        self.day_stamp.store(local_epoch_day(), Ordering::Relaxed);
        Ok(())
    }

    /// Load month-to-date spend from storage into the monthly counter on
    /// startup. `month` is a `YYYY-MM` string (local). Stamps the current local
    /// month so the lazy rollover fires at the next local-month change.
    pub fn hydrate_for_month(&self, storage: &Storage, month: &str) -> crate::storage::Result<()> {
        let spent = storage.total_cost_for_month(month)?;
        let units = (spent * MICROCENTS_PER_USD).round() as u64;
        self.month_microcents.store(units, Ordering::Relaxed);
        self.month_stamp
            .store(local_epoch_month(), Ordering::Relaxed);
        Ok(())
    }
}
