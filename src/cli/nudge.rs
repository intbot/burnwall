//! Contextual usage nudge for `burnwall status` — the "tip of the day" done
//! right.
//!
//! At most ONE data-driven, personalized one-liner, appended to `burnwall
//! status` and gated to once per day (see the once/day gate in `status.rs`,
//! backed by the `meta` table). It is **not** a canned tip and **not** on the
//! glanceable status line. Every nudge is drawn from the user's own data, so it
//! is evidence-backed and zero-telemetry.
//!
//! ## Bar for inclusion
//! Each finding either points at a Burnwall capability the data shows is
//! underused, or reports something Burnwall measured — reinforcing "cost is the
//! hook, security is why you stay." Generic AI-hygiene tips (e.g. "exclude lock
//! files from review") are deliberately out of scope: they point *away* from
//! the product. Findings already shown unconditionally elsewhere in `status`
//! (foregone cache-injection savings, the avoidable-spend teaser) are not
//! repeated here.
//!
//! This module is pure and unit-tested; the impure once/day gate lives in
//! `status.rs`.

/// The signals a nudge can be derived from — all already computed by `status`.
#[derive(Debug, Clone)]
pub struct NudgeState {
    /// Configured daily budget in USD (0.0 = none set).
    pub daily_budget_usd: f64,
    /// Whether there has been any real spend in the window (so we don't nag a
    /// brand-new install with no data).
    pub has_spend: bool,
    /// Aggregate cache-hit rate across the window, 0.0..=1.0.
    pub cache_hit_rate: f64,
    /// Total prompt-side tokens across the window (input + cache create + read).
    /// Used as a floor so a tiny sample doesn't trigger the cache nudge.
    pub prompt_tokens: u64,
    /// Enforcement blocks (requests actually stopped) over the window.
    pub security_blocked_window: i64,
    /// Advisory alerts (informational findings, nothing stopped) over the
    /// window. Kept separate so the receipt never inflates "blocked" with
    /// alert rows.
    pub security_alerts_window: i64,
    /// The window length in days (for message text).
    pub window_days: i64,
}

/// A selected nudge: a stable `kind` (for the once/day rotation gate) and the
/// rendered one-line message (without the leading glyph).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nudge {
    pub kind: &'static str,
    pub message: String,
}

/// Cache-hit rate below which we suggest looking at caching, when there is a
/// meaningful number of prompt tokens behind it.
const LOW_CACHE_HIT: f64 = 0.20;
/// Minimum prompt tokens before the low-cache-hit finding is eligible.
const CACHE_TOKEN_FLOOR: u64 = 50_000;

/// Fixed rotation order. `select` walks this so that, across days, a different
/// eligible finding surfaces instead of the same one every time.
const ROTATION: &[&str] = &["no_daily_budget", "low_cache_hit", "security_receipt"];

/// Render the finding of a given `kind` if its condition holds for `state`.
fn finding(kind: &str, state: &NudgeState) -> Option<Nudge> {
    match kind {
        "no_daily_budget" if state.has_spend && state.daily_budget_usd <= 0.0 => Some(Nudge {
            kind: "no_daily_budget",
            message:
                "No daily budget set — cap runaway agents with `burnwall config set budget.daily 20`."
                    .to_string(),
        }),
        "low_cache_hit"
            if state.prompt_tokens >= CACHE_TOKEN_FLOOR
                && state.cache_hit_rate < LOW_CACHE_HIT =>
        {
            Some(Nudge {
                kind: "low_cache_hit",
                message: format!(
                    "Cache hit rate is {:.0}% over {} day(s) — see what caching could save: `burnwall savings`.",
                    state.cache_hit_rate * 100.0,
                    state.window_days
                ),
            })
        }
        "security_receipt" if state.security_blocked_window > 0 => Some(Nudge {
            kind: "security_receipt",
            message: format!(
                "Burnwall blocked {} request(s) in the last {} day(s) — review them: `burnwall security --summary --days {}`.",
                state.security_blocked_window, state.window_days, state.window_days
            ),
        }),
        // Alert-only window: still a receipt worth showing, but worded as what
        // it is — findings, not interventions.
        "security_receipt" if state.security_alerts_window > 0 => Some(Nudge {
            kind: "security_receipt",
            message: format!(
                "Burnwall raised {} security alert(s) in the last {} day(s) — review them: `burnwall security --summary --days {}`.",
                state.security_alerts_window, state.window_days, state.window_days
            ),
        }),
        _ => None,
    }
}

/// Choose at most one nudge, rotating past `last_shown` so a repeat is avoided
/// whenever more than one finding is eligible. Returns `None` when the user's
/// data yields no real finding (the common, quiet case).
pub fn select(state: &NudgeState, last_shown: Option<&str>) -> Option<Nudge> {
    let eligible: Vec<Nudge> = ROTATION.iter().filter_map(|k| finding(k, state)).collect();
    if eligible.is_empty() {
        return None;
    }
    // Advance to the finding *after* the one shown last time, cyclically, so the
    // surfaced nudge changes day to day when several are eligible. With a single
    // eligible finding this returns it (worth repeating until acted on).
    let start = match last_shown.and_then(|ls| eligible.iter().position(|n| n.kind == ls)) {
        Some(i) => (i + 1) % eligible.len(),
        None => 0,
    };
    Some(eligible[start].clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> NudgeState {
        NudgeState {
            daily_budget_usd: 20.0,
            has_spend: true,
            cache_hit_rate: 0.8,
            prompt_tokens: 1_000_000,
            security_blocked_window: 0,
            security_alerts_window: 0,
            window_days: 7,
        }
    }

    #[test]
    fn no_finding_when_everything_is_healthy() {
        assert!(select(&base(), None).is_none());
    }

    #[test]
    fn quiet_for_a_fresh_install_with_no_spend() {
        let mut s = base();
        s.has_spend = false;
        s.daily_budget_usd = 0.0;
        // No spend ⇒ no budget nag, nothing else eligible ⇒ silent.
        assert!(select(&s, None).is_none());
    }

    #[test]
    fn surfaces_missing_budget() {
        let mut s = base();
        s.daily_budget_usd = 0.0;
        let n = select(&s, None).expect("a finding");
        assert_eq!(n.kind, "no_daily_budget");
        assert!(n.message.contains("budget.daily"));
    }

    #[test]
    fn low_cache_hit_needs_enough_tokens() {
        let mut s = base();
        s.cache_hit_rate = 0.05;
        s.prompt_tokens = 10_000; // below floor
        assert!(select(&s, None).is_none());
        s.prompt_tokens = 200_000; // above floor
        let n = select(&s, None).expect("a finding");
        assert_eq!(n.kind, "low_cache_hit");
    }

    #[test]
    fn rotates_past_the_last_shown_when_several_eligible() {
        let mut s = base();
        s.daily_budget_usd = 0.0; // no_daily_budget eligible
        s.cache_hit_rate = 0.0;
        s.prompt_tokens = 200_000; // low_cache_hit eligible
        s.security_blocked_window = 3; // security_receipt eligible

        // First time: starts at the front of the rotation.
        let first = select(&s, None).unwrap();
        assert_eq!(first.kind, "no_daily_budget");
        // Given that was last shown, the next surfaces a different finding.
        let second = select(&s, Some("no_daily_budget")).unwrap();
        assert_eq!(second.kind, "low_cache_hit");
        let third = select(&s, Some("low_cache_hit")).unwrap();
        assert_eq!(third.kind, "security_receipt");
        // Wraps around.
        let wrap = select(&s, Some("security_receipt")).unwrap();
        assert_eq!(wrap.kind, "no_daily_budget");
    }

    #[test]
    fn single_eligible_finding_repeats_until_resolved() {
        let mut s = base();
        s.security_blocked_window = 1; // only this one eligible
        let n = select(&s, Some("security_receipt")).unwrap();
        assert_eq!(n.kind, "security_receipt");
    }

    #[test]
    fn receipt_words_blocks_and_alerts_honestly() {
        // Real blocks → "blocked N request(s)".
        let mut s = base();
        s.security_blocked_window = 2;
        s.security_alerts_window = 153;
        let n = select(&s, None).expect("a finding");
        assert!(
            n.message.contains("blocked 2 request(s)"),
            "got: {}",
            n.message
        );
        assert!(
            !n.message.contains("155"),
            "alerts must not inflate the blocked count: {}",
            n.message
        );
        // Alert-only window → "raised N security alert(s)", never "blocked".
        s.security_blocked_window = 0;
        let n = select(&s, None).expect("a finding");
        assert!(
            n.message.contains("raised 153 security alert(s)"),
            "got: {}",
            n.message
        );
        assert!(!n.message.contains("blocked"), "got: {}", n.message);
    }
}
