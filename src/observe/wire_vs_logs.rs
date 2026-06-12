//! Wire-vs-logs accuracy (v0.9).
//!
//! Compares **real on-the-wire spend** — the cost Burnwall computed from the
//! provider's own `usage` block on every proxied response, stored in the
//! `requests` table — against what a **log-scraping estimate** would report for
//! the same window. Log scrapers read each tool's local session logs after the
//! fact; they can miss turns the proxy saw (or count turns that never reached a
//! provider), and they re-derive cost from the same pricing table but from
//! token counts the tool chose to persist. This surfaces that drift so a user
//! relying on a pure log reader can see the gap.
//!
//! Pure + metadata-only. The CLI feeds in the wire aggregates (from storage)
//! and the log-scrape entries; the math here is deterministic and testable.
//! Framing is factual: drift can run either direction and neither source is
//! "wrong" — they measure different things.

use std::collections::BTreeMap;

use crate::pricing;

/// Per-model wire vs. logs comparison.
#[derive(Debug, Clone, PartialEq)]
pub struct ModelDrift {
    pub model: String,
    /// Cost Burnwall recorded on the wire for this model in the window.
    pub wire_cost_usd: f64,
    /// Cost a log-scrape estimate would report for the same model + window.
    pub logs_cost_usd: f64,
    /// Requests seen on the wire (proxied, non-blocked).
    pub wire_requests: u64,
    /// Turns the log scrape attributed to this model.
    pub logs_turns: u64,
}

impl ModelDrift {
    /// Signed absolute drift, logs minus wire: positive when the log estimate
    /// over-reports, negative when it under-reports.
    pub fn drift_usd(&self) -> f64 {
        (self.logs_cost_usd - self.wire_cost_usd) + 0.0
    }

    /// Drift as a percentage of the on-the-wire cost. `None` when wire cost is
    /// zero (no proxied spend to compare against — percentage is undefined).
    pub fn drift_pct(&self) -> Option<f64> {
        if self.wire_cost_usd.abs() < f64::EPSILON {
            None
        } else {
            Some((self.logs_cost_usd - self.wire_cost_usd) / self.wire_cost_usd * 100.0)
        }
    }
}

/// The full comparison over a window: per-model rows plus a roll-up total.
#[derive(Debug, Clone, PartialEq)]
pub struct DriftReport {
    pub days: i64,
    pub by_model: Vec<ModelDrift>,
    pub total_wire_usd: f64,
    pub total_logs_usd: f64,
    /// True when no log-scrape entries fell in the window — the logs side is
    /// empty, so the report degrades to "wire only" rather than implying the
    /// scraper agreed.
    pub logs_unavailable: bool,
}

impl DriftReport {
    /// Signed total drift (logs − wire).
    pub fn total_drift_usd(&self) -> f64 {
        (self.total_logs_usd - self.total_wire_usd) + 0.0
    }

    /// Total drift as a percentage of total wire cost. `None` when wire total
    /// is zero.
    pub fn total_drift_pct(&self) -> Option<f64> {
        if self.total_wire_usd.abs() < f64::EPSILON {
            None
        } else {
            Some((self.total_logs_usd - self.total_wire_usd) / self.total_wire_usd * 100.0)
        }
    }
}

/// One on-the-wire per-model aggregate, as read from storage.
/// `(model, cost_usd, requests)`.
#[derive(Debug, Clone, PartialEq)]
pub struct WireModel {
    pub model: String,
    pub cost_usd: f64,
    pub requests: u64,
}

/// One log-scrape per-model aggregate. `(model, cost_usd, turns)`. Cost is
/// re-derived from the same pricing table the wire side used, so a difference
/// reflects differing token counts / turn coverage, not differing rates.
#[derive(Debug, Clone, PartialEq)]
pub struct LogsModel {
    pub model: String,
    pub cost_usd: f64,
    pub turns: u64,
}

/// Compute the drift report from pre-aggregated wire + logs per-model rows.
///
/// Models are matched by exact model name (both sides cost from the same
/// pricing table, so the model string is the join key). A model present on one
/// side only still appears, with the other side at zero — that *is* the drift a
/// log reader would miss. Output rows are sorted by wire cost descending, then
/// model name, for deterministic ordering.
pub fn compute_drift(
    days: i64,
    wire: &[WireModel],
    logs: &[LogsModel],
    logs_unavailable: bool,
) -> DriftReport {
    let mut map: BTreeMap<String, (f64, u64, f64, u64)> = BTreeMap::new();
    for w in wire {
        let e = map.entry(w.model.clone()).or_default();
        e.0 += w.cost_usd;
        e.1 += w.requests;
    }
    for l in logs {
        let e = map.entry(l.model.clone()).or_default();
        e.2 += l.cost_usd;
        e.3 += l.turns;
    }

    let mut by_model: Vec<ModelDrift> = map
        .into_iter()
        .map(
            |(model, (wire_cost, wire_req, logs_cost, logs_turns))| ModelDrift {
                model,
                wire_cost_usd: wire_cost + 0.0,
                logs_cost_usd: logs_cost + 0.0,
                wire_requests: wire_req,
                logs_turns,
            },
        )
        .collect();
    by_model.sort_by(|a, b| {
        b.wire_cost_usd
            .partial_cmp(&a.wire_cost_usd)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.model.cmp(&b.model))
    });

    let total_wire_usd = by_model.iter().map(|m| m.wire_cost_usd).sum::<f64>() + 0.0;
    let total_logs_usd = by_model.iter().map(|m| m.logs_cost_usd).sum::<f64>() + 0.0;

    DriftReport {
        days,
        by_model,
        total_wire_usd,
        total_logs_usd,
        logs_unavailable,
    }
}

/// Aggregate raw log-scrape entries into per-model [`LogsModel`] rows, costing
/// each via the pricing table (unknown model → 0.0, fail-open). Deterministic
/// order is not required here — [`compute_drift`] re-sorts.
pub fn logs_by_model(entries: &[crate::logscrape::UsageEntry]) -> Vec<LogsModel> {
    let mut map: BTreeMap<String, (f64, u64)> = BTreeMap::new();
    for e in entries {
        let cost = pricing::calculate_cost(&e.model, &e.usage).unwrap_or(0.0);
        let slot = map.entry(e.model.clone()).or_default();
        slot.0 += cost;
        slot.1 += 1;
    }
    map.into_iter()
        .map(|(model, (cost_usd, turns))| LogsModel {
            model,
            cost_usd,
            turns,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire(model: &str, cost: f64, req: u64) -> WireModel {
        WireModel {
            model: model.to_string(),
            cost_usd: cost,
            requests: req,
        }
    }
    fn logs(model: &str, cost: f64, turns: u64) -> LogsModel {
        LogsModel {
            model: model.to_string(),
            cost_usd: cost,
            turns,
        }
    }

    #[test]
    fn matched_model_computes_abs_and_pct_drift() {
        let r = compute_drift(7, &[wire("m", 10.0, 5)], &[logs("m", 8.0, 4)], false);
        assert_eq!(r.by_model.len(), 1);
        let d = &r.by_model[0];
        assert!((d.drift_usd() - (-2.0)).abs() < 1e-9, "logs under by 2");
        assert!((d.drift_pct().unwrap() - (-20.0)).abs() < 1e-9);
        assert!((r.total_drift_usd() - (-2.0)).abs() < 1e-9);
        assert!((r.total_drift_pct().unwrap() - (-20.0)).abs() < 1e-9);
    }

    #[test]
    fn model_only_on_wire_shows_full_gap() {
        // Log scraper missed this model entirely — exactly the gap to surface.
        let r = compute_drift(7, &[wire("seen", 5.0, 3)], &[], false);
        assert_eq!(r.by_model.len(), 1);
        assert_eq!(r.by_model[0].logs_cost_usd, 0.0);
        assert!((r.by_model[0].drift_pct().unwrap() - (-100.0)).abs() < 1e-9);
    }

    #[test]
    fn model_only_in_logs_has_undefined_pct() {
        // Counted by the scraper but never proxied: wire cost 0 ⇒ pct undefined.
        let r = compute_drift(7, &[], &[logs("ghost", 3.0, 2)], false);
        assert_eq!(r.by_model.len(), 1);
        assert_eq!(r.by_model[0].wire_cost_usd, 0.0);
        assert!(r.by_model[0].drift_pct().is_none());
        assert!((r.by_model[0].drift_usd() - 3.0).abs() < 1e-9);
    }

    #[test]
    fn rows_sorted_by_wire_cost_desc_then_model() {
        let r = compute_drift(
            7,
            &[wire("b", 1.0, 1), wire("a", 9.0, 1), wire("c", 9.0, 1)],
            &[],
            false,
        );
        let models: Vec<&str> = r.by_model.iter().map(|m| m.model.as_str()).collect();
        // 9.0 ties broken by model name asc (a before c), then 1.0.
        assert_eq!(models, vec!["a", "c", "b"]);
    }

    #[test]
    fn empty_both_sides_is_zero_not_negative_zero() {
        let r = compute_drift(7, &[], &[], true);
        assert!(r.by_model.is_empty());
        assert_eq!(r.total_wire_usd, 0.0);
        assert_eq!(r.total_drift_usd(), 0.0);
        assert!(r.total_drift_usd().is_sign_positive());
        assert!(r.total_drift_pct().is_none());
        assert!(r.logs_unavailable);
    }

    #[test]
    fn totals_sum_across_models() {
        let r = compute_drift(
            30,
            &[wire("m1", 10.0, 2), wire("m2", 5.0, 1)],
            &[logs("m1", 11.0, 2), logs("m2", 4.0, 1)],
            false,
        );
        assert!((r.total_wire_usd - 15.0).abs() < 1e-9);
        assert!((r.total_logs_usd - 15.0).abs() < 1e-9);
        // Net drift cancels to ~0 even though per-model drifts are non-zero.
        assert!(r.total_drift_usd().abs() < 1e-9);
    }
}
