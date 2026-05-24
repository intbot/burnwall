//! Waste insights — the cost-waste detection pillar.
//!
//! The big sibling of loop detection: where loop detection blocks the most
//! extreme runaway-cost pattern in real time, the waste engine surfaces the
//! softer, post-hoc-detectable patterns (cache starvation, model
//! overreliance, context bloat, ...) as an advisory report. It rides on the
//! same `logscrape` usage stream — read-only, metadata only, never prompt
//! content — so it works across every tool whose logs we can read, not just
//! proxied traffic.
//!
//! Findings carry an **observed** dollar figure (money already spent on the
//! pattern), never a speculative "saving". Each rule documents how it
//! estimates that figure.

pub mod rules;
pub mod types;

pub use types::{Finding, Severity, WasteContext, WasteRule};

use crate::logscrape::UsageEntry;

/// The default rule registry.
pub fn default_rules() -> Vec<Box<dyn WasteRule>> {
    vec![
        Box::new(rules::CacheHitStarvation::default()),
        Box::new(rules::ModelOverreliance::default()),
        Box::new(rules::ReasoningEffortOveruse::default()),
    ]
}

/// Run the default rules over `entries`, returning findings sorted by
/// observed waste (largest first).
pub fn analyze(entries: &[UsageEntry]) -> Vec<Finding> {
    analyze_with(entries, &default_rules())
}

/// Run a specific rule set — used by tests to inject tuned thresholds.
pub fn analyze_with(entries: &[UsageEntry], rules: &[Box<dyn WasteRule>]) -> Vec<Finding> {
    let ctx = WasteContext { entries };
    let mut findings: Vec<Finding> = rules.iter().filter_map(|r| r.evaluate(&ctx)).collect();
    findings.sort_by(|a, b| {
        b.observed_waste_usd
            .partial_cmp(&a.observed_waste_usd)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.severity.cmp(&a.severity))
            .then_with(|| a.rule_id.cmp(b.rule_id))
    });
    findings
}

/// Sum of observed waste across findings — the headline number. The `+ 0.0`
/// normalizes a `-0.0` sum to `0.0` so the JSON/table output reads cleanly.
pub fn total_waste_usd(findings: &[Finding]) -> f64 {
    findings.iter().map(|f| f.observed_waste_usd).sum::<f64>() + 0.0
}
