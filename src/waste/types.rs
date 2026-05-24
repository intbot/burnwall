//! Core types for the waste-insights engine.
//!
//! A [`WasteRule`] inspects the local usage stream and, if it finds a
//! cost-waste or security pattern, returns a [`Finding`] annotated with the
//! observed dollar impact. Rules are pure functions over a [`WasteContext`]:
//! no I/O, no clock, no network — so they're trivially testable.
//!
//! Rules are hardcoded Rust behind the trait.

use crate::logscrape::UsageEntry;

/// How loudly a finding should be surfaced. Ordering matters for sorting:
/// `High > Medium > Low`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
        }
    }
}

/// One detected waste/security pattern. `observed_waste_usd` is computed from
/// the *real* token counts in the usage stream and the pricing table — it is
/// an estimate (the rule documents its assumption), framed as money already
/// spent, never a speculative future "saving".
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub rule_id: &'static str,
    pub title: String,
    pub severity: Severity,
    /// Number of requests (or sessions) that tripped the rule.
    pub count: usize,
    /// Estimated USD already spent on the wasteful pattern. `0.0` is allowed
    /// for security-trend findings that have no direct dollar figure.
    pub observed_waste_usd: f64,
    /// One-line, human-readable explanation. Metadata only — never prompt
    /// content.
    pub detail: String,
}

/// Read-only input to every rule: the slice of usage entries under analysis
/// (already filtered to the requested time window by the caller).
pub struct WasteContext<'a> {
    pub entries: &'a [UsageEntry],
}

/// A single waste/security detector. Implementors are registered in
/// [`crate::waste::default_rules`].
pub trait WasteRule {
    /// Stable kebab-case identifier, e.g. `"cache-hit-starvation"`.
    fn id(&self) -> &'static str;

    /// Inspect the context; return `Some(Finding)` to surface, `None` to stay
    /// quiet. Must not panic and must not read prompt/response content.
    fn evaluate(&self, ctx: &WasteContext) -> Option<Finding>;
}
