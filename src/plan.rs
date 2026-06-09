//! Subscription-plan limit tracking from provider rate-limit response headers.
//!
//! A Claude subscription (Pro/Max) reports usage windows on every authenticated
//! Messages response as `anthropic-ratelimit-unified-*` headers (a rolling
//! 5-hour window and a 7-day window). An API key reports a *different* family
//! (`anthropic-ratelimit-requests-*` / `-tokens-*`, per-minute) and never emits
//! `unified-*` — so the header family is itself the subscription-vs-API
//! discriminator (verified against Anthropic's docs).
//!
//! The proxy parses these off the upstream response (they ride on traffic it
//! already forwards) and persists the latest [`PlanSnapshot`] **per provider** so
//! any surface — the Claude Code status line, `burnwall watch`, the editor
//! extension — can show real limit headroom, the scarce resource for a flat-rate
//! subscriber, instead of a notional dollar figure.
//!
//! ## Provider-generic by design
//!
//! A snapshot is a provider tag plus an ordered list of [`LimitWindow`]s (binding
//! window first). Anthropic is implemented; OpenAI/Google hooks exist but return
//! `None` until their subscription signal is *probed and verified* — we don't
//! fabricate a window from per-minute API limits (those are API mode → dollars).
//!
//! ## Not sensitive
//!
//! A snapshot is utilization percentages, reset timestamps, and a status word —
//! no API key, no prompt content, no org identifier. Consistent with the
//! metadata-only storage principle.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// File under the data dir holding the per-provider snapshot map.
pub const SNAPSHOT_FILE: &str = "plan_limits.json";

/// One usage window of a subscription plan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LimitWindow {
    /// Short label, e.g. `5h` / `7d`.
    pub label: String,
    /// Fraction consumed, 0.0–1.0.
    pub utilization: f64,
    /// Unix epoch (seconds) when the window fully resets (0 if unknown).
    pub reset: i64,
}

/// Latest subscription-limit reading for one provider.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlanSnapshot {
    /// Upstream provider this reading is for (`anthropic`, `openai`, …).
    pub provider: String,
    /// Usage windows, ordered with the binding (representative) window first.
    pub windows: Vec<LimitWindow>,
    /// Overall status (`allowed`, `throttled`, …).
    pub status: String,
    /// Unix epoch (seconds) when we observed this reading — for staleness.
    pub captured_at: i64,
}

impl PlanSnapshot {
    /// True if the snapshot is too old to trust (windows would be stale). A
    /// subscriber making any request refreshes it, so a long gap means they've
    /// been idle — show nothing rather than a misleading number.
    pub fn is_stale(&self, now: i64, max_age_secs: i64) -> bool {
        now - self.captured_at > max_age_secs
    }

    /// Map to the renderer's [`crate::ribbon::PlanLimits`] (binding window as
    /// primary, next as secondary). `None` if there are no windows.
    pub fn to_ribbon_limits(&self, now: i64) -> Option<crate::ribbon::PlanLimits> {
        let primary = self.windows.first()?;
        Some(crate::ribbon::PlanLimits {
            primary_label: primary.label.clone(),
            primary_pct: (primary.utilization * 100.0).clamp(0.0, 100.0),
            primary_reset_in: Some((primary.reset - now).max(0)),
            secondary: self
                .windows
                .get(1)
                .map(|w| (w.label.clone(), (w.utilization * 100.0).clamp(0.0, 100.0))),
            throttled: self.status != "allowed",
        })
    }
}

/// Parse a provider's rate-limit response headers into a [`PlanSnapshot`].
/// Returns `None` when there's no subscription signal (API key, error response,
/// or a provider we don't yet decode) — exactly the "not a subscription reading"
/// answer the caller wants.
pub fn parse_limits(provider: &str, headers: &hyper::HeaderMap, now: i64) -> Option<PlanSnapshot> {
    match provider {
        "anthropic" => parse_anthropic(headers, now),
        "openai" => parse_openai(headers, now),
        _ => None,
    }
}

/// Anthropic `unified-*` (Claude Pro/Max) → 5-hour + 7-day windows, ordered by
/// the provider's `representative-claim` (the currently-binding window first).
fn parse_anthropic(headers: &hyper::HeaderMap, now: i64) -> Option<PlanSnapshot> {
    let get = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    // The 5-hour utilization anchors detection: absent ⇒ not a unified response.
    let five_h: f64 = get("anthropic-ratelimit-unified-5h-utilization")?
        .trim()
        .parse()
        .ok()?;
    let i64_of = |name: &str| get(name).and_then(|s| s.trim().parse::<i64>().ok());
    let f64_of = |name: &str| get(name).and_then(|s| s.trim().parse::<f64>().ok());

    let five = LimitWindow {
        label: "5h".to_string(),
        utilization: five_h,
        reset: i64_of("anthropic-ratelimit-unified-5h-reset").unwrap_or(0),
    };
    let seven = LimitWindow {
        label: "7d".to_string(),
        utilization: f64_of("anthropic-ratelimit-unified-7d-utilization").unwrap_or(0.0),
        reset: i64_of("anthropic-ratelimit-unified-7d-reset").unwrap_or(0),
    };
    // Lead with whichever window the provider says is binding.
    let windows = match get("anthropic-ratelimit-unified-representative-claim") {
        Some("seven_day") => vec![seven, five],
        _ => vec![five, seven],
    };
    Some(PlanSnapshot {
        provider: "anthropic".to_string(),
        windows,
        status: get("anthropic-ratelimit-unified-status")
            .unwrap_or("allowed")
            .to_string(),
        captured_at: now,
    })
}

/// OpenAI subscription (ChatGPT Plus/Pro via Codex) is **unverified**: Codex may
/// not route through this proxy at all, and we have not observed a
/// subscription-usage header set. The standard API returns only per-minute
/// `x-ratelimit-*` (API mode → dollars), which is *not* a plan window, so we
/// deliberately do not synthesize one. Returns `None` until a live probe
/// confirms a real signal — see `internal/ROADMAP.md` for the probe method.
fn parse_openai(_headers: &hyper::HeaderMap, _now: i64) -> Option<PlanSnapshot> {
    None
}

/// Path to the snapshot file under the data dir, if a data dir resolves.
pub fn snapshot_path() -> Option<PathBuf> {
    crate::storage::data_dir().ok().map(|d| d.join(SNAPSHOT_FILE))
}

/// Load the per-provider snapshot map (empty on missing/unreadable/legacy file).
fn read_map() -> BTreeMap<String, PlanSnapshot> {
    snapshot_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Persist a snapshot for its provider, merging into the map (best-effort;
/// creates the data dir if needed).
pub fn write_snapshot(snap: &PlanSnapshot) -> std::io::Result<()> {
    let Some(path) = snapshot_path() else {
        return Ok(());
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut map = read_map();
    map.insert(snap.provider.clone(), snap.clone());
    let json = serde_json::to_string(&map).unwrap_or_default();
    std::fs::write(path, json)
}

/// All persisted provider snapshots.
pub fn read_all() -> Vec<PlanSnapshot> {
    read_map().into_values().collect()
}

/// The freshest non-stale snapshot across providers — what a single-line surface
/// (status bar, `watch`) leads with.
pub fn freshest(now: i64, max_age_secs: i64) -> Option<PlanSnapshot> {
    read_all()
        .into_iter()
        .filter(|s| !s.is_stale(now, max_age_secs))
        .max_by_key(|s| s.captured_at)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::HeaderMap;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                hyper::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                hyper::header::HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    fn unified() -> HeaderMap {
        headers(&[
            ("anthropic-ratelimit-unified-5h-utilization", "0.11"),
            ("anthropic-ratelimit-unified-5h-reset", "1780960800"),
            ("anthropic-ratelimit-unified-7d-utilization", "0.1"),
            ("anthropic-ratelimit-unified-7d-reset", "1781150400"),
            ("anthropic-ratelimit-unified-status", "allowed"),
            ("anthropic-ratelimit-unified-representative-claim", "five_hour"),
        ])
    }

    #[test]
    fn parses_anthropic_unified_with_binding_first() {
        let snap = parse_limits("anthropic", &unified(), 1780951905).expect("parses");
        assert_eq!(snap.provider, "anthropic");
        assert_eq!(snap.windows[0].label, "5h"); // representative = five_hour
        assert!((snap.windows[0].utilization - 0.11).abs() < 1e-9);
        assert_eq!(snap.windows[0].reset, 1780960800);
        assert_eq!(snap.windows[1].label, "7d");
        assert_eq!(snap.status, "allowed");
    }

    #[test]
    fn seven_day_binding_is_ordered_first() {
        let mut h = unified();
        h.insert(
            "anthropic-ratelimit-unified-representative-claim",
            hyper::header::HeaderValue::from_static("seven_day"),
        );
        let snap = parse_limits("anthropic", &h, 0).unwrap();
        assert_eq!(snap.windows[0].label, "7d");
        assert_eq!(snap.windows[1].label, "5h");
    }

    #[test]
    fn api_key_and_openai_yield_none() {
        // Classic per-minute Anthropic API headers carry no `unified-*`.
        let api = headers(&[("anthropic-ratelimit-tokens-remaining", "29000")]);
        assert!(parse_limits("anthropic", &api, 0).is_none());
        // OpenAI is unverified → None for now.
        assert!(parse_limits("openai", &unified(), 0).is_none());
        assert!(parse_limits("google", &unified(), 0).is_none());
    }

    #[test]
    fn to_ribbon_limits_maps_primary_and_secondary() {
        let snap = parse_limits("anthropic", &unified(), 1780951905).unwrap();
        let rl = snap.to_ribbon_limits(1780951905).unwrap();
        assert_eq!(rl.primary_label, "5h");
        assert!((rl.primary_pct - 11.0).abs() < 1e-9);
        assert_eq!(rl.secondary, Some(("7d".to_string(), 10.0)));
        assert!(!rl.throttled);
    }

    #[test]
    fn snapshot_json_round_trips() {
        let snap = parse_limits("anthropic", &unified(), 1780951905).unwrap();
        let json = serde_json::to_string(&snap).unwrap();
        let back: PlanSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, back);
    }

    #[test]
    fn staleness_check() {
        let snap = PlanSnapshot {
            provider: "anthropic".to_string(),
            windows: vec![],
            status: "allowed".to_string(),
            captured_at: 1000,
        };
        assert!(!snap.is_stale(1000 + 3600, 12 * 3600));
        assert!(snap.is_stale(1000 + 13 * 3600, 12 * 3600));
    }
}
