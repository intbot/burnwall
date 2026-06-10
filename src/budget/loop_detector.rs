//! Loop detection — block runaway agents that hammer the same request or
//! burn an unreasonable amount of money in a short window.
//!
//! Two independent mechanisms:
//!
//! - **Repeated-content loop**: hash the full request body; if the same
//!   hash appears `max_identical_requests` times within `window_seconds`,
//!   block with HTTP 429.
//! - **Cost spiral**: independently of content, if the rolling per-window
//!   cost exceeds `max_cost_per_window`, block.
//!
//! Both detectors use sliding-window state held in memory only — no
//! storage involvement, so the proxy can decide pre-forward in
//! sub-millisecond time. State is process-local; restarting the proxy
//! resets both windows.
//!
//! Hash function: stdlib `DefaultHasher` (SipHash). The seed is randomized
//! per-process which is fine — we only need same content -> same hash
//! within a single run.

use std::collections::hash_map::DefaultHasher;
use std::collections::VecDeque;
use std::hash::{Hash, Hasher};
use std::sync::Mutex;

use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LoopConfig {
    pub enabled: bool,
    pub max_identical_requests: u32,
    pub window_seconds: u32,
    /// USD cap per rolling window. `0.0` disables cost-spiral detection.
    pub max_cost_per_window: f64,
    /// When `true`, a tripped cost-spiral window blocks the next request
    /// (HTTP 429). When `false` (default) the spiral is still detected and
    /// logged by `record_cost`, but not enforced — blocking is opt-in so a
    /// normal burst of spend does not start 429-ing a working session.
    pub cost_spiral_enforce: bool,
}

impl Default for LoopConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_identical_requests: 5,
            window_seconds: 300,
            max_cost_per_window: 2.0,
            cost_spiral_enforce: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum LoopVerdict {
    Ok,
    /// N+ identical requests landed within the window.
    Repeated {
        count: u32,
        window_seconds: u32,
        hash: u64,
        /// Seconds until the window drains enough to retry (the oldest
        /// in-window arrival's expiry). Steers well-behaved SDKs to back off
        /// *past* the window instead of hammering it (B-C2).
        retry_after_secs: u64,
    },
    /// Rolling cost in the window exceeds the cap.
    CostSpiral {
        spent_usd: f64,
        cap_usd: f64,
        window_seconds: u32,
    },
}

impl LoopVerdict {
    pub fn is_blocking(&self) -> bool {
        !matches!(self, LoopVerdict::Ok)
    }

    /// Seconds the client should wait before retrying — the `Retry-After`
    /// header value. For a repeated-loop block it's the window-drain time; for
    /// a cost spiral it's the full window (the rolling cost needs that long to
    /// age out). `None` when not blocking.
    pub fn retry_after_secs(&self) -> Option<u64> {
        match self {
            LoopVerdict::Ok => None,
            LoopVerdict::Repeated {
                retry_after_secs, ..
            } => Some(*retry_after_secs),
            LoopVerdict::CostSpiral { window_seconds, .. } => Some(*window_seconds as u64),
        }
    }

    /// Human-readable message used as `block_reason` in storage and as the
    /// 429 body's `message` field.
    pub fn message(&self) -> String {
        match self {
            LoopVerdict::Ok => "ok".to_string(),
            LoopVerdict::Repeated {
                count,
                window_seconds,
                ..
            } => format!(
                "loop detected: {} identical requests within {}s",
                count, window_seconds
            ),
            LoopVerdict::CostSpiral {
                spent_usd,
                cap_usd,
                window_seconds,
            } => format!(
                "cost spiral: ${:.4} spent within {}s (cap ${:.2})",
                spent_usd, window_seconds, cap_usd
            ),
        }
    }
}

pub struct LoopDetector {
    config: LoopConfig,
    /// Per-hash sliding window of arrival timestamps.
    hash_history: DashMap<u64, VecDeque<DateTime<Utc>>>,
    /// Global sliding window of (when, cost) for cost-spiral detection.
    cost_history: Mutex<VecDeque<(DateTime<Utc>, f64)>>,
}

impl LoopDetector {
    pub fn new(config: LoopConfig) -> Self {
        Self {
            config,
            hash_history: DashMap::new(),
            cost_history: Mutex::new(VecDeque::new()),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(LoopConfig::default())
    }

    pub fn config(&self) -> &LoopConfig {
        &self.config
    }

    /// Compute the dedup signature for a request. Hashes `(method, provider,
    /// path, FULL body)`:
    ///
    /// - **Full body**, because agentic clients resend the whole (growing)
    ///   transcript every turn, so any fixed-size prefix is identical across a
    ///   session and a prefix hash would flag normal activity as a loop.
    /// - **method + provider + path**, so body-less requests (every `GET
    ///   /v1/models` hashes to the same empty body) don't collide into one
    ///   global bucket across tools and providers (B-H1). The handler also
    ///   skips loop detection for GET/body-less requests entirely.
    pub fn hash(&self, method: &str, provider: &str, path: &str, body: &[u8]) -> u64 {
        let mut h = DefaultHasher::new();
        method.hash(&mut h);
        provider.hash(&mut h);
        path.hash(&mut h);
        body.hash(&mut h);
        h.finish()
    }

    /// Read-only pre-forward check: prune expired arrivals and decide whether
    /// the window is already full, **without recording** this request. The
    /// arrival is recorded later (by [`record_arrival`](Self::record_arrival)),
    /// and only if the request was actually forwarded and succeeded.
    ///
    /// This split is what breaks the death spiral (B-C2): a request the
    /// detector blocks returns 429 but is *not* counted, and an SDK that
    /// retries that 429 — or retries after an upstream failure — re-peeks
    /// without refilling the window, so the window drains after
    /// `window_seconds` and the user recovers. Under the old "record then
    /// check" model every retry (including retries of the block itself) topped
    /// the window back up, so it never drained.
    pub fn check_request(&self, hash: u64) -> LoopVerdict {
        if !self.config.enabled {
            return LoopVerdict::Ok;
        }
        let now = Utc::now();
        let window = Duration::seconds(self.config.window_seconds as i64);
        let cutoff = now - window;

        let mut entry = self.hash_history.entry(hash).or_default();
        while let Some(front) = entry.front() {
            if *front < cutoff {
                entry.pop_front();
            } else {
                break;
            }
        }
        let count = entry.len() as u32;
        if count >= self.config.max_identical_requests {
            // Window drains when the oldest arrival ages out.
            let retry_after_secs = entry
                .front()
                .map(|oldest| {
                    let elapsed = (now - *oldest).num_seconds().max(0);
                    (self.config.window_seconds as i64 - elapsed).max(1) as u64
                })
                .unwrap_or(self.config.window_seconds as u64);
            return LoopVerdict::Repeated {
                count,
                window_seconds: self.config.window_seconds,
                hash,
                retry_after_secs,
            };
        }
        LoopVerdict::Ok
    }

    /// Record a forwarded-and-succeeded request arrival under its hash. Called
    /// from the response tee **only for 2xx responses** — never for blocked or
    /// failed requests — so the window counts genuine repeats, not retries of
    /// errors. Prunes expired arrivals as it goes.
    pub fn record_arrival(&self, hash: u64) {
        if !self.config.enabled {
            return;
        }
        let now = Utc::now();
        let cutoff = now - Duration::seconds(self.config.window_seconds as i64);
        let mut entry = self.hash_history.entry(hash).or_default();
        while let Some(front) = entry.front() {
            if *front < cutoff {
                entry.pop_front();
            } else {
                break;
            }
        }
        entry.push_back(now);
    }

    /// Append a recorded cost to the global window and decide whether the
    /// rolling spend has tripped the cost-spiral cap.
    ///
    /// Called from the response tee callback so a single fast spike of
    /// expensive responses can flag a spiral even when no two requests
    /// share a hash.
    pub fn record_cost(&self, cost_usd: f64) -> LoopVerdict {
        if !self.config.enabled || self.config.max_cost_per_window <= 0.0 {
            return LoopVerdict::Ok;
        }
        let now = Utc::now();
        let window = Duration::seconds(self.config.window_seconds as i64);
        let cutoff = now - window;

        let mut history = self
            .cost_history
            .lock()
            .expect("loop_detector cost_history mutex poisoned");
        while let Some(front) = history.front() {
            if front.0 < cutoff {
                history.pop_front();
            } else {
                break;
            }
        }
        history.push_back((now, cost_usd));

        let total: f64 = history.iter().map(|(_, c)| c).sum();
        if total > self.config.max_cost_per_window {
            return LoopVerdict::CostSpiral {
                spent_usd: total,
                cap_usd: self.config.max_cost_per_window,
                window_seconds: self.config.window_seconds,
            };
        }
        LoopVerdict::Ok
    }

    /// Pre-forward, read-only cost-spiral check. Returns `CostSpiral` only when
    /// enforcement is enabled *and* the rolling window already exceeds the cap,
    /// so a burst of expensive responses blocks the *next* request. Off by
    /// default (`cost_spiral_enforce = false`): the window is still tracked and
    /// `record_cost` warns, but nothing is blocked.
    pub fn check_cost_spiral(&self) -> LoopVerdict {
        if !self.config.enabled
            || !self.config.cost_spiral_enforce
            || self.config.max_cost_per_window <= 0.0
        {
            return LoopVerdict::Ok;
        }
        let total = self.current_window_cost();
        if total > self.config.max_cost_per_window {
            return LoopVerdict::CostSpiral {
                spent_usd: total,
                cap_usd: self.config.max_cost_per_window,
                window_seconds: self.config.window_seconds,
            };
        }
        LoopVerdict::Ok
    }

    /// Returns the current rolling cost in the window — used by `status`
    /// to surface "approaching cost-spiral cap" warnings.
    pub fn current_window_cost(&self) -> f64 {
        let now = Utc::now();
        let window = Duration::seconds(self.config.window_seconds as i64);
        let cutoff = now - window;
        let history = self
            .cost_history
            .lock()
            .expect("loop_detector cost_history mutex poisoned");
        history
            .iter()
            .filter(|(t, _)| *t >= cutoff)
            .map(|(_, c)| c)
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(enforce: bool, cap: f64) -> LoopConfig {
        LoopConfig {
            enabled: true,
            max_identical_requests: 5,
            window_seconds: 300,
            max_cost_per_window: cap,
            cost_spiral_enforce: enforce,
        }
    }

    fn h(det: &LoopDetector, body: &[u8]) -> u64 {
        det.hash("POST", "anthropic", "/v1/messages", body)
    }

    #[test]
    fn growing_transcript_does_not_loop() {
        // Regression: agentic clients (Claude Code) resend the entire
        // conversation every turn, so consecutive request bodies share a long
        // identical prefix — same model, same opening message — while growing
        // at the tail. The old 200-byte prefix hash saw those as identical
        // and 429'd any session that made 5 requests within 5 minutes.
        let det = LoopDetector::with_defaults();
        let prefix = r#"{"model":"claude-fable-5","messages":[{"role":"user","content":"please investigate why successful proxied requests are not recorded and fix the streaming usage parser so the cost tracking pipeline works again"}"#;
        assert!(prefix.len() > 200, "prefix must exceed the old hash window");
        for i in 0..10 {
            let body = format!(
                "{prefix},{{\"role\":\"assistant\",\"content\":\"turn {i}\"}}]}}"
            );
            let hash = h(&det, body.as_bytes());
            let verdict = det.check_request(hash);
            assert_eq!(verdict, LoopVerdict::Ok, "turn {i} wrongly flagged as loop");
            det.record_arrival(hash);
        }
    }

    #[test]
    fn byte_identical_bodies_still_trip() {
        let det = LoopDetector::with_defaults();
        let hash = h(&det, br#"{"model":"m","messages":[{"role":"user","content":"same"}]}"#);
        // Five identical *successful* requests are tolerated; the sixth peek
        // sees a full window and blocks. Each Ok request records its arrival
        // (as the tee does on a 2xx).
        for _ in 0..5 {
            assert_eq!(det.check_request(hash), LoopVerdict::Ok);
            det.record_arrival(hash);
        }
        assert!(det.check_request(hash).is_blocking());
    }

    #[test]
    fn blocked_requests_do_not_feed_the_window() {
        // The death-spiral regression (B-C2): the block path calls only
        // check_request (never record_arrival), so an SDK that hammers a 429 —
        // or retries after an upstream failure — cannot keep the window full.
        // check_request is read-only: calling it 100× without a single
        // record_arrival must never produce a block.
        let det = LoopDetector::with_defaults();
        let hash = h(&det, b"identical-retry-body");
        for _ in 0..100 {
            assert_eq!(det.check_request(hash), LoopVerdict::Ok);
        }
    }

    #[test]
    fn distinct_method_path_dont_share_a_bucket() {
        // B-H1: body-less requests (empty body) used to collide into one global
        // bucket; including method+provider+path keeps GET /v1/models on one
        // tool distinct from another tool's.
        let det = LoopDetector::with_defaults();
        let a = det.hash("GET", "anthropic", "/v1/models", b"");
        let b = det.hash("GET", "openai", "/v1/models", b"");
        let c = det.hash("GET", "anthropic", "/v1/models/claude", b"");
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn repeated_verdict_carries_retry_after() {
        let det = LoopDetector::with_defaults();
        let hash = h(&det, b"loop-body");
        for _ in 0..5 {
            det.record_arrival(hash);
        }
        let v = det.check_request(hash);
        match v {
            LoopVerdict::Repeated {
                retry_after_secs, ..
            } => assert!((1..=300).contains(&retry_after_secs)),
            other => panic!("expected Repeated, got {other:?}"),
        }
        assert!(det.check_request(hash).retry_after_secs().is_some());
    }

    #[test]
    fn cost_spiral_not_enforced_by_default() {
        let det = LoopDetector::new(cfg(false, 2.0));
        det.record_cost(5.0); // well over the cap
        assert_eq!(det.check_cost_spiral(), LoopVerdict::Ok);
    }

    #[test]
    fn cost_spiral_blocks_next_request_when_enforced() {
        let det = LoopDetector::new(cfg(true, 2.0));
        det.record_cost(1.5);
        assert_eq!(det.check_cost_spiral(), LoopVerdict::Ok); // under cap
        det.record_cost(1.0); // now $2.50 > $2.00
        assert!(det.check_cost_spiral().is_blocking());
    }

    #[test]
    fn cost_spiral_ok_when_under_cap_even_if_enforced() {
        let det = LoopDetector::new(cfg(true, 100.0));
        det.record_cost(3.0);
        assert_eq!(det.check_cost_spiral(), LoopVerdict::Ok);
    }
}
