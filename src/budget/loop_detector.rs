//! Loop detection — block runaway agents that hammer the same request or
//! burn an unreasonable amount of money in a short window.
//!
//! Two independent mechanisms:
//!
//! - **Repeated-content loop**: hash a prefix of the request body; if the
//!   same hash appears `max_identical_requests` times within
//!   `window_seconds`, block with HTTP 429.
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
    /// Bytes of request body to hash for the dedup signature.
    pub hash_prefix_bytes: usize,
}

impl Default for LoopConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_identical_requests: 5,
            window_seconds: 300,
            max_cost_per_window: 2.0,
            hash_prefix_bytes: 200,
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

    /// Compute the dedup signature for a request body.
    pub fn hash(&self, body: &[u8]) -> u64 {
        let take = self.config.hash_prefix_bytes.min(body.len());
        let mut h = DefaultHasher::new();
        body[..take].hash(&mut h);
        h.finish()
    }

    /// Record a request arrival under its hash and decide if it forms a
    /// loop. Always called pre-forward.
    pub fn check_request(&self, hash: u64) -> LoopVerdict {
        if !self.config.enabled {
            return LoopVerdict::Ok;
        }
        let now = Utc::now();
        let window = Duration::seconds(self.config.window_seconds as i64);
        let cutoff = now - window;

        let count = {
            let mut entry = self.hash_history.entry(hash).or_default();
            while let Some(front) = entry.front() {
                if *front < cutoff {
                    entry.pop_front();
                } else {
                    break;
                }
            }
            entry.push_back(now);
            entry.len() as u32
        };

        if count >= self.config.max_identical_requests {
            return LoopVerdict::Repeated {
                count,
                window_seconds: self.config.window_seconds,
                hash,
            };
        }
        LoopVerdict::Ok
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
