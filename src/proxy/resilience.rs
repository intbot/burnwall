//! Resilience: per-endpoint circuit breaking + same-model endpoint failover
//! (v0.7). All proxy-native — no cloud, no extra network calls beyond the
//! forwarding the proxy already does.
//!
//! ## Failover
//!
//! The same model is often reachable through more than one compatible
//! endpoint (e.g. Anthropic's own API, Amazon Bedrock, Google Vertex). When
//! the primary upstream is unreachable or returns a server error, Burnwall
//! tries the next configured endpoint for that provider — the request shape
//! is identical, so this is a transparent reroute, not a translation. Off by
//! default; enabled via `[resilience]` in config.
//!
//! ## Circuit breaker
//!
//! A dead endpoint should not be hammered on every request. Each endpoint has
//! a small failure counter; once it reaches `failure_threshold`, the endpoint
//! is "open" (skipped) for `cooldown`. After the cooldown elapses one probe is
//! allowed through (implicit half-open); a success closes the circuit, another
//! failure re-opens it. State is in-memory only — a restart starts clean.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use dashmap::DashMap;

/// The breaker's view of a single endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Requests flow normally.
    Closed,
    /// The endpoint is being skipped until its cooldown elapses.
    Open,
}

#[derive(Debug, Default)]
struct EndpointHealth {
    consecutive_failures: u32,
    /// When `Some`, the circuit is open until this instant.
    open_until: Option<Instant>,
}

/// Per-endpoint failure tracking with a cooldown. Cheap, lock-free reads via
/// `DashMap`; a never-seen endpoint is treated as healthy.
#[derive(Debug)]
pub struct CircuitBreaker {
    failure_threshold: u32,
    cooldown: Duration,
    health: DashMap<String, EndpointHealth>,
}

impl CircuitBreaker {
    pub fn new(failure_threshold: u32, cooldown: Duration) -> Self {
        Self {
            // A threshold of 0 would open the circuit on the first failure and
            // is almost certainly a misconfiguration — clamp to 1.
            failure_threshold: failure_threshold.max(1),
            cooldown,
            health: DashMap::new(),
        }
    }

    /// Whether a request may be sent to `endpoint` right now. A closed circuit
    /// (or one whose cooldown has elapsed — the half-open probe) is available.
    pub fn is_available(&self, endpoint: &str) -> bool {
        match self.health.get(endpoint) {
            None => true,
            Some(h) => match h.open_until {
                None => true,
                Some(until) => Instant::now() >= until,
            },
        }
    }

    /// Record a successful call: reset the failure count and close the circuit.
    pub fn record_success(&self, endpoint: &str) {
        if let Some(mut h) = self.health.get_mut(endpoint) {
            h.consecutive_failures = 0;
            h.open_until = None;
        }
    }

    /// Record a failed call. Opens the circuit once `failure_threshold`
    /// consecutive failures accumulate.
    pub fn record_failure(&self, endpoint: &str) {
        let mut h = self.health.entry(endpoint.to_string()).or_default();
        h.consecutive_failures = h.consecutive_failures.saturating_add(1);
        if h.consecutive_failures >= self.failure_threshold {
            h.open_until = Some(Instant::now() + self.cooldown);
        }
    }

    /// Current logical state of `endpoint` (for status surfaces / tests).
    pub fn state(&self, endpoint: &str) -> CircuitState {
        if self.is_available(endpoint) {
            CircuitState::Closed
        } else {
            CircuitState::Open
        }
    }
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new(3, Duration::from_secs(30))
    }
}

/// Runtime resilience policy shared on the proxy's `AppState`. `Default` is a
/// fully disabled no-op (via `CircuitBreaker`'s own `Default`) so existing call
/// sites and tests keep their behavior.
#[derive(Debug, Default)]
pub struct Resilience {
    pub enabled: bool,
    pub breaker: CircuitBreaker,
    /// Ordered list of *additional* upstream base URLs to try, per provider,
    /// after the primary upstream. Keyed by provider name ("anthropic",
    /// "openai", "google").
    failover: HashMap<String, Vec<String>>,
}

impl Resilience {
    pub fn new(
        enabled: bool,
        failure_threshold: u32,
        cooldown: Duration,
        failover: HashMap<String, Vec<String>>,
    ) -> Self {
        Self {
            enabled,
            breaker: CircuitBreaker::new(failure_threshold, cooldown),
            failover,
        }
    }

    /// The ordered list of candidate base URLs to try for a request, starting
    /// with the primary. When resilience is disabled, this is just `[primary]`.
    /// Duplicates of the primary in the failover list are dropped so it is
    /// never tried twice.
    pub fn candidates(&self, provider: &str, primary: &str) -> Vec<String> {
        let mut out = vec![primary.to_string()];
        if self.enabled {
            if let Some(extra) = self.failover.get(provider) {
                for url in extra {
                    if url != primary && !out.contains(url) {
                        out.push(url.clone());
                    }
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_endpoint_is_available() {
        let cb = CircuitBreaker::new(3, Duration::from_secs(30));
        assert!(cb.is_available("https://api.example.com"));
        assert_eq!(cb.state("https://api.example.com"), CircuitState::Closed);
    }

    #[test]
    fn opens_after_threshold_failures() {
        let cb = CircuitBreaker::new(3, Duration::from_secs(30));
        cb.record_failure("e");
        cb.record_failure("e");
        assert!(cb.is_available("e"), "still closed at 2 < 3 failures");
        cb.record_failure("e");
        assert!(!cb.is_available("e"), "open at 3 failures");
        assert_eq!(cb.state("e"), CircuitState::Open);
    }

    #[test]
    fn cooldown_elapse_allows_probe() {
        let cb = CircuitBreaker::new(1, Duration::from_millis(20));
        cb.record_failure("e");
        assert!(!cb.is_available("e"));
        std::thread::sleep(Duration::from_millis(30));
        assert!(cb.is_available("e"), "cooldown elapsed → half-open probe");
    }

    #[test]
    fn success_closes_circuit() {
        let cb = CircuitBreaker::new(2, Duration::from_secs(30));
        cb.record_failure("e");
        cb.record_failure("e");
        assert!(!cb.is_available("e"));
        cb.record_success("e");
        assert!(cb.is_available("e"));
    }

    #[test]
    fn threshold_clamped_to_one() {
        let cb = CircuitBreaker::new(0, Duration::from_secs(30));
        cb.record_failure("e");
        assert!(!cb.is_available("e"), "threshold 0 clamps to 1");
    }

    #[test]
    fn disabled_resilience_yields_only_primary() {
        let r = Resilience::default();
        assert_eq!(
            r.candidates("anthropic", "https://primary"),
            vec!["https://primary"]
        );
    }

    #[test]
    fn enabled_resilience_appends_failover_without_duplicating_primary() {
        let mut fo = HashMap::new();
        fo.insert(
            "anthropic".to_string(),
            vec![
                "https://primary".to_string(),
                "https://backup1".to_string(),
                "https://backup2".to_string(),
            ],
        );
        let r = Resilience::new(true, 3, Duration::from_secs(30), fo);
        assert_eq!(
            r.candidates("anthropic", "https://primary"),
            vec!["https://primary", "https://backup1", "https://backup2"]
        );
        // Unknown provider → just the primary.
        assert_eq!(r.candidates("openai", "https://oa"), vec!["https://oa"]);
    }
}
