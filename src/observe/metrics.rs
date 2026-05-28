//! Per-model observability metrics derived from the request log.
//!
//! Burnwall already records the upstream HTTP status and the round-trip
//! latency of every forwarded request (metadata only — no prompt content). This
//! module aggregates those samples into the kind of numbers a hosted LLM
//! observability product would show: latency percentiles (p50/p95), error
//! rate, throughput. All computed locally; nothing leaves the machine.

/// One forwarded request's observability sample, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LatencySample {
    pub provider: String,
    pub model: String,
    /// Upstream round-trip latency in milliseconds (time to response headers).
    pub latency_ms: i64,
    /// Upstream HTTP status. `0` means the request never got a response
    /// (connection error / all endpoints down) — counted as an error.
    pub http_status: i64,
}

impl LatencySample {
    /// A sample is an error if the upstream never responded (`0`) or returned
    /// a 4xx/5xx status.
    pub fn is_error(&self) -> bool {
        self.http_status == 0 || self.http_status >= 400
    }
}

/// Aggregated metrics for one (provider, model) pair over the window.
#[derive(Debug, Clone, PartialEq)]
pub struct ModelMetrics {
    pub provider: String,
    pub model: String,
    pub requests: u64,
    pub errors: u64,
    /// Fraction in `[0.0, 1.0]`.
    pub error_rate: f64,
    pub p50_ms: i64,
    pub p95_ms: i64,
    /// Average forwarded requests per day across the window.
    pub throughput_per_day: f64,
}

/// Nearest-rank percentile of a sorted, ascending slice. `p` is in `[0, 100]`.
/// Returns 0 for an empty slice.
fn percentile_sorted(sorted: &[i64], p: u8) -> i64 {
    if sorted.is_empty() {
        return 0;
    }
    if p == 0 {
        return sorted[0];
    }
    // Nearest-rank: rank = ceil(p/100 * N), 1-based.
    let n = sorted.len();
    let rank = ((p as f64 / 100.0) * n as f64).ceil() as usize;
    let idx = rank.clamp(1, n) - 1;
    sorted[idx]
}

/// Group samples by (provider, model) and compute the per-model metrics.
/// `days` is the window length used for the throughput denominator (clamped to
/// at least 1). Output is sorted by request count descending, then by label.
pub fn aggregate(samples: Vec<LatencySample>, days: i64) -> Vec<ModelMetrics> {
    use std::collections::BTreeMap;

    let days = days.max(1) as f64;
    // BTreeMap keeps a deterministic key order before the final sort.
    let mut groups: BTreeMap<(String, String), Vec<LatencySample>> = BTreeMap::new();
    for s in samples {
        groups
            .entry((s.provider.clone(), s.model.clone()))
            .or_default()
            .push(s);
    }

    let mut out: Vec<ModelMetrics> = groups
        .into_iter()
        .map(|((provider, model), rows)| {
            let requests = rows.len() as u64;
            let errors = rows.iter().filter(|s| s.is_error()).count() as u64;
            let error_rate = if requests > 0 {
                errors as f64 / requests as f64
            } else {
                0.0
            };
            let mut latencies: Vec<i64> = rows.iter().map(|s| s.latency_ms).collect();
            latencies.sort_unstable();
            ModelMetrics {
                provider,
                model,
                requests,
                errors,
                error_rate,
                p50_ms: percentile_sorted(&latencies, 50),
                p95_ms: percentile_sorted(&latencies, 95),
                throughput_per_day: requests as f64 / days,
            }
        })
        .collect();

    out.sort_by(|a, b| {
        b.requests
            .cmp(&a.requests)
            .then_with(|| a.provider.cmp(&b.provider))
            .then_with(|| a.model.cmp(&b.model))
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(model: &str, latency: i64, status: i64) -> LatencySample {
        LatencySample {
            provider: "anthropic".to_string(),
            model: model.to_string(),
            latency_ms: latency,
            http_status: status,
        }
    }

    #[test]
    fn percentile_nearest_rank() {
        let s = vec![10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
        assert_eq!(percentile_sorted(&s, 50), 50);
        assert_eq!(percentile_sorted(&s, 95), 100);
        assert_eq!(percentile_sorted(&s, 100), 100);
        assert_eq!(percentile_sorted(&[], 50), 0);
        assert_eq!(percentile_sorted(&[42], 95), 42);
    }

    #[test]
    fn error_classification() {
        assert!(sample("m", 100, 0).is_error());
        assert!(sample("m", 100, 500).is_error());
        assert!(sample("m", 100, 429).is_error());
        assert!(!sample("m", 100, 200).is_error());
    }

    #[test]
    fn aggregate_groups_and_computes() {
        let samples = vec![
            sample("claude-opus-4-7", 100, 200),
            sample("claude-opus-4-7", 200, 200),
            sample("claude-opus-4-7", 300, 500),
            sample("claude-haiku-4-5", 50, 200),
        ];
        let metrics = aggregate(samples, 1);
        assert_eq!(metrics.len(), 2);
        // opus has more requests → sorts first
        let opus = &metrics[0];
        assert_eq!(opus.model, "claude-opus-4-7");
        assert_eq!(opus.requests, 3);
        assert_eq!(opus.errors, 1);
        assert!((opus.error_rate - 1.0 / 3.0).abs() < 1e-9);
        assert_eq!(opus.p50_ms, 200);
        assert_eq!(opus.p95_ms, 300);
        assert!((opus.throughput_per_day - 3.0).abs() < 1e-9);

        let haiku = &metrics[1];
        assert_eq!(haiku.requests, 1);
        assert_eq!(haiku.errors, 0);
        assert_eq!(haiku.error_rate, 0.0);
    }

    #[test]
    fn throughput_divides_by_window() {
        let samples = vec![sample("m", 10, 200); 14];
        let metrics = aggregate(samples, 7);
        assert!((metrics[0].throughput_per_day - 2.0).abs() < 1e-9);
    }

    #[test]
    fn empty_input_is_empty_output() {
        assert!(aggregate(Vec::new(), 7).is_empty());
    }
}
