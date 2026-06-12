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

use std::collections::VecDeque;
use std::collections::hash_map::DefaultHasher;
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
    /// How many times the *same tool-call action signature* (tool name + its
    /// argument values, from the latest assistant turn) may repeat within the
    /// window before the near-duplicate "stuck repeating the same action"
    /// detector trips (feature #19). This catches the pattern the full-body
    /// hash deliberately misses — the transcript grows every turn, so the body
    /// hash differs, but the agent keeps issuing the identical action.
    pub action_repeat_threshold: u32,
    /// Enforce the action-repeat detector (block with HTTP 429). Off by default
    /// (#19, R5): the detector always only WARNs unless this is `true`, so a
    /// fuzzy near-duplicate signal never wedges a session by default. Even when
    /// on, it does NOT tighten the existing full-body-hash block — it is an
    /// additional, separately-gated signal.
    pub action_repeat_enforce: bool,
}

impl Default for LoopConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_identical_requests: 5,
            window_seconds: 300,
            max_cost_per_window: 2.0,
            cost_spiral_enforce: false,
            // Conservative: an agent must repeat the byte-identical action this
            // many times in the window before it even warns. Higher than the
            // identical-body threshold because near-duplicate matching is fuzzier.
            action_repeat_threshold: 10,
            action_repeat_enforce: false,
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
    /// The same tool-call action signature repeated `count` times within the
    /// window — the near-duplicate "stuck repeating the same action" pattern
    /// (#19). Warn-only by default; only `is_blocking` when enforcement is on
    /// (see [`LoopDetector::check_action_repeat`]).
    ActionRepeat {
        count: u32,
        window_seconds: u32,
        /// `true` when `action_repeat_enforce` is set — only then does this
        /// verdict block. A non-enforcing verdict is for warn/log surfaces only.
        enforced: bool,
    },
}

impl LoopVerdict {
    pub fn is_blocking(&self) -> bool {
        match self {
            LoopVerdict::Ok => false,
            // A non-enforcing action-repeat verdict is a warn-only signal — it
            // must never block (#19, R5). All other non-Ok verdicts block.
            LoopVerdict::ActionRepeat { enforced, .. } => *enforced,
            _ => true,
        }
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
            // Only an enforced action-repeat carries a retry hint; the rolling
            // window needs the full window to drain the repeats.
            LoopVerdict::ActionRepeat {
                window_seconds,
                enforced: true,
                ..
            } => Some(*window_seconds as u64),
            LoopVerdict::ActionRepeat {
                enforced: false, ..
            } => None,
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
            LoopVerdict::ActionRepeat {
                count,
                window_seconds,
                ..
            } => format!(
                "action loop: the same tool call repeated {} times within {}s",
                count, window_seconds
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
    /// Per-action-signature sliding window of arrival timestamps, for the
    /// near-duplicate action-repeat detector (#19). Keyed on a hash of the
    /// latest assistant turn's tool-call action (tool name + argument values),
    /// so a growing transcript that keeps issuing the *same* action trips this
    /// even though the full body — and therefore `hash_history` — differs.
    action_history: DashMap<u64, VecDeque<DateTime<Utc>>>,
}

impl LoopDetector {
    pub fn new(config: LoopConfig) -> Self {
        Self {
            config,
            hash_history: DashMap::new(),
            cost_history: Mutex::new(VecDeque::new()),
            action_history: DashMap::new(),
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

    /// Near-duplicate action-repeat check (#19). Extracts the latest assistant
    /// turn's tool-call action signature from `body`, records this arrival under
    /// it, and returns a verdict once the same signature has repeated
    /// `action_repeat_threshold`+ times within the window.
    ///
    /// Unlike [`check_request`], this **records as it checks** (a single
    /// recording-and-deciding pass): the action-repeat window's job is to count
    /// how often a given action recurs across the growing transcript, and the
    /// caller invokes it once per forwarded request pre-forward. It is purely
    /// additive — it never feeds or tightens the existing full-body-hash block.
    ///
    /// The returned verdict's `enforced` flag mirrors
    /// `action_repeat_enforce`, so [`LoopVerdict::is_blocking`] is `false` for a
    /// warn-only configuration (the default) and the handler logs without
    /// blocking. Returns `Ok` when loop detection is disabled, the threshold is
    /// 0, or the body carries no extractable tool-call action.
    pub fn check_action_repeat(&self, body: &[u8]) -> LoopVerdict {
        if !self.config.enabled || self.config.action_repeat_threshold == 0 {
            return LoopVerdict::Ok;
        }
        let Some(sig) = latest_action_signature(body) else {
            return LoopVerdict::Ok;
        };

        let now = Utc::now();
        let window = Duration::seconds(self.config.window_seconds as i64);
        let cutoff = now - window;

        let mut entry = self.action_history.entry(sig).or_default();
        while let Some(front) = entry.front() {
            if *front < cutoff {
                entry.pop_front();
            } else {
                break;
            }
        }
        entry.push_back(now);
        let count = entry.len() as u32;
        if count >= self.config.action_repeat_threshold {
            return LoopVerdict::ActionRepeat {
                count,
                window_seconds: self.config.window_seconds,
                enforced: self.config.action_repeat_enforce,
            };
        }
        LoopVerdict::Ok
    }
}

/// Extract a stable signature for the tool-call *action* in the latest
/// assistant turn of a request body, or `None` when there is no tool call to
/// fingerprint. The signature hashes `(tool_name, canonical_arguments)` across
/// the three provider shapes:
///
/// - **Anthropic** Messages API: `messages[*].content[*]` blocks of
///   `{"type":"tool_use","name":...,"input":{...}}`.
/// - **OpenAI** Chat Completions: `messages[*].tool_calls[*]` of
///   `{"function":{"name":...,"arguments":"<json string>"}}`.
/// - **Google** Gemini: `contents[*].parts[*]` of
///   `{"functionCall":{"name":...,"args":{...}}}`.
///
/// Only the **last** assistant turn is fingerprinted: a transcript grows every
/// turn, but the "stuck repeating the same action" pattern is the *newest* turn
/// re-issuing an identical action. Using the last turn (not the whole body)
/// keeps a growing transcript with varied actions from ever colliding. Returns
/// `None` (fail-open) on a non-JSON body or one with no tool-call action — the
/// detector simply stays quiet rather than guessing.
fn latest_action_signature(body: &[u8]) -> Option<u64> {
    let body = body.strip_prefix(b"\xef\xbb\xbf").unwrap_or(body);
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;

    // Collect the action (name, canonical-args) from the last assistant turn,
    // scanning the provider-appropriate container.
    let action = anthropic_last_action(&value)
        .or_else(|| openai_last_action(&value))
        .or_else(|| google_last_action(&value))?;

    let mut h = DefaultHasher::new();
    action.0.hash(&mut h);
    action.1.hash(&mut h);
    Some(h.finish())
}

/// Canonicalize a JSON value into a stable string so two structurally-equal
/// argument objects hash identically regardless of key order. `serde_json`
/// preserves object key order, so we sort keys recursively.
fn canonical_json(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let inner: Vec<String> = keys
                .into_iter()
                .map(|k| format!("{}:{}", k, canonical_json(&map[k])))
                .collect();
            format!("{{{}}}", inner.join(","))
        }
        serde_json::Value::Array(arr) => {
            let inner: Vec<String> = arr.iter().map(canonical_json).collect();
            format!("[{}]", inner.join(","))
        }
        other => other.to_string(),
    }
}

/// Last Anthropic `tool_use` block (name + canonical input) in the final
/// assistant message, if any.
fn anthropic_last_action(value: &serde_json::Value) -> Option<(String, String)> {
    let messages = value.get("messages")?.as_array()?;
    // Walk messages newest-first, returning the first tool_use we find.
    for msg in messages.iter().rev() {
        if msg.get("role").and_then(|r| r.as_str()) != Some("assistant") {
            continue;
        }
        let content = msg.get("content")?;
        let blocks = content.as_array()?;
        for block in blocks.iter().rev() {
            if block.get("type").and_then(|t| t.as_str()) == Some("tool_use") {
                let name = block.get("name").and_then(|n| n.as_str()).unwrap_or("");
                let input = block.get("input").map(canonical_json).unwrap_or_default();
                return Some((name.to_string(), input));
            }
        }
        // Newest assistant turn had no tool_use — not an action loop.
        return None;
    }
    None
}

/// Last OpenAI `tool_calls` entry (function name + arguments string) in the
/// final assistant message, if any.
fn openai_last_action(value: &serde_json::Value) -> Option<(String, String)> {
    let messages = value.get("messages")?.as_array()?;
    for msg in messages.iter().rev() {
        if msg.get("role").and_then(|r| r.as_str()) != Some("assistant") {
            continue;
        }
        let calls = msg.get("tool_calls").and_then(|c| c.as_array())?;
        if let Some(call) = calls.last() {
            let func = call.get("function")?;
            let name = func.get("name").and_then(|n| n.as_str()).unwrap_or("");
            // `arguments` is a JSON-encoded string in the OpenAI shape; canonicalize
            // it when it parses, else use the raw string.
            let raw = func.get("arguments").and_then(|a| a.as_str()).unwrap_or("");
            let args = serde_json::from_str::<serde_json::Value>(raw)
                .map(|v| canonical_json(&v))
                .unwrap_or_else(|_| raw.to_string());
            return Some((name.to_string(), args));
        }
        return None;
    }
    None
}

/// Last Google `functionCall` part (name + canonical args) in the final
/// `model`-role content, if any.
fn google_last_action(value: &serde_json::Value) -> Option<(String, String)> {
    let contents = value.get("contents")?.as_array()?;
    for content in contents.iter().rev() {
        // Gemini uses role "model" for assistant turns; some payloads omit role.
        let role = content.get("role").and_then(|r| r.as_str());
        if role.is_some() && role != Some("model") {
            continue;
        }
        let parts = content.get("parts").and_then(|p| p.as_array())?;
        for part in parts.iter().rev() {
            if let Some(fc) = part.get("functionCall") {
                let name = fc.get("name").and_then(|n| n.as_str()).unwrap_or("");
                let args = fc.get("args").map(canonical_json).unwrap_or_default();
                return Some((name.to_string(), args));
            }
        }
        return None;
    }
    None
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
            action_repeat_threshold: 10,
            action_repeat_enforce: false,
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
            let body = format!("{prefix},{{\"role\":\"assistant\",\"content\":\"turn {i}\"}}]}}");
            let hash = h(&det, body.as_bytes());
            let verdict = det.check_request(hash);
            assert_eq!(verdict, LoopVerdict::Ok, "turn {i} wrongly flagged as loop");
            det.record_arrival(hash);
        }
    }

    #[test]
    fn byte_identical_bodies_still_trip() {
        let det = LoopDetector::with_defaults();
        let hash = h(
            &det,
            br#"{"model":"m","messages":[{"role":"user","content":"same"}]}"#,
        );
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

    // ── #19 near-duplicate action-repeat detector ──

    fn action_cfg(threshold: u32, enforce: bool) -> LoopConfig {
        LoopConfig {
            action_repeat_threshold: threshold,
            action_repeat_enforce: enforce,
            ..LoopConfig::default()
        }
    }

    /// An Anthropic body whose newest assistant turn repeats `tool` with a
    /// fixed `path` argument, with `turn` prepended to the (growing) transcript
    /// so the FULL body differs every call — exactly the case the body hash
    /// misses.
    fn anthropic_action_body(turn: usize, tool: &str, path: &str) -> Vec<u8> {
        let v = serde_json::json!({
            "model": "claude-sonnet-4-6",
            "messages": [
                {"role": "user", "content": format!("growing transcript prefix turn {turn} ...")},
                {"role": "assistant", "content": [
                    {"type": "tool_use", "name": tool, "input": {"path": path}}
                ]}
            ]
        });
        serde_json::to_vec(&v).unwrap()
    }

    #[test]
    fn repeated_identical_action_warns_but_does_not_block_by_default() {
        let det = LoopDetector::new(action_cfg(5, false));
        let mut last = LoopVerdict::Ok;
        for turn in 0..10 {
            // Same action every turn, but the transcript prefix grows so the
            // full body differs each time.
            last = det.check_action_repeat(&anthropic_action_body(turn, "read_file", "/tmp/a"));
        }
        match last {
            LoopVerdict::ActionRepeat {
                count, enforced, ..
            } => {
                assert!(count >= 5, "should have counted the repeats, got {count}");
                assert!(!enforced, "warn-only by default");
            }
            other => panic!("expected ActionRepeat, got {other:?}"),
        }
        // R5/R1: a warn-only verdict must never block.
        assert!(!last.is_blocking(), "default action-repeat must not block");
    }

    #[test]
    fn repeated_identical_action_blocks_only_when_enforced() {
        let det = LoopDetector::new(action_cfg(5, true));
        let mut last = LoopVerdict::Ok;
        for turn in 0..6 {
            last = det.check_action_repeat(&anthropic_action_body(turn, "run", "ls"));
        }
        assert!(
            last.is_blocking(),
            "enforced action-repeat should block once over threshold, got {last:?}"
        );
        assert!(last.retry_after_secs().is_some());
    }

    #[test]
    fn distinct_actions_never_trip_action_repeat() {
        // A growing transcript that issues a DIFFERENT action every turn must
        // never trip — this is the core false-positive guard for #19.
        let det = LoopDetector::new(action_cfg(3, true)); // low threshold + enforce
        for turn in 0..50 {
            let body = anthropic_action_body(turn, "read_file", &format!("/file/{turn}"));
            let v = det.check_action_repeat(&body);
            assert_eq!(v, LoopVerdict::Ok, "distinct action on turn {turn} tripped");
        }
    }

    #[test]
    fn growing_transcript_with_varied_actions_does_not_trip() {
        // Mirrors the full-body-hash regression `growing_transcript_does_not_loop`
        // but for actions: alternating tools/args across a growing transcript.
        let det = LoopDetector::new(action_cfg(3, true));
        let tools = ["read_file", "edit_file", "grep", "run_test", "list_dir"];
        for turn in 0..40 {
            let tool = tools[turn % tools.len()];
            let body = anthropic_action_body(turn, tool, &format!("/p/{}", turn % 7));
            assert_eq!(
                det.check_action_repeat(&body),
                LoopVerdict::Ok,
                "varied action on turn {turn} tripped"
            );
        }
    }

    #[test]
    fn no_tool_call_body_never_trips() {
        // A plain chat body (no tool_use in the last assistant turn) has no
        // action to fingerprint — fail-open to Ok no matter how many times.
        let det = LoopDetector::new(action_cfg(2, true));
        let body = serde_json::to_vec(&serde_json::json!({
            "model": "claude-sonnet-4-6",
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .unwrap();
        for _ in 0..10 {
            assert_eq!(det.check_action_repeat(&body), LoopVerdict::Ok);
        }
    }

    #[test]
    fn non_json_body_fails_open_on_action_repeat() {
        let det = LoopDetector::new(action_cfg(2, true));
        for _ in 0..10 {
            assert_eq!(det.check_action_repeat(b"not json at all"), LoopVerdict::Ok);
        }
    }

    #[test]
    fn openai_repeated_tool_call_action_is_detected() {
        // OpenAI shape: tool_calls[].function.{name,arguments(JSON string)}.
        let det = LoopDetector::new(action_cfg(3, false));
        let body = |turn: usize| {
            serde_json::to_vec(&serde_json::json!({
                "model": "gpt-5.4",
                "messages": [
                    {"role": "user", "content": format!("turn {turn} prefix grows")},
                    {"role": "assistant", "tool_calls": [
                        {"id": "call_1", "type": "function",
                         "function": {"name": "search", "arguments": "{\"q\":\"same\"}"}}
                    ]}
                ]
            }))
            .unwrap()
        };
        let mut last = LoopVerdict::Ok;
        for turn in 0..5 {
            last = det.check_action_repeat(&body(turn));
        }
        assert!(
            matches!(last, LoopVerdict::ActionRepeat { .. }),
            "OpenAI repeated tool call should be detected, got {last:?}"
        );
    }

    #[test]
    fn action_repeat_threshold_zero_disables() {
        let det = LoopDetector::new(action_cfg(0, true));
        for turn in 0..20 {
            assert_eq!(
                det.check_action_repeat(&anthropic_action_body(turn, "read", "/x")),
                LoopVerdict::Ok
            );
        }
    }
}
