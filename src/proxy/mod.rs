//! Proxy server entry point.
//!
//! Binds a TCP listener, accepts connections, and dispatches every request
//! to [`handler::handle`], which routes by URL prefix, runs the security
//! and budget checks, and forwards via [`forwarding::forward`]. Response
//! bodies are streamed back using [`ProxyBody`]; on the way through, the
//! body is tee'd into a background parser so cost tracking works for both
//! streaming and non-streaming responses.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use tokio::net::TcpListener;
use tracing::{error, info};

use crate::budget::{BudgetTracker, LoopDetector};
use crate::security::SecurityEngine;
use crate::storage::Storage;

pub mod cache_injection;
pub mod forwarding;
pub mod handler;
pub mod resilience;
pub mod response_exfil;
pub mod streaming;
pub mod tool_trim;

pub use resilience::Resilience;
pub use streaming::{BoxError, ProxyBody};

/// Build the upstream HTTP client with deadlines and TCP keepalive (P-C1). A
/// bare `reqwest::Client::new()` has no connect timeout, no read timeout, and
/// no keepalive, so a VPN flip / captive portal blackholes a request for the OS
/// connect timeout (tens of seconds, freezing the user's tool), and a stalled
/// stream after laptop sleep/wake blocks the tee task forever — the request is
/// never recorded and the task plus its buffered body leak until restart.
///
/// - `connect_timeout`: fail fast to a clean 502 instead of a long hang.
/// - `tcp_keepalive`: detect a silently-dead socket (no FIN/RST) so a stalled
///   stream eventually errors instead of blocking forever.
/// - `read_timeout` (per-read, NOT total `timeout`): reclaims a socket that has
///   gone quiet, while still allowing arbitrarily long SSE streams — Anthropic
///   sends periodic pings, so a live stream keeps resetting the per-read clock.
///   A total `.timeout()` would wrongly kill long legitimate generations.
pub fn build_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .tcp_keepalive(std::time::Duration::from_secs(60))
        .read_timeout(std::time::Duration::from_secs(600))
        .build()
        .unwrap_or_else(|e| {
            tracing::warn!("falling back to default HTTP client: {e}");
            reqwest::Client::new()
        })
}

/// Credential kind a session is billing under, as a stable label for the
/// billing-flip watchdog (feature #11). Mirrors the handler's `AuthKind` but is
/// a plain string so the watchdog has no dependency on a private handler enum.
pub const AUTH_SUBSCRIPTION: &str = "subscription";
pub const AUTH_METERED: &str = "metered";

/// Silent-billing watchdog (feature #11) — ALERT-ONLY, never blocks.
///
/// Tracks the last-seen billing kind per `x-burnwall-session`. When a session
/// that was on a flat-rate **subscription** flips to **metered** API billing
/// (e.g. a `claude -p` style request that bills the API while the user expected
/// plan coverage), it warns once and records one informational `security_event`
/// — but the request is forwarded unchanged. State is a tiny concurrent map;
/// the flip is reported exactly once because `record` updates the stored kind
/// before returning the flip signal, so a steady run of metered requests after
/// the flip stays quiet. Sessions without an id are not tracked (no key).
#[derive(Debug, Default)]
pub struct BillingWatch {
    last: dashmap::DashMap<String, &'static str>,
}

impl BillingWatch {
    /// Record this request's billing kind for `session` and return `true`
    /// exactly once when it represents a subscription→metered flip. A first
    /// sighting, a steady kind, or a metered→subscription change returns
    /// `false` (only the surprising direction — losing plan coverage — alerts).
    pub fn record(&self, session: &str, kind: &'static str) -> bool {
        match self.last.insert(session.to_string(), kind) {
            Some(prev) => prev == AUTH_SUBSCRIPTION && kind == AUTH_METERED,
            None => false,
        }
    }
}

/// Slow-drip exfiltration monitor (feature #16) — ALERT-ONLY, never blocks.
///
/// Best-effort: counts how often each outbound network **host** (extracted from
/// a URL anywhere in a request body) is targeted across requests, and warns
/// once when a single host crosses [`DripMonitor::THRESHOLD`] in the process
/// lifetime. This is deliberately a coarse, conservative counter, not a rolling
/// window or a per-tool-arg parse: the goal is to surface an obvious
/// many-small-requests-to-one-host pattern without false-positive risk, and to
/// NEVER block (a high-frequency host is far more often a legitimate API than
/// an exfil sink). Because it only ever logs, scanning the whole body — not
/// just tool-call args — is safe: an over-count cannot wedge a session.
#[derive(Debug, Default)]
pub struct DripMonitor {
    counts: dashmap::DashMap<String, u64>,
    alerted: dashmap::DashSet<String>,
}

impl DripMonitor {
    /// Hits to one host before a single best-effort alert fires. High on
    /// purpose: this is an anomaly hint, not an enforcement signal.
    pub const THRESHOLD: u64 = 100;

    /// Count one sighting of `host` and return `true` exactly once, when the
    /// running total first reaches [`Self::THRESHOLD`]. Subsequent sightings of
    /// an already-alerted host return `false` (one warning per host).
    pub fn observe(&self, host: &str) -> bool {
        if host.is_empty() {
            return false;
        }
        let mut entry = self.counts.entry(host.to_string()).or_insert(0);
        *entry += 1;
        let total = *entry;
        drop(entry);
        if total >= Self::THRESHOLD && self.alerted.insert(host.to_string()) {
            return true;
        }
        false
    }
}

/// Process-global watchdog state (features #11 / #16). These live as statics
/// rather than `AppState` fields because both are pure alert-only side channels
/// with no per-instance configuration, and the proxy runs one process per
/// daemon — a process-lifetime map is exactly the right scope. Keeping them out
/// of `AppState` also leaves the struct's exhaustive constructors untouched.
pub static BILLING_WATCH: std::sync::LazyLock<BillingWatch> =
    std::sync::LazyLock::new(BillingWatch::default);
pub static DRIP_MONITOR: std::sync::LazyLock<DripMonitor> =
    std::sync::LazyLock::new(DripMonitor::default);

/// Extract outbound network hosts from any `http(s)://host…` URLs in `text`.
/// Best-effort and allocation-light: a linear scan for `://`, reading the host
/// token up to the next `/`, `:`, `"`, whitespace, or end. Lower-cased and
/// de-duplicated within the call. Used only by the alert-only slow-drip monitor
/// (feature #16); it never gates a request, so loose parsing is acceptable.
pub fn extract_hosts(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while let Some(pos) = text[i..].find("://") {
        let start = i + pos + 3;
        let mut end = start;
        while end < bytes.len() {
            let c = bytes[end];
            if c == b'/' || c == b':' || c == b'"' || c == b'\\' || c.is_ascii_whitespace() {
                break;
            }
            end += 1;
        }
        if end > start {
            let host = text[start..end].to_ascii_lowercase();
            if !out.contains(&host) {
                out.push(host);
            }
        }
        i = end.max(start);
    }
    out
}

/// Shared, immutable-from-the-handler-side state. Each component is `Arc`'d
/// so the tee callback (which runs in a spawned task) can clone the parts
/// it needs without copying the whole struct.
#[derive(Clone)]
pub struct AppState {
    pub upstream_anthropic: String,
    pub upstream_openai: String,
    /// Google Gemini upstream base (v0.7). Routed via `/google/*`.
    pub upstream_google: String,
    pub http_client: reqwest::Client,
    pub security: Arc<SecurityEngine>,
    pub budget: Arc<BudgetTracker>,
    pub loop_detector: Arc<LoopDetector>,
    pub storage: Arc<Storage>,
    /// Auto-inject Anthropic `cache_control` markers on outbound requests.
    /// Off by default — turned on via `proxy.cache_injection` or the
    /// `--rewrite-anthropic-cache` flag on `burnwall start`.
    pub cache_injection: bool,
    /// Trim oversized tool output out of outbound requests (#17,
    /// `proxy.trim_tool_output`). Off by default.
    pub trim_tool_output: bool,
    /// Paranoid / fail-closed mode (#20, `security.paranoid`): block a body the
    /// scanner could not parse rather than forwarding it unscanned. Off by
    /// default — the proxy fails open.
    pub paranoid: bool,
    /// Warn (never block) on a zero-click image/link exfil beacon in a model
    /// reply (#15, `security.warn_response_exfil`). Off by default.
    pub warn_response_exfil: bool,
    /// Endpoint failover + circuit breaking (v0.7). `Default` is a disabled
    /// no-op, so the proxy behaves exactly as before unless `[resilience]` is
    /// configured.
    pub resilience: Arc<Resilience>,
    /// OTel GenAI span sink (v0.7). `None` when `[observability].otel_spans`
    /// is off (the default).
    #[cfg(feature = "observe")]
    pub otel: Option<Arc<crate::observe::otel::SpanWriter>>,
    /// Runtime-pause state file (`~/.burnwall/pause.json`), checked per
    /// request so `burnwall pause` / `allow-once` flip protection live —
    /// without a daemon or tool restart. `None` disables the runtime pause
    /// (the test constructor's default, so a developer's real pause file
    /// can't leak into test runs).
    pub pause_path: Option<std::path::PathBuf>,
}

impl AppState {
    /// Test-friendly constructor: upstream URLs + default security and
    /// budget + loop detector + an in-memory SQLite. Production code (the
    /// `start` command) constructs `AppState` directly with a real
    /// `Storage::open_default()` and a config-derived `LoopDetector`.
    pub fn new(upstream_anthropic: String, upstream_openai: String) -> Self {
        Self {
            upstream_anthropic,
            upstream_openai,
            upstream_google: "https://generativelanguage.googleapis.com".to_string(),
            http_client: build_http_client(),
            security: Arc::new(SecurityEngine::with_defaults()),
            budget: Arc::new(BudgetTracker::with_defaults()),
            loop_detector: Arc::new(LoopDetector::with_defaults()),
            storage: Arc::new(Storage::open_in_memory().expect("in-memory storage cannot fail")),
            cache_injection: false,
            trim_tool_output: false,
            paranoid: false,
            warn_response_exfil: false,
            resilience: Arc::new(Resilience::default()),
            #[cfg(feature = "observe")]
            otel: None,
            pause_path: None,
        }
    }

    /// Real Anthropic and OpenAI hostnames + default everything else.
    /// Suitable for tests that don't need to mock upstream.
    pub fn with_defaults() -> Self {
        Self::new(
            "https://api.anthropic.com".to_string(),
            "https://api.openai.com".to_string(),
        )
    }
}

/// Spawn the real handler as a task and convert a panic into a 502 instead
/// of dropping the connection.
///
/// `tokio::spawn` catches panics in the spawned future and reports them via
/// `JoinError::is_panic()` — but the future must be `Send + 'static`, which
/// `handler::handle` already is. The wrapper returns `Result<…, Infallible>`
/// to match the original signature so the caller is unchanged.
async fn handle_with_panic_catch(
    req: Request<Incoming>,
    state: Arc<AppState>,
) -> Result<Response<ProxyBody>, Infallible> {
    let join = tokio::spawn(async move { handler::handle(req, state).await });
    match join.await {
        Ok(Ok(resp)) => Ok(resp),
        Ok(Err(infallible)) => match infallible {},
        Err(join_err) => {
            error!("handler panicked: {}", join_err);
            Ok(panic_response())
        }
    }
}

/// 502 with a clear, opinionated error body the user can act on. Tells them
/// the kill-switch exists so a runaway crash isn't a dead end.
fn panic_response() -> Response<ProxyBody> {
    let body = r#"{"error":{"type":"proxy_error","message":"Burnwall encountered an internal error. Run `burnwall pause` to relay traffic unchecked while you investigate (auto-resumes), or `burnwall stop` to turn the proxy off."}}"#;
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header("content-type", "application/json")
        .body(streaming::full(Bytes::from(body)))
        .expect("panic_response: builder")
}

/// Bind `addr` and run the accept loop until cancelled.
pub async fn run(addr: SocketAddr, state: AppState) -> std::io::Result<()> {
    run_with_shutdown(addr, state, std::future::pending::<()>()).await
}

/// Bind `addr` and run the accept loop until `shutdown` resolves.
pub async fn run_with_shutdown(
    addr: SocketAddr,
    state: AppState,
    shutdown: impl std::future::Future<Output = ()>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    info!("Burnwall proxy listening on http://{}", bound);
    serve_with_shutdown(listener, Arc::new(state), shutdown).await
}

/// Run the accept loop on a caller-supplied listener. Tests use this with a
/// port-zero bind so they can run in parallel without colliding.
pub async fn serve(listener: TcpListener, state: Arc<AppState>) -> std::io::Result<()> {
    serve_with_shutdown(listener, state, std::future::pending::<()>()).await
}

/// How long a shutdown waits for in-flight requests to finish before the
/// remaining connections are closed anyway. Long enough for a typical API
/// call to complete, short enough that `burnwall stop` stays responsive; a
/// multi-minute stream past this window is still cut (documented behavior).
const DRAIN_WINDOW: std::time::Duration = std::time::Duration::from_secs(10);

/// Run the accept loop until `shutdown` resolves, then stop accepting new
/// connections and **drain**: every in-flight request gets up to
/// [`DRAIN_WINDOW`] to finish (idle keep-alive connections close
/// immediately) before the rest are dropped. Without the drain, every
/// `stop`/`upgrade` cut active agent turns mid-stream, surfacing in the
/// user's AI tool as a bare "socket closed unexpectedly" error.
pub async fn serve_with_shutdown(
    listener: TcpListener,
    state: Arc<AppState>,
    shutdown: impl std::future::Future<Output = ()>,
) -> std::io::Result<()> {
    info!("  /anthropic/* → {}", state.upstream_anthropic);
    info!("  /openai/*    → {}", state.upstream_openai);

    let graceful = hyper_util::server::graceful::GracefulShutdown::new();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                let io = TokioIo::new(stream);
                let state = state.clone();

                let service = service_fn(move |req: hyper::Request<Incoming>| {
                    let state = state.clone();
                    // L1 — panic-catching wrapper. If anything in the
                    // request pipeline panics, return a 502 instead of
                    // dropping the connection (which would surface as a
                    // confusing low-level error inside the user's AI
                    // tool). The panic is logged so we can diagnose it.
                    // Catching panics across an async boundary requires
                    // spawning the work as a task and observing the join
                    // outcome — `AssertUnwindSafe(catch_unwind)` does
                    // not work because the future is not UnwindSafe.
                    async move { handle_with_panic_catch(req, state).await }
                });

                // Register with the drain set BEFORE spawning, so a shutdown
                // racing this accept still covers the connection.
                let conn = Builder::new(TokioExecutor::new())
                    .serve_connection(io, service)
                    .into_owned();
                let watched = graceful.watch(conn);
                tokio::spawn(async move {
                    if let Err(e) = watched.await {
                        error!("connection error from {}: {}", peer, e);
                    }
                });
            }
            _ = &mut shutdown => {
                info!("shutdown signal received — stopping the accept loop and draining in-flight requests");
                break;
            }
        }
    }

    // Drain phase: hyper tells each watched connection to finish its
    // in-flight request(s) and close. Bounded so `stop` stays responsive
    // when a long stream is mid-flight.
    tokio::select! {
        _ = graceful.shutdown() => {
            info!("all connections drained — exiting");
        }
        _ = tokio::time::sleep(DRAIN_WINDOW) => {
            tracing::warn!(
                "drain window ({}s) elapsed — closing remaining connections",
                DRAIN_WINDOW.as_secs()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod watch_tests {
    use super::*;

    // ── #11 silent-billing watchdog ──

    #[test]
    fn billing_flip_fires_once_on_subscription_to_metered() {
        let w = BillingWatch::default();
        // First sighting establishes state, never alerts.
        assert!(!w.record("sess-1", AUTH_SUBSCRIPTION));
        // The flip to metered alerts exactly once.
        assert!(w.record("sess-1", AUTH_METERED));
        // A steady run of metered after the flip stays quiet.
        assert!(!w.record("sess-1", AUTH_METERED));
        assert!(!w.record("sess-1", AUTH_METERED));
    }

    #[test]
    fn steady_metered_session_never_alerts() {
        let w = BillingWatch::default();
        assert!(!w.record("sess-2", AUTH_METERED));
        assert!(!w.record("sess-2", AUTH_METERED));
        assert!(!w.record("sess-2", AUTH_METERED));
    }

    #[test]
    fn steady_subscription_session_never_alerts() {
        let w = BillingWatch::default();
        assert!(!w.record("sess-3", AUTH_SUBSCRIPTION));
        assert!(!w.record("sess-3", AUTH_SUBSCRIPTION));
    }

    #[test]
    fn metered_to_subscription_is_not_a_flip() {
        // Only losing plan coverage (sub→metered) is the surprising direction.
        let w = BillingWatch::default();
        assert!(!w.record("sess-4", AUTH_METERED));
        assert!(!w.record("sess-4", AUTH_SUBSCRIPTION));
    }

    #[test]
    fn distinct_sessions_are_tracked_independently() {
        let w = BillingWatch::default();
        assert!(!w.record("a", AUTH_SUBSCRIPTION));
        assert!(!w.record("b", AUTH_METERED));
        assert!(w.record("a", AUTH_METERED)); // a flips
        assert!(!w.record("b", AUTH_METERED)); // b steady
    }

    // ── #16 slow-drip monitor ──

    #[test]
    fn drip_alerts_once_at_threshold_for_repeated_host() {
        let m = DripMonitor::default();
        let mut alerts = 0;
        for _ in 0..(DripMonitor::THRESHOLD + 50) {
            if m.observe("collector.example.com") {
                alerts += 1;
            }
        }
        assert_eq!(alerts, 1, "exactly one alert per host, at the threshold");
    }

    #[test]
    fn drip_does_not_alert_for_varied_hosts() {
        let m = DripMonitor::default();
        // Far more total requests than the threshold, but spread across many
        // distinct hosts — none individually crosses it.
        for i in 0..(DripMonitor::THRESHOLD * 3) {
            let host = format!("host-{i}.example.com");
            assert!(!m.observe(&host));
        }
    }

    #[test]
    fn drip_ignores_empty_host() {
        let m = DripMonitor::default();
        for _ in 0..(DripMonitor::THRESHOLD + 10) {
            assert!(!m.observe(""));
        }
    }

    // ── host extraction ──

    #[test]
    fn extract_hosts_pulls_url_hosts() {
        let hosts =
            extract_hosts(r#"curl https://Evil.Example.com/path?x=1 and http://other.test:8080/y"#);
        assert!(hosts.contains(&"evil.example.com".to_string()));
        assert!(hosts.contains(&"other.test".to_string()));
    }

    #[test]
    fn extract_hosts_dedups_and_handles_no_urls() {
        let hosts = extract_hosts("https://a.example.com/1 https://a.example.com/2");
        assert_eq!(hosts, vec!["a.example.com".to_string()]);
        assert!(extract_hosts("no urls here, just prose").is_empty());
    }
}
