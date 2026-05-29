//! Proxy server entry point.
//!
//! Binds a TCP listener, accepts connections, and dispatches every request
//! to [`handler::handle`], which routes by URL prefix, runs the security
//! and budget checks, and forwards via [`forwarding::forward`]. Response
//! bodies are streamed back using [`ProxyBody`]; on the way through, the
//! body is tee'd into a background parser so cost tracking works for both
//! streaming and non-streaming responses.

use std::net::SocketAddr;
use std::sync::Arc;

use hyper::body::Incoming;
use hyper::service::service_fn;
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
pub mod streaming;

pub use resilience::Resilience;
pub use streaming::{BoxError, ProxyBody};

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
    /// Endpoint failover + circuit breaking (v0.7). `Default` is a disabled
    /// no-op, so the proxy behaves exactly as before unless `[resilience]` is
    /// configured.
    pub resilience: Arc<Resilience>,
    /// OTel GenAI span sink (v0.7). `None` when `[observability].otel_spans`
    /// is off (the default).
    #[cfg(feature = "observe")]
    pub otel: Option<Arc<crate::observe::otel::SpanWriter>>,
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
            http_client: reqwest::Client::new(),
            security: Arc::new(SecurityEngine::with_defaults()),
            budget: Arc::new(BudgetTracker::with_defaults()),
            loop_detector: Arc::new(LoopDetector::with_defaults()),
            storage: Arc::new(Storage::open_in_memory().expect("in-memory storage cannot fail")),
            cache_injection: false,
            resilience: Arc::new(Resilience::default()),
            #[cfg(feature = "observe")]
            otel: None,
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

/// Run the accept loop until `shutdown` resolves, then stop accepting new
/// connections and return. In-flight connections are dropped — there is no
/// drain phase — because the proxy is read-only on the response path and
/// every cost record is committed per-request, so an abrupt stop cannot
/// corrupt state.
pub async fn serve_with_shutdown(
    listener: TcpListener,
    state: Arc<AppState>,
    shutdown: impl std::future::Future<Output = ()>,
) -> std::io::Result<()> {
    info!("  /anthropic/* → {}", state.upstream_anthropic);
    info!("  /openai/*    → {}", state.upstream_openai);

    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                let io = TokioIo::new(stream);
                let state = state.clone();

                tokio::spawn(async move {
                    let service = service_fn(move |req: hyper::Request<Incoming>| {
                        let state = state.clone();
                        async move { handler::handle(req, state).await }
                    });

                    if let Err(e) = Builder::new(TokioExecutor::new())
                        .serve_connection(io, service)
                        .await
                    {
                        error!("connection error from {}: {}", peer, e);
                    }
                });
            }
            _ = &mut shutdown => {
                info!("shutdown signal received — stopping the accept loop");
                return Ok(());
            }
        }
    }
}
