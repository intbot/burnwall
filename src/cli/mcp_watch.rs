//! `burnwall mcp-watch` — pass-through proxy in front of an MCP HTTP
//! transport that records every `tools/call` to `mcp_events`. Read-only:
//! we never block, never modify the request body, and never store
//! argument payloads.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::Context;
use clap::Args;

use crate::cli::daemon;
use crate::mcp::{self, WatchState};
use crate::storage::Storage;

#[derive(Args, Debug)]
pub struct McpWatchArgs {
    /// MCP server to forward requests to (e.g. `http://localhost:8080`).
    /// Required — the watcher has no built-in upstream.
    #[arg(long)]
    pub upstream: String,
    /// TCP port to listen on. Defaults to 4101 (one above the proxy).
    #[arg(long, default_value_t = 4101)]
    pub port: u16,
    /// Address to bind on.
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,
}

pub async fn run_cmd(args: McpWatchArgs) -> anyhow::Result<()> {
    init_tracing();

    let storage = Arc::new(Storage::open_default().context("opening default storage")?);
    let host: IpAddr = args
        .host
        .parse()
        .with_context(|| format!("invalid host: {}", args.host))?;
    let addr = SocketAddr::new(host, args.port);

    println!("🛡️  Burnwall mcp-watch v{}", env!("CARGO_PKG_VERSION"));
    println!("   Listen:   http://{}:{}", args.host, args.port);
    println!("   Upstream: {}", args.upstream);
    println!("   Logging tools/call invocations to ~/.burnwall/burnwall.db (mcp_events table).");
    println!("   Ready. Press Ctrl-C to stop.");

    let state = WatchState {
        upstream: args.upstream.clone(),
        http_client: reqwest::Client::new(),
        storage,
    };

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {addr} — is the port already in use?"))?;

    mcp::serve_with_shutdown(listener, Arc::new(state), daemon::shutdown_signal())
        .await
        .context("mcp-watch serve")?;
    Ok(())
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,hyper=warn,h2=warn")),
        )
        .try_init();
}
