//! `burnwall mcp-watch` — pass-through proxy in front of an MCP HTTP
//! transport that records every `tools/call` to `mcp_events`. Read-only:
//! we never block, never modify the request body, and never store
//! argument payloads.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::Context;
use clap::Args;

use crate::cli::daemon;
use crate::config;
use crate::mcp::{self, WatchState};
use crate::security::SecurityEngine;
use crate::storage::Storage;

#[derive(Args, Debug)]
pub struct McpWatchArgs {
    /// MCP server to forward unmatched paths to (e.g. `http://localhost:8080`).
    /// Optional when `[[mcp.servers]]` are configured; required otherwise.
    #[arg(long)]
    pub upstream: Option<String>,
    /// TCP port to listen on. Defaults to 4101 (one above the proxy).
    #[arg(long, default_value_t = 4101)]
    pub port: u16,
    /// Address to bind on.
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,
    /// Enforce mode: block `tools/call` to tools not yet approved with
    /// `burnwall mcp approve`. Overrides `mcp.require_approval` from config.
    #[arg(long)]
    pub require_approval: bool,
}

pub async fn run_cmd(args: McpWatchArgs) -> anyhow::Result<()> {
    init_tracing();

    let cfg_path = config::default_path()?;
    let user_config = config::load_or_default(&cfg_path)
        .with_context(|| format!("loading config from {}", cfg_path.display()))?;

    let storage = Arc::new(Storage::open_default().context("opening default storage")?);

    // Load the same security rules the LLM proxy uses, including any
    // discovered per-project profile — so MCP tool calls are filtered
    // against the exact same denylist (and any allow_paths exceptions).
    let mut ruleset: crate::security::Ruleset = (&user_config.security).into();
    let project_profile = match std::env::current_dir() {
        Ok(cwd) => config::project::discover_and_load(&cwd)
            .context("loading per-project .burnwall.yaml")?,
        Err(e) => {
            tracing::warn!("could not determine working directory: {e}");
            None
        }
    };
    if let Some((_, profile)) = &project_profile {
        profile.apply_to_ruleset(&mut ruleset);
    }
    let security = Arc::new(SecurityEngine::new(ruleset));

    // Named upstream servers for multi-server routing (v0.6.5). A `--upstream`
    // (if any) is the fallback for unmatched paths; with neither, we can't
    // route anything.
    let servers: Vec<mcp::McpServer> = user_config
        .mcp
        .servers
        .iter()
        .map(|s| mcp::McpServer {
            name: s.name.clone(),
            upstream: s.upstream.clone(),
        })
        .collect();
    if args.upstream.is_none() && servers.is_empty() {
        anyhow::bail!(
            "no upstream — pass --upstream <url> or configure [[mcp.servers]] in config.toml"
        );
    }
    let require_approval = args.require_approval || user_config.mcp.require_approval;

    let host: IpAddr = args
        .host
        .parse()
        .with_context(|| format!("invalid host: {}", args.host))?;
    let addr = SocketAddr::new(host, args.port);

    println!("🛡️  Burnwall mcp-watch v{}", env!("CARGO_PKG_VERSION"));
    println!("   Listen:   http://{}:{}", args.host, args.port);
    match &args.upstream {
        Some(u) => println!("   Upstream: {u} (default route)"),
        None => println!("   Upstream: (none — routed by [[mcp.servers]] only)"),
    }
    for s in &servers {
        println!("     /{} → {}", s.name, s.upstream);
    }
    println!(
        "   Approval: {}",
        if require_approval {
            "ENFORCE — tools/call to unapproved tools is blocked (see `burnwall mcp`)"
        } else {
            "observe-only (set mcp.require_approval to enforce)"
        }
    );
    println!(
        "   Security: {} deny paths, {} allow paths, {} deny commands, mounts={}, secrets={}, dlp={}",
        security.rules().deny_paths.len(),
        security.rules().allow_paths.len(),
        security.rules().deny_commands.len(),
        security.rules().block_network_mounts,
        security.rules().detect_secrets,
        security.rules().detect_egress,
    );
    if let Some((path, profile)) = &project_profile {
        println!(
            "   Project:  {} ({} allow, {} deny paths)",
            path.display(),
            profile.allow_paths.len(),
            profile.deny_paths.len(),
        );
    }
    println!("   Logging tools/call invocations to ~/.burnwall/burnwall.db (mcp_events table).");
    println!("   Ready. Press Ctrl-C to stop.");

    let state = WatchState {
        upstream: args.upstream.clone().unwrap_or_default(),
        servers,
        require_approval,
        http_client: reqwest::Client::new(),
        storage,
        security,
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
