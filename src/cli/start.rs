//! `burnwall start` — boot the proxy. Reads `~/.burnwall/config.toml` for
//! budget, security, and proxy bind values; CLI flags override individual
//! fields when present.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::Context;
use clap::Args;

use crate::budget::BudgetTracker;
use crate::config;
use crate::proxy::{run, AppState};
use crate::security::SecurityEngine;
use crate::storage::Storage;

#[derive(Args, Debug)]
pub struct StartArgs {
    /// TCP port to listen on. Overrides `proxy.port` from config.
    #[arg(long)]
    pub port: Option<u16>,
    /// Address to bind on. Overrides `proxy.host` from config.
    #[arg(long)]
    pub host: Option<String>,
    /// Override the Anthropic upstream URL (useful for testing).
    #[arg(long, default_value = "https://api.anthropic.com")]
    pub upstream_anthropic: String,
    /// Override the OpenAI upstream URL.
    #[arg(long, default_value = "https://api.openai.com")]
    pub upstream_openai: String,
}

pub async fn run_cmd(args: StartArgs) -> anyhow::Result<()> {
    init_tracing();

    let cfg_path = config::default_path()?;
    let user_config = config::load_or_default(&cfg_path)
        .with_context(|| format!("loading config from {}", cfg_path.display()))?;

    let storage = Arc::new(Storage::open_default().context("opening default storage")?);
    let security = Arc::new(SecurityEngine::new((&user_config.security).into()));
    let budget = Arc::new(BudgetTracker::new((&user_config.budget).into()));

    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    budget
        .hydrate_for_date(&storage, &today)
        .context("hydrating today's spend")?;

    let port = args.port.unwrap_or(user_config.proxy.port);
    let host_str = args
        .host
        .clone()
        .unwrap_or_else(|| user_config.proxy.host.clone());

    print_banner(&host_str, port, &args, &storage, &security, &budget);

    let state = AppState {
        upstream_anthropic: args.upstream_anthropic.clone(),
        upstream_openai: args.upstream_openai.clone(),
        http_client: reqwest::Client::new(),
        security,
        budget,
        storage,
    };

    let host: IpAddr = host_str
        .parse()
        .with_context(|| format!("invalid host: {}", host_str))?;
    let addr = SocketAddr::new(host, port);

    run(addr, state).await.context("proxy run")?;
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

fn print_banner(
    host: &str,
    port: u16,
    args: &StartArgs,
    storage: &Arc<Storage>,
    security: &Arc<SecurityEngine>,
    budget: &Arc<BudgetTracker>,
) {
    let _ = storage;
    println!("🛡️  Burnwall v{}", env!("CARGO_PKG_VERSION"));
    println!("   Proxy:    http://{}:{}", host, port);
    println!("   Routes:");
    println!("     /anthropic/* → {}", args.upstream_anthropic);
    println!("     /openai/*    → {}", args.upstream_openai);
    println!(
        "   Security: {} deny paths, {} deny commands, mounts={}, secrets={}",
        security.rules().deny_paths.len(),
        security.rules().deny_commands.len(),
        security.rules().block_network_mounts,
        security.rules().detect_secrets,
    );
    let cfg = budget.config();
    if cfg.daily_usd > 0.0 {
        println!(
            "   Budget:   ${:.2}/day (today: ${:.4})",
            cfg.daily_usd,
            budget.today_spent()
        );
    } else {
        println!("   Budget:   unlimited");
    }
    println!("   Ready. Press Ctrl-C to stop.");
}
