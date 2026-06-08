//! `burnwall sidecar` — run the proxy as a co-located egress point for an
//! agent that executes off your laptop (a self-hosted sandbox, a container, a
//! CI runner).
//!
//! As agentic dev shifts to background/cloud sandboxes, a proxy bound only to
//! `127.0.0.1` can't see the agent's traffic. This subcommand is the same
//! reverse proxy, bound by default to `0.0.0.0` so an agent in a co-located
//! sandbox can reach it, plus the exact env-vars to set inside that sandbox.
//!
//! It is NOT a TLS-terminating forward proxy — Burnwall never injects a CA (see
//! SECURITY.md). It's the existing path-prefix proxy, deployed beside the agent
//! on infrastructure you control.

use clap::Args;

use super::start::{self, StartArgs};

#[derive(Args, Debug)]
pub struct SidecarArgs {
    /// TCP port to listen on (default 4100).
    #[arg(long)]
    pub port: Option<u16>,
    /// Bind address. Defaults to `0.0.0.0` so an agent in a co-located
    /// sandbox/container can reach it. Set a specific bridge IP to limit
    /// exposure.
    #[arg(long)]
    pub host: Option<String>,
    /// Run in the background (PID file under the data dir).
    #[arg(long)]
    pub daemon: bool,
}

pub async fn run_cmd(args: SidecarArgs) -> anyhow::Result<()> {
    let host = args.host.unwrap_or_else(|| "0.0.0.0".to_string());
    let port = args.port.unwrap_or(4100);

    println!("🛰  Burnwall sidecar — co-locate this proxy with your agent's sandbox / CI runner.");
    println!("   Binding {host}:{port}. Inside the sandbox, point the agent at it:");
    println!("     ANTHROPIC_BASE_URL=http://<sidecar-host>:{port}/anthropic");
    println!("     OPENAI_BASE_URL=http://<sidecar-host>:{port}/openai");
    println!("     GOOGLE_GEMINI_BASE_URL=http://<sidecar-host>:{port}/google");
    if host == "0.0.0.0" {
        println!(
            "   ⚠  0.0.0.0 binds all interfaces — run it on an isolated/trusted network \
             (the sandbox bridge), never a public host."
        );
    }
    println!("   (Same scanning + budgets + cost tracking as `burnwall start`, just deployed beside the agent.)");
    println!();

    // Delegate to the normal start path with the sidecar bind defaults.
    start::run_cmd(StartArgs {
        port: Some(port),
        host: Some(host),
        daemon: args.daemon,
        upstream_anthropic: "https://api.anthropic.com".to_string(),
        upstream_openai: "https://api.openai.com".to_string(),
        upstream_google: "https://generativelanguage.googleapis.com".to_string(),
        rewrite_anthropic_cache: false,
    })
    .await
}
