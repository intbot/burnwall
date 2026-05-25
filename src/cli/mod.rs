//! Command-line surface — clap definitions + dispatch.

use clap::{Parser, Subcommand};

pub mod completions;
pub mod config_cmd;
pub mod daemon;
pub mod explore;
pub mod history;
pub mod init;
pub mod mcp_watch;
pub mod security;
pub mod start;
pub mod status;
pub mod stop;
pub mod waste;

#[derive(Parser, Debug)]
#[command(name = "burnwall", version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Start the proxy server.
    Start(start::StartArgs),
    /// Stop the running Burnwall proxy.
    Stop(stop::StopArgs),
    /// Show today's spend summary.
    Status(status::StatusArgs),
    /// Show per-day totals over the last N days.
    History(history::HistoryArgs),
    /// Read or write `~/.burnwall/config.toml`.
    Config(config_cmd::ConfigArgs),
    /// Detect AI tools and print/apply env-var setup.
    Init(init::InitArgs),
    /// Inspect security events (blocked attempts).
    Security(security::SecurityArgs),
    /// Print a shell-completion script to stdout.
    Completions(completions::CompletionsArgs),
    /// Pass-through MCP HTTP proxy that logs tools/call invocations.
    McpWatch(mcp_watch::McpWatchArgs),
    /// Report cost-waste patterns found in local AI session logs.
    Waste(waste::WasteArgs),
    /// Explore spend by model, harness, and workspace over a window.
    Explore(explore::ExploreArgs),
}

impl Cli {
    pub async fn dispatch(self) -> anyhow::Result<()> {
        match self.command {
            Command::Start(args) => start::run_cmd(args).await,
            Command::Stop(args) => stop::run_cmd(args),
            Command::Status(args) => status::run_cmd(args),
            Command::History(args) => history::run_cmd(args),
            Command::Config(args) => config_cmd::run_cmd(args),
            Command::Init(args) => init::run_cmd(args),
            Command::Security(args) => security::run_cmd(args),
            Command::Completions(args) => completions::run_cmd(args),
            Command::McpWatch(args) => mcp_watch::run_cmd(args).await,
            Command::Waste(args) => waste::run_cmd(args),
            Command::Explore(args) => explore::run_cmd(args),
        }
    }
}
