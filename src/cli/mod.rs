//! Command-line surface — clap definitions + dispatch.

use clap::{Parser, Subcommand};

#[cfg(feature = "audit")]
pub mod audit;
pub mod completions;
pub mod config_cmd;
#[cfg(feature = "observe")]
pub mod cost_per_pr;
pub mod daemon;
#[cfg(feature = "observe")]
pub mod digest;
pub mod disable_routing;
pub mod enable_routing;
#[cfg(feature = "logscrape")]
pub mod explore;
pub mod history;
pub mod init;
#[cfg(feature = "mcp")]
pub mod mcp;
#[cfg(feature = "mcp")]
pub mod mcp_watch;
#[cfg(feature = "observe")]
pub mod metrics;
pub mod pricing;
#[cfg(feature = "observe")]
pub mod report;
pub mod routing;
pub mod rules;
pub mod security;
pub mod self_rollback;
pub mod service;
pub mod start;
pub mod status;
pub mod stop;
#[cfg(feature = "waste")]
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
    #[cfg(feature = "mcp")]
    McpWatch(mcp_watch::McpWatchArgs),
    /// Manage MCP tool approvals and export the MCP audit log.
    #[cfg(feature = "mcp")]
    Mcp(mcp::McpArgs),
    /// Report cost-waste patterns found in local AI session logs.
    #[cfg(feature = "waste")]
    Waste(waste::WasteArgs),
    /// Explore spend by model, harness, and workspace over a window.
    #[cfg(feature = "logscrape")]
    Explore(explore::ExploreArgs),
    /// Manage security-rule packs (list / install official packs).
    Rules(rules::RulesArgs),
    /// Per-model latency (p50/p95), error rate, and throughput.
    #[cfg(feature = "observe")]
    Metrics(metrics::MetricsArgs),
    /// Agent Bill of Materials: models, MCP tools, security checks, cost.
    #[cfg(feature = "observe")]
    Digest(digest::DigestArgs),
    /// Cryptographic audit receipts + CycloneDX/SARIF compliance exports.
    #[cfg(feature = "audit")]
    Audit(audit::AuditArgs),
    /// Shareable weekly/monthly summary (spend, blocks, top models).
    #[cfg(feature = "observe")]
    Report(report::ReportArgs),
    /// Approximate cost of the current git branch / PR (local logs + git).
    #[cfg(feature = "observe")]
    CostPerPr(cost_per_pr::CostPerPrArgs),
    /// Enable AI-tool routing through the proxy (writes env file + rc hook).
    EnableRouting(enable_routing::EnableRoutingArgs),
    /// Disable AI-tool routing (empties env file; pair with `eval` to drop from current shell).
    DisableRouting(disable_routing::DisableRoutingArgs),
    /// Register burnwall as a login-time service (launchd / systemd / Scheduled Task).
    InstallService(service::InstallServiceArgs),
    /// Remove the burnwall login-time service.
    UninstallService(service::UninstallServiceArgs),
    /// Roll back to a prior burnwall release via the dist installer.
    SelfRollback(self_rollback::SelfRollbackArgs),
    /// Inspect and manage the pricing rate card (local + signed remote cards).
    Pricing(pricing::PricingArgs),
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
            #[cfg(feature = "mcp")]
            Command::McpWatch(args) => mcp_watch::run_cmd(args).await,
            #[cfg(feature = "mcp")]
            Command::Mcp(args) => mcp::run_cmd(args),
            #[cfg(feature = "waste")]
            Command::Waste(args) => waste::run_cmd(args),
            #[cfg(feature = "logscrape")]
            Command::Explore(args) => explore::run_cmd(args),
            Command::Rules(args) => rules::run_cmd(args),
            #[cfg(feature = "observe")]
            Command::Metrics(args) => metrics::run_cmd(args),
            #[cfg(feature = "observe")]
            Command::Digest(args) => digest::run_cmd(args),
            #[cfg(feature = "audit")]
            Command::Audit(args) => audit::run_cmd(args),
            #[cfg(feature = "observe")]
            Command::Report(args) => report::run_cmd(args),
            #[cfg(feature = "observe")]
            Command::CostPerPr(args) => cost_per_pr::run_cmd(args),
            Command::EnableRouting(args) => enable_routing::run_cmd(args).await,
            Command::DisableRouting(args) => disable_routing::run_cmd(args),
            Command::InstallService(args) => service::install_cmd(args),
            Command::UninstallService(args) => service::uninstall_cmd(args),
            Command::SelfRollback(args) => self_rollback::run_cmd(args),
            Command::Pricing(args) => pricing::run_cmd(args),
        }
    }
}
