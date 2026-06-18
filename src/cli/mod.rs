//! Command-line surface — clap definitions + dispatch.

use clap::{Parser, Subcommand};

pub mod accuracy;
#[cfg(feature = "audit")]
pub mod audit;
pub mod claude_settings;
pub mod completions;
pub mod config_cmd;
#[cfg(feature = "observe")]
pub mod cost_per_pr;
pub mod daemon;
#[cfg(feature = "observe")]
pub mod digest;
pub mod disable_routing;
pub mod doctor;
pub mod enable_routing;
pub mod explain;
#[cfg(feature = "logscrape")]
pub mod explore;
pub mod export;
pub mod guard;
pub mod history;
pub mod init;
#[cfg(feature = "mcp")]
pub mod mcp;
#[cfg(feature = "mcp")]
pub mod mcp_watch;
#[cfg(feature = "observe")]
pub mod metrics;
pub mod nudge;
pub mod pause;
pub mod pricing;
pub mod recover;
#[cfg(feature = "observe")]
pub mod report;
pub mod report_bug;
pub mod routing;
pub mod rules;
pub mod savings;
pub mod scan;
pub mod security;
pub mod self_rollback;
pub mod service;
#[cfg(feature = "audit")]
pub mod share;
pub mod sidecar;
pub mod skills;
pub mod start;
pub mod status;
pub mod statusline;
pub mod tags;
pub mod stop;
pub mod uninstall;
pub mod upgrade;
#[cfg(feature = "waste")]
pub mod waste;
pub mod watch;
#[cfg(feature = "observe")]
pub mod wire_check;

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
    /// Pause ALL protection for a short window (relay unchecked) — auto-resumes.
    Pause(pause::PauseArgs),
    /// Resume protection immediately (clears a pause or an armed allow-once).
    Resume,
    /// Let just the NEXT request through unchecked, then auto-restore.
    AllowOnce,
    /// Get unstuck after the proxy died under you: pause routing so new shells
    /// go direct, and print how to recover already-open tools.
    Recover(recover::RecoverArgs),
    /// Watchdog: pause routing automatically if the proxy dies while routed,
    /// so a crashed/quarantined proxy can't strand new shells.
    Guard(guard::GuardArgs),
    /// Show today's spend summary.
    Status(status::StatusArgs),
    /// Show per-day totals over the last N days.
    History(history::HistoryArgs),
    /// Real on-the-wire (cache-aware) cost vs a naive token-tally estimate.
    Accuracy(accuracy::AccuracyArgs),
    /// Attribute spend by `x-burnwall-tags` labels (feature / client / …).
    Tags(tags::TagsArgs),
    /// Read or write `~/.burnwall/config.toml`.
    Config(config_cmd::ConfigArgs),
    /// Detect AI tools and print/apply env-var setup.
    Init(init::InitArgs),
    /// Inspect security events (blocked attempts).
    Security(security::SecurityArgs),
    /// Explain one recorded security block: which rule fired, on what (masked),
    /// why, and how to proceed (from `burnwall security --json` ids).
    Explain(explain::ExplainArgs),
    /// Health check; with `--export`, write a redacted, metadata-only, self-
    /// scanned diagnostic bundle that is safe to attach to a bug report.
    Doctor(doctor::DoctorArgs),
    /// Export your own cost/usage rows (CSV or JSON) for backup, a spreadsheet,
    /// or a machine migration — your data, stays on your machine.
    Export(export::ExportArgs),
    /// Scan agent config files on disk for committed credentials and hidden
    /// instructions (CI / pre-commit file mode — not live traffic).
    Scan(scan::ScanArgs),
    /// Write a sanitized, local bug report of recent blocks (nothing is sent).
    ReportBug(report_bug::ReportBugArgs),
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
    /// Compare on-the-wire proxied spend with a local log-scrape estimate.
    #[cfg(feature = "observe")]
    WireCheck(wire_check::WireCheckArgs),
    /// Enable AI-tool routing through the proxy (writes env file + rc hook).
    EnableRouting(enable_routing::EnableRoutingArgs),
    /// Disable AI-tool routing (empties env file; pair with `eval` to drop from current shell).
    DisableRouting(disable_routing::DisableRoutingArgs),
    /// Register burnwall as a login-time service (launchd / systemd / Scheduled Task).
    InstallService(service::InstallServiceArgs),
    /// Remove the burnwall login-time service.
    UninstallService(service::UninstallServiceArgs),
    /// Uninstall Burnwall: stop the proxy, remove the service, status line, routing, and binary.
    Uninstall(uninstall::UninstallArgs),
    /// Roll back to a prior burnwall release via the dist installer.
    SelfRollback(self_rollback::SelfRollbackArgs),
    /// Upgrade to the latest release (stops the proxy, installs, restarts).
    #[command(visible_alias = "self-upgrade")]
    Upgrade(upgrade::UpgradeArgs),
    /// Inspect and manage the pricing rate card (local + signed remote cards).
    Pricing(pricing::PricingArgs),
    /// Render the Burnwall ribbon for Claude Code's status line (reads stdin JSON).
    Statusline(statusline::StatuslineArgs),
    /// Live cross-tool status ribbon for a spare terminal pane (sourced from the DB).
    Watch(watch::WatchArgs),
    /// Your own measured cache savings + where caching is underused.
    Savings(savings::SavingsArgs),
    /// Run the proxy as a co-located egress sidecar (for off-laptop sandboxes/CI).
    Sidecar(sidecar::SidecarArgs),
    /// Install a guide that teaches coding agents (Claude Code, Codex) to
    /// read Burnwall state and handle blocks — without weakening protection.
    Skills(skills::SkillsArgs),
    /// Emit an opt-in, signed, screenshot-friendly value card.
    #[cfg(feature = "audit")]
    Share(share::ShareArgs),
}

impl Cli {
    pub async fn dispatch(self) -> anyhow::Result<()> {
        match self.command {
            Command::Start(args) => start::run_cmd(args).await,
            Command::Stop(args) => stop::run_cmd(args),
            Command::Pause(args) => pause::run_pause(args),
            Command::Resume => pause::run_resume(),
            Command::AllowOnce => pause::run_allow_once(),
            Command::Recover(args) => recover::run_cmd(args),
            Command::Guard(args) => guard::run_cmd(args).await,
            Command::Status(args) => status::run_cmd(args),
            Command::History(args) => history::run_cmd(args),
            Command::Accuracy(args) => accuracy::run_cmd(args),
            Command::Tags(args) => tags::run_cmd(args),
            Command::Config(args) => config_cmd::run_cmd(args),
            Command::Init(args) => init::run_cmd(args),
            Command::Security(args) => security::run_cmd(args),
            Command::Explain(args) => explain::run_cmd(args),
            Command::Doctor(args) => doctor::run_cmd(args).await,
            Command::Export(args) => export::run_cmd(args),
            Command::Scan(args) => scan::run_cmd(args),
            Command::ReportBug(args) => report_bug::run_cmd(args),
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
            #[cfg(feature = "observe")]
            Command::WireCheck(args) => wire_check::run_cmd(args),
            Command::EnableRouting(args) => enable_routing::run_cmd(args).await,
            Command::DisableRouting(args) => disable_routing::run_cmd(args),
            Command::InstallService(args) => service::install_cmd(args),
            Command::UninstallService(args) => service::uninstall_cmd(args),
            Command::Uninstall(args) => uninstall::run_cmd(args),
            Command::SelfRollback(args) => self_rollback::run_cmd(args),
            Command::Upgrade(args) => upgrade::run_cmd(args),
            Command::Pricing(args) => pricing::run_cmd(args),
            Command::Statusline(args) => statusline::run_cmd(args),
            Command::Watch(args) => watch::run_cmd(args),
            Command::Savings(args) => savings::run_cmd(args),
            Command::Sidecar(args) => sidecar::run_cmd(args).await,
            Command::Skills(args) => skills::run_cmd(args),
            #[cfg(feature = "audit")]
            Command::Share(args) => share::run_cmd(args),
        }
    }
}
