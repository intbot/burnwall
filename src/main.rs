// Burnwall — AI agent firewall and cost tracker
// https://github.com/[OWNER]/burnwall

use clap::Parser;

use burnwall::cli::Cli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    Cli::parse().dispatch().await
}
