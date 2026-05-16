// Burnwall
// https://github.com/intbot/burnwall

use clap::Parser;

use burnwall::cli::Cli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    Cli::parse().dispatch().await
}
