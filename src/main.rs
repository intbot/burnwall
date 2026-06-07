// Burnwall
// https://github.com/intbot/burnwall

use clap::Parser;

use burnwall::cli::Cli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    // Load user pricing overrides before any command computes cost. Fail-open:
    // a malformed pricing.toml warns but never blocks the command.
    if let Err(e) = burnwall::pricing::init_overrides() {
        eprintln!("⚠  pricing override ignored: {e}");
    }
    cli.dispatch().await
}
