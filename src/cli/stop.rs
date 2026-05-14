//! `burnwall stop` — placeholder.
//!
//! v0.1 runs the proxy in the foreground (Ctrl-C to stop). Background
//! daemon mode + a real PID-file-aware `stop` is planned for a later
//! release.

use clap::Args;

#[derive(Args, Debug)]
pub struct StopArgs {}

pub fn run_cmd(_args: StopArgs) -> anyhow::Result<()> {
    println!("v0.1 runs in the foreground only — press Ctrl-C in the start window.");
    println!("Background daemon mode + a real `burnwall stop` lands in v0.2.");
    Ok(())
}
