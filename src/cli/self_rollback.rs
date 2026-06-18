//! `burnwall self-rollback <version>` — fetch and run the dist-pinned
//! installer for a prior release. The dist installer already handles atomic
//! replacement on POSIX; on Windows we ask the user to stop the service
//! first because a running `.exe` can't be overwritten.
//!
//! Per-version installer URLs follow cargo-dist's convention:
//!   https://github.com/intbot/burnwall/releases/download/v{ver}/burnwall-installer.sh
//!   https://github.com/intbot/burnwall/releases/download/v{ver}/burnwall-installer.ps1

use anyhow::{Context, Result};
use clap::Args;

const REPO: &str = "intbot/burnwall";

#[derive(Args, Debug)]
pub struct SelfRollbackArgs {
    /// Target version to roll back to, e.g. `0.9.2`. The leading `v` is
    /// optional.
    pub version: String,
    /// Print the install command without running it.
    #[arg(long)]
    pub dry_run: bool,
}

pub fn run_cmd(args: SelfRollbackArgs) -> Result<()> {
    let ver = args.version.trim_start_matches('v');
    let url = installer_url(ver);

    println!("🛡  Rolling back to v{ver}");
    println!("   Installer URL: {url}");

    if cfg!(windows) {
        if let Ok(Some(_)) = super::daemon::running_pid() {
            anyhow::bail!(
                "Burnwall is running — stop it first (`burnwall stop`) so Windows can replace the .exe.\n  Then re-run this rollback command."
            );
        }
    }

    if args.dry_run {
        if cfg!(windows) {
            println!("   Would run:  irm {url} | iex");
        } else {
            println!("   Would run:  curl --proto '=https' --tlsv1.2 -LsSf {url} | sh");
        }
        return Ok(());
    }

    run_installer(&url)
}

fn installer_url(ver: &str) -> String {
    let filename = if cfg!(windows) {
        "burnwall-installer.ps1"
    } else {
        "burnwall-installer.sh"
    };
    format!("https://github.com/{REPO}/releases/download/v{ver}/{filename}")
}

#[cfg(not(windows))]
fn run_installer(url: &str) -> Result<()> {
    // curl … | sh — the dist installer takes over from there.
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!(
            "curl --proto '=https' --tlsv1.2 -LsSf '{}' | sh",
            url
        ))
        .status()
        .context("running shell installer")?;
    if !status.success() {
        anyhow::bail!("installer exited with status {}", status);
    }
    Ok(())
}

#[cfg(windows)]
fn run_installer(url: &str) -> Result<()> {
    let status = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &format!("irm {} | iex", url),
        ])
        .status()
        .context("running PowerShell installer")?;
    if !status.success() {
        anyhow::bail!("installer exited with status {}", status);
    }
    Ok(())
}
