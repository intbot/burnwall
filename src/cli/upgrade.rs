//! `burnwall upgrade` (alias `self-upgrade`) — fetch and install the latest
//! release, handling the two things that make a manual `irm … | iex` fail:
//!
//! 1. **A running proxy holds `burnwall.exe` open** — Windows can't overwrite a
//!    live executable. We stop the proxy first (and restart it after).
//! 2. **The upgrade process IS `burnwall.exe`** — it holds its *own* file. On
//!    Windows we rename our running binary aside (`burnwall.exe.old`, which is
//!    permitted even while running) so the installer can write a fresh one; the
//!    stale `.old` is cleaned up on the next upgrade.
//!
//! Mirror of [`super::self_rollback`], which goes the other direction.

#[cfg(windows)]
use std::path::Path;

use anyhow::{Context, Result};
use clap::Args;

const REPO: &str = "intbot/burnwall";

#[derive(Args, Debug)]
pub struct UpgradeArgs {
    /// Print what would run without doing it.
    #[arg(long)]
    pub dry_run: bool,
    /// Don't restart the proxy afterward, even if it was running.
    #[arg(long)]
    pub no_restart: bool,
}

pub fn run_cmd(args: UpgradeArgs) -> Result<()> {
    let url = installer_url();
    println!("⬆  Upgrading Burnwall to the latest release");
    println!("   Installer URL: {url}");

    if args.dry_run {
        println!("   Would: stop the proxy (if running) → run the installer → restart it.");
        if cfg!(windows) {
            println!("   Would run:  irm {url} | iex");
        } else {
            println!("   Would run:  curl --proto '=https' --tlsv1.2 -LsSf {url} | sh");
        }
        return Ok(());
    }

    // 1. Stop the running proxy so the binary can be replaced. Keep routing:
    //    the stop is transient (we restart right after the install), and the
    //    restart refreshes it anyway. Every path below that ends with the
    //    proxy still down pauses routing explicitly instead.
    let was_running = matches!(super::daemon::running_pid(), Ok(Some(_)));
    if was_running {
        println!("   Stopping the running proxy so the binary can be replaced…");
        let _ = super::stop::run_cmd(super::stop::StopArgs { keep_routing: true });
    }

    // The canonical install path, captured before any rename so the restart
    // targets the freshly-written binary.
    let exe = std::env::current_exe().context("locating the burnwall executable")?;

    // 2. Install the latest release.
    #[cfg(windows)]
    win_upgrade(&url, &exe)?;
    #[cfg(not(windows))]
    run_installer(&url)?;

    println!("   ✓ Installed the latest release.");

    // 3. Restart the proxy if it was running. If it stays down — restart
    //    failed or --no-restart — pause routing so shells aren't left pointed
    //    at a dead port.
    if was_running && !args.no_restart {
        match std::process::Command::new(&exe)
            .args(["start", "--daemon"])
            .status()
        {
            Ok(s) if s.success() => println!("   Restarted the proxy on the new version."),
            _ => {
                println!("   (could not auto-restart — run `burnwall start --daemon`)");
                super::stop::pause_and_report();
            }
        }
    } else if was_running {
        println!("   (not restarted — run `burnwall start --daemon` when ready)");
        super::stop::pause_and_report();
    }
    Ok(())
}

/// Best-effort removal of the `burnwall.exe.old` left behind by a previous
/// Windows self-upgrade. The running binary can't delete itself, so the renamed
/// copy lingers until something else runs — this sweeps it on the next launch.
/// Silent and cheap (the file is normally absent). No-op off Windows, where no
/// rename-aside happens.
pub fn sweep_stale_artifact() {
    #[cfg(windows)]
    if let Ok(exe) = std::env::current_exe() {
        let old = exe.with_extension("exe.old");
        let _ = std::fs::remove_file(old);
    }
}

fn installer_url() -> String {
    // `releases/latest/download/…` always resolves to the newest release asset.
    let filename = if cfg!(windows) {
        "burnwall-installer.ps1"
    } else {
        "burnwall-installer.sh"
    };
    format!("https://github.com/{REPO}/releases/latest/download/{filename}")
}

#[cfg(not(windows))]
fn run_installer(url: &str) -> Result<()> {
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("curl --proto '=https' --tlsv1.2 -LsSf '{url}' | sh"))
        .status()
        .context("running shell installer")?;
    if !status.success() {
        anyhow::bail!("installer exited with status {status}");
    }
    Ok(())
}

/// Windows: rename our own running binary aside so the installer can write a
/// fresh one at the original path, then restore on failure.
#[cfg(windows)]
fn win_upgrade(url: &str, exe: &Path) -> Result<()> {
    let old = exe.with_extension("exe.old");
    // Best-effort: clear a leftover from a previous upgrade.
    let _ = std::fs::remove_file(&old);
    // Windows permits renaming a running executable (it can't overwrite it).
    std::fs::rename(exe, &old)
        .with_context(|| format!("moving current binary aside ({} → .old)", exe.display()))?;

    let result = run_installer_ps(url);
    if result.is_err() {
        // Restore the original binary so we never leave the user without one.
        let _ = std::fs::rename(&old, exe);
    }
    result
}

#[cfg(windows)]
fn run_installer_ps(url: &str) -> Result<()> {
    let status = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &format!("irm {url} | iex"),
        ])
        .status()
        .context("running PowerShell installer")?;
    if !status.success() {
        anyhow::bail!("installer exited with status {status}");
    }
    Ok(())
}
