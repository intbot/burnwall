//! `burnwall uninstall` — undo everything `install` + `init` set up, in one
//! command, so you can get back to a clean machine (and verify a fresh install
//! from scratch).
//!
//! It reverses, in order:
//!
//! 1. **The running proxy** — stopped (a live `burnwall.exe` also can't delete
//!    itself on Windows; stopping first frees the daemon, not this process).
//! 2. **The login service** — launchd / systemd unit / Windows Run-key+Task.
//! 3. **The Claude Code status line** — our `statusLine` block in
//!    `~/.claude/settings.json` (a foreign one is left untouched).
//! 4. **Shell routing** — the env file is emptied and the rc-source hook line
//!    removed, so new shells stop pointing at the proxy.
//! 5. **The binary** — removed (on Windows the *running* binary is renamed
//!    aside, since a live process can't unlink itself).
//!
//! By default the cost-history database (`~/.burnwall/burnwall.db`) is **kept**
//! — it's your data. `--purge` removes the entire `~/.burnwall` data directory.
//!
//! Destructive, so it confirms first unless `--yes`. Non-interactive stdin
//! without `--yes` aborts rather than guessing.

use std::io::{IsTerminal, Write};
use std::path::Path;

use anyhow::Result;
use clap::Args;

use super::init::Shell;

#[derive(Args, Debug)]
pub struct UninstallArgs {
    /// Also delete the data directory (`~/.burnwall`): cost-history database,
    /// status-line state, config. Without this, your spend history is kept.
    #[arg(long)]
    pub purge: bool,
    /// Skip the confirmation prompt (for scripts / unattended teardown).
    #[arg(long)]
    pub yes: bool,
}

pub fn run_cmd(args: UninstallArgs) -> Result<()> {
    let mut out = std::io::stdout().lock();

    if !confirm(&mut out, args.purge, args.yes)? {
        writeln!(out, "Aborted. Nothing was changed.")?;
        return Ok(());
    }
    writeln!(out)?;

    // 1. Stop the proxy (best-effort — not running is fine).
    writeln!(out, "1. Stopping the proxy…")?;
    if let Err(e) = super::stop::run_cmd(super::stop::StopArgs {}) {
        writeln!(out, "   • {e}")?;
    }

    // 2. Login service.
    writeln!(out, "2. Removing the login service…")?;
    if let Err(e) = super::service::uninstall_cmd(super::service::UninstallServiceArgs {}) {
        writeln!(out, "   • {e}")?;
    }

    // 3. Claude Code status line.
    writeln!(out, "3. Removing the Claude Code status line…")?;
    match super::claude_settings::settings_path() {
        Some(path) => match super::claude_settings::remove(&path) {
            Ok(true) => writeln!(out, "   ✓ removed `statusLine` from {}", path.display())?,
            Ok(false) => writeln!(out, "   • nothing of ours to remove")?,
            Err(e) => writeln!(out, "   ⚠  skipped: {e}")?,
        },
        None => writeln!(out, "   • could not locate ~/.claude/settings.json")?,
    }

    // 4. Shell routing (env file + rc hook) — across EVERY configured shell,
    // not just the one we're running in. A single-shell teardown is the bug
    // that leaves, e.g., bash still sourcing a hook that points at a removed
    // proxy after you uninstalled from PowerShell.
    writeln!(out, "4. Disabling shell routing…")?;
    let mut shells: Vec<Shell> = Shell::configured();
    if let Some(cur) = Shell::detect() {
        if !shells.contains(&cur) {
            shells.push(cur);
        }
    }
    let mut touched_any = false;
    for shell in &shells {
        // Only act on shells that actually carry our state — don't create a
        // disabled-stub env file in a shell the user never wired up (that would
        // *leave* a file behind on uninstall, the opposite of clean).
        if !super::routing::env_file_present(*shell) && !super::routing::rc_hook_present(*shell) {
            continue;
        }
        touched_any = true;
        match super::routing::clear_env_file(*shell) {
            Ok(p) => writeln!(out, "   ✓ {} env file emptied: {}", shell.label(), p.display())?,
            Err(e) => writeln!(out, "   • {} env file: {e}", shell.label())?,
        }
        match super::routing::remove_rc_hook(*shell) {
            Ok(true) => writeln!(out, "   ✓ {} rc-source hook removed", shell.label())?,
            Ok(false) => writeln!(out, "   • {} no rc hook present", shell.label())?,
            Err(e) => writeln!(out, "   • {} rc hook: {e}", shell.label())?,
        }
    }
    if !touched_any {
        writeln!(out, "   • nothing of ours found in any shell")?;
    }

    // 5. Data directory (--purge) and the binary.
    let data_dir = crate::storage::data_dir().ok();
    if args.purge {
        writeln!(out, "5. Purging the data directory…")?;
        if let Some(dir) = &data_dir {
            purge_data(dir, &mut out)?;
        }
    } else {
        writeln!(out, "5. Removing the binary (keeping your cost history)…")?;
    }
    if let Ok(exe) = std::env::current_exe() {
        remove_binary(&exe, &mut out)?;
    }

    writeln!(out)?;
    writeln!(out, "🛡  Burnwall uninstalled.")?;
    if !args.purge {
        if let Some(dir) = &data_dir {
            writeln!(out, "   Your cost history is kept at {}.", dir.display())?;
            writeln!(out, "   Re-run with --purge to delete it too.")?;
        }
    }
    writeln!(
        out,
        "   Reinstall any time:  irm https://raw.githubusercontent.com/intbot/burnwall/main/install.ps1 | iex"
    )?;
    Ok(())
}

/// Confirm the teardown. Non-interactive without `--yes` is treated as "no" so
/// a piped/CI invocation can't wipe a machine by accident.
fn confirm<W: Write>(out: &mut W, purge: bool, yes: bool) -> Result<bool> {
    if yes {
        return Ok(true);
    }
    if !std::io::stdin().is_terminal() {
        writeln!(
            out,
            "Refusing to uninstall non-interactively without --yes."
        )?;
        return Ok(false);
    }
    let scope = if purge {
        "Uninstall Burnwall AND delete your cost-history data"
    } else {
        "Uninstall Burnwall (cost-history data kept)"
    };
    write!(out, "{scope}? [y/N]: ")?;
    out.flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let a = line.trim().to_ascii_lowercase();
    Ok(a == "y" || a == "yes")
}

/// Remove the data files under `~/.burnwall`, leaving the `bin/` directory (the
/// running binary lives there and is handled separately). Best-effort per file.
fn purge_data<W: Write>(dir: &Path, out: &mut W) -> Result<()> {
    if !dir.exists() {
        writeln!(out, "   • no data directory at {}", dir.display())?;
        return Ok(());
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            writeln!(out, "   • could not read {}: {e}", dir.display())?;
            return Ok(());
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        // Skip the bin dir — removing the live binary's directory fails on
        // Windows; the binary itself is dealt with in `remove_binary`.
        if path.file_name().is_some_and(|n| n == "bin") {
            continue;
        }
        let res = if path.is_dir() {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        match res {
            Ok(()) => writeln!(out, "   ✓ removed {}", path.display())?,
            Err(e) => writeln!(out, "   • could not remove {}: {e}", path.display())?,
        }
    }
    Ok(())
}

/// Remove the running binary. On Unix a process can unlink its own executable,
/// so we just delete it. On Windows that fails (the image is locked), so we
/// rename it aside to `burnwall.exe.old` — the same trick `upgrade` uses; a
/// reinstall overwrites the real name and the stub can be deleted manually.
#[cfg(not(windows))]
fn remove_binary<W: Write>(exe: &Path, out: &mut W) -> Result<()> {
    match std::fs::remove_file(exe) {
        Ok(()) => writeln!(out, "   ✓ removed binary: {}", exe.display())?,
        Err(e) => writeln!(out, "   • could not remove {}: {e}", exe.display())?,
    }
    Ok(())
}

#[cfg(windows)]
fn remove_binary<W: Write>(exe: &Path, out: &mut W) -> Result<()> {
    let aside = exe.with_file_name("burnwall.exe.old");
    let _ = std::fs::remove_file(&aside); // clear any prior stub first
    match std::fs::rename(exe, &aside) {
        Ok(()) => {
            writeln!(
                out,
                "   ✓ renamed running binary aside: {}",
                aside.display()
            )?;
            writeln!(
                out,
                "     (a live binary can't delete itself; reinstall overwrites it)"
            )?;
        }
        Err(e) => writeln!(out, "   • could not remove {}: {e}", exe.display())?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purge_removes_data_but_keeps_bin() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("burnwall.db"), b"data").unwrap();
        std::fs::create_dir(root.join("statusline")).unwrap();
        std::fs::write(root.join("statusline").join("s.last"), b"0").unwrap();
        std::fs::create_dir(root.join("bin")).unwrap();
        std::fs::write(root.join("bin").join("burnwall.exe"), b"binary").unwrap();

        let mut out = Vec::new();
        purge_data(root, &mut out).unwrap();

        assert!(!root.join("burnwall.db").exists());
        assert!(!root.join("statusline").exists());
        // bin/ (and the live binary) is intentionally preserved here.
        assert!(root.join("bin").join("burnwall.exe").exists());
    }

    #[test]
    fn purge_on_missing_dir_is_ok() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope");
        let mut out = Vec::new();
        assert!(purge_data(&missing, &mut out).is_ok());
    }
}
