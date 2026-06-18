//! `burnwall recover` — get unstuck when the proxy died under you.
//!
//! The failure this fixes: the proxy went away (a crash, a forced kill, or —
//! most often on Windows — an **antivirus quarantining the unsigned binary**)
//! while shell routing still points every AI tool at `localhost:<port>`. New
//! requests then fail with a bare `ConnectionRefused` that names nothing.
//!
//! `recover` makes the machine safe again WITHOUT requiring the proxy:
//!
//! 1. If the proxy is down but routing is still Active, **pause routing** so
//!    every newly-opened shell/tool goes direct to the provider.
//! 2. Print the exact env-unset lines for the current shell, so a tool that
//!    re-reads its environment recovers without a restart.
//! 3. Tell the truth about already-running tools: a session that launched
//!    while routed froze the proxy URL at start and can only be fixed by
//!    restarting it — no command can rewrite a live process's environment.
//! 4. Flag a likely antivirus quarantine (binary missing / repeated unclean
//!    exits) and name the fix.
//!
//! It deliberately does NOT touch security or budget state, and never starts
//! anything — it only ever *relaxes* routing toward "go direct", which is the
//! fail-open, never-block-the-user direction.

use std::io::Write;
use std::time::Duration;

use anyhow::Result;
use clap::Args;

use crate::config;

use super::init::Shell;
use super::routing;

#[derive(Args, Debug)]
pub struct RecoverArgs {
    /// Emit only the shell-unset lines (for `eval "$(burnwall recover --eval)"`),
    /// nothing else. Lets a stranded shell drop the routing vars in place.
    #[arg(long)]
    pub eval: bool,
}

pub fn run_cmd(args: RecoverArgs) -> Result<()> {
    let cfg = config::default_path()
        .ok()
        .and_then(|p| config::load_or_default(&p).ok())
        .unwrap_or_default();
    let port = cfg.proxy.port;
    let proxy_up = routing::proxy_port_alive(port, Duration::from_millis(200));

    // --eval mode: pure shell output, nothing else on stdout.
    if args.eval {
        let shell = Shell::detect().unwrap_or(Shell::Bash);
        let mut out = std::io::stdout().lock();
        for line in routing::unset_lines(shell) {
            writeln!(out, "{line}")?;
        }
        return Ok(());
    }

    let mut out = std::io::stdout().lock();
    writeln!(out, "🚑 Burnwall recover")?;
    writeln!(out)?;
    writeln!(
        out,
        "Proxy on port {port}: {}",
        if proxy_up {
            "🟢 listening"
        } else {
            "⚪ not running"
        }
    )?;

    // Which shells are still actively routing (env file carries the exports).
    let routed: Vec<Shell> = Shell::ALL
        .iter()
        .copied()
        .filter(|s| routing::routing_active(*s))
        .collect();

    if proxy_up {
        writeln!(out)?;
        writeln!(
            out,
            "The proxy is up — nothing to recover. If a tool still shows connection errors, it"
        )?;
        writeln!(
            out,
            "was started before the proxy came up; just restart that tool."
        )?;
        return Ok(());
    }

    // Proxy is DOWN. If any shell still routes, pause it so new shells go
    // direct. `pause_routing_unless_alive` only pauses files whose port is
    // dead — exactly this case — and leaves a live second instance alone.
    if routed.is_empty() {
        writeln!(out)?;
        writeln!(
            out,
            "Routing is already direct — new shells reach the provider fine."
        )?;
    } else {
        match routing::pause_routing_unless_alive() {
            Ok(o) if !o.paused.is_empty() => {
                writeln!(out)?;
                writeln!(
                    out,
                    "✅ Paused routing for {} shell(s) — new terminals now go DIRECT to the provider.",
                    o.paused.len()
                )?;
            }
            Ok(_) => {}
            Err(e) => writeln!(out, "⚠️  could not pause routing: {e}")?,
        }
    }

    // Already-open tools: the frozen-env truth.
    writeln!(out)?;
    writeln!(
        out,
        "Already-open AI tools (e.g. a running Claude Code / Codex session):"
    )?;
    writeln!(
        out,
        "  They froze the proxy URL at launch and can't be fixed in place — restart them."
    )?;
    if let Some(shell) = Shell::detect() {
        writeln!(out)?;
        writeln!(
            out,
            "Drop the routing vars from THIS shell (helps tools that re-read the env):"
        )?;
        writeln!(out, "  {}", routing::manual_unset_hint(shell))?;
        writeln!(
            out,
            "  …or apply it directly:  eval \"$(burnwall recover --eval)\"   (PowerShell: iex)"
        )?;
    }

    // Antivirus-quarantine tell: the binary is gone from where it should be.
    if binary_missing() {
        writeln!(out)?;
        writeln!(
            out,
            "🛡️  Burnwall's binary appears to be missing — an antivirus may have quarantined it"
        )?;
        writeln!(
            out,
            "    (a false positive on unsigned binaries). To restore + prevent it:"
        )?;
        #[cfg(windows)]
        {
            writeln!(
                out,
                "      1. In an elevated PowerShell:  Add-MpPreference -ExclusionPath \"$env:USERPROFILE\\.burnwall\""
            )?;
            writeln!(
                out,
                "      2. Reinstall burnwall, then:  burnwall start --daemon"
            )?;
        }
        #[cfg(not(windows))]
        {
            writeln!(
                out,
                "      Restore it from your security tool's quarantine, reinstall, then `burnwall start --daemon`."
            )?;
        }
    } else {
        writeln!(out)?;
        writeln!(
            out,
            "When you're ready, bring the proxy back:  burnwall start --daemon"
        )?;
    }

    Ok(())
}

/// Best-effort check that the installed binary is where the launcher expects
/// it. A missing binary while routing was on is the antivirus-quarantine
/// signature. Conservative: only reports missing when the standard install
/// dir exists but the executable is gone (so a source/dev run doesn't
/// false-alarm).
fn binary_missing() -> bool {
    let Some(home) = dirs::home_dir() else {
        return false;
    };
    let bin_dir = home.join(".burnwall").join("bin");
    if !bin_dir.exists() {
        return false; // not installed via the standard installer — don't guess
    }
    let exe = if cfg!(windows) {
        bin_dir.join("burnwall.exe")
    } else {
        bin_dir.join("burnwall")
    };
    !exe.exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eval_mode_emits_only_unset_lines() {
        // The eval contract: every line must be a shell statement that clears
        // a routing var — nothing else, so `eval`/`iex` is safe.
        for shell in Shell::ALL {
            let lines = routing::unset_lines(shell);
            assert!(!lines.is_empty(), "{}", shell.label());
            assert!(
                lines
                    .iter()
                    .all(|l| l.contains("ANTHROPIC_BASE_URL") || l.contains("OPENAI_BASE_URL")),
                "{}: {lines:?}",
                shell.label()
            );
        }
    }
}
