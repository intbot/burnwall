//! `burnwall enable-routing` — write the env file + install the rc hook,
//! optionally run a self-test, and emit eval-able shell exports.
//!
//! ## Two output modes (Option b)
//!
//! When stdout is **a TTY**: human-readable output with the persistent file
//! write, the rc-hook install, and a hint to apply to the current shell now.
//!
//! When stdout is **a pipe** (`eval "$(burnwall enable-routing)"`): bare
//! `export …` lines suitable for direct evaluation, plus the persistent
//! file write. The current shell picks up the env vars immediately.
//!
//! ## Multi-shell sync
//!
//! Routing is applied to every shell the user has configured (plus the current
//! one), not just the detected shell — see [`Shell::routing_targets`]. A
//! Windows user typically drives both PowerShell and Git-bash; enabling from
//! one must not leave the other silently unrouted.

use std::io::{IsTerminal, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;

use super::init::Shell;
use super::routing::{self, PROXY_DEFAULT};
use crate::term::Styler;

#[derive(Args, Debug)]
pub struct EnableRoutingArgs {
    /// Proxy URL to point AI tools at.
    #[arg(long, default_value = PROXY_DEFAULT)]
    pub proxy_url: String,
    /// Skip the self-test request against the proxy. Use only if you know
    /// the proxy is healthy but don't have an API key handy.
    #[arg(long)]
    pub skip_preflight: bool,
    /// Force eval-mode output even when stdout is a TTY (useful for
    /// scripting where you want both: persist + emit exports).
    #[arg(long)]
    pub eval: bool,
}

/// Outcome of writing one shell's routing files.
struct ShellWrite {
    shell: Shell,
    env_path: PathBuf,
    /// `Some(true)` rc hook added, `Some(false)` already present, `None` the
    /// shell has no rc file we auto-edit (PowerShell — by design).
    hook: Option<bool>,
}

pub async fn run_cmd(args: EnableRoutingArgs) -> Result<()> {
    let current = Shell::detect()
        .ok_or_else(|| anyhow::anyhow!("could not detect shell — set $SHELL or use --eval"))?;
    let eval_mode = args.eval || !std::io::stdout().is_terminal();
    let sty = Styler::stdout();

    // ─── pre-flight (skip on --skip-preflight) ───
    if !args.skip_preflight {
        if let Err(e) = preflight(&args.proxy_url).await {
            // Pre-flight failure means: don't write the env file. Emit a
            // clear error and bail. The user can re-run with --skip-preflight
            // if they want to activate anyway.
            let est = Styler::stderr();
            let mut stderr = std::io::stderr().lock();
            writeln!(
                stderr,
                "{}",
                est.red("burnwall: pre-flight failed — routing NOT enabled.")
            )?;
            writeln!(stderr, "  {}", e)?;
            writeln!(
                stderr,
                "  (override with `--skip-preflight` if you know what you're doing)"
            )?;
            anyhow::bail!("pre-flight check failed");
        }
    }

    // ─── persistent write: env file + rc hook, for every target shell ───
    let targets = Shell::routing_targets();
    let mut writes: Vec<ShellWrite> = Vec::new();
    for shell in targets {
        let env_path = routing::write_env_file(shell, &args.proxy_url)?;
        // Every shell gets a persistent hook now — including PowerShell, whose
        // CurrentUserAllHosts profile(s) install_rc_hook manages (L-C2: the
        // default Windows shell used to be a silent dead end here).
        let hook = match routing::install_rc_hook(shell, &env_path) {
            Ok(b) => Some(b),
            Err(e) => {
                if !eval_mode {
                    let est = Styler::stderr();
                    eprintln!(
                        "{}",
                        est.yellow(&format!(
                            "burnwall: could not install rc hook for {} ({e}). \
                             The env file is written but won't auto-load.",
                            shell.label()
                        ))
                    );
                }
                Some(false)
            }
        };
        writes.push(ShellWrite {
            shell,
            env_path,
            hook,
        });
    }

    // ─── output ───
    let mut out = std::io::stdout().lock();
    if eval_mode {
        // Bare exports for the *current* shell only — you can't eval PowerShell
        // syntax in bash. The persistent files above already cover the rest.
        for line in routing::export_lines(current, &args.proxy_url) {
            writeln!(out, "{}", line)?;
        }
    } else {
        writeln!(out, "{}", sty.green("🛡  Burnwall routing enabled."))?;
        for w in &writes {
            let tag = if w.shell == current {
                format!("{} (current)", w.shell.label())
            } else {
                w.shell.label().to_string()
            };
            writeln!(
                out,
                "   {}  env file:  {}",
                sty.bold(&tag),
                sty.blue(&w.env_path.display().to_string())
            )?;
            let hook_label = if w.shell == crate::cli::init::Shell::Powershell {
                routing::powershell_profile_paths()
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            } else {
                w.shell
                    .rc_path()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| w.shell.label().to_string())
            };
            match w.hook {
                Some(true) => writeln!(
                    out,
                    "       rc hook:   {} (sourced on new shells)",
                    sty.blue(&hook_label)
                )?,
                Some(false) => writeln!(
                    out,
                    "       rc hook:   {} (already present — left unchanged)",
                    sty.blue(&hook_label)
                )?,
                None => writeln!(
                    out,
                    "       rc hook:   {}",
                    sty.yellow("not installed — use the eval line below for this session")
                )?,
            }
        }
        if writes.len() > 1 {
            writeln!(
                out,
                "   {}",
                sty.cyan(&format!(
                    "Synced {} shells so routing is consistent across all of them.",
                    writes.len()
                ))
            )?;
        }
        writeln!(out)?;
        writeln!(out, "   To activate in *this* shell without restarting:")?;
        match current {
            Shell::Powershell => {
                writeln!(
                    out,
                    "     {}",
                    sty.bold("burnwall enable-routing --eval | Out-String | Invoke-Expression")
                )?;
            }
            _ => {
                writeln!(out, "     {}", sty.bold("eval \"$(burnwall enable-routing)\""))?;
            }
        }
        writeln!(out)?;
        writeln!(
            out,
            "   Kill switch (instant bypass without disabling):  {}",
            sty.yellow("BURNWALL_BYPASS=1")
        )?;
        writeln!(
            out,
            "   Full disable:                                    burnwall disable-routing"
        )?;
    }
    Ok(())
}

/// Pre-flight self-test: GET `<proxy_url>/healthz` (a route the proxy
/// answers locally without touching upstream — cheap, no API key needed).
///
/// We do NOT send a real upstream request: it would require valid creds and
/// would cost the user a few tokens for no real signal beyond "is the proxy
/// up." The proxy being reachable is the meaningful gate here.
async fn preflight(proxy_url: &str) -> Result<()> {
    let url = format!("{}/healthz", proxy_url.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .context("building preflight HTTP client")?;
    let resp = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("could not reach {url} — is `burnwall start` running?"))?;
    if !resp.status().is_success() {
        anyhow::bail!("proxy returned {} on {}", resp.status(), url);
    }
    Ok(())
}
