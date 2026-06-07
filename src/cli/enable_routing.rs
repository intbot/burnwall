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

use std::io::{IsTerminal, Write};

use anyhow::{Context, Result};
use clap::Args;

use super::init::Shell;
use super::routing::{self, PROXY_DEFAULT};

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

pub async fn run_cmd(args: EnableRoutingArgs) -> Result<()> {
    let shell = Shell::detect()
        .ok_or_else(|| anyhow::anyhow!("could not detect shell — set $SHELL or use --eval"))?;
    let eval_mode = args.eval || !std::io::stdout().is_terminal();

    // ─── pre-flight (skip on --skip-preflight) ───
    if !args.skip_preflight {
        if let Err(e) = preflight(&args.proxy_url).await {
            // Pre-flight failure means: don't write the env file. Emit a
            // clear error and bail. The user can re-run with --skip-preflight
            // if they want to activate anyway.
            let mut stderr = std::io::stderr().lock();
            writeln!(stderr, "burnwall: pre-flight failed — routing NOT enabled.")?;
            writeln!(stderr, "  {}", e)?;
            writeln!(stderr, "  (override with `--skip-preflight` if you know what you're doing)")?;
            anyhow::bail!("pre-flight check failed");
        }
    }

    // ─── persistent write: env file + rc hook ───
    let env_path = routing::write_env_file(shell, &args.proxy_url)?;
    let hook_added = match routing::install_rc_hook(shell, &env_path) {
        Ok(b) => b,
        Err(e) => {
            // Hook install fails on PowerShell (no rc path support) — that's
            // OK in eval mode; the user pipes our output and sets the rc up
            // by hand if they want persistence. Surface the warning only in
            // TTY mode.
            if !eval_mode {
                eprintln!("burnwall: could not install rc hook ({}). The env file is written but won't auto-load.", e);
            }
            false
        }
    };

    // ─── output ───
    let mut out = std::io::stdout().lock();
    if eval_mode {
        // Bare exports for eval "$(burnwall enable-routing)".
        for line in routing::export_lines(shell, &args.proxy_url) {
            writeln!(out, "{}", line)?;
        }
    } else {
        writeln!(out, "🛡  Burnwall routing enabled.")?;
        writeln!(out, "   Env file:  {}", env_path.display())?;
        if hook_added {
            if let Some(rc) = shell.rc_path() {
                writeln!(out, "   Rc hook:   {} (sourced on new shells)", rc.display())?;
            }
        } else if let Some(rc) = shell.rc_path() {
            writeln!(out, "   Rc hook:   {} (already present — left unchanged)", rc.display())?;
        }
        writeln!(out)?;
        writeln!(out, "   To activate in *this* shell without restarting:")?;
        match shell {
            Shell::Powershell => {
                writeln!(out, "     burnwall enable-routing --eval | Out-String | Invoke-Expression")?;
            }
            _ => {
                writeln!(out, "     eval \"$(burnwall enable-routing)\"")?;
            }
        }
        writeln!(out)?;
        writeln!(out, "   Kill switch (instant bypass without disabling):  BURNWALL_BYPASS=1")?;
        writeln!(out, "   Full disable:                                    burnwall disable-routing")?;
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
