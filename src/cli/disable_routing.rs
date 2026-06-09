//! `burnwall disable-routing` — empty the env file and emit eval-able
//! unset lines for the current shell.
//!
//! Persistent state: every configured shell's env file body is replaced with a
//! banner-only stub. Future shells source an empty file → no env vars set →
//! traffic goes direct to upstreams. Disabling from one shell disables them all
//! (see [`Shell::routing_targets`]) so you can't end up routed in PowerShell but
//! not bash, or vice versa.
//!
//! Current-shell state: in eval mode, emit `unset …` lines so the user can
//! `eval "$(burnwall disable-routing)"` and drop the vars without a restart.

use std::io::{IsTerminal, Write};

use anyhow::Result;
use clap::Args;

use super::init::Shell;
use super::routing;
use crate::term::Styler;

#[derive(Args, Debug)]
pub struct DisableRoutingArgs {
    /// Force eval-mode output even when stdout is a TTY.
    #[arg(long)]
    pub eval: bool,
}

pub fn run_cmd(args: DisableRoutingArgs) -> Result<()> {
    let current = Shell::detect()
        .ok_or_else(|| anyhow::anyhow!("could not detect shell — set $SHELL or use --eval"))?;
    let eval_mode = args.eval || !std::io::stdout().is_terminal();
    let sty = Styler::stdout();

    let targets = Shell::routing_targets();
    let mut cleared = Vec::new();
    for shell in targets {
        let env_path = routing::clear_env_file(shell)?;
        cleared.push((shell, env_path));
    }

    let mut out = std::io::stdout().lock();
    if eval_mode {
        for line in routing::unset_lines(current) {
            writeln!(out, "{}", line)?;
        }
    } else {
        writeln!(out, "{}", sty.yellow("🛡  Burnwall routing disabled."))?;
        for (shell, env_path) in &cleared {
            writeln!(
                out,
                "   {}  env file emptied: {}",
                sty.bold(shell.label()),
                sty.blue(&env_path.display().to_string())
            )?;
        }
        if cleared.len() > 1 {
            writeln!(
                out,
                "   {}",
                sty.cyan(&format!("Disabled across {} shells.", cleared.len()))
            )?;
        }
        writeln!(
            out,
            "   (new shells will not have ANTHROPIC_BASE_URL / OPENAI_BASE_URL set)"
        )?;
        writeln!(out)?;
        writeln!(out, "   To drop the env vars from *this* shell now:")?;
        match current {
            Shell::Powershell => {
                writeln!(
                    out,
                    "     {}",
                    sty.bold("burnwall disable-routing --eval | Out-String | Invoke-Expression")
                )?;
            }
            _ => {
                writeln!(
                    out,
                    "     {}",
                    sty.bold("eval \"$(burnwall disable-routing)\"")
                )?;
            }
        }
        writeln!(out)?;
        writeln!(out, "   Re-enable with:  burnwall enable-routing")?;
    }
    Ok(())
}
