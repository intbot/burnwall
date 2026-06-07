//! `burnwall disable-routing` — empty the env file and emit eval-able
//! unset lines for the current shell.
//!
//! Persistent state: env file body is replaced with a banner-only stub.
//! Future shells source an empty file → no env vars set → traffic goes
//! direct to upstreams.
//!
//! Current-shell state: in eval mode, emit `unset …` lines so the user can
//! `eval "$(burnwall disable-routing)"` and drop the vars without a restart.

use std::io::{IsTerminal, Write};

use anyhow::Result;
use clap::Args;

use super::init::Shell;
use super::routing;

#[derive(Args, Debug)]
pub struct DisableRoutingArgs {
    /// Force eval-mode output even when stdout is a TTY.
    #[arg(long)]
    pub eval: bool,
}

pub fn run_cmd(args: DisableRoutingArgs) -> Result<()> {
    let shell = Shell::detect()
        .ok_or_else(|| anyhow::anyhow!("could not detect shell — set $SHELL or use --eval"))?;
    let eval_mode = args.eval || !std::io::stdout().is_terminal();

    let env_path = routing::clear_env_file(shell)?;

    let mut out = std::io::stdout().lock();
    if eval_mode {
        for line in routing::unset_lines(shell) {
            writeln!(out, "{}", line)?;
        }
    } else {
        writeln!(out, "🛡  Burnwall routing disabled.")?;
        writeln!(out, "   Env file emptied: {}", env_path.display())?;
        writeln!(out, "   (new shells will not have ANTHROPIC_BASE_URL / OPENAI_BASE_URL set)")?;
        writeln!(out)?;
        writeln!(out, "   To drop the env vars from *this* shell now:")?;
        match shell {
            Shell::Powershell => {
                writeln!(out, "     burnwall disable-routing --eval | Out-String | Invoke-Expression")?;
            }
            _ => {
                writeln!(out, "     eval \"$(burnwall disable-routing)\"")?;
            }
        }
        writeln!(out)?;
        writeln!(out, "   Re-enable with:  burnwall enable-routing")?;
    }
    Ok(())
}
