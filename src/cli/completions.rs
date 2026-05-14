//! `burnwall completions <shell>` — generate shell completion scripts.
//!
//! Pipes a clap-derived completion script for the requested shell to
//! stdout. Standard install pattern for each shell:
//!
//!   bash:        burnwall completions bash > /etc/bash_completion.d/burnwall
//!   zsh:         burnwall completions zsh  > "${fpath[1]}/_burnwall"
//!   fish:        burnwall completions fish > ~/.config/fish/completions/burnwall.fish
//!   powershell:  burnwall completions powershell > $PROFILE.CurrentUserAllHosts (then dot-source)
//!   elvish:      burnwall completions elvish > ~/.config/elvish/lib/burnwall.elv

use clap::{Args, CommandFactory};
use clap_complete::{generate, Shell};

use crate::cli::Cli;

#[derive(Args, Debug)]
pub struct CompletionsArgs {
    /// Shell to generate completions for.
    #[arg(value_enum)]
    pub shell: Shell,
}

pub fn run_cmd(args: CompletionsArgs) -> anyhow::Result<()> {
    let mut cmd = Cli::command();
    let bin_name = cmd.get_name().to_string();
    generate(args.shell, &mut cmd, bin_name, &mut std::io::stdout());
    Ok(())
}
