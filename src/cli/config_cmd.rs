//! `burnwall config set/show` — read and update `~/.burnwall/config.toml`.

use std::io::Write;

use anyhow::Context;
use clap::{Args, Subcommand};

use crate::config;

#[derive(Args, Debug)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub action: ConfigAction,
}

#[derive(Subcommand, Debug)]
pub enum ConfigAction {
    /// Print the current configuration. TOML by default, `--json` for JSON.
    Show {
        /// Emit JSON instead of TOML.
        #[arg(long)]
        json: bool,
    },
    /// Set a configuration value: `set <key> <value>` (e.g.
    /// `set budget.daily 20`).
    Set {
        /// Dotted key, e.g. `budget.daily` or `security.deny_paths`.
        key: String,
        /// Value to assign. Comma-separated for list keys.
        value: String,
    },
}

pub fn run_cmd(args: ConfigArgs) -> anyhow::Result<()> {
    let path = config::default_path()?;
    match args.action {
        ConfigAction::Show { json } => {
            let cfg = config::load_or_default(&path).context("loading config")?;
            let mut out = std::io::stdout().lock();
            if json {
                let text =
                    serde_json::to_string_pretty(&cfg).context("serializing config as JSON")?;
                writeln!(out, "{}", text)?;
            } else {
                let toml_text =
                    toml::to_string_pretty(&cfg).context("serializing config as TOML")?;
                writeln!(out, "{}", toml_text)?;
            }
        }
        ConfigAction::Set { key, value } => {
            let mut cfg = config::load_or_default(&path).context("loading config")?;
            config::set_dotted_key(&mut cfg, &key, &value).context("applying change")?;
            config::save(&path, &cfg).context("writing config")?;
            println!("✅ {} = {}", key, value);
        }
    }
    Ok(())
}
