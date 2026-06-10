//! `burnwall config set/show/doctor` — read, update, and diagnose
//! `~/.burnwall/config.toml`.

use std::io::Write;
use std::path::Path;

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
    /// Diagnose the effective config: deprecated/unknown keys, out-of-range
    /// values, and any principle-relaxing toggles that are ON.
    Doctor,
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
        ConfigAction::Doctor => doctor(&path)?,
    }
    Ok(())
}

/// Known top-level config sections — anything else is flagged as unknown.
const KNOWN_SECTIONS: &[&str] = &[
    "proxy",
    "budget",
    "security",
    "loop_detection",
    "logging",
    "tools",
    "waste",
    "rules",
    "mcp",
    "resilience",
    "observability",
    "log_scrape",
];

/// Read-only diagnostic: prints the effective config and flags deprecated /
/// unknown keys, out-of-range values, and principle-relaxing toggles that are
/// ON. Exits non-zero (via `Err`) when an error-level problem is found.
fn doctor(path: &Path) -> anyhow::Result<()> {
    let cfg = config::load_or_default(path).context("loading config")?;
    let mut out = std::io::stdout().lock();

    writeln!(out, "🩺 Burnwall config doctor")?;
    writeln!(out)?;
    writeln!(out, "Config file: {}", path.display())?;
    if !path.exists() {
        writeln!(out, "  (no file yet — showing built-in defaults)")?;
    }
    writeln!(out)?;

    writeln!(out, "Effective configuration:")?;
    let toml_text = toml::to_string_pretty(&cfg).context("serializing config")?;
    for line in toml_text.lines() {
        writeln!(out, "  {}", line)?;
    }
    writeln!(out)?;

    // Per-project profile that would merge on top at `burnwall start`.
    if let Ok(cwd) = std::env::current_dir() {
        match config::project::discover(&cwd) {
            Some(p) => writeln!(
                out,
                "Project profile: {} (merges on top at `burnwall start`)",
                p.display()
            )?,
            None => writeln!(out, "Project profile: none discovered from cwd")?,
        }
    }
    writeln!(out)?;

    let mut warnings = 0usize;
    let mut errors = 0usize;

    // Deprecated + unknown top-level sections (raw-key inspection — serde
    // silently drops unknown keys on load, so we re-parse to surface them).
    if path.exists() {
        let raw = std::fs::read_to_string(path).context("reading config")?;
        if let Ok(table) = raw.parse::<toml::Table>() {
            for key in table.keys() {
                if key == "log_scrape" {
                    warnings += 1;
                    writeln!(
                        out,
                        "⚠️  [log_scrape] is deprecated — use [tools] (claude_code / codex) instead."
                    )?;
                } else if !KNOWN_SECTIONS.contains(&key.as_str()) {
                    warnings += 1;
                    writeln!(out, "⚠️  unknown section [{}] — ignored (typo?).", key)?;
                }
            }
        }
    }

    // Principle-relaxing toggles that are ON.
    if cfg.proxy.cache_injection {
        warnings += 1;
        writeln!(
            out,
            "⚠️  proxy.cache_injection is ON — Burnwall rewrites request bodies to add cache markers."
        )?;
    }
    if !cfg.security.enabled {
        warnings += 1;
        writeln!(
            out,
            "⚠️  security.enabled is OFF — request scanning is disabled; nothing is blocked."
        )?;
    }

    // Out-of-range values (error) and no-op combinations (informational).
    if cfg.budget.warn_percent > 100 {
        errors += 1;
        writeln!(
            out,
            "❌ budget.warn_percent = {} is out of range (0–100).",
            cfg.budget.warn_percent
        )?;
    }
    if !cfg.waste.enabled {
        writeln!(
            out,
            "ℹ️  waste.enabled is OFF — `burnwall waste` and the status teaser are suppressed."
        )?;
    }
    if !cfg.any_scrape_enabled() {
        writeln!(
            out,
            "ℹ️  all log scraping is OFF — cross-tool spend and waste insights have no data."
        )?;
    }

    // Per-shell routing matrix (L-H4): env-file state × rc-hook presence ×
    // proxy liveness — the exact table a stranded "connection refused" user
    // needs, which no single surface printed before. Names the precise
    // missing link per shell rather than a generic "run enable-routing".
    writeln!(out)?;
    writeln!(out, "Routing matrix (per shell):")?;
    let proxy_up = crate::cli::routing::proxy_port_alive(
        cfg.proxy.port,
        std::time::Duration::from_millis(120),
    );
    writeln!(
        out,
        "  proxy: {} (port {})",
        if proxy_up { "🟢 listening" } else { "⚪ not running" },
        cfg.proxy.port
    )?;
    for shell in crate::cli::init::Shell::ALL {
        use crate::cli::routing::{env_file_state, rc_hook_present, EnvFileState};
        let env = match env_file_state(shell) {
            Some(EnvFileState::Active) => "active",
            Some(EnvFileState::Paused) => "paused",
            Some(EnvFileState::Disabled) => "disabled",
            None => "absent",
        };
        let hook = rc_hook_present(shell);
        let verdict = match (env, hook, proxy_up) {
            ("active", true, true) => "🟢 routed".to_string(),
            ("active", true, false) => {
                "🟡 will route once the proxy starts (liveness-gated)".to_string()
            }
            // Diagnostic only — machine state, not config state, so it never
            // flips the doctor's error/warning summary.
            ("active", false, _) | ("paused", false, _) => format!(
                "⚠️  env file present but no shell hook — add it with `burnwall enable-routing` (run from {})",
                shell.label()
            ),
            ("paused", true, _) => "⏸  paused — `burnwall start` re-enables".to_string(),
            ("disabled", _, _) => "⏹  explicitly disabled".to_string(),
            _ => "—  not configured".to_string(),
        };
        writeln!(
            out,
            "  {:<11} env:{:<9} hook:{:<3}  {}",
            shell.label(),
            env,
            if hook { "yes" } else { "no" },
            verdict
        )?;
    }

    writeln!(out)?;
    if errors == 0 && warnings == 0 {
        writeln!(out, "✅ No problems found.")?;
    } else {
        writeln!(
            out,
            "Summary: {} error(s), {} warning(s).",
            errors, warnings
        )?;
    }

    if errors > 0 {
        anyhow::bail!("config doctor found {} error(s)", errors);
    }
    Ok(())
}
