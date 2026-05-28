//! `burnwall cost-per-pr` — approximate cost of the current git branch/PR (v0.9.1).
//!
//! Buckets local cross-tool session-log spend into the active window of the
//! current branch (oldest commit on `base..HEAD`, else a fallback window).
//! Local + git metadata only — never reads prompt content. Approximate: spend
//! is time-bucketed, so a session spanning a branch switch is attributed by
//! timestamp.

use std::io::Write;

use anyhow::Context;
use clap::Args;

use crate::config;
use crate::logscrape;
use crate::observe::attribution::{self, Attribution, GitContext};

#[derive(Args, Debug)]
pub struct CostPerPrArgs {
    /// Base branch the current branch diverged from (default `main`).
    #[arg(long, default_value = "main")]
    pub base: String,
    /// Fallback window in days when branch commit times aren't available.
    #[arg(long, default_value_t = 30)]
    pub days: i64,
    /// Emit JSON instead of the table view.
    #[arg(long)]
    pub json: bool,
}

pub fn run_cmd(args: CostPerPrArgs) -> anyhow::Result<()> {
    let cfg = config::load_or_default(&config::default_path()?).context("loading config")?;
    let entries = logscrape::collect_selected(cfg.scrape_tools());

    let ctx = attribution::git_context(&args.base, args.days);
    let attr = attribution::attribute(&entries, ctx.repo_root.as_deref(), ctx.since);

    let mut out = std::io::stdout().lock();
    if args.json {
        write_json(&mut out, &args.base, &ctx, &attr)?;
    } else {
        write_table(&mut out, &args.base, &ctx, &attr)?;
    }
    Ok(())
}

fn write_table(
    w: &mut impl Write,
    base: &str,
    ctx: &GitContext,
    attr: &Attribution,
) -> std::io::Result<()> {
    let branch = ctx.branch.as_deref().unwrap_or("(not a git repo)");
    writeln!(w, "💸 Cost of branch '{branch}' (vs {base})")?;
    if let Some(since) = ctx.since {
        writeln!(
            w,
            "   Window: since {}{}",
            since.format("%Y-%m-%d %H:%M UTC"),
            if ctx.approximate {
                "  (approximate)"
            } else {
                ""
            }
        )?;
    }
    writeln!(w)?;
    writeln!(
        w,
        "   Total: ${:.2}  across {} turn{}",
        attr.total_cost_usd,
        attr.turns,
        if attr.turns == 1 { "" } else { "s" }
    )?;
    if attr.by_model.is_empty() {
        writeln!(
            w,
            "   (no local session-log spend attributed to this branch)"
        )?;
    } else {
        writeln!(w)?;
        for m in &attr.by_model {
            writeln!(
                w,
                "   {:<28}  ${:>8.2}  {:>5} turns",
                format!("{}/{}", m.tool, m.model),
                m.cost_usd,
                m.turns
            )?;
        }
    }
    writeln!(w)?;
    writeln!(
        w,
        "   Note: approximate — spend is attributed by timestamp from local tool logs."
    )?;
    Ok(())
}

fn write_json(
    w: &mut impl Write,
    base: &str,
    ctx: &GitContext,
    attr: &Attribution,
) -> std::io::Result<()> {
    use serde_json::json;
    let value = json!({
        "branch": ctx.branch,
        "base": base,
        "since": ctx.since.map(|s| s.to_rfc3339()),
        "approximate": ctx.approximate,
        "total_cost_usd": attr.total_cost_usd,
        "turns": attr.turns,
        "by_model": attr.by_model.iter().map(|m| json!({
            "tool": m.tool,
            "model": m.model,
            "cost_usd": m.cost_usd,
            "turns": m.turns,
        })).collect::<Vec<_>>(),
    });
    writeln!(w, "{}", serde_json::to_string_pretty(&value).unwrap())
}
