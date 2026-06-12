//! `burnwall cost-per-pr` — approximate cost of the current git branch/PR (v0.9.1).
//!
//! Buckets local cross-tool session-log spend into the active window of the
//! current branch (oldest commit on `base..HEAD`, else a fallback window).
//! Local + git metadata only — never reads prompt content. Approximate: spend
//! is time-bucketed, so a session spanning a branch switch is attributed by
//! timestamp.

use std::io::Write;
use std::path::PathBuf;

use anyhow::Context;
use chrono::{Duration, Local};
use clap::Args;

use crate::config;
use crate::logscrape::{self, UsageEntry};
use crate::observe::attribution::{self, Attribution, GitContext};
use crate::observe::cost_export;

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
    /// Export a per-repo + per-session spend CSV (across ALL repos in the
    /// window, not just the current branch) instead of the branch summary.
    #[arg(long)]
    pub export_csv: bool,
    /// Day window for `--export-csv` (default 30). Alias `-n`.
    #[arg(long, short = 'n', default_value_t = 30)]
    pub since: i64,
    /// Write the CSV to this path instead of stdout (with `--export-csv`).
    #[arg(long)]
    pub out: Option<PathBuf>,
}

pub fn run_cmd(args: CostPerPrArgs) -> anyhow::Result<()> {
    if args.export_csv {
        return run_export(&args);
    }

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

/// `--export-csv`: collect every tool's session-log spend in the `--since`
/// window, attribute each turn to its own repo + session (not by wall-clock
/// bucket), and emit a deterministic RFC 4180 CSV to stdout or `--out`.
fn run_export(args: &CostPerPrArgs) -> anyhow::Result<()> {
    let days = args.since.max(1);
    let cfg = config::load_or_default(&config::default_path()?).context("loading config")?;

    // Window filter in local time, matching `explore`.
    let cutoff = (Local::now() - Duration::days(days - 1)).date_naive();
    let entries: Vec<UsageEntry> = logscrape::collect_selected(cfg.scrape_tools())
        .into_iter()
        .filter(|e| e.timestamp.with_timezone(&Local).date_naive() >= cutoff)
        .collect();

    // The current repo root (if any) collapses its nested sub-dirs into one
    // repo bucket; other repos in the window keep their raw workspace path.
    let repo_roots: Vec<String> = attribution::git_context(&args.base, days)
        .repo_root
        .into_iter()
        .collect();

    let rows = cost_export::rows_from_entries(&entries, &repo_roots);

    match &args.out {
        Some(path) => {
            anyhow::ensure!(cost_export::is_writable_target(path), "--out path is empty");
            let csv = cost_export::to_csv_string(&rows);
            std::fs::write(path, csv)
                .with_context(|| format!("writing CSV to {}", path.display()))?;
            tracing::info!(rows = rows.len(), path = %path.display(), "cost CSV written");
            let mut out = std::io::stdout().lock();
            writeln!(out, "Wrote {} row(s) to {}", rows.len(), path.display())?;
        }
        None => {
            let mut out = std::io::stdout().lock();
            cost_export::write_csv(&mut out, &rows)?;
        }
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
