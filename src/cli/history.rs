//! `burnwall history` — per-day totals over the last N days.

use std::io::Write;
use std::sync::Arc;

use anyhow::Context;
use clap::Args;

use crate::storage::Storage;

#[derive(Args, Debug)]
pub struct HistoryArgs {
    /// Number of days back to include (default 7).
    #[arg(long, default_value_t = 7)]
    pub days: i64,
    /// Emit JSON instead of the table view.
    #[arg(long)]
    pub json: bool,
}

pub fn run_cmd(args: HistoryArgs) -> anyhow::Result<()> {
    let storage = Arc::new(Storage::open_default().context("opening storage")?);
    let totals = storage.daily_totals(args.days)?;

    let mut out = std::io::stdout().lock();
    if args.json {
        let value = serde_json::json!({
            "days": args.days,
            "rows": totals.iter().map(|t| serde_json::json!({
                "date": t.date,
                "total_cost_usd": t.total_cost,
                "total_requests": t.total_requests,
                "total_blocked": t.total_blocked,
                "cache_hit_rate": t.cache_hit_rate,
            })).collect::<Vec<_>>(),
        });
        writeln!(out, "{}", serde_json::to_string_pretty(&value).unwrap())?;
        return Ok(());
    }

    writeln!(
        out,
        "📅 Last {} day{}",
        args.days,
        if args.days == 1 { "" } else { "s" }
    )?;
    if totals.is_empty() {
        writeln!(out, "   (no data)")?;
        return Ok(());
    }

    writeln!(
        out,
        "   {:<14}{:>10}  {:>10}  {:>8}  {:>8}",
        "Date", "Cost", "Requests", "Cache", "Blocked"
    )?;
    writeln!(out, "   {}", "─".repeat(54))?;
    let mut total_cost = 0.0;
    let mut total_requests = 0i64;
    let mut total_blocked = 0i64;
    let mut sum_hit_rate = 0.0;
    for row in &totals {
        writeln!(
            out,
            "   {:<14}{:>10}  {:>10}  {:>7.0}%  {:>8}",
            row.date,
            format!("${:.2}", row.total_cost),
            row.total_requests,
            row.cache_hit_rate * 100.0,
            row.total_blocked,
        )?;
        total_cost += row.total_cost;
        total_requests += row.total_requests;
        total_blocked += row.total_blocked;
        sum_hit_rate += row.cache_hit_rate;
    }
    writeln!(out, "   {}", "─".repeat(54))?;
    let avg_hit_rate = if totals.is_empty() {
        0.0
    } else {
        sum_hit_rate / totals.len() as f64
    };
    writeln!(
        out,
        "   {:<14}{:>10}  {:>10}  avg {:>3.0}%  {:>8}",
        "Total",
        format!("${:.2}", total_cost),
        total_requests,
        avg_hit_rate * 100.0,
        total_blocked,
    )?;
    if !totals.is_empty() {
        let daily_avg = total_cost / totals.len() as f64;
        writeln!(out)?;
        writeln!(
            out,
            "   Estimated monthly (at this rate): ${:.2}",
            daily_avg * 30.0
        )?;
    }
    Ok(())
}
