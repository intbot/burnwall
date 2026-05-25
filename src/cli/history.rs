//! `burnwall history` — per-day totals over the last N days.

use std::io::Write;
use std::sync::Arc;

use anyhow::Context;
use chrono::{Datelike, Local, NaiveDate};
use clap::Args;

use crate::config;
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

/// Month-to-date burndown against the configured monthly budget.
struct Burndown {
    month: String,
    day_of_month: u32,
    days_in_month: u32,
    spent_usd: f64,
    /// Linear end-of-month projection from the current pace.
    projected_usd: f64,
    /// Configured monthly limit; `0.0` means unlimited (no pacing line).
    monthly_budget_usd: f64,
}

impl Burndown {
    fn compute(storage: &Storage, monthly_budget_usd: f64) -> anyhow::Result<Self> {
        let today = Local::now().date_naive();
        let month = today.format("%Y-%m").to_string();
        let day_of_month = today.day();
        let days_in_month = days_in_month(today.year(), today.month());
        let spent_usd = storage.cost_for_month(&month)?;
        let projected_usd = if day_of_month > 0 {
            spent_usd / day_of_month as f64 * days_in_month as f64
        } else {
            spent_usd
        };
        Ok(Self {
            month,
            day_of_month,
            days_in_month,
            spent_usd,
            projected_usd,
            monthly_budget_usd,
        })
    }
}

/// Number of days in a given (year, month), via the first-of-next-month trick.
fn days_in_month(year: i32, month: u32) -> u32 {
    let (ny, nm) = if month == 12 {
        (year + 1, 1)
    } else {
        (year, month + 1)
    };
    let first_next = NaiveDate::from_ymd_opt(ny, nm, 1).unwrap();
    let first_this = NaiveDate::from_ymd_opt(year, month, 1).unwrap();
    (first_next - first_this).num_days() as u32
}

pub fn run_cmd(args: HistoryArgs) -> anyhow::Result<()> {
    let storage = Arc::new(Storage::open_default().context("opening storage")?);
    let totals = storage.daily_totals(args.days)?;

    let cfg_path = config::default_path()?;
    let cfg = config::load_or_default(&cfg_path).context("loading config")?;
    let burndown = Burndown::compute(&storage, cfg.budget.monthly)?;

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
            "burndown": {
                "month": burndown.month,
                "day_of_month": burndown.day_of_month,
                "days_in_month": burndown.days_in_month,
                "spent_usd": burndown.spent_usd,
                "projected_eom_usd": burndown.projected_usd,
                "monthly_budget_usd": burndown.monthly_budget_usd,
            },
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
        // Still show the burndown — month-to-date spend may predate the window.
        write_burndown(&mut out, &burndown)?;
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
    write_burndown(&mut out, &burndown)?;
    Ok(())
}

fn write_burndown(w: &mut impl Write, b: &Burndown) -> std::io::Result<()> {
    writeln!(w)?;
    writeln!(w, "📉 Monthly burndown ({})", b.month)?;
    writeln!(
        w,
        "   Spent so far:   ${:.2}  (day {} of {})",
        b.spent_usd, b.day_of_month, b.days_in_month
    )?;
    if b.monthly_budget_usd > 0.0 {
        let ideal = b.monthly_budget_usd * b.day_of_month as f64 / b.days_in_month as f64;
        writeln!(w, "   Monthly budget: ${:.2}", b.monthly_budget_usd)?;
        writeln!(
            w,
            "   Ideal pace:     ${:.2}  ({}/{} of budget)",
            ideal, b.day_of_month, b.days_in_month
        )?;
        let verdict = if b.projected_usd > b.monthly_budget_usd {
            "over budget"
        } else {
            "within budget"
        };
        writeln!(
            w,
            "   Projected EOM:  ${:.2}  [{}]",
            b.projected_usd, verdict
        )?;
    } else {
        writeln!(
            w,
            "   Projected EOM:  ${:.2}  (no monthly limit configured)",
            b.projected_usd
        )?;
    }
    Ok(())
}
