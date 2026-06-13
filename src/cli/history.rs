//! `burnwall history` — per-day totals over the last N days.

use std::io::Write;
use std::sync::Arc;

use anyhow::Context;
use chrono::{Datelike, Local, NaiveDate};
use clap::Args;

use crate::config;
use crate::storage::Storage;
use crate::term::{Card, Color, Styler, fill_bar, gauge_hue, render_cards};

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
    // A non-positive --days would produce an invalid SQLite date modifier
    // and a silently empty table — clamp to at least one day (today).
    let days = args.days.max(1);
    let storage = Arc::new(Storage::open_default().context("opening storage")?);
    let totals = storage.daily_totals(days)?;

    let cfg_path = config::default_path()?;
    let cfg = config::load_or_default(&cfg_path).context("loading config")?;
    let burndown = Burndown::compute(&storage, cfg.budget.monthly)?;

    let mut out = std::io::stdout().lock();
    if args.json {
        let value = serde_json::json!({
            "days": days,
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

    let sty = Styler::stdout();
    writeln!(
        out,
        "🔥 {} · History · Last {} day{}",
        sty.bold("Burnwall"),
        days,
        if days == 1 { "" } else { "s" }
    )?;
    writeln!(out)?;
    if totals.is_empty() {
        writeln!(out, "  (no data)")?;
        // Still show the burndown — month-to-date spend may predate the window.
        write_burndown(&mut out, &burndown, &sty)?;
        return Ok(());
    }

    // Window totals, computed up front so they can headline as tiles.
    let total_cost: f64 = totals.iter().map(|t| t.total_cost).sum();
    let total_requests: i64 = totals.iter().map(|t| t.total_requests).sum();
    let total_blocked: i64 = totals.iter().map(|t| t.total_blocked).sum();
    let avg_hit_rate = totals.iter().map(|t| t.cache_hit_rate).sum::<f64>() / totals.len() as f64;
    let avg_hit_pct = avg_hit_rate * 100.0;

    let cards = [
        Card::new("Spent", &format!("${:.2}", total_cost), &format!("over {days}d")),
        Card::new("Requests", &total_requests.to_string(), "total"),
        Card::new("Cache", &format!("{avg_hit_pct:.0}%"), &fill_bar(avg_hit_pct, 8))
            .with_value_color(Color::Green)
            .with_sub_color(Color::Green),
        Card::new("Blocked", &total_blocked.to_string(), "events")
            .with_value_color(if total_blocked > 0 { Color::Red } else { Color::Green }),
    ];
    writeln!(out, "{}", render_cards(&cards, 11, 2, &sty))?;
    writeln!(out)?;

    writeln!(
        out,
        "  {:<14}{:>10}  {:>10}  {:>8}  {:>8}",
        "Date", "Cost", "Requests", "Cache", "Blocked"
    )?;
    writeln!(out, "  {}", "─".repeat(54))?;
    for row in &totals {
        writeln!(
            out,
            "  {:<14}{:>10}  {:>10}  {:>7.0}%  {:>8}",
            row.date,
            format!("${:.2}", row.total_cost),
            row.total_requests,
            row.cache_hit_rate * 100.0,
            row.total_blocked,
        )?;
    }
    writeln!(out, "  {}", "─".repeat(54))?;
    writeln!(
        out,
        "  {:<14}{:>10}  {:>10}  avg {:>3.0}%  {:>8}",
        "Total",
        format!("${:.2}", total_cost),
        total_requests,
        avg_hit_pct,
        total_blocked,
    )?;
    write_burndown(&mut out, &burndown, &sty)?;
    Ok(())
}

fn write_burndown(w: &mut impl Write, b: &Burndown, sty: &Styler) -> std::io::Result<()> {
    writeln!(w)?;
    writeln!(w, "  {} ({})", sty.bold("Monthly burndown"), b.month)?;
    writeln!(
        w,
        "  {:<15}${:.2}  (day {} of {})",
        "Spent so far", b.spent_usd, b.day_of_month, b.days_in_month
    )?;
    if b.monthly_budget_usd > 0.0 {
        let pct = b.spent_usd / b.monthly_budget_usd * 100.0;
        writeln!(
            w,
            "  {:<15}${:.2}   {} {:.0}%",
            "Monthly budget",
            b.monthly_budget_usd,
            sty.paint(&fill_bar(pct, 8), gauge_hue(pct)),
            pct
        )?;
        let verdict = if b.projected_usd > b.monthly_budget_usd {
            sty.red("over budget")
        } else {
            sty.green("within budget")
        };
        writeln!(
            w,
            "  {:<15}${:.2}   [{}]",
            "Projected EOM", b.projected_usd, verdict
        )?;
    } else {
        writeln!(
            w,
            "  {:<15}${:.2}   (no monthly limit configured)",
            "Projected EOM", b.projected_usd
        )?;
    }
    Ok(())
}
