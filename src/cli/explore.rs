//! `burnwall explore` — read-only data explorer over local spend.
//!
//! Surfaces cost dimensions the `status` table doesn't: proxied spend by
//! provider/model over a window (from SQLite), plus cross-tool spend by
//! harness and by workspace (from the read-only log scrape). Pure reads —
//! no prompt content, no writes.

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::Arc;

use anyhow::Context;
use chrono::{Duration, Local};
use clap::Args;

use crate::config;
use crate::logscrape::{self, UsageEntry};
use crate::pricing;
use crate::storage::{ModelBreakdown, Storage};

#[derive(Args, Debug)]
pub struct ExploreArgs {
    /// Days of history to explore (default 30).
    #[arg(long, default_value_t = 30)]
    pub days: i64,
    /// Emit JSON instead of the table view.
    #[arg(long)]
    pub json: bool,
}

/// One `(label, cost, count)` aggregate row of a cost dimension.
struct DimRow {
    label: String,
    cost: f64,
    count: usize,
}

pub fn run_cmd(args: ExploreArgs) -> anyhow::Result<()> {
    let days = args.days.max(1);
    let storage = Arc::new(Storage::open_default().context("opening storage")?);
    let proxied = storage.breakdown_since_days(days)?;

    let cfg_path = config::default_path()?;
    let cfg = config::load_or_default(&cfg_path).context("loading config")?;

    // Cross-tool entries within the window (read-only log scrape), honoring
    // the per-tool `[tools]` switches.
    let cutoff = (Local::now() - Duration::days(days - 1)).date_naive();
    let entries: Vec<UsageEntry> = logscrape::collect_selected(cfg.scrape_tools())
        .into_iter()
        .filter(|e| e.timestamp.with_timezone(&Local).date_naive() >= cutoff)
        .collect();
    let by_harness = dimension(&entries, |e| e.tool.to_string());
    let by_workspace = dimension(&entries, |e| {
        e.workspace
            .clone()
            .unwrap_or_else(|| "(unknown)".to_string())
    });

    let mut out = std::io::stdout().lock();
    if args.json {
        write_json(&mut out, days, &proxied, &by_harness, &by_workspace).context("writing JSON")?;
    } else {
        write_table(&mut out, days, &proxied, &by_harness, &by_workspace)
            .context("writing report")?;
    }
    Ok(())
}

/// Aggregate entries into `(label, cost, count)` rows by a key function,
/// sorted by cost descending. Cost uses the pricing table (unknown → 0).
fn dimension<F: Fn(&UsageEntry) -> String>(entries: &[UsageEntry], key: F) -> Vec<DimRow> {
    let mut map: BTreeMap<String, (f64, usize)> = BTreeMap::new();
    for e in entries {
        let cost = pricing::calculate_cost(&e.model, &e.usage).unwrap_or(0.0);
        let slot = map.entry(key(e)).or_insert((0.0, 0));
        slot.0 += cost;
        slot.1 += 1;
    }
    let mut rows: Vec<DimRow> = map
        .into_iter()
        .map(|(label, (cost, count))| DimRow { label, cost, count })
        .collect();
    rows.sort_by(|a, b| {
        b.cost
            .partial_cmp(&a.cost)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    rows
}

fn write_table(
    w: &mut impl Write,
    days: i64,
    proxied: &[ModelBreakdown],
    by_harness: &[DimRow],
    by_workspace: &[DimRow],
) -> std::io::Result<()> {
    writeln!(w, "🔎 Spend explorer (last {} day{})", days, plural(days))?;
    writeln!(w)?;

    writeln!(w, "   Proxied — by provider / model")?;
    if proxied.is_empty() {
        writeln!(w, "   (no proxied requests in window)")?;
    } else {
        for row in proxied {
            let label = format!("{}/{}", row.provider, row.model);
            writeln!(
                w,
                "   {:<34}  ${:>8.2}  {:>6} req",
                truncate(&label, 34),
                row.cost,
                row.requests
            )?;
        }
    }
    writeln!(w)?;

    write_dim(w, "Cross-tool (log files) — by harness", by_harness)?;
    writeln!(w)?;
    write_dim(w, "Cross-tool (log files) — by workspace", by_workspace)?;
    Ok(())
}

fn write_dim(w: &mut impl Write, heading: &str, rows: &[DimRow]) -> std::io::Result<()> {
    writeln!(w, "   {}", heading)?;
    if rows.is_empty() {
        writeln!(w, "   (no log-file activity in window)")?;
        return Ok(());
    }
    for row in rows {
        writeln!(
            w,
            "   {:<34}  ${:>8.2}  {:>6} turns",
            truncate(&row.label, 34),
            row.cost,
            row.count
        )?;
    }
    Ok(())
}

fn write_json(
    w: &mut impl Write,
    days: i64,
    proxied: &[ModelBreakdown],
    by_harness: &[DimRow],
    by_workspace: &[DimRow],
) -> std::io::Result<()> {
    use serde_json::json;
    let dim = |rows: &[DimRow]| {
        rows.iter()
            .map(|r| {
                json!({
                    "label": r.label,
                    "cost_usd": r.cost,
                    "turns": r.count,
                })
            })
            .collect::<Vec<_>>()
    };
    let value = json!({
        "window_days": days,
        "proxied_by_model": proxied.iter().map(|r| json!({
            "provider": r.provider,
            "model": r.model,
            "cost_usd": r.cost,
            "requests": r.requests,
        })).collect::<Vec<_>>(),
        "by_harness": dim(by_harness),
        "by_workspace": dim(by_workspace),
    });
    writeln!(w, "{}", serde_json::to_string_pretty(&value).unwrap())
}

fn plural(n: i64) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(n.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}
