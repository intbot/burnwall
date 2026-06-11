//! `burnwall waste` — advisory report of cost-waste patterns found in local
//! AI session logs. Read-only, metadata only; never reads prompt content.

use std::io::Write;

use anyhow::Context;
use chrono::{Duration, Local};
use clap::Args;

use crate::config::{self, Config};
use crate::logscrape::{self, UsageEntry};
use crate::waste::{self, Finding};

#[derive(Args, Debug)]
pub struct WasteArgs {
    /// Days of local history to analyze.
    #[arg(long, default_value_t = 7)]
    pub days: i64,
    /// Emit JSON instead of the table view.
    #[arg(long)]
    pub json: bool,
}

pub fn run_cmd(args: WasteArgs) -> anyhow::Result<()> {
    let days = args.days.max(1);
    let cfg_path = config::default_path()?;
    let cfg = config::load_or_default(&cfg_path).context("loading config")?;

    let mut out = std::io::stdout().lock();
    if !cfg.waste.enabled {
        writeln!(
            out,
            "Waste insights are disabled (set `waste.enabled = true` to re-enable)."
        )?;
        return Ok(());
    }

    let entries = collect_recent(&cfg, days);
    let findings = waste::analyze(&entries);
    // Capped at actual spend — rules overlap, so the raw sum can exceed reality.
    let total = waste::capped_waste_usd(&findings, &entries);

    if args.json {
        write_json(&mut out, &findings, days, total).context("writing JSON")?;
    } else {
        write_table(&mut out, &findings, days, total).context("writing report")?;
    }
    Ok(())
}

/// Usage entries whose local date falls within the last `days` days
/// (inclusive of today). Honors the per-tool `[tools]` switches. Fail-open:
/// tools with no logs contribute nothing.
fn collect_recent(cfg: &Config, days: i64) -> Vec<UsageEntry> {
    let cutoff = (Local::now() - Duration::days(days - 1)).date_naive();
    logscrape::collect_selected(cfg.scrape_tools())
        .into_iter()
        .filter(|e| e.timestamp.with_timezone(&Local).date_naive() >= cutoff)
        .collect()
}

fn write_table(
    w: &mut impl Write,
    findings: &[Finding],
    days: i64,
    total: f64,
) -> std::io::Result<()> {
    writeln!(w, "💸 Waste insights (last {} day{})", days, plural(days))?;
    writeln!(w)?;

    if findings.is_empty() {
        writeln!(w, "   No waste patterns detected. Nice.")?;
        writeln!(w)?;
        writeln!(
            w,
            "   (Analyzes local AI session logs read-only — never your prompt content.)"
        )?;
        return Ok(());
    }

    writeln!(
        w,
        "   Estimated avoidable spend: up to ${:.2} over the window",
        total
    )?;
    writeln!(w)?;
    for f in findings {
        writeln!(
            w,
            "   [{}] {} — ${:.2}",
            f.severity.as_str(),
            f.title,
            f.observed_waste_usd
        )?;
        writeln!(w, "      {}", f.detail)?;
        writeln!(w)?;
    }
    Ok(())
}

fn write_json(
    w: &mut impl Write,
    findings: &[Finding],
    days: i64,
    total: f64,
) -> std::io::Result<()> {
    use serde_json::json;
    let value = json!({
        "window_days": days,
        "estimated_waste_usd": total,
        "findings": findings.iter().map(|f| json!({
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity.as_str(),
            "count": f.count,
            "observed_waste_usd": f.observed_waste_usd,
            "detail": f.detail,
        })).collect::<Vec<_>>(),
    });
    writeln!(w, "{}", serde_json::to_string_pretty(&value).unwrap())
}

fn plural(n: i64) -> &'static str {
    if n == 1 { "" } else { "s" }
}
