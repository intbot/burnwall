//! `burnwall wire-check` — on-the-wire spend vs. a log-scrape estimate (v0.9).
//!
//! Burnwall computes cost from each provider's own `usage` block on the
//! response path and stores it; that is the authoritative on-the-wire figure.
//! A log-scraping estimate re-reads the same window from each tool's local
//! session logs. This command shows both, per model and in total, and the
//! drift between them — the overhead/inaccuracy a pure log reader can't see.
//! Framing is factual: drift can run either way; the two sources measure
//! different things (proxied traffic vs. what a tool chose to log).

use std::io::Write;

use anyhow::Context;
use chrono::{Duration, Local};
use clap::Args;

use crate::config;
use crate::logscrape::{self, UsageEntry};
use crate::observe::wire_vs_logs::{self, DriftReport, WireModel};
use crate::storage::Storage;

#[derive(Args, Debug)]
pub struct WireCheckArgs {
    /// Day window to compare (default 30). Alias `-n`.
    #[arg(long, short = 'n', default_value_t = 30)]
    pub days: i64,
    /// Emit JSON instead of the table view.
    #[arg(long)]
    pub json: bool,
}

pub fn run_cmd(args: WireCheckArgs) -> anyhow::Result<()> {
    let days = args.days.max(1);

    // Wire side: authoritative per-model spend from the proxy's request log.
    let storage = Storage::open_default().context("opening storage")?;
    let wire: Vec<WireModel> = storage
        .breakdown_since_days(days)?
        .into_iter()
        .map(|b| WireModel {
            model: b.model,
            cost_usd: b.cost,
            requests: b.requests.max(0) as u64,
        })
        .collect();

    // Logs side: the same window from local session logs (read-only scrape),
    // honoring the per-tool `[tools]` switches. Empty ⇒ degrade gracefully.
    let cfg = config::load_or_default(&config::default_path()?).context("loading config")?;
    let cutoff = (Local::now() - Duration::days(days - 1)).date_naive();
    let entries: Vec<UsageEntry> = logscrape::collect_selected(cfg.scrape_tools())
        .into_iter()
        .filter(|e| e.timestamp.with_timezone(&Local).date_naive() >= cutoff)
        .collect();
    let logs_unavailable = entries.is_empty();
    let logs = wire_vs_logs::logs_by_model(&entries);

    let report = wire_vs_logs::compute_drift(days, &wire, &logs, logs_unavailable);

    let mut out = std::io::stdout().lock();
    if args.json {
        write_json(&mut out, &report)?;
    } else {
        write_table(&mut out, &report)?;
    }
    Ok(())
}

fn write_table(w: &mut impl Write, r: &DriftReport) -> std::io::Result<()> {
    writeln!(
        w,
        "📐 Wire vs. logs — last {} day{}",
        r.days,
        if r.days == 1 { "" } else { "s" }
    )?;
    writeln!(
        w,
        "   Wire = cost Burnwall measured on proxied responses; Logs = a local"
    )?;
    writeln!(
        w,
        "   session-log estimate for the same window. Drift = logs − wire."
    )?;
    writeln!(w)?;

    if r.logs_unavailable {
        writeln!(
            w,
            "   (no local session-log activity in this window — showing wire only)"
        )?;
        writeln!(w)?;
    }

    if r.by_model.is_empty() {
        writeln!(w, "   (no spend on either side in this window)")?;
        return Ok(());
    }

    writeln!(
        w,
        "   {:<28} {:>11} {:>11} {:>11} {:>8}",
        "model", "wire $", "logs $", "drift $", "drift %"
    )?;
    for m in &r.by_model {
        writeln!(
            w,
            "   {:<28} {:>11.4} {:>11.4} {:>+11.4} {:>8}",
            truncate(&m.model, 28),
            m.wire_cost_usd,
            m.logs_cost_usd,
            m.drift_usd(),
            fmt_pct(m.drift_pct()),
        )?;
    }
    writeln!(w)?;
    writeln!(
        w,
        "   {:<28} {:>11.4} {:>11.4} {:>+11.4} {:>8}",
        "TOTAL",
        r.total_wire_usd,
        r.total_logs_usd,
        r.total_drift_usd(),
        fmt_pct(r.total_drift_pct()),
    )?;
    Ok(())
}

fn write_json(w: &mut impl Write, r: &DriftReport) -> std::io::Result<()> {
    use serde_json::json;
    let value = json!({
        "days": r.days,
        "logs_unavailable": r.logs_unavailable,
        "total_wire_usd": r.total_wire_usd,
        "total_logs_usd": r.total_logs_usd,
        "total_drift_usd": r.total_drift_usd(),
        "total_drift_pct": r.total_drift_pct(),
        "by_model": r.by_model.iter().map(|m| json!({
            "model": m.model,
            "wire_cost_usd": m.wire_cost_usd,
            "logs_cost_usd": m.logs_cost_usd,
            "wire_requests": m.wire_requests,
            "logs_turns": m.logs_turns,
            "drift_usd": m.drift_usd(),
            "drift_pct": m.drift_pct(),
        })).collect::<Vec<_>>(),
    });
    writeln!(w, "{}", serde_json::to_string_pretty(&value).unwrap())
}

fn fmt_pct(pct: Option<f64>) -> String {
    match pct {
        Some(p) => format!("{p:+.1}%"),
        None => "n/a".to_string(),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let head: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{head}…")
    }
}
