//! `burnwall metrics` — per-model latency percentiles, error rate, and
//! throughput (v0.7). Computed locally from the request log; metadata-only,
//! no prompt content. The local answer to hosted LLM observability.

use std::io::Write;

use anyhow::Context;
use clap::Args;

use crate::observe::metrics::{ModelMetrics, aggregate};
use crate::storage::Storage;

#[derive(Args, Debug)]
pub struct MetricsArgs {
    /// How many days back to include (default 7).
    #[arg(long, default_value_t = 7)]
    pub days: i64,
    /// Emit JSON instead of the table view.
    #[arg(long)]
    pub json: bool,
}

pub fn run_cmd(args: MetricsArgs) -> anyhow::Result<()> {
    let days = args.days.max(1);
    let storage = Storage::open_default().context("opening storage")?;
    let samples = storage.latency_samples_since_days(days)?;
    let metrics = aggregate(samples, days);

    let mut out = std::io::stdout().lock();
    if args.json {
        write_json(&mut out, days, &metrics)?;
    } else {
        write_table(&mut out, days, &metrics)?;
    }
    Ok(())
}

fn write_table(w: &mut impl Write, days: i64, metrics: &[ModelMetrics]) -> std::io::Result<()> {
    writeln!(
        w,
        "📈 Latency & reliability (last {} day{})",
        days,
        plural(days)
    )?;
    writeln!(w)?;
    if metrics.is_empty() {
        writeln!(w, "   (no forwarded requests in this window)")?;
        writeln!(w)?;
        writeln!(
            w,
            "   Metrics come from proxied traffic — start the proxy and route a request first."
        )?;
        return Ok(());
    }
    writeln!(
        w,
        "   {:<30}  {:>6}  {:>6}  {:>8}  {:>8}  {:>7}  {:>8}",
        "Provider / Model", "Reqs", "Errs", "p50", "p95", "Err%", "Req/day"
    )?;
    writeln!(w, "   {}", "─".repeat(86))?;
    for m in metrics {
        let label = format!("{}/{}", m.provider, m.model);
        writeln!(
            w,
            "   {:<30}  {:>6}  {:>6}  {:>6}ms  {:>6}ms  {:>6.1}%  {:>8.1}",
            truncate(&label, 30),
            m.requests,
            m.errors,
            m.p50_ms,
            m.p95_ms,
            m.error_rate * 100.0,
            m.throughput_per_day,
        )?;
    }
    Ok(())
}

fn write_json(w: &mut impl Write, days: i64, metrics: &[ModelMetrics]) -> std::io::Result<()> {
    use serde_json::json;
    let value = json!({
        "days": days,
        "models": metrics.iter().map(|m| json!({
            "provider": m.provider,
            "model": m.model,
            "requests": m.requests,
            "errors": m.errors,
            "error_rate": m.error_rate,
            "p50_ms": m.p50_ms,
            "p95_ms": m.p95_ms,
            "throughput_per_day": m.throughput_per_day,
        })).collect::<Vec<_>>(),
    });
    writeln!(w, "{}", serde_json::to_string_pretty(&value).unwrap())?;
    Ok(())
}

fn plural(n: i64) -> &'static str {
    if n == 1 { "" } else { "s" }
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
