//! `burnwall report` — a shareable weekly/monthly summary (v0.8).
//!
//! Renders the same [`Digest`] source as `digest`/`aibom`, but framed as a
//! period report you can save or paste: spend, turns, blocks, top models, and
//! security activity. `--format text|json|csv`. Metadata only.

use std::io::Write;

use anyhow::Context;
use clap::Args;

use crate::observe::digest::Digest;
use crate::storage::Storage;

#[derive(Args, Debug)]
pub struct ReportArgs {
    /// Window length in days (default 30 — a monthly report).
    #[arg(long, default_value_t = 30)]
    pub days: i64,
    /// Output format: `text`, `json`, or `csv`.
    #[arg(long, default_value = "text")]
    pub format: String,
}

pub fn run_cmd(args: ReportArgs) -> anyhow::Result<()> {
    let storage = Storage::open_default().context("opening storage")?;
    let digest = Digest::build(&storage, args.days)?;
    let mut out = std::io::stdout().lock();
    match args.format.as_str() {
        "text" => write_text(&mut out, &digest)?,
        "json" => write_json(&mut out, &digest)?,
        "csv" => write_csv(&mut out, &digest)?,
        other => anyhow::bail!("unknown format '{other}': use text, json, or csv"),
    }
    Ok(())
}

fn write_text(w: &mut impl Write, d: &Digest) -> std::io::Result<()> {
    writeln!(
        w,
        "📋 Burnwall report — last {} day{}",
        d.days,
        if d.days == 1 { "" } else { "s" }
    )?;
    writeln!(w)?;
    writeln!(w, "   Spend:    ${:.2}", d.total_cost_usd)?;
    writeln!(
        w,
        "   Activity: {} request{} forwarded/blocked, {} blocked",
        d.turns,
        if d.turns == 1 { "" } else { "s" },
        d.blocked
    )?;
    writeln!(w, "   MCP:      {} tool call(s)", d.mcp_tool_calls)?;
    writeln!(w)?;

    writeln!(w, "   Top models by cost:")?;
    if d.models.is_empty() {
        writeln!(w, "     (none)")?;
    } else {
        for m in &d.models {
            writeln!(
                w,
                "     {:<32}  {:>5} req   ${:.2}",
                format!("{}/{}", m.provider, m.model),
                m.requests,
                m.cost_usd
            )?;
        }
    }
    writeln!(w)?;

    let total_blocks: u64 = d.security_by_type.iter().map(|s| s.count).sum();
    writeln!(w, "   Security blocks: {total_blocks}")?;
    for s in &d.security_by_type {
        writeln!(w, "     {}: {}", s.event_type, s.count)?;
    }
    Ok(())
}

fn write_json(w: &mut impl Write, d: &Digest) -> std::io::Result<()> {
    use serde_json::json;
    let value = json!({
        "days": d.days,
        "total_cost_usd": d.total_cost_usd,
        "turns": d.turns,
        "blocked": d.blocked,
        "mcp_tool_calls": d.mcp_tool_calls,
        "models": d.models.iter().map(|m| json!({
            "provider": m.provider,
            "model": m.model,
            "requests": m.requests,
            "cost_usd": m.cost_usd,
        })).collect::<Vec<_>>(),
        "security_by_type": d.security_by_type.iter().map(|s| json!({
            "event_type": s.event_type,
            "count": s.count,
        })).collect::<Vec<_>>(),
    });
    writeln!(w, "{}", serde_json::to_string_pretty(&value).unwrap())
}

fn write_csv(w: &mut impl Write, d: &Digest) -> std::io::Result<()> {
    writeln!(w, "provider,model,requests,cost_usd")?;
    for m in &d.models {
        writeln!(
            w,
            "{},{},{},{:.6}",
            m.provider, m.model, m.requests, m.cost_usd
        )?;
    }
    Ok(())
}
