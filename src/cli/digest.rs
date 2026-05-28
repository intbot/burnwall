//! `burnwall digest` — a window-scoped Agent Bill of Materials (v0.7).
//! Models run + cost, MCP servers/tools, tool-call count, security checks
//! fired, turns. Metadata only — assembled from rows that never hold prompt
//! content. See [`crate::observe::digest`].

use std::io::Write;

use anyhow::Context;
use clap::Args;

use crate::observe::digest::Digest;
use crate::storage::Storage;

#[derive(Args, Debug)]
pub struct DigestArgs {
    /// How many days back to include (default 7).
    #[arg(long, default_value_t = 7)]
    pub days: i64,
    /// Emit JSON instead of the table view.
    #[arg(long)]
    pub json: bool,
}

pub fn run_cmd(args: DigestArgs) -> anyhow::Result<()> {
    let storage = Storage::open_default().context("opening storage")?;
    let digest = Digest::build(&storage, args.days)?;

    let mut out = std::io::stdout().lock();
    if args.json {
        write_json(&mut out, &digest)?;
    } else {
        write_table(&mut out, &digest)?;
    }
    Ok(())
}

fn write_table(w: &mut impl Write, d: &Digest) -> std::io::Result<()> {
    writeln!(
        w,
        "🧾 Agent Bill of Materials (last {} day{})",
        d.days,
        if d.days == 1 { "" } else { "s" }
    )?;
    writeln!(w)?;
    writeln!(
        w,
        "   Turns:      {} request{} ({} blocked)",
        d.turns,
        if d.turns == 1 { "" } else { "s" },
        d.blocked
    )?;
    writeln!(w, "   Total cost: ${:.2}", d.total_cost_usd)?;
    writeln!(w)?;

    writeln!(w, "   Models:")?;
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

    writeln!(
        w,
        "   MCP tool calls: {} ({} distinct tool{})",
        d.mcp_tool_calls,
        d.distinct_mcp_tools.len(),
        if d.distinct_mcp_tools.len() == 1 {
            ""
        } else {
            "s"
        }
    )?;
    if !d.mcp_tools.is_empty() {
        writeln!(w, "   MCP tools advertised:")?;
        for t in &d.mcp_tools {
            writeln!(w, "     {}/{} ({})", t.server, t.tool, t.trust_state)?;
        }
    }
    writeln!(w)?;

    let total_blocks: u64 = d.security_by_type.iter().map(|s| s.count).sum();
    writeln!(w, "   Security checks fired: {}", total_blocks)?;
    for s in &d.security_by_type {
        writeln!(w, "     {}: {}", s.event_type, s.count)?;
    }
    if !d.distinct_targets.is_empty() {
        writeln!(
            w,
            "   Distinct targets touched: {}",
            d.distinct_targets.len()
        )?;
    }
    Ok(())
}

fn write_json(w: &mut impl Write, d: &Digest) -> std::io::Result<()> {
    use serde_json::json;
    let value = json!({
        "days": d.days,
        "turns": d.turns,
        "blocked": d.blocked,
        "total_cost_usd": d.total_cost_usd,
        "models": d.models.iter().map(|m| json!({
            "provider": m.provider,
            "model": m.model,
            "requests": m.requests,
            "cost_usd": m.cost_usd,
        })).collect::<Vec<_>>(),
        "mcp_tool_calls": d.mcp_tool_calls,
        "distinct_mcp_tools": d.distinct_mcp_tools,
        "mcp_tools": d.mcp_tools.iter().map(|t| json!({
            "server": t.server,
            "tool": t.tool,
            "trust_state": t.trust_state,
        })).collect::<Vec<_>>(),
        "security_by_type": d.security_by_type.iter().map(|s| json!({
            "event_type": s.event_type,
            "count": s.count,
        })).collect::<Vec<_>>(),
        "distinct_targets": d.distinct_targets,
    });
    writeln!(w, "{}", serde_json::to_string_pretty(&value).unwrap())?;
    Ok(())
}
