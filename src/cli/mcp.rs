//! `burnwall mcp` — manage MCP tool approvals and export the MCP audit log.
//!
//! - `list` — every `(server, tool)` seen in a `tools/list`, with its approval
//!   state (`pending` / `approved`).
//! - `approve <server> [tool]` — approve one tool, or every tool of a server.
//!   In enforce mode (`mcp.require_approval`) a `tools/call` is held with 403
//!   until its tool is approved.
//! - `revoke <server> [tool]` — return a tool (or a whole server) to `pending`.
//! - `export [--days N] [--format json|csv]` — portable record of MCP
//!   tool-call activity + MCP security events over a window. Read-only.

use std::io::Write;

use anyhow::Context;
use clap::{Args, Subcommand, ValueEnum};

use crate::storage::Storage;

#[derive(Args, Debug)]
pub struct McpArgs {
    #[command(subcommand)]
    pub action: McpAction,
}

#[derive(Subcommand, Debug)]
pub enum McpAction {
    /// List MCP tools seen across servers and their approval state.
    List {
        /// Emit JSON instead of the table view.
        #[arg(long)]
        json: bool,
    },
    /// Approve a tool, or every tool of a server when <tool> is omitted.
    Approve {
        /// Server name (`default` for a single-upstream `mcp-watch`).
        server: String,
        /// Tool name. Omit to approve all of the server's current tools.
        tool: Option<String>,
    },
    /// Revoke approval (back to pending) for a tool or a whole server.
    Revoke {
        server: String,
        tool: Option<String>,
    },
    /// Export the MCP audit log (tool calls + MCP security events).
    Export {
        /// How many days back to include (default 7).
        #[arg(long, default_value_t = 7)]
        days: i64,
        /// Output format.
        #[arg(long, value_enum, default_value_t = ExportFormat::Json)]
        format: ExportFormat,
    },
}

#[derive(Clone, Debug, ValueEnum)]
pub enum ExportFormat {
    Json,
    Csv,
}

pub fn run_cmd(args: McpArgs) -> anyhow::Result<()> {
    match args.action {
        McpAction::List { json } => list(json),
        McpAction::Approve { server, tool } => approve(&server, tool.as_deref()),
        McpAction::Revoke { server, tool } => revoke(&server, tool.as_deref()),
        McpAction::Export { days, format } => export(days, format),
    }
}

// ── list ────────────────────────────────────────────────────────────────────

fn list(json: bool) -> anyhow::Result<()> {
    let storage = Storage::open_default().context("opening storage")?;
    let rows = storage.mcp_tools_all()?;
    let mut out = std::io::stdout().lock();

    if json {
        let value = serde_json::json!({
            "count": rows.len(),
            "tools": rows.iter().map(|r| serde_json::json!({
                "server": r.server,
                "tool": r.tool_name,
                "trust": r.trust_state,
                "last_seen": r.last_seen.to_rfc3339(),
            })).collect::<Vec<_>>(),
        });
        writeln!(out, "{}", serde_json::to_string_pretty(&value)?)?;
        return Ok(());
    }

    writeln!(out, "🔌 MCP tools seen:")?;
    if rows.is_empty() {
        writeln!(out, "   (none — run `burnwall mcp-watch` first)")?;
        return Ok(());
    }
    writeln!(out, "   {:<12}  {:<24}  Tool", "Trust", "Server")?;
    writeln!(out, "   {}", "-".repeat(60))?;
    for r in &rows {
        let mark = if r.trust_state == "approved" {
            "✓ approved"
        } else {
            "· pending"
        };
        writeln!(out, "   {:<12}  {:<24}  {}", mark, r.server, r.tool_name)?;
    }
    writeln!(out)?;
    writeln!(
        out,
        "Approve a tool:   burnwall mcp approve <server> <tool>"
    )?;
    writeln!(out, "Approve a server: burnwall mcp approve <server>")?;
    Ok(())
}

// ── approve / revoke ──────────────────────────────────────────────────────

fn approve(server: &str, tool: Option<&str>) -> anyhow::Result<()> {
    let storage = Storage::open_default().context("opening storage")?;
    match tool {
        Some(t) => {
            if storage.approve_mcp_tool(server, t)? {
                println!("✅ Approved '{t}' on server '{server}'.");
            } else {
                println!("ℹ️  No tool '{t}' seen on server '{server}' yet — nothing to approve.");
            }
        }
        None => {
            let n = storage.approve_mcp_server(server)?;
            println!("✅ Approved {n} tool(s) on server '{server}'.");
        }
    }
    Ok(())
}

fn revoke(server: &str, tool: Option<&str>) -> anyhow::Result<()> {
    let storage = Storage::open_default().context("opening storage")?;
    match tool {
        Some(t) => {
            if storage.revoke_mcp_tool(server, t)? {
                println!("✅ Revoked '{t}' on server '{server}' (back to pending).");
            } else {
                println!("ℹ️  No tool '{t}' seen on server '{server}'.");
            }
        }
        None => {
            let n = storage.revoke_mcp_server(server)?;
            println!("✅ Revoked {n} tool(s) on server '{server}' (back to pending).");
        }
    }
    Ok(())
}

// ── export ───────────────────────────────────────────────────────────────

fn export(days: i64, format: ExportFormat) -> anyhow::Result<()> {
    let days = days.max(1);
    let storage = Storage::open_default().context("opening storage")?;
    let tool_calls = storage.mcp_events_since_days(days)?;
    let security: Vec<_> = storage
        .security_events_since_days(days)?
        .into_iter()
        .filter(|e| e.provider.as_deref() == Some("mcp"))
        .collect();

    let mut out = std::io::stdout().lock();
    match format {
        ExportFormat::Json => {
            let value = serde_json::json!({
                "generated_at": chrono::Utc::now().to_rfc3339(),
                "days": days,
                "tool_calls": tool_calls.iter().map(|e| serde_json::json!({
                    "id": e.id,
                    "timestamp": e.timestamp.to_rfc3339(),
                    "tool_name": e.tool_name,
                    "rpc_id": e.rpc_id,
                    "upstream_status": e.upstream_status,
                    "upstream_uri": e.upstream_uri,
                })).collect::<Vec<_>>(),
                "security_events": security.iter().map(|e| serde_json::json!({
                    "id": e.id,
                    "timestamp": e.timestamp.to_rfc3339(),
                    "event_type": e.event_type,
                    "details": e.details,
                    "provider": e.provider,
                    "model": e.model,
                })).collect::<Vec<_>>(),
            });
            writeln!(out, "{}", serde_json::to_string_pretty(&value)?)?;
        }
        ExportFormat::Csv => {
            // Unified chronological audit table (newest first). Columns mean
            // slightly different things per category, as is normal for a
            // merged audit log.
            let mut rows: Vec<(chrono::DateTime<chrono::Utc>, String)> = Vec::new();
            for e in &tool_calls {
                rows.push((
                    e.timestamp,
                    csv_row(&[
                        &e.timestamp.to_rfc3339(),
                        "tool_call",
                        &e.tool_name,
                        &e.upstream_status.to_string(),
                        e.upstream_uri.as_deref().unwrap_or(""),
                    ]),
                ));
            }
            for e in &security {
                rows.push((
                    e.timestamp,
                    csv_row(&[
                        &e.timestamp.to_rfc3339(),
                        "security",
                        e.model.as_deref().unwrap_or(""),
                        &e.event_type,
                        &e.details,
                    ]),
                ));
            }
            rows.sort_by_key(|r| std::cmp::Reverse(r.0));
            writeln!(out, "timestamp,category,tool,status,detail")?;
            for (_, line) in rows {
                writeln!(out, "{line}")?;
            }
        }
    }
    Ok(())
}

/// Join fields into one CSV record, quoting per RFC 4180 where needed.
fn csv_row(fields: &[&str]) -> String {
    fields
        .iter()
        .map(|f| csv_escape(f))
        .collect::<Vec<_>>()
        .join(",")
}

fn csv_escape(field: &str) -> String {
    if field.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}
