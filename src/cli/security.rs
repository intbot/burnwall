//! `burnwall security` -- inspect blocked attempts.
//!
//! Lists rows from the `security_events` table from the last N local days.
//! Default is today only (`--days 1`). `--json` for machine output.

use std::io::Write;
use std::sync::Arc;

use anyhow::Context;
use clap::Args;

use crate::storage::Storage;

#[derive(Args, Debug)]
pub struct SecurityArgs {
    /// How many days back to include (default 1 = today only).
    #[arg(long, default_value_t = 1)]
    pub days: i64,
    /// Optional event-type filter (path_blocked / command_blocked /
    /// mount_blocked / secret_detected). Repeat to allow multiple.
    #[arg(long, value_name = "TYPE")]
    pub event_type: Vec<String>,
    /// Emit JSON instead of the table view.
    #[arg(long)]
    pub json: bool,
}

pub fn run_cmd(args: SecurityArgs) -> anyhow::Result<()> {
    let storage = Arc::new(Storage::open_default().context("opening storage")?);
    let mut events = storage.security_events_since_days(args.days)?;

    if !args.event_type.is_empty() {
        events.retain(|e| args.event_type.iter().any(|t| t == &e.event_type));
    }

    let mut out = std::io::stdout().lock();
    if args.json {
        let value = serde_json::json!({
            "days": args.days,
            "count": events.len(),
            "events": events.iter().map(|e| serde_json::json!({
                "id": e.id,
                "timestamp": e.timestamp.to_rfc3339(),
                "event_type": e.event_type,
                "details": e.details,
                "provider": e.provider,
                "model": e.model,
            })).collect::<Vec<_>>(),
        });
        writeln!(out, "{}", serde_json::to_string_pretty(&value).unwrap())?;
        return Ok(());
    }

    writeln!(
        out,
        "🛡️  Security events (last {} day{})",
        args.days,
        if args.days == 1 { "" } else { "s" }
    )?;
    if events.is_empty() {
        writeln!(out, "   (none)")?;
        return Ok(());
    }

    writeln!(
        out,
        "   {:<19}  {:<17}  {:<28}  Detail",
        "Time", "Type", "Provider/Model"
    )?;
    writeln!(out, "   {}", "-".repeat(85))?;
    for e in &events {
        let provider_model = match (&e.provider, &e.model) {
            (Some(p), Some(m)) => format!("{}/{}", p, m),
            (Some(p), None) => p.clone(),
            _ => "-".to_string(),
        };
        writeln!(
            out,
            "   {:<19}  {:<17}  {:<28}  {}",
            // Stored UTC, displayed in the user's local time.
            e.timestamp
                .with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M:%S"),
            e.event_type,
            truncate(&provider_model, 28),
            truncate(&e.details, 60),
        )?;
    }
    writeln!(out)?;
    writeln!(
        out,
        "   Total: {} event{}",
        events.len(),
        if events.len() == 1 { "" } else { "s" }
    )?;

    Ok(())
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
