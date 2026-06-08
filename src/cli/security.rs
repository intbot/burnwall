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
    /// Print a short "what Burnwall caught" summary (counts by type) instead of
    /// the per-event table — the visible receipt that passive protection is
    /// working. Pairs well with `--days 7`.
    #[arg(long)]
    pub summary: bool,
}

pub fn run_cmd(args: SecurityArgs) -> anyhow::Result<()> {
    let storage = Arc::new(Storage::open_default().context("opening storage")?);
    let mut events = storage.security_events_since_days(args.days)?;

    if !args.event_type.is_empty() {
        events.retain(|e| args.event_type.iter().any(|t| t == &e.event_type));
    }

    let mut out = std::io::stdout().lock();

    if args.summary && !args.json {
        return print_summary(&mut out, &events, args.days);
    }
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

/// Friendly label for an `event_type` value.
fn friendly_type(event_type: &str) -> &str {
    match event_type {
        "path_blocked" => "denied-path access",
        "command_blocked" => "dangerous command",
        "mount_blocked" => "network-mount access",
        "secret_detected" => "secret/credential in payload",
        "dlp_blocked" => "PII/data exfiltration",
        "exfil_blocked" => "data-exfiltration technique",
        other => other,
    }
}

/// The "what Burnwall caught for you" receipt — a grouped count over the window,
/// so passive protection registers as ongoing value rather than going unseen.
fn print_summary<W: Write>(
    out: &mut W,
    events: &[crate::storage::SecurityEvent],
    days: i64,
) -> anyhow::Result<()> {
    let window = if days == 1 {
        "today".to_string()
    } else {
        format!("the last {days} days")
    };
    if events.is_empty() {
        writeln!(out, "🛡️  All clear — Burnwall blocked nothing {window}.")?;
        writeln!(out, "   (No news is good news; protection is running silently.)")?;
        return Ok(());
    }

    // Count by event type, preserving a stable, severity-ish display order.
    use std::collections::HashMap;
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for e in events {
        *counts.entry(e.event_type.as_str()).or_default() += 1;
    }
    let order = [
        "exfil_blocked",
        "secret_detected",
        "dlp_blocked",
        "command_blocked",
        "path_blocked",
        "mount_blocked",
    ];

    writeln!(
        out,
        "🛡️  Burnwall blocked {} attempt{} {}:",
        events.len(),
        if events.len() == 1 { "" } else { "s" },
        window
    )?;
    for key in order {
        if let Some(n) = counts.remove(key) {
            writeln!(out, "   • {n:>3}  {}", friendly_type(key))?;
        }
    }
    // Any event types not in the canonical order (e.g. future kinds).
    let mut rest: Vec<(&str, usize)> = counts.into_iter().collect();
    rest.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    for (key, n) in rest {
        writeln!(out, "   • {:>3}  {}", n, friendly_type(key))?;
    }
    Ok(())
}
