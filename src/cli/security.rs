//! `burnwall security` -- inspect blocked attempts.
//!
//! Lists rows from the `security_events` table from the last N local days.
//! Default is today only (`--days 1`). `--json` for machine output.

use std::io::Write;
use std::sync::Arc;

use anyhow::Context;
use clap::Args;

use crate::storage::Storage;
use crate::term::{Card, Color, Styler, render_cards};

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

    // How many canary tripwires are armed (config values meeting the minimum
    // length) — a one-line confirmation the trap is set. Best-effort: a
    // missing/unreadable config just reads as zero.
    let canaries_armed = crate::config::default_path()
        .and_then(crate::config::load_or_default)
        .map(|c| crate::security::rules::armed_canaries(c.security.canaries.clone()).len())
        .unwrap_or(0);

    let mut out = std::io::stdout().lock();

    if args.summary && !args.json {
        return print_summary(&mut out, &events, args.days, canaries_armed);
    }
    if args.json {
        let value = serde_json::json!({
            "days": args.days,
            "count": events.len(),
            "canaries_armed": canaries_armed,
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

    let sty = Styler::stdout();
    writeln!(
        out,
        "🔥 {} · Security events · last {} day{}",
        sty.bold("Burnwall"),
        args.days,
        if args.days == 1 { "" } else { "s" }
    )?;
    writeln!(out)?;

    if events.is_empty() {
        if canaries_armed > 0 {
            writeln!(
                out,
                "  🐤 {} canary tripwire{} armed.",
                canaries_armed,
                if canaries_armed == 1 { "" } else { "s" }
            )?;
        }
        writeln!(out, "  (none)")?;
        return Ok(());
    }

    // Honest split: enforcement blocks vs advisory alerts (never conflated),
    // plus the armed-canary count — the glanceable receipt above the log.
    let (blocked, alerts) = events.iter().fold((0i64, 0i64), |(b, a), e| {
        if crate::security::catalog::is_advisory(&e.event_type) {
            (b, a + 1)
        } else {
            (b + 1, a)
        }
    });
    let cards = [
        Card::new("Blocked", &blocked.to_string(), "stopped")
            .with_value_color(if blocked > 0 { Color::Red } else { Color::Green }),
        Card::new("Alerts", &alerts.to_string(), "advisory")
            .with_value_color(if alerts > 0 { Color::Yellow } else { Color::Green }),
        Card::new("Canaries", &canaries_armed.to_string(), "armed")
            .with_value_color(if canaries_armed > 0 { Color::Green } else { Color::Blue }),
    ];
    writeln!(out, "{}", render_cards(&cards, 11, 2, &sty))?;
    writeln!(out)?;

    writeln!(
        out,
        "  {:<19}  {:<17}  {:<28}  Detail",
        "Time", "Type", "Provider/Model"
    )?;
    writeln!(out, "  {}", "─".repeat(84))?;
    for e in &events {
        let provider_model = match (&e.provider, &e.model) {
            (Some(p), Some(m)) => format!("{}/{}", p, m),
            (Some(p), None) => p.clone(),
            _ => "-".to_string(),
        };
        writeln!(
            out,
            "  {:<19}  {:<17}  {:<28}  {}",
            // Stored UTC, displayed in the user's local time.
            e.timestamp
                .with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M:%S"),
            e.event_type,
            truncate(&provider_model, 28),
            truncate(&e.details, 58),
        )?;
    }
    writeln!(out)?;
    writeln!(
        out,
        "  Total: {} event{}",
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
        "destructive_blocked" => "catastrophic command",
        "obfuscation_blocked" => "invisible-character obfuscation",
        "canary_triggered" => "canary tripwire (planted credential)",
        // Advisory alerts (request still flowed; informational).
        "slow_drip_alert" => "slow data-drip alert",
        "billing_flip" => "subscription→metered switch",
        "response_exfil_warning" => "data-carrying URL in response",
        "mcp_tool_poisoning" => "poisoned MCP tool description",
        "mcp_tool_changed" => "MCP tool definition drift",
        other => other,
    }
}

/// The "what Burnwall caught for you" receipt — a grouped count over the window,
/// so passive protection registers as ongoing value rather than going unseen.
fn print_summary<W: Write>(
    out: &mut W,
    events: &[crate::storage::SecurityEvent],
    days: i64,
    canaries_armed: usize,
) -> anyhow::Result<()> {
    let sty = Styler::stdout();
    let window = if days == 1 {
        "today".to_string()
    } else {
        format!("the last {days} days")
    };
    writeln!(out, "🔥 {} · Security · {}", sty.bold("Burnwall"), window)?;
    writeln!(out)?;

    let canary_line = |out: &mut W| -> anyhow::Result<()> {
        if canaries_armed > 0 {
            writeln!(
                out,
                "  🐤 {} canary tripwire{} armed.",
                canaries_armed,
                if canaries_armed == 1 { "" } else { "s" }
            )?;
        }
        Ok(())
    };

    if events.is_empty() {
        writeln!(
            out,
            "  {} All clear — nothing blocked {window}.",
            sty.green("✓")
        )?;
        writeln!(
            out,
            "  (No news is good news; protection is running silently.)"
        )?;
        canary_line(out)?;
        return Ok(());
    }

    // Count by event type, preserving a stable, severity-ish display order.
    use std::collections::HashMap;
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for e in events {
        *counts.entry(e.event_type.as_str()).or_default() += 1;
    }
    let order = [
        "canary_triggered",
        "destructive_blocked",
        "exfil_blocked",
        "secret_detected",
        "dlp_blocked",
        "obfuscation_blocked",
        "command_blocked",
        "path_blocked",
        "mount_blocked",
    ];

    // "Caught" (not "blocked"): the window may include advisory alerts that
    // nothing was stopped for — the bullet hue keeps the distinction (red =
    // enforcement block, yellow = advisory alert).
    writeln!(
        out,
        "  🛡️  Burnwall caught {} event{} {}:",
        events.len(),
        if events.len() == 1 { "" } else { "s" },
        window
    )?;
    writeln!(out)?;
    let bullet = |key: &str| {
        let hue = if crate::security::catalog::is_advisory(key) {
            Color::Yellow
        } else {
            Color::Red
        };
        sty.paint("●", hue)
    };
    for key in order {
        if let Some(n) = counts.remove(key) {
            writeln!(out, "  {} {n:>3}  {}", bullet(key), friendly_type(key))?;
        }
    }
    // Any event types not in the canonical order (e.g. future kinds).
    let mut rest: Vec<(&str, usize)> = counts.into_iter().collect();
    rest.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    for (key, n) in rest {
        writeln!(out, "  {} {:>3}  {}", bullet(key), n, friendly_type(key))?;
    }
    canary_line(out)?;
    Ok(())
}
