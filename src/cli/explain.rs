//! `burnwall explain <event-id>` — expand one recorded security block into the
//! full "why was I blocked, and what do I do now?" answer, self-serve.
//!
//! We are blind by design (no telemetry), so the support story is the product
//! explaining itself. This turns a terse `security_events` row into: which rule
//! fired (stable greppable id + docs anchor), on what, why that class is
//! blocked, and the concrete next move (`allow-once` / config). The event id
//! comes from `burnwall security --json` (`events[].id`).
//!
//! Terminal-only, like `burnwall security`: the detail is the user's own data
//! on their own machine and is shown in full here. The *masked* form (what is
//! safe to paste into a bug report) is what `burnwall doctor --export` writes.

use std::io::Write;
use std::sync::Arc;

use anyhow::Context;
use clap::Args;

use crate::security::catalog;
use crate::storage::Storage;
use crate::term::Styler;

#[derive(Args, Debug)]
pub struct ExplainArgs {
    /// The security-event id to explain (from `burnwall security --json`).
    pub event_id: i64,
    /// Emit JSON instead of the human view.
    #[arg(long)]
    pub json: bool,
}

pub fn run_cmd(args: ExplainArgs) -> anyhow::Result<()> {
    let storage = Arc::new(Storage::open_default().context("opening storage")?);
    let event = storage
        .get_security_event(args.event_id)
        .context("reading security event")?;

    let mut out = std::io::stdout().lock();
    let Some(event) = event else {
        if args.json {
            writeln!(
                out,
                "{}",
                serde_json::json!({ "error": "not_found", "event_id": args.event_id })
            )?;
        } else {
            writeln!(
                out,
                "No security event with id {}. List recent ones:  burnwall security --days 7 --json",
                args.event_id
            )?;
        }
        // Not found is a user error, not a crash — exit non-zero cleanly.
        std::process::exit(2);
    };

    let card = catalog::lookup(&event.event_type);

    if args.json {
        let value = serde_json::json!({
            "event_id": event.id,
            "timestamp": event.timestamp.to_rfc3339(),
            "event_type": event.event_type,
            "rule_id": card.id,
            "title": card.title,
            "detail": event.details,
            "why": card.why,
            "fix": card.fix,
            "docs_anchor": card.anchor,
            "provider": event.provider,
            "model": event.model,
        });
        writeln!(out, "{}", serde_json::to_string_pretty(&value).unwrap())?;
        return Ok(());
    }

    let sty = Styler::stdout();
    writeln!(out, "{} {}", sty.red("🛡️  Blocked:"), sty.bold(card.title))?;
    writeln!(out, "   rule: {}   ({})", sty.bold(card.id), card.anchor)?;
    writeln!(
        out,
        "   when: {}",
        event
            .timestamp
            .with_timezone(&chrono::Local)
            .format("%Y-%m-%d %H:%M:%S")
    )?;
    if let (Some(p), Some(m)) = (&event.provider, &event.model) {
        writeln!(out, "   route: {p}/{m}")?;
    }
    writeln!(out)?;

    // The recorded detail, in full — terminal-only, the user's own machine
    // (same disclosure level as `burnwall security`). What was matched:
    writeln!(out, "   {}", sty.bold("What matched"))?;
    writeln!(
        out,
        "     {}",
        strip_type_prefix(&event.event_type, &event.details)
    )?;
    writeln!(out)?;

    writeln!(out, "   {}", sty.bold("Why this is blocked"))?;
    for line in wrap(card.why, 72) {
        writeln!(out, "     {line}")?;
    }
    writeln!(out)?;

    writeln!(out, "   {}", sty.bold("How to proceed"))?;
    for line in wrap(card.fix, 72) {
        writeln!(out, "     {line}")?;
    }
    writeln!(out)?;
    writeln!(
        out,
        "   Burnwall blocks before forwarding — nothing left your machine."
    )?;
    Ok(())
}

/// Drop a leading `"<event_type>: "` prefix the scanner sometimes prepends to
/// `details`, so the displayed value is just the matched path/command/label.
fn strip_type_prefix<'a>(event_type: &str, details: &'a str) -> &'a str {
    details
        .strip_prefix(event_type)
        .and_then(|r| r.strip_prefix(": "))
        .unwrap_or(details)
}

/// Greedy word-wrap to `width` columns for the multi-line "why / fix" prose.
/// Collapses internal whitespace (the catalog strings use line continuations).
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut cur = String::new();
    for word in text.split_whitespace() {
        if !cur.is_empty() && cur.len() + 1 + word.len() > width {
            lines.push(std::mem::take(&mut cur));
        }
        if !cur.is_empty() {
            cur.push(' ');
        }
        cur.push_str(word);
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_event_type_prefix() {
        assert_eq!(
            strip_type_prefix("path_blocked", "path_blocked: ~/.ssh/id_rsa"),
            "~/.ssh/id_rsa"
        );
        // No prefix: returned unchanged.
        assert_eq!(
            strip_type_prefix("path_blocked", "~/.aws/credentials"),
            "~/.aws/credentials"
        );
        // A label-only detail (secret_detected stores the pattern name).
        assert_eq!(
            strip_type_prefix("secret_detected", "AWS access key ID"),
            "AWS access key ID"
        );
    }

    #[test]
    fn wrap_respects_width_and_keeps_all_words() {
        let text = "alpha beta gamma delta epsilon zeta eta theta iota kappa";
        let lines = wrap(text, 20);
        assert!(lines.iter().all(|l| l.len() <= 20));
        let rejoined = lines.join(" ");
        assert_eq!(rejoined, text);
    }
}
