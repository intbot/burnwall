//! `burnwall statusline` — render the Burnwall ribbon for Claude Code's
//! customizable status line.
//!
//! Claude Code pipes a JSON blob on stdin after each turn (model, cumulative
//! cost, context-window usage). We map it to a [`Ribbon`], enrich it with
//! cross-tool data from the proxy DB (today's spend, security blocks), and print
//! the one line Claude Code renders at the bottom of its UI.
//!
//! Wire it up in `~/.claude/settings.json`:
//! ```json
//! { "statusLine": { "type": "command", "command": "burnwall statusline" } }
//! ```
//!
//! Fail-open throughout: malformed/empty stdin or an unreadable DB still yields
//! a best-effort line rather than an error — a broken status line must never
//! disrupt the editor.

use std::io::Read;

use clap::Args;
use serde::Deserialize;

use crate::ribbon::{self, Ctx, Ribbon};

#[derive(Args, Debug)]
pub struct StatuslineArgs {
    /// Disable ANSI color (for surfaces that don't render escape codes).
    #[arg(long)]
    pub no_color: bool,
}

/// The subset of Claude Code's status-line stdin JSON we consume. Every field is
/// optional so a partial or future-extended payload still deserializes.
#[derive(Debug, Default, Deserialize)]
struct CcInput {
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    model: Option<CcModel>,
    #[serde(default)]
    cost: Option<CcCost>,
    #[serde(default)]
    context_window: Option<CcContext>,
}

#[derive(Debug, Default, Deserialize)]
struct CcModel {
    #[serde(default)]
    id: String,
    #[serde(default)]
    display_name: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct CcCost {
    #[serde(default)]
    total_cost_usd: f64,
}

#[derive(Debug, Default, Deserialize)]
struct CcContext {
    #[serde(default)]
    used_percentage: Option<f64>,
    #[serde(default)]
    current_usage: Option<CcUsage>,
}

#[derive(Debug, Default, Deserialize)]
struct CcUsage {
    #[serde(default)]
    input_tokens: u64,
    #[serde(default)]
    output_tokens: u64,
    #[serde(default)]
    cache_creation_input_tokens: u64,
    #[serde(default)]
    cache_read_input_tokens: u64,
}

pub fn run_cmd(args: StatuslineArgs) -> anyhow::Result<()> {
    let mut buf = String::new();
    let _ = std::io::stdin().read_to_string(&mut buf);
    let cc: CcInput = serde_json::from_str(&buf).unwrap_or_default();

    let ribbon = build_ribbon(&cc);
    println!("{}", ribbon.render(!args.no_color));
    Ok(())
}

/// Map Claude Code's input (+ DB enrichment) to a [`Ribbon`]. Pure given the
/// input and the enrichment closure, so it's unit-testable without a DB.
fn build_ribbon(cc: &CcInput) -> Ribbon {
    let sess = cc.cost.as_ref().map(|c| c.total_cost_usd).unwrap_or(0.0);
    let msg = session_msg_delta(cc.session_id.as_deref(), sess);

    // "up" is the true prompt size: uncached input + cache writes + cache reads.
    let usage = cc.context_window.as_ref().and_then(|c| c.current_usage.as_ref());
    let up = usage
        .map(|u| u.input_tokens + u.cache_creation_input_tokens + u.cache_read_input_tokens)
        .unwrap_or(0);
    let down = usage.map(|u| u.output_tokens).unwrap_or(0);

    // Claude Code reports an exact context %. If it's absent (early session /
    // just after /compact) we hide the segment rather than guess.
    let ctx = match cc.context_window.as_ref().and_then(|c| c.used_percentage) {
        Some(p) => Ctx::Exact(p),
        None => Ctx::Hidden,
    };

    let (today, blocks) = db_enrichment();

    let model_id = cc
        .model
        .as_ref()
        .map(|m| {
            if !m.id.is_empty() {
                m.id.clone()
            } else {
                m.display_name.clone().unwrap_or_default()
            }
        })
        .unwrap_or_default();

    Ribbon {
        model: ribbon::short_model(&model_id),
        tool: None, // rendered inside Claude Code's own line — no tool label needed
        up,
        down,
        msg_usd: msg,
        sess_usd: sess,
        today_usd: today,
        blocks_today: blocks,
        ctx,
    }
}

/// Claude Code reports *cumulative* session cost; cache the previous total per
/// session and return this turn's delta. `None` when we have no prior reading
/// (first turn of a session) so the ribbon shows session-only cost. Best-effort
/// — any I/O error just yields `None`.
fn session_msg_delta(session: Option<&str>, total: f64) -> Option<f64> {
    let session = session?;
    let dir = crate::storage::data_dir().ok()?.join("statusline");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join(format!("{}.last", sanitize(session)));
    let prev = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.trim().parse::<f64>().ok());
    let _ = std::fs::write(&path, total.to_string());
    prev.map(|p| (total - p).max(0.0))
}

/// Keep a session id safe as a filename component (it's normally a UUID, but be
/// defensive about path separators).
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

/// Today's cross-tool spend and security-block count from the proxy DB. Returns
/// zeros if the DB can't be opened (e.g. proxy never run yet) — never fatal.
fn db_enrichment() -> (f64, u64) {
    let today = chrono::Local::now().format("%Y-%m-%d").to_string();
    let Ok(storage) = crate::storage::Storage::open_default() else {
        return (0.0, 0);
    };
    let cost = storage.total_cost_for_date(&today).unwrap_or(0.0);
    let blocks = storage.security_event_count_for_date(&today).unwrap_or(0).max(0) as u64;
    (cost, blocks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_ribbon_maps_claude_code_fields() {
        let cc: CcInput = serde_json::from_str(
            r#"{
                "session_id": "s1",
                "model": {"id": "claude-sonnet-4-6", "display_name": "Sonnet"},
                "cost": {"total_cost_usd": 0.16},
                "context_window": {
                    "used_percentage": 22.0,
                    "current_usage": {
                        "input_tokens": 5000,
                        "output_tokens": 615,
                        "cache_creation_input_tokens": 3000,
                        "cache_read_input_tokens": 5000
                    }
                }
            }"#,
        )
        .unwrap();
        let r = build_ribbon(&cc);
        assert_eq!(r.model, "sonnet-4.6");
        assert_eq!(r.up, 13_000); // 5000 + 3000 + 5000
        assert_eq!(r.down, 615);
        assert!((r.sess_usd - 0.16).abs() < 1e-9);
        assert_eq!(r.ctx, Ctx::Exact(22.0));
    }

    #[test]
    fn missing_context_percentage_hides_segment() {
        let cc: CcInput =
            serde_json::from_str(r#"{"model":{"id":"gpt-5.4"},"cost":{"total_cost_usd":1.0}}"#)
                .unwrap();
        let r = build_ribbon(&cc);
        assert_eq!(r.ctx, Ctx::Hidden);
        assert_eq!(r.model, "gpt-5.4");
    }

    #[test]
    fn empty_input_is_fail_open() {
        // Garbage stdin → default struct → a renderable (zeroed) ribbon, no panic.
        let cc: CcInput = serde_json::from_str("not json").unwrap_or_default();
        let r = build_ribbon(&cc);
        assert_eq!(r.up, 0);
        assert!(r.render(false).contains("🔥"));
    }

    #[test]
    fn sanitize_strips_path_separators() {
        assert_eq!(sanitize("abc-123_DEF"), "abc-123_DEF");
        assert_eq!(sanitize("../../etc"), "______etc");
    }
}
