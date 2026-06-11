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
    let usage = cc
        .context_window
        .as_ref()
        .and_then(|c| c.current_usage.as_ref());
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
    let today_usd = if today > 0.0 { Some(today) } else { None };

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
        sess_usd: Some(sess),
        today_usd,
        blocks_today: blocks,
        plan: plan_limits(),
        routing: routing_state(&model_id),
        ctx,
    }
}

/// Routing health for the status line. The `statusline` process is spawned by
/// Claude Code and inherits its environment, so the tool's `*_BASE_URL` tells us
/// whether traffic is actually reaching the proxy. We key off the model's
/// provider (Claude Code is Anthropic, but be correct if that ever changes).
///
/// When the env says Proxied we additionally **liveness-probe the proxy port**
/// (U-C1): an already-open session keeps its env vars after a crash or
/// `burnwall stop`, and a green ribbon over a dead port — every request failing
/// with connection-refused — was the worst "Burnwall broke my setup" signal.
/// The probe is a sub-millisecond loopback connect, paid once per render.
fn routing_state(model_id: &str) -> ribbon::Routing {
    let provider = provider_of(model_id);
    match crate::cli::routing::current_routing(provider) {
        crate::cli::routing::EnvRouting::Proxied => {
            let var = crate::cli::routing::base_url_var_for_provider(provider);
            match std::env::var(var)
                .ok()
                .and_then(|u| crate::cli::routing::proxy_alive_for_url(&u))
            {
                Some(false) => ribbon::Routing::ProxyDown,
                _ => {
                    // Alive and routed — but is protection paused? A pause
                    // (`burnwall pause`) relays everything unchecked; surface
                    // it loudly for the whole window so it can't be forgotten.
                    let now = chrono::Utc::now().timestamp();
                    match crate::bypass::read(now) {
                        crate::bypass::Bypass::Paused { resumes_in_secs } => {
                            ribbon::Routing::Paused { resumes_in_secs }
                        }
                        // An armed allow-once lives for seconds before it's
                        // consumed — not worth a persistent chip.
                        _ => ribbon::Routing::Proxied,
                    }
                }
            }
        }
        crate::cli::routing::EnvRouting::Direct => ribbon::Routing::Direct,
        crate::cli::routing::EnvRouting::Bypassed => ribbon::Routing::Bypassed,
    }
}

/// Best-effort provider guess from a model id (only the families a status line
/// surfaces). Defaults to `anthropic` — the Claude Code case.
fn provider_of(model_id: &str) -> &'static str {
    let m = model_id.to_ascii_lowercase();
    if m.contains("gpt")
        || m.starts_with("o1")
        || m.starts_with("o3")
        || m.starts_with("o4")
        || m.contains("openai")
    {
        "openai"
    } else if m.contains("gemini") || m.contains("google") {
        "google"
    } else {
        "anthropic"
    }
}

/// Build the subscription-limit segment. Once any plan snapshot exists the
/// user is a known flat-rate subscriber and the ribbon stays in plan mode —
/// fresh readings show live headroom, stale or window-expired readings show
/// last-known headroom marked `~ … idle`, and only a true API user (no
/// snapshot ever) gets the dollar segment. See [`crate::plan::ribbon_limits`].
fn plan_limits() -> Option<ribbon::PlanLimits> {
    crate::plan::ribbon_limits(chrono::Utc::now().timestamp())
}

/// Claude Code reports *cumulative* session cost, and re-renders the status
/// line many times per turn (~300ms cadence while streaming). A naive
/// "delta since last render" therefore showed only the last streaming
/// increment — $0.05 of a $0.40 turn, or $0.00 after any idle re-render — the
/// most-watched number, systematically wrong-low (U-H1).
///
/// Turn-aware delta instead: track `(baseline, last_seen, last_msg)` per
/// session. While the total is moving (a turn is streaming), `msg` is the live
/// delta from the baseline — the turn's cost so far. When the total stops
/// moving (turn over), the final delta is locked in as `last_msg` and the
/// baseline advances, so the ribbon keeps showing the *completed* turn's cost
/// until the next turn starts. Best-effort — any I/O error yields `None`.
fn session_msg_delta(session: Option<&str>, total: f64) -> Option<f64> {
    let session = session?;
    let dir = crate::storage::data_dir().ok()?.join("statusline");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join(format!("{}.last", sanitize(session)));

    let state = std::fs::read_to_string(&path).ok().and_then(|s| {
        let mut it = s.split_whitespace().filter_map(|t| t.parse::<f64>().ok());
        Some((it.next()?, it.next(), it.next()))
    });

    let (msg, baseline, last_msg) = match state {
        // Legacy single-value file (just a total) or fresh triple.
        Some((baseline, last_seen, last_msg)) => {
            let last_seen = last_seen.unwrap_or(baseline);
            let last_msg = last_msg.unwrap_or(0.0);
            if total > last_seen + 1e-9 {
                // Turn in progress: live cost-so-far from the baseline.
                let live = (total - baseline).max(0.0);
                (Some(live), baseline, live)
            } else {
                // Total stopped moving: the turn is over. Lock in its final
                // cost and advance the baseline for the next turn.
                let final_msg = if total > baseline + 1e-9 {
                    (total - baseline).max(0.0)
                } else {
                    last_msg
                };
                (Some(final_msg), total, final_msg)
            }
        }
        // First render of a session — no baseline yet.
        None => (None, total, 0.0),
    };

    let _ = std::fs::write(&path, format!("{baseline} {total} {last_msg}"));
    msg
}

/// Keep a session id safe as a filename component (it's normally a UUID, but be
/// defensive about path separators).
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
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
    let blocks = storage
        .security_event_count_for_date(&today)
        .unwrap_or(0)
        .max(0) as u64;
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
        assert!((r.sess_usd.unwrap() - 0.16).abs() < 1e-9);
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
