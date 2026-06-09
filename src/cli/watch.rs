//! `burnwall watch` — a live, cross-tool status ribbon for a spare terminal
//! pane. The in-TUI ribbon (`burnwall statusline`) only works in Claude Code;
//! this surface shows the *same* renderer for every tool that routes through the
//! proxy (Codex, Gemini, Aider, …), sourced from the proxy database.
//!
//! It refreshes event-driven off the `watch.signal` marker the proxy touches
//! after each recorded turn, with a periodic fallback so wall-clock-y data stays
//! fresh. `--once` renders a single frame and exits (handy for scripting/tests).
//!
//! Context honesty: no tool feeds us an exact context %, so the gauge is an
//! estimate (`~`) when the model's window is known and the prompt fits, and `—`
//! otherwise — never an unqualified number (see [`crate::ribbon`]).

use std::io::Write;
use std::time::{Duration, Instant};

use anyhow::Context;
use clap::Args;

use crate::ribbon::{self, Ctx, Ribbon};
use crate::storage::{self, Storage};

#[derive(Args, Debug)]
pub struct WatchArgs {
    /// Render the compact one-line ribbon instead of the multi-line dashboard.
    #[arg(long)]
    pub oneline: bool,
    /// Render a single frame and exit (no loop). Good for scripts and tests.
    #[arg(long)]
    pub once: bool,
    /// Fallback refresh interval in seconds (event-driven updates happen sooner).
    #[arg(long, default_value_t = 2)]
    pub interval: u64,
    /// Disable ANSI color / screen clearing.
    #[arg(long)]
    pub no_color: bool,
    /// Emit the ribbon as a terminal-title escape (OSC) instead of drawing a
    /// pane — so a status-bar-less CLI gets the ribbon in its window/tab title.
    /// Wire into your shell's prompt hook (e.g. `precmd`/`PROMPT_COMMAND`), or
    /// `tmux` via `status-right` (those can also use `--once --oneline`).
    #[arg(long)]
    pub title: bool,
}

pub fn run_cmd(args: WatchArgs) -> anyhow::Result<()> {
    let db = Storage::open_default().context("opening storage")?;

    if args.once {
        let frame = if args.title {
            title_frame(&db)
        } else {
            render_frame(&db, &args)
        };
        print!("{frame}");
        std::io::stdout().flush().ok();
        return Ok(());
    }

    let interval = Duration::from_secs(args.interval.max(1));
    let signal = storage::watch_signal_path().ok();
    let mut last_sig = signal.as_ref().and_then(mtime);
    let mut last_render = Instant::now();
    draw(&db, &args);

    loop {
        std::thread::sleep(Duration::from_millis(200));
        let now_sig = signal.as_ref().and_then(mtime);
        let signal_changed = now_sig != last_sig;
        if signal_changed || last_render.elapsed() >= interval {
            last_sig = now_sig;
            last_render = Instant::now();
            draw(&db, &args);
        }
    }
}

/// Clear the screen (unless colour/clearing is off) and paint one frame.
fn draw(db: &Storage, args: &WatchArgs) {
    if args.title {
        // Title mode never clears the screen — it only updates the title.
        print!("{}", title_frame(db));
        std::io::stdout().flush().ok();
        return;
    }
    if !args.no_color {
        // Clear screen + move cursor home.
        print!("\x1b[2J\x1b[H");
    }
    print!("{}", render_frame(db, args));
    std::io::stdout().flush().ok();
}

/// OSC escape that sets the terminal window/icon title to the (uncoloured)
/// ribbon. `ESC ] 0 ; <text> BEL` is the widely-supported form.
fn title_frame(db: &Storage) -> String {
    format!("\x1b]0;{}\x07", ribbon_from_db(db).render(false))
}

/// Render the current frame to a string (pure given the DB snapshot) — the
/// one-line ribbon or the multi-line dashboard.
fn render_frame(db: &Storage, args: &WatchArgs) -> String {
    let ribbon = ribbon_from_db(db);
    let color = !args.no_color;
    if args.oneline {
        format!("{}\n", ribbon.render(color))
    } else {
        dashboard(db, &ribbon, color)
    }
}

/// Build the cross-tool ribbon from the proxy database. The originating tool
/// isn't recoverable from proxied HTTP (every tool hits the same provider
/// route), so `tool` and `sess` are left unset; `today` is the cross-tool total.
fn ribbon_from_db(db: &Storage) -> Ribbon {
    let today = chrono::Local::now().format("%Y-%m-%d").to_string();
    let today_usd = db.total_cost_for_date(&today).unwrap_or(0.0);
    let blocks = db
        .security_event_count_for_date(&today)
        .unwrap_or(0)
        .max(0) as u64;

    let last = db.most_recent_request().ok().flatten();
    let (model, up, down, msg_usd, ctx) = match last {
        Some(r) => {
            let prompt = r.input_tokens + r.cache_creation_tokens + r.cache_read_tokens;
            let ctx = ribbon::ctx_estimate(&r.model, prompt);
            (
                ribbon::short_model(&r.model),
                prompt,
                r.output_tokens,
                Some(r.cost_usd),
                ctx,
            )
        }
        None => ("—".to_string(), 0, 0, None, Ctx::Hidden),
    };

    Ribbon {
        model,
        tool: None,
        up,
        down,
        msg_usd,
        sess_usd: None, // the aggregate view has no session concept
        today_usd: Some(today_usd),
        blocks_today: blocks,
        // Subscription headroom (freshest provider) — the universal surface for
        // CLIs without their own status bar (run `watch` in a side pane).
        plan: {
            let now = chrono::Utc::now().timestamp();
            crate::plan::freshest(now, 12 * 3600).and_then(|s| s.to_ribbon_limits(now))
        },
        // The aggregate DB view spans every tool; there's no single tool
        // environment to judge routing from, so stay silent here. Per-tool
        // coverage is shown in the dashboard's `coverage:` block instead.
        routing: ribbon::Routing::Unknown,
        ctx,
    }
}

fn dashboard(db: &Storage, ribbon: &Ribbon, color: bool) -> String {
    let now = chrono::Local::now().format("%H:%M:%S");
    let rule = "─".repeat(58);
    let mut s = String::new();
    s.push_str(&format!(" burnwall · live{:>43}\n", now));
    s.push_str(&format!(" {rule}\n"));
    s.push_str(&format!(" {}\n", ribbon.render(color)));
    s.push('\n');

    // Per-provider/model breakdown for today (proxied traffic).
    let today = chrono::Local::now().format("%Y-%m-%d").to_string();
    if let Ok(rows) = db.breakdown_for_date(&today) {
        if !rows.is_empty() {
            s.push_str(" today by model:\n");
            for r in rows.iter().take(6) {
                s.push_str(&format!(
                    "   {:<28} ${:.2}\n",
                    format!("{}/{}", r.provider, ribbon::short_model(&r.model)),
                    r.cost
                ));
            }
            s.push('\n');
        }
    }
    // Coverage: which installed tools actually route through the proxy. Makes
    // silent non-coverage visible (e.g. ChatGPT-login Codex bypasses entirely).
    let coverage = crate::coverage::assess(db, chrono::Utc::now().timestamp());
    if !coverage.is_empty() {
        s.push_str(" coverage:\n");
        for tc in &coverage {
            s.push_str(&format!("   {:<14} {}\n", tc.label, tc.state.summary()));
        }
        s.push('\n');
    }

    s.push_str(&format!(" {rule}\n"));
    s.push_str(" refreshing on activity · ctrl-c to exit\n");
    s
}

fn mtime(path: &std::path::PathBuf) -> Option<std::time::SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::TokenUsage;
    use crate::storage::RequestRecord;

    fn db_with_request() -> Storage {
        let db = Storage::open_in_memory().unwrap();
        let usage = TokenUsage {
            input_tokens: 5_000,
            output_tokens: 615,
            cache_creation_tokens: 3_000,
            cache_read_tokens: 5_000,
        };
        let r = RequestRecord::successful("anthropic", "claude-sonnet-4-6", &usage, 0.05, None);
        db.insert_request(&r).unwrap();
        db
    }

    #[test]
    fn ribbon_from_db_uses_last_request_and_estimates_ctx() {
        let db = db_with_request();
        let r = ribbon_from_db(&db);
        assert_eq!(r.model, "sonnet-4.6");
        assert_eq!(r.up, 13_000); // input + cache_creation + cache_read
        assert_eq!(r.down, 615);
        assert_eq!(r.msg_usd, Some(0.05));
        assert_eq!(r.sess_usd, None); // no session concept in the aggregate view
        // 13k / 200k ≈ 6.5% → an Estimate (marked ~ at render time).
        match r.ctx {
            Ctx::Estimate(p) => assert!(p > 6.0 && p < 7.0),
            other => panic!("expected Estimate, got {other:?}"),
        }
    }

    #[test]
    fn ribbon_from_empty_db_is_safe() {
        let db = Storage::open_in_memory().unwrap();
        let r = ribbon_from_db(&db);
        assert_eq!(r.model, "—");
        assert_eq!(r.msg_usd, None);
        assert_eq!(r.ctx, Ctx::Hidden);
        // Still renders a line without panicking.
        assert!(r.render(false).contains("🔥"));
    }

    #[test]
    fn oneline_frame_contains_ribbon() {
        let db = db_with_request();
        let args = WatchArgs {
            oneline: true,
            once: true,
            interval: 2,
            no_color: true,
            title: false,
        };
        let frame = render_frame(&db, &args);
        assert!(frame.contains("🔥 burnwall · sonnet-4.6"));
        assert!(frame.contains("$0.05 msg"));
    }

    #[test]
    fn dashboard_frame_has_header_and_breakdown() {
        let db = db_with_request();
        let args = WatchArgs {
            oneline: false,
            once: true,
            interval: 2,
            no_color: true,
            title: false,
        };
        let frame = render_frame(&db, &args);
        assert!(frame.contains("burnwall · live"));
        assert!(frame.contains("today by model:"));
        assert!(frame.contains("anthropic/sonnet-4.6"));
    }
}
