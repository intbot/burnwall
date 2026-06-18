//! `burnwall pause` / `resume` / `allow-once` — the live escape hatch.
//!
//! Writes the auto-expiring state file in [`crate::bypass`]; the running proxy
//! picks it up on the very next request. No daemon restart, no AI-tool restart
//! — the agent's session and context survive, which is the whole point after a
//! false-positive block: `burnwall allow-once`, retry, done.

use clap::Args;

use crate::bypass;
use crate::term::Styler;

#[derive(Args, Debug)]
pub struct PauseArgs {
    /// How long to pause: `30s`, `5m`, `2h`, or bare seconds. Default 5m,
    /// capped at 24h (longer is `burnwall stop` territory).
    pub duration: Option<String>,
}

pub fn run_pause(args: PauseArgs) -> anyhow::Result<()> {
    let secs = match &args.duration {
        Some(d) => bypass::parse_duration(d).ok_or_else(|| {
            anyhow::anyhow!("could not parse duration {d:?} — use e.g. 30s, 5m, 2h")
        })?,
        None => bypass::DEFAULT_PAUSE_SECS,
    };
    let clamped = secs.min(bypass::MAX_PAUSE_SECS);
    let now = chrono::Utc::now().timestamp();
    let expires_at = bypass::pause_for(clamped, now)?;

    let sty = Styler::stdout();
    let until = chrono::Local::now() + chrono::Duration::seconds(clamped as i64);
    println!(
        "{} all traffic relays UNCHECKED — no security scan, no budget check, no cost capture.",
        sty.yellow("⏸  Protection paused —")
    );
    println!(
        "   Auto-resumes in {} (at {}). Restore early:  burnwall resume",
        crate::ribbon::human_duration(expires_at - now),
        until.format("%H:%M")
    );
    if clamped < secs {
        println!("   (requested duration capped at 24h)");
    }
    if !proxy_seems_alive() {
        println!(
            "   {} the proxy isn't running — the pause takes effect when it starts.",
            sty.orange("note:")
        );
    }
    Ok(())
}

pub fn run_resume() -> anyhow::Result<()> {
    let sty = Styler::stdout();
    if bypass::clear()? {
        println!(
            "{} every request is scanned again.",
            sty.green("🟢 Protection resumed —")
        );
    } else {
        println!("Protection was not paused — nothing to do.");
    }
    Ok(())
}

pub fn run_allow_once() -> anyhow::Result<()> {
    let now = chrono::Utc::now().timestamp();
    bypass::arm_allow_once(now)?;
    let sty = Styler::stdout();
    println!(
        "{} the NEXT request through the proxy relays unchecked, then protection restores itself.",
        sty.yellow("⏸  Allow-once armed —")
    );
    println!(
        "   Retry the blocked request now. Unused, this expires in {}; disarm with:  burnwall resume",
        crate::ribbon::human_duration(bypass::ALLOW_ONCE_TTL_SECS as i64)
    );
    if !proxy_seems_alive() {
        println!(
            "   {} the proxy isn't running — start it with `burnwall start`.",
            sty.orange("note:")
        );
    }
    Ok(())
}

/// Best-effort liveness probe of the configured proxy port, so pausing a dead
/// proxy doesn't read as success. Any config error just skips the note.
fn proxy_seems_alive() -> bool {
    let port = crate::config::default_path()
        .ok()
        .and_then(|p| crate::config::load_or_default(&p).ok())
        .map(|c| c.proxy.port)
        .unwrap_or(4100);
    crate::cli::routing::proxy_port_alive(port, std::time::Duration::from_millis(150))
}
