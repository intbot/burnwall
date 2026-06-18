//! `burnwall stop` — terminate the running proxy and pause shell routing.
//!
//! Finds the daemon via its PID file, asks it to terminate (SIGTERM on
//! Unix, which the proxy catches for a graceful shutdown; a hard kill on
//! Windows), then clears the PID file.
//!
//! Routing follows the proxy lifecycle: with the proxy down, an env file
//! still exporting `ANTHROPIC_BASE_URL` strands every new shell on a dead
//! port (`ConnectionRefused` from every AI tool). So `stop` pauses routing —
//! distinct from `disable-routing`'s explicit stub, so `start` knows to turn
//! it back on. `--keep-routing` opts out. The pause runs even when no proxy
//! was found: a crashed daemon leaves routing active too.

use std::time::{Duration, Instant};

use clap::Args;

use super::daemon;
use super::init::Shell;
use super::routing;
use crate::term::Styler;

#[derive(Args, Debug)]
pub struct StopArgs {
    /// Leave shell routing untouched (new shells will keep pointing at the
    /// stopped proxy until `burnwall start` runs again).
    #[arg(long)]
    pub keep_routing: bool,
    /// Terminate the proxy immediately and free the port, instead of leaving
    /// it up as a pass-through relay for already-running tools. Cuts in-flight
    /// requests and will make any tool still routed here fail to connect until
    /// it's restarted. The default (soft) stop avoids that.
    #[arg(long)]
    pub hard: bool,
}

pub fn run_cmd(args: StopArgs) -> anyhow::Result<()> {
    // Check before `running_pid()` cleans up a stale file, so we can tell
    // "nothing was running" apart from "a stale PID file was left behind".
    let had_pid_file = daemon::pid_file_path()?.exists();

    // Retire the guard watchdog: `stop` means we're done. A soft stop's drain
    // is self-retiring and a hard stop pauses routing itself, so a lingering
    // guard would only loop pointlessly (or fight a deliberate stop).
    daemon::stop_guard();

    match daemon::running_pid()? {
        // Soft stop (default): don't vacate the port. Flip the running proxy
        // into drain (relay-only) mode and leave it serving so an
        // already-running AI tool — which froze the proxy URL at launch and
        // can't be repointed — keeps working instead of hitting a dead port.
        // The proxy retires itself once traffic goes idle (then routing's
        // liveness gate sends new shells direct). This is the fix for the
        // "stop wedged my running tool with ConnectionRefused" failure.
        Some(pid) if !args.hard => return soft_stop(pid),
        // `--hard`: terminate now and free the port (cuts in-flight requests).
        Some(pid) => {
            hard_stop(pid);
            if !args.keep_routing {
                pause_and_report();
            }
        }
        None => {
            if had_pid_file {
                println!("Burnwall is not running (removed a stale PID file).");
            } else {
                println!("Burnwall is not running.");
            }
            if !args.keep_routing {
                pause_and_report();
            }
        }
    }
    Ok(())
}

/// Soft stop: flip the running proxy into drain (relay-only) mode and leave it
/// up. Already-running tools keep working (unprotected); the proxy retires
/// itself once traffic goes idle, freeing the port — at which point routing's
/// liveness gate sends new shells direct. Never cuts an in-flight request, and
/// `stop` → `start` re-arms protection (a fresh `start` retires the drainer).
fn soft_stop(pid: u32) -> anyhow::Result<()> {
    use anyhow::Context;
    crate::bypass::drain(chrono::Utc::now().timestamp())
        .context("could not enter drain mode — run `burnwall stop --hard` to terminate instead")?;
    let sty = Styler::stdout();
    println!(
        "{} the proxy (PID {pid}) now relays as a pass-through — no security scan, no budget check, no cost capture.",
        sty.yellow("⏹  Protection stopped —")
    );
    println!(
        "   Already-running AI tools keep working; the proxy retires itself once traffic goes idle."
    );
    println!(
        "   Free the port now (cuts in-flight requests):  {}",
        sty.bold("burnwall stop --hard")
    );
    println!("   Turn protection back on:  {}", sty.bold("burnwall start"));
    Ok(())
}

/// Hard stop: ask the daemon to shut down gracefully (drain in-flight requests,
/// up to ~10s), escalate to a kill if it doesn't wind down, and free the port.
/// A hard kill cuts every active agent turn mid-stream — the user's AI tool
/// sees a bare "socket closed unexpectedly" instead of a finished response —
/// so the graceful request goes first.
fn hard_stop(pid: u32) {
    let graceful_requested = daemon::request_graceful_shutdown(pid).is_ok();
    if !graceful_requested {
        let _ = daemon::terminate_process(pid);
    }

    // An idle daemon exits within one poll tick; one that is draining can take
    // up to the drain window. Tell the user why we're waiting once it's clearly
    // not the quick case.
    let started = Instant::now();
    let deadline = started + Duration::from_secs(13);
    let mut announced_drain = false;
    while daemon::process_is_alive(pid) && Instant::now() < deadline {
        if graceful_requested && !announced_drain && started.elapsed() > Duration::from_secs(2) {
            println!("   draining in-flight requests (up to 10s)…");
            announced_drain = true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    if daemon::process_is_alive(pid) {
        // Drain window blown (or graceful never landed) — hard kill.
        let _ = daemon::terminate_process(pid);
        let kill_deadline = Instant::now() + Duration::from_secs(3);
        while daemon::process_is_alive(pid) && Instant::now() < kill_deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    daemon::remove_pid_file().ok();
    daemon::clear_shutdown_file();
    // The proxy is gone for good — clear any drain/pause so a future `start`
    // doesn't boot into relay-only mode.
    let _ = crate::bypass::clear();

    if daemon::process_is_alive(pid) {
        println!("Sent stop signal to Burnwall (PID {pid}); it has not exited yet.");
    } else {
        println!("Stopped Burnwall (PID {pid}).");
    }
}

/// Pause shell routing (active env files → paused stub) and tell the user
/// what changed and how to clean already-open shells. Failures warn rather
/// than error — the proxy is already down; routing cleanup must not turn
/// that into a failure. Also called by a foreground `start` on its way out
/// and by `upgrade`.
///
/// Guarded per env file: a file whose routed port is STILL serving belongs
/// to a proxy that is still up — a second instance this stop/exit didn't
/// own — and is left routed (pausing it would strand new shells away from a
/// live proxy). Single-instance flows are unchanged: the stopped proxy's
/// port is dead by the time this runs, so its file pauses as before.
pub(crate) fn pause_and_report() {
    let outcome = match routing::pause_routing_unless_alive() {
        Ok(o) => o,
        Err(e) => {
            tracing::warn!("could not pause shell routing: {e}");
            return;
        }
    };
    for port in &outcome.left_alive {
        println!(
            "Routing untouched — port {port} is still serving (another Burnwall instance). New shells keep routing through it."
        );
    }
    let paused = outcome.paused;
    if paused.is_empty() {
        return;
    }
    let sty = Styler::stdout();
    println!(
        "{}",
        sty.yellow("🛡  Routing paused — new shells will go direct to providers.")
    );
    for path in &paused {
        println!(
            "   env file emptied: {}",
            sty.blue(&path.display().to_string())
        );
    }
    println!("   `burnwall start` re-enables routing automatically.");
    println!();
    println!(
        "   {}",
        sty.yellow("⚠  AI tools already running still point at the stopped proxy and will fail to connect.")
    );
    println!(
        "      Bring it back —  {}  — and they recover instantly,",
        sty.bold("burnwall start")
    );
    println!(
        "      or go direct with  {}  and restart those tools.",
        sty.bold("burnwall recover")
    );
    if let Some(shell) = Shell::detect() {
        println!(
            "      (Drop the vars from THIS shell:  {})",
            sty.bold(routing::manual_unset_hint(shell))
        );
    }
}
