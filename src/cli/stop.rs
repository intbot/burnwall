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
}

pub fn run_cmd(args: StopArgs) -> anyhow::Result<()> {
    // Check before `running_pid()` cleans up a stale file, so we can tell
    // "nothing was running" apart from "a stale PID file was left behind".
    let had_pid_file = daemon::pid_file_path()?.exists();

    match daemon::running_pid()? {
        Some(pid) => {
            daemon::terminate_process(pid)?;

            // Give it a moment to wind down so we can report the real outcome.
            let deadline = Instant::now() + Duration::from_secs(3);
            while daemon::process_is_alive(pid) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(50));
            }

            daemon::remove_pid_file().ok();

            if daemon::process_is_alive(pid) {
                println!("Sent stop signal to Burnwall (PID {pid}); it has not exited yet.");
            } else {
                println!("Stopped Burnwall (PID {pid}).");
            }
        }
        None => {
            if had_pid_file {
                println!("Burnwall is not running (removed a stale PID file).");
            } else {
                println!("Burnwall is not running.");
            }
        }
    }

    if !args.keep_routing {
        pause_and_report();
    }
    Ok(())
}

/// Pause shell routing (active env files → paused stub) and tell the user
/// what changed and how to clean already-open shells. Failures warn rather
/// than error — the proxy is already down; routing cleanup must not turn
/// that into a failure. Also called by a foreground `start` on its way out.
pub(crate) fn pause_and_report() {
    let paused = match routing::pause_routing() {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("could not pause shell routing: {e}");
            return;
        }
    };
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
        sty.yellow("⚠  Terminals already open still have ANTHROPIC_BASE_URL set —")
    );
    println!("      AI tools there will fail to connect until you restart them or run:");
    if let Some(shell) = Shell::detect() {
        println!("        {}", sty.bold(routing::manual_unset_hint(shell)));
    }
}
