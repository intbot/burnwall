//! `burnwall stop` — terminate the running proxy.
//!
//! Finds the daemon via its PID file, asks it to terminate (SIGTERM on
//! Unix, which the proxy catches for a graceful shutdown; a hard kill on
//! Windows), then clears the PID file.

use std::time::{Duration, Instant};

use clap::Args;

use super::daemon;

#[derive(Args, Debug)]
pub struct StopArgs {}

pub fn run_cmd(_args: StopArgs) -> anyhow::Result<()> {
    // Check before `running_pid()` cleans up a stale file, so we can tell
    // "nothing was running" apart from "a stale PID file was left behind".
    let had_pid_file = daemon::pid_file_path()?.exists();

    let pid = match daemon::running_pid()? {
        Some(pid) => pid,
        None => {
            if had_pid_file {
                println!("Burnwall is not running (removed a stale PID file).");
            } else {
                println!("Burnwall is not running.");
            }
            return Ok(());
        }
    };

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
    Ok(())
}
