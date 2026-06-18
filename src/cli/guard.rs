//! `burnwall guard` — a lightweight watchdog that keeps a dead proxy from
//! silently stranding routed shells.
//!
//! The liveness-gated routing protects a shell at the moment it STARTS (it
//! only exports the proxy URL if the port answers). But a shell already open
//! when the proxy dies stays routed at a now-dead port, and the persistent
//! env file keeps telling *new* shells to route until something flips it.
//! `guard` closes that window: it watches the proxy port and, once it has
//! been dead for a few checks while routing is still Active, **pauses
//! routing** so every new shell goes direct. When the proxy comes back, a
//! normal `burnwall start` resumes routing — so the guard only ever relaxes
//! toward "go direct" (fail-open) and never blocks the user.
//!
//! It deliberately does NOT restart the proxy by default: if the cause is an
//! antivirus quarantine of the binary, a restart loop would just fight the
//! AV. Pausing routing is the safe, sufficient action. (`--restart` opts into
//! a best-effort relaunch for users who want it.)
//!
//! Run it standalone (`burnwall guard`) or alongside the login service.

use std::time::Duration;

use anyhow::Result;
use clap::Args;

use crate::config;

use super::init::Shell;
use super::routing;

#[derive(Args, Debug)]
pub struct GuardArgs {
    /// Seconds between checks.
    #[arg(long, default_value_t = 5)]
    pub interval: u64,
    /// Consecutive dead-proxy checks before routing is paused (debounces a
    /// momentary blip such as a fast restart).
    #[arg(long, default_value_t = 3)]
    pub threshold: u32,
    /// Run a single check and exit (for cron / testing) instead of looping.
    #[arg(long)]
    pub once: bool,
    /// Best-effort: also try to relaunch the proxy when it is found dead.
    /// Off by default — a quarantined binary would just restart-loop.
    #[arg(long)]
    pub restart: bool,
}

/// What the watchdog should do this tick, decided purely from observable
/// state so it can be unit-tested without a clock or sockets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardAction {
    /// Routing isn't active anywhere — nothing to protect.
    Idle,
    /// Routing active and the proxy is healthy — keep watching.
    Healthy,
    /// Routing active, proxy dead, but under the streak threshold — wait
    /// (debounce a momentary blip).
    Watching,
    /// Proxy has been dead long enough while routing is active — pause routing.
    PauseRouting,
}

/// Pure decision for one tick. `dead_streak` is the count of consecutive
/// dead-proxy observations INCLUDING this tick (0 when the proxy is up).
pub fn decide(
    routing_active: bool,
    proxy_alive: bool,
    dead_streak: u32,
    threshold: u32,
) -> GuardAction {
    if !routing_active {
        return GuardAction::Idle;
    }
    if proxy_alive {
        return GuardAction::Healthy;
    }
    if dead_streak >= threshold {
        GuardAction::PauseRouting
    } else {
        GuardAction::Watching
    }
}

/// True if any shell's env file is actively routing (carries the exports).
fn any_routing_active() -> bool {
    Shell::ALL.iter().any(|s| routing::routing_active(*s))
}

pub async fn run_cmd(args: GuardArgs) -> Result<()> {
    let port = config::default_path()
        .ok()
        .and_then(|p| config::load_or_default(&p).ok())
        .map(|c| c.proxy.port)
        .unwrap_or(4100);

    let threshold = args.threshold.max(1);
    let interval = Duration::from_secs(args.interval.max(1));
    let mut dead_streak: u32 = 0;

    tracing::info!(
        "🛡 guard watching proxy port {port} (interval {}s, threshold {})",
        interval.as_secs(),
        threshold
    );

    loop {
        let routing_active = any_routing_active();
        let proxy_alive = routing::proxy_port_alive(port, Duration::from_millis(300));
        dead_streak = if proxy_alive {
            0
        } else {
            dead_streak.saturating_add(1)
        };

        match decide(routing_active, proxy_alive, dead_streak, threshold) {
            GuardAction::PauseRouting => {
                match routing::pause_routing_unless_alive() {
                    Ok(o) if !o.paused.is_empty() => {
                        tracing::warn!(
                            "proxy on port {port} has been dead for {dead_streak} checks — paused routing for {} shell(s); new terminals now go direct",
                            o.paused.len()
                        );
                    }
                    Ok(_) => {}
                    Err(e) => tracing::error!("guard could not pause routing: {e}"),
                }
                dead_streak = 0; // acted; don't repeat every tick
                if args.restart {
                    try_restart();
                }
            }
            GuardAction::Watching => {
                tracing::debug!("proxy dead ({dead_streak}/{threshold}) — watching");
            }
            GuardAction::Healthy | GuardAction::Idle => {}
        }

        if args.once {
            return Ok(());
        }
        tokio::time::sleep(interval).await;
    }
}

/// Best-effort relaunch of the daemon (`--restart`). Failures are logged, not
/// fatal — the guard's primary job (pausing routing) already happened.
fn try_restart() {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    match std::process::Command::new(exe)
        .args(["start", "--daemon"])
        .status()
    {
        Ok(s) if s.success() => tracing::info!("guard relaunched the proxy"),
        _ => tracing::warn!("guard could not relaunch the proxy (binary missing? quarantined?)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decide_covers_every_state() {
        let t = 3;
        // No routing → never act, regardless of proxy state.
        assert_eq!(decide(false, false, 99, t), GuardAction::Idle);
        assert_eq!(decide(false, true, 0, t), GuardAction::Idle);
        // Routing + healthy proxy → keep watching, no action.
        assert_eq!(decide(true, true, 0, t), GuardAction::Healthy);
        // Routing + dead proxy, under threshold → debounce.
        assert_eq!(decide(true, false, 1, t), GuardAction::Watching);
        assert_eq!(decide(true, false, 2, t), GuardAction::Watching);
        // Routing + dead proxy, at/over threshold → pause routing.
        assert_eq!(decide(true, false, 3, t), GuardAction::PauseRouting);
        assert_eq!(decide(true, false, 9, t), GuardAction::PauseRouting);
    }

    #[test]
    fn threshold_of_one_pauses_on_first_dead_check() {
        assert_eq!(decide(true, false, 1, 1), GuardAction::PauseRouting);
    }
}
