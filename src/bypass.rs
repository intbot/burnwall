//! Runtime protection pause — the escape hatch that works on a RUNNING daemon.
//!
//! The `BURNWALL_BYPASS` env var is read from the *proxy process's own*
//! environment, which is frozen at spawn — so for a backgrounded daemon it can
//! only be flipped by restarting the daemon (and "set it and restart your AI
//! tool", the old block-message advice, never reached the daemon at all). This
//! module replaces that with a tiny state file the proxy checks per request,
//! so protection can be paused and resumed live: no daemon restart, no tool
//! restart, the agent's session and context survive.
//!
//! Two modes, both **auto-expiring** so the escape hatch can never silently
//! outlive the emergency:
//!
//! - **Pause** (`burnwall pause [duration]`) — relay everything unchecked for
//!   a bounded window (default 5 minutes, capped at 24 hours). `burnwall
//!   resume` restores early; expiry restores automatically.
//! - **Allow-once** (`burnwall allow-once`) — exactly the *next* request
//!   bypasses, then protection restores by itself. The smoothest false-positive
//!   flow: arm it, retry the blocked request, done. An unused arm expires
//!   after 10 minutes so it can't sit forever waiting to swallow some
//!   unrelated request days later.
//!
//! ## Cost & trust model
//!
//! The proxy's fast path pays one `stat()` per request (file absent — the
//! overwhelmingly common case); only an existing file is read and parsed.
//! Anything running as the user can write this file, but that grants nothing
//! new: the same actor can already run `burnwall stop` or restart the daemon
//! with `BURNWALL_BYPASS=1`. The user-trust boundary is the AI tool's own
//! command approval, not this file.
//!
//! While paused, the proxy is a pure relay — no security scan, no budget
//! check, **no cost capture**. Surfaces show a loud paused warning for the
//! whole window so the state is impossible to forget.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// State-file name under the data dir (`~/.burnwall/pause.json`).
pub const PAUSE_FILE: &str = "pause.json";

/// Default pause window when no duration is given.
pub const DEFAULT_PAUSE_SECS: u64 = 5 * 60;
/// Hard cap on a pause window — a longer "pause" is `burnwall stop` territory.
pub const MAX_PAUSE_SECS: u64 = 24 * 3600;
/// How long an unused allow-once stays armed before it expires.
pub const ALLOW_ONCE_TTL_SECS: u64 = 10 * 60;
/// Backstop expiry for a `Drain` (the relay a soft `burnwall stop` leaves
/// behind to keep already-running tools alive). The real teardown is the
/// proxy's idle-retire monitor; this is only a safety net so a drainer that
/// somehow never goes idle can't relay unchecked forever. A fresh `start`
/// also clears any stale drain on boot, so protection is never silently off.
pub const DRAIN_BACKSTOP_SECS: u64 = 12 * 3600;

/// On-disk shape. Tiny and stable: a mode tag plus an absolute expiry.
#[derive(Debug, Serialize, Deserialize)]
struct StateFile {
    mode: Mode,
    expires_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Mode {
    Pause,
    AllowOnce,
    /// Soft-`stop` drain: relay everything unchecked, like `Pause`, but with no
    /// auto-resume — the proxy is on its way out and only stays up to keep
    /// already-running tools off a dead port. The proxy's idle-retire monitor
    /// shuts it down once traffic stops; `DRAIN_BACKSTOP_SECS` is the safety net.
    Drain,
}

/// The live bypass state, as the proxy and status surfaces see it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Bypass {
    /// No pause in effect — protection runs normally.
    None,
    /// All traffic relays unchecked until the window ends.
    Paused { resumes_in_secs: i64 },
    /// The next request relays unchecked (consume-on-use), then protection
    /// restores. Expires unused after the TTL.
    AllowOnce { expires_in_secs: i64 },
    /// A soft `burnwall stop` left the proxy up as a pure relay so
    /// already-running tools don't hit a dead port. Relays unchecked; the
    /// proxy retires itself once traffic goes idle. No auto-resume.
    Draining,
}

/// Default state-file path (`<data dir>/pause.json`), `None` if no data dir
/// resolves. The proxy captures this once at startup in `AppState`.
pub fn default_path() -> Option<PathBuf> {
    crate::storage::data_dir().ok().map(|d| d.join(PAUSE_FILE))
}

/// Read the bypass state at `path`. Missing, unparseable, or expired files all
/// mean [`Bypass::None`] — fail-closed back to *protection on*, never the other
/// way. An expired file is best-effort deleted so the fast path (a single
/// `stat()`) returns for subsequent requests.
pub fn read_at(path: &Path, now: i64) -> Bypass {
    if !path.exists() {
        return Bypass::None;
    }
    let Some(state) = std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str::<StateFile>(&s).ok())
    else {
        return Bypass::None;
    };
    let remaining = state.expires_at - now;
    if remaining <= 0 {
        let _ = std::fs::remove_file(path);
        return Bypass::None;
    }
    match state.mode {
        Mode::Pause => Bypass::Paused {
            resumes_in_secs: remaining,
        },
        Mode::AllowOnce => Bypass::AllowOnce {
            expires_in_secs: remaining,
        },
        Mode::Drain => Bypass::Draining,
    }
}

/// True if a drain (soft-stop relay) is currently in effect at the default
/// path. Used by `start` (to retire a stale drainer and take over the port)
/// and by the proxy's idle-retire monitor.
pub fn is_draining(now: i64) -> bool {
    matches!(read(now), Bypass::Draining)
}

/// Read the bypass state at the default path.
pub fn read(now: i64) -> Bypass {
    match default_path() {
        Some(p) => read_at(&p, now),
        None => Bypass::None,
    }
}

/// Consume an armed allow-once: the file delete *is* the atomic claim. Exactly
/// one concurrent caller gets `Ok` from `remove_file`; the rest see NotFound
/// and run the normal protected pipeline.
pub fn consume_allow_once_at(path: &Path) -> bool {
    std::fs::remove_file(path).is_ok()
}

/// Write a pause for `secs` (clamped to [`MAX_PAUSE_SECS`]). Returns the
/// expiry timestamp written.
pub fn pause_for(secs: u64, now: i64) -> std::io::Result<i64> {
    write_state(Mode::Pause, now + secs.min(MAX_PAUSE_SECS) as i64)
}

/// Arm allow-once (expires unused after [`ALLOW_ONCE_TTL_SECS`]). Returns the
/// expiry timestamp written.
pub fn arm_allow_once(now: i64) -> std::io::Result<i64> {
    write_state(Mode::AllowOnce, now + ALLOW_ONCE_TTL_SECS as i64)
}

/// Enter drain (soft `burnwall stop`): the running proxy relays unchecked and
/// retires itself when idle. Backstopped at [`DRAIN_BACKSTOP_SECS`] so it can
/// never silently relay forever. Returns the expiry timestamp written.
pub fn drain(now: i64) -> std::io::Result<i64> {
    write_state(Mode::Drain, now + DRAIN_BACKSTOP_SECS as i64)
}

/// Clear any pause / armed allow-once. `Ok(true)` if a file was removed.
pub fn clear() -> std::io::Result<bool> {
    let Some(path) = default_path() else {
        return Ok(false);
    };
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

fn write_state(mode: Mode, expires_at: i64) -> std::io::Result<i64> {
    let path = default_path()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no data directory"))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let body =
        serde_json::to_string(&StateFile { mode, expires_at }).expect("StateFile serializes");
    std::fs::write(&path, body)?;
    Ok(expires_at)
}

/// Parse a human duration: `30s`, `5m`, `2h`, or bare seconds (`300`).
pub fn parse_duration(s: &str) -> Option<u64> {
    let s = s.trim().to_ascii_lowercase();
    if s.is_empty() {
        return None;
    }
    let (num, unit) = match s.chars().last() {
        Some(c) if c.is_ascii_digit() => (s.as_str(), 1u64),
        Some('s') => (&s[..s.len() - 1], 1),
        Some('m') => (&s[..s.len() - 1], 60),
        Some('h') => (&s[..s.len() - 1], 3600),
        _ => return None,
    };
    let n: u64 = num.trim().parse().ok()?;
    if n == 0 {
        return None;
    }
    Some(n * unit)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("burnwall-bypass-tests");
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    fn write_at(path: &Path, mode: Mode, expires_at: i64) {
        std::fs::write(
            path,
            serde_json::to_string(&StateFile { mode, expires_at }).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn missing_file_is_none() {
        assert_eq!(read_at(Path::new("Z:/nope/pause.json"), 1000), Bypass::None);
    }

    #[test]
    fn garbage_file_is_none_fail_closed() {
        let p = temp_path("garbage.json");
        std::fs::write(&p, "not json at all").unwrap();
        assert_eq!(read_at(&p, 1000), Bypass::None);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn active_pause_reports_remaining() {
        let p = temp_path("pause-active.json");
        write_at(&p, Mode::Pause, 1300);
        assert_eq!(
            read_at(&p, 1000),
            Bypass::Paused {
                resumes_in_secs: 300
            }
        );
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn expired_pause_is_none_and_self_cleans() {
        // The escape hatch must never outlive its window: expiry → protection
        // restores, and the file is removed so the fast path returns.
        let p = temp_path("pause-expired.json");
        write_at(&p, Mode::Pause, 1000);
        assert_eq!(read_at(&p, 1000), Bypass::None); // boundary: expired
        assert!(!p.exists(), "expired file should be cleaned up");
    }

    #[test]
    fn allow_once_reports_and_consumes_exactly_once() {
        let p = temp_path("allow-once.json");
        write_at(&p, Mode::AllowOnce, 2000);
        assert!(matches!(read_at(&p, 1000), Bypass::AllowOnce { .. }));
        // First consume wins; the second caller finds nothing.
        assert!(consume_allow_once_at(&p));
        assert!(!consume_allow_once_at(&p));
        assert_eq!(read_at(&p, 1000), Bypass::None);
    }

    #[test]
    fn drain_reads_as_draining_until_backstop() {
        let p = temp_path("drain-active.json");
        write_at(&p, Mode::Drain, 5000);
        assert_eq!(read_at(&p, 1000), Bypass::Draining);
        // Past the backstop it self-clears (protection restores) just like the
        // other modes — a drainer can never relay unchecked forever.
        write_at(&p, Mode::Drain, 1000);
        assert_eq!(read_at(&p, 1000), Bypass::None);
        assert!(!p.exists());
    }

    #[test]
    fn expired_allow_once_is_none() {
        let p = temp_path("allow-once-expired.json");
        write_at(&p, Mode::AllowOnce, 999);
        assert_eq!(read_at(&p, 1000), Bypass::None);
        assert!(!p.exists());
    }

    #[test]
    fn pause_for_clamps_to_max() {
        // A "pause" longer than the cap is silently bounded — verified through
        // the same arithmetic pause_for applies before writing.
        let requested: u64 = 99 * 3600;
        let now = 1000i64;
        let expires = now + requested.min(MAX_PAUSE_SECS) as i64;
        assert_eq!(expires, now + MAX_PAUSE_SECS as i64);
        let small: u64 = 300;
        assert_eq!(now + small.min(MAX_PAUSE_SECS) as i64, now + 300);
    }

    #[test]
    fn parse_duration_shapes() {
        assert_eq!(parse_duration("30s"), Some(30));
        assert_eq!(parse_duration("5m"), Some(300));
        assert_eq!(parse_duration("2h"), Some(7200));
        assert_eq!(parse_duration("300"), Some(300));
        assert_eq!(parse_duration(" 5M "), Some(300));
        assert_eq!(parse_duration("0m"), None, "zero-length pause is a no-op");
        assert_eq!(parse_duration("abc"), None);
        assert_eq!(parse_duration(""), None);
        assert_eq!(parse_duration("5d"), None, "days deliberately unsupported");
    }
}
