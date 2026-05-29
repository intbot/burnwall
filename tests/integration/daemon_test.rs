//! Daemon lifecycle tests: PID file handling, process-liveness checks, and
//! the end-to-end `start --daemon` / `stop` round trip via the real binary.
//!
//! Tests that exercise the PID-file helpers in-process must agree on the
//! data directory, which is selected by the process-global
//! `BURNWALL_DATA_DIR` env var — so those are serialized behind `ENV_LOCK`.
//! The subprocess tests pass the data dir explicitly via `.env(...)` and
//! verify state by reading the PID file path directly, so they need no lock.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use assert_cmd::Command;
use burnwall::cli::daemon;
use predicates::prelude::*;

static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Run `f` with `BURNWALL_DATA_DIR` pointed at a fresh tempdir, serialized
/// against other env-dependent tests.
fn with_data_dir<T>(f: impl FnOnce(&Path) -> T) -> T {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    // TODO: Audit that the environment access only happens in single-threaded code.
    unsafe { std::env::set_var("BURNWALL_DATA_DIR", dir.path()) };
    let result = f(dir.path());
    // TODO: Audit that the environment access only happens in single-threaded code.
    unsafe { std::env::remove_var("BURNWALL_DATA_DIR") };
    result
}

fn burnwall(data_dir: &Path) -> Command {
    let mut cmd = Command::cargo_bin("burnwall").expect("binary");
    cmd.env("BURNWALL_DATA_DIR", data_dir);
    cmd
}

/// Best-effort kill of a leaked daemon if a test panics before `stop`.
struct DaemonCleanup(PathBuf);
impl Drop for DaemonCleanup {
    fn drop(&mut self) {
        if let Ok(contents) = fs::read_to_string(&self.0) {
            if let Ok(pid) = contents.trim().parse::<u32>() {
                let _ = daemon::terminate_process(pid);
            }
        }
        let _ = fs::remove_file(&self.0);
    }
}

fn wait_until_gone(pid: u32) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while daemon::process_is_alive(pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    !daemon::process_is_alive(pid)
}

// ───────────────────────── process liveness (pure) ─────────────────────────

#[test]
fn process_is_alive_for_the_current_process() {
    assert!(daemon::process_is_alive(std::process::id()));
}

#[test]
fn process_is_alive_false_for_a_bogus_pid() {
    // Far above any real PID on Linux (pid_max) / Windows.
    assert!(!daemon::process_is_alive(999_999_999));
}

// ───────────────────────────── PID file helpers ────────────────────────────

#[test]
fn pid_file_write_read_remove_roundtrip() {
    with_data_dir(|_| {
        assert_eq!(daemon::read_pid_file().unwrap(), None);

        daemon::write_pid_file(4242).unwrap();
        assert_eq!(daemon::read_pid_file().unwrap(), Some(4242));

        daemon::remove_pid_file().unwrap();
        assert_eq!(daemon::read_pid_file().unwrap(), None);

        // Removing an already-absent file is not an error.
        daemon::remove_pid_file().unwrap();
    });
}

#[test]
fn read_pid_file_discards_corrupt_contents() {
    with_data_dir(|dir| {
        let pid_file = dir.join("burnwall.pid");
        fs::write(&pid_file, "not-a-pid").unwrap();

        assert_eq!(daemon::read_pid_file().unwrap(), None);
        assert!(
            !pid_file.exists(),
            "a corrupt PID file is discarded on read"
        );
    });
}

#[test]
fn read_pid_file_rejects_zero() {
    with_data_dir(|dir| {
        fs::write(dir.join("burnwall.pid"), "0").unwrap();
        assert_eq!(daemon::read_pid_file().unwrap(), None);
    });
}

#[test]
fn running_pid_clears_a_stale_file() {
    with_data_dir(|dir| {
        let pid_file = dir.join("burnwall.pid");
        fs::write(&pid_file, "999999999").unwrap();

        assert_eq!(daemon::running_pid().unwrap(), None);
        assert!(!pid_file.exists(), "a stale PID file is cleared");
    });
}

#[test]
fn running_pid_reports_a_live_process() {
    with_data_dir(|_| {
        let me = std::process::id();
        daemon::write_pid_file(me).unwrap();
        assert_eq!(daemon::running_pid().unwrap(), Some(me));
    });
}

// ───────────────────────────── stop, no daemon ─────────────────────────────

#[test]
fn stop_when_not_running_says_so() {
    let dir = tempfile::tempdir().unwrap();
    burnwall(dir.path())
        .arg("stop")
        .assert()
        .success()
        .stdout(predicate::str::contains("Burnwall is not running"));
}

#[test]
fn stop_removes_a_stale_pid_file() {
    let dir = tempfile::tempdir().unwrap();
    let pid_file = dir.path().join("burnwall.pid");
    fs::write(&pid_file, "999999999").unwrap();

    burnwall(dir.path())
        .arg("stop")
        .assert()
        .success()
        .stdout(predicate::str::contains("stale PID file"));

    assert!(!pid_file.exists(), "stop clears the stale PID file");
}

// ──────────────────────── full start --daemon / stop ───────────────────────

#[test]
fn start_daemon_then_stop_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let pid_file = dir.path().join("burnwall.pid");

    // Port 0 lets the OS pick a free port — the test never connects, it only
    // exercises the daemon lifecycle.
    burnwall(dir.path())
        .args(["start", "--daemon", "--port", "0"])
        .assert()
        .success()
        .stdout(predicate::str::contains("running in the background"));

    let _cleanup = DaemonCleanup(pid_file.clone());

    assert!(
        pid_file.exists(),
        "the daemon writes its PID file once it is serving"
    );
    let pid: u32 = fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .expect("PID file holds a number");
    assert!(
        daemon::process_is_alive(pid),
        "the daemon process is running"
    );

    burnwall(dir.path())
        .arg("stop")
        .assert()
        .success()
        .stdout(predicate::str::contains("Stopped Burnwall"));

    assert!(!pid_file.exists(), "stop clears the PID file");
    assert!(wait_until_gone(pid), "the daemon process exits after stop");
}

#[test]
fn start_daemon_refuses_when_already_running() {
    let dir = tempfile::tempdir().unwrap();
    let pid_file = dir.path().join("burnwall.pid");

    burnwall(dir.path())
        .args(["start", "--daemon", "--port", "0"])
        .assert()
        .success();

    let _cleanup = DaemonCleanup(pid_file.clone());

    // A second daemon must not start on top of the first.
    burnwall(dir.path())
        .args(["start", "--daemon", "--port", "0"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already running"));

    // A foreground start refuses too (the check runs before the accept loop,
    // so this exits instead of blocking).
    burnwall(dir.path())
        .args(["start", "--port", "0"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already running"));

    burnwall(dir.path()).arg("stop").assert().success();
}
