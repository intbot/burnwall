//! Daemon lifecycle helpers shared by `burnwall start --daemon` and
//! `burnwall stop`.
//!
//! Burnwall does not `fork()`. `--daemon` re-execs the binary as a detached
//! child (`setsid` on Unix, `DETACHED_PROCESS` on Windows), which sidesteps
//! the "fork() with a live Tokio runtime" hazard entirely — the child is a
//! fresh process that builds its own runtime.
//!
//! On Windows the spawn calls `CreateProcessW` directly with
//! `bInheritHandles = FALSE`. `std::process::Command` always sets it to
//! `TRUE` so it can wire up the requested stdio, but `TRUE` also means the
//! daemon inherits *every other* inheritable handle in the launcher — most
//! importantly, the stdout/stderr pipe write-ends that an
//! `assert_cmd`-style test harness opens to capture the launcher's output.
//! Because the daemon never exits, those pipe handles would stay open
//! forever and `cargo test`'s read on the capture pipe would never see
//! EOF, hanging the test long after the launcher itself returned cleanly.
//! Disabling inheritance is the fix.
//!
//! The running proxy owns its PID file: it writes `<data dir>/burnwall.pid`
//! once it has bound the port and removes it on graceful shutdown. `stop`
//! also removes the file after terminating, so a hard kill (Windows has no
//! graceful signal) does not leave it behind. A PID file whose process is
//! gone is treated as stale and cleaned up on sight.

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::Context;

use super::start::StartArgs;
use crate::storage::data_dir;

/// Absolute path to the PID file: `<data dir>/burnwall.pid`
/// (honors `BURNWALL_DATA_DIR`).
pub fn pid_file_path() -> anyhow::Result<PathBuf> {
    Ok(data_dir()
        .context("locating the Burnwall data directory")?
        .join("burnwall.pid"))
}

/// Read the PID recorded in the PID file.
///
/// `Ok(None)` if the file is missing or its contents are unusable (a
/// corrupt file is discarded on read). An error is returned only for a
/// genuine I/O failure.
pub fn read_pid_file() -> anyhow::Result<Option<u32>> {
    let path = pid_file_path()?;
    let contents = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading PID file {}", path.display())),
    };
    match contents.trim().parse::<u32>() {
        Ok(pid) if pid > 0 => Ok(Some(pid)),
        _ => {
            tracing::warn!("ignoring corrupt PID file {}", path.display());
            let _ = fs::remove_file(&path);
            Ok(None)
        }
    }
}

/// Write `pid` to the PID file, creating the data directory if needed.
///
/// The write goes to a temp file and is then renamed into place, so a
/// concurrent reader (the parent waiting on `--daemon`) never observes a
/// half-written file.
pub fn write_pid_file(pid: u32) -> anyhow::Result<()> {
    let path = pid_file_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating data directory {}", parent.display()))?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, pid.to_string())
        .with_context(|| format!("writing PID file {}", tmp.display()))?;
    fs::rename(&tmp, &path).with_context(|| format!("finalizing PID file {}", path.display()))?;
    Ok(())
}

/// Remove the PID file. A missing file is not an error.
pub fn remove_pid_file() -> anyhow::Result<()> {
    let path = pid_file_path()?;
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("removing PID file {}", path.display())),
    }
}

/// The PID of a live Burnwall daemon, if one is running.
///
/// Reads the PID file and confirms the process is still alive. A PID file
/// pointing at a dead process is stale — it is removed and `None` returned.
pub fn running_pid() -> anyhow::Result<Option<u32>> {
    match read_pid_file()? {
        Some(pid) if process_is_alive(pid) => Ok(Some(pid)),
        Some(_) => {
            remove_pid_file()?;
            Ok(None)
        }
        None => Ok(None),
    }
}

/// Decide whether a fresh `start` may proceed. Returns `Some(pid)` if a
/// fully-protecting proxy is already running — the caller must refuse to start a
/// second one. Returns `None` if the path is clear: either nothing was running,
/// or a DRAIN-only relay (left by a soft `burnwall stop` to keep already-running
/// tools alive) was retired here to free the port. Shared by the foreground
/// `start` and the `--daemon` launcher so `stop` → `start` re-arms protection
/// instead of failing "already running".
pub fn protecting_proxy_blocking_start() -> anyhow::Result<Option<u32>> {
    let Some(pid) = running_pid()? else {
        return Ok(None);
    };
    if !crate::bypass::is_draining(chrono::Utc::now().timestamp()) {
        return Ok(Some(pid)); // a real, protecting proxy — caller should bail
    }
    tracing::info!("retiring the draining proxy (PID {pid}) to start a protected one");
    let _ = request_graceful_shutdown(pid);
    let deadline = Instant::now() + Duration::from_secs(12);
    while process_is_alive(pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    if process_is_alive(pid) {
        let _ = terminate_process(pid);
    }
    remove_pid_file().ok();
    clear_shutdown_file();
    Ok(None)
}

// ───────────────────────── guard watchdog lifecycle ─────────────────────────
//
// `start --daemon` spawns a `burnwall guard` watchdog alongside the proxy
// (unless `--no-guard`). It outlives a proxy crash and auto-pauses routing so a
// silently-dead proxy (the classic Windows AV-quarantine case) can't keep
// stranding new shells. Tracked by its own PID file so `stop` can retire it and
// a second `start` doesn't stack duplicates.

/// Absolute path to the guard watchdog's PID file
/// (`<data dir>/burnwall.guard.pid`).
pub fn guard_pid_file_path() -> anyhow::Result<PathBuf> {
    Ok(data_dir()
        .context("locating the Burnwall data directory")?
        .join("burnwall.guard.pid"))
}

/// PID of a live guard watchdog, if one is running. A file pointing at a dead
/// (or reused, non-burnwall) PID is stale — removed, and `None` returned.
pub fn running_guard_pid() -> anyhow::Result<Option<u32>> {
    let path = guard_pid_file_path()?;
    let contents = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    match contents.trim().parse::<u32>() {
        Ok(pid) if pid > 0 && process_is_alive(pid) => Ok(Some(pid)),
        _ => {
            let _ = fs::remove_file(&path);
            Ok(None)
        }
    }
}

/// Spawn the guard watchdog as a detached process (if one isn't already
/// running) and record its PID. Best-effort restart of a crashed proxy is on
/// (`--restart`): the guard's primary action, pausing routing, always happens
/// first, so a quarantined binary fails the relaunch safely rather than
/// stranding shells. Returns the guard PID.
pub fn spawn_guard(port: u16) -> anyhow::Result<u32> {
    if let Some(pid) = running_guard_pid()? {
        return Ok(pid); // already watching
    }
    let exe = std::env::current_exe().context("locating the burnwall executable")?;
    let pid = spawn_detached(
        &exe,
        &[
            "guard".to_string(),
            "--port".to_string(),
            port.to_string(),
            "--restart".to_string(),
        ],
    )
    .context("spawning the guard watchdog")?;
    let path = guard_pid_file_path()?;
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(&path, pid.to_string());
    Ok(pid)
}

/// Retire the guard watchdog (called by `stop`): terminate it if running and
/// clear its PID file. Best-effort — a stop must never fail on guard cleanup.
pub fn stop_guard() {
    if let Ok(Some(pid)) = running_guard_pid() {
        let _ = terminate_process(pid);
    }
    if let Ok(path) = guard_pid_file_path() {
        let _ = fs::remove_file(path);
    }
}

/// How the previous daemon run ended, inferred at the next start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PriorExit {
    /// No evidence of an unclean prior exit (no leftover PID file).
    Clean,
    /// A PID file from a previous run was left behind with no live burnwall
    /// behind it: the last run was terminated WITHOUT running any cleanup —
    /// a crash, a forced kill, an **antivirus quarantine of the binary**, or
    /// an unclean shutdown/reboot. `consecutive` is how many starts in a row
    /// have seen this (a rising count is the signature of an AV repeatedly
    /// quarantining the binary, vs. a one-off reboot).
    Abnormal { consecutive: u32 },
}

/// Path to the consecutive-unclean-exit counter (`<data dir>/burnwall.crashes`).
fn crash_counter_path() -> anyhow::Result<PathBuf> {
    Ok(data_dir()
        .context("locating the Burnwall data directory")?
        .join("burnwall.crashes"))
}

fn read_crash_counter() -> u32 {
    crash_counter_path()
        .ok()
        .and_then(|p| fs::read_to_string(p).ok())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

fn write_crash_counter(n: u32) {
    if let Ok(p) = crash_counter_path() {
        if let Some(parent) = p.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(p, n.to_string());
    }
}

/// Inspect (and record) how the previous run ended, BEFORE the normal
/// stale-PID cleanup in [`running_pid`] erases the evidence. A leftover PID
/// file with no live burnwall behind it means the last run never ran its
/// shutdown path. Bumps the consecutive-occurrence counter on an unclean
/// exit so the caller can escalate its message when it keeps happening. Call
/// once, early in `start` (before `running_pid`). Idempotent within a start:
/// the daemon launcher removes the PID file before re-spawning, so the child
/// sees `Clean` and the count isn't double-bumped.
pub fn take_prior_exit_status() -> PriorExit {
    let stale = matches!(read_pid_file(), Ok(Some(pid)) if !process_is_alive(pid));
    if !stale {
        return PriorExit::Clean;
    }
    let consecutive = read_crash_counter().saturating_add(1);
    write_crash_counter(consecutive);
    PriorExit::Abnormal { consecutive }
}

/// Reset the unclean-exit counter — called after a clean shutdown so a single
/// healthy run clears the "this keeps crashing" escalation.
pub fn note_clean_exit() {
    write_crash_counter(0);
}

/// Re-exec `burnwall start` (without `--daemon`) as a detached background
/// process, then wait for it to write its PID file before returning.
pub async fn spawn_background(args: &StartArgs) -> anyhow::Result<()> {
    // A fully-protecting proxy blocks a second start; a soft-stop drain relay is
    // retired here so `stop` → `start --daemon` re-arms protection seamlessly.
    if let Some(pid) = protecting_proxy_blocking_start()? {
        anyhow::bail!(
            "Burnwall is already running (PID {pid}). Use `burnwall stop` to stop it first."
        );
    }
    // A leftover temp/stale file would confuse the readiness poll below.
    remove_pid_file()?;

    let exe = std::env::current_exe().context("locating the burnwall executable")?;
    let daemon_pid = spawn_detached(&exe, &child_args(args))
        .context("spawning the background burnwall process")?;

    // The child writes its PID file once it has bound the port and is
    // serving — that is the readiness signal. If the child exits before
    // then (e.g. the port is taken), surface it instead of hanging.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(pid) = read_pid_file()? {
            let sty = crate::term::Styler::stdout();
            println!(
                "{}",
                sty.green(&format!(
                    "\u{1f6e1}\u{fe0f}  Burnwall is running in the background (PID {pid})."
                ))
            );
            // The child was spawned with --no-routing: it is detached, so its
            // routing report would go nowhere. The launcher resumes routing
            // here instead, once the child is confirmed serving.
            if !args.no_routing {
                super::start::resume_and_report(&format!(
                    "http://localhost:{}",
                    resolved_port(args)
                ));
            }
            // Guard watchdog (default): outlives a proxy crash and auto-pauses
            // routing so a silently-dead proxy can't keep stranding new shells.
            // Opt out with `--no-guard`.
            if !args.no_guard {
                match spawn_guard(resolved_port(args)) {
                    Ok(gpid) => println!(
                        "   Watchdog: guard running (PID {gpid}) — auto-recovers routing if the proxy dies."
                    ),
                    Err(e) => tracing::warn!("could not start the guard watchdog: {e}"),
                }
            }
            // Name the log file so a later crash is diagnosable (L-H2) —
            // before this, a dead daemon left nothing to look at.
            if let Some(log) = resolved_child_log_path() {
                println!("   Logs:     {}", log.display());
            }
            println!("   Check it with `burnwall status`; stop it with `burnwall stop`.");
            return Ok(());
        }
        if !process_is_alive(daemon_pid) {
            anyhow::bail!(
                "the background process exited before it was ready. \
                 Run `burnwall start` in the foreground to see the error."
            );
        }
        if Instant::now() >= deadline {
            let _ = terminate_process(daemon_pid);
            anyhow::bail!(
                "the background process did not become ready within 5s. \
                 Run `burnwall start` in the foreground to see the error."
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Rebuild the `start` argument list for the child, dropping `--daemon`.
/// The child gets `--no-routing` (the launcher handles the resume and its
/// messaging after readiness) plus `--pause-routing-on-exit` so a *gracefully*
/// exiting daemon still pauses routing itself — `burnwall stop` covers the
/// normal path, but a child that shuts down without `stop` (SIGTERM from the
/// OS, session logout) must not strand Active env files (L-C1). Hard kills get
/// no cleanup anywhere — the liveness-gated env files cover that case.
fn child_args(args: &StartArgs) -> Vec<String> {
    let mut out = vec![
        "start".to_string(),
        "--no-routing".to_string(),
        "--pause-routing-on-exit".to_string(),
    ];
    if let Some(port) = args.port {
        out.push("--port".to_string());
        out.push(port.to_string());
    }
    if let Some(host) = &args.host {
        out.push("--host".to_string());
        out.push(host.clone());
    }
    out.push("--upstream-anthropic".to_string());
    out.push(args.upstream_anthropic.clone());
    out.push("--upstream-openai".to_string());
    out.push(args.upstream_openai.clone());
    out.push("--upstream-google".to_string());
    out.push(args.upstream_google.clone());
    if args.rewrite_anthropic_cache {
        out.push("--rewrite-anthropic-cache".to_string());
    }
    out
}

/// The log file the daemon child will write — same config resolution the
/// child itself performs.
fn resolved_child_log_path() -> Option<std::path::PathBuf> {
    let cfg = crate::config::default_path()
        .ok()
        .and_then(|p| crate::config::load_or_default(&p).ok())?;
    super::start::resolved_log_path(&cfg.logging)
}

/// The port the child will serve on: the explicit flag, else the configured
/// port, else the built-in default — same resolution `start` itself uses.
fn resolved_port(args: &StartArgs) -> u16 {
    if let Some(p) = args.port {
        return p;
    }
    crate::config::default_path()
        .ok()
        .and_then(|p| crate::config::load_or_default(&p).ok())
        .map(|c| c.proxy.port)
        .unwrap_or(4100)
}

/// Absolute path to the graceful-shutdown request file:
/// `<data dir>/burnwall.shutdown` (honors `BURNWALL_DATA_DIR`).
///
/// This file is the only "signal" deliverable to a detached Windows process
/// — there is no SIGTERM equivalent that reaches a `DETACHED_PROCESS`.
/// `stop` writes it; the running daemon polls for it and shuts down
/// gracefully (drain in-flight requests, then exit) when it appears.
pub fn shutdown_file_path() -> anyhow::Result<PathBuf> {
    Ok(data_dir()
        .context("locating the Burnwall data directory")?
        .join("burnwall.shutdown"))
}

/// Ask a running daemon to shut down gracefully: stop accepting, drain
/// in-flight requests (bounded — see the proxy's drain window), then exit
/// on its own. Writes the shutdown file (works on every platform); on Unix
/// also sends SIGTERM so the reaction is immediate instead of waiting for
/// the next poll tick.
pub fn request_graceful_shutdown(_pid: u32) -> anyhow::Result<()> {
    let path = shutdown_file_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating data directory {}", parent.display()))?;
    }
    fs::write(&path, "graceful shutdown requested by `burnwall stop`")
        .with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        let _ = terminate_process(_pid);
    }
    Ok(())
}

/// Best-effort removal of the shutdown request file. Called by `stop` after
/// the daemon is gone (a hard-killed daemon never consumes the file, and a
/// leftover request would kill the NEXT daemon the moment it starts).
pub fn clear_shutdown_file() {
    if let Ok(path) = shutdown_file_path() {
        let _ = fs::remove_file(path);
    }
}

/// How often the daemon checks for the shutdown request file. One `stat()`
/// of a usually-absent file — the same budget as the pause-file check the
/// handler already does per request.
const SHUTDOWN_POLL: Duration = Duration::from_millis(250);

/// Resolve when the process is asked to shut down: Ctrl-C on any platform,
/// SIGTERM on Unix, or the shutdown request file appearing (the mechanism
/// `burnwall stop` uses — the only one that can reach a detached Windows
/// process). The resolved signal starts the proxy's graceful drain.
pub async fn shutdown_signal() {
    // Clear any stale request left behind by a crashed `stop` — without
    // this, a leftover file would shut the daemon down the moment it starts.
    let shutdown_file = shutdown_file_path().ok();
    if let Some(p) = &shutdown_file {
        let _ = fs::remove_file(p);
    }
    let file_request = async {
        match shutdown_file {
            Some(p) => loop {
                if p.exists() {
                    let _ = fs::remove_file(&p);
                    return;
                }
                tokio::time::sleep(SHUTDOWN_POLL).await;
            },
            None => std::future::pending::<()>().await,
        }
    };
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("could not install SIGTERM handler: {e}");
                tokio::select! {
                    _ = ctrl_c => {}
                    _ = file_request => {}
                }
                return;
            }
        };
        tokio::select! {
            _ = ctrl_c => {}
            _ = sigterm.recv() => {}
            _ = file_request => {}
        }
    }
    #[cfg(not(unix))]
    {
        tokio::select! {
            _ = ctrl_c => {}
            _ = file_request => {}
        }
    }
}

// ─────────────────────────── platform: process control ───────────────────

/// Spawn `exe args...` as a detached background process with no inherited
/// handles. Returns the new PID. Stdio is null on both platforms.
#[cfg(unix)]
fn spawn_detached(exe: &std::path::Path, args: &[String]) -> anyhow::Result<u32> {
    use std::os::unix::process::CommandExt;
    let mut cmd = std::process::Command::new(exe);
    cmd.args(args);
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // SAFETY: pre_exec runs in the forked child before exec. setsid() is
    // async-signal-safe; it moves the child into its own session so the
    // launching shell closing does not SIGHUP the daemon.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = cmd.spawn()?;
    Ok(child.id())
}

/// Spawn `exe args...` as a detached background process with no inherited
/// handles. Returns the new PID.
///
/// Uses `CreateProcessW` directly so we can pass `bInheritHandles = FALSE`
/// — see the module-level comment for why that matters.
#[cfg(windows)]
fn spawn_detached(exe: &std::path::Path, args: &[String]) -> anyhow::Result<u32> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        CREATE_NEW_PROCESS_GROUP, CreateProcessW, DETACHED_PROCESS, PROCESS_INFORMATION,
        STARTUPINFOW,
    };

    let exe_wide: Vec<u16> = exe.as_os_str().encode_wide().chain([0]).collect();

    // First token in the command line becomes argv[0]; passing the exe
    // explicitly via lpApplicationName means Windows doesn't go searching
    // PATH for us.
    let mut cmd_line: Vec<u16> = Vec::new();
    append_arg_quoted(&mut cmd_line, exe.as_os_str());
    for arg in args {
        cmd_line.push(b' ' as u16);
        append_arg_quoted(&mut cmd_line, OsStr::new(arg));
    }
    cmd_line.push(0);

    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let ok = unsafe {
        CreateProcessW(
            exe_wide.as_ptr(),
            cmd_line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0, // bInheritHandles = FALSE
            DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
            std::ptr::null(),
            std::ptr::null(),
            &si,
            &mut pi,
        )
    };

    if ok == 0 {
        return Err(std::io::Error::last_os_error())
            .context("CreateProcessW failed for the background burnwall process");
    }

    let pid = pi.dwProcessId;
    unsafe {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    Ok(pid)
}

/// Append `arg` to `cmd` using Windows' CommandLineToArgvW quoting rules:
/// 2n backslashes before a `"` become n backslashes plus a literal `"`,
/// trailing backslashes inside a quoted span double up before the close.
#[cfg(windows)]
fn append_arg_quoted(cmd: &mut Vec<u16>, arg: &std::ffi::OsStr) {
    use std::os::windows::ffi::OsStrExt;
    const SPACE: u16 = b' ' as u16;
    const TAB: u16 = b'\t' as u16;
    const QUOTE: u16 = b'"' as u16;
    const BACKSLASH: u16 = b'\\' as u16;

    let wide: Vec<u16> = arg.encode_wide().collect();
    let needs_quotes =
        wide.is_empty() || wide.iter().any(|&c| c == SPACE || c == TAB || c == QUOTE);

    if needs_quotes {
        cmd.push(QUOTE);
    }

    let mut backslashes: u32 = 0;
    for &x in &wide {
        if x == BACKSLASH {
            backslashes += 1;
        } else {
            if x == QUOTE {
                for _ in 0..=backslashes {
                    cmd.push(BACKSLASH);
                }
            }
            backslashes = 0;
        }
        cmd.push(x);
    }

    if needs_quotes {
        for _ in 0..backslashes {
            cmd.push(BACKSLASH);
        }
        cmd.push(QUOTE);
    }
}

/// Is a process with this PID currently alive **and actually burnwall**?
///
/// PID files have an inherent reuse hazard (L-H1): after a reboot or crash the
/// stale file's PID is frequently reassigned to an unrelated process. Without
/// an identity check, autostart would bail "already running" against a random
/// process (so the proxy never starts while env files claim routing), and
/// `burnwall stop` could hard-kill an innocent process — the user's browser or
/// IDE. A PID that exists but isn't burnwall is treated as *stale*.
#[cfg(unix)]
pub fn process_is_alive(pid: u32) -> bool {
    // kill(pid, 0) sends no signal — it just reports whether the process
    // exists and is signalable. EPERM means it exists but is owned by
    // someone else (and so is certainly not our daemon).
    let ret = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if ret != 0 {
        return false;
    }
    process_is_burnwall(pid)
}

/// Identity check via the process image name. Fail-open: if the platform
/// lookup fails (permissions, exotic kernel), assume it IS burnwall — wrongly
/// treating a live daemon as stale would double-start, which is worse than the
/// rare false "already running".
#[cfg(unix)]
fn process_is_burnwall(pid: u32) -> bool {
    // Linux: /proc/<pid>/exe symlink. macOS: no /proc — fall back to `ps`.
    // Match against the FULL image path, not just the file name: the real
    // binary's path always contains "burnwall" (its dir and/or file name), and
    // this keeps the three platforms consistent — Windows checks the full image
    // path and macOS's `ps -o comm=` returns the full path too. A bare file-name
    // check diverged on Linux and read a binary launched from a burnwall checkout
    // (e.g. the `daemon_test-*` integration runner) as "not burnwall".
    #[cfg(target_os = "linux")]
    {
        match std::fs::read_link(format!("/proc/{pid}/exe")) {
            Ok(p) => p.to_string_lossy().contains("burnwall"),
            Err(_) => true,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        match std::process::Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "comm="])
            .output()
        {
            Ok(out) if out.status.success() => {
                String::from_utf8_lossy(&out.stdout).contains("burnwall")
            }
            _ => true,
        }
    }
}

/// Ask the process to terminate. Unix sends SIGTERM, which the proxy
/// catches for a graceful shutdown.
#[cfg(unix)]
pub fn terminate_process(pid: u32) -> anyhow::Result<()> {
    let ret = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
            .with_context(|| format!("sending SIGTERM to process {pid}"))
    }
}

/// Is a process with this PID currently alive **and actually burnwall**?
/// See the Unix variant for why the identity check matters (PID reuse, L-H1).
#[cfg(windows)]
pub fn process_is_alive(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        QueryFullProcessImageNameW,
    };
    // A process that has fully exited reports an exit code other than
    // STILL_ACTIVE (259). A process that genuinely exits *with* 259 would be
    // misread as alive — an acceptable corner case for a PID file.
    const STILL_ACTIVE: u32 = 259;
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return false;
        }
        let mut exit_code: u32 = 0;
        let queried = GetExitCodeProcess(handle, &mut exit_code);
        if queried == 0 || exit_code != STILL_ACTIVE {
            CloseHandle(handle);
            return false;
        }
        // Identity check (L-H1): the PID is live, but is it burnwall? A reused
        // PID belonging to another program must read as stale — otherwise
        // autostart bails against a random process and `stop` could kill it.
        // Fail-open on lookup failure (assume burnwall) — see the Unix variant.
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut len);
        CloseHandle(handle);
        if ok == 0 {
            return true;
        }
        let image = String::from_utf16_lossy(&buf[..len as usize]).to_ascii_lowercase();
        image.contains("burnwall")
    }
}

/// Ask the process to terminate. Windows has no graceful signal deliverable
/// to a detached process, so this is a hard kill — acceptable because each
/// SQLite write is its own transaction, so the worst case is a dropped
/// in-flight connection, never a corrupt database.
#[cfg(windows)]
pub fn terminate_process(pid: u32) -> anyhow::Result<()> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess};
    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if handle.is_null() {
            return Err(anyhow::anyhow!(
                "could not open process {pid}: {}",
                std::io::Error::last_os_error()
            ));
        }
        let ok = TerminateProcess(handle, 1);
        let err = std::io::Error::last_os_error();
        CloseHandle(handle);
        if ok == 0 {
            return Err(err).with_context(|| format!("terminating process {pid}"));
        }
        Ok(())
    }
}
