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

/// Re-exec `burnwall start` (without `--daemon`) as a detached background
/// process, then wait for it to write its PID file before returning.
pub async fn spawn_background(args: &StartArgs) -> anyhow::Result<()> {
    if let Some(pid) = running_pid()? {
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
fn child_args(args: &StartArgs) -> Vec<String> {
    let mut out = vec!["start".to_string()];
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

/// Resolve when the process is asked to shut down: Ctrl-C on any platform,
/// or SIGTERM on Unix (which is what `burnwall stop` sends).
pub async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("could not install SIGTERM handler: {e}");
                ctrl_c.await;
                return;
            }
        };
        tokio::select! {
            _ = ctrl_c => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        ctrl_c.await;
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
        CreateProcessW, CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS, PROCESS_INFORMATION,
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

/// Is a process with this PID currently alive?
#[cfg(unix)]
pub fn process_is_alive(pid: u32) -> bool {
    // kill(pid, 0) sends no signal — it just reports whether the process
    // exists and is signalable. EPERM means it exists but is owned by
    // someone else, which still counts as "alive".
    let ret = unsafe { libc::kill(pid as libc::pid_t, 0) };
    ret == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
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

/// Is a process with this PID currently alive?
#[cfg(windows)]
pub fn process_is_alive(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
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
        CloseHandle(handle);
        queried != 0 && exit_code == STILL_ACTIVE
    }
}

/// Ask the process to terminate. Windows has no graceful signal deliverable
/// to a detached process, so this is a hard kill — acceptable because each
/// SQLite write is its own transaction, so the worst case is a dropped
/// in-flight connection, never a corrupt database.
#[cfg(windows)]
pub fn terminate_process(pid: u32) -> anyhow::Result<()> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
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
