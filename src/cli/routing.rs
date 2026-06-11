//! Routing activation: write/read/clear the small env file that points AI
//! tools at the Burnwall proxy, plus render bare export/unset lines for
//! `eval`-style activation.
//!
//! ## Two-step activation
//!
//! 1. A burnwall-owned **env file** holds the `export` lines. POSIX shells
//!    get `~/.config/burnwall/env.sh`; fish gets `env.fish`; PowerShell gets
//!    `%APPDATA%\burnwall\env.ps1`.
//! 2. The user's shell rc gets **one idempotent line** that sources the env
//!    file.
//!
//! ## Why this split
//!
//! Revert is trivial: truncate the env file (one place to edit) and every
//! future shell starts clean. No sed surgery on `.zshrc`/`.bashrc`. The rc
//! hook stays put — sourcing an empty file is a no-op.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::init::Shell;

/// Default proxy URL used when the caller doesn't override.
pub const PROXY_DEFAULT: &str = "http://localhost:4100";

/// Marker the rc-hook line carries so we can find + idempotently re-add it.
const RC_MARKER: &str = "# burnwall:routing";

/// Base directory for the burnwall-owned env file.
///
/// POSIX: `$XDG_CONFIG_HOME/burnwall` or `~/.config/burnwall`.
/// Windows: `%APPDATA%\burnwall`.
pub fn config_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        if let Some(appdata) = std::env::var_os("APPDATA") {
            return Some(PathBuf::from(appdata).join("burnwall"));
        }
        dirs::home_dir().map(|h| h.join("AppData").join("Roaming").join("burnwall"))
    }
    #[cfg(not(windows))]
    {
        if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
            if !xdg.is_empty() {
                return Some(PathBuf::from(xdg).join("burnwall"));
            }
        }
        dirs::home_dir().map(|h| h.join(".config").join("burnwall"))
    }
}

/// Absolute path to the env file for the given shell family.
pub fn env_file_path(shell: Shell) -> Option<PathBuf> {
    let dir = config_dir()?;
    let name = match shell {
        Shell::Powershell => "env.ps1",
        Shell::Fish => "env.fish",
        Shell::Zsh | Shell::Bash => "env.sh",
    };
    Some(dir.join(name))
}

/// Render the contents of the env file for a given shell + proxy URL.
///
/// The first line is a fixed banner so a human opening the file knows what
/// owns it. The body is the actual exports. An "empty" env file (after
/// `disable-routing`) keeps the banner but drops the body — sourcing it is
/// then a no-op.
pub fn env_file_contents(shell: Shell, proxy_url: &str) -> String {
    let mut out = String::new();
    let comment = match shell {
        Shell::Powershell => "#",
        _ => "#",
    };
    out.push_str(&format!(
        "{comment} burnwall routing — auto-generated. Toggle with `burnwall enable-routing` / `disable-routing`.\n"
    ));
    for line in export_lines(shell, proxy_url) {
        out.push_str(&line);
        out.push('\n');
    }
    out
}

/// Render only the empty banner (no exports). Used by `disable-routing`.
pub fn env_file_disabled(shell: Shell) -> String {
    let comment = match shell {
        Shell::Powershell => "#",
        _ => "#",
    };
    format!("{comment} burnwall routing — disabled. Re-enable with `burnwall enable-routing`.\n")
}

/// Marker carried by an env file that `burnwall stop` paused, telling it
/// apart from an explicit `disable-routing`: `start` re-enables paused files
/// but never overrides a deliberate disable.
const PAUSED_MARKER: &str = "# burnwall:paused";

/// Render the paused stub (no exports). Used by `burnwall stop`.
pub fn env_file_paused(shell: Shell) -> String {
    let comment = match shell {
        Shell::Powershell => "#",
        _ => "#",
    };
    format!(
        "{comment} burnwall routing — paused (proxy stopped). `burnwall start` re-enables it.\n{PAUSED_MARKER}\n"
    )
}

/// The persistent routing state one env file records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvFileState {
    /// Export lines present — new shells route through the proxy.
    Active,
    /// Paused by `burnwall stop` — `start` re-enables it automatically.
    Paused,
    /// Explicitly disabled with `disable-routing` — only `enable-routing`
    /// (or `init`) turns it back on.
    Disabled,
}

/// Classify env-file contents. Pure over its input for testability.
pub fn classify_env_contents(contents: &str) -> EnvFileState {
    if contents.contains("ANTHROPIC_BASE_URL") {
        EnvFileState::Active
    } else if contents.contains(PAUSED_MARKER) {
        EnvFileState::Paused
    } else {
        EnvFileState::Disabled
    }
}

/// The state of this shell's env file, or `None` when no file exists.
pub fn env_file_state(shell: Shell) -> Option<EnvFileState> {
    let contents = std::fs::read_to_string(env_file_path(shell)?).ok()?;
    Some(classify_env_contents(&contents))
}

/// Pause routing for every env file that is currently ACTIVE: replace the
/// exports with the paused stub so new shells go direct while the proxy is
/// down. Explicitly-disabled stubs and absent files are left alone — a
/// `disable-routing` decision survives a stop/start cycle untouched.
/// Returns the env files rewritten (deduped — bash and zsh share one).
pub fn pause_routing() -> Result<Vec<PathBuf>> {
    let mut paused = Vec::new();
    for shell in Shell::ALL {
        let Some(path) = env_file_path(shell) else {
            continue;
        };
        if paused.contains(&path) {
            continue;
        }
        let Ok(contents) = std::fs::read_to_string(&path) else {
            continue;
        };
        if classify_env_contents(&contents) != EnvFileState::Active {
            continue;
        }
        std::fs::write(&path, env_file_paused(shell))
            .with_context(|| format!("writing {}", path.display()))?;
        paused.push(path);
    }
    Ok(paused)
}

/// What `start` did to one configured shell's routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeAction {
    /// Routing was already on; the env file was rewritten with the current
    /// proxy URL (picks up a port change).
    Refreshed,
    /// Paused by `stop` (or the env file was missing) — turned back on.
    Resumed,
    /// Explicitly disabled by the user — respected, left off.
    LeftDisabled,
}

pub struct ResumeOutcome {
    pub shell: Shell,
    pub action: ResumeAction,
}

/// Pure resume decision for one shell, from its env-file state.
pub fn resume_action_for(state: Option<EnvFileState>) -> ResumeAction {
    match state {
        Some(EnvFileState::Disabled) => ResumeAction::LeftDisabled,
        Some(EnvFileState::Active) => ResumeAction::Refreshed,
        Some(EnvFileState::Paused) | None => ResumeAction::Resumed,
    }
}

/// Re-enable routing on proxy start, for every shell the user previously
/// configured (rc hook present, or own env file for fish/PowerShell). Never
/// wires up a fresh shell — that's `init` / `enable-routing`'s job — and
/// never overrides an explicit `disable-routing`.
pub fn resume_routing(proxy_url: &str) -> Result<Vec<ResumeOutcome>> {
    let mut out = Vec::new();
    let mut seen_paths: Vec<PathBuf> = Vec::new();
    for shell in Shell::configured() {
        let Some(path) = env_file_path(shell) else {
            continue;
        };
        // bash and zsh share env.sh — write it once, report it once.
        if seen_paths.contains(&path) {
            continue;
        }
        seen_paths.push(path);
        let action = resume_action_for(env_file_state(shell));
        match action {
            ResumeAction::Refreshed | ResumeAction::Resumed => {
                write_env_file(shell, proxy_url)?;
            }
            ResumeAction::LeftDisabled => {}
        }
        out.push(ResumeOutcome { shell, action });
    }
    Ok(out)
}

/// Plain commands a user can paste to drop the routing vars from an
/// already-open shell. Deliberately NOT `disable-routing --eval`: that would
/// also flip the persistent state to explicitly-disabled and stop `start`
/// from auto-resuming.
pub fn manual_unset_hint(shell: Shell) -> &'static str {
    match shell {
        Shell::Zsh | Shell::Bash => "unset ANTHROPIC_BASE_URL OPENAI_BASE_URL",
        Shell::Fish => "set -e ANTHROPIC_BASE_URL; set -e OPENAI_BASE_URL",
        Shell::Powershell => {
            "Remove-Item Env:ANTHROPIC_BASE_URL, Env:OPENAI_BASE_URL -ErrorAction SilentlyContinue"
        }
    }
}

/// Lines that set the proxy env vars for the given shell — **liveness-gated**
/// (L-C1): the exports only happen if the proxy port actually answers at the
/// moment the shell starts. This is the structural fix for the dead-proxy
/// trap: a crash, `kill`, or reboot can never run any cleanup, so without the
/// gate every new shell would export a base URL pointing at a dead port and
/// every AI tool would fail with connection-refused until the user figured out
/// `burnwall start`. With the gate, a shell opened against a dead proxy
/// silently goes DIRECT (unprotected, but *working*) and the next `start`
/// covers new shells again.
///
/// Probe cost: a loopback TCP connect is sub-millisecond when the proxy is
/// listening and fails immediately (RST) when nothing is bound — there's no
/// human-perceptible shell-startup cost.
pub fn export_lines(shell: Shell, proxy_url: &str) -> Vec<String> {
    let anthropic = format!("{}/anthropic", proxy_url);
    let openai = format!("{}/openai", proxy_url);
    let port = proxy_url_port(proxy_url);
    match shell {
        Shell::Zsh | Shell::Bash => vec![format!(
            "if (exec 3<>/dev/tcp/127.0.0.1/{port}) 2>/dev/null; then exec 3>&-; export ANTHROPIC_BASE_URL=\"{anthropic}\"; export OPENAI_BASE_URL=\"{openai}\"; fi"
        )],
        Shell::Fish => vec![
            // fish has no /dev/tcp; probe via bash when available (it is on any
            // dev box that also has fish), otherwise export ungated.
            format!(
                "if not command -q bash; or bash -c 'exec 3<>/dev/tcp/127.0.0.1/{port}' 2>/dev/null; set -gx ANTHROPIC_BASE_URL \"{anthropic}\"; set -gx OPENAI_BASE_URL \"{openai}\"; end"
            ),
        ],
        Shell::Powershell => vec![format!(
            "try {{ $__bw = [Net.Sockets.TcpClient]::new('127.0.0.1', {port}); $__bw.Dispose(); $env:ANTHROPIC_BASE_URL = \"{anthropic}\"; $env:OPENAI_BASE_URL = \"{openai}\" }} catch {{}}"
        )],
    }
}

/// Extract the port from a proxy URL (`http://localhost:4100` → 4100), falling
/// back to the default proxy port.
fn proxy_url_port(proxy_url: &str) -> u16 {
    let after_scheme = proxy_url.split("://").nth(1).unwrap_or(proxy_url);
    let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    authority
        .rsplit(':')
        .next()
        .and_then(|p| p.parse().ok())
        .unwrap_or(4100)
}

/// Quick TCP liveness probe of the local proxy port (used by status surfaces
/// to distinguish "routed and protected" from "routed at a dead port").
pub fn proxy_port_alive(port: u16, timeout: std::time::Duration) -> bool {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    std::net::TcpStream::connect_timeout(&addr, timeout).is_ok()
}

/// Liveness-probe the proxy that `base_url` points at. `None` if the URL isn't
/// loopback (nothing local to probe).
pub fn proxy_alive_for_url(base_url: &str) -> Option<bool> {
    if !url_is_loopback(base_url) {
        return None;
    }
    Some(proxy_port_alive(
        proxy_url_port(base_url),
        std::time::Duration::from_millis(80),
    ))
}

/// Lines that unset the proxy env vars for the given shell. Used by
/// `disable-routing` in eval-output mode so the current shell drops them
/// without a restart.
pub fn unset_lines(shell: Shell) -> Vec<String> {
    match shell {
        Shell::Zsh | Shell::Bash => vec![
            "unset ANTHROPIC_BASE_URL".to_string(),
            "unset OPENAI_BASE_URL".to_string(),
        ],
        Shell::Fish => vec![
            "set -e ANTHROPIC_BASE_URL".to_string(),
            "set -e OPENAI_BASE_URL".to_string(),
        ],
        Shell::Powershell => vec![
            "Remove-Item Env:ANTHROPIC_BASE_URL -ErrorAction SilentlyContinue".to_string(),
            "Remove-Item Env:OPENAI_BASE_URL -ErrorAction SilentlyContinue".to_string(),
        ],
    }
}

/// One-line rc hook that sources the env file when present. Idempotently
/// re-addable: the marker is fixed text, so [`install_rc_hook`] won't write
/// it twice.
pub fn rc_source_line(shell: Shell, env_path: &Path) -> String {
    let p = env_path.display();
    match shell {
        Shell::Zsh | Shell::Bash => format!("[ -f \"{p}\" ] && . \"{p}\"  {RC_MARKER}"),
        Shell::Fish => format!("test -f \"{p}\" ; and source \"{p}\"  {RC_MARKER}"),
        Shell::Powershell => {
            format!("if (Test-Path \"{p}\") {{ . \"{p}\" }}  {RC_MARKER}")
        }
    }
}

/// Write the env file with the given exports. Creates the parent dir.
/// Returns the path written.
pub fn write_env_file(shell: Shell, proxy_url: &str) -> Result<PathBuf> {
    let path = env_file_path(shell).context("locating burnwall env file path")?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::write(&path, env_file_contents(shell, proxy_url))
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

/// Delete the env file outright. Used by `uninstall`, where the rc hook is
/// removed in the same pass — a leftover stub would (a) be residue on a
/// machine the user asked to clean and (b) keep counting the shell as
/// "configured" forever. The rc hook line is `Test-Path`-guarded, so even a
/// hook that survives (PowerShell profiles are never auto-edited) sources
/// nothing. Returns `true` if a file existed and was removed.
pub fn delete_env_file(shell: Shell) -> Result<bool> {
    let Some(path) = env_file_path(shell) else {
        return Ok(false);
    };
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).with_context(|| format!("removing {}", path.display())),
    }
}

/// Replace the env file with the empty banner. Used by `disable-routing`
/// for the persistent state; the current shell's env is dropped separately
/// via eval output.
pub fn clear_env_file(shell: Shell) -> Result<PathBuf> {
    let path = env_file_path(shell).context("locating burnwall env file path")?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::write(&path, env_file_disabled(shell))
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

/// Whether a tool's traffic is actually reaching the proxy, judged from the
/// base-URL env var the tool would use. A surface that can see the tool's
/// environment (the Claude Code status line, `burnwall status`) uses this to
/// warn when traffic is silently going direct — i.e. unprotected and untracked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvRouting {
    /// Base URL points at the local proxy → routed through Burnwall.
    Proxied,
    /// No proxy base URL (or a non-loopback one) → traffic goes straight to the
    /// provider. Burnwall sees nothing: no security scan, no cost capture.
    Direct,
    /// Routed at the proxy, but `BURNWALL_BYPASS` makes it a pure relay — checks
    /// are off even though traffic still flows through.
    Bypassed,
}

/// Truthy `BURNWALL_BYPASS` values, matching the proxy's own `bypass_active`
/// (`1`/`true`/`yes`/`on`, case-insensitive, trimmed).
pub fn bypass_truthy(v: Option<&str>) -> bool {
    matches!(
        v.map(|s| s.trim().to_ascii_lowercase()),
        Some(ref s) if matches!(s.as_str(), "1" | "true" | "yes" | "on")
    )
}

/// Does this base URL point at a loopback host (i.e. the local proxy)? A crude
/// authority scan rather than a full URL parser — enough to tell `localhost` /
/// `127.0.0.1` / `[::1]` apart from `api.anthropic.com`, without a new dep.
pub fn url_is_loopback(u: &str) -> bool {
    let after_scheme = u.split("://").nth(1).unwrap_or(u);
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .trim();
    // Strip any userinfo (`user@host[:port]`), then isolate the host from the
    // port — matching the *exact* hostname so `localhost.evil.com` doesn't slip
    // through a prefix check.
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    let host = if let Some(rest) = host_port.strip_prefix('[') {
        rest.split(']').next().unwrap_or("") // IPv6 literal: "[::1]:4100" → "::1"
    } else {
        host_port.split(':').next().unwrap_or("")
    };
    matches!(host, "localhost" | "127.0.0.1" | "0.0.0.0" | "::1")
}

/// Classify routing from the relevant base-URL value and the bypass flag. Pure
/// over its inputs for testability — the caller supplies the env values.
pub fn classify_routing(base_url: Option<&str>, bypass: Option<&str>) -> EnvRouting {
    match base_url {
        Some(u) if url_is_loopback(u) => {
            if bypass_truthy(bypass) {
                EnvRouting::Bypassed
            } else {
                EnvRouting::Proxied
            }
        }
        _ => EnvRouting::Direct,
    }
}

/// The base-URL env var a tool for `provider` reads to find its endpoint.
pub fn base_url_var_for_provider(provider: &str) -> &'static str {
    match provider {
        "openai" => "OPENAI_BASE_URL",
        "google" => "GOOGLE_BASE_URL",
        _ => "ANTHROPIC_BASE_URL",
    }
}

/// Classify the current process's routing for `provider` by reading the live
/// environment. Used by surfaces that run inside the tool's env (the status
/// line is spawned by Claude Code and inherits its variables).
pub fn current_routing(provider: &str) -> EnvRouting {
    let var = base_url_var_for_provider(provider);
    let base = std::env::var(var).ok();
    let bypass = std::env::var("BURNWALL_BYPASS").ok();
    classify_routing(base.as_deref(), bypass.as_deref())
}

/// True if this shell has a burnwall env file on disk — whether enabled or the
/// disabled stub. Used to decide which shells a sync/teardown should touch.
pub fn env_file_present(shell: Shell) -> bool {
    env_file_path(shell).map(|p| p.exists()).unwrap_or(false)
}

/// The PowerShell `CurrentUserAllHosts` profile paths burnwall manages. Both
/// editions are covered on Windows — Windows PowerShell 5.1 reads
/// `Documents\WindowsPowerShell\profile.ps1` and PowerShell 7+ reads
/// `Documents\PowerShell\profile.ps1` — because either can be the user's daily
/// shell. `dirs::document_dir()` resolves known-folder redirection (OneDrive).
/// PowerShell *was* the one shell never auto-edited, which made persistent
/// routing on the default Windows shell a silent dead end (L-C2).
pub fn powershell_profile_paths() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        let Some(docs) = dirs::document_dir() else {
            return Vec::new();
        };
        vec![
            docs.join("WindowsPowerShell").join("profile.ps1"),
            docs.join("PowerShell").join("profile.ps1"),
        ]
    }
    #[cfg(not(windows))]
    {
        let Some(home) = dirs::home_dir() else {
            return Vec::new();
        };
        vec![home.join(".config").join("powershell").join("profile.ps1")]
    }
}

/// Bash *login-shell* profile files, in bash's own lookup order. Git Bash
/// terminals and macOS Terminal run login shells, which read the first of
/// these that exists and only read `.bashrc` if that file chains to it — so a
/// hook placed solely in `.bashrc` can silently never execute (L-H3).
fn bash_profile_paths() -> Vec<PathBuf> {
    let Some(home) = dirs::home_dir() else {
        return Vec::new();
    };
    vec![
        home.join(".bash_profile"),
        home.join(".bash_login"),
        home.join(".profile"),
    ]
}

/// True if this shell's rc file carries our source-hook marker — i.e. the user
/// previously wired this shell up. The strongest signal that a shell is
/// "configured", and the one that disambiguates bash vs zsh (which share a
/// single `env.sh`). PowerShell checks its managed profile paths.
pub fn rc_hook_present(shell: Shell) -> bool {
    if shell == Shell::Powershell {
        return powershell_profile_paths().iter().any(|p| {
            std::fs::read_to_string(p)
                .map(|c| c.contains(RC_MARKER))
                .unwrap_or(false)
        });
    }
    shell
        .rc_path()
        .and_then(|rc| std::fs::read_to_string(rc).ok())
        .map(|c| c.contains(RC_MARKER))
        .unwrap_or(false)
}

/// True if routing is *actively enabled* for this shell — the env file exists
/// and still carries the export lines (not a paused or disabled stub).
pub fn routing_active(shell: Shell) -> bool {
    env_file_state(shell) == Some(EnvFileState::Active)
}

/// Append the marker-carrying `line` to `path` if it isn't already there,
/// creating parent dirs. Returns `true` if the file was modified.
fn append_hook_line(path: &Path, line: &str) -> Result<bool> {
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    if existing.contains(RC_MARKER) {
        return Ok(false);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let mut content = existing;
    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }
    content.push_str(line);
    content.push('\n');
    std::fs::write(path, content).with_context(|| format!("writing {}", path.display()))?;
    Ok(true)
}

/// Append the rc-source line to the user's shell rc, if not already there.
/// Returns `true` if any file was modified.
///
/// PowerShell: writes the managed `CurrentUserAllHosts` profile(s) — every
/// edition whose profile dir already exists, or the first (Windows PowerShell)
/// one when none does (L-C2). The dot-source line is `Test-Path`-guarded, so a
/// machine with script-execution disabled merely no-ops.
///
/// Bash: also chains into the first existing login-profile file
/// (`.bash_profile` / `.bash_login` / `.profile`) when that file doesn't read
/// `.bashrc` — Git Bash and macOS terminals run *login* shells, which never
/// see a hook that lives only in `.bashrc` (L-H3).
pub fn install_rc_hook(shell: Shell, env_path: &Path) -> Result<bool> {
    if shell == Shell::Powershell {
        let line = rc_source_line(shell, env_path);
        let paths = powershell_profile_paths();
        if paths.is_empty() {
            anyhow::bail!("could not locate a PowerShell profile directory");
        }
        let mut targets: Vec<&PathBuf> = paths
            .iter()
            .filter(|p| p.parent().map(|d| d.exists()).unwrap_or(false))
            .collect();
        if targets.is_empty() {
            targets.push(&paths[0]);
        }
        let mut changed = false;
        for p in targets {
            changed |= append_hook_line(p, &line)?;
        }
        return Ok(changed);
    }

    let rc = shell
        .rc_path()
        .ok_or_else(|| anyhow::anyhow!("no rc file for shell {}", shell.label()))?;
    let mut changed = append_hook_line(&rc, &rc_source_line(shell, env_path))?;

    if shell == Shell::Bash {
        // Login-shell chaining (L-H3): if a profile file exists and neither
        // sources .bashrc nor carries our hook, login shells would never run
        // the hook above — add it to the first such file in bash's own order.
        if let Some(profile) = bash_profile_paths().iter().find(|p| p.exists()) {
            let contents = std::fs::read_to_string(profile).unwrap_or_default();
            if !contents.contains(".bashrc") && !contents.contains(RC_MARKER) {
                changed |= append_hook_line(profile, &rc_source_line(shell, env_path))?;
            }
        }
    }
    Ok(changed)
}

/// Strip marker-carrying lines from one file. `false` when the file is missing
/// or carries no marker.
fn remove_hook_lines(path: &Path) -> Result<bool> {
    let existing = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    if !existing.contains(RC_MARKER) {
        return Ok(false);
    }
    let kept: Vec<&str> = existing
        .lines()
        .filter(|l| !l.contains(RC_MARKER))
        .collect();
    let mut out = kept.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    std::fs::write(path, out).with_context(|| format!("writing {}", path.display()))?;
    Ok(true)
}

/// Remove the rc-source line (the one carrying [`RC_MARKER`]) from the user's
/// shell rc. Used by `uninstall`. Returns `true` if a line was removed. Missing
/// rc file or no marker line → `false` (nothing to do). Cleans every file
/// [`install_rc_hook`] can write: the PowerShell profiles, and for bash the
/// login-profile files alongside `.bashrc`.
pub fn remove_rc_hook(shell: Shell) -> Result<bool> {
    if shell == Shell::Powershell {
        let mut removed = false;
        for p in powershell_profile_paths() {
            removed |= remove_hook_lines(&p)?;
        }
        return Ok(removed);
    }
    let Some(rc) = shell.rc_path() else {
        return Ok(false);
    };
    let mut removed = remove_hook_lines(&rc)?;
    if shell == Shell::Bash {
        for p in bash_profile_paths() {
            removed |= remove_hook_lines(&p)?;
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_lines_posix_are_liveness_gated() {
        let lines = export_lines(Shell::Zsh, "http://localhost:4100");
        let joined = lines.join("\n");
        // L-C1: exports must be gated on a live proxy port so a shell opened
        // after a crash/reboot goes DIRECT instead of pointing at a dead port.
        assert!(joined.contains("/dev/tcp/127.0.0.1/4100"), "{joined}");
        assert!(joined.contains("export ANTHROPIC_BASE_URL=\"http://localhost:4100/anthropic\""));
        assert!(joined.contains("export OPENAI_BASE_URL=\"http://localhost:4100/openai\""));
    }

    #[test]
    fn export_lines_powershell_are_liveness_gated() {
        let lines = export_lines(Shell::Powershell, "http://localhost:4100");
        let joined = lines.join("\n");
        assert!(joined.contains("TcpClient"), "{joined}");
        assert!(joined.contains("$env:ANTHROPIC_BASE_URL ="));
        assert!(joined.contains("$env:OPENAI_BASE_URL ="));
        assert!(
            joined.contains("catch"),
            "probe failure must be swallowed: {joined}"
        );
    }

    #[test]
    fn export_lines_fish_are_liveness_gated() {
        let lines = export_lines(Shell::Fish, "http://localhost:4100");
        let joined = lines.join("\n");
        assert!(joined.contains("set -gx ANTHROPIC_BASE_URL"));
        assert!(joined.contains("/dev/tcp/127.0.0.1/4100"), "{joined}");
    }

    #[test]
    fn proxy_url_port_parses_common_shapes() {
        assert_eq!(proxy_url_port("http://localhost:4100"), 4100);
        assert_eq!(proxy_url_port("http://127.0.0.1:5000/x"), 5000);
        assert_eq!(proxy_url_port("localhost"), 4100); // fallback
    }

    #[test]
    fn dead_port_probe_reports_not_alive() {
        // Port 1 on loopback is essentially never bound; the probe must come
        // back fast and false rather than hanging.
        let started = std::time::Instant::now();
        assert!(!proxy_port_alive(1, std::time::Duration::from_millis(200)));
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[test]
    fn unset_lines_posix() {
        let lines = unset_lines(Shell::Bash);
        assert_eq!(
            lines,
            vec!["unset ANTHROPIC_BASE_URL", "unset OPENAI_BASE_URL"]
        );
    }

    #[test]
    fn unset_lines_powershell() {
        let lines = unset_lines(Shell::Powershell);
        assert!(lines[0].starts_with("Remove-Item Env:ANTHROPIC_BASE_URL"));
    }

    #[test]
    fn env_file_disabled_is_no_op_when_sourced() {
        let body = env_file_disabled(Shell::Zsh);
        assert!(!body.contains("export"));
        assert!(body.starts_with("# burnwall routing"));
    }

    #[test]
    fn env_file_paused_is_no_op_when_sourced() {
        let body = env_file_paused(Shell::Zsh);
        assert!(!body.contains("export"));
        assert!(body.starts_with("# burnwall routing"));
        assert!(body.contains(PAUSED_MARKER));
    }

    #[test]
    fn env_file_states_are_distinguishable() {
        // The three persistent states must classify distinctly, for every
        // shell flavor — `start`'s resume decision rides on this.
        for shell in Shell::ALL {
            assert_eq!(
                classify_env_contents(&env_file_contents(shell, PROXY_DEFAULT)),
                EnvFileState::Active,
                "{}",
                shell.label()
            );
            assert_eq!(
                classify_env_contents(&env_file_paused(shell)),
                EnvFileState::Paused,
                "{}",
                shell.label()
            );
            assert_eq!(
                classify_env_contents(&env_file_disabled(shell)),
                EnvFileState::Disabled,
                "{}",
                shell.label()
            );
        }
    }

    #[test]
    fn resume_respects_explicit_disable_but_recovers_paused() {
        // Paused (by stop) or missing → resume; active → refresh the URL;
        // explicitly disabled → hands off.
        assert_eq!(
            resume_action_for(Some(EnvFileState::Paused)),
            ResumeAction::Resumed
        );
        assert_eq!(resume_action_for(None), ResumeAction::Resumed);
        assert_eq!(
            resume_action_for(Some(EnvFileState::Active)),
            ResumeAction::Refreshed
        );
        assert_eq!(
            resume_action_for(Some(EnvFileState::Disabled)),
            ResumeAction::LeftDisabled
        );
    }

    #[test]
    fn manual_unset_hint_has_no_persistent_side_effects() {
        // The stop-time hint must only touch the live shell env — it must
        // not mention disable-routing (which would flip persistent state).
        for shell in Shell::ALL {
            let hint = manual_unset_hint(shell);
            assert!(hint.contains("ANTHROPIC_BASE_URL"), "{hint}");
            assert!(!hint.contains("disable-routing"), "{hint}");
        }
    }

    #[test]
    fn rc_source_line_carries_marker() {
        let line = rc_source_line(Shell::Bash, Path::new("/tmp/env.sh"));
        assert!(line.contains("# burnwall:routing"));
        assert!(line.contains("/tmp/env.sh"));
    }

    #[test]
    fn loopback_urls_recognized() {
        assert!(url_is_loopback("http://localhost:4100/anthropic"));
        assert!(url_is_loopback("http://127.0.0.1:4100"));
        assert!(url_is_loopback("http://[::1]:4100/anthropic"));
        assert!(url_is_loopback("http://0.0.0.0:4100"));
        assert!(!url_is_loopback("https://api.anthropic.com"));
        assert!(!url_is_loopback("https://api.openai.com/v1"));
        assert!(!url_is_loopback("https://localhost.evil.com")); // host is localhost.evil.com
    }

    #[test]
    fn classify_routing_states() {
        // Routed at the local proxy.
        assert_eq!(
            classify_routing(Some("http://localhost:4100/anthropic"), None),
            EnvRouting::Proxied
        );
        // Routed but bypassed → checks off.
        assert_eq!(
            classify_routing(Some("http://localhost:4100/anthropic"), Some("1")),
            EnvRouting::Bypassed
        );
        // No base URL set → direct to provider.
        assert_eq!(classify_routing(None, None), EnvRouting::Direct);
        // Explicit upstream → direct.
        assert_eq!(
            classify_routing(Some("https://api.anthropic.com"), None),
            EnvRouting::Direct
        );
        // Bypass only matters when actually routed; direct stays direct.
        assert_eq!(
            classify_routing(Some("https://api.anthropic.com"), Some("1")),
            EnvRouting::Direct
        );
    }

    #[test]
    fn bypass_truthiness_matches_proxy_semantics() {
        for v in ["1", "true", "TRUE", "yes", "on", " on "] {
            assert!(bypass_truthy(Some(v)), "{v:?} should be truthy");
        }
        for v in ["0", "false", "", "off", "no"] {
            assert!(!bypass_truthy(Some(v)), "{v:?} should be falsy");
        }
        assert!(!bypass_truthy(None));
    }

    #[test]
    fn base_url_var_by_provider() {
        assert_eq!(base_url_var_for_provider("anthropic"), "ANTHROPIC_BASE_URL");
        assert_eq!(base_url_var_for_provider("openai"), "OPENAI_BASE_URL");
        assert_eq!(base_url_var_for_provider("whatever"), "ANTHROPIC_BASE_URL");
    }
}
