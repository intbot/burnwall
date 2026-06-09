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
    format!(
        "{comment} burnwall routing — disabled. Re-enable with `burnwall enable-routing`.\n"
    )
}

/// Lines that set the proxy env vars for the given shell.
pub fn export_lines(shell: Shell, proxy_url: &str) -> Vec<String> {
    let anthropic = format!("{}/anthropic", proxy_url);
    let openai = format!("{}/openai", proxy_url);
    match shell {
        Shell::Zsh | Shell::Bash => vec![
            format!("export ANTHROPIC_BASE_URL=\"{}\"", anthropic),
            format!("export OPENAI_BASE_URL=\"{}\"", openai),
        ],
        Shell::Fish => vec![
            format!("set -gx ANTHROPIC_BASE_URL \"{}\"", anthropic),
            format!("set -gx OPENAI_BASE_URL \"{}\"", openai),
        ],
        Shell::Powershell => vec![
            format!("$env:ANTHROPIC_BASE_URL = \"{}\"", anthropic),
            format!("$env:OPENAI_BASE_URL = \"{}\"", openai),
        ],
    }
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

/// True if this shell's rc file carries our source-hook marker — i.e. the user
/// previously wired this shell up. The strongest signal that a shell is
/// "configured", and the one that disambiguates bash vs zsh (which share a
/// single `env.sh`).
pub fn rc_hook_present(shell: Shell) -> bool {
    shell
        .rc_path()
        .and_then(|rc| std::fs::read_to_string(rc).ok())
        .map(|c| c.contains(RC_MARKER))
        .unwrap_or(false)
}

/// True if routing is *actively enabled* for this shell — the env file exists
/// and still carries the export lines (not the `disable-routing` stub).
pub fn routing_active(shell: Shell) -> bool {
    env_file_path(shell)
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|c| c.contains("ANTHROPIC_BASE_URL"))
        .unwrap_or(false)
}

/// Append the rc-source line to the user's shell rc, if not already there.
/// Returns `true` if the file was modified.
pub fn install_rc_hook(shell: Shell, env_path: &Path) -> Result<bool> {
    let rc = shell
        .rc_path()
        .ok_or_else(|| anyhow::anyhow!("no rc file for shell {}", shell.label()))?;
    let existing = std::fs::read_to_string(&rc).unwrap_or_default();
    if existing.contains(RC_MARKER) {
        return Ok(false);
    }
    if let Some(parent) = rc.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let mut content = existing;
    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }
    content.push_str(&rc_source_line(shell, env_path));
    content.push('\n');
    std::fs::write(&rc, content).with_context(|| format!("writing {}", rc.display()))?;
    Ok(true)
}

/// Remove the rc-source line (the one carrying [`RC_MARKER`]) from the user's
/// shell rc. Used by `uninstall`. Returns `true` if a line was removed. Missing
/// rc file or no marker line → `false` (nothing to do).
pub fn remove_rc_hook(shell: Shell) -> Result<bool> {
    let Some(rc) = shell.rc_path() else {
        return Ok(false);
    };
    let existing = match std::fs::read_to_string(&rc) {
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
    std::fs::write(&rc, out).with_context(|| format!("writing {}", rc.display()))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_lines_posix() {
        let lines = export_lines(Shell::Zsh, "http://localhost:4100");
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("export ANTHROPIC_BASE_URL="));
        assert!(lines[0].contains("http://localhost:4100/anthropic"));
        assert!(lines[1].starts_with("export OPENAI_BASE_URL="));
        assert!(lines[1].contains("http://localhost:4100/openai"));
    }

    #[test]
    fn export_lines_powershell() {
        let lines = export_lines(Shell::Powershell, "http://localhost:4100");
        assert!(lines[0].starts_with("$env:ANTHROPIC_BASE_URL ="));
        assert!(lines[1].starts_with("$env:OPENAI_BASE_URL ="));
    }

    #[test]
    fn export_lines_fish() {
        let lines = export_lines(Shell::Fish, "http://localhost:4100");
        assert!(lines[0].starts_with("set -gx ANTHROPIC_BASE_URL"));
    }

    #[test]
    fn unset_lines_posix() {
        let lines = unset_lines(Shell::Bash);
        assert_eq!(lines, vec!["unset ANTHROPIC_BASE_URL", "unset OPENAI_BASE_URL"]);
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
