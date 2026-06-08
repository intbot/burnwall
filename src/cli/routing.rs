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
}
