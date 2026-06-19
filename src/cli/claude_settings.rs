//! Wire (and unwire) the Burnwall ribbon into Claude Code's
//! `~/.claude/settings.json` `statusLine` block.
//!
//! Claude Code reads a custom status line from a `statusLine` object in its
//! settings file. `burnwall statusline` renders that line, but nothing wired
//! it up for the user — they had to hand-edit JSON. `init --apply` now calls
//! [`install`]; `uninstall` calls [`remove`].
//!
//! ## Principles
//!
//! - **Idempotent merge.** We parse the existing settings, set *only* the
//!   `statusLine` key, and write everything else back untouched. Re-running is
//!   a no-op.
//! - **Never clobber a foreign status line.** If the user already points
//!   `statusLine` at something that isn't ours, we leave it alone and report
//!   it — security software doesn't silently overwrite your config.
//! - **PATH-resolved command.** We write `"burnwall statusline"`, not an
//!   absolute path, so the wiring survives a reinstall to a different dir
//!   (the installer puts `burnwall` on PATH).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// The command we write into `statusLine.command`. PATH-resolved on purpose —
/// see the module docs.
pub const STATUSLINE_COMMAND: &str = "burnwall statusline";

/// `~/.claude/settings.json`. Same location on every OS.
pub fn settings_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".claude").join("settings.json"))
}

/// Our canonical `statusLine` value.
fn our_statusline() -> serde_json::Value {
    serde_json::json!({
        "type": "command",
        "command": STATUSLINE_COMMAND,
        "padding": 0
    })
}

/// Does an existing `statusLine` value look like ours? True if its `command`
/// mentions both `burnwall` and `statusline` — this matches the PATH form
/// (`burnwall statusline`) and any absolute-path form
/// (`…/burnwall.exe statusline`) a user may have hand-written, so `remove`
/// cleans those up too.
fn is_ours(statusline: &serde_json::Value) -> bool {
    statusline
        .get("command")
        .and_then(|c| c.as_str())
        .map(|c| {
            let lc = c.to_lowercase();
            lc.contains("burnwall") && lc.contains("statusline")
        })
        .unwrap_or(false)
}

/// The Burnwall ↔ Claude Code status-line wiring, as seen by read-only surfaces
/// (`burnwall status`, `doctor`, the start banner). Lets them nudge
/// `burnwall init` when Claude Code is in use but the ribbon was never wired —
/// the gap a fresh install or a prior `uninstall` leaves, since `start` /
/// `upgrade` only manage the proxy and never touch `settings.json`. Stays quiet
/// for users who don't run Claude Code or who chose their own status line.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum StatuslineState {
    /// No `~/.claude` directory — Claude Code isn't in use here. Say nothing.
    NoClaudeCode,
    /// Our `burnwall statusline` is wired up. All good.
    Wired,
    /// Claude Code is present but no Burnwall status line is configured — what a
    /// fresh install or a prior `uninstall` leaves behind. Nudge `init`.
    Missing,
    /// A *different* `statusLine` is configured. The user's choice — leave it,
    /// and don't nudge.
    Foreign,
}

impl StatuslineState {
    /// Stable lowercase tag for JSON / the IDE extension.
    pub fn tag(self) -> &'static str {
        match self {
            StatuslineState::NoClaudeCode => "none",
            StatuslineState::Wired => "wired",
            StatuslineState::Missing => "missing",
            StatuslineState::Foreign => "foreign",
        }
    }
}

/// Inspect the Claude Code status-line wiring. `settings` is
/// `~/.claude/settings.json`; its parent (`~/.claude`) existing is how we tell
/// Claude Code is in use at all. Read-only and best-effort: an unreadable or
/// unparseable settings file is reported as [`StatuslineState::Foreign`], so we
/// neither nudge into nor offer to rewrite a file we can't understand.
pub fn statusline_state(settings: &Path) -> StatuslineState {
    let claude_present = settings.parent().map(|d| d.is_dir()).unwrap_or(false);
    if !claude_present {
        return StatuslineState::NoClaudeCode;
    }
    match std::fs::read_to_string(settings) {
        // Claude Code is here, but settings are empty/absent → not wired yet.
        Ok(s) if s.trim().is_empty() => StatuslineState::Missing,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => StatuslineState::Missing,
        Ok(s) => match serde_json::from_str::<serde_json::Value>(&s) {
            Ok(v) => match v.get("statusLine") {
                Some(sl) if is_ours(sl) => StatuslineState::Wired,
                Some(_) => StatuslineState::Foreign,
                None => StatuslineState::Missing,
            },
            // Unparseable: stay quiet rather than nudge into a file `install`
            // would refuse to touch.
            Err(_) => StatuslineState::Foreign,
        },
        Err(_) => StatuslineState::Foreign,
    }
}

/// [`statusline_state`] at the default `~/.claude/settings.json`. Returns
/// [`StatuslineState::NoClaudeCode`] when the home directory can't be resolved.
pub fn statusline_state_default() -> StatuslineState {
    match settings_path() {
        Some(p) => statusline_state(&p),
        None => StatuslineState::NoClaudeCode,
    }
}

/// Outcome of [`install`], so the caller can print an honest status line.
#[derive(Debug, PartialEq, Eq)]
pub enum InstallOutcome {
    /// We added (or refreshed) the Burnwall status line.
    Wrote,
    /// A Burnwall status line identical to ours was already present.
    AlreadyOurs,
    /// A *different* `statusLine` is configured — we left it untouched. The
    /// string is its `command`, for the message.
    ForeignPresent(String),
}

/// Parse `settings.json` into an object, tolerating a missing file (→ empty
/// object) but not malformed JSON (we won't blindly overwrite a file we can't
/// understand).
fn read_object(path: &Path) -> Result<serde_json::Map<String, serde_json::Value>> {
    match std::fs::read_to_string(path) {
        Ok(s) if s.trim().is_empty() => Ok(serde_json::Map::new()),
        Ok(s) => {
            let v: serde_json::Value = serde_json::from_str(&s)
                .with_context(|| format!("parsing {} (not valid JSON)", path.display()))?;
            match v {
                serde_json::Value::Object(m) => Ok(m),
                _ => anyhow::bail!("{} is not a JSON object", path.display()),
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(serde_json::Map::new()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// Pretty-write the object back as `settings.json`, creating `~/.claude` if
/// needed. Trailing newline so the file is POSIX-tidy.
fn write_object(path: &Path, obj: &serde_json::Map<String, serde_json::Value>) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let mut s = serde_json::to_string_pretty(&serde_json::Value::Object(obj.clone()))?;
    s.push('\n');
    std::fs::write(path, s).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Merge the Burnwall `statusLine` into `path`. Idempotent; never clobbers a
/// foreign status line.
pub fn install(path: &Path) -> Result<InstallOutcome> {
    let mut obj = read_object(path)?;
    if let Some(existing) = obj.get("statusLine") {
        if is_ours(existing) {
            // Refresh only if the value drifted from canonical (e.g. an old
            // absolute-path form) — otherwise it's a true no-op.
            if existing == &our_statusline() {
                return Ok(InstallOutcome::AlreadyOurs);
            }
        } else {
            let cmd = existing
                .get("command")
                .and_then(|c| c.as_str())
                .unwrap_or("<non-command status line>")
                .to_string();
            return Ok(InstallOutcome::ForeignPresent(cmd));
        }
    }
    obj.insert("statusLine".to_string(), our_statusline());
    write_object(path, &obj)?;
    Ok(InstallOutcome::Wrote)
}

/// Remove the Burnwall `statusLine` from `path`. Returns `true` if we removed
/// it, `false` if there was nothing of ours to remove (missing file, no
/// `statusLine`, or a foreign one we won't touch).
pub fn remove(path: &Path) -> Result<bool> {
    let mut obj = match std::fs::read_to_string(path) {
        Ok(s) if s.trim().is_empty() => return Ok(false),
        Ok(s) => match serde_json::from_str::<serde_json::Value>(&s) {
            Ok(serde_json::Value::Object(m)) => m,
            // Unparseable / non-object: leave it alone.
            _ => return Ok(false),
        },
        Err(_) => return Ok(false),
    };
    match obj.get("statusLine") {
        Some(v) if is_ours(v) => {
            obj.remove("statusLine");
            write_object(path, &obj)?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        (dir, path)
    }

    #[test]
    fn install_into_missing_file_creates_it() {
        let (_d, path) = tmp();
        assert_eq!(install(&path).unwrap(), InstallOutcome::Wrote);
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["statusLine"]["command"], STATUSLINE_COMMAND);
        assert_eq!(v["statusLine"]["type"], "command");
    }

    #[test]
    fn install_preserves_existing_keys() {
        let (_d, path) = tmp();
        std::fs::write(
            &path,
            r#"{"theme":"dark","permissions":{"allow":["Bash(*)"]}}"#,
        )
        .unwrap();
        assert_eq!(install(&path).unwrap(), InstallOutcome::Wrote);
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["theme"], "dark");
        assert_eq!(v["permissions"]["allow"][0], "Bash(*)");
        assert_eq!(v["statusLine"]["command"], STATUSLINE_COMMAND);
    }

    #[test]
    fn install_is_idempotent() {
        let (_d, path) = tmp();
        assert_eq!(install(&path).unwrap(), InstallOutcome::Wrote);
        assert_eq!(install(&path).unwrap(), InstallOutcome::AlreadyOurs);
    }

    #[test]
    fn install_refreshes_absolute_path_form() {
        let (_d, path) = tmp();
        std::fs::write(
            &path,
            r#"{"statusLine":{"type":"command","command":"C:\\x\\burnwall.exe statusline","padding":0}}"#,
        )
        .unwrap();
        // Recognized as ours (burnwall + statusline) but drifted → rewritten.
        assert_eq!(install(&path).unwrap(), InstallOutcome::Wrote);
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["statusLine"]["command"], STATUSLINE_COMMAND);
    }

    #[test]
    fn install_will_not_clobber_foreign_statusline() {
        let (_d, path) = tmp();
        std::fs::write(
            &path,
            r#"{"statusLine":{"type":"command","command":"my-custom-bar.sh"}}"#,
        )
        .unwrap();
        match install(&path).unwrap() {
            InstallOutcome::ForeignPresent(cmd) => assert_eq!(cmd, "my-custom-bar.sh"),
            other => panic!("expected ForeignPresent, got {other:?}"),
        }
        // And the foreign value is untouched on disk.
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["statusLine"]["command"], "my-custom-bar.sh");
    }

    #[test]
    fn install_bails_on_malformed_json() {
        let (_d, path) = tmp();
        std::fs::write(&path, "{not json").unwrap();
        assert!(install(&path).is_err());
    }

    #[test]
    fn remove_takes_out_ours_and_keeps_the_rest() {
        let (_d, path) = tmp();
        std::fs::write(&path, r#"{"theme":"dark"}"#).unwrap();
        install(&path).unwrap();
        assert!(remove(&path).unwrap());
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(v.get("statusLine").is_none());
        assert_eq!(v["theme"], "dark");
    }

    #[test]
    fn remove_leaves_foreign_statusline() {
        let (_d, path) = tmp();
        std::fs::write(
            &path,
            r#"{"statusLine":{"type":"command","command":"my-custom-bar.sh"}}"#,
        )
        .unwrap();
        assert!(!remove(&path).unwrap());
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["statusLine"]["command"], "my-custom-bar.sh");
    }

    #[test]
    fn remove_on_missing_file_is_false() {
        let (_d, path) = tmp();
        assert!(!remove(&path).unwrap());
    }

    // ----- statusline_state (the read-only discoverability primitive) -----

    #[test]
    fn statusline_state_no_claude_dir_is_silent() {
        // Parent `.claude` directory absent → Claude Code isn't in use → never
        // nudge.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".claude").join("settings.json");
        assert_eq!(statusline_state(&path), StatuslineState::NoClaudeCode);
    }

    #[test]
    fn statusline_state_missing_when_claude_present_but_unwired() {
        // The post-`uninstall` / fresh-install gap: Claude Code dir + settings
        // exist, but no `statusLine`.
        let (_d, path) = tmp();
        std::fs::write(&path, r#"{"theme":"dark"}"#).unwrap();
        assert_eq!(statusline_state(&path), StatuslineState::Missing);
    }

    #[test]
    fn statusline_state_missing_when_settings_file_absent() {
        // `~/.claude` exists (tempdir is the parent) but settings.json doesn't:
        // Claude Code present, nothing wired → Missing, not NoClaudeCode.
        let (_d, path) = tmp();
        assert_eq!(statusline_state(&path), StatuslineState::Missing);
    }

    #[test]
    fn statusline_state_wired_after_install() {
        let (_d, path) = tmp();
        install(&path).unwrap();
        assert_eq!(statusline_state(&path), StatuslineState::Wired);
    }

    #[test]
    fn statusline_state_foreign_is_left_alone() {
        let (_d, path) = tmp();
        std::fs::write(
            &path,
            r#"{"statusLine":{"type":"command","command":"my-custom-bar.sh"}}"#,
        )
        .unwrap();
        assert_eq!(statusline_state(&path), StatuslineState::Foreign);
    }

    #[test]
    fn statusline_state_malformed_json_stays_quiet() {
        // We won't nudge into (or offer to rewrite) a file we can't parse.
        let (_d, path) = tmp();
        std::fs::write(&path, "{not json").unwrap();
        assert_eq!(statusline_state(&path), StatuslineState::Foreign);
    }

    #[test]
    fn statusline_state_tags_are_stable() {
        assert_eq!(StatuslineState::NoClaudeCode.tag(), "none");
        assert_eq!(StatuslineState::Wired.tag(), "wired");
        assert_eq!(StatuslineState::Missing.tag(), "missing");
        assert_eq!(StatuslineState::Foreign.tag(), "foreign");
    }
}
