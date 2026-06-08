//! `burnwall init` — detect installed AI tools and suggest the env vars
//! needed to point them at the proxy.
//!
//! Default mode is **dry-run**: print what would change. `--apply` writes
//! the export lines to the user's shell rc file. We never modify a shell
//! config without `--apply`; users run security software, they don't want
//! surprise edits.

use std::env;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::Args;

use crate::storage;

/// Tools we can auto-configure via base-URL env vars.
const TOOLS: &[(&str, &str)] = &[
    ("claude", "Claude Code"),
    ("codex", "Codex CLI"),
    ("aider", "Aider"),
    ("opencode", "OpenCode"),
];

#[derive(Args, Debug)]
pub struct InitArgs {
    /// Actually write the export lines to your shell rc file. Without this
    /// flag, init only prints what it would do.
    #[arg(long)]
    pub apply: bool,
    /// Override the proxy host:port written into the env vars.
    #[arg(long, default_value = "http://localhost:4100")]
    pub proxy_url: String,
    /// Also register burnwall as a login-time service (launchd / systemd /
    /// Windows Scheduled Task). Implied by `--apply` in interactive mode if
    /// you confirm the prompt.
    #[arg(long)]
    pub install_service: bool,
    /// Skip all interactive prompts. Combine with `--apply` for unattended
    /// install in scripts.
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell {
    Zsh,
    Bash,
    Fish,
    Powershell,
}

impl Shell {
    pub fn detect() -> Option<Self> {
        if let Some(shell) = env::var_os("SHELL") {
            let s = shell.to_string_lossy().to_lowercase();
            if s.contains("zsh") {
                return Some(Shell::Zsh);
            }
            if s.contains("bash") {
                return Some(Shell::Bash);
            }
            if s.contains("fish") {
                return Some(Shell::Fish);
            }
        }
        if cfg!(windows) {
            return Some(Shell::Powershell);
        }
        None
    }

    pub fn rc_path(&self) -> Option<PathBuf> {
        let home = dirs::home_dir()?;
        Some(match self {
            Shell::Zsh => home.join(".zshrc"),
            Shell::Bash => home.join(".bashrc"),
            Shell::Fish => home.join(".config").join("fish").join("config.fish"),
            // We don't auto-edit PowerShell profile on Windows in v0.1 — too
            // many edge cases (signed scripts, `$PROFILE` per-host vs
            // per-user). Caller falls back to printing instructions.
            Shell::Powershell => return None,
        })
    }

    /// Lines to append to the shell rc to point AI tools at the proxy.
    pub fn export_lines(&self, proxy_url: &str) -> Vec<String> {
        let anthropic = format!("{}/anthropic", proxy_url);
        let openai = format!("{}/openai", proxy_url);
        match self {
            Shell::Zsh | Shell::Bash => vec![
                format!("export ANTHROPIC_BASE_URL={}", anthropic),
                format!("export OPENAI_BASE_URL={}", openai),
            ],
            Shell::Fish => vec![
                format!("set -gx ANTHROPIC_BASE_URL {}", anthropic),
                format!("set -gx OPENAI_BASE_URL {}", openai),
            ],
            Shell::Powershell => vec![
                format!("$env:ANTHROPIC_BASE_URL = \"{}\"", anthropic),
                format!("$env:OPENAI_BASE_URL = \"{}\"", openai),
            ],
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Shell::Zsh => "zsh",
            Shell::Bash => "bash",
            Shell::Fish => "fish",
            Shell::Powershell => "PowerShell",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Detection {
    pub binary: String,
    pub label: String,
    pub found: bool,
}

pub fn detect_tools() -> Vec<Detection> {
    TOOLS
        .iter()
        .map(|(bin, label)| Detection {
            binary: bin.to_string(),
            label: label.to_string(),
            found: binary_in_path(bin),
        })
        .collect()
}

/// Lookup a binary on the process `PATH`. On Windows, also try standard
/// extensions from `PATHEXT`.
pub fn binary_in_path(name: &str) -> bool {
    let path_var = env::var_os("PATH").unwrap_or_default();
    binary_in_path_var(name, &path_var)
}

/// Like [`binary_in_path`], but search the supplied PATH-formatted value
/// instead of the process env. Used by tests so they don't have to mutate
/// global state.
pub fn binary_in_path_var(name: &str, path_var: &std::ffi::OsStr) -> bool {
    let exts: Vec<String> = if cfg!(windows) {
        let pathext = env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string());
        let mut v = vec!["".to_string()];
        v.extend(pathext.split(';').map(|e| e.to_lowercase()));
        v
    } else {
        vec!["".to_string()]
    };
    for dir in env::split_paths(path_var) {
        for ext in &exts {
            let candidate = dir.join(format!("{}{}", name, ext));
            if candidate.is_file() {
                return true;
            }
        }
    }
    false
}

const MARKER: &str = "# Added by burnwall init";

/// Append `lines` to `rc_path`, separated from existing content with a
/// marker comment. Idempotent: if the marker already appears, do nothing
/// and report `false`. Returns `true` when the file was modified.
pub fn append_to_rc(rc_path: &Path, lines: &[String]) -> std::io::Result<bool> {
    let existing = std::fs::read_to_string(rc_path).unwrap_or_default();
    if existing.contains(MARKER) {
        return Ok(false);
    }
    if let Some(parent) = rc_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(rc_path)?;
    let needs_leading_newline = !existing.is_empty() && !existing.ends_with('\n');
    let prefix = if needs_leading_newline { "\n" } else { "" };
    let block = format!(
        "{}\n{}\n{}\n",
        MARKER,
        prefix.to_string() + &lines.join("\n"),
        ""
    );
    // Trim the trailing extra blank line for tidiness:
    let block = block.trim_end_matches("\n\n").to_string() + "\n";
    file.write_all(block.as_bytes())?;
    Ok(true)
}

pub fn run_cmd(args: InitArgs) -> anyhow::Result<()> {
    let mut out = std::io::stdout().lock();

    // Ensure data dir exists so subsequent `start` commands can write a DB
    // without a "not found" surprise.
    let data_dir = storage::data_dir().context("locating data dir")?;
    std::fs::create_dir_all(&data_dir)
        .with_context(|| format!("creating data directory {}", data_dir.display()))?;
    writeln!(out, "📁 Data directory: {}", data_dir.display())?;
    writeln!(out)?;

    // Detect tools
    writeln!(out, "🔍 Detecting AI tools...")?;
    let detections = detect_tools();
    for d in &detections {
        let mark = if d.found { "✓" } else { "✗" };
        let status = if d.found { "found" } else { "not found" };
        writeln!(out, "  {} {} ({})", mark, d.label, status)?;
    }
    writeln!(out)?;

    let shell = Shell::detect();
    writeln!(
        out,
        "🔧 Shell detected: {}",
        shell.map(|s| s.label()).unwrap_or("unknown")
    )?;
    writeln!(out)?;

    // Three things init can do — show what each is, then either dry-run or
    // execute based on --apply. Service install is opt-in via flag or prompt.
    if !args.apply {
        writeln!(out, "▶ This run is a DRY RUN. Re-run with --apply to perform the actions below.")?;
        writeln!(out)?;
    }

    // 1. Routing activation (env file + rc hook).
    writeln!(out, "1. Routing activation")?;
    writeln!(out, "   ─────────────────────")?;
    let action_label = if args.apply { "Action" } else { "Would do" };
    if let Some(s) = shell {
        let env_file = super::routing::env_file_path(s)
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<config>".to_string());
        writeln!(out, "   {action_label}: write env file ({env_file})")?;
        writeln!(out, "             contents:")?;
        for line in super::routing::export_lines(s, &args.proxy_url) {
            writeln!(out, "               {}", line)?;
        }
        if let Some(rc) = s.rc_path() {
            writeln!(out, "             append source line to {}", rc.display())?;
        } else {
            writeln!(out, "             (no rc file for {} — manual step needed)", s.label())?;
        }
        if args.apply {
            let env_path = super::routing::write_env_file(s, &args.proxy_url)?;
            let hook_added = match super::routing::install_rc_hook(s, &env_path) {
                Ok(b) => b,
                Err(e) => {
                    writeln!(out, "   ⚠  rc hook skipped: {}", e)?;
                    false
                }
            };
            writeln!(out, "   ✓ env file written: {}", env_path.display())?;
            if hook_added {
                if let Some(rc) = s.rc_path() {
                    writeln!(out, "   ✓ rc hook added to {}", rc.display())?;
                }
            } else if let Some(rc) = s.rc_path() {
                writeln!(out, "   • rc hook already present in {}", rc.display())?;
            }
        }
    } else {
        writeln!(out, "   (shell not detected — set ANTHROPIC_BASE_URL / OPENAI_BASE_URL manually)")?;
    }
    writeln!(out)?;

    // 2. Login service (always opt-in: --install-service flag or interactive
    // prompt). Default for unattended (--yes without --install-service) is NO.
    writeln!(out, "2. Login-time auto-start")?;
    writeln!(out, "   ──────────────────────")?;
    let want_service = if args.install_service {
        true
    } else if args.yes {
        false
    } else if args.apply {
        prompt_yes_no(&mut out, "   Register burnwall as a login service?")?
    } else {
        writeln!(out, "   (use --install-service to register the proxy as a login-time service)")?;
        false
    };
    if want_service {
        if args.apply {
            let exe = std::env::current_exe().context("locating burnwall executable")?;
            // Call platform install path directly — same code the
            // install-service command runs.
            super::service::install_cmd(super::service::InstallServiceArgs {
                no_start: false,
                task: false,
            })
            .with_context(|| format!("installing service for {}", exe.display()))?;
        } else {
            writeln!(out, "   {action_label}: register login-time service")?;
        }
    } else if args.apply {
        writeln!(out, "   • skipped (re-run with --install-service to add it later)")?;
    }
    writeln!(out)?;

    // 3. Claude Code status line — wire the Burnwall ribbon into
    //    ~/.claude/settings.json. Only offered when Claude Code is detected;
    //    the rest of init is shell-routing, this is the one editor integration.
    let claude_found = detections.iter().any(|d| d.binary == "claude" && d.found);
    if claude_found {
        writeln!(out, "3. Claude Code status line")?;
        writeln!(out, "   ───────────────────────")?;
        if let Some(path) = super::claude_settings::settings_path() {
            if args.apply {
                match super::claude_settings::install(&path) {
                    Ok(super::claude_settings::InstallOutcome::Wrote) => {
                        writeln!(out, "   ✓ added `statusLine` to {}", path.display())?;
                        writeln!(out, "     restart Claude Code to see: 🔥 model · ↑/↓ tokens · $ spend")?;
                    }
                    Ok(super::claude_settings::InstallOutcome::AlreadyOurs) => {
                        writeln!(out, "   • already wired up in {}", path.display())?;
                    }
                    Ok(super::claude_settings::InstallOutcome::ForeignPresent(cmd)) => {
                        writeln!(out, "   • left your existing status line untouched (command: {cmd})")?;
                        writeln!(out, "     to use Burnwall's, set statusLine.command to `burnwall statusline`")?;
                    }
                    Err(e) => writeln!(out, "   ⚠  skipped: {}", e)?,
                }
            } else {
                writeln!(out, "   {action_label}: merge `statusLine` → {}", path.display())?;
                writeln!(out, "             command: burnwall statusline")?;
            }
        } else {
            writeln!(out, "   (could not locate ~/.claude/settings.json)")?;
        }
        writeln!(out)?;
    }

    // 3. Next steps.
    writeln!(out, "▶ Next steps")?;
    if args.apply {
        writeln!(out, "   • New shells will source the env file automatically.")?;
        writeln!(out, "   • Apply to *this* shell now without restarting:")?;
        match shell {
            Some(Shell::Powershell) => {
                writeln!(out, "       burnwall enable-routing --eval | Out-String | Invoke-Expression")?;
            }
            _ => {
                writeln!(out, "       eval \"$(burnwall enable-routing)\"")?;
            }
        }
        if !want_service {
            writeln!(out, "   • Start the proxy:  burnwall start --daemon")?;
        }
        writeln!(out, "   • Kill switch (instant bypass):  export BURNWALL_BYPASS=1")?;
    } else {
        writeln!(out, "   • Re-run with --apply to execute.")?;
        writeln!(out, "   • Or run the commands directly:")?;
        writeln!(out, "       burnwall enable-routing")?;
        writeln!(out, "       burnwall install-service")?;
    }
    Ok(())
}

/// Y/n prompt with a default of yes. Returns false on EOF or non-interactive
/// stdin (treat as "no" — safer when stdin is piped).
fn prompt_yes_no<W: Write>(out: &mut W, question: &str) -> anyhow::Result<bool> {
    use std::io::{BufRead, IsTerminal};
    if !std::io::stdin().is_terminal() {
        writeln!(out, "{} (non-interactive — defaulting to no)", question)?;
        return Ok(false);
    }
    write!(out, "{} [Y/n]: ", question)?;
    out.flush()?;
    let mut line = String::new();
    let n = std::io::stdin().lock().read_line(&mut line)?;
    if n == 0 {
        return Ok(false);
    }
    let answer = line.trim().to_ascii_lowercase();
    Ok(answer.is_empty() || answer == "y" || answer == "yes")
}
