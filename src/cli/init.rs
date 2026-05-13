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

    // Detect shell + emit env-var instructions
    let shell = Shell::detect();
    let lines = shell
        .map(|s| s.export_lines(&args.proxy_url))
        .unwrap_or_else(|| {
            vec![
                format!("ANTHROPIC_BASE_URL={}/anthropic", args.proxy_url),
                format!("OPENAI_BASE_URL={}/openai", args.proxy_url),
            ]
        });

    writeln!(
        out,
        "🔧 Shell detected: {}",
        shell.map(|s| s.label()).unwrap_or("unknown")
    )?;

    let rc_path = shell.and_then(|s| s.rc_path());
    if args.apply {
        match (shell, rc_path.as_ref()) {
            (Some(_), Some(path)) => {
                let modified = append_to_rc(path, &lines)
                    .with_context(|| format!("writing to {}", path.display()))?;
                if modified {
                    writeln!(out, "  → Appended to {}", path.display())?;
                } else {
                    writeln!(
                        out,
                        "  (already configured — marker found in {})",
                        path.display()
                    )?;
                }
                writeln!(out, "  Run `source {}` to activate.", path.display())?;
            }
            _ => {
                writeln!(
                    out,
                    "  (no rc file to write on this shell — set these env vars manually:)"
                )?;
                for line in &lines {
                    writeln!(out, "    {}", line)?;
                }
            }
        }
    } else {
        writeln!(
            out,
            "  → Would add the following to {}:",
            rc_path
                .as_deref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "your shell config".into())
        )?;
        for line in &lines {
            writeln!(out, "    {}", line)?;
        }
        writeln!(out)?;
        writeln!(out, "  Re-run with --apply to write the changes.")?;
    }
    writeln!(out)?;
    writeln!(out, "▶  Then start the proxy:  burnwall start")?;
    Ok(())
}
