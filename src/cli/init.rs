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

    /// Every shell family burnwall can wire up. Iteration order is stable so
    /// teardown/sync output is deterministic.
    pub const ALL: [Shell; 4] = [Shell::Zsh, Shell::Bash, Shell::Fish, Shell::Powershell];

    /// Is this shell already configured for routing? True when its rc-hook is
    /// present, or — for shells with a *unique* env file — when that env file
    /// exists.
    ///
    /// Bash and zsh deliberately rely on the rc-hook signal only: they share a
    /// single `env.sh`, so env-file presence can't tell them apart, and we must
    /// not pull a never-used shell into a sync (which would, e.g., create a
    /// spurious `~/.zshrc` on a bash-only box). Fish/PowerShell have their own
    /// env files, so presence is unambiguous there.
    fn is_configured(self) -> bool {
        if super::routing::rc_hook_present(self) {
            return true;
        }
        match self {
            Shell::Powershell | Shell::Fish => super::routing::env_file_present(self),
            Shell::Bash | Shell::Zsh => false,
        }
    }

    /// Shells the user has previously configured for routing. This is why a
    /// command run from one shell can keep the *other* shells consistent — the
    /// single-shell assumption breaks on Windows, where PowerShell and Git-bash
    /// commonly coexist.
    pub fn configured() -> Vec<Shell> {
        Self::ALL
            .into_iter()
            .filter(|s| s.is_configured())
            .collect()
    }

    /// The shells an enable/disable should act on: every already-configured
    /// shell, plus the one we're running in now (so first-time setup still
    /// works on a fresh machine where nothing is configured yet).
    pub fn routing_targets() -> Vec<Shell> {
        let mut v = Self::configured();
        if let Some(cur) = Self::detect() {
            if !v.contains(&cur) {
                v.push(cur);
            }
        }
        v
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

/// Locate a Git-for-Windows `bash.exe` by finding `git.exe` on the given
/// PATH-formatted value and probing the Git install tree around it.
///
/// Keyed off `git.exe` rather than `bash.exe` deliberately: WSL also ships a
/// `bash.exe` (in System32), but WSL has its own home and filesystem, so a
/// hook written to the Windows `~/.bashrc` would never reach it. Git Bash
/// keeps `HOME` at `%USERPROFILE%` — exactly where our rc hook lands.
pub fn git_bash_from_path_var(path_var: &std::ffi::OsStr) -> Option<PathBuf> {
    for dir in env::split_paths(path_var) {
        if !dir.join("git.exe").is_file() {
            continue;
        }
        // git.exe lives in `<install>\cmd`, `<install>\bin`, or
        // `<install>\mingw64\bin`; bash.exe in `<install>\bin` or
        // `<install>\usr\bin`. Probing two ancestors covers all three.
        let ancestors = [dir.parent(), dir.parent().and_then(Path::parent)];
        for root in ancestors.into_iter().flatten() {
            for cand in [
                root.join("bin").join("bash.exe"),
                root.join("usr").join("bin").join("bash.exe"),
            ] {
                if cand.is_file() {
                    return Some(cand);
                }
            }
        }
    }
    None
}

/// Where this shell's source hook lands, for human-readable output.
/// PowerShell hooks live in the managed `CurrentUserAllHosts` profile(s)
/// rather than a classic rc file (L-C2).
fn hook_target_label(shell: Shell) -> String {
    if shell == Shell::Powershell {
        let paths = super::routing::powershell_profile_paths();
        if paths.is_empty() {
            return "the PowerShell profile".to_string();
        }
        return paths
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(" and ");
    }
    shell
        .rc_path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| format!("the {} profile", shell.label()))
}

/// Find Git Bash on this machine: PATH first, then the standard installer
/// locations (Git for Windows can be installed without PATH integration).
pub fn git_bash_path() -> Option<PathBuf> {
    if let Some(p) = git_bash_from_path_var(&env::var_os("PATH").unwrap_or_default()) {
        return Some(p);
    }
    let roots = [
        env::var_os("ProgramFiles").map(|p| PathBuf::from(p).join("Git")),
        env::var_os("ProgramFiles(x86)").map(|p| PathBuf::from(p).join("Git")),
        env::var_os("LOCALAPPDATA").map(|p| PathBuf::from(p).join("Programs").join("Git")),
    ];
    for root in roots.into_iter().flatten() {
        let cand = root.join("bin").join("bash.exe");
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
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

    // Coverage caveat at the moment it matters: a detected Codex on ChatGPT
    // login routes to the ChatGPT backend (OAuth) and cannot be protected by
    // Burnwall — or any no-MITM proxy. Say so plainly, with the fix.
    if detections.iter().any(|d| d.binary == "codex" && d.found)
        && crate::coverage::codex_auth_mode() == Some(crate::coverage::CodexAuth::ChatGpt)
    {
        writeln!(out)?;
        writeln!(
            out,
            "  ⚠️  Codex is on ChatGPT login — its traffic goes to the ChatGPT"
        )?;
        writeln!(
            out,
            "      backend and CANNOT be protected by Burnwall (or any no-MITM"
        )?;
        writeln!(
            out,
            "      proxy). Codex in API-key mode would route through Burnwall, but"
        )?;
        writeln!(
            out,
            "      it bills per-token rather than your flat subscription — weigh"
        )?;
        writeln!(out, "      the cost trade-off before switching.")?;
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
        writeln!(
            out,
            "▶ This run is a DRY RUN. Re-run with --apply to perform the actions below."
        )?;
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
        writeln!(
            out,
            "             append source line to {}",
            hook_target_label(s)
        )?;
        if args.apply {
            // Preflight (M1): writing an Active env file with no proxy serving
            // means every new terminal exports a dead-port URL — the user's
            // first contact with Burnwall becomes "it broke my AI tool". When
            // the proxy isn't up yet, write the *paused* stub instead; `start`
            // flips it Active automatically once the port is actually bound.
            let proxy_up = super::routing::proxy_alive_for_url(&args.proxy_url).unwrap_or(false);
            let env_path = if proxy_up {
                super::routing::write_env_file(s, &args.proxy_url)?
            } else {
                let path = super::routing::env_file_path(s)
                    .ok_or_else(|| anyhow::anyhow!("locating env file path"))?;
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&path, super::routing::env_file_paused(s))?;
                path
            };
            let hook_added = match super::routing::install_rc_hook(s, &env_path) {
                Ok(b) => b,
                Err(e) => {
                    writeln!(out, "   ⚠  rc hook skipped: {}", e)?;
                    false
                }
            };
            if proxy_up {
                writeln!(out, "   ✓ env file written: {}", env_path.display())?;
            } else {
                writeln!(
                    out,
                    "   ✓ env file written (paused): {} — routing activates when you run `burnwall start`",
                    env_path.display()
                )?;
            }
            if hook_added {
                writeln!(out, "   ✓ rc hook added to {}", hook_target_label(s))?;
            } else {
                writeln!(
                    out,
                    "   • rc hook already present in {}",
                    hook_target_label(s)
                )?;
            }
        }
    } else {
        writeln!(
            out,
            "   (shell not detected — set ANTHROPIC_BASE_URL / OPENAI_BASE_URL manually)"
        )?;
    }

    // Git Bash on Windows: init run from a PowerShell terminal detects
    // PowerShell, but Git Bash commonly coexists and shares the same Windows
    // home — and an unhooked bash session silently goes direct to the
    // provider. Detect it and offer to wire it up in the same pass.
    if cfg!(windows)
        && shell == Some(Shell::Powershell)
        && !super::routing::rc_hook_present(Shell::Bash)
        && git_bash_path().is_some()
    {
        let rc_label = Shell::Bash
            .rc_path()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "~/.bashrc".to_string());
        writeln!(out)?;
        writeln!(
            out,
            "   Git Bash detected — bash sessions are not routed yet."
        )?;
        if !args.apply {
            let env_file = super::routing::env_file_path(Shell::Bash)
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "<config>".to_string());
            writeln!(out, "   {action_label}: write env file ({env_file})")?;
            writeln!(out, "             append source line to {rc_label}")?;
        } else {
            let hook_bash =
                args.yes || prompt_yes_no(&mut out, "   Also enable routing for Git Bash?")?;
            if hook_bash {
                let env_path = super::routing::write_env_file(Shell::Bash, &args.proxy_url)?;
                writeln!(out, "   ✓ env file written: {}", env_path.display())?;
                match super::routing::install_rc_hook(Shell::Bash, &env_path) {
                    Ok(true) => writeln!(out, "   ✓ rc hook added to {rc_label}")?,
                    Ok(false) => writeln!(out, "   • rc hook already present in {rc_label}")?,
                    Err(e) => writeln!(out, "   ⚠  rc hook skipped: {}", e)?,
                }
            } else {
                writeln!(
                    out,
                    "   • skipped (run `burnwall enable-routing` from Git Bash to add it later)"
                )?;
            }
        }
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
        writeln!(
            out,
            "   (use --install-service to register the proxy as a login-time service)"
        )?;
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
        writeln!(
            out,
            "   • skipped (re-run with --install-service to add it later)"
        )?;
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
                        writeln!(
                            out,
                            "     restart Claude Code to see: 🔥 burnwall · model · ↑/↓ tokens · $ spend"
                        )?;
                    }
                    Ok(super::claude_settings::InstallOutcome::AlreadyOurs) => {
                        writeln!(out, "   • already wired up in {}", path.display())?;
                    }
                    Ok(super::claude_settings::InstallOutcome::ForeignPresent(cmd)) => {
                        writeln!(
                            out,
                            "   • left your existing status line untouched (command: {cmd})"
                        )?;
                        writeln!(
                            out,
                            "     to use Burnwall's, set statusLine.command to `burnwall statusline`"
                        )?;
                    }
                    Err(e) => writeln!(out, "   ⚠  skipped: {}", e)?,
                }
            } else {
                writeln!(
                    out,
                    "   {action_label}: merge `statusLine` → {}",
                    path.display()
                )?;
                writeln!(out, "             command: burnwall statusline")?;
            }
        } else {
            writeln!(out, "   (could not locate ~/.claude/settings.json)")?;
        }
        writeln!(out)?;
    }

    // 3. Next steps. Starting the proxy comes FIRST: routing only activates
    // once the port is bound, so it is the step everything else hangs on.
    writeln!(out, "▶ Next steps")?;
    if args.apply {
        if !want_service {
            writeln!(out, "   • Start the proxy:  burnwall start --daemon")?;
        }
        writeln!(
            out,
            "   • New shells then source the env file automatically (routing engages only while the proxy is up)."
        )?;
        writeln!(out, "   • Apply to *this* shell now without restarting:")?;
        match shell {
            Some(Shell::Powershell) => {
                writeln!(
                    out,
                    "       burnwall enable-routing --eval | Out-String | Invoke-Expression"
                )?;
            }
            _ => {
                writeln!(out, "       eval \"$(burnwall enable-routing)\"")?;
            }
        }
        writeln!(
            out,
            "   • Kill switch (pauses the running proxy):  burnwall pause   (auto-resumes in 5m)"
        )?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn touch(path: &Path) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "").unwrap();
    }

    #[test]
    fn git_bash_found_next_to_git_exe() {
        // Standard Git-for-Windows layout: git.exe in cmd\, bash.exe in bin\.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("Git");
        touch(&root.join("cmd").join("git.exe"));
        touch(&root.join("bin").join("bash.exe"));
        let path_var = env::join_paths([root.join("cmd")]).unwrap();
        assert_eq!(
            git_bash_from_path_var(&path_var),
            Some(root.join("bin").join("bash.exe"))
        );
    }

    #[test]
    fn git_bash_found_from_mingw64_bin() {
        // PATH carries mingw64\bin; bash.exe is two levels up under usr\bin.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("Git");
        touch(&root.join("mingw64").join("bin").join("git.exe"));
        touch(&root.join("usr").join("bin").join("bash.exe"));
        let path_var = env::join_paths([root.join("mingw64").join("bin")]).unwrap();
        assert_eq!(
            git_bash_from_path_var(&path_var),
            Some(root.join("usr").join("bin").join("bash.exe"))
        );
    }

    #[test]
    fn wsl_style_bash_without_git_is_not_git_bash() {
        // WSL ships System32\bash.exe with no git.exe beside it. WSL has its
        // own home, so hooking the Windows ~/.bashrc would do nothing — the
        // detector must not count it.
        let tmp = tempfile::tempdir().unwrap();
        let sys32 = tmp.path().join("System32");
        touch(&sys32.join("bash.exe"));
        let path_var = env::join_paths([sys32]).unwrap();
        assert_eq!(git_bash_from_path_var(&path_var), None);
    }

    #[test]
    fn git_without_bash_is_not_git_bash() {
        // MinGit / scm-only installs have git.exe but no bash.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("Git");
        touch(&root.join("cmd").join("git.exe"));
        let path_var = env::join_paths([root.join("cmd")]).unwrap();
        assert_eq!(git_bash_from_path_var(&path_var), None);
    }
}
