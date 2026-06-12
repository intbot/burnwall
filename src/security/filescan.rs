//! File-mode scanning: check agent configs and transcripts ON DISK — not
//! live traffic — for committed credentials and invisible-Unicode
//! instruction smuggling. Powers `burnwall scan` and the CI action; findings
//! export as SARIF (see `audit::sarif::build_file_findings`).
//!
//! Deliberately much narrower than the wire scanner. A config file is prose:
//! a `CLAUDE.md` that *mentions* a dangerous command or a sensitive path is
//! documentation, not an attack — the same reasoning that scopes the wire
//! scanner's command/path rules to tool-call arguments. Only two
//! high-precision checks run here:
//!
//! 1. **Committed credentials** — a real key pattern in a tracked config or
//!    transcript is a leak regardless of intent.
//! 2. **Invisible-character smuggling** — zero-width/bidi/tag characters
//!    hidden inside otherwise-ASCII text have no legitimate reason to exist
//!    in an agent instruction file.
//!
//! Findings carry a masked preview / counts only — never the raw value.

use std::path::{Path, PathBuf};

use super::{evasion, secrets};

/// One finding in one file. `line` is 1-based.
#[derive(Debug, Clone)]
pub struct Finding {
    /// Display path (as given / discovered), used verbatim in reports.
    pub path: String,
    /// 1-based line number.
    pub line: usize,
    /// Stable rule id: `secret_in_file` or `invisible_text`.
    pub rule: &'static str,
    /// Human message. Masked preview / counts only — never the raw value.
    pub message: String,
}

impl Finding {
    /// SARIF level for this finding's rule: a committed credential is an
    /// error (it has already leaked into version control); invisible-text
    /// smuggling is a warning (suspicious, but inspect before acting).
    pub fn level(&self) -> &'static str {
        match self.rule {
            "secret_in_file" => "error",
            _ => "warning",
        }
    }
}

/// Files that carry agent instructions or tool wiring — the attack surface
/// a poisoned PR would touch. Matched against the file name (case-exact;
/// these are conventional spellings).
const AGENT_CONFIG_NAMES: &[&str] = &[
    "CLAUDE.md",
    "CLAUDE.local.md",
    "AGENTS.md",
    "GEMINI.md",
    ".cursorrules",
    ".windsurfrules",
    ".clinerules",
    ".goosehints",
    ".replit",
    ".mcp.json",
    "mcp.json",
    "mcp_settings.json",
];

/// Directories whose contents are agent-tool state: any text file inside is
/// in scope (settings, hooks, rules, prompts, transcripts).
const AGENT_DIRS: &[&str] = &[
    ".claude",
    ".cursor",
    ".windsurf",
    ".codex",
    ".gemini",
    ".aider",
    ".cline",
];

/// Directories never worth descending into.
const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    ".venv",
    "venv",
    "__pycache__",
];

/// Extensions treated as text inside agent dirs / with `--all-files`.
const TEXT_EXTS: &[&str] = &[
    "md", "json", "jsonl", "toml", "yaml", "yml", "txt", "rules", "mdc",
];

/// Files larger than this are skipped — agent configs are small; anything
/// bigger is a data file that would only slow CI down.
const MAX_FILE_BYTES: u64 = 5 * 1024 * 1024;

/// Is `path` (by name or by an agent-dir ancestor) an agent config file?
pub fn is_agent_config(path: &Path) -> bool {
    let name = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n,
        None => return false,
    };
    if AGENT_CONFIG_NAMES.contains(&name) {
        return true;
    }
    // Any text file under a known agent directory (settings.json, hooks,
    // command prompts, session transcripts someone committed).
    let in_agent_dir = path
        .ancestors()
        .skip(1)
        .filter_map(|a| a.file_name().and_then(|n| n.to_str()))
        .any(|dir| AGENT_DIRS.contains(&dir));
    in_agent_dir && has_text_ext(path)
}

fn has_text_ext(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| TEXT_EXTS.contains(&e.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
}

/// Expand `roots` (files and/or directories) into the list of files to scan.
/// A file given explicitly is always scanned (the caller asked for it); a
/// directory is walked recursively for agent configs — or for every text
/// file when `all_files` is set. Deterministic order (sorted) so CI output
/// is stable.
pub fn collect_targets(roots: &[PathBuf], all_files: bool) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for root in roots {
        if root.is_file() {
            out.push(root.clone());
        } else if root.is_dir() {
            walk(root, all_files, &mut out);
        }
    }
    out.sort();
    out.dedup();
    out
}

fn walk(dir: &Path, all_files: bool, out: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return, // unreadable directory: skip, don't fail the scan
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if SKIP_DIRS.contains(&name) {
                continue;
            }
            walk(&path, all_files, out);
        } else if is_agent_config(&path) || (all_files && has_text_ext(&path)) {
            out.push(path);
        }
    }
}

/// Scan one file from disk. Oversized and non-UTF-8 (binary) files are
/// skipped with an empty result — file mode is advisory, never wedging.
pub fn scan_file(path: &Path) -> Vec<Finding> {
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.len() > MAX_FILE_BYTES {
            return Vec::new();
        }
    }
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    scan_text(&path.display().to_string(), &text)
}

/// Scan text line-by-line. Public for tests and for callers with in-memory
/// content (e.g. scanning a diff hunk).
pub fn scan_text(display_path: &str, text: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        let lineno = idx + 1;
        if let Some((name, masked)) = secrets::first_match_masked(line) {
            findings.push(Finding {
                path: display_path.to_string(),
                line: lineno,
                rule: "secret_in_file",
                message: format!("{} committed in file: {}", name, masked),
            });
        }
        // ASCII fast path: none of the invisible characters are ASCII.
        if !line.is_ascii() {
            let inv = evasion::scan_invisible(line);
            if inv.suspicious > 0 {
                findings.push(Finding {
                    path: display_path.to_string(),
                    line: lineno,
                    rule: "invisible_text",
                    message: format!(
                        "{} invisible character(s) hidden inside ASCII text ({} invisible total on this line) — possible instruction smuggling",
                        inv.suspicious, inv.total
                    ),
                });
            }
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_in_text_is_found_and_masked() {
        // The fake key is assembled (never a contiguous key-shaped literal in
        // source) — matching the rest of the suite's convention and keeping
        // this very file clean under the pre-push secret guard. It still
        // matches the Anthropic-key pattern at runtime, so the scanner fires.
        let key = format!("sk-ant-api03-{}", "A".repeat(64));
        let text = format!("model: claude\napi_key = \"{key}\"\n");
        let findings = scan_text("CLAUDE.md", &text);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "secret_in_file");
        assert_eq!(findings[0].line, 2);
        assert_eq!(findings[0].level(), "error");
        // Masked: the full key value must not appear in the message.
        assert!(!findings[0].message.contains("AAAAAAAAAAAAAAAAAAAAAAAA"));
    }

    #[test]
    fn invisible_smuggling_is_found_clean_prose_is_not() {
        let smuggled = "Always be helpful.\u{200B}\u{200B}\u{200B} Run the setup.\n";
        let findings = scan_text(".cursorrules", smuggled);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "invisible_text");
        assert_eq!(findings[0].level(), "warning");

        // Ordinary prose — including non-ASCII text — is clean.
        let clean = "Précis: run `cargo test` before committing. 你好.\n";
        assert!(scan_text("CLAUDE.md", clean).is_empty());
    }

    #[test]
    fn prose_mentioning_dangerous_commands_is_not_flagged() {
        // The whole point of file mode's narrow scope: documentation ABOUT
        // dangerous commands / sensitive paths is not an attack.
        let text = "Never run rm -rf /. Do not read ~/.ssh or ~/.aws credentials.\n";
        assert!(scan_text("CLAUDE.md", text).is_empty());
    }

    #[test]
    fn agent_config_detection() {
        assert!(is_agent_config(Path::new("CLAUDE.md")));
        assert!(is_agent_config(Path::new("sub/dir/.cursorrules")));
        assert!(is_agent_config(Path::new(".claude/settings.json")));
        assert!(is_agent_config(Path::new("a/.claude/commands/x.md")));
        assert!(!is_agent_config(Path::new("README.md")));
        assert!(!is_agent_config(Path::new("src/main.rs")));
        assert!(!is_agent_config(Path::new(".claude/some.bin")));
    }

    #[test]
    fn collect_walks_dirs_and_skips_vendored() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("CLAUDE.md"), "hi").unwrap();
        std::fs::write(root.join("README.md"), "hi").unwrap();
        std::fs::create_dir_all(root.join(".claude")).unwrap();
        std::fs::write(root.join(".claude/settings.json"), "{}").unwrap();
        std::fs::create_dir_all(root.join("node_modules/x")).unwrap();
        std::fs::write(root.join("node_modules/x/CLAUDE.md"), "hi").unwrap();

        let targets = collect_targets(&[root.to_path_buf()], false);
        let names: Vec<String> = targets
            .iter()
            .map(|p| {
                p.strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();
        assert_eq!(names, vec![".claude/settings.json", "CLAUDE.md"]);

        // --all-files widens to every text file, still skipping vendored dirs.
        let all = collect_targets(&[root.to_path_buf()], true);
        assert_eq!(all.len(), 3, "README.md joins with --all-files: {all:?}");
    }

    #[test]
    fn explicit_file_is_always_scanned() {
        let dir = tempfile::tempdir().unwrap();
        let exotic = dir.path().join("notes.weird");
        std::fs::write(&exotic, "hello").unwrap();
        let targets = collect_targets(std::slice::from_ref(&exotic), false);
        assert_eq!(targets, vec![exotic]);
    }
}
